// The public tester's "Run the whole flow" (examples/workers/tester, /flow/start and /flow/callback), in workerd on D1:
// the tester plays the client against an IdP stubbed at fetch, which checks what a real one must (client
// authentication, PKCE, the redirect URI) and can be told to answer badly. A run signs in, exchanges the ID token for
// an ID-JAG, checks the answer (checkExchange) and redeems the ID-JAG at the real receiver.
import { createLocalJWKSet, exportJWK, generateKeyPair, type JSONWebKeySet, jwtVerify, SignJWT } from "jose";
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import init0001 from "../../examples/workers/tester/migrations/0001_init.sql?raw";
import init0002 from "../../examples/workers/tester/migrations/0002_tester.sql?raw";
import init0003 from "../../examples/workers/tester/migrations/0003_client_secret.sql?raw";
import init0004 from "../../examples/workers/tester/migrations/0004_allowance.sql?raw";
import init0005 from "../../examples/workers/tester/migrations/0005_flow.sql?raw";
import { PROBES } from "../../examples/workers/tester/src/probes";
import { createClient, createIssuerHost, type IssuerHost, signUp } from "../support/issuer-host";

const workerd = navigator.userAgent === "Cloudflare-Workers";
const ORIGIN = "https://tester.example.net";
const SECRET = "tester-test-secret-that-is-at-least-32-characters";
const IP = "198.51.100.9";
/** Each tester's own issuer: once a run confirms one, nobody else can register it. */
const issuerOf = (login: string) => `https://idp-${login}.example.org`;
const IDP_URL = /^(https:\/\/idp-[a-z0-9-]+\.example\.org)(\/.*)$/;
const IDP_CLIENT = "idp-client";
// Characters that HTTP Basic must form-encode (RFC 6749 section 2.3.1).
const IDP_SECRET = "idp secret+/:%";

// good: an IdP that refuses what it must, with the draft's codes. lax: accepts any exchange. wrong-codes: refuses
// what it must, always with invalid_grant. busy: after the code exchange and the good exchange, 429 and 502 in turn.
// error-200: refuses what it must with the draft's codes, but with HTTP 200.
type Mode = "good" | "lax" | "wrong-codes" | "refuse" | "no-store-missing" | "wrong-nonce" | "other-audience" | "resource-normalised" | "no-id-token" | "no-refresh-subject" | "refresh-not-id-jag" | "foreign-key" | "busy" | "error-200" | "access-is-id-token" | "no-exp" | "azp-other" | "huge-id-jag";

describe.skipIf(!workerd)("tester: run the whole flow (workerd, D1)", () => {
  let env: Record<string, unknown> & { DB: Cloudflare.Env["DB"] };
  let worker: { fetch(r: Request, e: unknown, c: unknown): Promise<Response>; scheduled(e: unknown, env: unknown): Promise<void> };
  let LIMITS: Record<string, number>;
  let cf: typeof import("cloudflare:test");
  let signer: CryptoKey;
  let jwks: unknown;
  /** Our own issuer plugin as the IdP, when a test sets it up (on its own database). */
  let own: IssuerHost | undefined;
  const OWN_BASE = "https://own-idp.example.net";

  /** The stub IdP: what it was sent, and how it answers. */
  const idp = {
    mode: "good" as Mode,
    /** Each issuer's client at the tester, which its ID-JAGs name in client_id. */
    testerClientIds: new Map<string, string>(),
    /** Codes the "browser" brought back from sign-in: the PKCE challenge and nonce they were issued for. */
    codes: new Map<string, { challenge: string; nonce: string; redirectUri: string; scope: string }>(),
    /** Refresh tokens issued (for a sign-in with offline_access). */
    refreshTokens: new Set<string>(),
    /** Every ID token and access token issued: none may end up in the tester's database. */
    issued: [] as string[],
    /** Per issuer: fields that replace its metadata's. */
    metadata: new Map<string, Record<string, unknown>>(),
    requests: [] as { grant: string | null; form: URLSearchParams; authorization: string | null; userAgent: string | null }[],
  };

  const b64url = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const now = () => Math.floor(Date.now() / 1000);
  let otherSigner: CryptoKey;
  const sign = (claims: Record<string, unknown>, typ?: string, key?: CryptoKey) => new SignJWT(claims).setProtectedHeader({ alg: "RS256", kid: "k1", ...(typ ? { typ } : {}) }).sign(key ?? signer);

  /** The IdP's client authentication, as an IdP reads it: Basic (form-decoded) or in the body. */
  const authenticated = (form: URLSearchParams, authorization: string | null) => {
    if (authorization) {
      const [id, secret] = atob(authorization.replace(/^Basic /, "")).split(":").map((v) => decodeURIComponent(v.replace(/\+/g, " ")));
      return id === IDP_CLIENT && secret === IDP_SECRET && !form.has("client_secret");
    }
    return form.get("client_id") === IDP_CLIENT && form.get("client_secret") === IDP_SECRET;
  };

  const tokenEndpoint = async (request: Request, issuer: string): Promise<Response> => {
    const form = new URLSearchParams(await request.text());
    const authorization = request.headers.get("authorization");
    idp.requests.push({ grant: form.get("grant_type"), form, authorization, userAgent: request.headers.get("user-agent") });
    if (idp.mode === "busy" && idp.requests.length > 2) return idp.requests.length % 2 ? new Response("slow down", { status: 429 }) : new Response("bad gateway", { status: 502 });
    const exchanging = form.get("grant_type") === "urn:ietf:params:oauth:grant-type:token-exchange";
    const refuse = (error: string, status = 400) => Response.json({ error: idp.mode === "wrong-codes" ? "invalid_grant" : error }, { status: idp.mode === "wrong-codes" ? 400 : idp.mode === "error-200" ? 200 : status, headers: { "cache-control": "no-store" } });
    if (!authenticated(form, authorization) && !(exchanging && idp.mode === "lax")) return refuse("invalid_client", 401);
    if (form.get("grant_type") === "authorization_code") {
      const issued = idp.codes.get(form.get("code") ?? "");
      idp.codes.delete(form.get("code") ?? "");
      const verifier = form.get("code_verifier") ?? "";
      const challenge = b64url(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))));
      if (!issued || issued.challenge !== challenge || issued.redirectUri !== form.get("redirect_uri")) return Response.json({ error: "invalid_grant" }, { status: 400 });
      const accessToken = `at-${crypto.randomUUID()}`;
      idp.issued.push(accessToken);
      if (idp.mode === "no-id-token") return Response.json({ access_token: accessToken, token_type: "Bearer" }, { headers: { "cache-control": "no-store" } });
      const aud = idp.mode === "other-audience" ? "another-client" : idp.mode === "azp-other" ? [IDP_CLIENT, "another-client"] : IDP_CLIENT;
      const idToken = await sign({ iss: issuer, sub: "u1", aud, ...(idp.mode === "azp-other" ? { azp: "another-client" } : {}), nonce: idp.mode === "wrong-nonce" ? "another" : issued.nonce, iat: now(), ...(idp.mode === "no-exp" ? {} : { exp: now() + 300 }), email: "u1@idp.example.org" });
      idp.issued.push(idToken);
      if (idp.mode === "access-is-id-token") return Response.json({ access_token: idToken, token_type: "Bearer", id_token: idToken }, { headers: { "cache-control": "no-store" } });
      const refreshToken = issued.scope.split(" ").includes("offline_access") ? `rt-${crypto.randomUUID()}` : undefined;
      if (refreshToken) idp.refreshTokens.add(refreshToken);
      return Response.json({ access_token: accessToken, token_type: "Bearer", id_token: idToken, ...(refreshToken ? { refresh_token: refreshToken } : {}) }, { headers: { "cache-control": "no-store" } });
    }
    if (form.get("grant_type") === "urn:ietf:params:oauth:grant-type:token-exchange") {
      if (idp.mode === "refuse") return Response.json({ error: "access_denied", error_description: "not assigned" }, { status: 400, headers: { "cache-control": "no-store" } });
      if (idp.mode !== "lax") {
        // What an IdP must check (draft -06 section 4.3.3): one audience it trusts, resources it governs, and a subject
        // token that is an ID token it issued to this client (signed by it, no typ, aud the client).
        const audiences = form.getAll("audience");
        if (audiences.length !== 1) return refuse("invalid_request");
        if (audiences[0] !== `${ORIGIN}/api/auth`) return refuse("invalid_target");
        if (form.getAll("resource").some((r) => r !== `${ORIGIN}/mcp`)) return refuse("invalid_target");
        if (form.get("subject_token_type") === "urn:ietf:params:oauth:token-type:refresh_token") {
          if (idp.mode === "no-refresh-subject") return refuse("unsupported_token_type");
          if (idp.mode === "refresh-not-id-jag") return Response.json({ issued_token_type: "urn:ietf:params:oauth:token-type:jwt", access_token: "x", token_type: "N_A" }, { headers: { "cache-control": "no-store" } });
          if (!idp.refreshTokens.has(form.get("subject_token") ?? "")) return refuse("invalid_request");
        } else if (form.get("subject_token_type") !== "urn:ietf:params:oauth:token-type:id_token") return refuse("invalid_request");
        else try {
          const { protectedHeader } = await jwtVerify(form.get("subject_token") ?? "", createLocalJWKSet(jwks as JSONWebKeySet), { issuer, audience: IDP_CLIENT });
          if (protectedHeader.typ !== undefined) return refuse("invalid_request");
        } catch {
          return refuse("invalid_request");
        }
      }
      const resource = form.get("resource") ?? "";
      const idJag = await sign({ iss: issuer, sub: "u1", aud: form.get("audience"), client_id: idp.testerClientIds.get(issuer), jti: crypto.randomUUID(), iat: now(), exp: now() + 300, resource: idp.mode === "resource-normalised" ? `${resource}/` : resource, scope: form.get("scope"), email: "u1@idp.example.org", ...(idp.mode === "huge-id-jag" ? { padding: "x".repeat(25_000) } : {}) }, "oauth-id-jag+jwt", idp.mode === "foreign-key" ? otherSigner : undefined);
      return Response.json({ issued_token_type: "urn:ietf:params:oauth:token-type:id-jag", access_token: idJag, token_type: "N_A", expires_in: 300 }, { headers: idp.mode === "no-store-missing" ? {} : { "cache-control": "no-store" } });
    }
    return Response.json({ error: "unsupported_grant_type" }, { status: 400 });
  };

  const call = async (path: string, init: RequestInit & { cookie?: string } = {}) => {
    const headers = new Headers(init.headers);
    if (init.cookie) headers.set("cookie", init.cookie);
    headers.set("cf-connecting-ip", IP);
    const ctx = cf.createExecutionContext();
    const response = await worker.fetch(new Request(`${ORIGIN}${path}`, { ...init, headers }), env, ctx);
    await cf.waitOnExecutionContext(ctx);
    return response;
  };

  let nextAccountId = 5000;
  const signedIn = async (login: string) => {
    const { createAuth } = await import("../../examples/workers/tester/src/auth");
    const ctx = await createAuth(env as never, ORIGIN).$context;
    const id = nextAccountId++;
    const user = await ctx.internalAdapter.createUser({ email: `github-${id}@testers.invalid`, name: login, emailVerified: false, accountCreatedAt: new Date(Date.now() - 2000 * 86_400_000) }, { method: "test" });
    await ctx.internalAdapter.linkAccount({ userId: user.id, providerId: "github", accountId: String(id), accessToken: `token-${login}`, refreshToken: "r" });
    const s = await ctx.internalAdapter.createSession(user.id);
    const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const sig = btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(s.token)))));
    return { cookie: `${ctx.authCookies.sessionToken.name}=${encodeURIComponent(`${s.token}.${sig}`)}`, userId: user.id };
  };

  const rows = async <T>(sql: string, ...binds: unknown[]) => (await env.DB.prepare(sql).bind(...binds).all()).results as T[];
  const post = (path: string, cookie: string, form: Record<string, string>, origin = ORIGIN) => call(path, { method: "POST", cookie, headers: { origin, "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(form).toString() });

  /** A tester with a registration of their own issuer, and the stub IdP told its client id here. */
  const registeredTester = async (login: string) => {
    const t = await signedIn(login);
    const page = await post("/register", t.cookie, { issuer: issuerOf(login), authMethod: "client_secret_basic", "cf-turnstile-response": "ok" });
    expect(page.status).toBe(200);
    const reg = (await rows<{ id: string; clientId: string }>(`select id, clientId from testerRegistration where userId = ?`, t.userId))[0];
    if (!reg) throw new Error("not registered");
    idp.testerClientIds.set(issuerOf(login), reg.clientId);
    return { ...t, registrationId: reg.id, clientId: reg.clientId };
  };

  /** /flow/start, then what the IdP's sign-in page would do: a code for the request's challenge and nonce. */
  const start = async (t: { cookie: string; registrationId: string }, o: Record<string, string> = {}) => {
    const response = await post("/flow/start", t.cookie, { registration: t.registrationId, client_id: IDP_CLIENT, client_secret: IDP_SECRET, auth_method: "client_secret_basic", scope: "read", ...o });
    const html = await response.text();
    const href = html.match(/<a href="([^"]+)"><strong>Continue/)?.[1]?.replace(/&amp;/g, "&");
    return { response, html, to: href ? new URL(href) : null };
  };
  const signInAtIdp = (to: URL, code = `code-${crypto.randomUUID()}`) => {
    idp.codes.set(code, { challenge: to.searchParams.get("code_challenge") ?? "", nonce: to.searchParams.get("nonce") ?? "", redirectUri: to.searchParams.get("redirect_uri") ?? "", scope: to.searchParams.get("scope") ?? "" });
    return code;
  };
  const callback = (cookie: string, params: Record<string, string>) => call(`/flow/callback?${new URLSearchParams(params)}`, { cookie });
  const lastCheck = async (registrationId: string) => (await rows<{ results: string; error: string | null; httpStatus: number; jti: string | null }>(`select results, error, httpStatus, jti from testerCheck where registrationId = ? order by at desc, rowid desc limit 1`, registrationId))[0];
  const outcomes = (check: { results: string } | undefined) => Object.fromEntries((JSON.parse(check?.results ?? "[]") as { id: string; outcome: string }[]).map((r) => [r.id, r.outcome]));

  beforeAll(async () => {
    cf = await import("cloudflare:test");
    const ok = { limit: async () => ({ success: true }) };
    env = { DB: cf.env.DB, BETTER_AUTH_SECRET: SECRET, GITHUB_CLIENT_ID: "gh", GITHUB_CLIENT_SECRET: "gh-secret", GITLAB_CLIENT_ID: "", TURNSTILE_SITE_KEY: "site", TURNSTILE_SECRET_KEY: "turnstile", TESTER_ENABLED: "true", TOKEN_LIMIT: ok, IP_LIMIT: ok, MCP_LIMIT: ok };
    for (const sql of [init0001, init0002, init0003, init0004, init0005]) for (const stmt of sql.replace(/^--.*$/gm, "").split(/;\s*\n/).map((s: string) => s.trim()).filter(Boolean)) await env.DB.prepare(stmt).run();
    const pair = await generateKeyPair("RS256", { extractable: true });
    signer = pair.privateKey;
    otherSigner = (await generateKeyPair("RS256")).privateKey;
    jwks = { keys: [{ ...(await exportJWK(pair.publicKey)), kid: "k1", alg: "RS256", use: "sig" }] };
    const real = globalThis.fetch;
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init);
      const url = request.url;
      if (own && url.startsWith(OWN_BASE)) return own.auth.handler(request);
      const [, issuer, path] = url.match(IDP_URL) ?? [];
      if (issuer && path === "/.well-known/oauth-authorization-server") return Response.json({ issuer, jwks_uri: `${issuer}/jwks`, authorization_endpoint: `${issuer}/authorize?tenant=t1`, token_endpoint: `${issuer}/token`, identity_chaining_requested_token_types_supported: ["urn:ietf:params:oauth:token-type:id-jag"], ...idp.metadata.get(issuer) });
      if (issuer && path === "/jwks") return Response.json(jwks);
      if (issuer && path === "/token" && request.method === "POST") return tokenEndpoint(request, issuer);
      if (url === "https://challenges.cloudflare.com/turnstile/v0/siteverify") return Response.json({ success: true });
      if (url.startsWith(ORIGIN)) return real(input, init);
      return new Response("not found", { status: 404 });
    });
    worker = (await import("../../examples/workers/tester/src/index")).default as never;
    LIMITS = (await import("../../examples/workers/tester/src/limits")).LIMITS as never;
    LIMITS.registrationsPerDay = 100;
    LIMITS.registrationsPerIpPerDay = 100;
    LIMITS.registrationsPerAccountPerDay = 100;
  }, 60_000);

  beforeEach(() => {
    idp.mode = "good";
    idp.requests.length = 0;
  });

  it("a run: sign-in, token exchange, the answer's rules, the redemption; the registration confirmed; nothing of the IdP's kept", async () => {
    const t = await registeredTester("runner");
    const results = await (await call("/results", { cookie: t.cookie })).text();
    expect(results).toContain('action="/flow/start"');
    expect(results).toContain(`${ORIGIN}/flow/callback`);

    const { response, html, to } = await start(t);
    expect(response.status).toBe(200);
    expect(html).toContain("idp-runner.example.org");
    if (!to) throw new Error(`no link in: ${html.slice(0, 300)}`);
    // The IdP's own query is kept; the sign-in request is OpenID Connect with PKCE S256.
    expect(Object.fromEntries(to.searchParams)).toMatchObject({ tenant: "t1", response_type: "code", client_id: IDP_CLIENT, redirect_uri: `${ORIGIN}/flow/callback`, scope: "openid", code_challenge_method: "S256" });
    for (const k of ["state", "nonce", "code_challenge"]) expect(to.searchParams.get(k)?.length).toBeGreaterThan(20);
    // Kept for the run: hashed state, sealed secret and verifier.
    const [flow] = await rows<Record<string, string>>(`select * from testerFlow where registrationId = ?`, t.registrationId);
    expect(flow?.stateHash).not.toBe(to.searchParams.get("state"));
    expect(JSON.stringify(flow)).not.toContain(IDP_SECRET);

    const code = signInAtIdp(to);
    const back = await callback(t.cookie, { code, state: to.searchParams.get("state") ?? "", iss: issuerOf("runner") });
    expect(back.status).toBe(302);
    expect(back.headers.get("location")).toBe("/results");

    // What the IdP was sent: the code exchange, then the token exchange, both with the client's Basic credentials.
    expect(idp.requests.map((r) => r.grant)).toEqual(["authorization_code", "urn:ietf:params:oauth:grant-type:token-exchange"]);
    const exchange = idp.requests[1];
    expect(Object.fromEntries(exchange?.form ?? [])).toMatchObject({ requested_token_type: "urn:ietf:params:oauth:token-type:id-jag", audience: `${ORIGIN}/api/auth`, resource: `${ORIGIN}/mcp`, scope: "read", subject_token_type: "urn:ietf:params:oauth:token-type:id_token" });
    expect(exchange?.authorization).toMatch(/^Basic /);
    expect(exchange?.userAgent).toBe(`idjag-tester (${ORIGIN})`);

    const check = await lastCheck(t.registrationId);
    expect(check?.httpStatus).toBe(200);
    const results2 = JSON.parse(check?.results ?? "[]") as { id: string; outcome: string }[];
    expect(results2[0]?.id).toBe("exchange.status");
    expect(results2.filter((r) => r.outcome === "fail")).toEqual([]);
    expect(outcomes(check)).toMatchObject({ "exchange.no_store": "pass", "exchange.resource_echo": "pass", signature: "pass", "claim.client_id": "pass" });
    expect((await rows<{ confirmedAt: number | null }>(`select confirmedAt from testerRegistration where id = ?`, t.registrationId))[0]?.confirmedAt).not.toBeNull();
    // The run is gone; neither the IdP client's secret nor the IdP's tokens are anywhere in the database.
    expect(await rows(`select 1 from testerFlow`)).toEqual([]);
    const tables = (await rows<{ name: string }>(`select name from sqlite_master where type = 'table' and name not like 'sqlite_%' and name not like '_cf_%'`)).map((r) => r.name);
    expect(tables).toContain("testerCheck");
    const dump = JSON.stringify(await Promise.all(tables.map((t2) => rows(`select * from "${t2}"`))));
    expect(dump).not.toContain(IDP_SECRET);
    expect(idp.issued.length).toBeGreaterThanOrEqual(2);
    for (const token of idp.issued) expect(dump).not.toContain(token);
    const page = await (await call("/results", { cookie: t.cookie })).text();
    expect(page).toContain("whole flow");
  });

  it("the IdP's client in the form body (client_secret_post)", async () => {
    const t = await registeredTester("poster");
    const { to } = await start(t, { auth_method: "client_secret_post" });
    if (!to) throw new Error("no link");
    await callback(t.cookie, { code: signInAtIdp(to), state: to.searchParams.get("state") ?? "" });
    expect(idp.requests.map((r) => r.authorization)).toEqual([null, null]);
    expect(idp.requests.every((r) => r.form.get("client_secret") === IDP_SECRET)).toBe(true);
    expect((await lastCheck(t.registrationId))?.httpStatus).toBe(200);
  });

  it("a state works once, only for the tester who started it, and only for 10 minutes", async () => {
    const t = await registeredTester("once");
    const other = await registeredTester("other");
    const first = await start(t);
    if (!first.to) throw new Error("no link");
    const state = first.to.searchParams.get("state") ?? "";
    // Someone else's browser with this state: refused, and the run is spent.
    const stolen = await callback(other.cookie, { code: signInAtIdp(first.to), state });
    expect(stolen.status).toBe(400);
    expect(await callback(t.cookie, { code: signInAtIdp(first.to), state })).toHaveProperty("status", 400);
    expect(idp.requests).toEqual([]);

    const second = await start(t);
    if (!second.to) throw new Error("no link");
    const code = signInAtIdp(second.to);
    const state2 = second.to.searchParams.get("state") ?? "";
    expect((await callback(t.cookie, { code, state: state2 })).status).toBe(302);
    expect((await callback(t.cookie, { code, state: state2 })).status).toBe(400);

    const third = await start(t);
    if (!third.to) throw new Error("no link");
    await env.DB.prepare(`update testerFlow set expiresAt = ?`).bind(Date.now() - 1).run();
    const late = await callback(t.cookie, { code: signInAtIdp(third.to), state: third.to.searchParams.get("state") ?? "" });
    expect(late.status).toBe(400);
    expect(await late.text()).toContain("10 minutes");
    expect(await callback(t.cookie, { code: "x" })).toHaveProperty("status", 400);
    // Signed out: back to the home page, the run untouched.
    const fourth = await start(t);
    expect((await call(`/flow/callback?state=${fourth.to?.searchParams.get("state")}`)).status).toBe(302);
    expect(await rows(`select 1 from testerFlow`)).toHaveLength(1);
  });

  it("the IdP refuses the exchange: the report has the refusal, nothing reached the receiver", async () => {
    const t = await registeredTester("refused");
    idp.mode = "refuse";
    const { to } = await start(t);
    if (!to) throw new Error("no link");
    expect((await callback(t.cookie, { code: signInAtIdp(to), state: to.searchParams.get("state") ?? "" })).status).toBe(302);
    const check = await lastCheck(t.registrationId);
    expect(check).toMatchObject({ httpStatus: 0, error: "exchange_failed", jti: null });
    expect(outcomes(check)).toEqual({ "exchange.status": "fail" });
    expect(check?.results).toContain("access_denied");
    expect((await rows<{ confirmedAt: number | null }>(`select confirmedAt from testerRegistration where id = ?`, t.registrationId))[0]?.confirmedAt).toBeNull();
    expect(await (await call("/results", { cookie: t.cookie })).text()).toContain("not reached: your IdP issued no ID-JAG");
  });

  it("the answer's own rules are reported beside the receiver's decision", async () => {
    const t = await registeredTester("rules");
    for (const [mode, rule] of [["no-store-missing", "exchange.no_store"], ["resource-normalised", "exchange.resource_echo"]] as const) {
      idp.mode = mode;
      const { to } = await start(t);
      if (!to) throw new Error("no link");
      await callback(t.cookie, { code: signInAtIdp(to), state: to.searchParams.get("state") ?? "" });
      expect(outcomes(await lastCheck(t.registrationId))[rule]).toBe("fail");
    }
  });

  it("a sign-in that fails stops the run with a message, and records nothing", async () => {
    const t = await registeredTester("stops");
    const stopped = async (params: (to: URL) => Record<string, string>, mode: Mode = "good") => {
      idp.mode = mode;
      const { to } = await start(t);
      if (!to) throw new Error("no link");
      const r = await callback(t.cookie, { state: to.searchParams.get("state") ?? "", ...params(to) });
      expect(r.status).toBeGreaterThanOrEqual(400);
      return r.text();
    };
    expect(await stopped((to) => ({ code: signInAtIdp(to) }), "wrong-nonce")).toContain("nonce");
    expect(await stopped((to) => ({ code: signInAtIdp(to) }), "other-audience")).toContain("your IdP client as aud");
    expect(await stopped((to) => ({ code: signInAtIdp(to) }), "no-id-token")).toContain("no ID token");
    expect(await stopped((to) => ({ code: signInAtIdp(to), iss: "https://elsewhere.example.org" }))).toContain("RFC 9207");
    expect(await stopped(() => ({ error: "access_denied", error_description: "<b>no</b>" }))).toContain("&lt;b&gt;no&lt;/b&gt;");
    expect(await stopped(() => ({ code: "never-issued" }))).toContain("invalid_grant");
    expect(await rows(`select 1 from testerCheck where registrationId = ?`, t.registrationId)).toEqual([]);
  });

  it("/flow/start: this site's own form, the tester's own active registration, a valid scope, a usable issuer", async () => {
    const t = await registeredTester("starts");
    const other = await registeredTester("someone");
    expect((await post("/flow/start", t.cookie, { registration: t.registrationId, client_id: IDP_CLIENT, client_secret: IDP_SECRET }, "https://evil.example.org")).status).toBe(403);
    expect((await start(t, { registration: other.registrationId })).response.status).toBe(404);
    expect((await start(t, { scope: "read  write" })).response.status).toBe(400);
    expect((await start(t, { client_secret: "" })).response.status).toBe(400);
    expect(await rows(`select 1 from testerFlow where registrationId = ?`, t.registrationId)).toEqual([]);
  });

  it("at most LIMITS.runsPerRegistrationPerDay runs a day per registration", async () => {
    const t = await registeredTester("limited");
    const before = LIMITS.runsPerRegistrationPerDay;
    LIMITS.runsPerRegistrationPerDay = 2;
    try {
      expect((await start(t)).response.status).toBe(200);
      expect((await start(t)).response.status).toBe(200);
      expect((await start(t)).response.status).toBe(429);
    } finally {
      LIMITS.runsPerRegistrationPerDay = before as number;
    }
  });

  it("runs go with their registration, with the tester's data, and when they expire", async () => {
    const t = await registeredTester("leaver");
    await start(t);
    await start(t);
    await env.DB.prepare(`update testerFlow set expiresAt = ? where registrationId = ?`).bind(Date.now() - 1, t.registrationId).run();
    const kept = await registeredTester("stayer");
    await start(kept);
    await worker.scheduled({}, env);
    expect(await rows(`select 1 from testerFlow where registrationId = ?`, t.registrationId)).toEqual([]);
    expect(await rows(`select 1 from testerFlow where registrationId = ?`, kept.registrationId)).toHaveLength(1);
    await post("/delete", kept.cookie, {});
    expect(await rows(`select 1 from testerFlow where userId = ?`, kept.userId)).toEqual([]);
  });

  /** A run with the refusal probes; the outcome of each probe.* rule. */
  const probeRun = async (login: string, mode: Mode) => {
    const t = await registeredTester(login);
    idp.mode = mode;
    idp.requests.length = 0;
    const { to } = await start(t, { probes: "1" });
    if (!to) throw new Error("no link");
    expect((await callback(t.cookie, { code: signInAtIdp(to), state: to.searchParams.get("state") ?? "" })).status).toBe(302);
    const check = await lastCheck(t.registrationId);
    const probes = Object.fromEntries(Object.entries(outcomes(check)).filter(([id]) => id.startsWith("probe.")));
    return { t, check, probes };
  };

  it("probes, asked for: a careful IdP refuses each with the draft's code; the run is redeemed as usual", async () => {
    const { check, probes } = await probeRun("careful", "good");
    expect(probes).toEqual(Object.fromEntries(PROBES.map((p) => [p.id, "pass"])));
    expect(check?.httpStatus).toBe(200);
    // The code exchange, the good exchange, then the seven probes, in order; the first without the client's credentials.
    expect(idp.requests).toHaveLength(9);
    expect(idp.requests[2]?.authorization).toBeNull();
    expect(idp.requests[2]?.form.has("client_secret")).toBe(false);
    expect(idp.requests[3]?.form.getAll("audience")).toHaveLength(2);
    // In the report: the exchange's rules, then the probes', then the ID-JAG's.
    const ids = (JSON.parse(check?.results ?? "[]") as { id: string }[]).map((r) => r.id);
    expect(ids.indexOf("exchange.resource_echo")).toBeLessThan(ids.indexOf("probe.no_client_auth"));
    expect(ids.indexOf("probe.wrong_subject_type")).toBeLessThan(ids.indexOf("jwt.structure"));
  });

  it("probes: an IdP that accepts them fails each one, but a SHOULD only warns", async () => {
    const { probes } = await probeRun("lax", "lax");
    expect(probes).toEqual(Object.fromEntries(PROBES.map((p) => [p.id, p.accepted])));
    expect(probes["probe.resource_not_governed"]).toBe("warn");
  });

  it("probes: a refusal with another code fails where the draft names the code, and warns where it only profiles one", async () => {
    const { probes } = await probeRun("codes", "wrong-codes");
    expect(probes).toEqual(Object.fromEntries(PROBES.map((p) => [p.id, p.codeRequired ? "fail" : "warn"])));
    // The resource probe names one resource, so a refusal grants none: invalid_target is then a MUST.
    expect(probes["probe.resource_not_governed"]).toBe("fail");
  });

  it("probes: only when asked for, only after an ID-JAG was issued, and only for a confirmed registration", async () => {
    // The IdP refused the correct request: a refusal of a wrong one would prove nothing, so none is sent.
    const refusing = await probeRun("refusing", "refuse");
    expect(refusing.probes).toEqual(Object.fromEntries(PROBES.map((p) => [p.id, "skip"])));
    expect(refusing.check?.results).toContain("issued no ID-JAG");
    expect(idp.requests).toHaveLength(2);
    // An ID-JAG that doesn't confirm the registration (not signed with the issuer's published key): none is sent.
    const unproven = await probeRun("unproven", "foreign-key");
    expect(unproven.probes).toEqual(Object.fromEntries(PROBES.map((p) => [p.id, "skip"])));
    expect(unproven.check?.results).toContain("confirmed registration");
    expect(idp.requests).toHaveLength(2);
    idp.requests.length = 0;
    idp.mode = "good";
    const t = await registeredTester("unasked");
    const { to } = await start(t);
    if (!to) throw new Error("no link");
    await callback(t.cookie, { code: signInAtIdp(to), state: to.searchParams.get("state") ?? "" });
    expect(idp.requests).toHaveLength(2);
  });

  it("a refresh token as the subject, asked for: supported or not, as information; the refresh token never stored", async () => {
    const run = async (login: string, mode: Mode, refresh = true) => {
      const t = await registeredTester(login);
      idp.mode = mode;
      idp.requests.length = 0;
      const { to } = await start(t, refresh ? { refresh: "1" } : {});
      if (!to) throw new Error("no link");
      expect(to.searchParams.get("scope")).toBe(refresh ? "openid offline_access" : "openid");
      // OpenID Connect Core section 11: offline_access is asked for with prompt=consent.
      expect(to.searchParams.get("prompt")).toBe(refresh ? "consent" : null);
      await callback(t.cookie, { code: signInAtIdp(to), state: to.searchParams.get("state") ?? "" });
      const check = await lastCheck(t.registrationId);
      return { check, rule: (JSON.parse(check?.results ?? "[]") as { id: string; outcome: string; message: string }[]).find((r) => r.id === "exchange.refresh_subject") };
    };
    const yes = await run("refresher", "good");
    expect(yes.rule).toMatchObject({ outcome: "info" });
    expect(yes.rule?.message).toContain("Supported");
    expect(idp.requests.map((r) => r.form.get("subject_token_type"))).toEqual([null, "urn:ietf:params:oauth:token-type:id_token", "urn:ietf:params:oauth:token-type:refresh_token"]);
    expect(yes.check?.httpStatus).toBe(200);
    for (const rt of idp.refreshTokens) expect(JSON.stringify(await rows(`select * from testerCheck`))).not.toContain(rt);
    const no = await run("norefresh", "no-refresh-subject");
    expect(no.rule?.message).toContain("Not supported");
    expect(no.rule?.message).toContain("unsupported_token_type");
    expect((await run("notidjag", "refresh-not-id-jag")).rule?.message).toContain("not an ID-JAG");
    expect((await run("unasked2", "good", false)).rule).toBeUndefined();
  });

  it("/flow/start: the metadata must name the registered issuer, and both endpoints must pass the guard", async () => {
    const t = await registeredTester("badmeta");
    const issuer = issuerOf("badmeta");
    for (const [fields, says] of [
      [{ issuer: `${issuer}/other` }, "doesn't name your registered issuer"],
      [{ token_endpoint: "http://idp-badmeta.example.org/token" }, "token_endpoint must use https"],
      [{ token_endpoint: "https://10.0.0.1/token" }, "token_endpoint must use a DNS name"],
      [{ authorization_endpoint: "https://localhost/authorize" }, "authorization_endpoint must use a fully qualified DNS name"],
      [{ authorization_endpoint: undefined }, "authorization_endpoint"],
    ] as const) {
      idp.metadata.set(issuer, fields);
      const { response, html } = await start(t);
      expect(response.status).toBe(502);
      expect(html).toContain(says.replace(/'/g, "&#39;"));
    }
    idp.metadata.delete(issuer);
    expect(await rows(`select 1 from testerFlow where registrationId = ?`, t.registrationId)).toEqual([]);
  });

  it("a run the tester's own limits keep from the receiver is still reported, with the IdP's answers", async () => {
    const t = await registeredTester("overlimit");
    const before = LIMITS.redemptionsPerRegistrationPerDay;
    LIMITS.redemptionsPerRegistrationPerDay = 0;
    try {
      const { to } = await start(t, { probes: "1" });
      if (!to) throw new Error("no link");
      const r = await callback(t.cookie, { code: signInAtIdp(to), state: to.searchParams.get("state") ?? "" });
      expect(r.status).toBe(429);
      expect(await r.text()).toContain("results page");
    } finally {
      LIMITS.redemptionsPerRegistrationPerDay = before as number;
    }
    const check = await lastCheck(t.registrationId);
    expect(check).toMatchObject({ httpStatus: 0, error: "not_redeemed" });
    expect(outcomes(check)["exchange.status"]).toBe("pass");
    // Never redeemed, so not confirmed: no probe was sent.
    expect(outcomes(check)["probe.no_client_auth"]).toBe("skip");
    expect(await (await call("/results", { cookie: t.cookie })).text()).toContain("the tester&#39;s limits kept the ID-JAG back");
  });

  it("at most LIMITS.runsPerDay runs a day across everyone; the registration's run is given back", async () => {
    const t = await registeredTester("everyone");
    const before = LIMITS.runsPerDay;
    const day = Date.now() - (Date.now() % 86_400_000);
    const [used] = await rows<{ used: number }>(`select used from testerAllowance where key = ?`, `run:everyone:${day}`);
    LIMITS.runsPerDay = used?.used ?? 0;
    try {
      expect((await start(t)).response.status).toBe(503);
    } finally {
      LIMITS.runsPerDay = before as number;
    }
    expect(await rows(`select used from testerAllowance where key = ?`, `run:registration:${t.registrationId}:${day}`)).toEqual([{ used: 0 }]);
  });

  it("probes: a rate limit or a server error isn't graded", async () => {
    const { probes, check } = await probeRun("busy", "busy");
    expect(probes).toEqual(Object.fromEntries(PROBES.map((p) => [p.id, "skip"])));
    expect(check?.results).toContain("answered HTTP 429 (too many requests)");
    expect(check?.results).toContain("answered HTTP 502 (a server error)");
    expect(check?.httpStatus).toBe(200);
  });

  it("probes: an access token that is the ID token itself isn't sent as the wrong subject", async () => {
    const { probes, check } = await probeRun("sameat", "access-is-id-token");
    expect(probes).toEqual(Object.fromEntries(PROBES.map((p) => [p.id, p.id === "probe.access_token_as_id_token" ? "skip" : "pass"])));
    expect(check?.results).toContain("access token is its ID token");
    expect(idp.requests).toHaveLength(2 + PROBES.length - 1);
  });

  it("probes: an OAuth error sent with HTTP 200 is a refusal with the wrong status, at best a warn", async () => {
    const { probes, check } = await probeRun("ok200", "error-200");
    expect(probes).toEqual(Object.fromEntries(PROBES.map((p) => [p.id, "warn"])));
    expect(check?.results).toContain("RFC 6749 section 5.2");
  });

  it("HEAD /flow/callback is refused: it doesn't spend the run or reach the IdP", async () => {
    const t = await registeredTester("header");
    const { to } = await start(t);
    if (!to) throw new Error("no link");
    const params = new URLSearchParams({ code: signInAtIdp(to), state: to.searchParams.get("state") ?? "" });
    const head = await call(`/flow/callback?${params}`, { method: "HEAD", cookie: t.cookie });
    expect(head.status).toBe(405);
    expect(head.headers.get("allow")).toBe("GET");
    expect(idp.requests).toEqual([]);
    expect(await rows(`select 1 from testerFlow where registrationId = ?`, t.registrationId)).toHaveLength(1);
    expect((await call(`/flow/callback?${params}`, { cookie: t.cookie })).status).toBe(302);
    // Other pages still answer HEAD.
    expect((await call("/", { method: "HEAD" })).status).toBe(200);
  });

  it("an ID-JAG the tester keeps from the receiver for another reason says which", async () => {
    // Too large for the tester's token endpoint.
    const big = await registeredTester("bigjag");
    idp.mode = "huge-id-jag";
    const first = await start(big);
    if (!first.to) throw new Error("no link");
    expect((await callback(big.cookie, { code: signInAtIdp(first.to), state: first.to.searchParams.get("state") ?? "" })).status).toBe(302);
    expect(await lastCheck(big.registrationId)).toMatchObject({ httpStatus: 0, error: "too_large" });
    expect(await (await call("/results", { cookie: big.cookie })).text()).toContain("too large for the tester&#39;s token endpoint");
    // The registration's own client can't be used (its secret can't be opened).
    idp.mode = "good";
    const broken = await registeredTester("brokenclient");
    const second = await start(broken);
    if (!second.to) throw new Error("no link");
    await env.DB.prepare(`update testerRegistration set clientSecretEnc = ? where id = ?`).bind("not-sealed", broken.registrationId).run();
    expect((await callback(broken.cookie, { code: signInAtIdp(second.to), state: second.to.searchParams.get("state") ?? "" })).status).toBe(302);
    expect(await lastCheck(broken.registrationId)).toMatchObject({ httpStatus: 0, error: "client_refused" });
    expect(await (await call("/results", { cookie: broken.cookie })).text()).toContain("own client for this registration couldn&#39;t redeem it");
  });

  it("the ID token: sub, exp and iat present; azp, if present or with several audiences, is the IdP client", async () => {
    const t = await registeredTester("claims");
    for (const [mode, says] of [["no-exp", "exp"], ["azp-other", "azp"]] as const) {
      idp.mode = mode;
      const { to } = await start(t);
      if (!to) throw new Error("no link");
      const r = await callback(t.cookie, { code: signInAtIdp(to), state: to.searchParams.get("state") ?? "" });
      expect(r.status).toBe(400);
      expect(await r.text()).toContain(says);
    }
    expect(idp.requests.map((r) => r.grant)).toEqual(["authorization_code", "authorization_code"]);
  });

  it("the IdP's text shown back is cut short", async () => {
    const t = await registeredTester("longtext");
    const { to } = await start(t);
    if (!to) throw new Error("no link");
    const r = await callback(t.cookie, { state: to.searchParams.get("state") ?? "", error: "e".repeat(500), error_description: "d".repeat(5000) });
    const html = await r.text();
    expect(html).toContain(`${"e".repeat(64)}…`);
    expect(html).toContain(`${"d".repeat(200)}…`);
    expect(html).not.toContain("d".repeat(201));
  });

  it("a run with the probes and the refresh token: still nothing of the IdP's kept", async () => {
    const t = await registeredTester("everything");
    const { to } = await start(t, { probes: "1", refresh: "1" });
    if (!to) throw new Error("no link");
    expect((await callback(t.cookie, { code: signInAtIdp(to), state: to.searchParams.get("state") ?? "" })).status).toBe(302);
    expect(idp.requests).toHaveLength(2 + PROBES.length + 1);
    const tables = (await rows<{ name: string }>(`select name from sqlite_master where type = 'table' and name not like 'sqlite_%' and name not like '_cf_%'`)).map((r) => r.name);
    const dump = JSON.stringify(await Promise.all(tables.map((t2) => rows(`select * from "${t2}"`))));
    expect(dump).not.toContain(IDP_SECRET);
    for (const token of [...idp.issued, ...idp.refreshTokens]) expect(dump).not.toContain(token);
  });

  it("against our own issuer plugin as the IdP: a run with the probes and the refresh token, every probe refused as the draft says", async () => {
    // The package's issuer (oauthProvider + jwt + idJagIssuer) on its own database, its policy as the demo IdP's:
    // the tester's authorization server and resource only, the tester's client there named in the ID-JAG.
    let testerClientId = "";
    own = await createIssuerHost({
      baseURL: OWN_BASE,
      database: (cf.env as unknown as { IDP_DB: unknown }).IDP_DB,
      issuer: {
        authorize: ({ audience, resource }) => {
          if (audience !== `${ORIGIN}/api/auth`) return { decision: "unknown_audience", reason: "not the tester" };
          if (resource !== undefined && resource !== `${ORIGIN}/mcp`) return { decision: "unknown_resource", reason: "not the tester's resource" };
          return { decision: "allow", scopes: ["read"], resource: `${ORIGIN}/mcp`, clientIdAtResource: testerClientId, claims: { email: true } };
        },
      },
    });
    const host = own;
    try {
      const admin = await signUp(host);
      const client = await createClient(host, admin.browser, { grantTypes: ["authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:token-exchange"], extra: { redirect_uris: [`${ORIGIN}/flow/callback`], scope: "openid profile email offline_access" } });
      const t = await signedIn("ownidp");
      expect((await post("/register", t.cookie, { issuer: host.issuerUrl, authMethod: "client_secret_basic", "cf-turnstile-response": "ok" })).status).toBe(200);
      const reg = (await rows<{ id: string; clientId: string }>(`select id, clientId from testerRegistration where userId = ?`, t.userId))[0];
      if (!reg) throw new Error("not registered");
      testerClientId = reg.clientId;

      const { to } = await start({ cookie: t.cookie, registrationId: reg.id }, { client_id: client.client_id, client_secret: client.client_secret, probes: "1", refresh: "1" });
      if (!to) throw new Error("no link");
      expect(to.origin + to.pathname).toBe(`${host.issuerUrl}/oauth2/authorize`);
      // The person signs in at the IdP and, for offline_access with prompt=consent, consents.
      const user = await signUp(host);
      // The issuer puts email in an ID-JAG only when it is verified.
      await host.ctx.adapter.update({ model: "user", where: [{ field: "id", value: user.id }], update: { emailVerified: true } });
      let back = new URL((await user.browser.fetch(to.href)).headers.get("location") ?? "", OWN_BASE);
      if (back.pathname === "/consent") {
        const consent = await user.browser.fetch(`${host.issuerUrl}/oauth2/consent`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ accept: true, oauth_query: back.search.slice(1) }) });
        back = new URL(((await consent.json()) as { url: string }).url, OWN_BASE);
      }
      expect(back.origin + back.pathname).toBe(`${ORIGIN}/flow/callback`);
      expect(back.searchParams.get("iss")).toBe(host.issuerUrl);
      const done = await call(`/flow/callback?${back.searchParams}`, { cookie: t.cookie });
      expect(done.status).toBe(302);

      const check = await lastCheck(reg.id);
      expect(check?.httpStatus).toBe(200);
      const results = JSON.parse(check?.results ?? "[]") as { id: string; outcome: string; message: string }[];
      const notPassed = results.filter((r) => r.outcome !== "pass" && r.outcome !== "info").map((r) => `${r.id} ${r.outcome}: ${r.message}`);
      expect(notPassed).toEqual([]);
      expect(results.filter((r) => r.id.startsWith("probe.")).map((r) => r.id)).toEqual(PROBES.map((p) => p.id));
      expect(results.find((r) => r.id === "exchange.refresh_subject")?.message).toContain("Supported");
      expect((await rows<{ confirmedAt: number | null }>(`select confirmedAt from testerRegistration where id = ?`, reg.id))[0]?.confirmedAt).not.toBeNull();
    } finally {
      own = undefined;
    }
  });
});
