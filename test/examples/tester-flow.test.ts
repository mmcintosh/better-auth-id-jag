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
// what it must, always with invalid_grant.
type Mode = "good" | "lax" | "wrong-codes" | "refuse" | "no-store-missing" | "wrong-nonce" | "other-audience" | "resource-normalised" | "no-id-token" | "no-refresh-subject";

describe.skipIf(!workerd)("tester: run the whole flow (workerd, D1)", () => {
  let env: Record<string, unknown> & { DB: Cloudflare.Env["DB"] };
  let worker: { fetch(r: Request, e: unknown, c: unknown): Promise<Response>; scheduled(e: unknown, env: unknown): Promise<void> };
  let LIMITS: Record<string, number>;
  let cf: typeof import("cloudflare:test");
  let signer: CryptoKey;
  let jwks: unknown;

  /** The stub IdP: what it was sent, and how it answers. */
  const idp = {
    mode: "good" as Mode,
    /** Each issuer's client at the tester, which its ID-JAGs name in client_id. */
    testerClientIds: new Map<string, string>(),
    /** Codes the "browser" brought back from sign-in: the PKCE challenge and nonce they were issued for. */
    codes: new Map<string, { challenge: string; nonce: string; redirectUri: string; scope: string }>(),
    /** Refresh tokens issued (for a sign-in with offline_access). */
    refreshTokens: new Set<string>(),
    requests: [] as { grant: string | null; form: URLSearchParams; authorization: string | null; userAgent: string | null }[],
  };

  const b64url = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const now = () => Math.floor(Date.now() / 1000);
  const sign = (claims: Record<string, unknown>, typ?: string) => new SignJWT(claims).setProtectedHeader({ alg: "RS256", kid: "k1", ...(typ ? { typ } : {}) }).sign(signer);

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
    const exchanging = form.get("grant_type") === "urn:ietf:params:oauth:grant-type:token-exchange";
    const refuse = (error: string, status = 400) => Response.json({ error: idp.mode === "wrong-codes" ? "invalid_grant" : error }, { status: idp.mode === "wrong-codes" ? 400 : status, headers: { "cache-control": "no-store" } });
    if (!authenticated(form, authorization) && !(exchanging && idp.mode === "lax")) return refuse("invalid_client", 401);
    if (form.get("grant_type") === "authorization_code") {
      const issued = idp.codes.get(form.get("code") ?? "");
      idp.codes.delete(form.get("code") ?? "");
      const verifier = form.get("code_verifier") ?? "";
      const challenge = b64url(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))));
      if (!issued || issued.challenge !== challenge || issued.redirectUri !== form.get("redirect_uri")) return Response.json({ error: "invalid_grant" }, { status: 400 });
      if (idp.mode === "no-id-token") return Response.json({ access_token: "at", token_type: "Bearer" }, { headers: { "cache-control": "no-store" } });
      const idToken = await sign({ iss: issuer, sub: "u1", aud: idp.mode === "other-audience" ? "another-client" : IDP_CLIENT, nonce: idp.mode === "wrong-nonce" ? "another" : issued.nonce, iat: now(), exp: now() + 300, email: "u1@idp.example.org" });
      const refreshToken = issued.scope.split(" ").includes("offline_access") ? `rt-${crypto.randomUUID()}` : undefined;
      if (refreshToken) idp.refreshTokens.add(refreshToken);
      return Response.json({ access_token: "at", token_type: "Bearer", id_token: idToken, ...(refreshToken ? { refresh_token: refreshToken } : {}) }, { headers: { "cache-control": "no-store" } });
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
      const idJag = await sign({ iss: issuer, sub: "u1", aud: form.get("audience"), client_id: idp.testerClientIds.get(issuer), jti: crypto.randomUUID(), iat: now(), exp: now() + 300, resource: idp.mode === "resource-normalised" ? `${resource}/` : resource, scope: form.get("scope"), email: "u1@idp.example.org" }, "oauth-id-jag+jwt");
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
    jwks = { keys: [{ ...(await exportJWK(pair.publicKey)), kid: "k1", alg: "RS256", use: "sig" }] };
    const real = globalThis.fetch;
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init);
      const url = request.url;
      const [, issuer, path] = url.match(IDP_URL) ?? [];
      if (issuer && path === "/.well-known/oauth-authorization-server") return Response.json({ issuer, jwks_uri: `${issuer}/jwks`, authorization_endpoint: `${issuer}/authorize?tenant=t1`, token_endpoint: `${issuer}/token`, identity_chaining_requested_token_types_supported: ["urn:ietf:params:oauth:token-type:id-jag"] });
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
    const dump = JSON.stringify(await Promise.all(["testerCheck", "testerRegistration", "idJagAudit"].map((t2) => rows(`select * from "${t2}"`))));
    expect(dump).not.toContain(IDP_SECRET);
    expect(dump).not.toContain("id_token");
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

  it("probes: an IdP that accepts them fails each one", async () => {
    const { probes } = await probeRun("lax", "lax");
    expect(probes).toEqual(Object.fromEntries(PROBES.map((p) => [p.id, "fail"])));
  });

  it("probes: a refusal with another code fails where the draft names the code, and warns where it only profiles one", async () => {
    const { probes } = await probeRun("codes", "wrong-codes");
    expect(probes).toEqual(Object.fromEntries(PROBES.map((p) => [p.id, p.codeRequired ? "fail" : "warn"])));
  });

  it("probes: only when asked for, and the ID-JAG one skipped when the IdP issued none", async () => {
    const { probes } = await probeRun("refusing", "refuse");
    expect(probes["probe.id_jag_as_id_token"]).toBe("skip");
    expect(Object.keys(probes)).toHaveLength(7);
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
    expect((await run("unasked2", "good", false)).rule).toBeUndefined();
  });
});
