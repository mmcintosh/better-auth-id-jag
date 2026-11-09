// The "test your IdP" Worker end to end, in workerd on D1 (examples/workers/tester): register an issuer (pending),
// confirm it with an ID-JAG signed by the issuer's key, redeem at the real receiver, read the report; and the
// lockdown: squatters, limits, isolation, the admin keys and blocklist, both kill switches, revocation, "delete my
// data", what is (not) stored about testers, expiry and the purge. Turnstile and the issuers' metadata are stubbed at
// fetch; sign-in is reproduced from what Better Auth's GitHub sign-in leaves behind; the rest is the Worker as deployed.
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import init0001 from "../../examples/workers/tester/migrations/0001_init.sql?raw";
import init0002 from "../../examples/workers/tester/migrations/0002_tester.sql?raw";

const workerd = navigator.userAgent === "Cloudflare-Workers";
const ORIGIN = "https://tester.example.net";
const AUD = `${ORIGIN}/api/auth`;
const SECRET = "tester-test-secret-that-is-at-least-32-characters";
const KEYS = { stats: "s".repeat(40), close: "c".repeat(40), open: "o".repeat(40) };
const IP = "198.51.100.7";
// [2] is never registered at first: it stands for a trust row someone added by hand. [3] and [4]: one user, two
// issuers at once. [5]: two users confirming the same issuer at once.
const ISSUERS = ["https://idp-one.example.org", "https://idp-two.example.org", "https://idp-three.example.org", "https://idp-four.example.org", "https://idp-five.example.org", "https://idp-six.example.org"] as const;

describe.skipIf(!workerd)("tester Worker (workerd, D1)", () => {
  /** The Worker's Env, assembled for the test. */
  let env: Record<string, unknown> & { DB: Cloudflare.Env["DB"]; TESTER_ENABLED: string };
  let worker: { fetch(r: Request, e: unknown, c: unknown): Promise<Response>; scheduled(e: unknown, env: unknown): Promise<void> };
  let LIMITS: Record<string, number>;
  let cf: typeof import("cloudflare:test");
  const signers: Record<string, CryptoKey> = {};
  const jwks: Record<string, unknown> = {};
  let fetchSpy: ReturnType<typeof vi.spyOn>;

  const call = async (path: string, init: RequestInit & { cookie?: string; ip?: string } = {}) => {
    const headers = new Headers(init.headers);
    if (init.cookie) headers.set("cookie", init.cookie);
    headers.set("cf-connecting-ip", init.ip ?? IP);
    const ctx = cf.createExecutionContext();
    const response = await worker.fetch(new Request(`${ORIGIN}${path}`, { ...init, headers }), env, ctx);
    await cf.waitOnExecutionContext(ctx);
    return response;
  };

  let nextAccountId = 1000;
  /** A tester signed in: what Better Auth's GitHub sign-in leaves behind (through the Worker's own hooks), and the cookie. */
  const signedIn = async (login: string, o: { ageDays?: number; accountId?: number } = {}) => {
    const { createAuth } = await import("../../examples/workers/tester/src/auth");
    const ctx = await createAuth(env as never, ORIGIN).$context;
    const id = o.accountId ?? nextAccountId++;
    const user = await ctx.internalAdapter.createUser({ email: `github-${id}@testers.invalid`, name: login, emailVerified: false, accountCreatedAt: new Date(Date.now() - (o.ageDays ?? 2000) * 86_400_000) }, { method: "test" });
    await ctx.internalAdapter.linkAccount({ userId: user.id, providerId: "github", accountId: String(id), accessToken: `token-${login}`, refreshToken: "r" });
    const s = await ctx.internalAdapter.createSession(user.id);
    const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const sig = btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(s.token)))));
    return { cookie: `${ctx.authCookies.sessionToken.name}=${encodeURIComponent(`${s.token}.${sig}`)}`, userId: user.id };
  };

  const register = async (cookie: string, issuer: string, o: { origin?: string; ip?: string } = {}) =>
    call("/register", { method: "POST", cookie, ip: o.ip ?? IP, headers: { origin: o.origin ?? ORIGIN, "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ issuer, authMethod: "client_secret_basic", "cf-turnstile-response": "ok" }).toString() });

  const credentials = async (page: Response | string) => {
    const html = typeof page === "string" ? page : await page.text();
    const secret = html.match(/shown once:<\/strong> copy it now\.<\/p><pre>([^<]+)<\/pre>/)?.[1];
    const clientId = html.match(/<td><code>client_id<\/code><\/td><td><code>([^<]+)<\/code>/)?.[1];
    if (!secret || !clientId) throw new Error(`no credentials in: ${html.slice(0, 400)}`);
    return { clientId, secret };
  };

  const idJag = (issuer: string, clientId: string, claims: Record<string, unknown> = {}, header: Record<string, unknown> = {}, signer: string = issuer) => {
    const now = Math.floor(Date.now() / 1000);
    return new SignJWT({ iss: issuer, sub: "u1", aud: AUD, client_id: clientId, jti: crypto.randomUUID(), iat: now, exp: now + 300, resource: `${ORIGIN}/mcp`, scope: "read", ...claims })
      .setProtectedHeader({ alg: "RS256", typ: "oauth-id-jag+jwt", kid: "k1", ...header })
      .sign(signers[signer] as CryptoKey);
  };

  const redeem = (c: { clientId: string; secret: string }, assertion: string) =>
    call("/api/auth/oauth2/token", { method: "POST", headers: { authorization: `Basic ${btoa(`${c.clientId}:${c.secret}`)}`, "content-type": "application/x-www-form-urlencoded", "user-agent": "curl/8.0" }, body: new URLSearchParams({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion }).toString() });

  const rows = async <T>(sql: string, ...binds: unknown[]) => (await env.DB.prepare(sql).bind(...binds).all()).results as T[];
  const lastCheck = async () => (await rows<{ results: string; error: string | null; httpStatus: number; checkedAgainst: string }>(`select results, error, httpStatus, checkedAgainst from testerCheck order by at desc, rowid desc limit 1`))[0];
  const failed = (check: { results: string } | undefined) => (JSON.parse(check?.results ?? "[]") as { id: string; outcome: string }[]).filter((r) => r.outcome === "fail").map((r) => r.id);

  beforeAll(async () => {
    cf = await import("cloudflare:test");
    const ok = { limit: async () => ({ success: true }) };
    env = { DB: cf.env.DB, BETTER_AUTH_SECRET: SECRET, GITHUB_CLIENT_ID: "gh", GITHUB_CLIENT_SECRET: "gh-secret", GITLAB_CLIENT_ID: "gl", GITLAB_CLIENT_SECRET: "gl-secret", TURNSTILE_SITE_KEY: "site", TURNSTILE_SECRET_KEY: "turnstile", TESTER_ENABLED: "true", ADMIN_STATS_KEY: KEYS.stats, ADMIN_CLOSE_KEY: KEYS.close, ADMIN_OPEN_KEY: KEYS.open, TOKEN_LIMIT: ok, IP_LIMIT: ok, MCP_LIMIT: ok };
    for (const sql of [init0001, init0002]) for (const stmt of sql.replace(/^--.*$/gm, "").split(/;\s*\n/).map((s: string) => s.trim()).filter(Boolean)) await env.DB.prepare(stmt).run();
    for (const issuer of ISSUERS) {
      const pair = await generateKeyPair("RS256", { extractable: true });
      signers[issuer] = pair.privateKey;
      jwks[issuer] = { keys: [{ ...(await exportJWK(pair.publicKey)), kid: "k1", alg: "RS256", use: "sig" }] };
    }
    const real = globalThis.fetch;
    fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = input instanceof Request ? input.url : String(input);
      for (const issuer of ISSUERS) {
        if (url === `${new URL(issuer).origin}/.well-known/oauth-authorization-server`) return Response.json({ issuer, jwks_uri: `${issuer}/jwks`, token_endpoint: `${issuer}/token`, identity_chaining_requested_token_types_supported: ["urn:ietf:params:oauth:token-type:id-jag"] });
        if (url === `${issuer}/jwks`) return Response.json(jwks[issuer]);
      }
      if (url === "https://github.com/login/oauth/access_token") return Response.json({ access_token: "gho_test", token_type: "bearer", scope: "read:user" });
      if (url === "https://api.github.com/user") return Response.json({ id: 555, login: "octo", email: "octo@example.com", avatar_url: "https://avatars.example/octo.png", created_at: "2015-01-01T00:00:00Z" });
      if (url === "https://api.github.com/user/emails") return new Response("not found", { status: 404 });
      if (url === "https://challenges.cloudflare.com/turnstile/v0/siteverify") return Response.json({ success: (init?.body as URLSearchParams | undefined)?.get?.("response") === "ok" });
      if (url.startsWith(ORIGIN)) return real(input, init);
      return new Response("not found", { status: 404 });
    });
    const mod = await import("../../examples/workers/tester/src/index");
    worker = mod.default as never;
    LIMITS = mod.LIMITS as never;
    // Room for every registration these tests make; the daily caps are tested on their own.
    LIMITS.registrationsPerDay = 100;
    LIMITS.registrationsPerIpPerDay = 100;
    // Six RSA keys and the schema: slow on a loaded runner, so the whole test timeout, not a hook's 10 s.
  }, 60_000);

  afterAll(() => fetchSpy?.mockRestore());

  let alice: { cookie: string; userId: string };
  let aliceClient: { clientId: string; secret: string };
  let mallory: { cookie: string; userId: string };
  let malloryClient: { clientId: string; secret: string };

  it("a real GitHub sign-in (through the callback) keeps the login and account age, and nothing else", async () => {
    const home = await call("/");
    expect(home.headers.get("content-security-policy")).toContain("form-action 'self' https://github.com https://gitlab.com");
    expect(await home.clone().text()).toContain('<link rel="icon" href="/logo.svg"');
    const logo = await call("/logo.svg");
    expect(logo.headers.get("content-type")).toBe("image/svg+xml");
    expect(await logo.text()).toMatch(/^<svg /);
    const start = await call("/signin", { method: "POST", headers: { origin: ORIGIN, "content-type": "application/x-www-form-urlencoded" }, body: "provider=github" });
    expect(start.status).toBe(302);
    const authorize = new URL(start.headers.get("location") ?? "");
    expect(authorize.origin + authorize.pathname).toBe("https://github.com/login/oauth/authorize");
    expect(authorize.searchParams.get("scope")).toBe("read:user");
    const jar = start.headers.getSetCookie().map((c) => c.split(";")[0]).join("; ");
    const back = await call(`/api/auth/callback/github?code=test-code&state=${encodeURIComponent(authorize.searchParams.get("state") ?? "")}`, { cookie: jar, headers: { "user-agent": "TesterBrowser/1.0" } });
    expect(back.status, await back.clone().text()).toBe(302);
    expect(back.headers.get("location")).toContain("/register");
    const [user] = await rows<{ id: string; email: string; name: string; image: string | null; accountCreatedAt: string | null }>(`select id, email, name, image, accountCreatedAt from "user" where email = 'github-555@testers.invalid'`);
    expect(user).toMatchObject({ name: "octo", image: null });
    expect(user?.accountCreatedAt).toBeTruthy();
    expect(await rows(`select accessToken, refreshToken, idToken, scope from "account" where userId = ?`, user?.id)).toEqual([{ accessToken: null, refreshToken: null, idToken: null, scope: "read:user" }]);
    expect(await rows(`select ipAddress, userAgent from "session" where userId = ?`, user?.id)).toEqual([{ ipAddress: null, userAgent: null }]);
    expect(JSON.stringify(await rows(`select * from "user"`))).not.toContain("octo@example.com");
    // And that tester can register: the account age came through the real sign-in.
    const session = back.headers.getSetCookie().map((c) => c.split(";")[0]).join("; ");
    expect(await (await register(session, ISSUERS[1])).text()).toContain("Registered, pending");
  });

  it("sign-in keeps the login and account age, never the email, picture or provider tokens", async () => {
    const { createAuth } = await import("../../examples/workers/tester/src/auth");
    const options = createAuth(env as never, ORIGIN).options as unknown as { socialProviders: Record<string, { mapProfileToUser(p: unknown): Record<string, unknown>; scope?: string[]; disableDefaultScope?: boolean }> };
    const gh = options.socialProviders.github;
    expect(gh?.disableDefaultScope).toBe(true);
    expect(gh?.scope).toEqual(["read:user"]);
    expect(gh?.mapProfileToUser({ id: 42, login: "octo", email: "octo@example.com", avatar_url: "https://x/a.png", created_at: "2015-01-01T00:00:00Z" })).toEqual({ email: "github-42@testers.invalid", name: "octo", image: undefined, emailVerified: false, accountCreatedAt: new Date("2015-01-01T00:00:00Z") });
    expect(options.socialProviders.gitlab?.mapProfileToUser({ id: 7, username: "tanuki", email: "t@example.com", created_at: "2016-01-01T00:00:00Z" })).toMatchObject({ email: "gitlab-7@testers.invalid", name: "tanuki" });
    alice = await signedIn("alice");
    expect(await rows(`select accessToken, refreshToken, idToken from "account" where userId = ?`, alice.userId)).toEqual([{ accessToken: null, refreshToken: null, idToken: null }]);
    const home = await (await call("/")).text();
    expect(home).toContain("Sign in with GitHub");
    expect(home).toContain("Sign in with GitLab");
  });

  it("a tester registers an issuer: pending, a client, no trust row yet; the abuse record holds fingerprints only", async () => {
    const page = await register(alice.cookie, ISSUERS[0]);
    expect(page.status).toBe(200);
    const html = await page.text();
    expect(html).toContain("Registered, pending");
    expect(html).toContain(AUD);
    aliceClient = await credentials(html);
    expect(await rows(`select id from "idJagTrustedIssuer"`)).toEqual([]);
    const [ends] = await rows<{ expiresAt: number; sessionEnds: string }>(`select r.expiresAt, (select max(s.expiresAt) from "session" s where s.userId = r.userId) as sessionEnds from testerRegistration r where r.clientId = ?`, aliceClient.clientId);
    expect(ends?.expiresAt).toBeLessThanOrEqual(Date.parse(ends?.sessionEnds ?? ""));
    const abuse = await rows<Record<string, unknown>>(`select * from testerAbuse where id = (select id from testerRegistration where clientId = ?)`, aliceClient.clientId);
    expect(abuse).toHaveLength(1);
    const text = JSON.stringify(abuse);
    for (const personal of ["alice", IP, "198.51.100", alice.userId]) expect(text).not.toContain(personal);
    expect(abuse[0]).toMatchObject({ provider: "github", accountAge: "over 5 years", issuerHost: "idp-one.example.org", confirmed: 0 });
    // Nothing anywhere stores the address itself.
    for (const table of ["testerRegistration", "testerCheck", "testerAbuse", "testerKey", "testerBlock"]) expect(JSON.stringify(await rows(`select * from ${table}`))).not.toContain("198.51.100");
  });

  it("a pending issuer can be registered by others too; only the issuer's key confirms", async () => {
    mallory = await signedIn("mallory");
    malloryClient = await credentials(await register(mallory.cookie, ISSUERS[0]));
    // Mallory doesn't have the issuer's key: the ID-JAG is refused, nothing is confirmed, and the report says why.
    expect((await redeem(malloryClient, await idJag(ISSUERS[0], malloryClient.clientId, {}, {}, ISSUERS[1]))).status).toBe(400);
    const check = await lastCheck();
    expect(check?.error).toBe("not_confirmed");
    expect(failed(check)).toContain("signature");
    expect(await rows(`select id from "idJagTrustedIssuer"`)).toEqual([]);
  });

  it("the first correctly signed ID-JAG confirms the registration and is redeemed; the MCP tools answer", async () => {
    const response = await redeem(aliceClient, await idJag(ISSUERS[0], aliceClient.clientId));
    const body = (await response.json()) as { access_token?: string; scope?: string };
    expect(response.status, JSON.stringify(body)).toBe(200);
    expect(body.scope).toBe("read");
    const [trust] = await rows<{ allowedClientIds: string }>(`select allowedClientIds from "idJagTrustedIssuer" where issuer = ?`, ISSUERS[0]);
    expect(trust?.allowedClientIds).toBe(JSON.stringify([aliceClient.clientId]));
    const check = await lastCheck();
    expect(check?.httpStatus).toBe(200);
    expect(failed(check)).toEqual([]);
    expect(check?.checkedAgainst).toMatch(/^draft-ietf-oauth-identity-assertion-authz-grant-06; better-auth-id-jag \d+\.\d+\.\d+/);
    expect(await rows(`select confirmed from testerAbuse where confirmed = 1`)).toHaveLength(1);
    expect(await rows(`select id from "idJagAudit" where ipAddress is not null or userAgent is not null`)).toEqual([]);

    const mcp = (method: string, params: unknown = {}) => call("/mcp", { method: "POST", headers: { authorization: `Bearer ${body.access_token}`, "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) });
    const whoami = (await (await mcp("tools/call", { name: "whoami" })).json()) as { result: { content: { text: string }[] } };
    expect(JSON.parse(whoami.result.content[0]?.text ?? "{}")).toMatchObject({ scope: "read" });
    const checks = (await (await mcp("tools/call", { name: "checks" })).json()) as { result: { content: { text: string }[] } };
    expect(JSON.parse(checks.result.content[0]?.text ?? "[]")[0]).toMatchObject({ httpStatus: 200 });
  });

  it("once proven, the issuer is held: the squatter can't take it, and nobody else can register it", async () => {
    expect((await redeem(malloryClient, await idJag(ISSUERS[0], malloryClient.clientId))).status).toBe(400);
    expect((await lastCheck())?.error).toBe("issuer_taken");
    expect(await rows(`select id from "idJagTrustedIssuer" where issuer = ?`, ISSUERS[0])).toHaveLength(1);
    expect(await (await register((await signedIn("trent")).cookie, ISSUERS[0])).text()).toContain("Another tester has proven that issuer");
  });

  it("the reservation itself refuses an issuer someone has proven, whatever got past the page's own check", async () => {
    const store = await import("../../examples/workers/tester/src/store");
    const now = Date.now();
    const reg = { id: "direct", userId: "nobody", issuer: ISSUERS[0], jwksUri: "", jwks: "{}", jwksFetchedAt: now, clientId: "", trustRowId: "", authMethod: "client_secret_basic", metadataReport: "[]", blockAccountFp: "a", blockNetFp: "n", createdAt: now, expiresAt: now + 3_600_000, confirmedAt: null, revokedAt: null, revokedReason: null };
    const abuse = { id: "direct", at: now, keyId: "w0", provider: "github", accountFp: "x", ipFp: "y", netFp: "z", blockAccountFp: "ba", blockNetFp: "bn", accountAge: "over 5 years", issuerHost: "idp-one.example.org" };
    expect(await store.reserve(env.DB as never, reg, abuse, { day: 0, perDay: 100, perAccount: 100, perIp: 100 })).toBe(false);
    expect(await rows(`select id from testerAbuse where id = 'direct'`)).toEqual([]);
  });

  it("an unknown client is refused before the receiver; only jwt-bearer is accepted; other Better Auth paths are closed", async () => {
    expect((await redeem({ clientId: "nobody", secret: "x" }, "a.b.c")).status).toBe(401);
    expect((await call("/api/auth/oauth2/token", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: "grant_type=client_credentials" })).status).toBe(400);
    for (const path of ["/api/auth/sign-up/email", "/api/auth/oauth2/register", "/api/auth/sign-in/email", "/api/auth/admin/oauth2/create-client"]) expect((await call(path, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" })).status, path).toBe(404);
    expect((await call("/api/auth/oauth2/authorize?client_id=x")).status).toBe(404);
  });

  it("a bad ID-JAG is refused by the receiver and the report names every rule it broke", async () => {
    const response = await redeem(aliceClient, await idJag(ISSUERS[0], aliceClient.clientId, { scope: undefined, aud: [AUD, "https://x.example"] }, { typ: "JWT" }));
    expect(response.status).toBe(400);
    const check = await lastCheck();
    expect(failed(check)).toEqual(expect.arrayContaining(["header.typ", "claim.aud", "claim.scope"]));
    expect(check?.error).toBe("invalid_grant");
  });

  it("the results page shows the reports, escaped, with the registration's state and the delete button", async () => {
    await redeem(aliceClient, await idJag(ISSUERS[0], aliceClient.clientId, { aud: "<script>alert(1)</script>", jti: "<img src=x onerror=alert(1)>" }));
    const html = await (await call("/results", { cookie: alice.cookie })).text();
    expect(html).toContain(ISSUERS[0]);
    expect(html).toContain("every rule passed");
    expect(html).toContain("Confirmed.");
    expect(html).toContain("Delete my data now");
    expect(html).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
    expect(html).not.toContain("<script>alert");
    expect(html).not.toContain("<img src=x");
    expect(await (await call("/results", { cookie: mallory.cookie })).text()).toContain("Pending");
  });

  it("one active registration per tester, accounts at least 30 days old, same-origin forms only", async () => {
    expect(await (await register(alice.cookie, ISSUERS[1])).text()).toContain("one at a time");
    expect(await (await register((await signedIn("newbie", { ageDays: 3 })).cookie, ISSUERS[1])).text()).toContain("at least 30 days old");
    expect((await register((await signedIn("bob")).cookie, ISSUERS[1], { origin: "https://evil.example" })).status).toBe(403);
  });

  it("issuers are isolated: the same sub at two issuers is two sandbox users, and neither is a tester", async () => {
    const bobClient = await credentials(await register((await signedIn("bob2")).cookie, ISSUERS[1]));
    expect((await redeem(bobClient, await idJag(ISSUERS[1], bobClient.clientId))).status).toBe(200);
    expect((await redeem(aliceClient, await idJag(ISSUERS[1], aliceClient.clientId))).status).toBe(400);
    expect((await redeem(bobClient, await idJag(ISSUERS[0], bobClient.clientId))).status).toBe(400);
    expect(await rows(`select reason from "idJagAudit" where reason = 'client_mismatch' and clientId in (?, ?)`, aliceClient.clientId, bobClient.clientId)).toHaveLength(2);
    const sandbox = await rows<{ email: string }>(`select email from "user" where email like '%.sandbox.invalid'`);
    expect(new Set(sandbox.map((u) => u.email.split("@")[1])).size).toBe(2);
    expect(await rows(`select id from "account" where userId in (select id from "user" where email like '%.sandbox.invalid')`)).toEqual([]);
  });

  it("a trust row that isn't the registration's own never gets a sandbox user, even with no client restriction", async () => {
    const now = new Date().toISOString();
    await env.DB.prepare(`insert into "idJagTrustedIssuer" (id, issuer, jwksUri, jitProvisioning, jitTrustEmailVerified, enabled, createdAt, updatedAt) values ('by-hand', ?, ?, 0, 0, 1, ?, ?)`).bind(ISSUERS[2], `${ISSUERS[2]}/jwks`, now, now).run();
    try {
      const before = (await rows(`select id from "user"`)).length;
      expect((await redeem(aliceClient, await idJag(ISSUERS[2], aliceClient.clientId))).status).toBe(400);
      expect((await rows(`select id from "user"`)).length).toBe(before);
      expect(await rows(`select reason from "idJagAudit" where iss = ? and reason = 'subject_rejected'`, ISSUERS[2])).toHaveLength(1);
    } finally {
      await env.DB.prepare(`delete from "idJagTrustedIssuer" where id = 'by-hand'`).run();
    }
  });

  it("at the same moment: one user gets one registration; two users proving one issuer get one trust row", async () => {
    const carol = await signedIn("carol");
    const both = await Promise.all([register(carol.cookie, ISSUERS[3]), register(carol.cookie, ISSUERS[4])]);
    expect((await Promise.all(both.map((r) => r.text()))).filter((t) => t.includes("shown once"))).toHaveLength(1);
    const [erin, frank] = await Promise.all([signedIn("erin"), signedIn("frank")]);
    const clients = [await credentials(await register(erin.cookie, ISSUERS[5])), await credentials(await register(frank.cookie, ISSUERS[5]))];
    const answers = await Promise.all(clients.map(async (c) => redeem(c, await idJag(ISSUERS[5], c.clientId))));
    expect(answers.map((r) => r.status).sort()).toEqual([200, 400]);
    expect(await rows(`select id from "idJagTrustedIssuer" where issuer = ?`, ISSUERS[5])).toHaveLength(1);
    // The winner sending two more at once is never told another tester holds its own issuer.
    const winner = clients[answers.findIndex((r) => r.status === 200)] as { clientId: string; secret: string };
    const again = await Promise.all([0, 1].map(async () => (await redeem(winner, await idJag(ISSUERS[5], winner.clientId))).json() as Promise<{ error_description?: string }>));
    expect(again.map((a) => a.error_description ?? "")).not.toContainEqual(expect.stringContaining("Another tester"));
  });

  it("an issuer whose registration just ended can be proven again before the purge runs", async () => {
    await env.DB.prepare(`update testerRegistration set revokedAt = ? where clientId = ?`).bind(Date.now(), aliceClient.clientId).run();
    const grace = await signedIn("grace");
    aliceClient = await credentials(await register(grace.cookie, ISSUERS[0]));
    alice = grace;
    expect((await redeem(aliceClient, await idJag(ISSUERS[0], aliceClient.clientId))).status).toBe(200);
    expect(await rows(`select id from "idJagTrustedIssuer" where issuer = ?`, ISSUERS[0])).toHaveLength(1);
  });

  it("the daily registration cap holds", async () => {
    const before = LIMITS.registrationsPerDay;
    LIMITS.registrationsPerDay = (await rows(`select id from testerAbuse`)).length;
    try {
      expect(await (await register((await signedIn("heidi")).cookie, ISSUERS[2])).text()).toContain("used up");
    } finally {
      LIMITS.registrationsPerDay = before as number;
    }
  });

  it("only requests the receiver authenticated are counted or shown; one client authentication method at a time", async () => {
    const count = async () => (await rows(`select id from testerCheck`)).length;
    const before = await count();
    expect((await redeem({ clientId: aliceClient.clientId, secret: "wrong" }, await idJag(ISSUERS[0], aliceClient.clientId))).status).toBe(401);
    expect(await count()).toBe(before);
    const mixed = await call("/api/auth/oauth2/token", { method: "POST", headers: { authorization: `Basic ${btoa(`${aliceClient.clientId}:wrong`)}`, "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion: "a.b.c", client_id: "other", client_secret: "x" }).toString() });
    expect(mixed.status).toBe(400);
    expect(await count()).toBe(before);
    // Mallory's own credentials in a Basic header the receiver accepts (two spaces), Alice's client id in the body.
    const smuggled = await call("/api/auth/oauth2/token", { method: "POST", headers: { authorization: `Basic  ${btoa(`${malloryClient.clientId}:${malloryClient.secret}`)}`, "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion: "a.b.c", client_id: aliceClient.clientId }).toString() });
    expect(smuggled.status).toBe(400);
    expect(await count()).toBe(before);
    // A Basic header the receiver accepts is read the same way here: two spaces still work.
    const spaced = await call("/api/auth/oauth2/token", { method: "POST", headers: { authorization: `Basic  ${btoa(`${aliceClient.clientId}:${aliceClient.secret}`)}`, "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion: await idJag(ISSUERS[0], aliceClient.clientId) }).toString() });
    expect(spaced.status).toBe(200);
  });

  it("a stored JWKS that isn't one is refetched, never a 500", async () => {
    await env.DB.prepare(`update testerRegistration set jwks = 'null', jwksFetchedAt = 0 where clientId = ?`).bind(aliceClient.clientId).run();
    expect((await redeem(aliceClient, await idJag(ISSUERS[0], aliceClient.clientId))).status).toBe(200);
    expect(failed(await lastCheck())).toEqual([]);
  });

  it("the daily redemption budget stops redemptions until 00:00 UTC without closing the tester", async () => {
    const before = LIMITS.redemptionsPerDay;
    LIMITS.redemptionsPerDay = (await rows(`select id from testerCheck`)).length;
    try {
      expect((await redeem(aliceClient, await idJag(ISSUERS[0], aliceClient.clientId))).status).toBe(503);
      expect(await rows(`select closed from testerState where closed = 1`)).toEqual([]);
    } finally {
      LIMITS.redemptionsPerDay = before as number;
    }
  });

  it("only the configured public origin is served", async () => {
    env.PUBLIC_ORIGIN = "https://elsewhere.example.net";
    try {
      expect((await call("/")).status).toBe(404);
    } finally {
      env.PUBLIC_ORIGIN = "";
    }
  });

  it("admin keys: stats reads fingerprints and counts only; close closes; only the open key reopens", async () => {
    const admin = (path: string, key: string, method = "POST", body: unknown = { reason: "test" }) => call(path, { method, headers: { authorization: `Bearer ${key}`, "content-type": "application/json" }, ...(method === "POST" ? { body: JSON.stringify(body) } : {}) });
    expect((await admin("/admin/stats", "wrong", "GET")).status).toBe(403);
    const statsText = await (await admin("/admin/stats", KEYS.stats, "GET")).text();
    const stats = JSON.parse(statsText) as { checksToday: number; abuseRecord: unknown[] };
    expect(stats.checksToday).toBeGreaterThan(0);
    expect(stats.abuseRecord.length).toBeGreaterThan(0);
    for (const personal of ["alice", "mallory", IP, "testers.invalid"]) expect(statsText).not.toContain(personal);
    expect((await admin("/admin/close", KEYS.stats)).status).toBe(403);
    expect((await admin("/admin/close", KEYS.close)).status).toBe(200);
    expect((await redeem(aliceClient, await idJag(ISSUERS[0], aliceClient.clientId))).status).toBe(503);
    expect((await admin("/admin/open", KEYS.close)).status).toBe(403);
    expect((await admin("/admin/open", KEYS.open)).status).toBe(200);
    expect((await redeem(aliceClient, await idJag(ISSUERS[0], aliceClient.clientId))).status).toBe(200);
  });

  it("blocking: the account and its network stay out, by fingerprint, and the registration ends", async () => {
    const [reg] = await rows<{ id: string }>(`select id from testerRegistration where clientId = ?`, malloryClient.clientId);
    const block = await call("/admin/block", { method: "POST", headers: { authorization: `Bearer ${KEYS.close}`, "content-type": "application/json" }, body: JSON.stringify({ registrationId: reg?.id, kinds: ["account", "network"], reason: "test" }) });
    expect(await block.json()).toEqual({ blocked: ["account", "network"], revoked: true });
    await worker.scheduled({}, env);
    expect(await (await register(mallory.cookie, ISSUERS[2], { ip: "203.0.113.9" })).text()).toContain("register here for now");
    // Someone else from Mallory's network (the next address) is kept out too.
    expect(await (await register((await signedIn("mallory2")).cookie, ISSUERS[2], { ip: "198.51.100.8" })).text()).toContain("register here for now");
    expect(JSON.stringify(await rows(`select * from testerBlock`))).not.toContain("198.51.100");
  });

  it("the deploy-level switch closes everything but the home page and the admin endpoints", async () => {
    env.TESTER_ENABLED = "false";
    try {
      expect((await redeem(aliceClient, await idJag(ISSUERS[0], aliceClient.clientId))).status).toBe(503);
      expect((await call("/signin", { method: "POST", headers: { origin: ORIGIN } })).status).toBe(503);
      expect((await call("/results", { cookie: alice.cookie })).status).toBe(503);
      expect((await call("/api/auth/callback/github?code=x&state=y")).status).toBe(503);
      expect((await call("/mcp", { method: "POST" })).status).toBe(503);
      expect((await call("/")).status).toBe(200);
      expect((await call("/admin/stats", { headers: { authorization: `Bearer ${KEYS.stats}` } })).status).toBe(200);
    } finally {
      env.TESTER_ENABLED = "true";
    }
  });

  it("delete my data now: the registration, its results and the tester's records go at once; the abuse record stays", async () => {
    const ivan = await signedIn("ivan");
    // From another network: the blocklist test above blocked this file's usual one.
    const ivanClient = await credentials(await register(ivan.cookie, ISSUERS[2], { ip: "192.0.2.10" }));
    expect((await redeem(ivanClient, await idJag(ISSUERS[2], ivanClient.clientId))).status).toBe(200);
    const [reg] = await rows<{ id: string }>(`select id from testerRegistration where userId = ?`, ivan.userId);
    expect((await call("/delete", { method: "POST", cookie: ivan.cookie, headers: { origin: "https://evil.example" } })).status).toBe(403);
    // Deleting works even while the tester is closed.
    await env.DB.prepare(`insert into testerState (id, closed, reason, changedAt, changedBy) values ('main', 1, 'test', 0, 'test') on conflict (id) do update set closed = 1`).run();
    const done = await call("/delete", { method: "POST", cookie: ivan.cookie, headers: { origin: ORIGIN } });
    await env.DB.prepare(`update testerState set closed = 0`).run();
    expect(done.status).toBe(200);
    expect(await rows(`select id from "user" where id = ?`, ivan.userId)).toEqual([]);
    expect(await rows(`select id from "session" where userId = ?`, ivan.userId)).toEqual([]);
    expect(await rows(`select id from "account" where userId = ?`, ivan.userId)).toEqual([]);
    expect(await rows(`select id from testerRegistration where userId = ?`, ivan.userId)).toEqual([]);
    expect(await rows(`select id from "oauthClient" where clientId = ?`, ivanClient.clientId)).toEqual([]);
    expect(await rows(`select id from testerCheck where registrationId = ?`, reg?.id)).toEqual([]);
    expect(await rows(`select id from "idJagTrustedIssuer" where issuer = ?`, ISSUERS[2])).toEqual([]);
    expect(await rows(`select ended from testerAbuse where id = ?`, reg?.id)).toEqual([{ ended: "deleted by the tester" }]);
  });

  it("an abuser who deleted their data can still be blocked, for the abuse record's 7 days", async () => {
    const oscar = await signedIn("oscar", { accountId: 77 });
    await credentials(await register(oscar.cookie, ISSUERS[2], { ip: "192.0.2.20" }));
    const [reg] = await rows<{ id: string }>(`select id from testerRegistration where userId = ?`, oscar.userId);
    expect((await call("/delete", { method: "POST", cookie: oscar.cookie, headers: { origin: ORIGIN } })).status).toBe(200);
    const block = await call("/admin/block", { method: "POST", headers: { authorization: `Bearer ${KEYS.close}`, "content-type": "application/json" }, body: JSON.stringify({ registrationId: reg?.id, kinds: ["account"], reason: "test" }) });
    expect(block.status).toBe(200);
    // The same GitHub account, signed in again from elsewhere: kept out.
    expect(await (await register((await signedIn("oscar-again", { accountId: 77 })).cookie, ISSUERS[2], { ip: "192.0.2.99" })).text()).toContain("register here for now");
  });

  it("the purge for an issuer removes trust rows that no active registration holds", async () => {
    const store = await import("../../examples/workers/tester/src/store");
    const now = new Date().toISOString();
    await env.DB.prepare(`insert into "idJagTrustedIssuer" (id, issuer, jwksUri, jitProvisioning, jitTrustEmailVerified, enabled, createdAt, updatedAt) values ('stray', ?, ?, 0, 0, 1, ?, ?)`).bind(ISSUERS[3], `${ISSUERS[3]}/jwks`, now, now).run();
    await store.purge(env.DB as never, Date.now(), ISSUERS[3]);
    expect(await rows(`select id from "idJagTrustedIssuer" where id = 'stray'`)).toEqual([]);
  });

  it("revoking a registration stops its client and tokens at once; expiry and the purge remove everything, testers included", async () => {
    const issued = (await (await redeem(aliceClient, await idJag(ISSUERS[0], aliceClient.clientId))).json()) as { access_token: string };
    const [reg] = await rows<{ id: string }>(`select id from testerRegistration where clientId = ?`, aliceClient.clientId);
    const revoke = await call("/admin/revoke", { method: "POST", headers: { authorization: `Bearer ${KEYS.close}`, "content-type": "application/json" }, body: JSON.stringify({ registrationId: reg?.id, reason: "test" }) });
    expect(await revoke.json()).toEqual({ revoked: true });
    expect((await redeem(aliceClient, await idJag(ISSUERS[0], aliceClient.clientId))).status).toBe(401);
    const mcp = await call("/mcp", { method: "POST", headers: { authorization: `Bearer ${issued.access_token}`, "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "whoami" } }) });
    expect(mcp.status).toBe(401);
    expect(await rows(`select id from "idJagTrustedIssuer" where enabled = 1 and allowedClientIds like ?`, `%${aliceClient.clientId}%`)).toEqual([]);

    // Every registration ends; every sign-in ends; a week passes for the abuse record and two for the keys.
    await env.DB.prepare(`update testerRegistration set expiresAt = ?`).bind(Date.now() - 1).run();
    await env.DB.prepare(`update "session" set expiresAt = ?`).bind(new Date(Date.now() - 1000).toISOString()).run();
    for (let i = 0; i < 3; i++) await worker.scheduled({}, env);
    for (const table of ["oauthClient", "idJagTrustedIssuer", "testerRegistration", "testerCheck", "idJagAudit", "idJagJti", "session", "account", "user"]) expect(await rows(`select * from "${table}"`), table).toEqual([]);
    expect((await rows(`select id from testerAbuse`)).length).toBeGreaterThan(0);
    // The blocklist key stays while any abuse record holds a fingerprint made with it, however old the key.
    await env.DB.prepare(`update testerBlock set expiresAt = ?`).bind(Date.now() - 1).run();
    await env.DB.prepare(`update testerKey set createdAt = ? where id = 'block'`).bind(Date.now() - 15 * 86_400_000).run();
    await worker.scheduled({}, env);
    expect(await rows(`select id from testerKey where id = 'block'`)).toHaveLength(1);
    await env.DB.prepare(`update testerAbuse set at = ?`).bind(Date.now() - 8 * 86_400_000).run();
    await env.DB.prepare(`update testerKey set createdAt = ?`).bind(Date.now() - 15 * 86_400_000).run();
    await env.DB.prepare(`update testerBlock set expiresAt = ?`).bind(Date.now() - 1).run();
    await worker.scheduled({}, env);
    for (const table of ["testerAbuse", "testerKey", "testerBlock"]) expect(await rows(`select * from "${table}"`), table).toEqual([]);
  });
});
