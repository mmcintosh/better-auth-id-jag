// The "test your IdP" Worker end to end, in workerd on D1 (examples/workers/tester): register an issuer, redeem
// ID-JAGs at the real receiver, read the report, and the lockdown: one registration at a time, issuers isolated from
// each other, the admin keys, the kill switch, revocation, expiry and the purge. GitHub, Turnstile and the issuers'
// metadata are stubbed at fetch; everything else is the Worker as deployed.
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import init0001 from "../../examples/workers/tester/migrations/0001_init.sql?raw";
import init0002 from "../../examples/workers/tester/migrations/0002_tester.sql?raw";

const workerd = navigator.userAgent === "Cloudflare-Workers";
const ORIGIN = "https://tester.example.net";
const AUD = `${ORIGIN}/api/auth`;
const SECRET = "tester-test-secret-that-is-at-least-32-characters";
const KEYS = { stats: "s".repeat(40), close: "c".repeat(40), open: "o".repeat(40) };
// The third is never registered: it stands for a trust row someone added by hand, without a client restriction.
// The last two are for the same-moment registration test.
const ISSUERS = ["https://idp-one.example.org", "https://idp-two.example.org", "https://idp-three.example.org", "https://idp-four.example.org", "https://idp-five.example.org"] as const;

describe.skipIf(!workerd)("tester Worker (workerd, D1)", () => {
  /** The Worker's Env, assembled for the test. */
  let env: Record<string, unknown> & { DB: Cloudflare.Env["DB"]; TESTER_ENABLED: string };
  let worker: { fetch(r: Request, e: unknown, c: unknown): Promise<Response>; scheduled(e: unknown, env: unknown): Promise<void> };
  let LIMITS: Record<string, number>;
  let cf: typeof import("cloudflare:test");
  const signers: Record<string, CryptoKey> = {};
  const jwks: Record<string, unknown> = {};
  let fetchSpy: ReturnType<typeof vi.spyOn>;

  const call = async (path: string, init: RequestInit & { cookie?: string } = {}) => {
    const headers = new Headers(init.headers);
    if (init.cookie) headers.set("cookie", init.cookie);
    const ctx = cf.createExecutionContext();
    const response = await worker.fetch(new Request(`${ORIGIN}${path}`, { ...init, headers }), env, ctx);
    await cf.waitOnExecutionContext(ctx);
    return response;
  };

  /** A GitHub user signed in to the tester: what Better Auth's GitHub sign-in leaves behind, and the session cookie. */
  const signedIn = async (login: string) => {
    const { createAuth } = await import("../../examples/workers/tester/src/auth");
    const ctx = await createAuth(env as never, ORIGIN).$context;
    const user = await ctx.internalAdapter.createUser({ email: `${login}@users.example.org`, name: login, emailVerified: true }, { method: "test" });
    await ctx.internalAdapter.linkAccount({ userId: user.id, providerId: "github", accountId: `gh-${login}`, accessToken: `token-${login}` });
    const s = await ctx.internalAdapter.createSession(user.id);
    const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const sig = btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(s.token)))));
    return `${ctx.authCookies.sessionToken.name}=${encodeURIComponent(`${s.token}.${sig}`)}`;
  };

  const register = async (cookie: string, issuer: string, origin = ORIGIN) =>
    call("/register", { method: "POST", cookie, headers: { origin, "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ issuer, authMethod: "client_secret_basic", "cf-turnstile-response": "ok" }).toString() });

  const credentials = async (page: Response) => {
    const html = await page.text();
    const secret = html.match(/shown once:<\/strong> copy it now\.<\/p><pre>([^<]+)<\/pre>/)?.[1];
    const clientId = html.match(/<td><code>client_id<\/code><\/td><td><code>([^<]+)<\/code>/)?.[1];
    if (!secret || !clientId) throw new Error(`no credentials in: ${html.slice(0, 400)}`);
    return { clientId, secret };
  };

  const idJag = (issuer: string, clientId: string, claims: Record<string, unknown> = {}, header: Record<string, unknown> = {}) => {
    const now = Math.floor(Date.now() / 1000);
    return new SignJWT({ iss: issuer, sub: "u1", aud: AUD, client_id: clientId, jti: crypto.randomUUID(), iat: now, exp: now + 300, resource: `${ORIGIN}/mcp`, scope: "read", ...claims })
      .setProtectedHeader({ alg: "RS256", typ: "oauth-id-jag+jwt", kid: "k1", ...header })
      .sign(signers[issuer] as CryptoKey);
  };

  const redeem = (c: { clientId: string; secret: string }, assertion: string) =>
    call("/api/auth/oauth2/token", { method: "POST", headers: { authorization: `Basic ${btoa(`${c.clientId}:${c.secret}`)}`, "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion }).toString() });

  const rows = async <T>(sql: string, ...binds: unknown[]) => (await env.DB.prepare(sql).bind(...binds).all()).results as T[];

  beforeAll(async () => {
    cf = await import("cloudflare:test");
    const ok = { limit: async () => ({ success: true }) };
    env = { DB: cf.env.DB, BETTER_AUTH_SECRET: SECRET, GITHUB_CLIENT_ID: "gh", GITHUB_CLIENT_SECRET: "gh-secret", TURNSTILE_SITE_KEY: "site", TURNSTILE_SECRET_KEY: "turnstile", TESTER_ENABLED: "true", ADMIN_STATS_KEY: KEYS.stats, ADMIN_CLOSE_KEY: KEYS.close, ADMIN_OPEN_KEY: KEYS.open, TOKEN_LIMIT: ok, IP_LIMIT: ok, MCP_LIMIT: ok };
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
      if (url === "https://api.github.com/user") {
        const login = String(new Headers(init?.headers).get("authorization")).replace("Bearer token-", "");
        return Response.json({ login, created_at: login === "newbie" ? new Date().toISOString() : "2019-05-01T00:00:00Z" });
      }
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
    // Five RSA keys and the schema: slow on a loaded runner, so the whole test timeout, not a hook's 10 s.
  }, 60_000);

  afterAll(() => fetchSpy?.mockRestore());

  let alice: string;
  let aliceClient: { clientId: string; secret: string };

  it("a tester registers an issuer and gets a client; the page shows the values to mint with", async () => {
    alice = await signedIn("alice");
    const page = await register(alice, ISSUERS[0]);
    expect(page.status).toBe(200);
    aliceClient = await credentials(page.clone());
    expect(await page.text()).toContain(AUD);
    const [trust] = await rows<{ issuer: string; allowedClientIds: string; jitProvisioning: number }>(`select issuer, allowedClientIds, jitProvisioning from "idJagTrustedIssuer"`);
    expect(trust).toMatchObject({ issuer: ISSUERS[0], allowedClientIds: JSON.stringify([aliceClient.clientId]), jitProvisioning: 0 });
  });

  it("a correct ID-JAG is accepted, every rule passes, and the MCP tools answer", async () => {
    const response = await redeem(aliceClient, await idJag(ISSUERS[0], aliceClient.clientId));
    const body = (await response.json()) as { access_token?: string; scope?: string };
    expect(response.status, JSON.stringify(body)).toBe(200);
    expect(body.scope).toBe("read");
    const [check] = await rows<{ httpStatus: number; results: string }>(`select httpStatus, results from testerCheck order by at desc limit 1`);
    expect(check?.httpStatus).toBe(200);
    expect((await rows<{ checkedAgainst: string }>(`select checkedAgainst from testerCheck`))[0]?.checkedAgainst).toMatch(/^draft-ietf-oauth-identity-assertion-authz-grant-06; better-auth-id-jag \d+\.\d+\.\d+/);
    expect((JSON.parse(check?.results ?? "[]") as { outcome: string }[]).filter((r) => r.outcome === "fail")).toEqual([]);

    const mcp = (method: string, params: unknown = {}) => call("/mcp", { method: "POST", headers: { authorization: `Bearer ${body.access_token}`, "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) });
    const whoami = (await (await mcp("tools/call", { name: "whoami" })).json()) as { result: { content: { text: string }[] } };
    expect(JSON.parse(whoami.result.content[0]?.text ?? "{}")).toMatchObject({ scope: "read" });
    const checks = (await (await mcp("tools/call", { name: "checks" })).json()) as { result: { content: { text: string }[] } };
    expect(JSON.parse(checks.result.content[0]?.text ?? "[]")).toHaveLength(1);
  });

  it("a bad ID-JAG is refused by the receiver and the report names every rule it broke", async () => {
    const response = await redeem(aliceClient, await idJag(ISSUERS[0], aliceClient.clientId, { scope: undefined, aud: [AUD, "https://x.example"] }, { typ: "JWT" }));
    expect(response.status).toBe(400);
    const [check] = await rows<{ results: string; error: string }>(`select results, error from testerCheck order by at desc limit 1`);
    const failed = (JSON.parse(check?.results ?? "[]") as { id: string; outcome: string }[]).filter((r) => r.outcome === "fail").map((r) => r.id);
    expect(failed).toEqual(expect.arrayContaining(["header.typ", "claim.aud", "claim.scope"]));
    expect(check?.error).toBe("invalid_grant");
  });

  it("the results page shows the reports, escaped", async () => {
    await redeem(aliceClient, await idJag(ISSUERS[0], aliceClient.clientId, { aud: "<script>alert(1)</script>", jti: "<img src=x onerror=alert(1)>" }));
    const html = await (await call("/results", { cookie: alice })).text();
    expect(html).toContain(ISSUERS[0]);
    expect(html).toContain("every rule passed");
    expect(html).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
    expect(html).not.toContain("<script>alert");
    expect(html).not.toContain("<img src=x");
  });

  it("one active registration per tester, one tester per issuer, accounts at least 30 days old, same-origin forms only", async () => {
    expect(await (await register(alice, ISSUERS[1])).text()).toContain("one at a time");
    const bob = await signedIn("bob");
    expect(await (await register(bob, ISSUERS[0])).text()).toContain("registered by someone else");
    expect(await (await register(await signedIn("newbie"), ISSUERS[1])).text()).toContain("at least 30 days old");
    expect((await register(bob, ISSUERS[1], "https://evil.example")).status).toBe(403);
  });

  it("issuers are isolated: the same sub at two issuers is two sandbox users, and neither is a GitHub user", async () => {
    const bobClient = await credentials(await register(await signedIn("bob2"), ISSUERS[1]));
    expect((await redeem(bobClient, await idJag(ISSUERS[1], bobClient.clientId))).status).toBe(200);
    // Alice's client can't redeem the other issuer's ID-JAG, nor Bob's its own issuer's.
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

  it("an unknown client is refused before the receiver; only jwt-bearer is accepted; other Better Auth paths are closed", async () => {
    expect((await redeem({ clientId: "nobody", secret: "x" }, "a.b.c")).status).toBe(401);
    const cc = await call("/api/auth/oauth2/token", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: "grant_type=client_credentials" });
    expect(cc.status).toBe(400);
    expect((await call("/api/auth/sign-up/email", { method: "POST", headers: { "content-type": "application/json" }, body: "{}" })).status).toBe(404);
    expect((await call("/api/auth/oauth2/register", { method: "POST", headers: { "content-type": "application/json" }, body: "{}" })).status).toBe(404);
  });

  it("registrations at the same moment can't get past the limits", async () => {
    // One user, two issuers at once: one registration.
    const carol = await signedIn("carol");
    const both = await Promise.all([register(carol, ISSUERS[3]), register(carol, ISSUERS[4])]);
    expect((await Promise.all(both.map((r) => r.text()))).filter((t) => t.includes("shown once"))).toHaveLength(1);
    // Two users, one issuer at once: one registration, one trust row.
    const [dave, erin] = await Promise.all([signedIn("dave"), signedIn("erin")]);
    // Alice's registration of that issuer has just ended and the scheduled purge hasn't run: registering must still work.
    await env.DB.prepare(`update testerRegistration set revokedAt = ? where clientId = ?`).bind(Date.now(), aliceClient.clientId).run();
    const race = await Promise.all([register(dave, ISSUERS[0]), register(erin, ISSUERS[0])]);
    const won = (await Promise.all(race.map((r) => r.text()))).filter((t) => t.includes("shown once"));
    expect(won).toHaveLength(1);
    expect(await rows(`select id from "idJagTrustedIssuer" where issuer = ?`, ISSUERS[0])).toHaveLength(1);
    // The winner's client works: a fresh registration of an issuer whose old one was ended and purged.
    aliceClient = await credentials(new Response(won[0]));
    expect((await redeem(aliceClient, await idJag(ISSUERS[0], aliceClient.clientId))).status).toBe(200);
  });

  it("the daily registration cap holds", async () => {
    const before = LIMITS.registrationsPerDay;
    LIMITS.registrationsPerDay = (await rows(`select id from testerRegistration`)).length;
    try {
      expect(await (await register(await signedIn("frank"), ISSUERS[2])).text()).toContain("used up");
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
  });

  it("a stored JWKS that isn't one is refetched, never a 500", async () => {
    await env.DB.prepare(`update testerRegistration set jwks = 'null', jwksFetchedAt = 0 where clientId = ?`).bind(aliceClient.clientId).run();
    expect((await redeem(aliceClient, await idJag(ISSUERS[0], aliceClient.clientId))).status).toBe(200);
    const [check] = await rows<{ results: string }>(`select results from testerCheck order by at desc limit 1`);
    expect((JSON.parse(check?.results ?? "[]") as { id: string; outcome: string }[]).find((r) => r.id === "signature")?.outcome).toBe("pass");
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

  it("admin keys: stats reads, close closes, only the open key reopens", async () => {
    const admin = (path: string, key: string, method = "POST") => call(path, { method, headers: { authorization: `Bearer ${key}`, "content-type": "application/json" }, ...(method === "POST" ? { body: JSON.stringify({ reason: "test" }) } : {}) });
    expect((await admin("/admin/stats", "wrong", "GET")).status).toBe(403);
    const stats = (await (await admin("/admin/stats", KEYS.stats, "GET")).json()) as { checksToday: number; state: { closed: boolean } };
    expect(stats.checksToday).toBeGreaterThan(0);
    expect((await admin("/admin/close", KEYS.stats)).status).toBe(403);
    expect((await admin("/admin/close", KEYS.close)).status).toBe(200);
    expect((await redeem(aliceClient, await idJag(ISSUERS[0], aliceClient.clientId))).status).toBe(503);
    expect((await admin("/admin/open", KEYS.close)).status).toBe(403);
    expect((await admin("/admin/open", KEYS.open)).status).toBe(200);
    expect((await redeem(aliceClient, await idJag(ISSUERS[0], aliceClient.clientId))).status).toBe(200);
  });

  it("the deploy-level switch closes everything but the admin endpoints", async () => {
    env.TESTER_ENABLED = "false";
    try {
      expect((await redeem(aliceClient, await idJag(ISSUERS[0], aliceClient.clientId))).status).toBe(503);
      expect((await call("/signin", { method: "POST", headers: { origin: ORIGIN } })).status).toBe(503);
      expect((await call("/results", { cookie: alice })).status).toBe(503);
      expect((await call("/api/auth/callback/github?code=x&state=y")).status).toBe(503);
      expect((await call("/mcp", { method: "POST" })).status).toBe(503);
      expect((await call("/")).status).toBe(200);
      expect((await call("/admin/stats", { headers: { authorization: `Bearer ${KEYS.stats}` } })).status).toBe(200);
    } finally {
      env.TESTER_ENABLED = "true";
    }
  });

  it("revoking a registration stops its client at once; expiry and the purge remove everything it left", async () => {
    const issued = (await (await redeem(aliceClient, await idJag(ISSUERS[0], aliceClient.clientId))).json()) as { access_token: string };
    const [reg] = await rows<{ id: string }>(`select id from testerRegistration where clientId = ?`, aliceClient.clientId);
    const revoke = await call("/admin/revoke", { method: "POST", headers: { authorization: `Bearer ${KEYS.close}`, "content-type": "application/json" }, body: JSON.stringify({ registrationId: reg?.id, reason: "test" }) });
    expect(await revoke.json()).toEqual({ revoked: true });
    expect((await redeem(aliceClient, await idJag(ISSUERS[0], aliceClient.clientId))).status).toBe(401);
    const mcp = await call("/mcp", { method: "POST", headers: { authorization: `Bearer ${issued.access_token}`, "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "whoami" } }) });
    expect(mcp.status).toBe(401);
    expect(await rows(`select id from "idJagTrustedIssuer" where enabled = 1 and allowedClientIds like ?`, `%${aliceClient.clientId}%`)).toEqual([]);

    await env.DB.prepare(`update testerRegistration set expiresAt = ?`).bind(Date.now() - 1).run();
    await worker.scheduled({}, env);
    expect(await rows(`select id from "oauthClient"`)).toEqual([]);
    expect(await rows(`select id from "idJagTrustedIssuer"`)).toEqual([]);
    expect(await rows(`select id from "user" where email like '%.sandbox.invalid'`)).toEqual([]);
    expect(await rows(`select id from testerCheck`)).toEqual([]);
    expect(await rows(`select id from "idJagAudit"`)).toEqual([]);
    expect((await rows<{ purgedAt: number | null }>(`select purgedAt from testerRegistration`)).every((r) => r.purgedAt !== null)).toBe(true);
  });
});
