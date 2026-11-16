// The example MCP server as a Worker (examples/workers/mcp-server), in workerd on D1 with its own migrations: /mcp checks
// the access token with requireMcpAuth (@better-auth/mcp), and its tools apply the scope and agent rules on top.
// Tokens are signed here with the server's own keys (the same database and secret), as its token endpoint signs them,
// for a client registered through its /setup and that client's user: on Better Auth 1.8, requireMcpAuth also checks
// both exist (and that the client isn't disabled), as they do for every token the endpoint issues.
// One test also exchanges an ID-JAG at the token endpoint, signed with a stand-in IdP key served through the IDP binding.
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import m0001 from "../../examples/workers/mcp-server/migrations/0001_init.sql?raw";
import m0002 from "../../examples/workers/mcp-server/migrations/0002_better_auth_1_8.sql?raw";
import { REQUIRE_MCP_AUTH_IN_PROCESS } from "../support/better-auth-version";

const workerd = navigator.userAgent === "Cloudflare-Workers";
const MCP = "https://mcp.example.net";
const IDP_ISSUER = "https://idp.example.net/api/auth";

// Better Auth 1.7.25 or later: older requireMcpAuth fetches the server's own keys by URL, which a Worker can't do.
describe.skipIf(!workerd || !REQUIRE_MCP_AUTH_IN_PROCESS)("example MCP server as a Worker: /mcp behind requireMcpAuth (workerd, D1)", () => {
  let cf: typeof import("cloudflare:test");
  let worker: { fetch(r: Request, e: unknown, c: unknown): Promise<Response> };
  let env: Record<string, unknown>;
  let sign: (claims: Record<string, unknown>) => Promise<string>;
  let clientId: string;
  let clientSecret: string;
  let userId: string;
  let idpKey: CryptoKey;
  let idpJwks: { keys: unknown[] };
  let createAuthFor: (e: Record<string, unknown>) => unknown;

  const rpc = async (body: unknown, token?: string, method = "POST") => {
    const ctx = cf.createExecutionContext();
    const headers: Record<string, string> = { "content-type": "application/json", ...(token ? { authorization: `Bearer ${token}` } : {}) };
    const response = await worker.fetch(new Request(`${MCP}/mcp`, { method, headers, ...(method === "POST" ? { body: JSON.stringify(body) } : {}) }), env, ctx);
    await cf.waitOnExecutionContext(ctx);
    return response;
  };
  const call = (name: string, token: string) => rpc({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: {} } }, token);
  const token = (over: Record<string, unknown> = {}) => {
    const now = Math.floor(Date.now() / 1000);
    return sign({ iss: `${MCP}/api/auth`, aud: `${MCP}/mcp`, sub: userId, azp: clientId, client_id: clientId, scope: "read write", iat: now, exp: now + 300, ...over });
  };

  /** An ID-JAG from the test's IdP, exchanged at `origin`'s token endpoint by `client` (default: the one from /setup). */
  const exchange = async (origin: string, workerEnv: Record<string, unknown>, claims: Record<string, unknown>, client = { client_id: clientId, client_secret: clientSecret }) => {
    const now = Math.floor(Date.now() / 1000);
    const assertion = await new SignJWT({ iss: IDP_ISSUER, aud: `${origin}/api/auth`, client_id: client.client_id, jti: crypto.randomUUID(), iat: now, exp: now + 300, resource: `${origin}/mcp`, scope: "read", ...claims })
      .setProtectedHeader({ alg: "ES256", typ: "oauth-id-jag+jwt", kid: "idp-1" })
      .sign(idpKey);
    const ctx = cf.createExecutionContext();
    const r = await worker.fetch(new Request(`${origin}/api/auth/oauth2/token`, { method: "POST", headers: { authorization: `Basic ${btoa(`${client.client_id}:${client.client_secret}`)}`, "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion }).toString() }), workerEnv, ctx);
    await cf.waitOnExecutionContext(ctx);
    return { status: r.status, json: (await r.json()) as { error?: string; access_token?: string } };
  };
  /** POST /setup at `origin`, as the operator. */
  const setupAt = async (origin: string, workerEnv: Record<string, unknown>, body: Record<string, unknown>) => {
    const ctx = cf.createExecutionContext();
    const r = await worker.fetch(new Request(`${origin}/setup`, { method: "POST", headers: { "x-setup-key": env.SETUP_KEY as string, "content-type": "application/json" }, body: JSON.stringify(body) }), workerEnv, ctx);
    await cf.waitOnExecutionContext(ctx);
    return r;
  };

  beforeAll(async () => {
    cf = await import("cloudflare:test");
    env = { DB: cf.env.DB, BETTER_AUTH_SECRET: "example-mcp-test-secret-at-least-32-characters", SETUP_KEY: "setup-key-that-is-long-enough-for-the-example", IDP_ISSUER, IDP: { fetch: (url: string) => (url === `${IDP_ISSUER}/jwks` ? Response.json(idpJwks) : new Response("not found", { status: 404 })) } };
    const pair = await generateKeyPair("ES256", { extractable: true });
    idpKey = pair.privateKey;
    idpJwks = { keys: [{ ...(await exportJWK(pair.publicKey)), kid: "idp-1", alg: "ES256", use: "sig" }] };
    for (const sql of [m0001, m0002]) for (const stmt of sql.replace(/^--.*$/gm, "").split(/;\s*\n/).map((s: string) => s.trim()).filter(Boolean)) await cf.env.DB.prepare(stmt).run();
    worker = (await import("../../examples/workers/mcp-server/src/index")).default as never;
    const { createAuth } = await import("../../examples/workers/mcp-server/src/auth");
    createAuthFor = (e) => createAuth(e as never, MCP);
    const auth = createAuth(env as never, MCP) as unknown as { api: { signJWT(o: { body: { payload: Record<string, unknown> } }): Promise<{ token: string }> } };
    sign = async (payload) => (await auth.api.signJWT({ body: { payload } })).token;
    const ctx = cf.createExecutionContext();
    const made = await worker.fetch(new Request(`${MCP}/setup`, { method: "POST", headers: { "x-setup-key": env.SETUP_KEY as string, "content-type": "application/json" }, body: JSON.stringify({ email: "operator@example.net", password: "example-password-1234" }) }), env, ctx);
    await cf.waitOnExecutionContext(ctx);
    ({ client_id: clientId, client_secret: clientSecret } = (await made.json()) as { client_id: string; client_secret: string });
    const context = await (createAuth(env as never, MCP) as unknown as { $context: Promise<{ internalAdapter: { findUserByEmail(e: string): Promise<{ user: { id: string } } | null> } }> }).$context;
    userId = (await context.internalAdapter.findUserByEmail("operator@example.net"))?.user.id ?? "";
    expect(clientId && userId).toBeTruthy();
  }, 60_000);

  it("no token, or one it can't verify: 401 with the RFC 9728 challenge", async () => {
    for (const bearer of [undefined, "not-a-jwt"]) {
      const r = await rpc({ jsonrpc: "2.0", id: 1, method: "tools/list" }, bearer);
      expect(r.status).toBe(401);
      expect(r.headers.get("www-authenticate")).toContain(`resource_metadata="${MCP}/.well-known/oauth-protected-resource/mcp"`);
    }
  });

  it("a token for another audience or issuer, or expired, is refused", async () => {
    const now = Math.floor(Date.now() / 1000);
    for (const over of [{ aud: "https://other.example.net/mcp" }, { iss: "https://other.example.net/api/auth" }, { iat: now - 600, exp: now - 300 }]) {
      expect((await rpc({ jsonrpc: "2.0", id: 1, method: "tools/list" }, await token(over))).status, JSON.stringify(over)).toBe(401);
    }
  });

  it("a valid token reaches the tools: whoami answers with the verified claims", async () => {
    const r = await call("whoami", await token());
    expect(r.status).toBe(200);
    const body = (await r.json()) as { result?: { content?: { text?: string }[] } };
    expect(JSON.parse(body.result?.content?.[0]?.text ?? "{}")).toMatchObject({ tool: "whoami", sub: userId, scope: "read write", act: null });
    // Not a GET: Streamable HTTP's answer for no server stream is 405, after the token is checked.
    expect((await rpc(undefined, await token(), "GET")).status).toBe(405);
  });

  it("the tools still decide by scope and by actor: a missing scope is 403 insufficient_scope; an agent needs approval to delete", async () => {
    const readOnly = await call("add_note", await token({ scope: "read" }));
    expect(readOnly.status).toBe(403);
    expect(readOnly.headers.get("www-authenticate")).toContain('error="insufficient_scope", scope="write"');
    const agent = await token({ act: { sub: "agent-1", sub_profile: "ai_agent" } });
    const added = (await (await call("add_note", agent)).json()) as { result?: { isError?: boolean } };
    expect(added.result?.isError).toBeFalsy();
    const deleted = (await (await call("delete_note", agent)).json()) as { result?: { isError?: boolean; structuredContent?: { status?: string } } };
    expect(deleted.result).toMatchObject({ isError: true, structuredContent: { status: "approval_required" } });
  });
  it("with PUBLIC_ORIGIN, any other address gets a 308 to the same path there", async () => {
    const ctx = cf.createExecutionContext();
    const r = await worker.fetch(new Request("https://id-jag-example-mcp.someone.workers.dev/mcp", { method: "POST", body: "{}", redirect: "manual" }), { ...env, PUBLIC_ORIGIN: MCP }, ctx);
    await cf.waitOnExecutionContext(ctx);
    expect(r.status).toBe(308);
    expect(r.headers.get("location")).toBe(`${MCP}/mcp`);
  });

  it("after the IdP's issuer changes, IDP_ACCOUNT_PROVIDER_ID keeps its users: without it, a user linked under the old issuer is unknown", async () => {
    const OLD_NAMESPACE = "id-jag:https://old-idp.example.net/api/auth";
    const context = await (createAuthFor(env) as unknown as { $context: Promise<{ internalAdapter: { createUser(u: Record<string, unknown>): Promise<{ id: string }>; linkAccount(a: Record<string, unknown>): Promise<unknown> } }> }).$context;
    const moved = await context.internalAdapter.createUser({ email: "moved@example.net", name: "Moved", emailVerified: true });
    await context.internalAdapter.linkAccount({ userId: moved.id, providerId: OLD_NAMESPACE, accountId: "idp-sub-moved" });
    // The Worker keeps one auth instance per origin, built from the env of its first request: each setting gets its own
    // origin, and its own client (a client is linked to one origin's resource).
    const KEPT = "https://mcp-kept.example.net";
    const keptEnv = { ...env, IDP_ACCOUNT_PROVIDER_ID: OLD_NAMESPACE };
    const keptClient = (await (await setupAt(KEPT, keptEnv, { email: "operator-kept@example.net", password: "example-password-1234" })).json()) as { client_id: string; client_secret: string };
    const subject = { sub: "idp-sub-moved", email: "moved@example.net", email_verified: true };
    // The default namespace is the new issuer's: this user is unknown there, and JIT refuses an email that has a user.
    expect(await exchange(MCP, env, subject)).toMatchObject({ status: 400, json: { error: "access_denied" } });
    const kept = await exchange(KEPT, keptEnv, subject, keptClient);
    expect(kept.status).toBe(200);
    const claims = JSON.parse(atob((kept.json.access_token ?? "").split(".")[1]!.replace(/-/g, "+").replace(/_/g, "/"))) as { sub?: string };
    expect(claims.sub).toBe(moved.id);
  });

  it("after the server's own address changes, /setup's link keeps a client: its id and secret work for the new /mcp", async () => {
    // A client registered through MCP (beforeAll) is linked to MCP's /mcp only; the same server at a new address refuses
    // its ID-JAGs for the new /mcp until the client is linked there too.
    const MOVED = "https://mcp-moved.example.net";
    const subject = { sub: "idp-sub-link", email: "link@example.net", email_verified: true };
    expect(await exchange(MOVED, env, subject)).toMatchObject({ status: 400, json: { error: "invalid_target" } });
    const operator = { email: "operator@example.net", password: "example-password-1234" };
    expect((await setupAt(MOVED, { ...env, SETUP_KEY: "another-setup-key-that-is-long-enough" }, { ...operator, link: clientId })).status).toBe(403);
    expect(await (await setupAt(MOVED, env, { ...operator, link: "no-such-client" })).text()).toBe("no client no-such-client to link");
    const linked = await setupAt(MOVED, env, { ...operator, link: clientId });
    expect(await linked.json()).toEqual({ client_id: clientId, resource: `${MOVED}/mcp`, linked: true, already_linked: false });
    expect(await (await setupAt(MOVED, env, { ...operator, link: clientId })).json()).toMatchObject({ already_linked: true });
    expect((await exchange(MOVED, env, subject)).status).toBe(200);
    // Still linked to the old address too.
    expect((await exchange(MCP, env, { ...subject, sub: "idp-sub-link-old", email: "link-old@example.net" })).status).toBe(200);
  });
});
