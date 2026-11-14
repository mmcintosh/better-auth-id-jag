// The example IdP as a Worker (examples/workers/enterprise-idp), in workerd on D1 with its own migrations: /setup makes
// a client for the public tester, and a sign-in with prompt=consent (the tester's run asks for offline_access with it)
// goes through /consent and comes back to the tester's /flow/callback with a code.
import { beforeAll, describe, expect, it } from "vitest";
import m0001 from "../../examples/workers/enterprise-idp/migrations/0001_init.sql?raw";
import m0002 from "../../examples/workers/enterprise-idp/migrations/0002_phase2.sql?raw";
import { testerCallbackOf } from "../../examples/workers/enterprise-idp/src/auth";

const workerd = navigator.userAgent === "Cloudflare-Workers";
const IDP = "https://idp.example.net";
const TESTER = "https://tester.example.net";
const SETUP_KEY = "setup-key-that-is-long-enough-for-the-example";
const EMAIL = "agent-user@example.com";
const PASSWORD = "example-password-1234";
// RFC 7636 appendix B's challenge (its verifier isn't needed: no code is exchanged here).
const CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

describe("example IdP: the tester's callback from TESTER_AS_ISSUER", () => {
  it("is the tester's origin's /flow/callback, or null when unset or not an absolute URL", () => {
    expect(testerCallbackOf({ TESTER_AS_ISSUER: `${TESTER}/api/auth` })).toBe(`${TESTER}/flow/callback`);
    for (const bad of [undefined, "", "tester.example.net/api/auth", "not a url"]) expect(testerCallbackOf({ TESTER_AS_ISSUER: bad })).toBeNull();
  });
});

describe.skipIf(!workerd)("example IdP as a Worker: a tester client, sign-in and consent (workerd, D1)", () => {
  let cf: typeof import("cloudflare:test");
  let worker: { fetch(r: Request, e: unknown, c: unknown): Promise<Response> };
  let env: Record<string, unknown>;

  const call = async (path: string, init: RequestInit = {}, e = env) => {
    const ctx = cf.createExecutionContext();
    const response = await worker.fetch(new Request(new URL(path, IDP), { ...init, redirect: "manual" }), e, ctx);
    await cf.waitOnExecutionContext(ctx);
    return response;
  };
  const setup = (e = env) => call("/setup", { method: "POST", headers: { "x-setup-key": SETUP_KEY, "content-type": "application/json" }, body: JSON.stringify({ email: EMAIL, password: PASSWORD, clientIdAtResource: "the-tester-client", agent: true, for: "tester" }) }, e);

  beforeAll(async () => {
    cf = await import("cloudflare:test");
    env = { DB: cf.env.DB, BETTER_AUTH_SECRET: "example-idp-test-secret-at-least-32-characters", SETUP_KEY, MCP_AS_ISSUER: "https://mcp.example.net/api/auth", MCP_RESOURCE: "https://mcp.example.net/mcp", TESTER_AS_ISSUER: `${TESTER}/api/auth`, TESTER_RESOURCE: `${TESTER}/mcp` };
    for (const sql of [m0001, m0002]) for (const stmt of sql.replace(/^--.*$/gm, "").split(/;\s*\n/).map((s: string) => s.trim()).filter(Boolean)) await cf.env.DB.prepare(stmt).run();
    worker = (await import("../../examples/workers/enterprise-idp/src/index")).default as never;
  }, 60_000);

  it("a tester client signs in with prompt=consent: /consent, Allow, and back to the tester's /flow/callback with a code", async () => {
    const made = await setup();
    expect(made.status).toBe(200);
    const { client_id } = (await made.json()) as { client_id: string };
    const signIn = await call("/api/auth/sign-in/email", { method: "POST", headers: { "content-type": "application/json", origin: IDP }, body: JSON.stringify({ email: EMAIL, password: PASSWORD }) });
    expect(signIn.status).toBe(200);
    const cookie = signIn.headers.getSetCookie().map((c) => c.split(";")[0]).join("; ");

    const q = new URLSearchParams({ response_type: "code", client_id, redirect_uri: `${TESTER}/flow/callback`, scope: "openid offline_access", prompt: "consent", state: "st", nonce: "nn", code_challenge: CHALLENGE, code_challenge_method: "S256" });
    const authorize = await call(`/api/auth/oauth2/authorize?${q}`, { headers: { cookie } });
    const to = new URL(authorize.headers.get("location") ?? "", IDP);
    expect(to.origin + to.pathname).toBe(`${IDP}/consent`);
    const page = await call(`/consent${to.search}`);
    expect(page.status).toBe(200);
    expect(page.headers.get("content-security-policy")).toContain("frame-ancestors 'none'");
    expect(await page.text()).toContain("/api/auth/oauth2/consent");

    // What the page's Allow sends: the signed part of the query.
    const names = new Set(to.searchParams.getAll("ba_param"));
    const signed = new URLSearchParams([...to.searchParams].filter(([k]) => k === "sig" || k === "ba_param" || names.has(k)));
    const allow = await call("/api/auth/oauth2/consent", { method: "POST", headers: { cookie, origin: IDP, "content-type": "application/json" }, body: JSON.stringify({ accept: true, oauth_query: signed.toString() }) });
    expect(allow.status).toBe(200);
    const back = new URL(((await allow.json()) as { url: string }).url);
    expect(back.origin + back.pathname).toBe(`${TESTER}/flow/callback`);
    expect(back.searchParams.get("code")).toBeTruthy();
    expect(back.searchParams.get("state")).toBe("st");
  });

  it("/setup for the tester with a TESTER_AS_ISSUER that isn't a URL: a 400 that says so, not a server error", async () => {
    const made = await setup({ ...env, TESTER_AS_ISSUER: "tester.example.net" });
    expect(made.status).toBe(400);
    expect(await made.text()).toContain("TESTER_AS_ISSUER");
  });
});
