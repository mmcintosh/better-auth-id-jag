// Interop, row 4: our issuer → node-oauth2-server's receiver. The jwt-bearer / ID-JAG grant is an
// open pull request (node-oauth/node-oauth2-server#462), not released, so it is not a dependency of
// this package: install the PR's head commit in a directory of your own and point the test at it
// (docs/interop.md has the commands). Gated: INTEROP_NODE_OAUTH2=1 and INTEROP_NODE_OAUTH2_DIR, Node only.
//
// node-oauth2-server leaves key resolution to the host's model (getRequestingIssuerKey(iss, kid)),
// so the model here reads our issuer's /jwks, in process, and returns the JWK with that kid.
import { describe, expect, it } from "vitest";
import { createClient, getIdToken, signUp } from "../support/issuer-host";
import { basicAuth, decodeJwtPart, exchangeAt, type IdpHost, idpHost } from "../support/interop-hosts";

const env = typeof process !== "undefined" ? process.env : {};
const enabled = env?.INTEROP_NODE_OAUTH2 === "1" && !!env?.INTEROP_NODE_OAUTH2_DIR && navigator.userAgent !== "Cloudflare-Workers";
const AS = "https://as.node-oauth2.example";
const AGENT = { id: "agent-noas", secret: "agent-noas-secret" };
const IDP = "https://idp.example";

interface Lib {
  default?: unknown;
  Request: new (o: Record<string, unknown>) => unknown;
  Response: new (o?: Record<string, unknown>) => unknown;
}

async function lib() {
  const { createRequire } = await import("node:module");
  const { join } = await import("node:path");
  const req = createRequire(join(env.INTEROP_NODE_OAUTH2_DIR as string, "package.json"));
  const OAuth2Server = req("@node-oauth/oauth2-server") as (new (o: Record<string, unknown>) => { token: (rq: unknown, rs: unknown) => Promise<Record<string, unknown>> }) & Lib;
  return OAuth2Server;
}

async function world(o: { alg?: "ES256" | "RS256" | "EdDSA"; mapTo?: string } = {}) {
  const keyPairConfig = o.alg === "RS256" ? { alg: "RS256", modulusLength: 2048 } : o.alg === "EdDSA" ? { alg: "EdDSA", crv: "Ed25519" } : { alg: "ES256" };
  const idp: IdpHost = await idpHost({
    base: IDP,
    database: "sqlite",
    keyPairConfig,
    issuer: { authorize: (input) => (input.audience === AS ? { decision: "allow", scopes: ["read", "write"], clientIdAtResource: o.mapTo ?? AGENT.id } : { decision: "deny" }) },
  });
  const users = new Map<string, { id: string }>();
  const jtis = new Set<string>();
  const OAuth2Server = await lib();
  const model = {
    getClient: async (id: string, secret?: string) => (id === AGENT.id && (secret === undefined || secret === AGENT.secret) ? { id, grants: ["urn:ietf:params:oauth:grant-type:jwt-bearer"] } : false),
    getTrustedIssuer: async (iss: string) => (iss === idp.issuerUrl ? { issuer: iss } : false),
    getRequestingIssuerKey: async (iss: string, kid: string) => {
      const res = await idp.auth.handler(new Request(`${iss}/jwks`));
      const { keys } = (await res.json()) as { keys: { kid: string }[] };
      return keys.find((k) => k.kid === kid) ?? false;
    },
    getUserFromIdJagAssertion: async (_iss: string, sub: string) => users.get(sub) ?? false,
    validateIdJagPermission: async () => true,
    validateJti: async (jti: string, iss: string) => {
      const key = JSON.stringify([iss, jti]);
      if (jtis.has(key)) return false;
      jtis.add(key);
      return true;
    },
    validateScope: async (_u: unknown, _c: unknown, scope: string[] | undefined) => scope ?? [],
    saveToken: async (token: Record<string, unknown>, client: unknown, user: unknown) => ({ ...token, client, user }),
  };
  const server = new OAuth2Server({ model, tokenEndpointUri: AS, requireClientAuthentication: { "urn:ietf:params:oauth:grant-type:jwt-bearer": true } });
  const owner = await signUp(idp);
  const atIdp = await createClient(idp, owner.browser);
  const user = await signUp(idp);
  const idToken = await getIdToken(idp, user.browser, atIdp);
  const redeem = async (assertion: string, extra: Record<string, string> = {}) => {
    // As an HTTP framework would hand it over: the parsed form, and the headers (type-is needs content-length).
    const body = { grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion, ...extra };
    const rq = new OAuth2Server.Request({
      method: "POST",
      query: {},
      headers: { "content-type": "application/x-www-form-urlencoded", "content-length": String(new URLSearchParams(body).toString().length), authorization: basicAuth(AGENT.id, AGENT.secret) },
      body,
    });
    const rs = new OAuth2Server.Response({ headers: {} });
    try {
      const token = await server.token(rq, rs);
      return { ok: true as const, token, rs };
    } catch (e) {
      const err = e as { name?: string; code?: number; message?: string };
      console.log(`[node-oauth2-server] refused: ${err.code} ${err.name} ${err.message}`);
      return { ok: false as const, error: err };
    }
  };
  return { idp, atIdp, user, idToken, users, redeem };
}

async function idJag(w: Awaited<ReturnType<typeof world>>, form: { scope?: string; resource?: string } = {}) {
  const x = await exchangeAt(w.idp, w.atIdp, w.idToken, { audience: AS, ...form });
  expect(x.status, JSON.stringify(x.body)).toBe(200);
  return x.body.access_token as string;
}

describe.skipIf(!enabled)("interop: our issuer → node-oauth2-server receiver (PR #462)", () => {
  for (const alg of ["ES256", "RS256"] as const) {
    it(`an ID-JAG from our issuer (${alg}) becomes an access token; replay refused`, async () => {
      const w = await world({ alg });
      w.users.set(w.user.id, { id: "local-ada" });
      const assertion = await idJag(w, { scope: "read" });
      expect(decodeJwtPart(assertion, 0)).toMatchObject({ typ: "oauth-id-jag+jwt", alg });
      const r = await w.redeem(assertion);
      expect(r.ok, JSON.stringify(r)).toBe(true);
      if (!r.ok) return;
      expect(r.token.scope).toEqual(["read"]);
      expect(r.token.refreshToken).toBeUndefined();
      expect(r.token.user).toEqual({ id: "local-ada" });
      const again = await w.redeem(assertion);
      expect(again.ok).toBe(false);
      if (!again.ok) expect(again.error.name).toBe("invalid_grant");
    });
  }

  it("not interoperable: EdDSA, which its default allow-list (RS256, ES256, PS256) and its verifier don't support", async () => {
    const w = await world({ alg: "EdDSA" });
    w.users.set(w.user.id, { id: "local-ada" });
    const r = await w.redeem(await idJag(w));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error.name).toBe("invalid_grant");
  });

  it("scope: the request may narrow the ID-JAG's scope but not widen it (widening is invalid_scope)", async () => {
    const w = await world();
    w.users.set(w.user.id, { id: "local-ada" });
    const narrowed = await w.redeem(await idJag(w, { scope: "read write" }), { scope: "read" });
    expect(narrowed.ok).toBe(true);
    if (narrowed.ok) expect(narrowed.token.scope).toEqual(["read"]);
    const widened = await w.redeem(await idJag(w, { scope: "read" }), { scope: "read write" });
    expect(widened.ok).toBe(false);
    if (!widened.ok) expect(widened.error.name).toBe("invalid_scope");
  });

  it("refused: client_id is the agent's id at the IdP (client-id continuity); an unknown subject", async () => {
    const w = await world({ mapTo: "agent-at-the-idp" });
    w.users.set(w.user.id, { id: "local-ada" });
    const mismatch = await w.redeem(await idJag(w));
    expect(mismatch.ok).toBe(false);
    if (!mismatch.ok) expect(mismatch.error.name).toBe("invalid_grant");
    const w2 = await world();
    const unknown = await w2.redeem(await idJag(w2));
    expect(unknown.ok).toBe(false);
    if (!unknown.ok) expect(unknown.error.name).toBe("invalid_grant");
  });
});
