// Interop, row 2: our issuer → Keycloak's receiver (its experimental `identity-assertion-jwt`
// feature, 26.7+). Gated: runs only with INTEROP_KEYCLOAK=1, on Node, against a Keycloak you started
// (docs/interop.md has the command). Our IdP is served over real HTTP on 127.0.0.1 so Keycloak (on
// the host network) can fetch its JWKS; everything else is in-process.
//
// Keycloak's rules, from its source at 26.8.0 (docs/interop.md has the file references): the header
// typ must be exactly oauth-id-jag+jwt for the ID-JAG validator to run; iss picks the identity
// provider by its `issuer`; client_id must equal the authenticated client's clientId; aud must be the
// realm issuer or its token endpoint (one value); jti single use; at most 300 s since iat; the
// subject must already be linked (federated identity) to a Keycloak user.
import { afterAll, describe, expect, it } from "vitest";
import { createClient, getIdToken, signUp } from "../support/issuer-host";
import { decodeJwtPart, exchangeAt, type IdpHost, idpHost } from "../support/interop-hosts";
import type { Served } from "../support/interop-http";
import { addClient, addIdentityProvider, addLinkedUser, createRealm, type KeycloakRealm, redeemAtKeycloak } from "../support/interop-keycloak";

const enabled = typeof process !== "undefined" && process.env?.INTEROP_KEYCLOAK === "1" && navigator.userAgent !== "Cloudflare-Workers";
const KEYCLOAK = (typeof process !== "undefined" && process.env?.INTEROP_KEYCLOAK_URL) || "http://localhost:18080";
const ALIAS = "better-auth";
const AGENT = { clientId: "agent-kc", secret: "agent-kc-secret-0123456789abcdef" };

const servers: Served[] = [];
afterAll(async () => {
  for (const s of servers) await s.close();
});

/** Our IdP over HTTP, and a Keycloak realm that trusts it. `mapTo` is the client id the IdP puts in the ID-JAG. */
async function world(o: { mapTo?: string; providerId?: "jwt-authorization-grant" | "oidc"; alg?: "ES256" | "RS256" | "EdDSA" } = {}) {
  const { listen } = await import("../support/interop-http");
  const server = await listen();
  servers.push(server);
  const kc: KeycloakRealm = await createRealm(KEYCLOAK);
  const keyPairConfig = o.alg === "RS256" ? { alg: "RS256", modulusLength: 2048 } : o.alg === "EdDSA" ? { alg: "EdDSA", crv: "Ed25519" } : { alg: "ES256" };
  const idp: IdpHost = await idpHost({
    base: `http://localhost:${server.port}`,
    database: "sqlite",
    keyPairConfig,
    issuer: {
      // Keycloak's realm issuer is http on localhost here.
      allowLoopbackHttpAudiences: true,
      authorize: (input) => (input.audience.startsWith(kc.issuer) ? { decision: "allow", scopes: ["read"], clientIdAtResource: o.mapTo ?? AGENT.clientId } : { decision: "deny" }),
    },
  });
  server.use((r) => idp.auth.handler(r));
  await addIdentityProvider(kc, { alias: ALIAS, issuer: idp.issuerUrl, jwksUrl: `${idp.issuerUrl}/jwks`, ...(o.providerId ? { providerId: o.providerId } : {}) });
  await addClient(kc, { ...AGENT, idps: [ALIAS] });
  const owner = await signUp(idp);
  const atIdp = await createClient(idp, owner.browser);
  const user = await signUp(idp);
  const idToken = await getIdToken(idp, user.browser, atIdp);
  return { server, kc, idp, atIdp, user, idToken };
}

async function idJag(w: Awaited<ReturnType<typeof world>>, audience = w.kc.issuer) {
  const x = await exchangeAt(w.idp, w.atIdp, w.idToken, { audience });
  expect(x.status, JSON.stringify(x.body)).toBe(200);
  return x.body.access_token as string;
}

const record = (what: string, r: { status: number; text: string }) => console.log(`[keycloak] ${what}: ${r.status} ${r.text}`);

describe.skipIf(!enabled)("interop: our issuer → Keycloak receiver", () => {
  it("an ID-JAG from our issuer, for a pre-linked subject, becomes a Keycloak access token", async () => {
    const w = await world();
    const kcUser = await addLinkedUser(w.kc, { username: "ada", email: w.user.email, alias: ALIAS, sub: w.user.id });
    const assertion = await idJag(w);
    const r = await redeemAtKeycloak(w.kc, AGENT, assertion);
    expect(r.status, r.text).toBe(200);
    expect(r.body.token_type).toMatch(/^bearer$/i);
    expect(r.body.refresh_token).toBeUndefined();
    const at = decodeJwtPart(r.body.access_token as string, 1);
    console.log(`[keycloak] access token claims: ${JSON.stringify(at)}`);
    expect(at).toMatchObject({ iss: w.kc.issuer, sub: kcUser, azp: AGENT.clientId });
    // Keycloak fetched our JWKS over HTTP.
    expect(w.server.seen).toContain("GET /api/auth/jwks");

    // Single use: the same ID-JAG again.
    const again = await redeemAtKeycloak(w.kc, AGENT, assertion);
    record("replay", again);
    expect(again.status).toBe(400);
    expect(again.body.error).toBe("invalid_grant");
  });

  it("differs: Keycloak doesn't narrow its token to the ID-JAG's scope or resource; it issues the client's default scopes", async () => {
    const w = await world();
    await addLinkedUser(w.kc, { username: "ada", email: w.user.email, alias: ALIAS, sub: w.user.id });
    const x = await exchangeAt(w.idp, w.atIdp, w.idToken, { audience: w.kc.issuer, resource: "https://mcp.example/mcp", scope: "read" });
    expect(x.status, JSON.stringify(x.body)).toBe(200);
    expect(decodeJwtPart(x.body.access_token as string, 1)).toMatchObject({ scope: "read", resource: "https://mcp.example/mcp" });
    const r = await redeemAtKeycloak(w.kc, AGENT, x.body.access_token as string, { resource: "https://mcp.example/mcp" });
    expect(r.status, r.text).toBe(200);
    const at = decodeJwtPart(r.body.access_token as string, 1);
    record("scope and resource", { status: r.status, text: JSON.stringify({ scope: r.body.scope, aud: at.aud }) });
    expect(String(r.body.scope).split(" ")).not.toContain("read");
    expect(at.aud).not.toBe("https://mcp.example/mcp");
  });

  it("aud may also be the realm's token endpoint", async () => {
    const w = await world();
    await addLinkedUser(w.kc, { username: "ada", email: w.user.email, alias: ALIAS, sub: w.user.id });
    const r = await redeemAtKeycloak(w.kc, AGENT, await idJag(w, w.kc.tokenEndpoint));
    expect(r.status, r.text).toBe(200);
  });

  it("the same, with the identity provider configured as an OIDC broker (the guide's example)", async () => {
    const w = await world({ providerId: "oidc" });
    await addLinkedUser(w.kc, { username: "ada", email: w.user.email, alias: ALIAS, sub: w.user.id });
    const r = await redeemAtKeycloak(w.kc, AGENT, await idJag(w));
    record("oidc broker", r);
    expect(r.status, r.text).toBe(200);
  });

  for (const alg of ["RS256", "EdDSA"] as const) {
    it(`signing algorithm ${alg}`, async () => {
      const w = await world({ alg });
      await addLinkedUser(w.kc, { username: "ada", email: w.user.email, alias: ALIAS, sub: w.user.id });
      const assertion = await idJag(w);
      expect(decodeJwtPart(assertion, 0).alg).toBe(alg);
      const r = await redeemAtKeycloak(w.kc, AGENT, assertion);
      record(alg, r);
      expect(r.status, r.text).toBe(200);
    });
  }

  it("refused: an unlinked subject (Keycloak does no JIT or email matching for this grant)", async () => {
    const w = await world();
    const r = await redeemAtKeycloak(w.kc, AGENT, await idJag(w));
    record("unlinked subject", r);
    expect(r.status).toBe(400);
    expect(r.body.error).toBe("invalid_grant");
  });

  it("refused: client_id is the agent's id at the IdP, not at Keycloak (client-id continuity)", async () => {
    const w = await world({ mapTo: "agent-at-the-idp" });
    await addLinkedUser(w.kc, { username: "ada", email: w.user.email, alias: ALIAS, sub: w.user.id });
    const r = await redeemAtKeycloak(w.kc, AGENT, await idJag(w));
    record("client_id mismatch", r);
    expect(r.status).toBe(400);
    expect(r.body.error).toBe("invalid_grant");
  });

  it("refused: aud with a trailing slash (exact match, no normalisation)", async () => {
    const w = await world();
    await addLinkedUser(w.kc, { username: "ada", email: w.user.email, alias: ALIAS, sub: w.user.id });
    const r = await redeemAtKeycloak(w.kc, AGENT, await idJag(w, `${w.kc.issuer}/`));
    record("aud with trailing slash", r);
    expect(r.status).toBe(400);
    expect(r.body.error).toBe("invalid_grant");
  });
});
