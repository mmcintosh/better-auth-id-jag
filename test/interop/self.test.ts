// Interop, row 1: our issuer → our receiver (plan §4, "CI, always"). Two Better Auth instances in one
// process, each with its own database, talking only through HTTP-shaped Requests:
//   1. a user signs in at the IdP and the agent gets an ID token by authorization_code (PKCE);
//   2. RFC 8693 token exchange at the IdP: audience = the MCP AS's issuer, resource = the MCP resource;
//   3. RFC 7523 jwt-bearer at the MCP AS, the agent authenticating with the client id the MCP AS
//      issued it (the IdP maps its own client id to that one: client-id-at-resource, D-004);
//   4. the MCP AS verifies the ID-JAG against the IdP's /jwks, fetched over the receiver's injected
//      fetch, routed to the IdP's handler;
//   5. requireMcpAuth accepts the access token for the MCP resource, and only for it.
import { requireMcpAuth } from "@better-auth/mcp";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ID_JAG_TOKEN_TYPE } from "../../src";
import { createClient, getIdToken, signUp } from "../support/issuer-host";
import { decodeJwtPart, exchangeAt, idpHost, mcpClient, mcpHost, redeemAt, routedFetch } from "../support/interop-hosts";

afterEach(() => vi.unstubAllGlobals());

const IDP = "https://idp.example";
const IDP_ISSUER = `${IDP}/api/auth`;
const MCP = "https://mcp.example";
const MCP_ISSUER = `${MCP}/api/auth`;
const MCP_RESOURCE = `${MCP}/mcp`;

/** Both hosts, the agent registered at each (two different client ids), and a user with an ID token. */
async function world(o: { jit?: boolean; email?: boolean; anyAudience?: boolean } = {}) {
  const mapping: { atResource?: string } = {};
  const idp = await idpHost({
    base: IDP,
    issuer: {
      // The IdP's policy: this audience and resource only, scope read, the agent's id at the MCP AS.
      authorize: (input) =>
        (o.anyAudience || input.audience === MCP_ISSUER) && input.resource === MCP_RESOURCE
          ? { decision: "allow", scopes: ["read"], ...(mapping.atResource ? { clientIdAtResource: mapping.atResource } : {}), ...(o.email ? { claims: { email: true } } : {}) }
          : { decision: "deny" },
    },
  });
  const net = routedFetch(idp);
  const mcp = await mcpHost({
    base: MCP,
    resource: MCP_RESOURCE,
    receiver: { trustedIssuers: [{ issuer: IDP_ISSUER, jwksUri: `${IDP_ISSUER}/jwks`, ...(o.jit ? { jitProvisioning: { trustEmailVerified: true } } : {}) }], fetch: net.fetch },
  });
  const atMcp = await mcpClient(mcp);
  mapping.atResource = atMcp.client_id;
  const owner = await signUp(idp);
  const atIdp = await createClient(idp, owner.browser);
  const user = await signUp(idp);
  if (o.email) await idp.ctx.adapter.update({ model: "user", where: [{ field: "id", value: user.id }], update: { emailVerified: true } });
  const idToken = await getIdToken(idp, user.browser, atIdp);
  return { idp, mcp, net, atIdp, atMcp, user, idToken };
}

/** Route requireMcpAuth's JWKS fetch (global fetch) to the MCP host. */
function stubAsJwks(mcp: Awaited<ReturnType<typeof mcpHost>>) {
  const fetched: string[] = [];
  vi.stubGlobal("fetch", async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = input instanceof Request ? input.url : String(input);
    fetched.push(url);
    if (url !== `${MCP_ISSUER}/jwks`) throw new Error(`unexpected fetch ${url}`);
    return mcp.auth.handler(new Request(url, { method: "GET", ...(init?.headers ? { headers: init.headers } : {}) }));
  });
  return fetched;
}

const callTool = (handler: (req: Request) => Promise<Response>, token: string) => handler(new Request(MCP_RESOURCE, { method: "POST", headers: { authorization: `Bearer ${token}` }, body: "{}" }));

describe("interop: our issuer → our receiver", () => {
  it("the five steps: ID token → ID-JAG → access token → requireMcpAuth, with the subject pre-linked at the MCP AS", async () => {
    const w = await world();
    expect(w.atIdp.client_id).not.toBe(w.atMcp.client_id);
    // The MCP AS links the IdP's subject to a local user beforehand (what an SSO sign-in would do).
    const local = await w.mcp.ctx.internalAdapter.createUser({ email: `local+${crypto.randomUUID()}@example.com`, name: "Local", emailVerified: true }, { method: "admin" });
    await w.mcp.ctx.internalAdapter.linkAccount({ userId: local.id, providerId: `id-jag:${IDP_ISSUER}`, accountId: w.user.id });

    // 2. Token exchange at the IdP.
    const x = await exchangeAt(w.idp, w.atIdp, w.idToken, { audience: MCP_ISSUER, resource: MCP_RESOURCE, scope: "read write" });
    expect(x.status, JSON.stringify(x.body)).toBe(200);
    expect(x.body).toMatchObject({ issued_token_type: ID_JAG_TOKEN_TYPE, token_type: "N_A", scope: "read" });
    const idJag = x.body.access_token as string;
    expect(decodeJwtPart(idJag, 0)).toMatchObject({ typ: "oauth-id-jag+jwt", alg: "ES256" });
    expect(decodeJwtPart(idJag, 1)).toMatchObject({ iss: IDP_ISSUER, sub: w.user.id, aud: MCP_ISSUER, client_id: w.atMcp.client_id, resource: MCP_RESOURCE, scope: "read" });

    // 3–4. jwt-bearer at the MCP AS; its only outbound request is the IdP's JWKS.
    const r = await redeemAt(w.mcp, w.atMcp, idJag);
    expect(r.status, r.text).toBe(200);
    expect(w.net.urls).toEqual([`${IDP_ISSUER}/jwks`]);
    expect(r.body.token_type).toBe("Bearer");
    expect(r.body.refresh_token).toBeUndefined();
    expect(r.body.id_token).toBeUndefined();
    const accessToken = r.body.access_token as string;
    expect(decodeJwtPart(accessToken, 1)).toMatchObject({ iss: MCP_ISSUER, aud: MCP_RESOURCE, sub: local.id, scope: "read" });
    expect(w.mcp.accepted[0]).toMatchObject({ type: "id-jag.accepted" });

    // 5. requireMcpAuth: accepted for the MCP resource, refused for another.
    const fetched = stubAsJwks(w.mcp);
    const seen: Record<string, unknown>[] = [];
    const tool = async (_req: Request, claims: Record<string, unknown>) => {
      seen.push(claims);
      return Response.json({ ok: true });
    };
    const ok = await callTool(requireMcpAuth(w.mcp.auth, tool, { resource: MCP_RESOURCE }), accessToken);
    expect(ok.status, await ok.clone().text()).toBe(200);
    expect(seen[0]).toMatchObject({ sub: local.id, aud: MCP_RESOURCE, iss: MCP_ISSUER, scope: "read" });
    const other = await callTool(requireMcpAuth(w.mcp.auth, tool, { resource: `${MCP}/other` }), accessToken);
    expect(other.status).toBe(401);
    expect(seen).toHaveLength(1);
    expect(fetched.every((u) => u === `${MCP_ISSUER}/jwks`)).toBe(true);

    // The same ID-JAG a second time: single use (D-009).
    const again = await redeemAt(w.mcp, w.atMcp, idJag);
    expect(again.status).toBe(400);
    expect(again.body.error).toBe("invalid_grant");
    expect(w.mcp.refused.at(-1)?.reason).toBe("replay");
  });

  it("JIT: an unknown subject with a verified email the IdP chose to send becomes a local user", async () => {
    const w = await world({ jit: true, email: true });
    const x = await exchangeAt(w.idp, w.atIdp, w.idToken, { audience: MCP_ISSUER, resource: MCP_RESOURCE, scope: "read" });
    expect(x.status, JSON.stringify(x.body)).toBe(200);
    expect(decodeJwtPart(x.body.access_token as string, 1).email).toBe(w.user.email);
    const r = await redeemAt(w.mcp, w.atMcp, x.body.access_token as string);
    expect(r.status, r.text).toBe(200);
    const sub = decodeJwtPart(r.body.access_token as string, 1).sub as string;
    const local = await w.mcp.ctx.internalAdapter.findUserById(sub);
    expect(local?.email).toBe(w.user.email);
    const accounts = await w.mcp.ctx.internalAdapter.findAccounts(sub);
    expect(accounts.map((a) => [a.providerId, a.accountId])).toContainEqual([`id-jag:${IDP_ISSUER}`, w.user.id]);
  });

  it("without the client-id mapping, the ID-JAG names the IdP's client id, and the MCP AS refuses it (client-id continuity)", async () => {
    const w = await world();
    const local = await w.mcp.ctx.internalAdapter.createUser({ email: `local+${crypto.randomUUID()}@example.com`, name: "Local", emailVerified: true }, { method: "admin" });
    await w.mcp.ctx.internalAdapter.linkAccount({ userId: local.id, providerId: `id-jag:${IDP_ISSUER}`, accountId: w.user.id });
    // A second IdP world where the policy maps nothing: reuse this one's hosts, minting with the IdP's client id.
    const idp2 = await idpHost({ base: IDP, issuer: { authorize: () => ({ decision: "allow", scopes: ["read"] }) } });
    const owner = await signUp(idp2);
    const atIdp2 = await createClient(idp2, owner.browser);
    const user2 = await signUp(idp2);
    const x = await exchangeAt(idp2, atIdp2, await getIdToken(idp2, user2.browser, atIdp2), { audience: MCP_ISSUER, resource: MCP_RESOURCE });
    expect(x.status).toBe(200);
    expect(decodeJwtPart(x.body.access_token as string, 1).client_id).toBe(atIdp2.client_id);
    // idp2 has its own keys, at the same issuer URL the MCP AS trusts; route its JWKS fetch to idp2.
    const mcp2 = await mcpHost({ base: MCP, resource: MCP_RESOURCE, receiver: { trustedIssuers: [{ issuer: IDP_ISSUER, jwksUri: `${IDP_ISSUER}/jwks` }], fetch: routedFetch(idp2).fetch } });
    const atMcp2 = await mcpClient(mcp2);
    const r = await redeemAt(mcp2, atMcp2, x.body.access_token as string);
    expect(r.status).toBe(400);
    expect(r.body.error).toBe("invalid_grant");
    expect(mcp2.refused.at(-1)?.reason).toBe("client_mismatch");
  });

  it("audience: the IdP's policy refuses an audience it doesn't know; the MCP AS refuses an ID-JAG minted for another AS", async () => {
    const strict = await world();
    const denied = await exchangeAt(strict.idp, strict.atIdp, strict.idToken, { audience: "https://elsewhere.example/api/auth", resource: MCP_RESOURCE });
    expect(denied.status).toBe(400);
    expect(denied.body.error).toBe("invalid_grant");
    expect(strict.idp.recorded.refused.at(-1)?.reason).toBe("policy_denied");

    const w = await world({ anyAudience: true });
    // The MCP resource itself is not the AS's issuer identifier; neither is the bare origin.
    for (const audience of [MCP_RESOURCE, MCP, `${MCP_ISSUER}/`]) {
      const x = await exchangeAt(w.idp, w.atIdp, w.idToken, { audience, resource: MCP_RESOURCE });
      expect(x.status, JSON.stringify(x.body)).toBe(200);
      const r = await redeemAt(w.mcp, w.atMcp, x.body.access_token as string);
      expect(r.status, audience).toBe(400);
      expect(w.mcp.refused.at(-1)?.reason, audience).toBe("wrong_audience");
    }
  });

  it("an ID-JAG signed by a key the trusted issuer doesn't publish is refused", async () => {
    const w = await world();
    // Another IdP instance with the same issuer URL but its own keys: the MCP AS fetches the real IdP's JWKS.
    const impostor = await idpHost({ base: IDP, issuer: { authorize: () => ({ decision: "allow", scopes: ["read"], clientIdAtResource: w.atMcp.client_id }) } });
    const owner = await signUp(impostor);
    const c = await createClient(impostor, owner.browser);
    const u = await signUp(impostor);
    const x = await exchangeAt(impostor, c, await getIdToken(impostor, u.browser, c), { audience: MCP_ISSUER, resource: MCP_RESOURCE });
    expect(x.status).toBe(200);
    const r = await redeemAt(w.mcp, w.atMcp, x.body.access_token as string);
    expect(r.status).toBe(400);
    expect(r.body.error).toBe("invalid_grant");
    expect(w.mcp.refused.at(-1)?.reason).toBe("bad_signature");
  });
});
