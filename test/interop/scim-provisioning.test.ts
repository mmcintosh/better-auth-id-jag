// Interop with better-auth-scim-provisioning (D-027): the IdP runs it and our issuer; the MCP
// server's AS runs @better-auth/scim and our receiver, its trust entry linked by `scim`. The IdP
// provisions its users to the receiver over SCIM (externalId = the IdP's user id = the ID-JAG's
// `sub`), so the receiver resolves an ID-JAG to the provisioned user, and refuses it once the IdP
// deprovisions them, even an ID-JAG issued before that (the receiver enforces it on its own).
// @better-auth/scim needs native transactions, so Node only (node:sqlite), not workerd's D1.
import { acquireActiveSCIMUserLink, scim } from "@better-auth/scim";
import type { BetterAuthPlugin } from "better-auth";
import { scimProvisioning } from "better-auth-scim-provisioning";
import { describe, expect, it } from "vitest";
import { createClient, getIdToken, signUp } from "../support/issuer-host";
import { decodeJwtPart, exchangeAt, idpHost, type McpHost, mcpClient, mcpHost, redeemAt, routedFetch } from "../support/interop-hosts";

const IDP = "https://idp.example";
const IDP_ISSUER = `${IDP}/api/auth`;
const MCP = "https://mcp.example";
const MCP_ISSUER = `${MCP}/api/auth`;
const MCP_RESOURCE = `${MCP}/mcp`;
const CONNECTION = "our-idp";
const TOKEN = "receiver-scim-bearer-token-that-is-long-enough";
const workerd = typeof navigator !== "undefined" && navigator.userAgent === "Cloudflare-Workers";

async function world() {
  const mapping: { atResource?: string } = {};
  const receiver: { host?: McpHost } = {};
  const idp = await idpHost({
    base: IDP,
    issuer: { authorize: (i) => (i.audience === MCP_ISSUER ? { decision: "allow", scopes: ["read"], ...(mapping.atResource ? { clientIdAtResource: mapping.atResource } : {}) } : { decision: "deny" }) },
    plugins: [
      scimProvisioning({
        targets: [{ id: "mcp", type: "scim", url: `${MCP}/api/auth/scim/v2`, token: TOKEN, fetch: (input, init) => (receiver.host as McpHost).auth.handler(new Request(input, init)) }],
      }) as unknown as BetterAuthPlugin,
    ],
  });
  const mcp = await mcpHost({
    base: MCP,
    resource: MCP_RESOURCE,
    plugins: [scim({ connections: [{ id: CONNECTION, credentials: [{ type: "bearer", id: "our-idp-token", token: TOKEN }] }] }) as unknown as BetterAuthPlugin],
    receiver: {
      trustedIssuers: [{ issuer: IDP_ISSUER, jwksUri: `${IDP_ISSUER}/jwks`, scim: { connectionId: CONNECTION } }],
      scim: { acquireActiveSCIMUserLink: acquireActiveSCIMUserLink as never },
      fetch: routedFetch(idp).fetch,
    },
  });
  receiver.host = mcp;
  const atMcp = await mcpClient(mcp);
  mapping.atResource = atMcp.client_id;
  const owner = await signUp(idp);
  const atIdp = await createClient(idp, owner.browser);
  /** A user signed up at the IdP who verified their email (so the IdP's SCIM client provisions them), and an ID-JAG for them. */
  const userWithIdJag = async () => {
    const user = await signUp(idp);
    // better-auth-scim-provisioning provisions users with a verified email only (requireVerifiedEmail).
    await idp.ctx.internalAdapter.updateUser(user.id, { emailVerified: true });
    await idp.settle();
    const idToken = await getIdToken(idp, user.browser, atIdp);
    const jag = await exchangeAt(idp, atIdp, idToken, { audience: MCP_ISSUER, resource: MCP_RESOURCE, scope: "read" });
    expect(jag.status, JSON.stringify(jag.body)).toBe(200);
    return { user, idToken, idJag: jag.body.access_token as string };
  };
  const exchange = async (idToken: string) => (await exchangeAt(idp, atIdp, idToken, { audience: MCP_ISSUER, resource: MCP_RESOURCE, scope: "read" })).body.access_token as string;
  const scimUserFor = (externalId: string) => mcp.ctx.adapter.findOne<{ userId: string; active: boolean }>({ model: "scimUser", where: [{ field: "externalId", value: externalId }] });
  return { idp, mcp, atMcp, userWithIdJag, exchange, scimUserFor };
}

describe.skipIf(workerd)("better-auth-scim-provisioning at the IdP → @better-auth/scim + our receiver at the MCP AS", () => {
  it("an ID-JAG resolves to the user the IdP provisioned, by SCIM; the access token is that user's", async () => {
    const w = await world();
    const { user, idJag } = await w.userWithIdJag();
    expect(decodeJwtPart(idJag, 1).sub).toBe(user.id);
    const provisioned = await w.scimUserFor(user.id);
    expect(provisioned).toMatchObject({ active: true });
    const r = await redeemAt(w.mcp, w.atMcp, idJag);
    expect(r.status, r.text).toBe(200);
    expect(decodeJwtPart(r.body.access_token as string, 1).sub).toBe(provisioned?.userId);
    expect(w.mcp.accepted.at(-1)).toMatchObject({ sub: user.id, userId: provisioned?.userId, resolvedBy: "scim" });
  });

  it("banned at the IdP: deprovisioned, and the receiver refuses an ID-JAG issued before the ban; unbanned: the same user again", async () => {
    const w = await world();
    const { user, idToken, idJag } = await w.userWithIdJag();
    const provisioned = await w.scimUserFor(user.id);
    await w.idp.ctx.internalAdapter.updateUser(user.id, { banned: true });
    await w.idp.settle();
    expect(await w.scimUserFor(user.id)).toMatchObject({ active: false });
    const refused = await redeemAt(w.mcp, w.atMcp, idJag);
    expect(refused.body).toEqual({ error: "invalid_grant", error_description: "The grant is invalid." });
    expect(w.mcp.refused.at(-1)).toMatchObject({ reason: "unknown_subject", detail: "SCIM: no active provisioned user for this sub" });
    await w.idp.ctx.internalAdapter.updateUser(user.id, { banned: false });
    await w.idp.settle();
    const again = await redeemAt(w.mcp, w.atMcp, await w.exchange(idToken));
    expect(again.status, again.text).toBe(200);
    expect(decodeJwtPart(again.body.access_token as string, 1).sub).toBe(provisioned?.userId);
  });

  it("deleted at the IdP: deprovisioned, and its last ID-JAG is refused at the receiver", async () => {
    const w = await world();
    const { user, idJag } = await w.userWithIdJag();
    await w.idp.ctx.internalAdapter.deleteUser(user.id);
    await w.idp.settle();
    const r = await redeemAt(w.mcp, w.atMcp, idJag);
    expect(r.status).toBe(400);
    expect(w.mcp.refused.at(-1)).toMatchObject({ reason: "unknown_subject" });
  });
});
