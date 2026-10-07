// Path (b), D-B27: a SAML assertion this IdP issued, exchanged for a refresh token (draft -04 §4.5,
// what Okta's SAML requesting app and MCP's Enterprise-Managed Authorization send), which then
// yields ID-JAGs through the existing refresh-token subject path (D-B14).
import { decodeJwt } from "jose";
import { describe, expect, it } from "vitest";
import { ID_JAG_TOKEN_TYPE, ID_TOKEN_TOKEN_TYPE, publicDescription, REFRESH_TOKEN_TOKEN_TYPE, type ReasonCode, SAML2_TOKEN_TYPE } from "../../src/core";
import { type AuthorizeResult, BLOCK_MODEL } from "../../src/issuer";
import {
  AUDIENCE,
  createSamlHost,
  exchange,
  exchangeRefresh,
  type IssuerHost,
  CODE_MAP,
  REFRESH_TOKEN_TYPE,
  RESOURCE,
  refresh,
  requestSamlRefresh,
  revoke,
  SAML_SP_ENTITY_ID,
  type SamlHost,
  samlToken,
  setupSaml,
  takeReasons,
  verifyWithHostJwks,
} from "../support/issuer-host";


const GENERIC_GRANT = { error: "invalid_grant", error_description: "The grant is invalid." };
const GENERIC_SCOPE = { error: "invalid_scope", error_description: "The requested scope is invalid." };
const allow = (): AuthorizeResult => ({ decision: "allow", scopes: ["read", "write"] });

async function world(o: { saml?: NonNullable<Parameters<typeof createSamlHost>[0]>["saml"]; provider?: Record<string, unknown>; issuer?: Record<string, unknown>; setup?: Parameters<typeof setupSaml>[1] } = {}) {
  const host = await createSamlHost({ issuer: { authorize: allow, ...o.issuer }, ...(o.saml ? { saml: o.saml } : {}), ...(o.provider ? { provider: o.provider } : {}) });
  const a = await setupSaml(host, o.setup);
  const assertion = (x: Partial<Parameters<SamlHost["idp"]["issue"]>[0]> = {}) => host.idp.issue({ userId: a.user.id, clientId: a.client.client_id, ...x });
  return { host, ...a, assertion };
}

const rows = (host: IssuerHost, model: string) => host.ctx.adapter.findMany<Record<string, unknown>>({ model, limit: 1000 });

async function refusedAs(host: IssuerHost, r: Awaited<ReturnType<typeof exchange>>, reason: ReasonCode, body: Record<string, string>) {
  expect(r.body, JSON.stringify(r.body)).toEqual(body);
  expect(takeReasons(host)).toEqual([reason]);
}

describe("path (b): saml2 → refresh token", () => {
  it("issues exactly the draft's response: the refresh token in access_token, token_type N_A, its lifetime in expires_in; no ID token, no access token left behind (T0)", async () => {
    const { host, client, user, assertion } = await world();
    const authnInstant = new Date(Math.floor(Date.now() / 1000) * 1000 - 30_000);
    const a = assertion({ authnInstant });
    const atBefore = (await rows(host, "oauthAccessToken")).length;
    const r = await requestSamlRefresh(host, client, samlToken(a.xml), { scope: "openid offline_access profile" });
    expect(r.status, JSON.stringify(r.body)).toBe(200);
    expect(Object.keys(r.body).sort()).toEqual(["access_token", "expires_in", "issued_token_type", "scope", "token_type"]);
    expect(r.body).toMatchObject({ issued_token_type: REFRESH_TOKEN_TOKEN_TYPE, token_type: "N_A", scope: "openid offline_access profile" });
    // The provider's default refresh-token lifetime: 30 days.
    expect(r.body.expires_in).toBeGreaterThanOrEqual(2_592_000 - 2);
    expect(r.body.expires_in).toBeLessThanOrEqual(2_592_000);
    expect(r.headers.get("cache-control")).toBe("no-store");
    // The refresh token's row: this client, this user, our scopes, the AuthnInstant, live.
    const [rt] = (await rows(host, "oauthRefreshToken")).filter((x) => x.userId === user.id);
    expect(rt).toMatchObject({ clientId: client.client_id, userId: user.id, revoked: null, confirmation: null });
    expect(JSON.parse(JSON.stringify(rt?.scopes)).toString()).toContain("offline_access");
    expect(new Date(rt?.authTime as string).getTime()).toBe(authnInstant.getTime());
    // T0: issueTokens also stored an opaque access token (1 h, linked to the refresh token); deleted.
    expect((await rows(host, "oauthAccessToken")).length).toBe(atBefore);
    // Audit: refresh-issued, not an ID-JAG.
    expect(host.recorded.issued).toHaveLength(0);
    expect(host.recorded.refreshIssued).toHaveLength(1);
    expect(host.recorded.refreshIssued[0]).toMatchObject({ type: "id-jag.refresh-issued", userId: user.id, clientId: client.client_id, scopes: ["openid", "offline_access", "profile"], spEntityId: SAML_SP_ENTITY_ID, assertionId: a.id });
    expect(JSON.stringify(host.recorded.refreshIssued[0])).not.toContain(r.body.access_token as string);
    expect(host.idp.calls[0]).toMatchObject({ xml: a.xml, clientId: client.client_id });
  });

  it("expires_in is the provider's configured refresh-token lifetime; its prefixes are honoured (and the stray access token still found)", async () => {
    const { host, client, assertion } = await world({ provider: { refreshTokenExpiresIn: 7200, prefix: { refreshToken: "rt_", opaqueAccessToken: "at_" } } });
    const r = await requestSamlRefresh(host, client, samlToken(assertion().xml));
    expect(r.status, JSON.stringify(r.body)).toBe(200);
    expect(r.body.expires_in).toBeGreaterThanOrEqual(7198);
    expect(r.body.expires_in).toBeLessThanOrEqual(7200);
    expect(String(r.body.access_token).startsWith("rt_")).toBe(true);
    expect(await rows(host, "oauthAccessToken")).toHaveLength(0);
  });

  it("P3-S15: the refresh token yields ID-JAGs through the refresh-token subject path, works at the token endpoint, is bound to its client and revocable", async () => {
    const { host, client, user, assertion } = await world();
    const other = await setupSaml(host);
    const authnInstant = new Date(Math.floor(Date.now() / 1000) * 1000 - 10_000);
    const r = await requestSamlRefresh(host, client, samlToken(assertion({ authnInstant }).xml));
    const rt = r.body.access_token as string;
    const jag = await exchangeRefresh(host, client, rt, { scope: "read", resource: RESOURCE });
    expect(jag.status, JSON.stringify(jag.body)).toBe(200);
    expect(jag.body.issued_token_type).toBe(ID_JAG_TOKEN_TYPE);
    const claims = (await verifyWithHostJwks(host, jag.body.access_token as string)).claims;
    expect(claims).toMatchObject({ sub: user.id, aud: AUDIENCE, client_id: client.client_id, scope: "read", auth_time: authnInstant.getTime() / 1000 });
    // Another client can't use it (the existing D-B15 check).
    const stolen = await exchangeRefresh(host, other.client, rt);
    expect(stolen.body).toEqual(GENERIC_GRANT);
    expect(host.recorded.refused.at(-1)?.detail).toBe("refresh token: issued to another client");
    // The client can refresh with it as with any refresh token (and the ID token from that is ours).
    const refreshed = await refresh(host, client, rt);
    expect(refreshed.status, JSON.stringify(refreshed.body)).toBe(200);
    expect(decodeJwt(refreshed.body.id_token as string).sub).toBe(user.id);
    const next = refreshed.body.refresh_token as string;
    // Revoked at /oauth2/revoke: refused afterwards.
    expect(await revoke(host, client, next)).toBe(200);
    const after = await exchangeRefresh(host, client, next);
    expect(after.body).toEqual(GENERIC_GRANT);
    expect(host.recorded.refused.at(-1)?.detail).toBe("refresh token: revoked");
  });

  it("revoking the refresh token straight away stops it too", async () => {
    const { host, client, assertion } = await world();
    const rt = (await requestSamlRefresh(host, client, samlToken(assertion().xml))).body.access_token as string;
    expect(await revoke(host, client, rt)).toBe(200);
    expect((await exchangeRefresh(host, client, rt)).body).toEqual(GENERIC_GRANT);
    expect((await refresh(host, client, rt)).status).toBe(400);
  });

  it("off unless saml.refreshTokens: requested_token_type=refresh_token is unsupported, and the verifier is never called", async () => {
    for (const saml of [{ subjectTokens: true }, { subjectTokens: true, refreshTokens: false as const }]) {
      const { host, client, assertion } = await world({ saml });
      const r = await requestSamlRefresh(host, client, samlToken(assertion().xml));
      await refusedAs(host, r, "unsupported_requested_token_type", { error: "invalid_request", error_description: publicDescription("unsupported_requested_token_type") });
      expect(host.idp.calls).toHaveLength(0);
    }
  });

  it("only saml2 → refresh_token: other subject token types for a refresh token, and other requested types, stay refused", async () => {
    const { host, client, assertion } = await world();
    for (const t of [ID_TOKEN_TOKEN_TYPE, REFRESH_TOKEN_TYPE, "urn:ietf:params:oauth:token-type:access_token", "urn:ietf:params:oauth:token-type:jwt"]) {
      const r = await requestSamlRefresh(host, client, samlToken(assertion().xml), { subject_token_type: t });
      await refusedAs(host, r, "unsupported_subject_token_type", { error: "invalid_request", error_description: publicDescription("unsupported_subject_token_type") });
    }
    for (const t of ["urn:ietf:params:oauth:token-type:access_token", "urn:ietf:params:oauth:token-type:id_token", "urn:ietf:params:oauth:token-type:saml2", `${REFRESH_TOKEN_TYPE} `]) {
      const r = await requestSamlRefresh(host, client, samlToken(assertion().xml), { requested_token_type: t });
      await refusedAs(host, r, "unsupported_requested_token_type", { error: "invalid_request", error_description: publicDescription("unsupported_requested_token_type") });
    }
    expect(host.idp.calls).toHaveLength(0);
  });

  it("P3-S9: openid and offline_access required (scope_required, public); within the configured list, the client's and the provider's scopes (no_scope); no audience or resource", async () => {
    const { host, client, assertion } = await world({ saml: { refreshTokens: { scopes: ["openid", "offline_access", "profile"] } } });
    const a = assertion();
    const token = samlToken(a.xml);
    const required = { error: "invalid_scope", error_description: "openid and offline_access are required." };
    for (const scope of [undefined, "", "openid", "offline_access", "openid profile", "offline_access profile email"]) await refusedAs(host, await requestSamlRefresh(host, client, token, { scope }), "scope_required", required);
    // email: the provider and the client have it, the configured list doesn't.
    await refusedAs(host, await requestSamlRefresh(host, client, token, { scope: "openid offline_access email" }), "no_scope", GENERIC_SCOPE);
    for (const form of [{ audience: AUDIENCE }, { audience: "" }, { resource: RESOURCE }]) {
      await refusedAs(host, await requestSamlRefresh(host, client, token, form), "unsupported_parameter", { error: "invalid_request", error_description: publicDescription("unsupported_parameter") });
    }
    // None of these reached the verifier, so the assertion is still good.
    expect(host.idp.calls).toHaveLength(0);
    expect((await requestSamlRefresh(host, client, token, { scope: "offline_access openid profile openid" })).body.scope).toBe("offline_access openid profile");
  });

  it("P3-S9: the client's registered scopes bound it too, as do the provider's", async () => {
    const { host, client, assertion } = await world({ saml: { refreshTokens: { scopes: ["openid", "offline_access", "profile", "email", "phone"] } }, setup: { clientExtra: { scope: "openid offline_access profile" } } });
    await refusedAs(host, await requestSamlRefresh(host, client, samlToken(assertion().xml), { scope: "openid offline_access email" }), "no_scope", GENERIC_SCOPE);
    expect(host.recorded.refused).toHaveLength(0);
    await requestSamlRefresh(host, client, samlToken(assertion().xml), { scope: "openid offline_access phone" });
    expect(host.recorded.refused.map((e) => [e.reason, e.detail])).toEqual([["no_scope", "phone not among the client's scopes"]]);
    expect(host.idp.calls).toHaveLength(0);
  });

  it("P3-S9: a scope the provider doesn't offer is refused even when configured and the client lists none", async () => {
    const { host, client, assertion } = await world({ saml: { refreshTokens: { scopes: ["openid", "offline_access", "phone"] } }, setup: { clientExtra: { scope: undefined } } });
    await requestSamlRefresh(host, client, samlToken(assertion().xml), { scope: "openid offline_access phone" });
    expect(host.recorded.refused.map((e) => [e.reason, e.detail])).toEqual([["no_scope", "phone not among the provider's scopes"]]);
  });

  it("P3-S9: the provider's scopes bound it when the client lists scopes too", async () => {
    const { host, client, assertion } = await world({ saml: { refreshTokens: { scopes: ["openid", "offline_access", "phone"] } } });
    // Registration refuses scopes the provider doesn't offer: this client was registered with phone
    // before the operator withdrew it from the provider.
    await host.ctx.adapter.update({ model: "oauthClient", where: [{ field: "clientId", value: client.client_id }], update: { scopes: ["openid", "offline_access", "phone"] } });
    await refusedAs(host, await requestSamlRefresh(host, client, samlToken(assertion().xml), { scope: "openid offline_access phone" }), "no_scope", GENERIC_SCOPE);
    expect(host.idp.calls).toHaveLength(0);
  });

  it("P3-S10: a public client is refused even with allowPublicClients; a client must list refresh_token itself", async () => {
    const pub = await world({ issuer: { allowPublicClients: true }, setup: { authMethod: "none" } });
    const r = await requestSamlRefresh(pub.host, { client_id: pub.client.client_id }, samlToken(pub.assertion().xml), { client_id: pub.client.client_id });
    expect(r.status).toBe(401);
    expect(r.body).toEqual({ error: "invalid_client", error_description: "Client authentication failed." });
    expect(takeReasons(pub.host)).toEqual(["public_client"]);
    expect(pub.host.idp.calls).toHaveLength(0);
    // authorization_code implies refresh_token at the provider (clientAllowsGrant); not here.
    const noRefresh = await world({ setup: { grantTypes: ["authorization_code", "urn:ietf:params:oauth:grant-type:token-exchange"] } });
    const n = await requestSamlRefresh(noRefresh.host, noRefresh.client, samlToken(noRefresh.assertion().xml));
    expect(n.body).toEqual({ error: "unauthorized_client", error_description: "The client is not authorized for this grant." });
    expect(takeReasons(noRefresh.host)).toEqual(["client_not_allowed_grant"]);
    expect(noRefresh.host.idp.calls).toHaveLength(0);
  });

  it("a pairwise client is refused before the verifier (D-B02)", async () => {
    const { host, client, assertion } = await world({ provider: { pairwiseSecret: "p".repeat(40) }, setup: { clientExtra: { subject_type: "pairwise" } } });
    const r = await requestSamlRefresh(host, client, samlToken(assertion().xml));
    expect(r.body).toEqual(GENERIC_GRANT);
    expect(host.recorded.refused.map((e) => e.detail)).toEqual(["pairwise subject (not supported in v1)"]);
    expect(host.idp.calls).toHaveLength(0);
  });

  it("P3-S11: (user), (user, client) and (client) blocks refuse; blocks naming an audience don't apply to a refresh token", async () => {
    const { host, client, user, owner, assertion } = await world();
    const block = (b: { userId?: string | null; clientId?: string | null; audience?: string | null }) =>
      host.ctx.adapter.create<Record<string, unknown>>({ model: BLOCK_MODEL, data: { userId: null, clientId: null, audience: null, reason: "r", createdBy: owner.id, createdAt: new Date(), expiresAt: null, ...b } });
    const clear = () => host.ctx.adapter.deleteMany({ model: BLOCK_MODEL, where: [{ field: "createdBy", value: owner.id }] });
    for (const b of [{ userId: user.id }, { userId: user.id, clientId: client.client_id }, { clientId: client.client_id }]) {
      const row = await block(b);
      const r = await requestSamlRefresh(host, client, samlToken(assertion().xml));
      expect(r.body, JSON.stringify(b)).toEqual(GENERIC_GRANT);
      expect(host.recorded.refused.map((e) => [e.reason, e.detail])).toEqual([["blocked", String(row.id)]]);
      host.recorded.refused.length = 0;
      await clear();
    }
    for (const b of [{ audience: AUDIENCE }, { userId: user.id, audience: AUDIENCE }, { clientId: client.client_id, audience: AUDIENCE }, { userId: user.id, clientId: client.client_id, audience: AUDIENCE }, { userId: "someone-else" }, { clientId: "another-client" }]) {
      await block(b);
      const r = await requestSamlRefresh(host, client, samlToken(assertion().xml));
      expect(r.status, JSON.stringify([b, r.body])).toBe(200);
      // The audience block applies later, when the refresh token is exchanged for that audience.
      if (b.audience && b.userId !== "someone-else") expect((await exchangeRefresh(host, client, r.body.access_token as string)).body).toEqual(GENERIC_GRANT);
      await clear();
    }
    expect(host.recorded.refreshIssued).toHaveLength(6);
  });

  it("every SAML IdP error code maps as for path (a), with the same bodies", async () => {
    const { host, client, assertion } = await world();
    for (const [code, reason] of CODE_MAP) {
      host.idp.failWith = code;
      const r = await requestSamlRefresh(host, client, samlToken(assertion().xml));
      expect(takeReasons(host), code).toEqual([reason]);
      expect(r.body, code).toEqual(reason === "subject_token_expired" || reason === "not_yet_valid" ? { error: "invalid_grant", error_description: publicDescription(reason) } : GENERIC_GRANT);
    }
    host.idp.failWith = undefined;
    const a = assertion();
    expect((await requestSamlRefresh(host, client, samlToken(a.xml))).status).toBe(200);
    expect((await requestSamlRefresh(host, client, samlToken(a.xml))).body).toEqual(GENERIC_GRANT);
    expect(takeReasons(host)).toEqual(["replay"]);
    expect(host.recorded.refreshIssued).toHaveLength(1);
  });

  it("a verifier that accepts anything can't widen it: unknown or banned users refused; the token is this client's, with only the scopes we checked", async () => {
    const { host, client, user, assertion } = await world();
    host.idp.override = () => host.idp.verified({ id: "_any", userId: "nobody" });
    await refusedAs(host, await requestSamlRefresh(host, client, samlToken(assertion().xml)), "unknown_subject", GENERIC_GRANT);
    host.idp.override = (_xml, expected) => ({ ...host.idp.verified({ id: "_any", userId: user.id }), clientId: "someone-else", scopes: ["admin"], expected });
    const r = await requestSamlRefresh(host, client, samlToken(assertion().xml), { scope: "openid offline_access email" });
    expect(r.status).toBe(200);
    const [row] = (await rows(host, "oauthRefreshToken")).filter((x) => x.userId === user.id);
    expect(row?.clientId).toBe(client.client_id);
    expect(JSON.stringify(row?.scopes)).toBe(JSON.stringify(["openid", "offline_access", "email"]));
    await host.ctx.adapter.update({ model: "user", where: [{ field: "id", value: user.id }], update: { banned: true } });
    await refusedAs(host, await requestSamlRefresh(host, client, samlToken(assertion().xml)), "banned_user", GENERIC_GRANT);
  });

  it("P3-S13: no outbound request, issued or refused", async () => {
    const { host, client, assertion } = await world();
    const original = globalThis.fetch;
    const calls: string[] = [];
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      calls.push(String(input instanceof Request ? input.url : input));
      throw new Error("no outbound requests");
    }) as typeof fetch;
    try {
      const r = await requestSamlRefresh(host, client, samlToken(assertion().xml));
      expect(r.status).toBe(200);
      expect((await exchangeRefresh(host, client, r.body.access_token as string)).status).toBe(200);
      expect((await requestSamlRefresh(host, client, samlToken('<saml:Assertion ID="_nope"/>'))).status).toBe(400);
    } finally {
      globalThis.fetch = original;
    }
    expect(calls).toEqual([]);
  });

  it("an ID token or refresh token subject for an ID-JAG is unchanged by the saml option", async () => {
    const { host, client, assertion } = await world();
    const rt = (await requestSamlRefresh(host, client, samlToken(assertion().xml))).body.access_token as string;
    expect((await exchange(host, client, rt, { subject_token_type: REFRESH_TOKEN_TYPE })).status).toBe(200);
    expect((await exchange(host, client, rt, { subject_token_type: SAML2_TOKEN_TYPE })).body).toEqual(GENERIC_GRANT);
  });
});
