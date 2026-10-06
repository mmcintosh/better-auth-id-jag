// The receiver end to end on mcp(): the happy path, metadata, and every reason code the handler
// can produce, each asserted by its audit reason and by the response body.
import { createLocalJWKSet, jwtVerify } from "jose";
import { describe, expect, it } from "vitest";
import { ID_JAG_GRANT_PROFILE, JWT_BEARER_GRANT, publicDescription, REASONS, type ReasonCode } from "../../src/core";
import type { IdJagGrantOptions } from "../../src/receiver";
import {
  BASE,
  type Client,
  createClient,
  decodePayload,
  ISSUER,
  linkedUser,
  MCP_RESOURCE,
  network,
  type ReceiverHost,
  type Recorder,
  receiverHost,
  recorder,
  redeem,
  signUp,
  type TestIdp,
  testIdp,
} from "../support/receiver-host";

interface Setup {
  h: ReceiverHost;
  idp: TestIdp;
  rec: Recorder;
  client: Client;
  net: ReturnType<typeof network>;
  /** A valid ID-JAG for a linked user, with claim overrides. */
  valid: (over?: Record<string, unknown>, header?: Record<string, unknown>) => Promise<string>;
  userId: string;
  sub: string;
}

async function setup(o: { receiver?: Partial<IdJagGrantOptions>; admin?: boolean; clientScope?: string } = {}): Promise<Setup> {
  const idp = await testIdp();
  const net = network(idp);
  const rec = recorder();
  const h = await receiverHost("mcp", {
    receiver: { trustedIssuers: [{ issuer: idp.issuer, jwksUri: idp.jwksUri }], fetch: net.fetch, ...o.receiver },
    recorder: rec,
    ...(o.admin ? { admin: true } : {}),
  });
  const client = await createClient(h, o.clientScope ? { scope: o.clientScope } : {});
  const sub = `sub-${crypto.randomUUID()}`;
  const user = await linkedUser(h, `id-jag:${idp.issuer}`, sub);
  const valid = (over: Record<string, unknown> = {}, header: Record<string, unknown> = {}) => idp.mint(idp.claims({ sub, client_id: client.client_id, ...over }), header);
  return { h, idp, rec, client, net, valid, userId: user.id, sub };
}

/** Assert a refusal by its audit reason and by the body the caller sees. */
async function expectRefusal(s: Setup, r: { status: number; body: Record<string, unknown> }, reason: ReasonCode) {
  await s.rec.settle();
  expect(s.rec.refused.at(-1)?.reason, JSON.stringify(r.body)).toBe(reason);
  expect(r.body).toEqual({ error: REASONS[reason].error, error_description: publicDescription(reason) });
  expect(r.status).toBe(REASONS[reason].error === "invalid_client" ? 401 : 400);
}

describe("receiver: a valid ID-JAG", () => {
  it("carries act (who acts for the user, as Okta sends for an AI agent) into the access token (D-010)", async () => {
    const s = await setup();
    const act = { sub: "0oa-agent", sub_profile: "ai_agent web_app" };
    const r = await redeem(s.h, s.client, await s.valid({ act }));
    expect(r.status, r.text).toBe(200);
    const jwks = (await (await s.h.auth.handler(new Request(`${ISSUER}/jwks`))).json()) as never;
    const at = await jwtVerify(r.body.access_token as string, createLocalJWKSet(jwks), { issuer: ISSUER, audience: MCP_RESOURCE });
    expect(at.payload.act).toEqual(act);
    // Without act in the ID-JAG, none in the access token.
    const plain = await redeem(s.h, s.client, await s.valid());
    const at2 = await jwtVerify(plain.body.access_token as string, createLocalJWKSet(jwks), { issuer: ISSUER, audience: MCP_RESOURCE });
    expect(at2.payload).not.toHaveProperty("act");
  });

  it("yields an access token audience-restricted to the MCP resource, with no refresh token and no ID token", async () => {
    const s = await setup();
    // The ID-JAG asks for openid and offline_access too; the client may use refresh_token.
    const r = await redeem(s.h, s.client, await s.valid({ scope: "read openid offline_access" }));
    expect(r.status, r.text).toBe(200);
    expect(r.body.token_type).toBe("Bearer");
    expect(r.body.scope).toBe("read");
    // Regression guard (review): provider internals could start issuing these.
    expect(r.body).not.toHaveProperty("refresh_token");
    expect(r.body).not.toHaveProperty("id_token");
    const jwks = (await (await s.h.auth.handler(new Request(`${ISSUER}/jwks`))).json()) as never;
    const at = await jwtVerify(r.body.access_token as string, createLocalJWKSet(jwks), { issuer: ISSUER, audience: MCP_RESOURCE });
    expect(at.payload.aud).toBe(MCP_RESOURCE);
    expect(at.payload.sub).toBe(s.userId);
    expect(at.payload.client_id).toBe(s.client.client_id);
    expect(at.payload.idjag).toMatchObject({ iss: s.idp.issuer });
    await s.rec.settle();
    expect(s.rec.accepted).toHaveLength(1);
    expect(s.rec.accepted[0]).toMatchObject({ type: "id-jag.accepted", iss: s.idp.issuer, sub: s.sub, userId: s.userId, clientId: s.client.client_id, resource: MCP_RESOURCE, scopes: ["read"] });
    // S10: the only outbound request was the trusted issuer's JWKS.
    expect(s.net.urls()).toEqual([s.idp.jwksUri]);
    expect(s.net.calls[0]?.init.redirect).toBe("manual");
  });

  it("is advertised: authorization_grant_profiles_supported and jwt-bearer in grant_types_supported", async () => {
    const s = await setup();
    const doc = (await (await s.h.auth.handler(new Request(`${BASE}/.well-known/oauth-authorization-server/api/auth`))).json()) as Record<string, unknown>;
    expect(doc.authorization_grant_profiles_supported).toEqual([ID_JAG_GRANT_PROFILE]);
    expect(doc.grant_types_supported).toContain(JWT_BEARER_GRANT);
    expect(doc.issuer).toBe(ISSUER);
  });
});

describe("receiver: every refusal, by reason and by body", () => {
  it("missing_parameter: no assertion", async () => {
    const s = await setup();
    await expectRefusal(s, await redeem(s.h, s.client, undefined), "missing_parameter");
  });

  it("malformed_token, wrong_typ (a plain RFC 7523 assertion), disallowed_alg, missing_kid", async () => {
    const s = await setup();
    await expectRefusal(s, await redeem(s.h, s.client, "not.a.jwt"), "malformed_token");
    await expectRefusal(s, await redeem(s.h, s.client, await s.valid({}, { typ: "JWT" })), "wrong_typ");
    // A JWT with no typ at all (an ID token, an access token) is not an ID-JAG either (S2).
    const b64 = (v: object) => btoa(JSON.stringify(v)).replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
    const claims = s.idp.claims({ client_id: s.client.client_id });
    await expectRefusal(s, await redeem(s.h, s.client, `${b64({ alg: "ES256", kid: "k" })}.${b64(claims)}.c2ln`), "wrong_typ");
    await expectRefusal(s, await redeem(s.h, s.client, `${b64({ alg: "HS256", kid: "k", typ: "oauth-id-jag+jwt" })}.${b64(claims)}.c2ln`), "disallowed_alg");
    await expectRefusal(s, await redeem(s.h, s.client, `${b64({ alg: "ES256", typ: "oauth-id-jag+jwt" })}.${b64(claims)}.c2ln`), "missing_kid");
  });

  it("missing_claim, unsupported_claim, invalid_claim, lifetime_too_long", async () => {
    const s = await setup();
    await expectRefusal(s, await redeem(s.h, s.client, await s.valid({ jti: undefined })), "missing_claim");
    await expectRefusal(s, await redeem(s.h, s.client, await s.valid({ authorization_details: [{ type: "x", actions: ["read"] }] })), "unsupported_claim");
    await expectRefusal(s, await redeem(s.h, s.client, await s.valid({ aud: [ISSUER, "https://other.example"] })), "invalid_claim");
    const t = Math.floor(Date.now() / 1000);
    await expectRefusal(s, await redeem(s.h, s.client, await s.valid({ iat: t, exp: t + 901 })), "lifetime_too_long");
  });

  it("expired and not_yet_valid, before any trust lookup (no fetch)", async () => {
    const s = await setup();
    const t = Math.floor(Date.now() / 1000);
    await expectRefusal(s, await redeem(s.h, s.client, await s.valid({ iat: t - 400, exp: t - 100 })), "expired");
    await expectRefusal(s, await redeem(s.h, s.client, await s.valid({ iat: t + 200, exp: t + 400 })), "not_yet_valid");
    expect(s.net.calls).toHaveLength(0);
  });

  it("untrusted_issuer: no fetch to the claimed issuer", async () => {
    const s = await setup();
    const stranger = await testIdp();
    const token = await stranger.mint(stranger.claims({ client_id: s.client.client_id }));
    await expectRefusal(s, await redeem(s.h, s.client, token), "untrusted_issuer");
    expect(s.net.calls).toHaveLength(0);
  });

  it("S8: an expired token from an untrusted issuer says expired, exactly as from a trusted one", async () => {
    const s = await setup();
    const stranger = await testIdp();
    const t = Math.floor(Date.now() / 1000);
    const fromStranger = await redeem(s.h, s.client, await stranger.mint(stranger.claims({ client_id: s.client.client_id, iat: t - 400, exp: t - 100 })));
    await expectRefusal(s, fromStranger, "expired");
    const fromTrusted = await redeem(s.h, s.client, await s.valid({ iat: t - 400, exp: t - 100 }));
    expect(fromTrusted.text).toBe(fromStranger.text);
  });

  it("self_issued: our own issuer configured as trusted is still refused", async () => {
    const s = await setup();
    const self = await setup({ receiver: { trustedIssuers: [{ issuer: ISSUER, jwksUri: "https://self.example/jwks" }] } });
    const token = await s.idp.mint(s.idp.claims({ iss: ISSUER, client_id: self.client.client_id }));
    await expectRefusal(self, await redeem(self.h, self.client, token), "self_issued");
  });

  it("jwks_unavailable: the issuer's JWKS can't be fetched", async () => {
    const s = await setup();
    s.idp.override = () => new Response("down", { status: 503 });
    await expectRefusal(s, await redeem(s.h, s.client, await s.valid()), "jwks_unavailable");
  });

  it("bad_signature: signed by a key the issuer doesn't publish, under a published kid", async () => {
    const s = await setup();
    const forger = await s.idp.signingKey("ES256", s.idp.key.kid);
    const token = await s.idp.mint(s.idp.claims({ sub: s.sub, client_id: s.client.client_id }), {}, forger);
    await expectRefusal(s, await redeem(s.h, s.client, token), "bad_signature");
  });

  it("wrong_audience: aud compared exactly (no trailing slash, case or path games)", async () => {
    const s = await setup();
    for (const aud of [`${ISSUER}/`, ISSUER.toUpperCase(), "http://LOCALHOST:3000/api/auth", BASE, `${ISSUER}/oauth2/token`, "https://localhost:3000/api/auth"]) {
      await expectRefusal(s, await redeem(s.h, s.client, await s.valid({ aud })), "wrong_audience");
    }
    // A one-element array is the same audience.
    expect((await redeem(s.h, s.client, await s.valid({ aud: [ISSUER] }))).status).toBe(200);
  });

  it("client_mismatch: the client_id claim must be the authenticated client's id here", async () => {
    const s = await setup();
    const other = await createClient(s.h);
    await expectRefusal(s, await redeem(s.h, other, await s.valid()), "client_mismatch");
    await expectRefusal(s, await redeem(s.h, s.client, await s.valid({ client_id: `${s.client.client_id} ` })), "client_mismatch");
  });

  it("client_mismatch: a client not in the issuer's allowedClientIds", async () => {
    const idp = await testIdp();
    const net = network(idp);
    const rec = recorder();
    const h = await receiverHost("mcp", { receiver: { trustedIssuers: [{ issuer: idp.issuer, jwksUri: idp.jwksUri, allowedClientIds: ["someone-else"] }], fetch: net.fetch }, recorder: rec });
    const client = await createClient(h);
    const sub = crypto.randomUUID();
    await linkedUser(h, `id-jag:${idp.issuer}`, sub);
    const r = await redeem(h, client, await idp.mint(idp.claims({ sub, client_id: client.client_id })));
    await rec.settle();
    expect(rec.refused.at(-1)?.reason).toBe("client_mismatch");
    expect(r.body.error).toBe("invalid_grant");
  });

  it("no_scope: nothing left after the intersection; refused before the subject is looked up", async () => {
    const s = await setup();
    await expectRefusal(s, await redeem(s.h, s.client, await s.valid({ scope: "admin" })), "no_scope");
    await expectRefusal(s, await redeem(s.h, s.client, await s.valid({ scope: undefined })), "no_scope");
    // Only openid / offline_access: stripped, so nothing is left.
    await expectRefusal(s, await redeem(s.h, s.client, await s.valid({ scope: "openid offline_access" })), "no_scope");
    // S8: the same for a subject nobody here knows.
    await expectRefusal(s, await redeem(s.h, s.client, await s.valid({ scope: "admin", sub: "nobody" })), "no_scope");
  });

  it("unknown_resource (invalid_target): a resource outside the registered set, in the claim or the request", async () => {
    const s = await setup();
    await expectRefusal(s, await redeem(s.h, s.client, await s.valid({ resource: "https://elsewhere.example/mcp" })), "unknown_resource");
    await expectRefusal(s, await redeem(s.h, s.client, await s.valid({ resource: undefined }), { resource: "https://elsewhere.example/mcp" }), "unknown_resource");
    // The request may only pick among the claim's resources.
    await expectRefusal(s, await redeem(s.h, s.client, await s.valid(), { resource: "http://localhost:3000/other" }), "unknown_resource");
    await expectRefusal(s, await redeem(s.h, s.client, await s.valid({ resource: [MCP_RESOURCE, "http://localhost:3000/other"] })), "unknown_resource");
    // No claim, no request parameter: the one registered resource.
    const r = await redeem(s.h, s.client, await s.valid({ resource: undefined }));
    expect(r.status, r.text).toBe(200);
    expect(decodePayload(r.body.access_token as string).aud).toBe(MCP_RESOURCE);
  });

  it("requireResourceClaim: no `resource` claim is the public missing_claim, before trust, keys and jti", async () => {
    const s = await setup({ receiver: { requireResourceClaim: true } });
    const jti = `jti-${crypto.randomUUID()}`;
    await expectRefusal(s, await redeem(s.h, s.client, await s.valid({ resource: undefined, jti })), "missing_claim");
    expect(s.rec.refused.at(-1)?.detail).toBe("resource");
    // A request parameter doesn't stand in for the claim, and defaultResource isn't consulted.
    await expectRefusal(s, await redeem(s.h, s.client, await s.valid({ resource: undefined }), { resource: MCP_RESOURCE }), "missing_claim");
    // Checked before the signature: no keys were fetched for it.
    expect(s.net.calls).toHaveLength(0);
    // The same answer for an issuer nobody trusts (S8: it says nothing about trust).
    const stranger = await testIdp();
    await expectRefusal(s, await redeem(s.h, s.client, await stranger.mint(stranger.claims({ client_id: s.client.client_id, resource: undefined }))), "missing_claim");
    // The refused token's jti wasn't recorded: the same jti with the claim is accepted.
    const r = await redeem(s.h, s.client, await s.valid({ jti }));
    expect(r.status, r.text).toBe(200);
    expect(decodePayload(r.body.access_token as string).aud).toBe(MCP_RESOURCE);
  });

  it("replay: the same ID-JAG twice", async () => {
    const s = await setup();
    const token = await s.valid();
    expect((await redeem(s.h, s.client, token)).status).toBe(200);
    await expectRefusal(s, await redeem(s.h, s.client, token), "replay");
  });

  it("unknown_subject: a subject with no linked account and no fallback", async () => {
    const s = await setup();
    await expectRefusal(s, await redeem(s.h, s.client, await s.valid({ sub: "nobody", email: "nobody@example.com" })), "unknown_subject");
  });

  it("subject_rejected: the host's hook says reject", async () => {
    const s = await setup({ receiver: { resolveSubject: () => ({ action: "reject" }) } });
    await expectRefusal(s, await redeem(s.h, s.client, await s.valid()), "subject_rejected");
  });

  it("banned_user: a banned user is refused; one whose ban expired is accepted", async () => {
    const s = await setup({ admin: true });
    await s.h.ctx.internalAdapter.updateUser(s.userId, { banned: true });
    await expectRefusal(s, await redeem(s.h, s.client, await s.valid()), "banned_user");
    await s.h.ctx.internalAdapter.updateUser(s.userId, { banned: true, banExpires: new Date(Date.now() + 60_000) });
    await expectRefusal(s, await redeem(s.h, s.client, await s.valid()), "banned_user");
    await s.h.ctx.internalAdapter.updateUser(s.userId, { banned: true, banExpires: new Date(Date.now() - 60_000) });
    expect((await redeem(s.h, s.client, await s.valid())).status).toBe(200);
  });

  it("only refusals after client authentication are marked authenticated", async () => {
    const s = await setup();
    await redeem(s.h, s.client, "garbage");
    await s.rec.settle();
    expect(s.rec.refused.at(-1)).toMatchObject({ reason: "malformed_token", authenticated: true, clientId: s.client.client_id });
  });
});

describe("receiver: client authentication (S5)", () => {
  it("no credentials, a wrong secret, a public client: invalid_client; nothing accepted", async () => {
    const s = await setup();
    const token = await s.valid();
    const none = await redeem(s.h, null, token, { client_id: s.client.client_id });
    expect(none.body.error).toBe("invalid_client");
    const wrong = await redeem(s.h, { client_id: s.client.client_id, secret: "nope" } as unknown as Client, token);
    expect(wrong.body.error).toBe("invalid_client");
    // The provider's refusal goes out unchanged, and is audited with the client id the caller named.
    await s.rec.settle();
    expect(s.rec.refused.at(-1)).toMatchObject({ reason: "client_authentication_failed", authenticated: false, clientId: s.client.client_id, detail: "invalid_client" });
    const pub = await createClient(s.h, { authMethod: "none" });
    const asPublic = await redeem(s.h, null, await s.valid({ client_id: pub.client_id }), { client_id: pub.client_id });
    expect(asPublic.body.error, asPublic.text).toBe("invalid_client");
    await s.rec.settle();
    expect(s.rec.accepted).toHaveLength(0);
    // The same ID-JAG is still redeemable by its client: nothing above consumed its jti.
    expect((await redeem(s.h, s.client, token)).status).toBe(200);
  });

  it("a client not registered for the jwt-bearer grant: unauthorized_client", async () => {
    const s = await setup();
    const other = await createClient(s.h, { grantTypes: ["authorization_code"] });
    const r = await redeem(s.h, other, await s.valid({ client_id: other.client_id }));
    expect(r.body.error).toBe("unauthorized_client");
    await s.rec.settle();
    expect(s.rec.refused.at(-1)).toMatchObject({ reason: "client_not_allowed_grant", authenticated: false, clientId: other.client_id });
  });

  it("allowPublicClients: a public client is accepted, and the startup warning is logged", async () => {
    const warnings: string[] = [];
    const s = await setup({ receiver: { allowPublicClients: true } });
    // The warning is logged from init; check it on a fresh instance with a captured logger.
    const { betterAuth } = await import("better-auth");
    const { idJagGrant } = await import("../../src/receiver");
    const { oauthProvider } = await import("@better-auth/oauth-provider");
    const { jwt } = await import("better-auth/plugins");
    const { database } = await import("../support/receiver-host");
    const probe = betterAuth({
      baseURL: BASE,
      database: (await database()) as never,
      secret: "test-secret-that-is-at-least-32-characters-long",
      telemetry: { enabled: false },
      logger: { level: "warn", log: (_l, m) => void warnings.push(m) },
      plugins: [jwt(), oauthProvider({ loginPage: "/l", consentPage: "/c" }) as never, idJagGrant({ allowPublicClients: true, trustedIssuers: [{ issuer: "https://idp.example", jwksUri: "https://idp.example/jwks" }] })],
    });
    await probe.$context;
    expect(warnings.some((w) => w.includes("allowPublicClients"))).toBe(true);
    const pub = await createClient(s.h, { authMethod: "none" });
    const r = await redeem(s.h, null, await s.valid({ client_id: pub.client_id }), { client_id: pub.client_id });
    expect(r.status, r.text).toBe(200);
  });
});

describe("receiver: scopes only narrow (S7)", () => {
  it("ID-JAG ∩ request scope ∩ client scopes ∩ resource scopes", async () => {
    const s = await setup({ clientScope: "read write" });
    const all = await redeem(s.h, s.client, await s.valid({ scope: "read write profile admin" }));
    expect(all.status, all.text).toBe(200);
    // profile: not the client's; admin: nobody's.
    expect(all.body.scope).toBe("read write");
    const narrowed = await redeem(s.h, s.client, await s.valid({ scope: "read write" }), { scope: "write admin" });
    expect(narrowed.body.scope).toBe("write");
  });

  it("allowEmptyScope: an empty intersection issues a token with no scope", async () => {
    const s = await setup({ receiver: { allowEmptyScope: true } });
    const r = await redeem(s.h, s.client, await s.valid({ scope: "admin" }));
    expect(r.status, r.text).toBe(200);
    expect(r.body.scope).toBe("");
  });
});

describe("receiver: S8, refusals the caller can't tell apart", () => {
  it("unknown subject, untrusted issuer, bad signature, replay, wrong audience, client mismatch: byte-identical bodies", async () => {
    const s = await setup();
    const stranger = await testIdp();
    const forger = await s.idp.signingKey("ES256", s.idp.key.kid);
    const replayed = await s.valid();
    expect((await redeem(s.h, s.client, replayed)).status).toBe(200);
    const other = await createClient(s.h);
    const results = [
      await redeem(s.h, s.client, await s.valid({ sub: "nobody" })),
      await redeem(s.h, s.client, await stranger.mint(stranger.claims({ client_id: s.client.client_id }))),
      await redeem(s.h, s.client, await s.idp.mint(s.idp.claims({ sub: s.sub, client_id: s.client.client_id }), {}, forger)),
      await redeem(s.h, s.client, replayed),
      await redeem(s.h, s.client, await s.valid({ aud: `${ISSUER}/` })),
      await redeem(s.h, other, await s.valid()),
    ];
    await s.rec.settle();
    expect(s.rec.refused.map((e) => e.reason)).toEqual(["unknown_subject", "untrusted_issuer", "bad_signature", "replay", "wrong_audience", "client_mismatch"]);
    const first = results[0]!;
    for (const r of results) {
      expect(r.status).toBe(first.status);
      expect(r.text).toBe(first.text);
    }
    expect(first.body).toEqual({ error: "invalid_grant", error_description: "The grant is invalid." });
  });
});

describe("receiver: signUp helper sanity", () => {
  it("clients are created by a signed-in user", async () => {
    const s = await setup();
    const { headers } = await signUp(s.h);
    expect((await createClient(s.h, { headers })).client_id).toBeTypeOf("string");
  });
});
