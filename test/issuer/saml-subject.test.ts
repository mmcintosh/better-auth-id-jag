// Path (a), D-B26: a SAML assertion this IdP issued (verified and consumed by better-auth-saml-idp,
// here a stub of its frozen interface) exchanged directly for an ID-JAG. Each of the SAML IdP's
// error codes maps onto one of our refusals (P3-S12), and a verifier that accepts anything still
// can't widen what we mint: the user, ban, blocks and policy are ours.
import { describe, expect, it } from "vitest";
import { ID_JAG_TOKEN_TYPE, publicDescription, type ReasonCode, SAML2_TOKEN_TYPE } from "../../src/core";
import { type AuthorizeInput, type AuthorizeResult, BLOCK_MODEL } from "../../src/issuer";
import {
  AUDIENCE,
  CODE_MAP,
  createIssuerHost,
  createSamlHost,
  type exchange,
  exchangeSaml,
  FakeAssertionExchangeError,
  type IssuerHost,
  PERSISTENT,
  RESOURCE,
  SAML_IDP_ENTITY_ID,
  SAML_SP_ENTITY_ID,
  type SamlHost,
  samlToken,
  samlTokenStd,
  setupSaml,
  takeReasons,
  verifyWithHostJwks,
} from "../support/issuer-host";

const GENERIC_GRANT = { error: "invalid_grant", error_description: "The grant is invalid." };
const allow = (): AuthorizeResult => ({ decision: "allow", scopes: ["read", "write"] });

async function refused(host: IssuerHost, r: Awaited<ReturnType<typeof exchange>>, reason: ReasonCode) {
  expect(r.body, JSON.stringify(r.body)).toEqual({ error: "invalid_grant", error_description: publicDescription(reason) });
  expect(r.status).toBe(400);
  expect(takeReasons(host)).toEqual([reason]);
}

async function world(o: { authorize?: (i: AuthorizeInput) => AuthorizeResult; saml?: NonNullable<Parameters<typeof createSamlHost>[0]>["saml"]; provider?: Record<string, unknown> } = {}) {
  const host = await createSamlHost({ issuer: { authorize: o.authorize ?? allow }, ...(o.saml ? { saml: o.saml } : {}), ...(o.provider ? { provider: o.provider } : {}) });
  const a = await setupSaml(host);
  const assertion = (x: Partial<Parameters<SamlHost["idp"]["issue"]>[0]> = {}) => host.idp.issue({ userId: a.user.id, clientId: a.client.client_id, ...x });
  return { host, ...a, assertion };
}

describe("path (a): saml2 → ID-JAG", () => {
  it("an assertion this IdP issued yields an ID-JAG core verifyIdJag accepts: sub the user, auth_time its AuthnInstant, acr its class", async () => {
    const seen: AuthorizeInput[] = [];
    const { host, client, user, assertion } = await world({
      authorize: (i) => {
        seen.push(i);
        return { decision: "allow", scopes: ["read"], clientIdAtResource: "agent-at-rs" };
      },
    });
    const authnInstant = new Date(Math.floor(Date.now() / 1000) * 1000 - 42_000);
    const a = assertion({ authnInstant, acr: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport" });
    const before = Date.now();
    const r = await exchangeSaml(host, client, samlToken(a.xml), { scope: "read write", resource: RESOURCE });
    expect(r.status, JSON.stringify(r.body)).toBe(200);
    expect(r.body).toMatchObject({ issued_token_type: ID_JAG_TOKEN_TYPE, token_type: "N_A", scope: "read", expires_in: 300 });
    const parsed = await verifyWithHostJwks(host, r.body.access_token as string);
    expect(parsed.claims).toMatchObject({ sub: user.id, aud: AUDIENCE, client_id: "agent-at-rs", scope: "read", resource: RESOURCE, auth_time: authnInstant.getTime() / 1000, acr: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport" });
    expect(parsed.claims.amr).toBeUndefined();
    // The verifier got the decoded XML, the authenticated client's id, and our clock.
    expect(host.idp.calls).toHaveLength(1);
    expect(host.idp.calls[0]?.xml).toBe(a.xml);
    expect(host.idp.calls[0]?.clientId).toBe(client.client_id);
    expect(host.idp.calls[0]?.now?.getTime()).toBeGreaterThanOrEqual(before);
    expect(host.idp.calls[0]?.now?.getTime()).toBeLessThanOrEqual(Date.now());
    // The policy sees what the assertion said, never the assertion.
    expect(seen[0]?.subjectToken).toMatchObject({ tokenType: SAML2_TOKEN_TYPE, sub: user.id, auth_time: authnInstant.getTime() / 1000 });
    expect(seen[0]?.subjectToken.raw).toEqual({ issuer: SAML_IDP_ENTITY_ID, spEntityId: SAML_SP_ENTITY_ID, nameIdFormat: PERSISTENT, assertionId: a.id, notOnOrAfter: expect.any(Number) });
    expect(JSON.stringify(seen[0]?.subjectToken)).not.toContain("<saml:");
    expect(host.recorded.issued).toHaveLength(1);
    expect(host.recorded.issued[0]).toMatchObject({ userId: user.id, clientId: client.client_id, audience: AUDIENCE });
  });

  it("padded standard base64 works too; one ID-JAG per assertion", async () => {
    const { host, client, assertion } = await world();
    const a = assertion();
    expect((await exchangeSaml(host, client, samlTokenStd(a.xml))).status).toBe(200);
    expect(host.idp.calls[0]?.xml).toBe(a.xml);
  });

  it("off unless saml.subjectTokens: unsupported_subject_token_type, and the verifier is never called", async () => {
    for (const saml of [{ refreshTokens: {} }, { subjectTokens: false }]) {
      const { host, client, assertion } = await world({ saml });
      const r = await exchangeSaml(host, client, samlToken(assertion().xml));
      expect(r.body).toEqual({ error: "invalid_request", error_description: publicDescription("unsupported_subject_token_type") });
      expect(takeReasons(host)).toEqual(["unsupported_subject_token_type"]);
      expect(host.idp.calls).toHaveLength(0);
    }
    // And without any saml option (no SAML IdP at all), as before Phase 3.
    const plain = await createIssuerHost({ issuer: { authorize: allow } });
    const p = await setupSaml(plain);
    expect((await exchangeSaml(plain, p.client, samlToken("<x/>"))).body.error_description).toBe(publicDescription("unsupported_subject_token_type"));
  });

  it("every SAML IdP error code maps to its refusal (P3-S12): one generic body for all but the time window", async () => {
    const { host, client, assertion } = await world();
    const bodies = new Set<string>();
    for (const [code, reason] of CODE_MAP) {
      host.idp.failWith = code;
      const r = await exchangeSaml(host, client, samlToken(assertion().xml));
      expect(r.status, code).toBe(400);
      expect(takeReasons(host), code).toEqual([reason]);
      if (reason !== "subject_token_expired" && reason !== "not_yet_valid") bodies.add(JSON.stringify(r.body));
      else expect(r.body, code).toEqual({ error: "invalid_grant", error_description: publicDescription(reason) });
    }
    // ALREADY_EXCHANGED and WRONG_CLIENT can't be told from NOT_OURS (or any other failure).
    expect([...bodies]).toEqual([JSON.stringify(GENERIC_GRANT)]);
    expect(publicDescription("subject_token_expired")).toBe("The subject token has expired.");
    expect(publicDescription("not_yet_valid")).toBe("The assertion is not yet valid.");
  });

  it("the audit detail names the code; an unknown code, a non-AssertionExchangeError throw and a malformed result fail closed", async () => {
    const { host, client, assertion } = await world();
    const errors: unknown[] = [];
    const original = host.ctx.logger.error;
    host.ctx.logger.error = (...a: unknown[]) => void errors.push(a);
    try {
      host.idp.failWith = "WRONG_CLIENT";
      await exchangeSaml(host, client, samlToken(assertion().xml));
      host.idp.failWith = new FakeAssertionExchangeError("SOMETHING_NEW");
      await exchangeSaml(host, client, samlToken(assertion().xml));
      host.idp.failWith = new TypeError("boom");
      await exchangeSaml(host, client, samlToken(assertion().xml));
      host.idp.failWith = undefined;
      const good = host.idp.verified({ id: "_x", userId: "u" });
      const malformed: unknown[] = [undefined, null, "yes", {}, { ...good, userId: "" }, { ...good, userId: 7 }, { ...good, authnInstant: "2026-01-01T00:00:00Z" }, { ...good, authnInstant: new Date(Number.NaN) }, { ...good, serviceProvider: { id: "s" } }, { ...good, assertionId: undefined }, { ...good, notOnOrAfter: undefined }, { ...good, authnContextClassRef: 1 }];
      for (const m of malformed) {
        host.idp.override = () => m;
        const r = await exchangeSaml(host, client, samlToken(assertion().xml));
        expect(r.body, JSON.stringify(m)).toEqual(GENERIC_GRANT);
      }
    } finally {
      host.ctx.logger.error = original;
    }
    const details = host.recorded.refused.map((e) => [e.reason, e.detail]);
    expect(details.slice(0, 3)).toEqual([
      ["invalid_subject_token", "saml2: WRONG_CLIENT: forced WRONG_CLIENT"],
      ["invalid_subject_token", "saml2: the verifier failed"],
      ["invalid_subject_token", "saml2: the verifier failed"],
    ]);
    for (const d of details.slice(3)) expect(d).toEqual(["invalid_subject_token", "saml2: the verifier returned a malformed result"]);
    expect(details).toHaveLength(15);
    // The operator hears about the two unexpected throws and every malformed result.
    expect(errors).toHaveLength(14);
  });

  it("single use (P3-S5, our side): the same assertion twice is a replay; another client's is WRONG_CLIENT (P3-S3); neither is distinguishable", async () => {
    const { host, client, assertion } = await world();
    const other = await setupSaml(host);
    const a = assertion();
    expect((await exchangeSaml(host, client, samlToken(a.xml))).status).toBe(200);
    const replay = await exchangeSaml(host, client, samlToken(a.xml));
    expect(replay.body).toEqual(GENERIC_GRANT);
    expect(takeReasons(host)).toEqual(["replay"]);
    const b = assertion();
    const wrong = await exchangeSaml(host, other.client, samlToken(b.xml));
    expect(wrong.body).toEqual(GENERIC_GRANT);
    expect(host.recorded.refused.map((e) => e.detail)).toEqual(["saml2: WRONG_CLIENT"]);
    expect(host.idp.calls.at(-1)?.clientId).toBe(other.client.client_id);
    takeReasons(host);
    // Never ours at all.
    expect((await exchangeSaml(host, client, samlToken('<saml:Assertion ID="_unknown"/>'))).body).toEqual(GENERIC_GRANT);
    // The rightful client can still use b: WRONG_CLIENT didn't consume it (the IdP's order).
    expect((await exchangeSaml(host, client, samlToken(b.xml))).status).toBe(200);
  });

  it("expired and not-yet-valid assertions: the public refusals, with the IdP deciding the window on our clock", async () => {
    const { host, client, assertion } = await world();
    await refused(host, await exchangeSaml(host, client, samlToken(assertion({ lifetimeSeconds: -1 }).xml)), "subject_token_expired");
    await refused(host, await exchangeSaml(host, client, samlToken(assertion({ notBefore: new Date(Date.now() + 60_000) }).xml)), "not_yet_valid");
  });

  it("a malformed token is refused before the verifier is called: nothing consumed", async () => {
    const { host, client } = await world();
    for (const t of ["not base64!", "QUJ", btoa(String.fromCharCode(0xff, 0xfe)), "A".repeat(87_385)]) {
      const r = await exchangeSaml(host, client, t);
      expect(r.body).toEqual(GENERIC_GRANT);
    }
    expect(takeReasons(host)).toEqual(["invalid_subject_token", "invalid_subject_token", "invalid_subject_token", "invalid_subject_token"]);
    expect(host.idp.calls).toHaveLength(0);
  });

  it("a large assertion (just under the SAML IdP's 65536-byte cap) is accepted over HTTP", async () => {
    const { host, client, assertion } = await world();
    const a = assertion({ filler: 65_000 });
    const token = samlToken(a.xml);
    expect(new TextEncoder().encode(a.xml).length).toBeGreaterThan(65_000);
    expect(token.length).toBeLessThanOrEqual(87_384);
    const r = await exchangeSaml(host, client, token);
    expect(r.status, JSON.stringify(r.body)).toBe(200);
    expect(host.idp.calls[0]?.xml).toBe(a.xml);
  });

  it("request errors come before the verifier: a bad request never burns the assertion", async () => {
    const { host, client, assertion } = await world();
    const a = assertion();
    for (const form of [{ audience: undefined }, { audience: "http://rs.example" }, { resource: [RESOURCE, `${RESOURCE}/2`] }, { actor_token: "x", actor_token_type: SAML2_TOKEN_TYPE }, { scope: "x".repeat(5000) }]) {
      expect((await exchangeSaml(host, client, samlToken(a.xml), form)).status).toBe(400);
    }
    expect(host.idp.calls).toHaveLength(0);
    expect((await exchangeSaml(host, client, samlToken(a.xml))).status).toBe(200);
  });

  it("a pairwise client is refused before the verifier (D-B02)", async () => {
    const host = await createSamlHost({ provider: { pairwiseSecret: "p".repeat(40) }, issuer: { authorize: allow } });
    const a = await setupSaml(host, { clientExtra: { subject_type: "pairwise" } });
    const r = await exchangeSaml(host, a.client, samlToken(host.idp.issue({ userId: a.user.id, clientId: a.client.client_id }).xml));
    expect(r.body).toEqual(GENERIC_GRANT);
    expect(host.recorded.refused.map((e) => e.detail)).toEqual(["pairwise subject (not supported in v1)"]);
    expect(host.idp.calls).toHaveLength(0);
  });
});

describe("path (a): a verifier that accepts anything can't widen what we mint", () => {
  it("the user must exist (re-read) and not be banned (P3-S7, our side)", async () => {
    const { host, client, user, assertion } = await world();
    host.idp.override = () => host.idp.verified({ id: "_any", userId: "no-such-user" });
    await refused(host, await exchangeSaml(host, client, samlToken(assertion().xml)), "unknown_subject");
    host.idp.override = () => host.idp.verified({ id: "_any", userId: user.id });
    await host.ctx.adapter.update({ model: "user", where: [{ field: "id", value: user.id }], update: { banned: true } });
    await refused(host, await exchangeSaml(host, client, samlToken(assertion().xml)), "banned_user");
  });

  it("blocks and the policy are ours: a block refuses, a deny refuses, scopes and audience are the policy's", async () => {
    let verdict: AuthorizeResult = { decision: "allow", scopes: ["read"] };
    const { host, client, user, owner, assertion } = await world({ authorize: () => verdict });
    host.idp.override = () => host.idp.verified({ id: "_any", userId: user.id });
    const ok = await exchangeSaml(host, client, samlToken(assertion().xml), { scope: "read write admin" });
    expect(ok.status).toBe(200);
    const claims = (await verifyWithHostJwks(host, ok.body.access_token as string)).claims;
    expect(claims).toMatchObject({ sub: user.id, aud: AUDIENCE, client_id: client.client_id, scope: "read" });
    verdict = { decision: "deny", reason: "no" };
    await refused(host, await exchangeSaml(host, client, samlToken(assertion().xml)), "policy_denied");
    verdict = { decision: "allow", scopes: ["read"] };
    await host.ctx.adapter.create({ model: BLOCK_MODEL, data: { userId: user.id, clientId: null, audience: null, reason: "r", createdBy: owner.id, createdAt: new Date(), expiresAt: null } });
    await refused(host, await exchangeSaml(host, client, samlToken(assertion().xml)), "blocked");
  });
});

describe("path (a): S10 (P3-S13)", () => {
  it("no outbound request, accepted or refused", async () => {
    const { host, client, assertion } = await world();
    const original = globalThis.fetch;
    const calls: string[] = [];
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      calls.push(String(input instanceof Request ? input.url : input));
      throw new Error("no outbound requests");
    }) as typeof fetch;
    try {
      expect((await exchangeSaml(host, client, samlToken(assertion().xml))).status).toBe(200);
      expect((await exchangeSaml(host, client, samlToken('<saml:Assertion ID="_nope"/>'))).status).toBe(400);
    } finally {
      globalThis.fetch = original;
    }
    expect(calls).toEqual([]);
  });
});
