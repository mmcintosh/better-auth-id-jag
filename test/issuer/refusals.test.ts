// Every refusal the issuer can produce, asserted by reason (onRefused) and by response body. The
// registry's own refusals (unknown_resource, no_policy without a resource server) are in
// registry.test.ts.
import { decodeJwt, decodeProtectedHeader, exportJWK, generateKeyPair, SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import { ID_JAG_TOKEN_TYPE, ID_TOKEN_TOKEN_TYPE, publicDescription, type ReasonCode, TOKEN_EXCHANGE_GRANT } from "../../src/core";
import type { AuthorizeResult } from "../../src/issuer";
import { BETTER_AUTH_1_8 } from "../support/better-auth-version";
import { AUDIENCE, createClient, createIssuerHost, exchange, getIdToken, getTokens, ISSUER, type IssuerHost, RESOURCE, setup, setupRefresh, signUp, takeReasons } from "../support/issuer-host";

const allow = (): AuthorizeResult => ({ decision: "allow", scopes: ["read"] });
const GENERIC_DENIED = { error: "access_denied", error_description: "The subject or client is not authorized for this request." };
const GENERIC_REQUEST = { error: "invalid_request", error_description: "The request is invalid." };

/** The exchange is refused for `reason`, with that reason's public body. */
async function refused(host: IssuerHost, r: Awaited<ReturnType<typeof exchange>>, reason: ReasonCode, error: string) {
  expect(r.body, JSON.stringify(r.body)).toEqual({ error, error_description: publicDescription(reason) });
  expect(r.status).toBe(error === "invalid_client" ? 401 : error === "server_error" ? 500 : 400);
  expect(takeReasons(host)).toEqual([reason]);
}

async function forged(o: { iss?: string; aud?: string; sub?: string; exp?: number; header?: Record<string, unknown>; kid?: string } = {}) {
  const { privateKey, publicKey } = await generateKeyPair("ES256", { extractable: true });
  const now = Math.floor(Date.now() / 1000);
  const token = await new SignJWT({ iss: o.iss ?? ISSUER, aud: o.aud ?? "x", sub: o.sub ?? "x", iat: now, exp: o.exp ?? now + 600 })
    .setProtectedHeader({ alg: "ES256", kid: o.kid ?? "forged-kid", ...o.header })
    .sign(privateKey);
  return { token, jwk: await exportJWK(publicKey) };
}

describe("refusals: the request (public reasons, specific descriptions)", () => {
  it("requested_token_type other than id-jag, or absent: unsupported_requested_token_type", async () => {
    const host = await createIssuerHost({ issuer: { authorize: allow } });
    const { client, idToken } = await setup(host);
    await refused(host, await exchange(host, client, idToken, { requested_token_type: "urn:ietf:params:oauth:token-type:access_token" }), "unsupported_requested_token_type", "invalid_request");
    await refused(host, await exchange(host, client, idToken, { requested_token_type: undefined }), "unsupported_requested_token_type", "invalid_request");
  });

  it("actor_token: actor_token_unsupported", async () => {
    const host = await createIssuerHost({ issuer: { authorize: allow } });
    const { client, idToken } = await setup(host);
    await refused(host, await exchange(host, client, idToken, { actor_token: idToken, actor_token_type: ID_TOKEN_TOKEN_TYPE }), "actor_token_unsupported", "invalid_request");
    await refused(host, await exchange(host, client, idToken, { actor_token_type: ID_TOKEN_TOKEN_TYPE }), "actor_token_unsupported", "invalid_request");
  });

  it("a DPoP proof: dpop_unsupported, never an unbound ID-JAG (draft -06 §9.11.1.1; D-066)", async () => {
    const host = await createIssuerHost({ issuer: { authorize: allow } });
    const { client, idToken } = await setup(host);
    await refused(host, await exchange(host, client, idToken, {}, { headers: { DPoP: "any-proof" } }), "dpop_unsupported", "invalid_request");
    // Without the header the same request is served.
    expect((await exchange(host, client, idToken)).status).toBe(200);
  });

  it("authorization_details: refused, never ignored (draft -06 §4.3.3: the IdP MUST process it)", async () => {
    // Ignoring it would issue the policy's scopes to a client that asked for something narrower.
    const host = await createIssuerHost({ issuer: { authorize: () => ({ decision: "allow", scopes: ["read", "write"] }) } });
    const { client, idToken } = await setup(host);
    for (const value of ['[{"type":"chat_read","actions":["read"]}]', "", "not json"])
      await refused(host, await exchange(host, client, idToken, { authorization_details: value, scope: undefined }), "authorization_details_unsupported", "invalid_request");
    expect((await exchange(host, client, idToken, { scope: undefined })).status).toBe(200);
  });

  it("subject_token, subject_token_type or audience missing: missing_parameter", async () => {
    const host = await createIssuerHost({ issuer: { authorize: allow } });
    const { client, idToken } = await setup(host);
    for (const name of ["subject_token", "subject_token_type", "audience"]) {
      await refused(host, await exchange(host, client, idToken, { [name]: undefined }), "missing_parameter", "invalid_request");
      expect(host.recorded.refused).toHaveLength(0);
    }
  });

  it("a subject_token_type other than id_token: unsupported_subject_token_type", async () => {
    const host = await createIssuerHost({ issuer: { authorize: allow } });
    const { client, idToken } = await setup(host);
    for (const t of ["urn:ietf:params:oauth:token-type:access_token", "urn:ietf:params:oauth:token-type:saml2", "urn:ietf:params:oauth:token-type:jwt"])
      await refused(host, await exchange(host, client, idToken, { subject_token_type: t }), "unsupported_subject_token_type", "invalid_request");
  });

  it("an audience that isn't an https issuer identifier, or our own issuer: invalid_audience; several: repeated_audience (D-059)", async () => {
    const host = await createIssuerHost({ issuer: { authorize: allow } });
    const { client, idToken } = await setup(host);
    // Draft -06 §4.3.3: more than one audience MUST be invalid_request.
    await refused(host, await exchange(host, client, idToken, { audience: [AUDIENCE, "https://other.example"] }), "repeated_audience", "invalid_request");
    await refused(host, await exchange(host, client, idToken, { audience: [AUDIENCE, AUDIENCE] }), "repeated_audience", "invalid_request");
    for (const audience of ["http://rs.example", "https://rs.example/#x", "https://rs.example/?a=1", "rs.example", "https://user@rs.example", "https://rs.example/ a", "", ISSUER]) {
      const r = await exchange(host, client, idToken, { audience });
      // An empty audience is a missing one.
      await refused(host, r, audience === "" ? "missing_parameter" : "invalid_audience", audience === "" ? "invalid_request" : "invalid_target");
    }
  });

  it("a resource that isn't an absolute URI without a fragment: invalid_resource, never a 500", async () => {
    const host = await createIssuerHost({ issuer: { authorize: allow } });
    const { client, idToken } = await setup(host);
    // These pass the provider's own resource check (1.7 and 1.8) and used to reach the ID-JAG builder: a 500.
    for (const resource of [`https://rs.example/${"x".repeat(2100)}`, "https://rs.example/\u0001", "https://rs.example/a\u007fb", "https://rs.example/a\nb"])
      await refused(host, await exchange(host, client, idToken, { resource }), "invalid_resource", "invalid_target");
    // These the provider refuses first on 1.7 (invalid_request, before our handler); on 1.8 an empty one reaches us.
    for (const resource of ["", " ", "rel/path", "https://rs.example/mcp#x"]) {
      const r = await exchange(host, client, idToken, { resource });
      expect(r.status, JSON.stringify(resource)).toBe(400);
      expect(["invalid_request", "invalid_target"], JSON.stringify(r.body)).toContain(r.body.error);
      takeReasons(host);
    }
    expect((await exchange(host, client, idToken, { resource: "urn:example:mcp" })).status).toBe(200);
  });

  it("allowLoopbackHttpAudiences admits http://localhost only", async () => {
    const host = await createIssuerHost({ issuer: { authorize: allow, allowLoopbackHttpAudiences: true } });
    const { client, idToken } = await setup(host);
    expect((await exchange(host, client, idToken, { audience: "http://localhost:4000/api/auth" })).status).toBe(200);
    await refused(host, await exchange(host, client, idToken, { audience: "http://rs.example/api/auth" }), "invalid_audience", "invalid_target");
    // Our own issuer (http://localhost here) is refused as an audience even then.
    await refused(host, await exchange(host, client, idToken, { audience: ISSUER }), "invalid_audience", "invalid_target");
  });

  it("a repeated parameter, two resources, an over-long scope: unsupported_parameter", async () => {
    const host = await createIssuerHost({ issuer: { authorize: allow } });
    const { client, idToken } = await setup(host);
    for (const repeated of [{ scope: ["read", "write"] }, { subject_token: [idToken, idToken] }]) {
      const r = await exchange(host, client, idToken, repeated);
      if (!BETTER_AUTH_1_8) await refused(host, r, "unsupported_parameter", "invalid_request");
      else {
        // 1.8 refuses a repeated parameter (other than resource and audience) itself, before our handler (D-056).
        expect(r.status).toBe(400);
        expect(r.body.error).toBe("invalid_request");
        expect(r.body).not.toHaveProperty("access_token");
        expect(takeReasons(host)).toEqual([]);
      }
    }
    await refused(host, await exchange(host, client, idToken, { resource: [RESOURCE, "https://mcp2.example/mcp"] }), "unsupported_parameter", "invalid_request");
    await refused(host, await exchange(host, client, idToken, { scope: "a".repeat(4097) }), "unsupported_parameter", "invalid_request");
  });

  it("a resource that isn't an absolute URI is the provider's invalid_target, before our handler", async () => {
    const host = await createIssuerHost({ issuer: { authorize: allow } });
    const { client, idToken } = await setup(host);
    const r = await exchange(host, client, idToken, { resource: "not a uri" });
    expect(r.status).toBe(400);
    expect(takeReasons(host)).toEqual([]);
  });
});

describe("refusals: the client (S5)", () => {
  it("a public client: public_client, 401 with a Basic challenge; a confidential client without its secret too", async () => {
    const host = await createIssuerHost({ issuer: { authorize: allow } });
    const owner = await signUp(host);
    const pub = await createClient(host, owner.browser, { authMethod: "none", extra: { application_type: "native" } });
    const idToken = await getIdToken(host, owner.browser, pub);
    const r = await exchange(host, null, idToken, { client_id: pub.client_id });
    await refused(host, r, "public_client", "invalid_client");
    expect(r.headers.get("www-authenticate")).toMatch(/^Basic /);
    expect(host.recorded.refused).toHaveLength(0);

    const { client, idToken: confidential } = await setup(host);
    await refused(host, await exchange(host, null, confidential, { client_id: client.client_id }), "public_client", "invalid_client");
  });

  it("refusals before client authentication say authenticated: false and aren't stored; after it, true and stored", async () => {
    const host = await createIssuerHost({ issuer: { authorize: allow, auditLog: { retentionDays: 1 } } });
    const { client, idToken } = await setup(host);
    await exchange(host, null, idToken, { client_id: client.client_id });
    await exchange(host, client, idToken, { subject_token_type: "urn:x" });
    expect(host.recorded.refused.map((e) => [e.reason, e.authenticated])).toEqual([
      ["public_client", false],
      ["unsupported_subject_token_type", true],
    ]);
    const rows = await host.ctx.adapter.findMany<Record<string, unknown>>({ model: "idJagAudit", where: [{ field: "type", value: "id-jag.refused" }] });
    const mine = rows.filter((r) => r.clientId === client.client_id);
    expect(mine.map((r) => r.reason)).toEqual(["unsupported_subject_token_type"]);
  });

  it("allowPublicClients: a public client gets an ID-JAG, and startup warns", async () => {
    const warnings: string[] = [];
    const host = await createIssuerHost({ issuer: { authorize: allow, allowPublicClients: true }, auth: { logger: { level: "warn", log: (_l: string, m: string) => void warnings.push(m) } } });
    expect(warnings.some((w) => w.includes("allowPublicClients") && w.includes("outside draft -06 §4.3.3"))).toBe(true);
    const owner = await signUp(host);
    const pub = await createClient(host, owner.browser, { authMethod: "none", extra: { application_type: "native" } });
    const idToken = await getIdToken(host, owner.browser, pub);
    const r = await exchange(host, null, idToken, { client_id: pub.client_id });
    expect(r.status, JSON.stringify(r.body)).toBe(200);
  });

  it("the provider's own client refusals pass through unchanged, and are audited (not stored): a wrong secret, a client not registered for token exchange", async () => {
    const host = await createIssuerHost({ issuer: { authorize: allow } });
    const { client, idToken, user, owner } = await setup(host);
    await host.settle();
    takeReasons(host);
    const wrong = await exchange(host, { client_id: client.client_id, client_secret: "wrong" }, idToken);
    expect(wrong.body.error).toBe("invalid_client");
    await host.settle();
    expect(host.recorded.refused.at(-1)).toMatchObject({ reason: "client_authentication_failed", authenticated: false, detail: "invalid_client" });
    const codeOnly = await createClient(host, owner.browser, { grantTypes: ["authorization_code"] });
    const own = await getIdToken(host, user.browser, codeOnly);
    expect((await exchange(host, codeOnly, own)).body.error).toBe("unauthorized_client");
    await host.settle();
    expect(host.recorded.refused.at(-1)).toMatchObject({ reason: "client_not_allowed_grant", authenticated: false });
  });
});

describe("refusals: the subject token (S6)", () => {
  it("an ID token from another issuer (a real one, from a second IdP) is refused", async () => {
    const host = await createIssuerHost({ issuer: { authorize: allow } });
    const other = await createIssuerHost({ withoutIssuer: true, baseURL: "http://other.localhost:3000" });
    const { client } = await setup(host);
    const o = await setup(other, { grantTypes: ["authorization_code"] });
    expect(decodeJwt(o.idToken).iss).toBe("http://other.localhost:3000/api/auth");
    await refused(host, await exchange(host, client, o.idToken), "invalid_subject_token", "invalid_request");
    // Forged with our client as audience but another iss: refused at iss, before any key.
    const f = await forged({ iss: "https://trusted-elsewhere.example", aud: client.client_id });
    await refused(host, await exchange(host, client, f.token), "invalid_subject_token", "invalid_request");
  });

  it("refuses, by step: another client's ID token, a forged key, a tampered payload, wrong typ (an ID-JAG), alg none/HS256, no kid, not a JWT", async () => {
    const host = await createIssuerHost({ issuer: { authorize: allow } });
    const details: string[] = [];
    const { client, idToken, user, owner } = await setup(host);
    const second = await createClient(host, owner.browser);
    const step = async (token: string, c = client) => {
      await refused(host, await exchange(host, c, token), "invalid_subject_token", "invalid_request");
    };
    await step(idToken, second); // aud is the first client
    await step((await forged({ aud: client.client_id, sub: user.id })).token); // unknown kid
    // Our kid, someone else's key.
    const kid = (decodeJwt(idToken) && (JSON.parse(atob(idToken.split(".")[0]!.replace(/-/g, "+").replace(/_/g, "/"))) as { kid: string }).kid) as string;
    await step((await forged({ aud: client.client_id, sub: user.id, kid })).token);
    // Tampered payload, our signature.
    const [h, p, s] = idToken.split(".");
    const claims = JSON.parse(atob(p!.replace(/-/g, "+").replace(/_/g, "/"))) as Record<string, unknown>;
    const tampered = btoa(JSON.stringify({ ...claims, sub: "someone-else" })).replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
    await step(`${h}.${tampered}.${s}`);
    // An ID-JAG we issued is not an ID token.
    const idJag = (await exchange(host, client, idToken)).body.access_token as string;
    await step(idJag);
    const b64 = (v: unknown) => btoa(JSON.stringify(v)).replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
    await step(`${b64({ alg: "none", kid })}.${p}.`);
    await step(`${b64({ alg: "HS256", kid })}.${p}.${s}`);
    await step(`${b64({ alg: "ES256" })}.${p}.${s}`);
    await step(`${b64({ alg: "ES256", kid, typ: "at+jwt" })}.${p}.${s}`);
    await step(`${b64({ alg: "ES256", kid, crit: ["x"], x: 1 })}.${p}.${s}`);
    await step("not-a-jwt");
    await step("a".repeat(17 * 1024));
    for (const e of host.recorded.refused) if (e.detail) details.push(e.detail);
  });

  it("names each step in the audit detail", async () => {
    const host = await createIssuerHost({ issuer: { authorize: allow } });
    const { client, idToken, owner } = await setup(host);
    const second = await createClient(host, owner.browser);
    await exchange(host, second, idToken);
    await exchange(host, client, (await forged({ aud: client.client_id })).token);
    await exchange(host, client, (await forged({ iss: "https://elsewhere.example", aud: client.client_id })).token);
    expect(host.recorded.refused.map((e) => e.detail)).toEqual(["audience is not the authenticated client", "unknown kid", "issuer"]);
  });

  it("an expired ID token is refused (no grace): subject_token_expired", async () => {
    const host = await createIssuerHost({ provider: { idTokenExpiresIn: 1 }, issuer: { authorize: allow } });
    const { client, idToken } = await setup(host);
    await new Promise((r) => setTimeout(r, 2100));
    await refused(host, await exchange(host, client, idToken), "subject_token_expired", "invalid_request");
  });

  it("a pairwise client's ID token is refused explicitly (its sub isn't the user id)", async () => {
    const host = await createIssuerHost({ provider: { pairwiseSecret: "p".repeat(40) }, issuer: { authorize: allow } });
    const owner = await signUp(host);
    const pairwise = await createClient(host, owner.browser, { extra: { subject_type: "pairwise" } });
    const idToken = await getIdToken(host, owner.browser, pairwise);
    expect(decodeJwt(idToken).sub).not.toBe(owner.id);
    await refused(host, await exchange(host, pairwise, idToken), "pairwise_client", "access_denied");
    expect(host.recorded.refused.length).toBe(0);
  });

  it("a user who no longer exists: unknown_subject; a banned user: banned_user", async () => {
    const host = await createIssuerHost({ issuer: { authorize: allow } });
    const a = await setup(host);
    await host.ctx.adapter.update({ model: "user", where: [{ field: "id", value: a.user.id }], update: { banned: true } });
    await refused(host, await exchange(host, a.client, a.idToken), "banned_user", "access_denied");
    // A ban that has expired doesn't count.
    await host.ctx.adapter.update({ model: "user", where: [{ field: "id", value: a.user.id }], update: { banExpires: new Date(Date.now() - 1000) } });
    expect((await exchange(host, a.client, a.idToken)).status).toBe(200);
    const b = await setup(host);
    await host.ctx.adapter.deleteMany({ model: "session", where: [{ field: "userId", value: b.user.id }] });
    await host.ctx.adapter.delete({ model: "user", where: [{ field: "id", value: b.user.id }] });
    await refused(host, await exchange(host, b.client, b.idToken), "unknown_subject", "access_denied");
  });
});

describe("refusals: policy (S1, S7)", () => {
  it("no policy source configured: no_policy, and a startup warning", async () => {
    const warnings: string[] = [];
    const host = await createIssuerHost({ auth: { logger: { level: "warn", log: (_l: string, m: string) => void warnings.push(m) } } });
    expect(warnings.some((w) => w.includes("no policy source"))).toBe(true);
    const { client, idToken } = await setup(host);
    await refused(host, await exchange(host, client, idToken), "no_policy", "access_denied");
  });

  it("the hook denies or answers something malformed: policy_denied; it throws: a 500 server_error, not access_denied (a reason goes to the audit only)", async () => {
    let verdict: () => unknown = () => ({ decision: "deny", reason: "not on a weekend\n" });
    const host = await createIssuerHost({ issuer: { authorize: (() => verdict()) as never } });
    const { client, idToken } = await setup(host);
    await refused(host, await exchange(host, client, idToken), "policy_denied", "access_denied");
    // Its database is down, say: our failure, so the client mustn't be told a new token won't help.
    verdict = () => {
      throw new Error("boom");
    };
    await refused(host, await exchange(host, client, idToken), "internal_error", "server_error");
    for (const v of [
      () => true,
      () => ({ decision: "allow" }),
      () => ({ decision: "allow", scopes: "read" }),
      () => ({ decision: "maybe", scopes: [] }),
      () => undefined,
    ]) {
      verdict = v;
      await refused(host, await exchange(host, client, idToken), "policy_denied", "access_denied");
    }
  });

  it("a malformed act is policy_denied: not true/false/{ sub_profile }, and never another actor's sub (D-036)", async () => {
    let act: unknown;
    const host = await createIssuerHost({ issuer: { authorize: (() => ({ decision: "allow", scopes: ["read"], claims: { act } })) as never } });
    const { client, idToken } = await setup(host);
    for (const a of ["yes", 1, null, { sub: "someone-else" }, { sub_profile: "" }, { sub_profile: "ai\nagent" }, { sub_profile: "x".repeat(257) }, { sub_profile: 7 }]) {
      act = a;
      await refused(host, await exchange(host, client, idToken), "policy_denied", "access_denied");
    }
  });

  it("a sub_profile that is blank, padded, or carries invisible or separator characters is policy_denied (D-036)", async () => {
    let sub_profile = "";
    const host = await createIssuerHost({ issuer: { authorize: (() => ({ decision: "allow", scopes: ["read"], claims: { act: { sub_profile } } })) as never } });
    const { client, idToken } = await setup(host);
    // Blank, leading/trailing/doubled space, tab, NBSP, zero-width space, RTL override, BOM, U+2028, U+2029, word joiner;
    for (const p of [" ", " ai_agent", "ai_agent ", "ai_agent  web_app", "ai_agent\tweb_app", "ai_agent\u00a0web_app", "ai\u200bagent", "ai_agent\u202e", "\ufeffai_agent", "ai\u2028agent", "ai\u2029agent", "ai\u2060agent",
      // Blank-looking letters and symbols (Hangul fillers, blank braille), combining marks (variation selectors, CGJ,
      // one after the space), private use, unassigned (U+2065, which the audit would strip), a noncharacter, a lone surrogate.
      "ai_agent\u3164web_app", "\u115fai", "ai\uffa0", "ai\u2800agent", "ai\ufe0f", "ai\u{e0100}", "ai\u034fagent", "ai_agent \u0301web_app", "ai\ue000", "ai\u2065agent", "ai\uffff", "ai\ud800agent"]) {
      sub_profile = p;
      await refused(host, await exchange(host, client, idToken), "policy_denied", "access_denied");
    }
    // Space-separated names (Okta's form), non-ASCII letters, symbols, 256 code points (zod counts code points) are fine.
    for (const p of ["ai_agent", "ai_agent web_app", "agent-é", "x".repeat(256), "🤖".repeat(256), "urn:example:agent/v1"]) {
      sub_profile = p;
      expect((await exchange(host, client, idToken)).status, p).toBe(200);
    }
  });

  it("the hook's details stay in the audit log, made log-safe", async () => {
    const host = await createIssuerHost({ issuer: { authorize: () => ({ decision: "deny", reason: "line one\nfake line" }) } });
    const { client, idToken } = await setup(host);
    const r = await exchange(host, client, idToken);
    expect(JSON.stringify(r.body)).not.toContain("line one");
    expect(host.recorded.refused[0]?.detail).toBe("authorize: line onefake line");
  });

  it("the hook asks for step-up: insufficient_user_authentication with its parameters, audited as step_up_required (D-043)", async () => {
    let stepUp: unknown = { maxAge: 300, acrValues: ["phr"], description: "Confirm it's you, then try again.", uri: "https://idp.example/confirm?next=%2Fagents" };
    const host = await createIssuerHost({ issuer: { authorize: (() => ({ decision: "deny", reason: "mfa too old", stepUp })) as never } });
    const { client, idToken } = await setup(host);
    const r = await exchange(host, client, idToken);
    expect(r.status).toBe(400);
    expect(r.headers.get("cache-control")).toBe("no-store");
    expect(r.body).toEqual({ error: "insufficient_user_authentication", error_description: "Confirm it's you, then try again.", error_uri: "https://idp.example/confirm?next=%2Fagents", max_age: 300, acr_values: "phr" });
    expect(host.recorded.refused[0]?.detail).toBe("authorize: mfa too old (max_age=300 acr_values=phr error_uri=https://idp.example/confirm?next=%2Fagents)");
    expect(takeReasons(host)).toEqual(["step_up_required"]);
    stepUp = {};
    await refused(host, await exchange(host, client, idToken), "step_up_required", "insufficient_user_authentication");
  });

  it("a malformed stepUp is policy_denied, with the generic body (D-043)", async () => {
    let stepUp: unknown;
    const host = await createIssuerHost({ issuer: { authorize: (() => ({ decision: "deny", stepUp })) as never } });
    const { client, idToken } = await setup(host);
    for (const s of [
      true,
      "https://idp.example/confirm",
      { url: "https://idp.example/confirm" },
      { maxAge: -1 },
      { maxAge: 1.5 },
      { maxAge: "300" },
      { acrValues: [] },
      { acrValues: ["has space"] },
      { acrValues: ['q"uote'] },
      { acrValues: "phr" },
      { description: 'say "hi"' },
      { description: "back\\slash" },
      { description: "line\nbreak" },
      { description: "café" },
      { description: "" },
      { description: "x".repeat(301) },
      { uri: "http://idp.example/confirm" },
      { uri: "javascript:alert(1)" },
      { uri: "/confirm" },
      { uri: "https://user:pw@idp.example/confirm" },
      { uri: "https://idp.example/confirm#x" },
      { uri: "https://idp.example/confirm#" },
      { uri: "https://idp.example/con firm" },
      { uri: "https://idp.example/é" },
      { uri: `https://idp.example/${"x".repeat(2048)}` },
    ]) {
      stepUp = s;
      await refused(host, await exchange(host, client, idToken), "policy_denied", "access_denied");
    }
    // At the edges: every allowed punctuation mark, 300 characters, a bare max_age of 0.
    for (const s of [{ description: "Confirm it's you: https://idp.example/x?a=1&b=[2] {ok} ~!@$%^*()_+-=|;,./<>?`" }, { description: "x".repeat(300) }, { maxAge: 0 }]) {
      stepUp = s;
      expect((await exchange(host, client, idToken)).body.error, JSON.stringify(s)).toBe("insufficient_user_authentication");
    }
  });

  it("no requested scope is allowed: no_scope (only after an allow)", async () => {
    const host = await createIssuerHost({ issuer: { authorize: allow } });
    const { client, idToken } = await setup(host);
    await refused(host, await exchange(host, client, idToken, { scope: "write admin" }), "no_scope", "invalid_scope");
  });

  it("the hook names another resource than the one asked for: policy_denied", async () => {
    const host = await createIssuerHost({ issuer: { authorize: () => ({ decision: "allow", scopes: ["read"], resource: "https://elsewhere.example/mcp" }) } });
    const { client, idToken } = await setup(host);
    await refused(host, await exchange(host, client, idToken, { resource: RESOURCE }), "policy_denied", "access_denied");
  });

  it("the hook says the audience is unknown: unknown_audience, invalid_target (draft -06 §4.3.3, D-059); its reason goes to the audit only", async () => {
    const host = await createIssuerHost({ issuer: { authorize: ({ audience }) => (audience === AUDIENCE ? allow() : { decision: "unknown_audience", reason: "SECRET-REASON" }) } });
    const { client, idToken } = await setup(host);
    const r = await exchange(host, client, idToken, { audience: "https://elsewhere.example" });
    expect(host.recorded.refused.at(-1)?.detail).toBe("authorize: SECRET-REASON");
    await refused(host, r, "unknown_audience", "invalid_target");
    expect(JSON.stringify(r.body)).not.toContain("SECRET-REASON");
    expect((await exchange(host, client, idToken)).status).toBe(200);
  });

  it("the hook says the resource is unknown: unknown_resource, invalid_target (draft -06 §4.3.3); its reason goes to the audit only", async () => {
    const host = await createIssuerHost({ issuer: { authorize: ({ resource }) => (resource === undefined || resource === "https://mcp.example.com/" ? allow() : { decision: "unknown_resource", reason: "SECRET-REASON" }) } });
    const { client, idToken } = await setup(host);
    const r = await exchange(host, client, idToken, { resource: "https://elsewhere.example/api" });
    expect(host.recorded.refused.at(-1)?.detail).toBe("authorize: SECRET-REASON");
    await refused(host, r, "unknown_resource", "invalid_target");
    expect(JSON.stringify(r.body)).not.toContain("SECRET-REASON");
    expect((await exchange(host, client, idToken)).status).toBe(200);
  });

  it("an administrator's block wins over an unknown audience: access_denied, as any block", async () => {
    // Blocks run before every policy source, so a blocked user learns nothing about which audiences exist.
    const host = await createIssuerHost({ issuer: { authorize: () => ({ decision: "unknown_audience" }), blocks: { canManage: () => true } } });
    const { client, idToken, user, owner } = await setup(host);
    await host.ctx.adapter.create({ model: "idJagBlock", data: { userId: user.id, clientId: null, audience: null, reason: "r", createdBy: owner.id, createdAt: new Date(), expiresAt: null } });
    await refused(host, await exchange(host, client, idToken), "blocked", "access_denied");
  });
});

describe("subject token type (draft -06 §4.3.3, D-060): a token of another kind is never taken for an ID token", () => {
  it("our ID-JAG, a JWT access token, an opaque access token and a refresh token, as subject_token_type id_token: invalid_subject_token", async () => {
    const host = await createIssuerHost({ provider: { resources: [RESOURCE], clientRegistrationDefaultResources: [RESOURCE] }, issuer: { authorize: allow } });
    const { client, user } = await setupRefresh(host);
    const tokens = await getTokens(host, user.browser, client, { scope: "openid profile email offline_access", resource: RESOURCE });
    const jwtAccess = tokens.access_token as string;
    // The provider's JWT access token: RFC 9068, typ at+jwt, signed with the same JWKS as our ID tokens.
    expect(decodeProtectedHeader(jwtAccess).typ).toBe("at+jwt");
    const opaque = (await getTokens(host, user.browser, client)).access_token as string;
    expect(opaque.split(".")).toHaveLength(1);
    const idJag = (await exchange(host, client, tokens.id_token as string)).body.access_token as string;
    expect(decodeProtectedHeader(idJag).typ).toBe("oauth-id-jag+jwt");
    takeReasons(host);
    const issuedBefore = host.recorded.issued.length;
    for (const [name, t] of [["ID-JAG", idJag], ["JWT access token", jwtAccess], ["opaque access token", opaque], ["refresh token", tokens.refresh_token as string]]) {
      const r = await exchange(host, client, t as string);
      expect([r.status, r.body], name).toEqual([400, { error: "invalid_request", error_description: "The request is invalid." }]);
      // The JWTs stop at the typ check, before anything else is looked at.
      if (name === "ID-JAG" || name === "JWT access token") expect(host.recorded.refused.at(-1)?.detail, name).toBe("typ");
      expect(takeReasons(host), name).toEqual(["invalid_subject_token"]);
    }
    expect(host.recorded.issued.length).toBe(issuedBefore);
    // And the ID token itself still works.
    expect((await exchange(host, client, tokens.id_token as string)).status).toBe(200);
  });

  it("a granted resource appears in the ID-JAG exactly as sent: not normalised (draft -06 §4.3.3, Simple String Comparison)", async () => {
    const host = await createIssuerHost({ issuer: { authorize: allow } });
    const { client, idToken } = await setup(host);
    for (const resource of ["https://MCP.example/mcp", "https://mcp.example/mcp/", "https://mcp.example:443/mcp", "urn:example:MCP"]) {
      const r = await exchange(host, client, idToken, { resource });
      expect(r.status, JSON.stringify(r.body)).toBe(200);
      expect(decodeJwt(r.body.access_token as string).resource, resource).toBe(resource);
    }
  });
});

describe("S8: unknown user, banned user, no policy and policy denied look the same; a foreign ID token is a bad subject token", () => {
  it("one status and body for the authorization failures (access_denied, D-059); invalid_request for the token", async () => {
    let decision: "allow" | "deny" = "allow";
    const policyHost = await createIssuerHost({ issuer: { authorize: () => (decision === "allow" ? allow() : { decision: "deny" }) } });
    const bare = await createIssuerHost({});
    const answers: string[] = [];
    const record = (r: Awaited<ReturnType<typeof exchange>>) => answers.push(JSON.stringify([r.status, r.body]));

    const a = await setup(policyHost);
    decision = "deny";
    record(await exchange(policyHost, a.client, a.idToken)); // policy_denied
    decision = "allow";
    await policyHost.ctx.adapter.update({ model: "user", where: [{ field: "id", value: a.user.id }], update: { banned: true } });
    record(await exchange(policyHost, a.client, a.idToken)); // banned_user
    const b = await setup(policyHost);
    await policyHost.ctx.adapter.deleteMany({ model: "session", where: [{ field: "userId", value: b.user.id }] });
    await policyHost.ctx.adapter.delete({ model: "user", where: [{ field: "id", value: b.user.id }] });
    record(await exchange(policyHost, b.client, b.idToken)); // unknown_subject
    const c = await setup(bare);
    record(await exchange(bare, c.client, c.idToken)); // no_policy
    expect([...takeReasons(policyHost), ...takeReasons(bare)].sort()).toEqual(["banned_user", "no_policy", "policy_denied", "unknown_subject"]);
    expect(new Set(answers).size).toBe(1);
    expect(JSON.parse(answers[0]!)).toEqual([400, GENERIC_DENIED]);
    // Draft -06 §4.3.4.3: an ID token issued to another client failed validation: invalid_request, generic.
    const foreign = await exchange(policyHost, a.client, c.idToken);
    expect([foreign.status, foreign.body]).toEqual([400, GENERIC_REQUEST]);
    expect(takeReasons(policyHost)).toEqual(["invalid_subject_token"]);
  });
});

describe("the grant itself", () => {
  it("only serves token exchange for id-jag: the grant type URN is what dispatches", async () => {
    const host = await createIssuerHost({ issuer: { authorize: allow } });
    const { client, idToken } = await setup(host);
    const r = await exchange(host, client, idToken, { grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer" });
    expect(r.body.error).toBe("unsupported_grant_type");
    expect((await exchange(host, client, idToken, { grant_type: TOKEN_EXCHANGE_GRANT, requested_token_type: ID_JAG_TOKEN_TYPE })).status).toBe(200);
  });

  it("a server-side call (auth.api, no Request) works from the parsed body", async () => {
    const host = await createIssuerHost({ issuer: { authorize: allow } });
    const owner = await signUp(host);
    // Server-side there is no Authorization header to read: client_secret_post.
    const client = await createClient(host, owner.browser, { authMethod: "client_secret_post" });
    const user = await signUp(host);
    const idToken = await getIdToken(host, user.browser, client, { post: true });
    const api = host.auth.api as unknown as { oauth2Token: (o: { body: Record<string, unknown> }) => Promise<Record<string, unknown>> };
    const body = await api.oauth2Token({
      body: { grant_type: TOKEN_EXCHANGE_GRANT, requested_token_type: ID_JAG_TOKEN_TYPE, subject_token: idToken, subject_token_type: ID_TOKEN_TOKEN_TYPE, audience: AUDIENCE, client_id: client.client_id, client_secret: client.client_secret },
    });
    expect(body.issued_token_type).toBe(ID_JAG_TOKEN_TYPE);
  });
});
