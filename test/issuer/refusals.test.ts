// Every refusal the issuer can produce, asserted by reason (onRefused) and by response body. The
// registry's own refusals (unknown_resource, no_policy without a resource server) are in
// registry.test.ts.
import { decodeJwt, exportJWK, generateKeyPair, SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import { ID_JAG_TOKEN_TYPE, ID_TOKEN_TOKEN_TYPE, publicDescription, type ReasonCode, TOKEN_EXCHANGE_GRANT } from "../../src/core";
import type { AuthorizeResult } from "../../src/issuer";
import { AUDIENCE, createClient, createIssuerHost, exchange, getIdToken, ISSUER, type IssuerHost, RESOURCE, setup, signUp, takeReasons } from "../support/issuer-host";

const allow = (): AuthorizeResult => ({ decision: "allow", scopes: ["read"] });
const GENERIC_GRANT = { error: "invalid_grant", error_description: "The grant is invalid." };

/** The exchange is refused for `reason`, with that reason's public body. */
async function refused(host: IssuerHost, r: Awaited<ReturnType<typeof exchange>>, reason: ReasonCode, error: string) {
  expect(r.body, JSON.stringify(r.body)).toEqual({ error, error_description: publicDescription(reason) });
  expect(r.status).toBe(error === "invalid_client" ? 401 : 400);
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

  it("an audience that isn't an https issuer identifier, several audiences, or our own issuer: invalid_audience", async () => {
    const host = await createIssuerHost({ issuer: { authorize: allow } });
    const { client, idToken } = await setup(host);
    for (const audience of ["http://rs.example", "https://rs.example/#x", "https://rs.example/?a=1", "rs.example", "https://user@rs.example", "https://rs.example/ a", "", ISSUER, [AUDIENCE, "https://other.example"]]) {
      const r = await exchange(host, client, idToken, { audience });
      // An empty audience is a missing one.
      await refused(host, r, audience === "" ? "missing_parameter" : "invalid_audience", audience === "" ? "invalid_request" : "invalid_target");
    }
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
    await refused(host, await exchange(host, client, idToken, { scope: ["read", "write"] }), "unsupported_parameter", "invalid_request");
    await refused(host, await exchange(host, client, idToken, { subject_token: [idToken, idToken] }), "unsupported_parameter", "invalid_request");
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
    expect(warnings.some((w) => w.includes("allowPublicClients"))).toBe(true);
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
    await refused(host, await exchange(host, client, o.idToken), "invalid_subject_token", "invalid_grant");
    // Forged with our client as audience but another iss: refused at iss, before any key.
    const f = await forged({ iss: "https://trusted-elsewhere.example", aud: client.client_id });
    await refused(host, await exchange(host, client, f.token), "invalid_subject_token", "invalid_grant");
  });

  it("refuses, by step: another client's ID token, a forged key, a tampered payload, wrong typ (an ID-JAG), alg none/HS256, no kid, not a JWT", async () => {
    const host = await createIssuerHost({ issuer: { authorize: allow } });
    const details: string[] = [];
    const { client, idToken, user, owner } = await setup(host);
    const second = await createClient(host, owner.browser);
    const step = async (token: string, c = client) => {
      await refused(host, await exchange(host, c, token), "invalid_subject_token", "invalid_grant");
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
    await refused(host, await exchange(host, client, idToken), "subject_token_expired", "invalid_grant");
  });

  it("a pairwise client's ID token is refused explicitly (its sub isn't the user id)", async () => {
    const host = await createIssuerHost({ provider: { pairwiseSecret: "p".repeat(40) }, issuer: { authorize: allow } });
    const owner = await signUp(host);
    const pairwise = await createClient(host, owner.browser, { extra: { subject_type: "pairwise" } });
    const idToken = await getIdToken(host, owner.browser, pairwise);
    expect(decodeJwt(idToken).sub).not.toBe(owner.id);
    await refused(host, await exchange(host, pairwise, idToken), "invalid_subject_token", "invalid_grant");
    expect(host.recorded.refused.length).toBe(0);
  });

  it("a user who no longer exists: unknown_subject; a banned user: banned_user", async () => {
    const host = await createIssuerHost({ issuer: { authorize: allow } });
    const a = await setup(host);
    await host.ctx.adapter.update({ model: "user", where: [{ field: "id", value: a.user.id }], update: { banned: true } });
    await refused(host, await exchange(host, a.client, a.idToken), "banned_user", "invalid_grant");
    // A ban that has expired doesn't count.
    await host.ctx.adapter.update({ model: "user", where: [{ field: "id", value: a.user.id }], update: { banExpires: new Date(Date.now() - 1000) } });
    expect((await exchange(host, a.client, a.idToken)).status).toBe(200);
    const b = await setup(host);
    await host.ctx.adapter.deleteMany({ model: "session", where: [{ field: "userId", value: b.user.id }] });
    await host.ctx.adapter.delete({ model: "user", where: [{ field: "id", value: b.user.id }] });
    await refused(host, await exchange(host, b.client, b.idToken), "unknown_subject", "invalid_grant");
  });
});

describe("refusals: policy (S1, S7)", () => {
  it("no policy source configured: no_policy, and a startup warning", async () => {
    const warnings: string[] = [];
    const host = await createIssuerHost({ auth: { logger: { level: "warn", log: (_l: string, m: string) => void warnings.push(m) } } });
    expect(warnings.some((w) => w.includes("no policy source"))).toBe(true);
    const { client, idToken } = await setup(host);
    await refused(host, await exchange(host, client, idToken), "no_policy", "invalid_grant");
  });

  it("the hook denies, throws, or answers something malformed: policy_denied (a reason goes to the audit only)", async () => {
    let verdict: () => unknown = () => ({ decision: "deny", reason: "not on a weekend\n" });
    const host = await createIssuerHost({ issuer: { authorize: (() => verdict()) as never } });
    const { client, idToken } = await setup(host);
    await refused(host, await exchange(host, client, idToken), "policy_denied", "invalid_grant");
    for (const v of [
      () => {
        throw new Error("boom");
      },
      () => true,
      () => ({ decision: "allow" }),
      () => ({ decision: "allow", scopes: "read" }),
      () => ({ decision: "maybe", scopes: [] }),
      () => undefined,
    ]) {
      verdict = v;
      await refused(host, await exchange(host, client, idToken), "policy_denied", "invalid_grant");
    }
  });

  it("the hook's details stay in the audit log, made log-safe", async () => {
    const host = await createIssuerHost({ issuer: { authorize: () => ({ decision: "deny", reason: "line one\nfake line" }) } });
    const { client, idToken } = await setup(host);
    const r = await exchange(host, client, idToken);
    expect(JSON.stringify(r.body)).not.toContain("line one");
    expect(host.recorded.refused[0]?.detail).toBe("authorize: line onefake line");
  });

  it("no requested scope is allowed: no_scope (only after an allow)", async () => {
    const host = await createIssuerHost({ issuer: { authorize: allow } });
    const { client, idToken } = await setup(host);
    await refused(host, await exchange(host, client, idToken, { scope: "write admin" }), "no_scope", "invalid_scope");
  });

  it("the hook names another resource than the one asked for: policy_denied", async () => {
    const host = await createIssuerHost({ issuer: { authorize: () => ({ decision: "allow", scopes: ["read"], resource: "https://elsewhere.example/mcp" }) } });
    const { client, idToken } = await setup(host);
    await refused(host, await exchange(host, client, idToken, { resource: RESOURCE }), "policy_denied", "invalid_grant");
  });
});

describe("S8: unknown user, banned user, no policy, policy denied and a foreign ID token look the same", () => {
  it("one status and body for all of them", async () => {
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
    record(await exchange(policyHost, a.client, c.idToken)); // invalid_subject_token
    expect([...takeReasons(policyHost), ...takeReasons(bare)].sort()).toEqual(["banned_user", "invalid_subject_token", "no_policy", "policy_denied", "unknown_subject"]);
    expect(new Set(answers).size).toBe(1);
    expect(JSON.parse(answers[0]!)).toEqual([400, GENERIC_GRANT]);
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
