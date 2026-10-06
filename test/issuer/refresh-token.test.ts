// Refresh tokens as subject tokens (D-B14, D-B15): a refresh token this provider issued to the
// authenticated client, obtained the honest way (authorization_code with offline_access), is
// exchanged for an ID-JAG without being rotated, consumed or extended.
import { decodeJwt } from "jose";
import { describe, expect, it } from "vitest";
import { publicDescription, type ReasonCode } from "../../src/core";
import type { AuthorizeInput, AuthorizeResult } from "../../src/issuer";
import { AUDIENCE, basic, createIssuerHost, exchange, exchangeRefresh, type IssuerHost, RESOURCE, refresh, setupRefresh, takeReasons, verifyWithHostJwks } from "../support/issuer-host";

const allow = (): AuthorizeResult => ({ decision: "allow", scopes: ["read", "write"] });
const GENERIC_GRANT = { error: "invalid_grant", error_description: "The grant is invalid." };
const MODEL = "oauthRefreshToken";

async function refused(host: IssuerHost, r: Awaited<ReturnType<typeof exchange>>, reason: ReasonCode) {
  expect(r.body, JSON.stringify(r.body)).toEqual({ error: "invalid_grant", error_description: publicDescription(reason) });
  expect(r.status).toBe(400);
  expect(takeReasons(host)).toEqual([reason]);
}

/** The provider's row for this user and client (there is one after a single authorization_code grant). */
async function rowOf(host: IssuerHost, client: { client_id: string }, userId: string) {
  const rows = await host.ctx.adapter.findMany<Record<string, unknown>>({ model: MODEL, where: [{ field: "clientId", value: client.client_id }] });
  const mine = rows.filter((r) => r.userId === userId);
  expect(mine).toHaveLength(1);
  return mine[0] as Record<string, unknown>;
}

const setRow = (host: IssuerHost, id: unknown, update: Record<string, unknown>) => host.ctx.adapter.update({ model: MODEL, where: [{ field: "id", value: String(id) }], update });

describe("refresh token subject: allowed", () => {
  it("a refresh token from authorization_code + offline_access yields an ID-JAG that core verifyIdJag accepts; sub is the user, auth_time as stored", async () => {
    const seen: AuthorizeInput[] = [];
    const host = await createIssuerHost({
      issuer: {
        authorize: (i) => {
          seen.push(i);
          return { decision: "allow", scopes: ["read"], clientIdAtResource: "agent-at-rs" };
        },
      },
    });
    const { client, refreshToken, idToken, user } = await setupRefresh(host);
    const r = await exchangeRefresh(host, client, refreshToken, { scope: "read write", resource: RESOURCE });
    expect(r.status, JSON.stringify(r.body)).toBe(200);
    const parsed = await verifyWithHostJwks(host, r.body.access_token as string);
    expect(parsed.claims).toMatchObject({ sub: user.id, aud: AUDIENCE, client_id: "agent-at-rs", scope: "read", resource: RESOURCE });
    expect(parsed.claims.auth_time).toBe(decodeJwt(idToken).auth_time);
    expect(parsed.claims.acr).toBeUndefined();
    expect(host.recorded.issued).toHaveLength(1);
    const subject = seen[0]?.subjectToken;
    expect(subject).toMatchObject({ tokenType: "urn:ietf:params:oauth:token-type:refresh_token", sub: user.id });
    expect(subject?.raw).toMatchObject({ token_type: "refresh_token", client_id: client.client_id });
    // Never the token, nor its stored hash.
    const row = await rowOf(host, client, user.id);
    expect(JSON.stringify(subject)).not.toContain(refreshToken);
    expect(JSON.stringify(subject)).not.toContain(String(row.token));
  });

  it("the exchange doesn't rotate, consume or extend the refresh token: the client keeps using the same one at the token endpoint", async () => {
    const host = await createIssuerHost({ issuer: { authorize: allow } });
    const { client, refreshToken, user } = await setupRefresh(host);
    const before = await rowOf(host, client, user.id);
    expect((await exchangeRefresh(host, client, refreshToken)).status).toBe(200);
    expect((await exchangeRefresh(host, client, refreshToken)).status).toBe(200);
    const after = await rowOf(host, client, user.id);
    expect(after).toEqual(before);
    expect(after.revoked ?? null).toBeNull();
    // The same token still refreshes.
    const refreshed = await refresh(host, client, refreshToken);
    expect(refreshed.status, JSON.stringify(refreshed.body)).toBe(200);
    const next = refreshed.body.refresh_token as string;
    expect(next).toBeTypeOf("string");
    // The provider rotated it: the old one is now refused here too (rotated), the new one works.
    await refused(host, await exchangeRefresh(host, client, refreshToken), "invalid_subject_token");
    expect(host.recorded.refused).toHaveLength(0);
    expect((await exchangeRefresh(host, client, next)).status).toBe(200);
  });

  it("the policy and narrowing are the same for both subject token types", async () => {
    const host = await createIssuerHost({ issuer: { authorize: () => ({ decision: "allow", scopes: ["read", "write"], lifetimeSeconds: 120, claims: { tenant: "org-1" } }) } });
    const { client, refreshToken, idToken } = await setupRefresh(host);
    const strip = (t: string): Record<string, unknown> => {
      const { jti, iat, exp, ...rest } = decodeJwt(t);
      return { ...rest, life: (exp ?? 0) - (iat ?? 0) };
    };
    for (const form of [{}, { scope: "write admin" }, { scope: "read", resource: RESOURCE }]) {
      const a = await exchange(host, client, idToken, form);
      const b = await exchangeRefresh(host, client, refreshToken, form);
      expect(b.status, JSON.stringify(b.body)).toBe(200);
      expect({ ...b.body, access_token: undefined }).toEqual({ ...a.body, access_token: undefined });
      const { acr: _acr, ...fromId } = strip(a.body.access_token as string);
      expect(strip(b.body.access_token as string)).toEqual(fromId);
    }
    // A refusal is the same too.
    const a = await exchange(host, client, idToken, { scope: "admin" });
    const b = await exchangeRefresh(host, client, refreshToken, { scope: "admin" });
    expect([b.status, b.body]).toEqual([a.status, a.body]);
    expect(takeReasons(host).slice(-2)).toEqual(["no_scope", "no_scope"]);
  });

  it("email only when the policy opts in and the user's email is verified, as for ID tokens", async () => {
    const host = await createIssuerHost({ issuer: { authorize: () => ({ decision: "allow", scopes: ["read"], claims: { email: true } }) } });
    const { client, refreshToken, user } = await setupRefresh(host);
    const email = async () => decodeJwt((await exchangeRefresh(host, client, refreshToken)).body.access_token as string).email;
    expect(await email()).toBeUndefined();
    await host.ctx.adapter.update({ model: "user", where: [{ field: "id", value: user.id }], update: { emailVerified: true } });
    expect(await email()).toBe(user.email);
  });

  it("the provider's refresh-token prefix: required, and stripped before the provider's hash", async () => {
    const host = await createIssuerHost({ provider: { prefix: { refreshToken: "idp_rt_" } }, issuer: { authorize: allow } });
    const { client, refreshToken } = await setupRefresh(host);
    expect(refreshToken.startsWith("idp_rt_")).toBe(true);
    expect((await exchangeRefresh(host, client, refreshToken)).status).toBe(200);
    await refused(host, await exchangeRefresh(host, client, refreshToken.slice("idp_rt_".length)), "invalid_subject_token");
  });
});

describe("refresh token subject: refused", () => {
  it("unknown, another client's, revoked (through the provider's /oauth2/revoke): invalid_subject_token, one body", async () => {
    const host = await createIssuerHost({ issuer: { authorize: allow } });
    const a = await setupRefresh(host);
    const b = await setupRefresh(host);
    const answers: string[] = [];
    const record = (r: Awaited<ReturnType<typeof exchange>>) => answers.push(JSON.stringify([r.status, r.body]));
    record(await exchangeRefresh(host, a.client, "not-a-refresh-token-we-issued"));
    // b's token, presented by a (with a's credentials): another client's.
    record(await exchangeRefresh(host, a.client, b.refreshToken));
    // An ID token presented as a refresh token is just unknown.
    record(await exchangeRefresh(host, a.client, a.idToken));
    const revoke = await host.auth.handler(
      new Request(`${host.issuerUrl}/oauth2/revoke`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded", authorization: basic(a.client) },
        body: new URLSearchParams({ token: a.refreshToken, token_type_hint: "refresh_token" }),
      }),
    );
    expect(revoke.status).toBe(200);
    record(await exchangeRefresh(host, a.client, a.refreshToken));
    expect(host.recorded.refused.map((e) => e.detail)).toEqual(["refresh token: unknown", "refresh token: issued to another client", "refresh token: unknown", "refresh token: revoked"]);
    expect(takeReasons(host)).toEqual(Array(4).fill("invalid_subject_token"));
    expect(new Set(answers).size).toBe(1);
    expect(JSON.parse(answers[0]!)).toEqual([400, GENERIC_GRANT]);
    // b's own token still works for b.
    expect((await exchangeRefresh(host, b.client, b.refreshToken)).status).toBe(200);
  });

  it("expired: subject_token_expired, but only for the client's own unrevoked token (else the generic refusal)", async () => {
    const host = await createIssuerHost({ issuer: { authorize: allow } });
    const a = await setupRefresh(host);
    const b = await setupRefresh(host);
    const row = await rowOf(host, a.client, a.user.id);
    await setRow(host, row.id, { expiresAt: new Date(Date.now() - 1000) });
    await refused(host, await exchangeRefresh(host, a.client, a.refreshToken), "subject_token_expired");
    // Another client presenting it learns nothing about its expiry.
    await refused(host, await exchangeRefresh(host, b.client, a.refreshToken), "invalid_subject_token");
    // Revoked and expired: revoked.
    await setRow(host, row.id, { revoked: new Date() });
    await refused(host, await exchangeRefresh(host, a.client, a.refreshToken), "invalid_subject_token");
    // Expiring now is expired (no grace).
    const rowB = await rowOf(host, b.client, b.user.id);
    await setRow(host, rowB.id, { expiresAt: new Date(Math.floor(Date.now() / 1000) * 1000) });
    await refused(host, await exchangeRefresh(host, b.client, b.refreshToken), "subject_token_expired");
  });

  it("a banned user: banned_user (an expired ban doesn't count)", async () => {
    const host = await createIssuerHost({ issuer: { authorize: allow } });
    const a = await setupRefresh(host);
    await host.ctx.adapter.update({ model: "user", where: [{ field: "id", value: a.user.id }], update: { banned: true } });
    await refused(host, await exchangeRefresh(host, a.client, a.refreshToken), "banned_user");
    await host.ctx.adapter.update({ model: "user", where: [{ field: "id", value: a.user.id }], update: { banExpires: new Date(Date.now() - 1000) } });
    expect((await exchangeRefresh(host, a.client, a.refreshToken)).status).toBe(200);
  });

  it("a sender-constrained refresh token (cnf) is refused: we can't check the proof of possession", async () => {
    const host = await createIssuerHost({ issuer: { authorize: allow } });
    const a = await setupRefresh(host);
    const row = await rowOf(host, a.client, a.user.id);
    await setRow(host, row.id, { confirmation: JSON.stringify({ jkt: "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I" }) });
    await refused(host, await exchangeRefresh(host, a.client, a.refreshToken), "invalid_subject_token");
    expect(host.recorded.refused).toHaveLength(0);
  });

  it("a refresh token not granted openid is refused (an ID-JAG is an identity assertion)", async () => {
    const host = await createIssuerHost({ issuer: { authorize: allow } });
    const a = await setupRefresh(host);
    const row = await rowOf(host, a.client, a.user.id);
    await setRow(host, row.id, { scopes: ["profile", "offline_access"] });
    const r = await exchangeRefresh(host, a.client, a.refreshToken);
    expect(r.body).toEqual(GENERIC_GRANT);
    expect(host.recorded.refused.map((e) => [e.reason, e.detail])).toEqual([["invalid_subject_token", "refresh token: not granted openid"]]);
  });

  it("an over-long token is refused before any lookup", async () => {
    const host = await createIssuerHost({ issuer: { authorize: allow } });
    const a = await setupRefresh(host);
    const r = await exchangeRefresh(host, a.client, "x".repeat(20_000));
    expect(r.body).toEqual(GENERIC_GRANT);
    expect(host.recorded.refused.map((e) => e.detail)).toEqual(["length"]);
  });

  it("S10: no outbound request", async () => {
    const host = await createIssuerHost({ issuer: { authorize: allow } });
    const a = await setupRefresh(host);
    const original = globalThis.fetch;
    const calls: string[] = [];
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      calls.push(String(input instanceof Request ? input.url : input));
      throw new Error("no outbound requests");
    }) as typeof fetch;
    try {
      expect((await exchangeRefresh(host, a.client, a.refreshToken)).status).toBe(200);
      expect((await exchangeRefresh(host, a.client, "unknown")).status).toBe(400);
    } finally {
      globalThis.fetch = original;
    }
    expect(calls).toEqual([]);
  });
});
