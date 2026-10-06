// An ID token keeps no session: oauth-provider's live 10 hours by default, so without a cap one
// would keep minting ID-JAGs long after sign-out (D-B22). `maxIdTokenAgeSeconds` (default 3600)
// caps the age of an ID token by its `iat`; a client with an older sign-in exchanges its refresh
// token instead. An ID token that carries `sid` (oauth-provider puts it in for clients with
// `enable_end_session` or a back-channel logout URI) is refused once that session is gone (D-B23).
import { decodeJwt } from "jose";
import { afterEach, describe, expect, it, vi } from "vitest";
import { publicDescription } from "../../src/core";
import type { AuthorizeResult } from "../../src/issuer";
import { createIssuerHost, exchange, exchangeRefresh, type IssuerHost, setup, setupRefresh, takeReasons } from "../support/issuer-host";

const allow = (): AuthorizeResult => ({ decision: "allow", scopes: ["read"] });
const EXPIRED = { error: "invalid_grant", error_description: publicDescription("subject_token_expired") };
const GENERIC_GRANT = { error: "invalid_grant", error_description: "The grant is invalid." };

/** Moves `Date` (only) forward by `seconds`; timers stay real. */
function travel(seconds: number) {
  const now = Date.now();
  vi.useFakeTimers({ toFake: ["Date"], now: now + seconds * 1000 });
}
afterEach(() => {
  vi.useRealTimers();
});

const signOut = async (host: IssuerHost, browser: { fetch(url: string, init?: RequestInit): Promise<Response> }) => {
  const res = await browser.fetch(`${host.issuerUrl}/sign-out`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
  expect(res.status).toBe(200);
};

describe("ID token age cap (maxIdTokenAgeSeconds)", () => {
  it("an ID token older than the default cap (3600 s) is refused as subject_token_expired although unexpired; its refresh token still works", async () => {
    const host = await createIssuerHost({ issuer: { authorize: allow } });
    const { client, idToken, refreshToken } = await setupRefresh(host);
    const { iat, exp } = decodeJwt(idToken) as { iat: number; exp: number };
    expect(exp - iat).toBeGreaterThan(3601); // the provider's 10 hours: still valid after the cap
    travel(3601);
    const r = await exchange(host, client, idToken);
    expect([r.status, r.body]).toEqual([400, EXPIRED]);
    expect(takeReasons(host)).toEqual(["subject_token_expired"]);
    expect(host.recorded.issued).toHaveLength(0);
    // The way forward for an older sign-in.
    expect((await exchangeRefresh(host, client, refreshToken)).status).toBe(200);
  });

  it("within the cap it is accepted", async () => {
    const host = await createIssuerHost({ issuer: { authorize: allow } });
    const { client, idToken } = await setup(host);
    travel(3500);
    const r = await exchange(host, client, idToken);
    expect(r.status, JSON.stringify(r.body)).toBe(200);
  });

  it("a shorter cap applies as configured", async () => {
    const host = await createIssuerHost({ issuer: { authorize: allow, maxIdTokenAgeSeconds: 60 } });
    const { client, idToken } = await setup(host);
    travel(50);
    expect((await exchange(host, client, idToken)).status).toBe(200);
    travel(70);
    expect((await exchange(host, client, idToken)).body).toEqual(EXPIRED);
  });

  it("after sign-out, an ID token without sid still works until the cap, and not after it", async () => {
    const host = await createIssuerHost({ issuer: { authorize: allow } });
    const { client, idToken, user } = await setup(host);
    expect(decodeJwt(idToken).sid).toBeUndefined();
    await signOut(host, user.browser);
    expect(await host.ctx.adapter.findMany({ model: "session", where: [{ field: "userId", value: user.id }] })).toEqual([]);
    expect((await exchange(host, client, idToken)).status).toBe(200);
    travel(3601);
    expect((await exchange(host, client, idToken)).body).toEqual(EXPIRED);
  });
});

describe("ID token sid: the session must still exist", () => {
  it("a client with enable_end_session gets ID tokens with sid; after sign-out they are refused (invalid_subject_token)", async () => {
    const host = await createIssuerHost({ issuer: { authorize: allow } });
    const { client, idToken, user } = await setup(host, { clientExtra: { enable_end_session: true } });
    const sid = decodeJwt(idToken).sid;
    expect(typeof sid).toBe("string");
    expect((await exchange(host, client, idToken)).status).toBe(200);
    await signOut(host, user.browser);
    takeReasons(host);
    const r = await exchange(host, client, idToken);
    expect([r.status, r.body]).toEqual([400, GENERIC_GRANT]);
    expect(host.recorded.refused.at(-1)).toMatchObject({ reason: "invalid_subject_token", detail: "session ended" });
  });

  it("an expired session counts as ended; the same token works again while the session is live", async () => {
    const host = await createIssuerHost({ issuer: { authorize: allow } });
    const { client, idToken } = await setup(host, { clientExtra: { enable_end_session: true } });
    const sid = decodeJwt(idToken).sid as string;
    await host.ctx.adapter.update({ model: "session", where: [{ field: "id", value: sid }], update: { expiresAt: new Date(Date.now() - 1000) } });
    takeReasons(host);
    expect((await exchange(host, client, idToken)).body).toEqual(GENERIC_GRANT);
    expect(host.recorded.refused.at(-1)?.detail).toBe("session ended");
    await host.ctx.adapter.update({ model: "session", where: [{ field: "id", value: sid }], update: { expiresAt: new Date(Date.now() + 3600_000) } });
    expect((await exchange(host, client, idToken)).status).toBe(200);
  });
});
