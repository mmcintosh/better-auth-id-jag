// #19: with no algorithm configured, the issuer can't know at startup what Better Auth will sign with, so it checks
// each ID-JAG: a host whose current key is one receivers refuse (here PS256) issues none. Own file: one jwks table.
import { createJwk } from "better-auth/plugins";
import { decodeProtectedHeader } from "jose";
import { describe, expect, it } from "vitest";
import { createIssuerHost, exchangeRequest, setup } from "../support/issuer-host";

describe("the key Better Auth signs with must be one receivers accept (#19, S4)", () => {
  it("a PS256 key and no keyPairConfig: ID tokens still work, but no ID-JAG is issued", async () => {
    const host = await createIssuerHost({ noKeyPairConfig: true, issuer: { authorize: () => ({ decision: "allow", scopes: ["read"] }) } });
    await createJwk({ context: host.ctx } as never, { jwks: { keyPairConfig: { alg: "PS256" } } });
    const { client, idToken } = await setup(host);
    expect(decodeProtectedHeader(idToken).alg).toBe("PS256");
    const res = await host.auth.handler(exchangeRequest(client, idToken, {}, {}));
    const text = await res.text();
    await host.settle();
    // A server error: the host is misconfigured; the caller gets no token, and the log names the key's algorithm.
    expect(res.status, text).toBe(500);
    expect(text).not.toContain("access_token");
    expect(host.recorded.issued).toHaveLength(0);
  });
});
