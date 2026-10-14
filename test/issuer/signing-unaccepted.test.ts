// #19: the key Better Auth signs an ID-JAG with must be one receivers accept (S4), whatever its default or the keys
// in the database. assertIssuableAlgorithm in isolation, then a host whose only key is PS256. Own file: one jwks table.
import { createJwk } from "better-auth/plugins";
import { decodeProtectedHeader, generateKeyPair, SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import { ALLOWED_ALGORITHMS } from "../../src/core";
import { assertIssuableAlgorithm } from "../../src/issuer/exchange";
import { createIssuerHost, exchangeRequest, setup } from "../support/issuer-host";

describe("the key Better Auth signs with must be one receivers accept (#19, S4)", () => {
  it("assertIssuableAlgorithm: RS256, ES256 and EdDSA pass; PS256, ES512 and HS256 throw, naming the algorithm", async () => {
    const signed = async (alg: string, o: Record<string, unknown> = {}) => {
      const key = alg === "HS256" ? new TextEncoder().encode("x".repeat(32)) : (await generateKeyPair(alg, o)).privateKey;
      return new SignJWT({ sub: "x" }).setProtectedHeader({ alg, typ: "oauth-id-jag+jwt" }).sign(key);
    };
    for (const [alg, o] of [["RS256", {}], ["ES256", {}], ["EdDSA", { crv: "Ed25519" }]] as const) {
      const token = await signed(alg, o);
      expect(() => assertIssuableAlgorithm(token), alg).not.toThrow();
    }
    for (const alg of ["PS256", "ES512", "HS256"]) {
      const token = await signed(alg);
      expect(() => assertIssuableAlgorithm(token), alg).toThrow(new RegExp(`signing key is ${alg}`));
    }
  });

  it("a host whose only key is PS256 (no keyPairConfig) issues no ID-JAG, if Better Auth signs with that key", async () => {
    const host = await createIssuerHost({ noKeyPairConfig: true, issuer: { authorize: () => ({ decision: "allow", scopes: ["read"] }) } });
    await createJwk({ context: host.ctx } as never, { jwks: { keyPairConfig: { alg: "PS256" } } });
    const { client, idToken } = await setup(host);
    const res = await host.auth.handler(exchangeRequest(client, idToken, {}, {}));
    const text = await res.text();
    await host.settle();
    if (decodeProtectedHeader(idToken).alg === "PS256") {
      // Better Auth 1.7 signs with the latest key when none has its default algorithm: the PS256 key. Nothing issued.
      expect(res.status, text).toBe(500);
      expect(text).not.toContain("access_token");
      expect(host.recorded.issued).toHaveLength(0);
    } else {
      // A Better Auth that mints a key of its own default instead (better-auth#9935): an accepted algorithm, issued.
      expect(res.status, text).toBe(200);
      expect(ALLOWED_ALGORITHMS as readonly string[]).toContain(decodeProtectedHeader(JSON.parse(text).access_token).alg);
    }
  });
});
