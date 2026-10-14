// #19: an issuer host whose jwt plugin has no keyPairConfig at all signs ID-JAGs with whatever Better Auth's default
// key is (EdDSA through 1.7, RS256 once better-auth#9935 ships), never an algorithm this package assumed. Own file:
// one jwks table.
import { decodeProtectedHeader } from "jose";
import { describe, expect, it } from "vitest";
import { ALLOWED_ALGORITHMS } from "../../src/core";
import { createIssuerHost, exchange, setup, verifyWithHostJwks } from "../support/issuer-host";

const allow = () => ({ decision: "allow" as const, scopes: ["read"] });

describe("no keyPairConfig: Better Auth's default algorithm (#19)", () => {
  it("the ID-JAG is signed with the host's own default key, as its ID tokens are, and verifies against its JWKS", async () => {
    const host = await createIssuerHost({ noKeyPairConfig: true, issuer: { authorize: allow } });
    const { client, idToken } = await setup(host);
    const r = await exchange(host, client, idToken);
    expect(r.status, JSON.stringify(r.body)).toBe(200);
    const { header } = await verifyWithHostJwks(host, r.body.access_token as string);
    expect(header.alg).toBe(decodeProtectedHeader(idToken).alg);
    expect(ALLOWED_ALGORITHMS as readonly string[]).toContain(header.alg);
  });

  it("signingAlgorithm RS256 from keyPairConfigs, with no keyPairConfig: the ID-JAG is RS256", async () => {
    const host = await createIssuerHost({ noKeyPairConfig: true, keyPairConfigs: ["RS256"], issuer: { signingAlgorithm: "RS256", authorize: allow } });
    const { client, idToken } = await setup(host);
    const r = await exchange(host, client, idToken);
    expect(r.status, JSON.stringify(r.body)).toBe(200);
    expect((await verifyWithHostJwks(host, r.body.access_token as string)).header.alg).toBe("RS256");
  });
});
