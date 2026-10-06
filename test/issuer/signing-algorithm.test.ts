// signingAlgorithm (D-004): the ID-JAG's algorithm is a visible option. An EdDSA host (the jwt
// plugin's default) that signs ID-JAGs with ES256 from keyPairConfigs. Own file: one jwks table.
import { decodeProtectedHeader } from "jose";
import { describe, expect, it } from "vitest";
import { createIssuerHost, exchange, setup, verifyWithHostJwks } from "../support/issuer-host";

describe("signingAlgorithm", () => {
  it("default: the jwt plugin's algorithm (EdDSA here); with signingAlgorithm ES256 the ID-JAG is ES256 while ID tokens stay EdDSA", async () => {
    const plain = await createIssuerHost({ alg: "EdDSA", issuer: { authorize: () => ({ decision: "allow", scopes: ["read"] }) } });
    const a = await setup(plain);
    const eddsa = (await exchange(plain, a.client, a.idToken)).body.access_token as string;
    expect(decodeProtectedHeader(a.idToken).alg).toBe("EdDSA");
    expect((await verifyWithHostJwks(plain, eddsa)).header.alg).toBe("EdDSA");

    const pinned = await createIssuerHost({ alg: "EdDSA", keyPairConfigs: ["ES256"], issuer: { signingAlgorithm: "ES256", authorize: () => ({ decision: "allow", scopes: ["read"] }) } });
    const b = await setup(pinned);
    expect(decodeProtectedHeader(b.idToken).alg).toBe("EdDSA");
    const r = await exchange(pinned, b.client, b.idToken);
    expect(r.status, JSON.stringify(r.body)).toBe(200);
    expect((await verifyWithHostJwks(pinned, r.body.access_token as string)).header.alg).toBe("ES256");
  });
});
