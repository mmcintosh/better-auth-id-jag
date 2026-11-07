// An RS256 host (own file: workerd test files each have their own D1 and jwks table).
import { decodeProtectedHeader } from "jose";
import { describe, expect, it } from "vitest";
import { ISSUER_SIGNING_ALG_METADATA_FIELD } from "../../src/core";
import { createIssuerHost, discoveryDocs, exchange, setup, verifyWithHostJwks } from "../support/issuer-host";

describe("RS256 (the jwt plugin's keyPairConfig)", () => {
  it("ID token and ID-JAG are RS256; core verifyIdJag accepts the ID-JAG against /jwks with the policy's scopes and mapped client_id", async () => {
    const host = await createIssuerHost({ alg: "RS256", issuer: { authorize: () => ({ decision: "allow", scopes: ["read"], clientIdAtResource: "rs-client" }) } });
    const { client, idToken } = await setup(host);
    expect(decodeProtectedHeader(idToken).alg).toBe("RS256");
    const r = await exchange(host, client, idToken, { scope: "read write" });
    expect(r.status, JSON.stringify(r.body)).toBe(200);
    const parsed = await verifyWithHostJwks(host, r.body.access_token as string);
    expect(parsed.header.alg).toBe("RS256");
    expect(parsed.claims).toMatchObject({ scope: "read", client_id: "rs-client" });
    // Draft -06 section 7.1: the algorithm is published, and it is the one the ID-JAG was signed with (D-061).
    for (const [path, doc] of await discoveryDocs(host)) expect(doc[ISSUER_SIGNING_ALG_METADATA_FIELD], path).toEqual(["RS256"]);
  });
});
