// The "test your IdP" tester's rule-by-rule report (examples/workers/tester/src/checks.ts): each rule says pass or
// fail for the right reason, and the metadata check stops registrations that would never work.
import { exportJWK, generateKeyPair, type JWTPayload, SignJWT } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import { checkIdJag, checkIssuerMetadata, type IdJagCheckInput, type RuleResult } from "../../examples/workers/tester/src/checks";

const ISSUER = "https://idp.example.org";
const AUD = "https://tester.example.net/api/auth";
const RESOURCE = "https://tester.example.net/mcp";
const now = 1_800_000_000;

let key: CryptoKey;
let otherKey: CryptoKey;
let jwks: { keys: Record<string, unknown>[] };

beforeAll(async () => {
  const pair = await generateKeyPair("RS256", { extractable: true });
  key = pair.privateKey;
  otherKey = (await generateKeyPair("RS256")).privateKey;
  jwks = { keys: [{ ...(await exportJWK(pair.publicKey)), kid: "k1", alg: "RS256", use: "sig" }] };
});

const good: JWTPayload & Record<string, unknown> = { iss: ISSUER, sub: "u1", aud: AUD, client_id: "c1", jti: "j1", iat: now - 10, exp: now + 290, resource: RESOURCE, scope: "read", email: "a@example.org" };
const sign = (claims: Record<string, unknown>, header: Record<string, unknown> = {}, k: CryptoKey = key) =>
  new SignJWT(claims).setProtectedHeader({ alg: "RS256", typ: "oauth-id-jag+jwt", kid: "k1", ...header }).sign(k);
const input = (o: Partial<IdJagCheckInput> = {}): IdJagCheckInput => ({ issuer: ISSUER, audience: AUD, resource: RESOURCE, grantableScopes: ["read"], clientId: "c1", jwks: jwks as never, now, ...o });
const outcome = (results: RuleResult[], id: string) => results.find((r) => r.id === id)?.outcome;

describe("tester: checkIdJag", () => {
  it("a correct ID-JAG passes every rule that can fail", async () => {
    const { results } = await checkIdJag(await sign(good), input());
    expect(results.filter((r) => r.outcome === "fail")).toEqual([]);
    for (const id of ["header.typ", "header.alg", "signature", "claim.iss", "claim.sub", "claim.aud", "claim.client_id", "claim.jti", "claim.exp", "claim.iat", "claim.lifetime", "claim.resource", "claim.scope"]) expect(outcome(results, id), id).toBe("pass");
    expect(results.every((r) => r.cite.length > 0)).toBe(true);
  });

  it("reports every failure at once, not just the first", async () => {
    const { results } = await checkIdJag(await sign({ ...good, aud: [AUD, "https://other.example"], client_id: "someone-else", scope: undefined }, { typ: "JWT" }), input());
    expect(outcome(results, "header.typ")).toBe("fail");
    expect(outcome(results, "claim.aud")).toBe("fail");
    expect(outcome(results, "claim.client_id")).toBe("fail");
    expect(outcome(results, "claim.scope")).toBe("fail");
  });

  it("a signature by a key not in the JWKS fails; no JWKS skips the rule", async () => {
    expect(outcome((await checkIdJag(await sign(good, {}, otherKey), input())).results, "signature")).toBe("fail");
    expect(outcome((await checkIdJag(await sign(good), input({ jwks: null }))).results, "signature")).toBe("skip");
  });

  it("aud may be a one-element array; the resource must be ours; scope must be a string", async () => {
    const r = (await checkIdJag(await sign({ ...good, aud: [AUD], resource: [RESOURCE, "https://elsewhere.example/api"], scope: ["read"] }), input())).results;
    expect(outcome(r, "claim.aud")).toBe("pass");
    expect(outcome(r, "claim.resource")).toBe("fail");
    expect(outcome(r, "claim.scope")).toBe("fail");
  });

  it("expired, issued in the future, and too long-lived", async () => {
    expect(outcome((await checkIdJag(await sign({ ...good, iat: now - 1000, exp: now - 500 }), input())).results, "claim.exp")).toBe("fail");
    expect(outcome((await checkIdJag(await sign({ ...good, iat: now + 600, exp: now + 800 }), input())).results, "claim.iat")).toBe("fail");
    expect(outcome((await checkIdJag(await sign({ ...good, exp: now + 3600 }), input())).results, "claim.lifetime")).toBe("fail");
  });

  it("missing required claims each fail; absent optional ones are informational", async () => {
    const { iss: _i, sub: _s, jti: _j, client_id: _c, resource: _r, ...rest } = good;
    const r = (await checkIdJag(await sign(rest), input())).results;
    for (const id of ["claim.iss", "claim.sub", "claim.jti", "claim.client_id"]) expect(outcome(r, id), id).toBe("fail");
    expect(outcome(r, "claim.resource")).toBe("info");
  });

  it("alg none and HS256 are refused; a non-JWT is a structure failure", async () => {
    const none = `${btoa(JSON.stringify({ alg: "none", typ: "oauth-id-jag+jwt" })).replace(/=/g, "")}.${btoa(JSON.stringify(good)).replace(/=/g, "")}.`;
    expect(outcome((await checkIdJag(none, input())).results, "header.alg")).toBe("fail");
    const hs = await new SignJWT(good).setProtectedHeader({ alg: "HS256", typ: "oauth-id-jag+jwt" }).sign(new TextEncoder().encode("x".repeat(32)));
    expect(outcome((await checkIdJag(hs, input())).results, "header.alg")).toBe("fail");
    const junk = await checkIdJag("not a jwt", input());
    expect(junk.results).toHaveLength(1);
    expect(outcome(junk.results, "jwt.structure")).toBe("fail");
  });

  it("matches the receiver: typ in any case or with application/, a key named by x5t, crit, whole seconds, cnf", async () => {
    for (const typ of ["OAUTH-ID-JAG+JWT", "application/oauth-id-jag+jwt"]) {
      const r = (await checkIdJag(await sign(good, { typ }), input())).results;
      expect(outcome(r, "header.typ"), typ).toBe("pass");
      expect(outcome(r, "receiver.parse"), typ).toBe("pass");
    }
    const thumb = "A".repeat(27);
    const byThumb = { keys: [{ ...jwks.keys[0], kid: undefined, x5t: thumb }, { ...jwks.keys[0], kid: undefined, x5t: "B".repeat(27), n: "AQAB" }] };
    const x5tOnly = await new SignJWT(good).setProtectedHeader({ alg: "RS256", typ: "oauth-id-jag+jwt", x5t: thumb }).sign(key);
    const r1 = (await checkIdJag(x5tOnly, input({ jwks: byThumb as never }))).results;
    expect(outcome(r1, "header.kid")).toBe("warn");
    expect(outcome(r1, "signature")).toBe("pass");
    const unnamed = (await checkIdJag(await new SignJWT(good).setProtectedHeader({ alg: "RS256", typ: "oauth-id-jag+jwt" }).sign(key), input())).results;
    expect(outcome(unnamed, "header.kid")).toBe("fail");
    expect(outcome(unnamed, "receiver.parse")).toBe("fail");
    expect(outcome((await checkIdJag(await sign(good, { crit: ["b64"], b64: true }), input())).results, "header.crit")).toBe("fail");
    expect(outcome((await checkIdJag(await sign({ ...good, exp: now + 290.5 }), input())).results, "claim.exp")).toBe("fail");
    const cnf = (await checkIdJag(await sign({ ...good, cnf: { jkt: "x" } }), input())).results;
    expect(outcome(cnf, "claim.cnf")).toBe("fail");
    expect(outcome(cnf, "receiver.parse")).toBe("fail");
  });

  it("an encryption key never verifies, as at the receiver", async () => {
    const enc = { keys: [{ ...jwks.keys[0], use: "enc" }] };
    expect(outcome((await checkIdJag(await sign(good), input({ jwks: enc as never }))).results, "signature")).toBe("fail");
  });

  it("never throws, whatever it is given", async () => {
    for (const t of ["", "a.b.c", "....", "x".repeat(20_000), `${btoa("[]")}.${btoa("{}")}.x`]) await expect(checkIdJag(t, input())).resolves.toBeDefined();
  });
});

describe("tester: checkIssuerMetadata", () => {
  const meta = { issuer: ISSUER, jwks_uri: `${ISSUER}/jwks`, identity_chaining_requested_token_types_supported: ["urn:ietf:params:oauth:token-type:id-jag"], id_jag_signing_alg_values_supported: ["RS256", "ES256"] };

  it("good metadata and keys pass and nothing blocks", () => {
    const r = checkIssuerMetadata({ issuer: ISSUER, source: "oauth-authorization-server", metadata: meta, jwks });
    expect(r.blocking).toEqual([]);
    expect(r.results.filter((x) => x.outcome === "fail")).toEqual([]);
  });

  it("an issuer mismatch, private key material, or an empty JWKS blocks the registration", () => {
    expect(checkIssuerMetadata({ issuer: ISSUER, source: "oauth-authorization-server", metadata: { ...meta, issuer: `${ISSUER}/` }, jwks }).blocking).toContain("metadata.issuer");
    expect(checkIssuerMetadata({ issuer: ISSUER, source: "oauth-authorization-server", metadata: meta, jwks: { keys: [{ ...jwks.keys[0], d: "secret" }] } }).blocking).toContain("jwks.no_private");
    expect(checkIssuerMetadata({ issuer: ISSUER, source: "oauth-authorization-server", metadata: meta, jwks: { keys: [] } }).blocking).toContain("jwks.keys");
  });

  it("the OIDC fallback and a missing id-jag token type only warn; signing algs without RS256 fail without blocking", () => {
    const r = checkIssuerMetadata({ issuer: ISSUER, source: "openid-configuration", metadata: { issuer: ISSUER, jwks_uri: `${ISSUER}/jwks`, id_jag_signing_alg_values_supported: ["ES256"] }, jwks });
    expect(outcome(r.results, "metadata.location")).toBe("warn");
    expect(outcome(r.results, "metadata.token_types")).toBe("warn");
    expect(outcome(r.results, "metadata.signing_algs")).toBe("fail");
    expect(r.blocking).toEqual([]);
  });
});
