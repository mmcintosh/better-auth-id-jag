// verifyOwnIdToken in isolation: the jwt plugin's key adapter (`adapter.getJwks`) supplies "our"
// keys, so every defect can be the only one in an otherwise valid token signed by our key.
import type { GenericEndpointContext } from "better-auth";
import type { Jwk, JwtOptions } from "better-auth/plugins";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import { IdJagRefusal } from "../../src/core";
import { verifyOwnIdToken } from "../../src/issuer";
import { keyAlgorithm } from "../../src/issuer/subject/id-token";

const ISS = "https://idp.example/api/auth";
const CLIENT = "client-1";
const NOW = 1_800_000_000;

async function ours(alg: "ES256" | "RS256" = "ES256") {
  const { publicKey, privateKey } = await generateKeyPair(alg, { extractable: true });
  const jwk: Jwk = { id: `kid-${alg}`, publicKey: JSON.stringify(await exportJWK(publicKey)), privateKey: "unused", createdAt: new Date(), alg } as Jwk;
  const jwtOptions = { adapter: { getJwks: async () => [jwk] } } as unknown as JwtOptions;
  const sign = (payload: Record<string, unknown>, header: Record<string, unknown> = {}) =>
    new SignJWT({ iss: ISS, aud: CLIENT, sub: "user-1", iat: NOW, exp: NOW + 600, ...payload }).setProtectedHeader({ alg, kid: jwk.id, ...header }).sign(privateKey);
  return { jwk, jwtOptions, sign };
}

const ctx = {} as GenericEndpointContext;

async function outcome(token: string, jwtOptions: JwtOptions, o: { clientId?: string; now?: number; maxAgeSeconds?: number } = {}): Promise<string> {
  try {
    const c = await verifyOwnIdToken(ctx, token, { issuer: ISS, clientId: o.clientId ?? CLIENT, jwtOptions, now: o.now ?? NOW, ...(o.maxAgeSeconds !== undefined ? { maxAgeSeconds: o.maxAgeSeconds } : {}) });
    return `ok:${c.sub}`;
  } catch (e) {
    if (e instanceof IdJagRefusal) return `${e.reason}:${e.detail ?? ""}`;
    throw e;
  }
}

describe("verifyOwnIdToken", () => {
  it("accepts an ID token of ours: no typ or typ JWT, aud a string or an array with azp", async () => {
    for (const alg of ["ES256", "RS256"] as const) {
      const k = await ours(alg);
      expect(await outcome(await k.sign({}), k.jwtOptions)).toBe("ok:user-1");
      expect(await outcome(await k.sign({}, { typ: "JWT" }), k.jwtOptions)).toBe("ok:user-1");
      expect(await outcome(await k.sign({ aud: [CLIENT, "other"], azp: CLIENT }), k.jwtOptions)).toBe("ok:user-1");
    }
  });

  it("refuses a token of ours whose only defect is its typ (an access token, an ID-JAG, a logout token)", async () => {
    const k = await ours();
    for (const typ of ["at+jwt", "oauth-id-jag+jwt", "logout+jwt"]) expect(await outcome(await k.sign({}, { typ }), k.jwtOptions)).toBe("invalid_subject_token:typ");
  });

  it("refuses several audiences without azp naming the client, and an azp naming another", async () => {
    const k = await ours();
    expect(await outcome(await k.sign({ aud: [CLIENT, "other"] }), k.jwtOptions)).toBe("invalid_subject_token:azp");
    expect(await outcome(await k.sign({ azp: "other" }), k.jwtOptions)).toBe("invalid_subject_token:azp");
    expect(await outcome(await k.sign({ aud: "other" }), k.jwtOptions)).toBe("invalid_subject_token:audience is not the authenticated client");
  });

  it("time: expired at exp (no grace); iat more than 60 s ahead refused", async () => {
    const k = await ours();
    expect(await outcome(await k.sign({ exp: NOW }), k.jwtOptions)).toBe("subject_token_expired:");
    expect(await outcome(await k.sign({ exp: NOW + 1 }), k.jwtOptions)).toBe("ok:user-1");
    expect(await outcome(await k.sign({ iat: NOW + 61 }), k.jwtOptions)).toBe("invalid_subject_token:iat in the future");
    expect(await outcome(await k.sign({ iat: NOW + 60 }), k.jwtOptions)).toBe("ok:user-1");
  });

  it("age: iat older than maxAgeSeconds (default 3600) is subject_token_expired although exp is later; no iat is refused", async () => {
    const k = await ours();
    const later = { exp: NOW + 36_000 };
    expect(await outcome(await k.sign({ ...later, iat: NOW - 3600 }), k.jwtOptions)).toBe("ok:user-1");
    expect(await outcome(await k.sign({ ...later, iat: NOW - 3601 }), k.jwtOptions)).toBe("subject_token_expired:older than 3600 s");
    expect(await outcome(await k.sign({ ...later, iat: NOW - 60 }), k.jwtOptions, { maxAgeSeconds: 60 })).toBe("ok:user-1");
    expect(await outcome(await k.sign({ ...later, iat: NOW - 61 }), k.jwtOptions, { maxAgeSeconds: 60 })).toBe("subject_token_expired:older than 60 s");
    // Like exp, the age depends on the token only, so it is checked before the issuer.
    expect(await outcome(await k.sign({ ...later, iat: NOW - 3601, iss: "https://other.example" }), k.jwtOptions)).toBe("subject_token_expired:older than 3600 s");
    expect(await outcome(await k.sign({ ...later, iat: undefined }), k.jwtOptions)).toBe("invalid_subject_token:claims: iat");
  });

  it("refuses a symmetric algorithm even if a (misconfigured) key source hands over an oct key", async () => {
    const secret = new TextEncoder().encode("s".repeat(32));
    const jwk = { id: "hs", publicKey: JSON.stringify({ kty: "oct", k: btoa("s".repeat(32)).replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_") }), privateKey: "x", createdAt: new Date(), alg: "HS256" } as unknown as Jwk;
    const jwtOptions = { adapter: { getJwks: async () => [jwk] } } as unknown as JwtOptions;
    const token = await new SignJWT({ iss: ISS, aud: CLIENT, sub: "user-1", iat: NOW, exp: NOW + 600 }).setProtectedHeader({ alg: "HS256", kid: "hs" }).sign(secret);
    expect(await outcome(token, jwtOptions)).toBe("invalid_subject_token:alg");
  });

  it("refuses: another issuer, an unknown kid, a key whose alg differs, a missing claim, keys past their grace period", async () => {
    const k = await ours();
    expect(await outcome(await k.sign({ iss: "https://other.example" }), k.jwtOptions)).toBe("invalid_subject_token:issuer");
    expect(await outcome(await k.sign({}, { kid: "nope" }), k.jwtOptions)).toBe("invalid_subject_token:unknown kid");
    const rs = await ours("RS256");
    const mixed = { adapter: { getJwks: async () => [{ ...rs.jwk, id: k.jwk.id }] } } as unknown as JwtOptions;
    expect(await outcome(await k.sign({}), mixed)).toBe("invalid_subject_token:alg differs from the key's");
    expect(await outcome(await k.sign({ sub: undefined }), k.jwtOptions)).toBe("invalid_subject_token:claims: sub");
    const expired = { adapter: { getJwks: async () => [{ ...k.jwk, expiresAt: new Date((NOW - 31 * 86_400) * 1000) }] } } as unknown as JwtOptions;
    expect(await outcome(await k.sign({}), expired)).toBe("invalid_subject_token:unknown kid");
    const inGrace = { adapter: { getJwks: async () => [{ ...k.jwk, expiresAt: new Date((NOW - 86_400) * 1000) }] } } as unknown as JwtOptions;
    expect(await outcome(await k.sign({}), inGrace)).toBe("ok:user-1");
  });
});

describe("a stored key without alg (#19): its algorithm comes from the key, not from Better Auth's default", () => {
  it("keyAlgorithm: the stored alg; else the configured one when it fits the key type; else the key type's own", () => {
    const rsa = { kty: "RSA", n: "x", e: "AQAB" };
    expect(keyAlgorithm("ES256", rsa, undefined)).toBe("ES256");
    expect(keyAlgorithm(undefined, rsa, undefined)).toBe("RS256");
    expect(keyAlgorithm(null, rsa, "PS256")).toBe("PS256");
    expect(keyAlgorithm(undefined, rsa, "ES256")).toBe("RS256"); // configured, but not an RSA algorithm
    expect(keyAlgorithm(undefined, { kty: "EC", crv: "P-256" }, undefined)).toBe("ES256");
    expect(keyAlgorithm(undefined, { kty: "EC", crv: "P-384" }, "ES256")).toBe("ES384");
    expect(keyAlgorithm(undefined, { kty: "OKP", crv: "Ed25519" }, undefined)).toBe("EdDSA");
    expect(keyAlgorithm(undefined, { kty: "OKP", crv: "Ed25519" }, "Ed25519")).toBe("Ed25519");
    expect(keyAlgorithm(undefined, { kty: "OKP", crv: "X25519" }, undefined)).toBeUndefined();
    expect(keyAlgorithm(undefined, { kty: "oct" }, "HS256")).toBeUndefined();
  });

  for (const [alg, configured] of [["RS256", undefined], ["ES256", undefined], ["EdDSA", undefined], ["PS256", "PS256"]] as const) {
    it(`an ID token from a ${alg} key stored without alg verifies${configured ? " (keyPairConfig.alg PS256)" : ""}`, async () => {
      const { publicKey, privateKey } = await generateKeyPair(alg, { extractable: true, ...(alg === "EdDSA" ? { crv: "Ed25519" } : {}) });
      const jwk = { id: `kid-noalg-${alg}`, publicKey: JSON.stringify(await exportJWK(publicKey)), privateKey: "unused", createdAt: new Date() } as Jwk;
      const jwtOptions = { adapter: { getJwks: async () => [jwk] }, ...(configured ? { jwks: { keyPairConfig: { alg: configured } } } : {}) } as unknown as JwtOptions;
      const token = await new SignJWT({ iss: ISS, aud: CLIENT, sub: "user-1", iat: NOW, exp: NOW + 600 }).setProtectedHeader({ alg, kid: jwk.id }).sign(privateKey);
      expect(await outcome(token, jwtOptions)).toBe("ok:user-1");
    });
  }

  it("refuses a stored key whose type has no algorithm it can name", async () => {
    const k = await ours();
    const x25519 = { adapter: { getJwks: async () => [{ ...k.jwk, alg: undefined, publicKey: JSON.stringify({ kty: "OKP", crv: "X25519", x: "AAAA" }) }] } } as unknown as JwtOptions;
    expect(await outcome(await k.sign({}), x25519)).toBe("invalid_subject_token:key alg unknown");
  });
});

describe("an ID token with a crit header (D-014 #7)", () => {
  it("is refused, whether by our own check or by jose's (our guard is defence in depth)", async () => {
    const { publicKey, privateKey } = await generateKeyPair("ES256", { extractable: true });
    const jwk: Jwk = { id: "kid-crit", publicKey: JSON.stringify(await exportJWK(publicKey)), privateKey: "unused", createdAt: new Date(), alg: "ES256" } as Jwk;
    const jwtOptions = { adapter: { getJwks: async () => [jwk] } } as unknown as JwtOptions;
    const token = await new SignJWT({ iss: ISS, aud: CLIENT, sub: "user-1", iat: NOW, exp: NOW + 600 })
      .setProtectedHeader({ alg: "ES256", kid: jwk.id, crit: ["x-ext"], "x-ext": 1 } as never)
      .sign(privateKey, { crit: { "x-ext": true } });
    expect(await outcome(token, jwtOptions)).toMatch(/^invalid_subject_token:/);
  });
});
