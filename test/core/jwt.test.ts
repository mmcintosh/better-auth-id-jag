import fc from "fast-check";
import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT } from "jose";
import type { CryptoKey, JWK, JWTPayload } from "jose";
import { describe, expect, it } from "vitest";
import { buildIdJag, IdJagRefusal, type IdJagClaims, isIdJagTyp, MAX_TOKEN_LENGTH, newJti, parseIdJag, verifyIdJag } from "../../src/core";

const ISS = "https://idp.example";
const AUD = "https://as.example/api/auth";
const now = () => Math.floor(Date.now() / 1000);

async function keyPair(alg: "RS256" | "ES256" | "EdDSA" | "HS256" | "PS256", kid = "k1") {
  if (alg === "HS256") return { alg, kid, privateKey: new TextEncoder().encode("h".repeat(32)) as unknown as CryptoKey, jwks: createLocalJWKSet({ keys: [] }) };
  const { publicKey, privateKey } = await generateKeyPair(alg, { extractable: true });
  const jwk: JWK = { ...(await exportJWK(publicKey)), kid, alg };
  return { alg, kid, privateKey, jwk, jwks: createLocalJWKSet({ keys: [jwk] }) };
}

function claims(over: Partial<IdJagClaims> = {}): IdJagClaims {
  const t = now();
  return { iss: ISS, sub: "user-1", aud: AUD, client_id: "client-at-as", jti: newJti(), iat: t, exp: t + 300, ...over };
}

async function sign(k: { alg: string; kid: string; privateKey: CryptoKey }, payload: Record<string, unknown>, header: Record<string, unknown> = {}) {
  return new SignJWT(payload as JWTPayload).setProtectedHeader({ alg: k.alg, kid: k.kid, typ: "oauth-id-jag+jwt", ...header }).sign(k.privateKey);
}

const b64url = (v: unknown) => btoa(unescape(encodeURIComponent(JSON.stringify(v)))).replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
/** A compact JWS with any header (the signature is junk: for parse-step refusals only). */
const raw = (header: object, payload: object) => `${b64url(header)}.${b64url(payload)}.c2ln`;

async function reasonOf(p: Promise<unknown> | (() => unknown)): Promise<string> {
  try {
    await (typeof p === "function" ? p() : p);
    return "accepted";
  } catch (e) {
    if (e instanceof IdJagRefusal) return e.reason;
    throw e;
  }
}

describe("verifyIdJag: accepts", () => {
  for (const alg of ["RS256", "ES256", "EdDSA"] as const) {
    it(`a valid ${alg} ID-JAG`, async () => {
      const k = await keyPair(alg);
      const v = await verifyIdJag(await sign(k, claims()), k.jwks, { issuer: ISS, audience: AUD });
      expect(v.claims.client_id).toBe("client-at-as");
      expect(v.audience).toBe(AUD);
      expect(v.header.alg).toBe(alg);
    });
  }

  it("aud as a one-element array, typ in any case or with application/", async () => {
    const k = await keyPair("ES256");
    for (const typ of ["OAUTH-ID-JAG+JWT", "application/oauth-id-jag+jwt", "Application/Oauth-Id-Jag+Jwt"]) {
      const v = await verifyIdJag(await sign(k, claims({ aud: [AUD] }), { typ }), k.jwks, { issuer: ISS, audience: AUD });
      expect(v.audience).toBe(AUD);
    }
  });

  it("built with buildIdJag (the issuer's path)", async () => {
    const k = await keyPair("ES256");
    const token = await buildIdJag(claims({ scope: "read", resource: "https://mcp.example/mcp" }), (payload, header) => sign(k, payload, header));
    const v = await verifyIdJag(token, k.jwks, { issuer: ISS, audience: AUD });
    expect(v.claims.scope).toBe("read");
    expect(v.claims.resource).toBe("https://mcp.example/mcp");
  });
});

describe("verifyIdJag: refuses, each with its reason (S2, S3, S4, S7)", () => {
  it("parse step: typ, alg, kid, crit, claims, lifetime", async () => {
    const k = await keyPair("ES256");
    const expect_ = { issuer: ISS, audience: AUD };
    const cases: [string, Promise<string>][] = [
      ["wrong_typ", sign(k, claims(), { typ: "JWT" })],
      ["wrong_typ", sign(k, claims(), { typ: "at+jwt" })],
      ["wrong_typ", sign(k, claims(), { typ: undefined })],
      ["missing_kid", new SignJWT(claims() as JWTPayload).setProtectedHeader({ alg: "ES256", typ: "oauth-id-jag+jwt" }).sign(k.privateKey)],
      ["invalid_claim", Promise.resolve(raw({ alg: "ES256", kid: "k1", typ: "oauth-id-jag+jwt", crit: ["x-ext"], "x-ext": 1 }, claims()))],
      ["missing_claim", sign(k, { ...claims(), client_id: undefined })],
      ["missing_claim", sign(k, { ...claims(), jti: undefined })],
      ["invalid_claim", sign(k, claims({ aud: [AUD, "https://other.example"] as unknown as [string] }))],
      ["invalid_claim", sign(k, { ...claims(), exp: "soon" })],
      ["invalid_claim", sign(k, claims({ exp: now() - 10, iat: now() }))],
      ["lifetime_too_long", sign(k, claims({ iat: now(), exp: now() + 901 }))],
    ];
    for (const [want, token] of cases) expect(await reasonOf(verifyIdJag(await token, k.jwks, expect_)), want).toBe(want);
  });

  it("algorithms outside RS256/ES256/EdDSA, including HS256 and none", async () => {
    const hs = await keyPair("HS256");
    expect(await reasonOf(verifyIdJag(await sign(hs, claims()), hs.jwks, { issuer: ISS, audience: AUD }))).toBe("disallowed_alg");
    const ps = await keyPair("PS256");
    expect(await reasonOf(verifyIdJag(await sign(ps, claims()), ps.jwks, { issuer: ISS, audience: AUD }))).toBe("disallowed_alg");
    const none = `${b64url({ alg: "none", typ: "oauth-id-jag+jwt", kid: "k1" })}.${b64url(claims())}.`;
    expect(await reasonOf(verifyIdJag(none, hs.jwks, { issuer: ISS, audience: AUD }))).toBe("disallowed_alg");
  });

  it("an algorithm the caller narrowed away", async () => {
    const k = await keyPair("EdDSA");
    expect(await reasonOf(verifyIdJag(await sign(k, claims()), k.jwks, { issuer: ISS, audience: AUD, algorithms: ["RS256", "ES256"] }))).toBe("disallowed_alg");
  });

  it("an issuer other than the resolved one, before any key is used", async () => {
    const k = await keyPair("ES256");
    let keyUsed = false;
    const spy = ((...a: Parameters<typeof k.jwks>) => {
      keyUsed = true;
      return k.jwks(...a);
    }) as typeof k.jwks;
    expect(await reasonOf(verifyIdJag(await sign(k, claims({ iss: "https://evil.example" })), spy, { issuer: ISS, audience: AUD }))).toBe("untrusted_issuer");
    expect(keyUsed).toBe(false);
  });

  it("a signature by another key, an unknown kid, a tampered payload", async () => {
    const k = await keyPair("ES256");
    const other = await keyPair("ES256");
    expect(await reasonOf(verifyIdJag(await sign(other, claims()), k.jwks, { issuer: ISS, audience: AUD }))).toBe("bad_signature");
    expect(await reasonOf(verifyIdJag(await sign({ ...k, kid: "unknown" }, claims()), k.jwks, { issuer: ISS, audience: AUD }))).toBe("bad_signature");
    const [h, , s] = (await sign(k, claims())).split(".");
    const forged = `${h}.${btoa(JSON.stringify(claims({ sub: "admin" }))).replace(/=+$/, "")}.${s}`;
    expect(await reasonOf(verifyIdJag(forged, k.jwks, { issuer: ISS, audience: AUD }))).toBe("bad_signature");
  });

  it("aud: exact string match, no trailing-slash or case games", async () => {
    const k = await keyPair("ES256");
    for (const aud of [`${AUD}/`, AUD.toUpperCase(), "https://as.example", "https://as.example/api/auth#x"]) {
      expect(await reasonOf(verifyIdJag(await sign(k, claims({ aud })), k.jwks, { issuer: ISS, audience: AUD })), aud).toBe("wrong_audience");
    }
  });

  it("time: expired beyond skew, nbf or iat in the future beyond skew; within skew is fine", async () => {
    const k = await keyPair("ES256");
    const t = now();
    const at = async (c: IdJagClaims) => reasonOf(verifyIdJag(await sign(k, c), k.jwks, { issuer: ISS, audience: AUD, clockSkewSeconds: 60 }));
    expect(await at(claims({ iat: t - 400, exp: t - 61 }))).toBe("expired");
    expect(await at(claims({ iat: t - 400, exp: t - 59 }))).toBe("accepted");
    expect(await at(claims({ nbf: t + 61 }))).toBe("not_yet_valid");
    expect(await at(claims({ iat: t + 61, exp: t + 200 }))).toBe("not_yet_valid");
    expect(await at(claims({ iat: t + 59, exp: t + 200 }))).toBe("accepted");
  });

  it("buildIdJag refuses what a receiver would", async () => {
    const k = await keyPair("ES256");
    const s = (p: Record<string, unknown>, h: { typ: string }) => sign(k, p, h);
    await expect(buildIdJag(claims({ iat: now(), exp: now() + 901 }), s)).rejects.toThrow(/lifetime/);
    await expect(buildIdJag({ ...claims(), client_id: "" }, s)).rejects.toThrow(/client_id/);
  });
});

describe("parseIdJag: properties (S9)", () => {
  it("any string is either parsed or refused with a reason, never another error", () => {
    fc.assert(
      fc.property(fc.oneof(fc.string(), fc.string({ unit: "binary" }), fc.stringMatching(/^[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*$/)), (s) => {
        try {
          parseIdJag(s);
        } catch (e) {
          expect(e).toBeInstanceOf(IdJagRefusal);
        }
      }),
      { numRuns: 500 },
    );
  });

  it("arbitrary JSON header and payload: refused with a reason, or the result honours every invariant", () => {
    const header = fc.record({ alg: fc.constantFrom("ES256", "RS256", "EdDSA", "HS256", "none", 7), kid: fc.oneof(fc.string(), fc.constant(undefined)), typ: fc.constantFrom("oauth-id-jag+jwt", "OAUTH-ID-JAG+JWT", "jwt", "", undefined) }, { requiredKeys: [] });
    const t = now();
    const payload = fc.record(
      {
        iss: fc.oneof(fc.string(), fc.integer()),
        sub: fc.oneof(fc.string(), fc.constant(null)),
        aud: fc.oneof(fc.string(), fc.array(fc.string(), { maxLength: 3 })),
        client_id: fc.string(),
        jti: fc.string({ maxLength: 300 }),
        iat: fc.oneof(fc.integer({ min: t - 1000, max: t + 1000 }), fc.double()),
        exp: fc.integer({ min: t - 1000, max: t + 2000 }),
      },
      { requiredKeys: [] },
    );
    fc.assert(
      fc.property(header, payload, (h, p) => {
        const token = raw(h, p);
        let parsed: ReturnType<typeof parseIdJag>;
        try {
          parsed = parseIdJag(token);
        } catch (e) {
          expect(e).toBeInstanceOf(IdJagRefusal);
          return;
        }
        expect(isIdJagTyp(parsed.header.typ)).toBe(true);
        expect(["ES256", "RS256", "EdDSA"]).toContain(parsed.header.alg);
        expect(parsed.header.kid.length).toBeGreaterThan(0);
        expect(typeof parsed.audience).toBe("string");
        expect(parsed.claims.exp - parsed.claims.iat).toBeGreaterThan(0);
        expect(parsed.claims.exp - parsed.claims.iat).toBeLessThanOrEqual(900);
      }),
      { numRuns: 1000 },
    );
  });

  it("parse alone (the receiver's issuer lookup) refuses algorithms outside the allow-list", () => {
    for (const alg of ["HS256", "none", "PS256", "RS512", "es256"]) {
      expect(() => parseIdJag(raw({ alg, kid: "k1", typ: "oauth-id-jag+jwt" }, claims())), alg).toThrow(expect.objectContaining({ reason: "disallowed_alg" }));
    }
    expect(parseIdJag(raw({ alg: "ES256", kid: "k1", typ: "oauth-id-jag+jwt" }, claims())).header.alg).toBe("ES256");
  });

  it("refuses an oversized token before decoding", () => {
    expect(() => parseIdJag("a".repeat(MAX_TOKEN_LENGTH + 1))).toThrow(IdJagRefusal);
  });

  it("newJti: 128 bits, base64url, distinct", () => {
    const seen = new Set(Array.from({ length: 1000 }, newJti));
    expect(seen.size).toBe(1000);
    for (const j of seen) expect(j).toMatch(/^[A-Za-z0-9_-]{22}$/);
  });
});
