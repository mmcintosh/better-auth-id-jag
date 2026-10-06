import fc from "fast-check";
import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT } from "jose";
import type { CryptoKey, JWK, JWTPayload } from "jose";
import { describe, expect, it } from "vitest";
import { buildIdJag, IdJagRefusal, type IdJagClaims, isIdJagTyp, MAX_TOKEN_LENGTH, newJti, parseIdJag, verifyIdJag } from "../../src/core";

const ISS = "https://idp.example";
const AUD = "https://as.example/api/auth";
// A fixed clock, injected everywhere: no test depends on which second it runs in.
const T = 1_800_000_000;

async function keyPair(alg: "RS256" | "ES256" | "EdDSA" | "Ed25519" | "HS256" | "PS256", kid = "k1") {
  if (alg === "HS256") return { alg, kid, privateKey: new TextEncoder().encode("h".repeat(32)) as unknown as CryptoKey, jwks: createLocalJWKSet({ keys: [] }) };
  const { publicKey, privateKey } = await generateKeyPair(alg, { extractable: true });
  const jwk: JWK = { ...(await exportJWK(publicKey)), kid, alg };
  return { alg, kid, privateKey, jwk, jwks: createLocalJWKSet({ keys: [jwk] }) };
}

function claims(over: Partial<IdJagClaims> & Record<string, unknown> = {}): IdJagClaims {
  return { iss: ISS, sub: "user-1", aud: AUD, client_id: "client-at-as", jti: newJti(), iat: T, exp: T + 300, ...over };
}

async function sign(k: { alg: string; kid: string; privateKey: CryptoKey }, payload: Record<string, unknown>, header: Record<string, unknown> = {}) {
  return new SignJWT(payload as JWTPayload).setProtectedHeader({ alg: k.alg, kid: k.kid, typ: "oauth-id-jag+jwt", ...header }).sign(k.privateKey);
}

const b64url = (v: unknown) => btoa(unescape(encodeURIComponent(JSON.stringify(v)))).replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
/** A compact JWS with any header (the signature is junk: for parse-step refusals only). */
const raw = (header: object, payload: object) => `${b64url(header)}.${b64url(payload)}.c2ln`;
const HEADER = { alg: "ES256", kid: "k1", typ: "oauth-id-jag+jwt" };

async function reasonOf(p: Promise<unknown> | (() => unknown)): Promise<string> {
  try {
    await (typeof p === "function" ? p() : p);
    return "accepted";
  } catch (e) {
    if (e instanceof IdJagRefusal) return e.reason;
    throw e;
  }
}

const at = (now = T) => ({ issuer: ISS, audience: AUD, now });

describe("verifyIdJag: accepts", () => {
  for (const alg of ["RS256", "ES256", "EdDSA", "Ed25519"] as const) {
    it(`a valid ${alg} ID-JAG`, async () => {
      const k = await keyPair(alg);
      const v = await verifyIdJag(await sign(k, claims()), k.jwks, at());
      expect(v.claims.client_id).toBe("client-at-as");
      expect(v.audience).toBe(AUD);
      expect(v.header.alg).toBe(alg);
    });
  }

  it("aud as a one-element array, typ in any case or with application/", async () => {
    const k = await keyPair("ES256");
    for (const typ of ["OAUTH-ID-JAG+JWT", "application/oauth-id-jag+jwt", "Application/Oauth-Id-Jag+Jwt"]) {
      const v = await verifyIdJag(await sign(k, claims({ aud: [AUD] }), { typ }), k.jwks, at());
      expect(v.audience).toBe(AUD);
    }
  });

  it("built with buildIdJag (the issuer's path)", async () => {
    const k = await keyPair("ES256");
    const token = await buildIdJag(claims({ scope: "read", resource: "https://mcp.example/mcp" }), (payload, header) => sign(k, payload, header));
    const v = await verifyIdJag(token, k.jwks, at());
    expect(v.claims.scope).toBe("read");
    expect(v.claims.resource).toBe("https://mcp.example/mcp");
  });

  it("act, as Okta sends it for an AI agent (D-010), and a nested delegation chain", async () => {
    const k = await keyPair("RS256");
    const okta = { sub: "0oa18f03hj0tOU9Hd698", sub_profile: "ai_agent web_app" };
    const v = await verifyIdJag(await sign(k, claims({ act: okta, sub_profile: "user" })), k.jwks, at());
    expect(v.claims.act).toEqual(okta);
    const chain = { sub: "a1", act: { sub: "a2", act: { sub: "a3", act: { sub: "a4" } } } };
    expect((await verifyIdJag(await sign(k, claims({ act: chain })), k.jwks, at())).claims.act).toEqual(chain);
  });

  it("two keys with the same kid during rotation: the one that verifies is used", async () => {
    const old = await keyPair("ES256", "same");
    const fresh = await keyPair("ES256", "same");
    const jwks = createLocalJWKSet({ keys: [old.jwk!, fresh.jwk!] });
    expect(await reasonOf(verifyIdJag(await sign(fresh, claims()), jwks, at()))).toBe("accepted");
    expect(await reasonOf(verifyIdJag(await sign(old, claims()), jwks, at()))).toBe("accepted");
    const stranger = await keyPair("ES256", "same");
    expect(await reasonOf(verifyIdJag(await sign(stranger, claims()), jwks, at()))).toBe("bad_signature");
  });
});

describe("verifyIdJag: refuses, each with its reason (S2, S3, S4, S7)", () => {
  it("parse step: typ, alg, kid, crit, claims, lifetime", async () => {
    const k = await keyPair("ES256");
    const cases: [string, Promise<string>][] = [
      ["wrong_typ", sign(k, claims(), { typ: "JWT" })],
      ["wrong_typ", sign(k, claims(), { typ: "at+jwt" })],
      ["wrong_typ", sign(k, claims(), { typ: undefined })],
      ["missing_kid", new SignJWT(claims() as JWTPayload).setProtectedHeader({ alg: "ES256", typ: "oauth-id-jag+jwt" }).sign(k.privateKey)],
      ["missing_kid", Promise.resolve(raw({ ...HEADER, kid: "" }, claims()))],
      ["invalid_claim", Promise.resolve(raw({ ...HEADER, crit: ["x-ext"], "x-ext": 1 }, claims()))],
      ["missing_claim", sign(k, { ...claims(), client_id: undefined })],
      ["missing_claim", sign(k, { ...claims(), jti: undefined })],
      ["invalid_claim", sign(k, claims({ aud: [AUD, "https://other.example"] as unknown as [string] }))],
      ["invalid_claim", sign(k, { ...claims(), exp: "soon" })],
      ["invalid_claim", sign(k, claims({ exp: T - 10, iat: T }))],
      ["invalid_claim", sign(k, claims({ exp: T, iat: T }))],
      ["invalid_claim", sign(k, claims({ jti: "a\u0000b" }))],
      ["invalid_claim", sign(k, claims({ iss: "https://idp.example\n" }))],
      ["lifetime_too_long", sign(k, claims({ iat: T, exp: T + 901 }))],
      ["unsupported_claim", sign(k, claims({ authorization_details: [{ type: "x", actions: ["read"] }] }))],
      ["invalid_claim", sign(k, claims({ act: { sub_profile: "ai_agent" } as never }))],
      ["invalid_claim", sign(k, claims({ act: "agent" as never }))],
      ["invalid_claim", sign(k, claims({ act: { sub: "a1", act: { sub: "a2", act: { sub: "a3", act: { sub: "a4", act: { sub: "a5" } } } } } }))],
    ];
    for (const [want, token] of cases) expect(await reasonOf(verifyIdJag(await token, k.jwks, at())), want).toBe(want);
    // The boundary: exactly 900 seconds is allowed.
    expect(await reasonOf(verifyIdJag(await sign(k, claims({ iat: T, exp: T + 900 })), k.jwks, at()))).toBe("accepted");
  });

  it("algorithms outside the allow-list, including HS256 and none", async () => {
    const hs = await keyPair("HS256");
    expect(await reasonOf(verifyIdJag(await sign(hs, claims()), hs.jwks, at()))).toBe("disallowed_alg");
    const ps = await keyPair("PS256");
    expect(await reasonOf(verifyIdJag(await sign(ps, claims()), ps.jwks, at()))).toBe("disallowed_alg");
    const none = `${b64url({ alg: "none", typ: "oauth-id-jag+jwt", kid: "k1" })}.${b64url(claims())}.`;
    expect(await reasonOf(verifyIdJag(none, hs.jwks, at()))).toBe("disallowed_alg");
  });

  it("an algorithm the issuer doesn't publish is a bad signature, not a public alg refusal (S8)", async () => {
    const k = await keyPair("EdDSA");
    expect(await reasonOf(verifyIdJag(await sign(k, claims()), k.jwks, { ...at(), algorithms: ["RS256", "ES256"] }))).toBe("bad_signature");
  });

  it("an issuer other than the resolved one, before any key is used", async () => {
    const k = await keyPair("ES256");
    let keyUsed = false;
    const spy = ((...a: Parameters<typeof k.jwks>) => {
      keyUsed = true;
      return k.jwks(...a);
    }) as typeof k.jwks;
    expect(await reasonOf(verifyIdJag(await sign(k, claims({ iss: "https://evil.example" })), spy, at()))).toBe("untrusted_issuer");
    expect(keyUsed).toBe(false);
  });

  it("caller-checkable refusals come before trust: an expired token from an untrusted issuer says expired (S8)", async () => {
    const k = await keyPair("ES256");
    const expired = claims({ iss: "https://anyone.example", iat: T - 1000, exp: T - 700 });
    expect(await reasonOf(verifyIdJag(await sign(k, expired), k.jwks, at()))).toBe("expired");
  });

  it("an ID-JAG issued to itself (draft §9.3)", async () => {
    const k = await keyPair("ES256");
    expect(await reasonOf(verifyIdJag(await sign(k, claims({ iss: AUD })), k.jwks, { issuer: AUD, audience: AUD, now: T }))).toBe("self_issued");
  });

  it("a signature by another key, an unknown kid, a tampered payload", async () => {
    const k = await keyPair("ES256");
    const other = await keyPair("ES256");
    expect(await reasonOf(verifyIdJag(await sign(other, claims()), k.jwks, at()))).toBe("bad_signature");
    expect(await reasonOf(verifyIdJag(await sign({ ...k, kid: "unknown" }, claims()), k.jwks, at()))).toBe("bad_signature");
    const [h, , s] = (await sign(k, claims())).split(".");
    const forged = `${h}.${b64url(claims({ sub: "admin" }))}.${s}`;
    expect(await reasonOf(verifyIdJag(forged, k.jwks, at()))).toBe("bad_signature");
  });

  it("keys that can't be loaded are jwks_unavailable, not a forged token", async () => {
    const k = await keyPair("ES256");
    const token = await sign(k, claims());
    const down = (async () => {
      throw new TypeError("fetch failed");
    }) as unknown as typeof k.jwks;
    expect(await reasonOf(verifyIdJag(token, down, at()))).toBe("jwks_unavailable");
    const refusing = (async () => {
      throw new IdJagRefusal("jwks_unavailable", "status 503");
    }) as unknown as typeof k.jwks;
    expect(await reasonOf(verifyIdJag(token, refusing, at()))).toBe("jwks_unavailable");
  });

  it("aud: exact string match, no trailing-slash or case games", async () => {
    const k = await keyPair("ES256");
    for (const aud of [`${AUD}/`, AUD.toUpperCase(), "https://as.example", "https://as.example/api/auth#x"]) {
      expect(await reasonOf(verifyIdJag(await sign(k, claims({ aud })), k.jwks, at())), aud).toBe("wrong_audience");
    }
  });

  it("time, at the boundaries: exp + skew, nbf - skew, iat - skew", async () => {
    const k = await keyPair("ES256");
    const check = async (c: IdJagClaims) => reasonOf(verifyIdJag(await sign(k, c), k.jwks, { ...at(), clockSkewSeconds: 60 }));
    expect(await check(claims({ iat: T - 400, exp: T - 60 }))).toBe("expired");
    expect(await check(claims({ iat: T - 400, exp: T - 59 }))).toBe("accepted");
    expect(await check(claims({ nbf: T + 61 }))).toBe("not_yet_valid");
    expect(await check(claims({ nbf: T + 60 }))).toBe("accepted");
    expect(await check(claims({ iat: T + 61, exp: T + 200 }))).toBe("not_yet_valid");
    expect(await check(claims({ iat: T + 60, exp: T + 200 }))).toBe("accepted");
  });

  it("numeric options that would switch a check off are configuration errors", async () => {
    const k = await keyPair("ES256");
    const token = await sign(k, claims({ iat: T - 86_400, exp: T - 86_000 }));
    for (const o of [{ clockSkewSeconds: Number.NaN }, { clockSkewSeconds: Number.POSITIVE_INFINITY }, { clockSkewSeconds: 301 }, { clockSkewSeconds: -1 }, { now: Number.NaN }, { maxLifetimeSeconds: Number.NaN }, { maxLifetimeSeconds: 1e9 }, { maxLifetimeSeconds: 0 }]) {
      await expect(verifyIdJag(token, k.jwks, { ...at(), ...o }), JSON.stringify(o)).rejects.toThrow(/id-jag: /);
    }
    expect(() => parseIdJag(token, { maxLifetimeSeconds: 901 })).toThrow(/id-jag: maxLifetimeSeconds/);
  });

  it("buildIdJag refuses what a receiver would", async () => {
    const k = await keyPair("ES256");
    const s = (p: Record<string, unknown>, h: { typ: string }) => sign(k, p, h);
    await expect(buildIdJag(claims({ iat: T, exp: T + 901 }), s)).rejects.toThrow(/lifetime/);
    await expect(buildIdJag({ ...claims(), client_id: "" }, s)).rejects.toThrow(/client_id/);
    await expect(buildIdJag(claims({ authorization_details: [{ type: "x" }] }), s)).rejects.toThrow(/authorization_details/);
    await expect(buildIdJag(claims(), s, { maxLifetimeSeconds: Number.NaN })).rejects.toThrow(/id-jag: /);
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

  it("a valid token with one field changed: refused with a reason, or the result honours every invariant", () => {
    // Valid by default, then one header or claim field replaced by an arbitrary value, so most runs
    // reach the deep checks (a fully random token almost never does).
    const valid = { header: HEADER, payload: claims({ jti: "fixed-jti" }) };
    const anyValue = fc.oneof(fc.string(), fc.integer(), fc.double(), fc.boolean(), fc.constant(null), fc.array(fc.string(), { maxLength: 3 }), fc.constant(undefined), fc.object({ maxDepth: 1 }));
    const headerField = fc.constantFrom("alg", "kid", "typ", "crit");
    const claimField = fc.constantFrom("iss", "sub", "aud", "client_id", "jti", "exp", "iat", "nbf", "scope", "resource", "authorization_details", "act", "sub_id", "amr");
    const change = fc.oneof(fc.record({ where: fc.constant("header" as const), field: headerField, value: anyValue }), fc.record({ where: fc.constant("payload" as const), field: claimField, value: anyValue }));
    let parsedCount = 0;
    fc.assert(
      fc.property(change, (c) => {
        const header: Record<string, unknown> = { ...valid.header };
        const payload: Record<string, unknown> = { ...valid.payload };
        (c.where === "header" ? header : payload)[c.field] = c.value;
        let parsed: ReturnType<typeof parseIdJag>;
        try {
          parsed = parseIdJag(raw(header, payload));
        } catch (e) {
          expect(e).toBeInstanceOf(IdJagRefusal);
          return;
        }
        parsedCount++;
        expect(isIdJagTyp(parsed.header.typ)).toBe(true);
        expect(["ES256", "RS256", "EdDSA", "Ed25519"]).toContain(parsed.header.alg);
        expect(parsed.header.kid.length).toBeGreaterThan(0);
        expect(typeof parsed.audience).toBe("string");
        expect(parsed.claims.exp - parsed.claims.iat).toBeGreaterThan(0);
        expect(parsed.claims.exp - parsed.claims.iat).toBeLessThanOrEqual(900);
        expect(parsed.claims.authorization_details).toBeUndefined();
        if (parsed.claims.act !== undefined) expect(typeof parsed.claims.act.sub).toBe("string");
        // biome-ignore lint/suspicious/noControlCharactersInRegex: asserting their absence.
        for (const k of ["iss", "sub", "client_id", "jti"] as const) expect(parsed.claims[k]).not.toMatch(/[\u0000-\u001f]/);
      }),
      { numRuns: 1000 },
    );
    // The invariant branch must actually run: ~95 per 1000 here, ~0.25 with fully random tokens.
    expect(parsedCount).toBeGreaterThan(50);
  });

  it("header values whose toString throws are refused, not crashed on (found by the property test)", () => {
    const evil = { toString: "not a function" };
    expect(() => parseIdJag(raw({ ...HEADER, typ: evil }, claims()))).toThrow(expect.objectContaining({ reason: "wrong_typ", detail: "<object>" }));
    expect(() => parseIdJag(raw({ ...HEADER, alg: evil }, claims()))).toThrow(expect.objectContaining({ reason: "disallowed_alg" }));
  });

  it("parse alone (the receiver's issuer lookup) refuses algorithms outside the allow-list", () => {
    for (const alg of ["HS256", "none", "PS256", "RS512", "es256"]) {
      expect(() => parseIdJag(raw({ ...HEADER, alg }, claims())), alg).toThrow(expect.objectContaining({ reason: "disallowed_alg" }));
    }
    expect(parseIdJag(raw(HEADER, claims())).header.alg).toBe("ES256");
  });

  it("refuses a well-formed token one character over the length cap, accepts one exactly at it", () => {
    const [h, p] = raw(HEADER, claims()).split(".") as [string, string];
    // The signature segment is junk either way: parse never checks it.
    const ofLength = (n: number) => `${h}.${p}.${"A".repeat(n - h.length - p.length - 2)}`;
    expect(parseIdJag(ofLength(MAX_TOKEN_LENGTH)).claims.iss).toBe(ISS);
    expect(() => parseIdJag(ofLength(MAX_TOKEN_LENGTH + 1))).toThrow(expect.objectContaining({ reason: "malformed_token", detail: "length" }));
  });

  it("newJti: 128 bits, base64url, distinct", () => {
    const seen = new Set(Array.from({ length: 1000 }, newJti));
    expect(seen.size).toBe(1000);
    for (const j of seen) expect(j).toMatch(/^[A-Za-z0-9_-]{22}$/);
  });
});
