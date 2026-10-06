// Building, parsing and verifying ID-JAGs (draft -04 §3). Parsing comes before the signature so a
// failure names its step, and the receiver can pick the trusted issuer from the (unverified) `iss`
// before fetching any key, as Okta's resource-app guide asks. Verification is the signature only
// (jose's compactVerify) followed by our own claim checks, so every failure has our reason code.
import { compactVerify, decodeJwt, decodeProtectedHeader } from "jose";
import type { CompactVerifyGetKey, CryptoKey, JWTPayload, KeyObject } from "jose";
import { z } from "zod";
import { IdJagRefusal, refuse } from "./errors";
import { ALLOWED_ALGORITHMS, DEFAULT_CLOCK_SKEW_SECONDS, ID_JAG_TYP, type IdJagAlgorithm, MAX_LIFETIME_SECONDS } from "./urns";

/** Longer than any real ID-JAG by far; refused before decoding (S9). */
export const MAX_TOKEN_LENGTH = 16 * 1024;

const nonEmpty = z.string().min(1).max(2048);
const seconds = z.number().int().nonnegative().max(2 ** 40);

/** The claims, required ones strict, optional ones typed when present, unknown ones kept. */
export const idJagClaimsSchema = z.looseObject({
  iss: nonEmpty,
  sub: nonEmpty,
  // A string, or an array with exactly one string (RFC 7519 allows arrays; one audience here).
  aud: z.union([nonEmpty, z.tuple([nonEmpty])]),
  client_id: nonEmpty,
  jti: z.string().min(1).max(256),
  exp: seconds,
  iat: seconds,
  nbf: seconds.optional(),
  resource: z.union([nonEmpty, z.array(nonEmpty).min(1).max(16)]).optional(),
  scope: z.string().max(4096).optional(),
  auth_time: seconds.optional(),
  acr: nonEmpty.optional(),
  amr: z.array(nonEmpty).max(32).optional(),
  email: nonEmpty.optional(),
  tenant: nonEmpty.optional(),
  aud_tenant: nonEmpty.optional(),
  aud_sub: nonEmpty.optional(),
});
export type IdJagClaims = z.infer<typeof idJagClaimsSchema>;

const REQUIRED = ["iss", "sub", "aud", "client_id", "jti", "exp", "iat"] as const;

export interface IdJagHeader {
  alg: IdJagAlgorithm;
  kid: string;
  typ: string;
}

export interface ParsedIdJag {
  header: IdJagHeader;
  claims: IdJagClaims;
  /** `aud` as a single string. */
  audience: string;
}

/**
 * `typ` is a media type (RFC 7515 §4.1.9): compared case-insensitively, `application/` optional.
 * Anything else, including a missing `typ`, is not an ID-JAG (S2).
 */
export function isIdJagTyp(typ: unknown): boolean {
  if (typeof typ !== "string") return false;
  const t = typ.toLowerCase();
  return t === ID_JAG_TYP || t === `application/${ID_JAG_TYP}`;
}

/**
 * Header and claims, checked for shape and lifetime, **without** verifying the signature. Throws
 * IdJagRefusal with the step that failed.
 */
export function parseIdJag(token: string, o: { maxLifetimeSeconds?: number } = {}): ParsedIdJag {
  if (typeof token !== "string" || token.length === 0 || token.length > MAX_TOKEN_LENGTH) refuse("malformed_token", "length");
  let rawHeader: Record<string, unknown>;
  let rawClaims: JWTPayload;
  try {
    // decodeJwt refuses anything but a compact JWS with a JSON object payload.
    rawHeader = decodeProtectedHeader(token) as Record<string, unknown>;
    rawClaims = decodeJwt(token);
  } catch {
    refuse("malformed_token");
  }
  if (!isIdJagTyp(rawHeader.typ)) refuse("wrong_typ", String(rawHeader.typ));
  if (typeof rawHeader.alg !== "string" || !(ALLOWED_ALGORITHMS as readonly string[]).includes(rawHeader.alg)) refuse("disallowed_alg", String(rawHeader.alg));
  if (typeof rawHeader.kid !== "string" || rawHeader.kid.length === 0) refuse("missing_kid");
  // Critical header parameters we don't understand mean "don't accept" (RFC 7515 §4.1.11).
  if (rawHeader.crit !== undefined) refuse("invalid_claim", "crit");

  for (const name of REQUIRED) if (rawClaims[name] === undefined) refuse("missing_claim", name);
  const parsed = idJagClaimsSchema.safeParse(rawClaims);
  if (!parsed.success) refuse("invalid_claim", parsed.error.issues.map((i) => i.path.join(".")).join(","));
  const claims = parsed.data;

  if (claims.exp <= claims.iat) refuse("invalid_claim", "exp <= iat");
  const max = o.maxLifetimeSeconds ?? MAX_LIFETIME_SECONDS;
  if (claims.exp - claims.iat > max) refuse("lifetime_too_long", `${claims.exp - claims.iat}s > ${max}s`);

  return {
    header: { alg: rawHeader.alg as IdJagAlgorithm, kid: rawHeader.kid, typ: rawHeader.typ as string },
    claims,
    audience: typeof claims.aud === "string" ? claims.aud : claims.aud[0],
  };
}

export type IdJagKey = CryptoKey | KeyObject | Uint8Array | CompactVerifyGetKey;

export interface VerifyExpectations {
  /** The trusted issuer the caller resolved from the unverified `iss`: exact match. */
  issuer: string;
  /** The receiver's own issuer identifier: exact match (S3). */
  audience: string;
  /** Seconds since the epoch; defaults to now. */
  now?: number;
  clockSkewSeconds?: number;
  maxLifetimeSeconds?: number;
  /** A subset of ALLOWED_ALGORITHMS, e.g. what the issuer's JWKS publishes. */
  algorithms?: readonly IdJagAlgorithm[];
}

/**
 * Parse, verify the signature with `key`, then check `iss`, `aud` and the time claims, in that
 * order. `client_id` continuity and `jti` single use need the request and the database, so the
 * receiver checks them after this returns.
 */
export async function verifyIdJag(token: string, key: IdJagKey, expected: VerifyExpectations): Promise<ParsedIdJag> {
  const parsed = parseIdJag(token, expected.maxLifetimeSeconds === undefined ? {} : { maxLifetimeSeconds: expected.maxLifetimeSeconds });
  const algorithms = [...(expected.algorithms ?? ALLOWED_ALGORITHMS)];
  if (!algorithms.includes(parsed.header.alg)) refuse("disallowed_alg", parsed.header.alg);
  // Before the signature: no key is fetched for an issuer the caller didn't resolve.
  if (parsed.claims.iss !== expected.issuer) refuse("untrusted_issuer", parsed.claims.iss);
  try {
    await compactVerify(token, key as CompactVerifyGetKey, { algorithms });
  } catch (error) {
    if (error instanceof IdJagRefusal) throw error;
    const code = (error as { code?: string }).code ?? "";
    // jose's JWKS errors (timeout, fetch failure, invalid set) are the issuer's keys being unavailable;
    // no matching key and a failed signature are the token's fault.
    if (code === "ERR_JWKS_TIMEOUT" || code === "ERR_JWKS_INVALID") refuse("jwks_unavailable", code);
    refuse("bad_signature", code || (error as Error).message);
  }
  if (parsed.audience !== expected.audience) refuse("wrong_audience", parsed.audience);
  checkTimes(parsed.claims, expected.now ?? Math.floor(Date.now() / 1000), expected.clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS);
  return parsed;
}

/** `exp`, `nbf` and `iat` against `now`, with skew. */
export function checkTimes(claims: Pick<IdJagClaims, "exp" | "iat" | "nbf">, now: number, skew: number): void {
  if (claims.exp + skew <= now) refuse("expired");
  if (claims.nbf !== undefined && claims.nbf - skew > now) refuse("not_yet_valid", "nbf");
  if (claims.iat - skew > now) refuse("not_yet_valid", "iat");
}

/** Signs a payload with a protected header; the issuer passes one built on the jwt plugin. */
export type IdJagSigner = (payload: Record<string, unknown>, header: { typ: string }) => Promise<string>;

/** 128 random bits, base64url: a `jti`. */
export function newJti(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * Build and sign an ID-JAG. The claims are checked against the same schema and lifetime cap the
 * receiver applies, so this side can't mint what a receiver of this package would refuse.
 */
export async function buildIdJag(claims: IdJagClaims, sign: IdJagSigner, o: { maxLifetimeSeconds?: number } = {}): Promise<string> {
  const parsed = idJagClaimsSchema.safeParse(claims);
  if (!parsed.success) throw new Error(`buildIdJag: invalid claims (${parsed.error.issues.map((i) => i.path.join(".")).join(",")})`);
  const max = o.maxLifetimeSeconds ?? MAX_LIFETIME_SECONDS;
  if (claims.exp <= claims.iat || claims.exp - claims.iat > max) throw new Error(`buildIdJag: lifetime must be within (0, ${max}] seconds`);
  // No `undefined` members: they'd be dropped by JSON anyway, and JWT payload types refuse them.
  const payload = Object.fromEntries(Object.entries(parsed.data).filter(([, v]) => v !== undefined));
  return sign(payload, { typ: ID_JAG_TYP });
}
