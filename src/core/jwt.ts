// Building, parsing and verifying ID-JAGs (draft -04 §3, §4.4). Parsing comes before the signature
// so a failure names its step, and the receiver can pick the trusted issuer from the (unverified)
// `iss` before fetching any key, as Okta's resource-app guide asks. Verification is the signature
// only (jose's compactVerify) followed by our own claim checks, so every failure has our reason code.
//
// S8 ordering: everything the caller can check for itself (shape, typ, alg, lifetime, time) is
// checked before anything that depends on our trust configuration (iss, key, signature, aud), so a
// public refusal never tells the caller whether an issuer is trusted (review of D-006, finding 4).
import { compactVerify, decodeJwt, decodeProtectedHeader, errors as joseErrors } from "jose";
import type { CompactVerifyGetKey, CryptoKey, JWTPayload, KeyObject } from "jose";
import { z } from "zod";
import { IdJagRefusal, refuse } from "./errors";
import { ALLOWED_ALGORITHMS, DEFAULT_CLOCK_SKEW_SECONDS, ID_JAG_TYP, type IdJagAlgorithm, MAX_CLOCK_SKEW_SECONDS, MAX_LIFETIME_SECONDS } from "./urns";

/** Longer than any real ID-JAG by far; refused before decoding (S9). */
export const MAX_TOKEN_LENGTH = 16 * 1024;

// No C0/C1 controls (NUL included) in identifiers: they end up in keys, logs and comparisons.
// biome-ignore lint/suspicious/noControlCharactersInRegex: refusing them is the point.
const noControls = (s: string) => !/[\u0000-\u001f\u007f-\u009f]/.test(s);
const nonEmpty = z.string().min(1).max(2048).refine(noControls, "control characters");
const seconds = z.number().int().nonnegative().max(2 ** 40);

/**
 * Claims this package cannot honour yet. The draft says a receiver MUST process
 * `authorization_details` (RFC 9396); accepting it while ignoring it could grant more than the IdP
 * authorised, so it's refused (v1). `act` is supported: see actSchema (D-010).
 */
export const UNSUPPORTED_CLAIMS = ["authorization_details"] as const;

/** How deep a delegation chain (`act` inside `act`) may go. */
export const MAX_ACT_DEPTH = 4;

/**
 * RFC 8693 §4.1 `act`: who acts on the subject's behalf, e.g. Okta names the AI agent
 * (`{ sub: "<agent id>", sub_profile: "ai_agent ..." }`). It records delegation and widens
 * nothing; the receiver carries it into the access token so the resource server sees the actor.
 * An object with a string `sub`, optionally nested (prior actors), at most MAX_ACT_DEPTH deep.
 */
export type ActClaim = { sub: string; act?: ActClaim; [k: string]: unknown };
const actSchema: z.ZodType<ActClaim> = z.lazy(() => z.looseObject({ sub: nonEmpty, sub_profile: z.string().max(256).optional(), act: actSchema.optional() })) as z.ZodType<ActClaim>;

function actDepth(act: ActClaim | undefined): number {
  let depth = 0;
  for (let a = act; a; a = a.act) depth++;
  return depth;
}

/** The claims, required ones strict, optional ones typed when present, unknown ones kept. */
export const idJagClaimsSchema = z.looseObject({
  iss: nonEmpty,
  sub: nonEmpty,
  // A string, or an array with exactly one string (RFC 7519 allows arrays; one audience here).
  aud: z.union([nonEmpty, z.tuple([nonEmpty])]),
  client_id: nonEmpty,
  jti: z.string().min(1).max(256).refine(noControls, "control characters"),
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
  // RFC 9493 subject identifier. Never a source of trust (draft §8): informational only.
  sub_id: z.looseObject({ format: nonEmpty }).optional(),
  act: actSchema.optional(),
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

/** A header value, for a refusal's detail: never calls the caller's toString (it may throw). */
function describe(v: unknown): string {
  return typeof v === "string" ? v : typeof v === "number" || typeof v === "boolean" ? `${v}` : `<${v === null ? "null" : typeof v}>`;
}

/** A host's numeric option, checked: NaN or Infinity would silently switch a check off. */
function intOption(name: string, value: number | undefined, fallback: number, min: number, max: number): number {
  if (value === undefined) return fallback;
  if (!Number.isInteger(value) || value < min || value > max) throw new Error(`id-jag: ${name} must be an integer in [${min}, ${max}], got ${value}`);
  return value;
}

export const lifetimeOption = (v: number | undefined) => intOption("maxLifetimeSeconds", v, MAX_LIFETIME_SECONDS, 1, MAX_LIFETIME_SECONDS);
export const skewOption = (v: number | undefined) => intOption("clockSkewSeconds", v, DEFAULT_CLOCK_SKEW_SECONDS, 0, MAX_CLOCK_SKEW_SECONDS);

/**
 * Header and claims, checked for shape and lifetime, **without** verifying the signature. Throws
 * IdJagRefusal with the step that failed.
 */
export function parseIdJag(token: string, o: { maxLifetimeSeconds?: number } = {}): ParsedIdJag {
  const max = lifetimeOption(o.maxLifetimeSeconds);
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
  if (!isIdJagTyp(rawHeader.typ)) refuse("wrong_typ", describe(rawHeader.typ));
  if (typeof rawHeader.alg !== "string" || !(ALLOWED_ALGORITHMS as readonly string[]).includes(rawHeader.alg)) refuse("disallowed_alg", describe(rawHeader.alg));
  if (typeof rawHeader.kid !== "string" || rawHeader.kid.length === 0) refuse("missing_kid");
  // Critical header parameters we don't understand mean "don't accept" (RFC 7515 §4.1.11).
  if (rawHeader.crit !== undefined) refuse("invalid_claim", "crit");

  for (const name of REQUIRED) if (rawClaims[name] === undefined) refuse("missing_claim", name);
  for (const name of UNSUPPORTED_CLAIMS) if (rawClaims[name] !== undefined) refuse("unsupported_claim", name);
  const parsed = idJagClaimsSchema.safeParse(rawClaims);
  if (!parsed.success) refuse("invalid_claim", parsed.error.issues.map((i) => i.path.join(".")).join(","));
  const claims = parsed.data;

  if (claims.exp <= claims.iat) refuse("invalid_claim", "exp <= iat");
  if (actDepth(claims.act) > MAX_ACT_DEPTH) refuse("invalid_claim", "act nested too deep");
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

/** jose errors that mean "this token's signature is not valid with these keys". */
const SIGNATURE_CODES = new Set(["ERR_JWS_SIGNATURE_VERIFICATION_FAILED", "ERR_JWKS_NO_MATCHING_KEY", "ERR_JWS_INVALID", "ERR_JOSE_ALG_NOT_ALLOWED", "ERR_JOSE_NOT_SUPPORTED"]);

async function verifySignature(token: string, key: IdJagKey, algorithms: string[]): Promise<void> {
  try {
    await compactVerify(token, key as CompactVerifyGetKey, { algorithms });
  } catch (error) {
    if (error instanceof IdJagRefusal) throw error;
    // During rotation an issuer may publish two keys with the same kid: jose hands them over.
    if (error instanceof joseErrors.JWKSMultipleMatchingKeys) {
      for await (const candidate of error as unknown as AsyncIterable<CryptoKey>) {
        try {
          await compactVerify(token, candidate, { algorithms });
          return;
        } catch {}
      }
      refuse("bad_signature", "no matching key among several with this kid");
    }
    const code = (error as { code?: string }).code ?? "";
    if (SIGNATURE_CODES.has(code)) refuse("bad_signature", code);
    // Anything else (a JWKS that didn't load, a network error, a timeout) is the issuer's keys
    // being unavailable, not a forged token: the audit log must say so.
    refuse("jwks_unavailable", code || (error as Error).name);
  }
}

/**
 * Parse, check the time claims, then `iss`, signature and `aud`, in that order. `client_id`
 * continuity and `jti` single use need the request and the database, so the receiver checks them
 * after this returns.
 */
export async function verifyIdJag(token: string, key: IdJagKey, expected: VerifyExpectations): Promise<ParsedIdJag> {
  const skew = skewOption(expected.clockSkewSeconds);
  const now = expected.now ?? Math.floor(Date.now() / 1000);
  if (!Number.isInteger(now) || now < 0) throw new Error(`id-jag: now must be a non-negative integer, got ${now}`);
  const parsed = parseIdJag(token, expected.maxLifetimeSeconds === undefined ? {} : { maxLifetimeSeconds: expected.maxLifetimeSeconds });
  // Caller-checkable: before anything that depends on whom we trust (S8).
  checkTimes(parsed.claims, now, skew);
  // Before the signature: no key is fetched for an issuer the caller didn't resolve.
  if (parsed.claims.iss !== expected.issuer) refuse("untrusted_issuer", parsed.claims.iss);
  // Draft §9.3: an IdP must not accept an ID-JAG it issued to itself.
  if (expected.issuer === expected.audience || parsed.claims.iss === parsed.audience) refuse("self_issued", parsed.claims.iss);
  const algorithms = [...(expected.algorithms ?? ALLOWED_ALGORITHMS)];
  // Narrowed to what this trusted issuer publishes: not public, or it would reveal the trust (S8).
  if (!algorithms.includes(parsed.header.alg)) refuse("bad_signature", `alg ${parsed.header.alg} not published by the issuer`);
  await verifySignature(token, key, algorithms);
  if (parsed.audience !== expected.audience) refuse("wrong_audience", parsed.audience);
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
  const max = lifetimeOption(o.maxLifetimeSeconds);
  for (const name of UNSUPPORTED_CLAIMS) if ((claims as Record<string, unknown>)[name] !== undefined) throw new Error(`buildIdJag: ${name} is not supported`);
  const parsed = idJagClaimsSchema.safeParse(claims);
  if (!parsed.success) throw new Error(`buildIdJag: invalid claims (${parsed.error.issues.map((i) => i.path.join(".")).join(",")})`);
  if (claims.exp <= claims.iat || claims.exp - claims.iat > max) throw new Error(`buildIdJag: lifetime must be within (0, ${max}] seconds`);
  // No `undefined` members: they'd be dropped by JSON anyway, and JWT payload types refuse them.
  const payload = Object.fromEntries(Object.entries(parsed.data).filter(([, v]) => v !== undefined));
  return sign(payload, { typ: ID_JAG_TYP });
}
