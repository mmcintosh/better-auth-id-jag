// Subject token v1: an ID token **this IdP** issued (S6). Verified with this host's own jwt-plugin
// keys, read from its database (or the jwt plugin's own key adapter): no outbound request at all
// (S10). The checks, in order, caller-checkable ones first (as the core does, D-007):
//   shape, typ, alg, kid, exp, iat  →  iss  →  signature by one of our keys  →  aud/azp  →  sub.
// An ID token from any other issuer is refused, even one this host trusts elsewhere.
//
// What oauth-provider 1.7.6 puts in an ID token (dist, createIdToken): `iss` = jwt.issuer ??
// baseURL, `aud` = the client id (a string), `sub` = the user id, or a pairwise value for a
// pairwise client (refused here: it can't be resolved to a user without the user), `auth_time`,
// `acr` ("0" unless a host claim overrides it), no `typ` header.
import type { GenericEndpointContext } from "better-auth";
import type { Jwk, JwtOptions } from "better-auth/plugins";
import { compactVerify, decodeJwt, decodeProtectedHeader, importJWK } from "jose";
import { z } from "zod";
import { IdJagRefusal, MAX_TOKEN_LENGTH, refuse } from "../../core";

/** Asymmetric algorithms the jwt plugin can sign with. No HS*, no `none`. */
const ASYMMETRIC = new Set(["EdDSA", "Ed25519", "ES256", "ES384", "ES512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512"]);
/** How far in the future `iat` may be (clocks differ a little between instances). */
const IAT_SKEW_SECONDS = 60;
const DEFAULT_GRACE_SECONDS = 30 * 86_400;

const str = z.string().min(1).max(2048);
const seconds = z.number().int().nonnegative();
const idTokenClaimsSchema = z.looseObject({
  iss: str,
  sub: str,
  aud: z.union([str, z.array(str).min(1).max(32)]),
  exp: seconds,
  iat: seconds.optional(),
  azp: str.optional(),
  auth_time: seconds.optional(),
  acr: str.optional(),
  amr: z.array(str).max(32).optional(),
});
export type IdTokenClaims = z.infer<typeof idTokenClaimsSchema>;

export interface IdTokenExpectations {
  /** Our issuer identifier: what oauth-provider puts in `iss`. */
  issuer: string;
  /** The authenticated client: it must be an audience of the token. */
  clientId: string;
  jwtOptions: JwtOptions | undefined;
  /** Seconds since the epoch. */
  now: number;
}

const bad = (detail: string): never => refuse("invalid_subject_token", detail);

/** The keys the jwt plugin would publish at its JWKS route (expired ones within the grace period). */
async function ourKeys(ctx: GenericEndpointContext, o: JwtOptions | undefined, now: number): Promise<Jwk[]> {
  const keys = o?.adapter?.getJwks ? await o.adapter.getJwks(ctx) : await ctx.context.adapter.findMany<Jwk>({ model: "jwks" });
  const grace = (o?.jwks?.gracePeriod ?? DEFAULT_GRACE_SECONDS) * 1000;
  return (keys ?? []).filter((k) => !k.expiresAt || new Date(k.expiresAt).getTime() + grace > now * 1000);
}

/**
 * Verifies an ID token this IdP issued to `clientId`. Throws IdJagRefusal: `invalid_subject_token`
 * (with the step in the detail, for the audit log), or `expired`.
 */
export async function verifyOwnIdToken(ctx: GenericEndpointContext, token: string, expected: IdTokenExpectations): Promise<IdTokenClaims> {
  if (token.length > MAX_TOKEN_LENGTH) bad("length");
  let header: Record<string, unknown>;
  let raw: unknown;
  try {
    header = decodeProtectedHeader(token) as Record<string, unknown>;
    raw = decodeJwt(token);
  } catch {
    return bad("not a JWS-compact JWT");
  }
  // An ID token has no typ, or "JWT". An access token (at+jwt), an ID-JAG, a logout token is not one.
  if (header.typ !== undefined && (typeof header.typ !== "string" || header.typ.toLowerCase() !== "jwt")) bad("typ");
  if (typeof header.alg !== "string" || !ASYMMETRIC.has(header.alg)) bad("alg");
  if (typeof header.kid !== "string" || header.kid.length === 0) bad("no kid");
  if (header.crit !== undefined) bad("crit");
  const parsed = idTokenClaimsSchema.safeParse(raw);
  if (!parsed.success) return bad(`claims: ${parsed.error.issues.map((i) => i.path.join(".")).join(",")}`);
  const claims = parsed.data;
  // Expired is expired: no grace (plan §3.3 step 3).
  if (claims.exp <= expected.now) refuse("subject_token_expired");
  if (claims.iat !== undefined && claims.iat - IAT_SKEW_SECONDS > expected.now) bad("iat in the future");
  // S6: ours, and only ours. Before any key is looked up.
  if (claims.iss !== expected.issuer) bad("issuer");

  const key = (await ourKeys(ctx, expected.jwtOptions, expected.now)).find((k) => k.id === header.kid);
  if (!key) return bad("unknown kid");
  const alg = key.alg ?? expected.jwtOptions?.jwks?.keyPairConfig?.alg ?? "EdDSA";
  if (alg !== header.alg) bad("alg differs from the key's");
  try {
    const publicKey = await importJWK(JSON.parse(key.publicKey) as Record<string, unknown>, alg);
    await compactVerify(token, publicKey, { algorithms: [alg] });
  } catch (e) {
    if (e instanceof IdJagRefusal) throw e;
    return bad("signature");
  }

  // OIDC Core §3.1.3.7: the client is an audience; with several, azp names it.
  const aud = typeof claims.aud === "string" ? [claims.aud] : claims.aud;
  if (!aud.includes(expected.clientId)) bad("audience is not the authenticated client");
  if (aud.length > 1 && claims.azp !== expected.clientId) bad("azp");
  if (claims.azp !== undefined && claims.azp !== expected.clientId) bad("azp");
  return claims;
}
