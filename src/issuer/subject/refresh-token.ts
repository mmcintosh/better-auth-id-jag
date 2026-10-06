// Subject token: a refresh token **this provider** issued to the authenticated client (draft -04
// §4.3: "a Refresh Token previously issued by the IdP Authorization Server for that resource
// owner"; the MCP extension's SAML path and conformance tools exchange one). D-B14.
//
// Looked up exactly as oauth-provider 1.7.6 looks it up at its refresh_token grant (dist,
// introspect: decodeRefreshToken, getStoredToken): strip `prefix.refreshToken` (refused when the
// host configured one and it's missing), `formatRefreshToken.decrypt` when configured, then the
// provider's own hash (`provider.hashToken(token, "refresh_token")`) against
// `oauthRefreshToken.token`. Nothing is written: the row isn't rotated, consumed or extended, so
// the client keeps using the token at the token endpoint as before.
//
// In order: found (the stored hash matches exactly), issued to the authenticated client (S6 for
// refresh tokens), not revoked (`revoked` is also set by rotation, so a rotated-out token is
// refused even inside the provider's reuse interval), not sender-constrained (no `confirmation`:
// we can't check a DPoP proof yet), granted `openid` (an ID-JAG is an identity assertion; the ID
// token path implies openid too), then expiry. Unknown, another client's, revoked, rotated,
// sender-constrained and openid-less tokens are all `invalid_subject_token` (not public), so a
// caller can't tell them apart. `subject_token_expired` (public) comes only after the client and
// revocation checks: it can only tell the client a fact about its own live-until-now token. D-B15.
import type { GenericEndpointContext } from "better-auth";
import type { OAuthOptions, OAuthProviderApi, Scope } from "@better-auth/oauth-provider";
import { MAX_TOKEN_LENGTH, refuse } from "../../core";

/** The subject token type for a refresh token (RFC 8693 §3). Not in the core's URNs yet: a core change request. */
export { REFRESH_TOKEN_TOKEN_TYPE } from "../../core";

export const REFRESH_TOKEN_MODEL = "oauthRefreshToken";

/** What a verified refresh token tells the exchange. */
export interface RefreshTokenSubject {
  /** The user the token was issued for (the provider stores the user id, never a pairwise value). */
  userId: string;
  /** The token's scopes at this IdP (openid, offline_access, …): not the ID-JAG's scopes. */
  scopes: string[];
  /** When the user authenticated, when the provider stored it (seconds). */
  authTime?: number | undefined;
  /** Seconds. */
  issuedAt: number;
  /** Seconds. */
  expiresAt: number;
  /** The provider's session reference, when it kept one. */
  sessionId?: string | undefined;
}

export interface RefreshTokenExpectations {
  /** The authenticated client: the token must have been issued to it. */
  clientId: string;
  /** Seconds since the epoch. */
  now: number;
  /** The provider's options (prefix, formatRefreshToken). */
  opts: Pick<OAuthOptions<Scope[]>, "prefix" | "formatRefreshToken">;
  /** The provider's own token hash. */
  hashToken: OAuthProviderApi["hashToken"];
}

const bad = (detail: string): never => refuse("invalid_subject_token", detail);

const seconds = (v: unknown): number | undefined => {
  if (v === null || v === undefined) return undefined;
  const t = v instanceof Date ? v.getTime() : new Date(v as string | number).getTime();
  return Number.isNaN(t) ? undefined : Math.floor(t / 1000);
};

/** The provider stores `string[]` columns as JSON text on SQL, as arrays elsewhere. */
function stringArray(v: unknown): string[] | undefined {
  let x = v;
  if (typeof x === "string") {
    try {
      x = JSON.parse(x);
    } catch {
      return undefined;
    }
  }
  return Array.isArray(x) && x.every((s) => typeof s === "string") ? (x as string[]) : undefined;
}

/** The stored value the provider hashes: its prefix stripped and its format decoded, as its refresh grant does. */
async function storedValueOf(token: string, opts: RefreshTokenExpectations["opts"]): Promise<string> {
  let value = token;
  const prefix = opts.prefix?.refreshToken;
  if (prefix) {
    if (!value.startsWith(prefix)) return bad("refresh token: prefix missing");
    value = value.slice(prefix.length);
  }
  if (opts.formatRefreshToken?.decrypt) {
    try {
      const decoded = (await opts.formatRefreshToken.decrypt(value)) as { token?: unknown } | undefined;
      if (typeof decoded?.token !== "string" || decoded.token.length === 0) return bad("refresh token: format");
      value = decoded.token;
    } catch {
      return bad("refresh token: format");
    }
  }
  if (value.length === 0) bad("refresh token: empty");
  return value;
}

/**
 * Verifies a refresh token this provider issued to `clientId`, without changing it. Throws
 * IdJagRefusal: `invalid_subject_token` (the step in the detail, for the audit log), or
 * `subject_token_expired`.
 */
export async function verifyOwnRefreshToken(ctx: GenericEndpointContext, token: string, expected: RefreshTokenExpectations): Promise<RefreshTokenSubject> {
  if (token.length > MAX_TOKEN_LENGTH) bad("length");
  const value = await storedValueOf(token, expected.opts);
  const hash = await expected.hashToken(value, "refresh_token");
  const row = await ctx.context.adapter.findOne<Record<string, unknown>>({ model: REFRESH_TOKEN_MODEL, where: [{ field: "token", value: hash }] });
  // Exact match, whatever the collation.
  if (!row || row.token !== hash) return bad("refresh token: unknown");
  if (row.clientId !== expected.clientId) bad("refresh token: issued to another client");
  if (row.revoked !== null && row.revoked !== undefined) bad(row.rotatedAt ? "refresh token: rotated" : "refresh token: revoked");
  if (row.confirmation !== null && row.confirmation !== undefined && row.confirmation !== "") bad("refresh token: sender-constrained");
  const scopes = stringArray(row.scopes);
  if (!scopes) return bad("refresh token: scopes unreadable");
  if (!scopes.includes("openid")) bad("refresh token: not granted openid");
  const expiresAt = seconds(row.expiresAt);
  if (expiresAt === undefined) return bad("refresh token: no expiry");
  // Expired is expired: no grace, as for ID tokens.
  if (expiresAt <= expected.now) refuse("subject_token_expired", "refresh token");
  if (typeof row.userId !== "string" || row.userId.length === 0) return bad("refresh token: no user");
  const authTime = seconds(row.authTime);
  return {
    userId: row.userId,
    scopes,
    ...(authTime !== undefined ? { authTime } : {}),
    issuedAt: seconds(row.createdAt) ?? expected.now,
    expiresAt,
    ...(typeof row.sessionId === "string" ? { sessionId: row.sessionId } : {}),
  };
}
