// The jwt-bearer grant for ID-JAGs (plan §3.4, with the order D-007 settled):
//  1. client authentication (confidential only by default; a CIMD client only with private_key_jwt)
//  2. parse the assertion (typ, alg, kid, required claims, lifetime), then its time claims, then
//     `resource` when requireResourceClaim is on
//  3. trust lookup from the unverified `iss`
//  4. verifyIdJag with that issuer's keys: iss, signature, aud = our issuer (exact)
//  5. client_id continuity: the claim is the authenticated client's id here, exactly
//  6. scopes: ID-JAG ∩ request ∩ client ∩ resource; before the subject, so `no_scope` can't tell
//     whether a user exists (S8)
//  7. resource: from the registered set only
//  8. jti single use (recordJti)
//  9. subject resolution
// 10. issue: access token audience-restricted to the resource; no refresh token, no ID token.
// Every refusal is an IdJagRefusal, audited, then turned into the standard JSON error.
import type { CompactVerifyGetKey } from "jose";
import { getIssuer, type OAuthExtensionGrantHandlerInput, type OAuthTokenResponse } from "@better-auth/oauth-provider";
import { checkTimes, emit, IdJagRefusal, logSafe, providerErrorCode, providerRefusalReason, type ParsedIdJag, parseIdJag, recordJti, refuse, sweepAudit, sweepJtis, toApiError, verifyIdJag } from "../core";
import type { ResolvedReceiverOptions, TrustEntry } from "./options";
import { resolveSubject } from "./resolve";
import { findTrustedIssuer } from "./trust";

/** Scopes never granted through an ID-JAG: no ID token (not an OIDC flow), no refresh token. */
export const STRIPPED_SCOPES = ["openid", "offline_access"] as const;

const DEFAULT_PROVIDER_SCOPES = ["openid", "profile", "email", "offline_access"];

type Opts = OAuthExtensionGrantHandlerInput["opts"];

function stringList(v: unknown): string[] | undefined {
  if (typeof v === "string") return [v];
  if (Array.isArray(v) && v.every((x): x is string => typeof x === "string")) return v;
  if (v === undefined || v === null) return undefined;
  refuse("unsupported_parameter", "resource");
}

const splitScope = (s: string | undefined) => (s ?? "").split(" ").filter(Boolean);

/** The identifiers of the protected resources this provider issues tokens for (mcp() adds its own). */
export function registeredResources(opts: Opts): string[] {
  return (opts.resources ?? []).map((r) => (typeof r === "string" ? r : r.identifier));
}

/** The scopes a resource supports: its own allow-list when configured, else the provider's scopes. */
function resourceScopes(opts: Opts, resource: string | undefined): string[] {
  const configured = opts.resources?.find((r) => typeof r !== "string" && r.identifier === resource);
  if (configured && typeof configured !== "string" && Array.isArray(configured.allowedScopes)) return configured.allowedScopes as string[];
  const advertised = (opts as { advertisedMetadata?: { scopes_supported?: string[] } }).advertisedMetadata?.scopes_supported;
  return (advertised ?? (opts.scopes as string[] | undefined) ?? DEFAULT_PROVIDER_SCOPES) as string[];
}

/** Which resource the token is for, before it is checked against the registered set. */
function chooseResource(claimed: string[] | undefined, requested: string[] | undefined, fallback: string | undefined, registered: string[]): string {
  if (requested && requested.length !== 1) refuse("unknown_resource", "one resource per request");
  const asked = requested?.[0];
  if (claimed) {
    if (asked !== undefined) {
      if (!claimed.includes(asked)) refuse("unknown_resource", "requested resource not in the ID-JAG");
      return asked;
    }
    if (claimed.length !== 1) refuse("unknown_resource", "the ID-JAG names several resources; request one");
    return claimed[0] as string;
  }
  const chosen = asked ?? fallback ?? (registered.length === 1 ? registered[0] : undefined);
  if (chosen === undefined) refuse("unknown_resource", "no resource");
  return chosen;
}

function maybeSweep(input: OAuthExtensionGrantHandlerInput, o: ResolvedReceiverOptions): void {
  const now = o.clock().getTime();
  if (now - o.sweep.lastAt < o.sweep.intervalMs) return;
  o.sweep.lastAt = now;
  const { adapter, logger } = input.ctx.context;
  const run = async () => {
    try {
      await sweepJtis(adapter, new Date(now));
      if (o.audit.auditLog) await sweepAudit(adapter, new Date(now));
    } catch (e) {
      logger.warn("[id-jag] sweep of expired rows failed", e);
    }
  };
  input.ctx.context.runInBackground(run());
}

interface Progress {
  authenticated: boolean;
  clientId?: string | undefined;
  parsed?: ParsedIdJag | undefined;
  userId?: string | undefined;
}

/**
 * The grant handler as a plain function, for hosts (or a future core) that compose grants
 * themselves. `idJagGrant()` registers exactly this under the jwt-bearer grant type.
 */
/** The client_id the caller named (form body or Basic auth), before authentication: audit only. */
function claimedClientId(ctx: { body?: unknown; request?: Request | undefined; headers?: Headers | undefined }): string | undefined {
  const fromBody = (ctx.body as Record<string, unknown> | undefined)?.client_id;
  if (typeof fromBody === "string") return fromBody;
  const auth = (ctx.request?.headers ?? ctx.headers)?.get("authorization");
  if (auth?.toLowerCase().startsWith("basic ")) {
    try {
      return decodeURIComponent(atob(auth.slice(6).trim()).split(":")[0] ?? "");
    } catch {
      return undefined;
    }
  }
  return undefined;
}

export async function handleIdJagGrant(input: OAuthExtensionGrantHandlerInput, o: ResolvedReceiverOptions): Promise<OAuthTokenResponse> {
  const { ctx, opts, provider } = input;
  maybeSweep(input, o);
  const audience = getIssuer(ctx, opts);
  const progress: Progress = { authenticated: false };
  try {
    // 1. Client authentication. The provider throws its own invalid_client / unauthorized_client.
    const authn = await provider.authenticateClient({ requireCredentials: !o.allowPublicClients });
    progress.clientId = authn.clientId;
    const isPublic = authn.method === "none" || authn.method === undefined || authn.client.tokenEndpointAuthMethod === "none";
    if (!o.allowPublicClients && isPublic) refuse("public_client", authn.clientId);
    // A CIMD (discovered) client is confidential only when it proved a key (private_key_jwt).
    if (!o.allowPublicClients && authn.client.clientDiscoveryId && authn.method !== "private_key_jwt") refuse("public_client", `discovered client using ${authn.method}`);
    progress.authenticated = true;

    // 2. Parse, then the time claims: both caller-checkable, so before anything trust-dependent (S8).
    const body = (ctx.body ?? {}) as Record<string, unknown>;
    const assertion = body.assertion;
    if (typeof assertion !== "string" || assertion.length === 0) refuse("missing_parameter", "assertion");
    const parsed = parseIdJag(assertion, { maxLifetimeSeconds: o.maxLifetimeSeconds });
    progress.parsed = parsed;
    const now = Math.floor(o.clock().getTime() / 1000);
    checkTimes(parsed.claims, now, o.clockSkewSeconds);
    // With requireResourceClaim, a missing `resource` is a defect of the token the caller sent: public,
    // and checked here, before trust, so the answer is the same whether the issuer is trusted (D-A21).
    if (o.requireResourceClaim && parsed.claims.resource === undefined) refuse("missing_claim", "resource");

    // 3. Trust, from the unverified iss.
    const trust: TrustEntry = await findTrustedIssuer(ctx, o, parsed.claims);

    // 4. iss (and not self-issued), signature with the trusted issuer's keys, then aud (exact).
    // The keys are fetched lazily, when the signature is checked, so nothing is fetched for a
    // token verifyIdJag refuses earlier (a self-issued one).
    const key: CompactVerifyGetKey = async (header, token) => {
      const keys = await o.jwks.keysFor(trust, parsed.header.kid, (e) =>
        ctx.context.logger.warn(`[id-jag] JWKS refetch for ${logSafe(trust.issuer)} failed; using its cached keys (within jwks.maxStaleSeconds): ${logSafe(e instanceof IdJagRefusal ? (e.detail ?? e.reason) : String(e))}`),
      );
      // Narrowed to what this issuer publishes; not public, or it would reveal the trust (S8).
      if (keys.algorithms && !(keys.algorithms as string[]).includes(header.alg)) refuse("bad_signature", `alg ${header.alg} not published by the issuer`);
      return keys.key(header, token);
    };
    const verified = await verifyIdJag(assertion, key, { issuer: trust.issuer, audience, now, clockSkewSeconds: o.clockSkewSeconds, maxLifetimeSeconds: o.maxLifetimeSeconds });
    const claims = verified.claims;

    // 5. client_id continuity (D-004: the client's id at this server).
    if (claims.client_id !== authn.clientId) refuse("client_mismatch", `claim ${claims.client_id}`);
    if (trust.allowedClientIds && !trust.allowedClientIds.includes(authn.clientId)) refuse("client_mismatch", "client not allowed for this issuer");

    // 6. Scopes, which only narrow (S7).
    const registered = registeredResources(opts);
    const resource = chooseResource(stringList(claims.resource), stringList(body.resource), o.defaultResource, registered);
    const requestScope = typeof body.scope === "string" ? new Set(splitScope(body.scope)) : null;
    const clientScopes = authn.client.scopes ? new Set<string>(authn.client.scopes) : null;
    const supported = new Set(resourceScopes(opts, resource));
    const scopes = [...new Set(splitScope(claims.scope))].filter(
      (s) => !(STRIPPED_SCOPES as readonly string[]).includes(s) && (requestScope === null || requestScope.has(s)) && (clientScopes === null || clientScopes.has(s)) && supported.has(s),
    );
    if (scopes.length === 0 && !o.allowEmptyScope) refuse("no_scope", claims.scope ?? "(none)");

    // 7. Resource, from the registered set only.
    if (!registered.includes(resource)) refuse("unknown_resource", resource);

    // 8. Single use (S3). The row's expiry is computed from exp + skew by the core.
    const first = await recordJti(ctx.context.adapter, { side: "accepted", jti: claims.jti, iss: claims.iss, aud: audience, sub: claims.sub, clientId: authn.clientId, exp: claims.exp, clockSkewSeconds: o.clockSkewSeconds });
    if (!first) refuse("replay", claims.jti);

    // 9. Subject.
    const { user, via } = await resolveSubject(ctx, o, trust, claims, authn.clientId);
    progress.userId = user.id;

    // 10. Issue: audience = the resource; no refresh token (offline_access stripped), no ID token.
    const response = await provider.issueTokens({
      client: authn.client,
      user,
      scopes,
      resources: [resource],
      // `act` (who acts for the user, e.g. an AI agent) goes into the access token as RFC 8693 says.
      accessTokenClaims: { idjag: { iss: claims.iss, jti: claims.jti, ...(claims.tenant ? { tenant: claims.tenant } : {}) }, ...(claims.act ? { act: claims.act } : {}) },
      ...(claims.auth_time !== undefined ? { authTime: new Date(claims.auth_time * 1000) } : {}),
      tokenResponse: {},
    });
    emit(ctx, o.audit, {
      type: "id-jag.accepted",
      iss: claims.iss,
      sub: claims.sub,
      userId: user.id,
      clientId: authn.clientId,
      resource,
      scopes,
      jti: claims.jti,
      organizationId: trust.organizationId,
      resolvedBy: via,
    });
    return response;
  } catch (error) {
    if (!(error instanceof IdJagRefusal)) {
      // The provider's own refusals (a wrong secret, a client not registered for the grant, a
      // client not linked to the resource): audited, then passed on unchanged.
      const reason = providerRefusalReason(error);
      if (reason)
        emit(ctx, o.audit, {
          type: "id-jag.refused",
          side: "receiver",
          reason,
          authenticated: progress.authenticated,
          clientId: progress.clientId ?? claimedClientId(ctx),
          userId: progress.userId,
          iss: progress.parsed?.claims.iss,
          audience: progress.parsed?.audience,
          jti: progress.parsed?.claims.jti,
          detail: providerErrorCode(error),
        });
      throw error;
    }
    emit(ctx, o.audit, {
      type: "id-jag.refused",
      side: "receiver",
      reason: error.reason,
      authenticated: progress.authenticated,
      clientId: progress.clientId,
      userId: progress.userId,
      iss: progress.parsed?.claims.iss,
      audience: progress.parsed?.audience,
      jti: progress.parsed?.claims.jti,
      detail: error.detail,
    });
    throw toApiError(error);
  }
}
