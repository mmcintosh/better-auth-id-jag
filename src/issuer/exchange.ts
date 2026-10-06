// The token-exchange grant (RFC 8693) that issues ID-JAGs (draft -04 §4.3), plan §3.3:
//   1. client  2. parameters  3. subject token  4. policy  5. mint  6. record, audit, respond.
// With `saml.refreshTokens`, one more exact pair: requested_token_type=refresh_token for
// subject_token_type=saml2 issues a refresh token instead (draft -04 §4.5,
// issueRefreshTokenForAssertion, D-B27). Every other requested type is refused.
// Exported as a plain function too (`handleTokenExchange`), so a host, or a future core grant
// that owns the token-exchange key, can compose it: two extensions can't share a grant key
// (docs/phase-0.md).
//
// Every refusal is an IdJagRefusal, audited, then thrown as the APIError the token endpoint turns
// into an RFC 6749 §5.2 body (a plain Error would be an empty 500). Errors the provider throws
// itself during client authentication (a wrong secret, a client not registered for this grant)
// are passed through as the provider shaped them.
import type { GenericEndpointContext, User } from "better-auth";
import { isAPIError } from "better-auth/api";
import type { JwtOptions } from "better-auth/plugins";
import { signJWT } from "better-auth/plugins";
import { getIssuer, type OAuthExtensionGrantHandlerInput, type OAuthTokenResponse } from "@better-auth/oauth-provider";
import {
  buildIdJag,
  emit,
  ID_JAG_TOKEN_TYPE,
  ID_TOKEN_TOKEN_TYPE,
  SAML2_TOKEN_TYPE,
  type IdJagClaims,
  IdJagRefusal,
  type IdJagSigner,
  newJti,
  providerErrorCode,
  providerRefusalReason,
  recordJti,
  refuse,
  sweepAudit,
  sweepJtis,
  toApiError,
} from "../core";
import type { RegistryDirectory } from "./directory";
import type { PolicyClient, ResolvedIssuerOptions, SubjectTokenClaims } from "./options";
import { decide } from "./policy";
import { checkBlocksWithoutAudience, sweepBlocks } from "./blocks";
import { verifyOwnIdToken } from "./subject/id-token";
import { REFRESH_TOKEN_TOKEN_TYPE, refreshTokenRow, storedSeconds, verifyOwnRefreshToken } from "./subject/refresh-token";
import { verifyOwnSamlAssertion } from "./subject/saml2";

/** The provider's opaque access-token table. */
const ACCESS_TOKEN_MODEL = "oauthAccessToken";
import { normalizeAudience } from "./url";

/** What the plugin keeps per instance: resolved options, the registry directory, the sweep clock. */
export interface IssuerState {
  options: ResolvedIssuerOptions;
  directory: RegistryDirectory | undefined;
  lastSweep: number;
}

const MAX_SCOPE_LENGTH = 4096;
/** Parameters that may appear at most once (RFC 6749 §3.2). `resource` may repeat (RFC 8707) but we take one. */
const SINGLE = ["requested_token_type", "subject_token", "subject_token_type", "audience", "scope", "actor_token", "actor_token_type"] as const;

type Form = Map<string, string[]>;

/** The request's parameters, with repeats kept (the provider's body schema keeps the last one). */
async function readForm(ctx: GenericEndpointContext): Promise<Form> {
  const form: Form = new Map();
  const request = ctx.request;
  if (request && (request.headers.get("content-type") ?? "").toLowerCase().includes("application/x-www-form-urlencoded")) {
    let text = "";
    try {
      text = await request.clone().text();
    } catch {}
    const params = new URLSearchParams(text);
    for (const key of new Set(params.keys())) form.set(key, params.getAll(key));
    if (form.size > 0) return form;
  }
  // A server-side call (auth.api) has a parsed body and no request.
  for (const [key, value] of Object.entries((ctx.body ?? {}) as Record<string, unknown>)) {
    if (typeof value === "string") form.set(key, [value]);
    else if (Array.isArray(value)) form.set(key, value.filter((v): v is string => typeof v === "string"));
  }
  return form;
}

function hasClientCredentials(ctx: GenericEndpointContext, form: Form): boolean {
  const authorization = ctx.request?.headers.get("authorization") ?? (ctx.headers?.get("authorization") || undefined);
  return !!authorization || form.has("client_secret") || form.has("client_assertion");
}

const isBanned = (user: Record<string, unknown>, now: Date) => {
  const banned = user.banned === true || user.banned === 1 || user.banned === "1" || user.banned === "true";
  if (!banned) return false;
  const exp = user.banExpires;
  if (exp === null || exp === undefined) return true;
  const t = exp instanceof Date ? exp.getTime() : new Date(exp as string | number).getTime();
  return Number.isNaN(t) || t > now.getTime();
};

/** The jwt plugin's options (the host is checked at startup to have the plugin). */
export function jwtOptionsOf(ctx: { getPlugin(id: string): unknown }): JwtOptions | undefined {
  return (ctx.getPlugin("jwt") as { options?: JwtOptions } | null)?.options;
}

/** Our issuer identifier, as oauth-provider puts it in ID tokens and access tokens. */
/**
 * The ID-JAG's `iss`: exactly the issuer identifier the provider publishes in its RFC 8414
 * metadata, from the provider's own getIssuer (D-012). Not a copy of its logic, which could
 * drift: Authelia shipped `iss` = its access-token issuer and had to fix it (authelia/oauth2-provider#834).
 */
export const issuerOf = (ctx: GenericEndpointContext) => {
  const provider = (ctx.context as unknown as { getPlugin(id: string): { options: Parameters<typeof getIssuer>[1] } | null }).getPlugin("oauth-provider");
  if (!provider) throw new Error("id-jag: idJagIssuer requires oauthProvider()");
  return getIssuer(ctx, provider.options);
};

function maybeSweep(ctx: GenericEndpointContext, state: IssuerState): void {
  const interval = state.options.sweepIntervalSeconds * 1000;
  const now = Date.now();
  if (interval === 0 || now - state.lastSweep < interval) return;
  state.lastSweep = now;
  const adapter = ctx.context.adapter;
  ctx.context.runInBackground(
    (async () => {
      try {
        await sweepJtis(adapter);
        await sweepBlocks(ctx);
        if (state.options.auditLog) await sweepAudit(adapter);
      } catch (e) {
        ctx.context.logger.error("[id-jag] sweep failed", e);
      }
    })(),
  );
}

/** The token-exchange grant handler. Returns the RFC 8693 response; throws APIError on refusal. */
export async function handleTokenExchange(input: OAuthExtensionGrantHandlerInput, state: IssuerState): Promise<OAuthTokenResponse> {
  const { ctx, opts, provider } = input;
  const options = state.options;
  // What the refusal event can say, filled in as the steps pass.
  const seen: { authenticated: boolean; clientId?: string; userId?: string; audience?: string } = { authenticated: false };
  const form = await readForm(ctx);
  try {
    // 1. Client. Confidential only unless the host opted in (S5); the provider also checks the
    //    client is registered for this grant type (unauthorized_client).
    const claimed = form.get("client_id")?.[0];
    if (claimed !== undefined) seen.clientId = claimed;
    let authenticated: Awaited<ReturnType<typeof provider.authenticateClient>>;
    try {
      authenticated = await provider.authenticateClient({ requireCredentials: !options.allowPublicClients });
    } catch (e) {
      if (isAPIError(e) && (e.body as { error?: string } | undefined)?.error === "invalid_client" && !hasClientCredentials(ctx, form) && claimed !== undefined)
        throw new IdJagRefusal("public_client", "no client credentials");
      throw e;
    }
    const client = authenticated.client;
    if (!options.allowPublicClients && client.tokenEndpointAuthMethod === "none") refuse("public_client", "public client");
    seen.authenticated = true;
    seen.clientId = client.clientId;

    // 2. Parameters.
    for (const name of SINGLE) if ((form.get(name)?.length ?? 0) > 1) refuse(name === "audience" ? "invalid_audience" : "unsupported_parameter", `repeated ${name}`);
    const one = (name: string) => form.get(name)?.[0];
    const requestedTokenType = one("requested_token_type");
    // An ID-JAG always; a refresh token only for a SAML assertion, with saml.refreshTokens (D-B27).
    const wantsRefreshToken = requestedTokenType === REFRESH_TOKEN_TOKEN_TYPE && options.samlRefreshScopes !== undefined;
    if (requestedTokenType !== ID_JAG_TOKEN_TYPE && !wantsRefreshToken) refuse("unsupported_requested_token_type", requestedTokenType ?? "absent");
    if (one("actor_token") !== undefined || one("actor_token_type") !== undefined) refuse("actor_token_unsupported");
    const subjectToken = one("subject_token");
    if (!subjectToken) refuse("missing_parameter", "subject_token");
    const subjectTokenType = one("subject_token_type");
    if (!subjectTokenType) refuse("missing_parameter", "subject_token_type");
    if (wantsRefreshToken) {
      if (subjectTokenType !== SAML2_TOKEN_TYPE) refuse("unsupported_subject_token_type", `${subjectTokenType} for a refresh token`);
      return await issueRefreshTokenForAssertion(input, state, { client, form, subjectToken, seen });
    }
    const subjectTypeAccepted = subjectTokenType === ID_TOKEN_TOKEN_TYPE || subjectTokenType === REFRESH_TOKEN_TOKEN_TYPE || (subjectTokenType === SAML2_TOKEN_TYPE && options.samlSubjectTokens);
    if (!subjectTypeAccepted) refuse("unsupported_subject_token_type", subjectTokenType);
    const rawAudience = one("audience");
    if (!rawAudience) refuse("missing_parameter", "audience");
    const normalized = normalizeAudience(rawAudience, { allowLoopbackHttp: options.allowLoopbackHttpAudiences });
    if (!normalized.ok) return refuse("invalid_audience", normalized.why);
    const audience = normalized.audience;
    seen.audience = audience;
    const issuer = issuerOf(ctx);
    if (audience === issuer) refuse("invalid_audience", "our own issuer");
    const resources = form.get("resource") ?? [];
    if (resources.length > 1) refuse("unsupported_parameter", "more than one resource");
    const resource = resources[0];
    const scopeParam = one("scope") ?? "";
    if (scopeParam.length > MAX_SCOPE_LENGTH) refuse("unsupported_parameter", "scope too long");
    const requestedScopes = [...new Set(scopeParam.split(" ").filter(Boolean))];

    // 3. Subject token: an ID token or a refresh token this IdP issued to this client (S6).
    const jwtOptions = jwtOptionsOf(ctx.context as unknown as { getPlugin(id: string): unknown });
    // A pairwise client's ID tokens carry a per-client hash, not the user id: refused, not guessed.
    // Its refresh tokens too: the ID-JAG's sub is the user id, which the client could read (D-B14).
    if (client.subjectType === "pairwise" && opts.pairwiseSecret) refuse("invalid_subject_token", "pairwise subject (not supported in v1)");
    const at = new Date();
    const now = Math.floor(at.getTime() / 1000);
    // Our ID tokens carry the provider's raw issuer (jwt.issuer ?? baseURL), which getIssuer may
    // normalise (https, no trailing slash): check them against what the provider actually signs.
    const idTokenIssuer = jwtOptions?.jwt?.issuer ?? ctx.context.baseURL;
    const subject = await verifySubject(input, subjectTokenType, subjectToken, { issuer: idTokenIssuer, clientId: client.clientId, jwtOptions, now, at, maxAgeSeconds: options.maxIdTokenAgeSeconds });
    const user = (await ctx.context.internalAdapter.findUserById(subject.sub)) as (User & Record<string, unknown>) | null;
    if (!user || user.id !== subject.sub) return refuse("unknown_subject");
    seen.userId = user.id;
    if (isBanned(user, new Date(now * 1000))) refuse("banned_user");

    // 4. Policy.
    const policyClient: PolicyClient = {
      clientId: client.clientId,
      name: client.name ?? undefined,
      referenceId: client.referenceId ?? undefined,
      metadata: typeof client.metadata === "string" ? safeJson(client.metadata) : (client.metadata as Record<string, unknown> | undefined),
    };
    const grant = await decide(options, state.directory, { ctx, user, client: policyClient, audience, resource, requestedScopes, subjectToken: subject });

    // 5. Mint. buildIdJag checks the claims against the receiver's schema and the 900 s cap (S7).
    const jti = newJti();
    const exp = now + grant.lifetimeSeconds;
    const email = grant.includeEmail && user.emailVerified === true && typeof user.email === "string" ? user.email : undefined;
    const claims: IdJagClaims = {
      iss: issuer,
      sub: user.id,
      aud: audience,
      client_id: grant.clientIdAtResource,
      jti,
      iat: now,
      exp,
      ...(grant.resource !== undefined ? { resource: grant.resource } : {}),
      ...(grant.scopes.length > 0 ? { scope: grant.scopes.join(" ") } : {}),
      ...(subject.auth_time !== undefined ? { auth_time: subject.auth_time } : {}),
      ...(subject.acr !== undefined ? { acr: subject.acr } : {}),
      ...(subject.amr !== undefined ? { amr: subject.amr } : {}),
      ...(email !== undefined ? { email } : {}),
      ...(grant.tenant !== undefined ? { tenant: grant.tenant } : {}),
    };
    const signer: IdJagSigner = (payload, header) => signJWT(ctx, { options: jwtOptions, header, payload, ...(options.signingAlgorithm ? { signingAlgorithm: options.signingAlgorithm } : {}) });
    const token = await buildIdJag(claims, signer);

    // 6. Record (audit, and the block-from-this-jti admin action), audit, respond.
    if (!(await recordJti(ctx.context.adapter, { side: "issued", jti, iss: issuer, aud: audience, sub: user.id, clientId: client.clientId, exp, clockSkewSeconds: 0 }))) throw new Error("id-jag: jti collision");
    emit(ctx, options, {
      type: "id-jag.issued",
      userId: user.id,
      clientId: client.clientId,
      clientIdAtResource: grant.clientIdAtResource,
      audience,
      resource: grant.resource,
      scopes: grant.scopes,
      jti,
      expiresAt: new Date(exp * 1000),
      organizationId: grant.tenant,
    });
    maybeSweep(ctx, state);
    // RFC 8693 §2.2.1. Cache-Control: no-store comes from the token endpoint (metadata.noStore).
    const response = {
      issued_token_type: ID_JAG_TOKEN_TYPE,
      access_token: token,
      token_type: "N_A",
      ...(grant.scopes.length > 0 ? { scope: grant.scopes.join(" ") } : {}),
      expires_in: grant.lifetimeSeconds,
    };
    return response as unknown as OAuthTokenResponse;
  } catch (e) {
    if (!(e instanceof IdJagRefusal)) {
      // The provider's own refusals: audited, then passed on unchanged.
      const reason = providerRefusalReason(e);
      if (reason)
        emit(ctx, options, {
          type: "id-jag.refused",
          side: "issuer",
          reason,
          authenticated: seen.authenticated,
          clientId: seen.clientId,
          userId: seen.userId,
          audience: seen.audience,
          detail: providerErrorCode(e),
        });
      throw e;
    }
    emit(ctx, options, {
      type: "id-jag.refused",
      side: "issuer",
      reason: e.reason,
      authenticated: seen.authenticated,
      clientId: seen.clientId,
      userId: seen.userId,
      audience: seen.audience,
      detail: e.detail,
    });
    throw toApiError(e);
  }
}

type AuthenticatedClient = Awaited<ReturnType<OAuthExtensionGrantHandlerInput["provider"]["authenticateClient"]>>["client"];
type Seen = { authenticated: boolean; clientId?: string; userId?: string; audience?: string };

/** What issueTokens returned: the body itself, or (when the endpoint runs asResponse) better-call's json wrapper. */
function tokenBody(r: unknown): Record<string, unknown> {
  const x = r as { _flag?: unknown; body?: unknown } | null | undefined;
  const body = x && x._flag === "json" && x.body && typeof x.body === "object" ? x.body : x;
  return body && typeof body === "object" ? (body as Record<string, unknown>) : {};
}

/**
 * Path (b), D-B27: a SAML assertion this IdP issued, exchanged for a refresh token (draft -04
 * §4.5: `requested_token_type=refresh_token`, `subject_token_type=saml2`). In order: the client
 * (confidential, allowed `refresh_token`, not pairwise); no `audience` or `resource` (the token is
 * for us); scopes (openid and offline_access, within the configured list, the client's and the
 * provider's); the assertion (verified and consumed by the SAML IdP); the user re-read (exists, not
 * banned); blocks without an audience; then the provider mints. No policy source runs: the
 * refresh token is only for this IdP, and the policy decides when it's exchanged for an ID-JAG.
 */
async function issueRefreshTokenForAssertion(
  input: OAuthExtensionGrantHandlerInput,
  state: IssuerState,
  r: { client: AuthenticatedClient; form: Form; subjectToken: string; seen: Seen },
): Promise<OAuthTokenResponse> {
  const { ctx, opts, provider } = input;
  const { client, form, seen } = r;
  const options = state.options;
  const allowedScopes = options.samlRefreshScopes ?? [];

  // 1. The client: confidential even with allowPublicClients (a long-lived credential), allowed
  //    the refresh_token grant by name, not pairwise (D-B02: the refresh token's later ID-JAGs
  //    carry the user id).
  if (client.tokenEndpointAuthMethod === "none" || (client as { public?: unknown }).public === true) refuse("public_client", "refresh token for a public client");
  if (!(client.grantTypes ?? []).includes("refresh_token")) refuse("client_not_allowed_grant", "refresh_token not in the client's grant types");
  if (client.subjectType === "pairwise" && opts.pairwiseSecret) refuse("invalid_subject_token", "pairwise subject (not supported in v1)");

  // 2. Parameters: the refresh token is for this IdP, so no audience and no resource.
  if (form.has("audience")) refuse("unsupported_parameter", "audience with requested_token_type=refresh_token");
  if (form.has("resource")) refuse("unsupported_parameter", "resource with requested_token_type=refresh_token");
  const scopeParam = form.get("scope")?.[0] ?? "";
  if (scopeParam.length > MAX_SCOPE_LENGTH) refuse("unsupported_parameter", "scope too long");
  const scopes = [...new Set(scopeParam.split(" ").filter(Boolean))];
  if (!scopes.includes("openid") || !scopes.includes("offline_access")) refuse("scope_required", `requested ${scopes.join(" ") || "none"}`);
  // issueTokens doesn't check scopes (a "raw minting primitive"): every bound is ours.
  const clientScopes = client.scopes && client.scopes.length > 0 ? client.scopes : undefined;
  const providerScopes = opts.scopes && opts.scopes.length > 0 ? opts.scopes : undefined;
  for (const s of scopes) {
    if (!allowedScopes.includes(s)) refuse("no_scope", `${s} not in saml.refreshTokens.scopes`);
    if (clientScopes && !clientScopes.includes(s)) refuse("no_scope", `${s} not among the client's scopes`);
    if (providerScopes && !providerScopes.includes(s)) refuse("no_scope", `${s} not among the provider's scopes`);
  }

  // 3. The assertion: verified and consumed (single use) by the SAML IdP, for this client.
  const at = new Date();
  const assertion = await verifyOwnSamlAssertion(ctx, r.subjectToken, { clientId: client.clientId, now: at });
  const user = (await ctx.context.internalAdapter.findUserById(assertion.userId)) as (User & Record<string, unknown>) | null;
  if (!user || user.id !== assertion.userId) return refuse("unknown_subject");
  seen.userId = user.id;
  if (isBanned(user, at)) refuse("banned_user");

  // 4. Blocks: (user), (user, client), (client).
  await checkBlocksWithoutAudience(ctx, { userId: user.id, clientId: client.clientId });

  // 5. Mint. The provider also mints an access token (and an ID token, for openid) we don't hand
  //    out: the ID token is never stored; the opaque access token's row is deleted (T0, D-B28).
  const issued = tokenBody(await provider.issueTokens({ client, user, scopes, authTime: assertion.authnInstant, tokenResponse: {} }));
  const refreshToken = issued.refresh_token;
  if (typeof refreshToken !== "string" || refreshToken.length === 0) throw new Error("id-jag: the provider issued no refresh token");
  await discardAccessToken(ctx, opts, provider, issued.access_token);
  const row = await refreshTokenRow(ctx, refreshToken, { opts, hashToken: provider.hashToken });
  const expiresAt = storedSeconds(row?.expiresAt);
  if (expiresAt === undefined) throw new Error("id-jag: the provider's refresh token has no stored expiry");

  // 6. Audit, respond (draft -04 §4.5: the refresh token in access_token, token_type N_A).
  emit(ctx, options, { type: "id-jag.refresh-issued", userId: user.id, clientId: client.clientId, scopes, spEntityId: assertion.serviceProvider.entityId, assertionId: assertion.assertionId });
  maybeSweep(ctx, state);
  const response = {
    issued_token_type: REFRESH_TOKEN_TOKEN_TYPE,
    access_token: refreshToken,
    token_type: "N_A",
    scope: scopes.join(" "),
    // From the response's own clock: the row's iat is later than `now`, so `expiresAt - now` could exceed the lifetime.
    expires_in: Math.max(0, expiresAt - Math.floor(Date.now() / 1000)),
  };
  return response as unknown as OAuthTokenResponse;
}

/** Deletes the opaque access token issueTokens stored alongside the refresh token. Best effort: logged, never fatal. */
async function discardAccessToken(ctx: GenericEndpointContext, opts: OAuthExtensionGrantHandlerInput["opts"], provider: OAuthExtensionGrantHandlerInput["provider"], accessToken: unknown): Promise<void> {
  if (typeof accessToken !== "string" || accessToken.length === 0) return;
  try {
    const prefix = opts.prefix?.opaqueAccessToken;
    const value = prefix && accessToken.startsWith(prefix) ? accessToken.slice(prefix.length) : accessToken;
    const hash = await provider.hashToken(value, "access_token");
    await ctx.context.adapter.deleteMany({ model: ACCESS_TOKEN_MODEL, where: [{ field: "token", value: hash }] });
  } catch (e) {
    ctx.context.logger.warn("[id-jag] could not delete the unused access token minted with a SAML refresh token", e);
  }
}

/** Step 3 for each subject token type, as the policy sees it. */
async function verifySubject(
  input: OAuthExtensionGrantHandlerInput,
  type: string,
  token: string,
  e: { issuer: string; clientId: string; jwtOptions: JwtOptions | undefined; now: number; at: Date; maxAgeSeconds: number },
): Promise<SubjectTokenClaims> {
  if (type === SAML2_TOKEN_TYPE) {
    // Path (a), D-B26: the SAML IdP verifies and consumes it; then the same steps as any subject.
    const a = await verifyOwnSamlAssertion(input.ctx, token, { clientId: e.clientId, now: e.at });
    return {
      tokenType: SAML2_TOKEN_TYPE,
      sub: a.userId,
      auth_time: Math.floor(a.authnInstant.getTime() / 1000),
      acr: a.authnContextClassRef,
      amr: undefined,
      raw: { issuer: a.issuer, spEntityId: a.serviceProvider.entityId, nameIdFormat: a.nameIdFormat, assertionId: a.assertionId, notOnOrAfter: Math.floor(a.notOnOrAfter.getTime() / 1000) },
    };
  }
  if (type === REFRESH_TOKEN_TOKEN_TYPE) {
    const rt = await verifyOwnRefreshToken(input.ctx, token, { clientId: e.clientId, now: e.now, opts: input.opts, hashToken: input.provider.hashToken });
    return {
      tokenType: REFRESH_TOKEN_TOKEN_TYPE,
      sub: rt.userId,
      auth_time: rt.authTime,
      acr: undefined,
      amr: undefined,
      raw: { token_type: "refresh_token", client_id: e.clientId, scope: rt.scopes.join(" "), iat: rt.issuedAt, exp: rt.expiresAt },
    };
  }
  const idToken = await verifyOwnIdToken(input.ctx, token, e);
  return { tokenType: ID_TOKEN_TOKEN_TYPE, sub: idToken.sub, auth_time: idToken.auth_time, acr: idToken.acr, amr: idToken.amr, raw: { ...idToken } };
}

function safeJson(s: string): Record<string, unknown> | undefined {
  try {
    const v = JSON.parse(s) as unknown;
    return v !== null && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : undefined;
  } catch {
    return undefined;
  }
}
