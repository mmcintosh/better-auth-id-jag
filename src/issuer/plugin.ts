// idJagIssuer(): makes a Better Auth OIDC provider (@better-auth/oauth-provider + jwt) an ID-JAG
// issuer (draft-ietf-oauth-identity-assertion-authz-grant-04 §4.3). It registers, from `init`:
// - grants["urn:ietf:params:oauth:grant-type:token-exchange"], serving only
//   requested_token_type=urn:ietf:params:oauth:token-type:id-jag;
// - metadata: identity_chaining_requested_token_types_supported (grant_types_supported lists the
//   grant automatically: docs/phase-0.md);
// and, with `registry.enabled`, its tables, plus the admin API when `registry.canManage` is set.
import type { AuthContext, BetterAuthPlugin } from "better-auth";
import type { JwtOptions } from "better-auth/plugins";
import { extendOAuthProvider, type OAuthProviderExtension } from "@better-auth/oauth-provider";
import { ALLOWED_ALGORITHMS, ID_JAG_TOKEN_TYPE, ISSUER_METADATA_FIELD, TOKEN_EXCHANGE_GRANT, warnIfReplayUnsafe } from "../core";
import { RegistryDirectory } from "./directory";
import { handleTokenExchange, type IssuerState } from "./exchange";
import { type IdJagIssuerOptions, resolveIssuerOptions } from "./options";
import { ID_JAG_REGISTRY_ERROR_CODES, registryEndpoints } from "./registry";
import { issuerSchema } from "./schema";

export const ISSUER_PLUGIN_ID = "id-jag-issuer";

type PluginLookup = { getPlugin(id: string): { options?: unknown } | null | undefined };

/** Startup checks: a host this plugin can't serve safely fails at boot, with a clear error. */
export function checkIssuerHost(ctx: AuthContext, state: IssuerState): void {
  const lookup = ctx as unknown as PluginLookup;
  const provider = lookup.getPlugin("oauth-provider") as { options?: { disableJwtPlugin?: boolean } } | null | undefined;
  if (!provider) throw new Error("idJagIssuer: requires the oauth-provider plugin (oauthProvider() from @better-auth/oauth-provider)");
  if (provider.options?.disableJwtPlugin)
    throw new Error("idJagIssuer: oauthProvider({ disableJwtPlugin: true }) signs ID tokens with HS256 under each client's secret; ID-JAG subject tokens must be verifiable with this IdP's own asymmetric keys. Use the jwt plugin.");
  const jwt = lookup.getPlugin("jwt") as { options?: JwtOptions } | null | undefined;
  if (!jwt) throw new Error("idJagIssuer: requires the jwt plugin (jwt() from better-auth/plugins): it holds the keys ID tokens and ID-JAGs are signed with");
  const o = jwt.options;
  if (o?.jwt?.sign || o?.jwks?.remoteUrl)
    throw new Error("idJagIssuer: a jwt plugin with jwt.sign / jwks.remoteUrl (remote keys) isn't supported: ID tokens are verified with the keys in this host's database, with no outbound request (S10)");
  const primary = o?.jwks?.keyPairConfig?.alg ?? "EdDSA";
  const configured = [primary, ...(o?.jwks?.keyPairConfigs ?? []).map((c) => c.alg)];
  const alg = state.options.signingAlgorithm ?? primary;
  if (!configured.includes(alg)) throw new Error(`idJagIssuer: signingAlgorithm ${alg} is neither the jwt plugin's keyPairConfig.alg (${primary}) nor in its keyPairConfigs`);
  if (!(ALLOWED_ALGORITHMS as readonly string[]).includes(alg))
    throw new Error(`idJagIssuer: the ID-JAG would be signed with ${alg}; receivers accept RS256, ES256 or EdDSA (S4). Set signingAlgorithm, or the jwt plugin's keyPairConfig.alg.`);
  if (state.options.allowPublicClients)
    ctx.logger.warn("[id-jag] allowPublicClients is on: public clients can obtain ID-JAGs. The draft says this grant SHOULD only be supported for confidential clients.");
  if (!state.options.authorize && !state.directory) ctx.logger.warn("[id-jag] no policy source (authorize or registry): every token exchange is refused (no_policy).");
}

/**
 * The state `handleTokenExchange` needs (validated options, registry directory). For a host that
 * composes the grant itself instead of installing the plugin's extension: call `checkIssuerHost`
 * from its own init too.
 */
export function createIssuerState(options: IdJagIssuerOptions = {}): IssuerState {
  const resolved = resolveIssuerOptions(options);
  return {
    options: resolved,
    directory: resolved.registryEnabled ? new RegistryDirectory({ cacheSeconds: resolved.cacheSeconds, allowLoopbackHttp: resolved.allowLoopbackHttpAudiences }) : undefined,
    lastSweep: 0,
  };
}

/** The ID-JAG issuer plugin. */
export function idJagIssuer(options: IdJagIssuerOptions = {}) {
  const state = createIssuerState(options);
  const resolved = state.options;
  const extension: OAuthProviderExtension = {
    grants: { [TOKEN_EXCHANGE_GRANT]: (input) => handleTokenExchange(input, state) },
    metadata: () => ({ [ISSUER_METADATA_FIELD]: [ID_JAG_TOKEN_TYPE] }),
  };
  // Typed as mounted so the client plugin can infer the routes; empty at runtime without canManage.
  const endpoints = (resolved.registryEnabled && resolved.registry?.canManage ? registryEndpoints(state) : {}) as ReturnType<typeof registryEndpoints>;
  return {
    id: ISSUER_PLUGIN_ID,
    init(ctx: AuthContext) {
      checkIssuerHost(ctx, state);
      extendOAuthProvider(ctx, extension);
      warnIfReplayUnsafe(ctx, "idJagIssuer");
    },
    schema: issuerSchema({ registry: resolved.registryEnabled, auditLog: resolved.auditLog !== undefined }),
    endpoints,
    $ERROR_CODES: Object.fromEntries(Object.values(ID_JAG_REGISTRY_ERROR_CODES).map((e) => [e.code, e])) as Record<string, { code: string; message: string }>,
  } satisfies BetterAuthPlugin;
}
