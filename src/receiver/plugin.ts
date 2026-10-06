// idJagGrant(): the receiver plugin. Registers the jwt-bearer grant (for ID-JAGs only: a plain
// RFC 7523 assertion is refused at parse with `wrong_typ`) and the grant-profile metadata on the
// host's `@better-auth/mcp` or `@better-auth/oauth-provider`, through `extendOAuthProvider` from
// `init` (docs/phase-0.md). Options are validated when the plugin is built.
import type { BetterAuthPlugin } from "better-auth";
import { extendOAuthProvider, type OAuthProviderExtension } from "@better-auth/oauth-provider";
import { auditSchema, ID_JAG_GRANT_PROFILE, JWT_BEARER_GRANT, jtiSchema, RECEIVER_METADATA_FIELD } from "../core";
import { handleIdJagGrant, registeredResources } from "./grant";
import { type IdJagGrantOptions, type ResolvedReceiverOptions, resolveReceiverOptions } from "./options";
import { trustedIssuerSchema } from "./schema";

export const RECEIVER_PLUGIN_ID = "id-jag-grant";

/** The extension the plugin registers; exported for hosts that pass `oauthProvider({ extensions })`. */
export function idJagGrantExtension(resolved: ResolvedReceiverOptions): OAuthProviderExtension {
  return {
    grants: { [JWT_BEARER_GRANT]: (input) => handleIdJagGrant(input, resolved) },
    metadata: () => ({ [RECEIVER_METADATA_FIELD]: [ID_JAG_GRANT_PROFILE] }),
  };
}

export function idJagGrant(options: IdJagGrantOptions = {}) {
  const resolved = resolveReceiverOptions(options);
  return {
    id: RECEIVER_PLUGIN_ID,
    init(ctx) {
      extendOAuthProvider(ctx, idJagGrantExtension(resolved));
      if (resolved.allowPublicClients) ctx.logger.warn("[id-jag] allowPublicClients is on: public clients may redeem ID-JAGs. The draft says this grant SHOULD be for confidential clients only.");
      if (resolved.trustedIssuers.length === 0 && !resolved.sso && !resolved.trustedIssuerTable) ctx.logger.warn("[id-jag] no trusted issuers configured: every ID-JAG will be refused.");
      if (resolved.sso && !ctx.hasPlugin("sso")) ctx.logger.warn("[id-jag] sso trust is on but the sso plugin is not installed: no sso providers will be trusted.");
      if (resolved.defaultResource !== undefined) {
        const provider = ctx.getPlugin("oauth-provider") as { options?: Parameters<typeof registeredResources>[0] } | null;
        if (provider?.options && !registeredResources(provider.options).includes(resolved.defaultResource)) throw new Error(`id-jag receiver: defaultResource ${resolved.defaultResource} is not a registered resource`);
      }
    },
    schema: {
      ...jtiSchema(),
      ...(resolved.audit.auditLog ? auditSchema() : {}),
      ...(resolved.trustedIssuerTable ? trustedIssuerSchema() : {}),
    },
    options,
  } satisfies BetterAuthPlugin;
}
