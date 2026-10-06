// Phase 0 spike: a throwaway companion plugin that registers one extension grant
// (`urn:example:ping`) and one metadata field through extendOAuthProvider, from its init. The grant
// authenticates the client, signs an ID-JAG-shaped JWT with jwt()'s key, and issues tokens for a
// user, so one request exercises everything the two real plugins will need from the provider.
import type { BetterAuthPlugin } from "better-auth";
import { signJWT } from "better-auth/plugins";
import { extendOAuthProvider } from "@better-auth/oauth-provider";
import type { OAuthProviderExtension } from "@better-auth/oauth-provider";

export const PING_GRANT = "urn:example:ping";
export const PING_METADATA_FIELD = "example_ping_supported";

export interface PingObservation {
  /** What `opts.resources` held when the handler ran (mcp() appends its `resource` there). */
  resources: unknown;
  /** Whether the sso plugin's `ssoProvider` model answered through ctx.context.adapter. */
  ssoProviderReachable: boolean | "no-sso";
}

export function ping(o: { grantType?: string; observe?: (seen: PingObservation) => void; id?: string } = {}): BetterAuthPlugin {
  const grantType = o.grantType ?? PING_GRANT;
  const extension: OAuthProviderExtension = {
    grants: {
      [grantType]: async ({ ctx, opts, provider }) => {
        const { client } = await provider.authenticateClient({ requireCredentials: true });
        const email = typeof ctx.body?.username === "string" ? ctx.body.username : "";
        const user = await ctx.context.internalAdapter.findUserByEmail(email);
        if (!user) throw new Error("ping: no such user");
        let ssoProviderReachable: PingObservation["ssoProviderReachable"] = "no-sso";
        if (ctx.context.hasPlugin("sso")) {
          const rows = await ctx.context.adapter.findMany({ model: "ssoProvider", limit: 1 });
          ssoProviderReachable = Array.isArray(rows);
        }
        o.observe?.({ resources: opts.resources, ssoProviderReachable });
        const now = Math.floor(Date.now() / 1000);
        const idJag = await signJWT(ctx, {
          header: { typ: "oauth-id-jag+jwt" },
          payload: {
            iss: ctx.context.baseURL,
            sub: user.user.id,
            aud: "https://receiver.example",
            client_id: client.clientId,
            jti: crypto.randomUUID(),
            iat: now,
            exp: now + 300,
          },
        });
        const resource = typeof ctx.body?.resource === "string" ? ctx.body.resource : undefined;
        return provider.issueTokens({
          client,
          user: user.user,
          scopes: ["read"],
          ...(resource ? { resources: [resource] } : {}),
          tokenResponse: { id_jag: idJag },
        });
      },
    },
    metadata: () => ({ [PING_METADATA_FIELD]: true }),
  };
  return {
    id: o.id ?? "ping",
    init(ctx) {
      extendOAuthProvider(ctx, extension);
    },
  };
}
