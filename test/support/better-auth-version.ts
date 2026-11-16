// Better Auth 1.8 or later, told by a feature rather than a version (D-056): oauthTokenExchange() is exported from
// @better-auth/oauth-provider 1.8 on, the line that also refuses repeated form parameters itself and adds
// authenticationContext. A version read wouldn't do: oauth-provider doesn't export its package.json, workerd has no
// fs, and our own package.json pin is what scripts/use-better-auth.sh rewrites.
import * as oauthProviderModule from "@better-auth/oauth-provider";
import * as oauthProviderInternal from "@better-auth/oauth-provider/internal";

export const BETTER_AUTH_1_8 = typeof (oauthProviderModule as Record<string, unknown>).oauthTokenExchange === "function";

// requireMcpAuth (@better-auth/mcp) reads the authorization server's keys in process from 1.7.25 on
// (better-auth/better-auth#12501), through oauth-provider's internal getLocalJwksSource; before, it fetched them by URL,
// which a Worker can't do to itself. Told by that function, as above: the /internal entry exists from 1.7.16 on.
export const REQUIRE_MCP_AUTH_IN_PROCESS = typeof (oauthProviderInternal as Record<string, unknown>).getLocalJwksSource === "function";
