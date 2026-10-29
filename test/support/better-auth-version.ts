// Better Auth 1.8 or later, told by a feature rather than a version (D-056): oauthTokenExchange() is exported from
// @better-auth/oauth-provider 1.8 on, the line that also refuses repeated form parameters itself and adds
// authenticationContext. A version read wouldn't do: oauth-provider doesn't export its package.json, workerd has no
// fs, and our own package.json pin is what scripts/use-better-auth.sh rewrites.
import * as oauthProviderModule from "@better-auth/oauth-provider";

export const BETTER_AUTH_1_8 = typeof (oauthProviderModule as Record<string, unknown>).oauthTokenExchange === "function";
