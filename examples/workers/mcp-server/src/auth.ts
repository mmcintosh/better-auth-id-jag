// The MCP server's authorization server: mcp() (an OAuth provider bound to this server's resource)
// + jwt() + idJagGrant(), which accepts ID-JAGs from the trusted enterprise IdP (IDP_ISSUER) and,
// optionally, from Okta (OKTA_ISSUER). Users are provisioned on first use (JIT) from the ID-JAG's
// verified email.
import { betterAuth, type BetterAuthPlugin } from "better-auth";
import { backgroundTasks } from "../../background";
import { jwt } from "better-auth/plugins";
import { mcp } from "@better-auth/mcp";
import { idJagGrant, type StaticTrustedIssuer } from "better-auth-id-jag";

export interface Env {
  DB: D1Database;
  BETTER_AUTH_SECRET: string;
  SETUP_KEY: string;
  /** The enterprise IdP's issuer identifier (its /api/auth base URL). */
  IDP_ISSUER: string;
  /** The same IdP, reached through a service binding: a Worker can't fetch another on the same account by URL. */
  IDP: Fetcher;
  /** Optional: an Okta authorization server issuer, for Cross App Access. */
  OKTA_ISSUER?: string;
  /** Optional: Okta's xaa.dev playground IdP (https://idp.xaa.dev), for its conformance testers. */
  XAA_ISSUER?: string;
  OKTA_JWKS_URI?: string;
}

export function createAuth(env: Env, origin: string) {
  const idpHost = new URL(env.IDP_ISSUER).host;
  const trustedIssuers: StaticTrustedIssuer[] = [{ issuer: env.IDP_ISSUER, jwksUri: `${env.IDP_ISSUER}/jwks`, jitProvisioning: { trustEmailVerified: true } }];
  if (env.OKTA_ISSUER && env.OKTA_JWKS_URI) trustedIssuers.push({ issuer: env.OKTA_ISSUER, jwksUri: env.OKTA_JWKS_URI, jitProvisioning: { trustEmailVerified: true } });
  if (env.XAA_ISSUER) trustedIssuers.push({ issuer: env.XAA_ISSUER, jwksUri: `${env.XAA_ISSUER}/jwks`, jitProvisioning: { trustEmailVerified: true } });
  return betterAuth({
    baseURL: origin,
    secret: env.BETTER_AUTH_SECRET,
    telemetry: { enabled: false },
    database: env.DB as never,
    advanced: { backgroundTasks },
    // Only the operator who registers clients signs in here; agents' users arrive by ID-JAG.
    emailAndPassword: { enabled: true, disableSignUp: true },
    plugins: [
      jwt({ jwks: { keyPairConfig: { alg: "ES256" } } }),
      mcp({
        loginPage: "/login",
        consentPage: "/consent",
        resource: `${origin}/mcp`,
        allowDynamicClientRegistration: false,
        scopes: ["read"],
        clientPrivileges: ({ headers }) => !!env.SETUP_KEY && headers?.get("x-setup-key") === env.SETUP_KEY,
      }) as unknown as BetterAuthPlugin,
      idJagGrant({
        trustedIssuers,
        // The IdP's JWKS through the service binding; anything else (Okta) over the internet.
        fetch: (url, init) => (new URL(url).host === idpHost ? env.IDP.fetch(url, init) : fetch(url, init)),
        auditLog: { retentionDays: 30 },
      }),
    ],
  });
}
