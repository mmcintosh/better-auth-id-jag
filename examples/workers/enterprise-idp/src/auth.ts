// The enterprise IdP: an OAuth 2.1 / OIDC provider (oauthProvider + jwt, ES256) that also issues
// ID-JAGs (idJagIssuer). Its policy is a code hook: a registered client may reach the MCP server's
// authorization server (MCP_AS_ISSUER) for the `read` scope (`write` for WRITERS); the client's id
// *there* is kept in its metadata (`clientIdAtResource`), because the MCP server issues the client its
// own id. A client registered as an AI agent (metadata `agent: true`) is named in the ID-JAG's `act`
// (D-036), as Okta does, so the MCP server can treat agents differently from apps (D-037).
import { betterAuth, type BetterAuthPlugin } from "better-auth";
import { backgroundTasks } from "../../background";
import { jwt } from "better-auth/plugins";
import { oauthProvider } from "@better-auth/oauth-provider";
import { idJagIssuer } from "better-auth-id-jag";

export interface Env {
  DB: D1Database;
  BETTER_AUTH_SECRET: string;
  /** Required by /setup (the demo's one admin action). */
  SETUP_KEY: string;
  /** The MCP server's authorization server issuer identifier: the ID-JAG audience. */
  MCP_AS_ISSUER: string;
  /** The MCP server's protected resource. */
  MCP_RESOURCE: string;
  /** Optional: emails (comma-separated) whose agents may get the write scope; everyone gets read. */
  WRITERS?: string;
}

export function createAuth(env: Env, origin: string) {
  return betterAuth({
    baseURL: origin,
    secret: env.BETTER_AUTH_SECRET,
    telemetry: { enabled: false },
    database: env.DB as never,
    advanced: { backgroundTasks },
    emailAndPassword: { enabled: true, disableSignUp: true },
    plugins: [
      // ES256, not EdDSA: receivers such as Keycloak may not accept Ed25519 (D-004).
      jwt({ jwks: { keyPairConfig: { alg: "ES256" } } }),
      oauthProvider({
        loginPage: "/login",
        consentPage: "/consent",
        allowDynamicClientRegistration: false,
        scopes: ["openid", "profile", "email", "offline_access"],
        // Client creation is the setup route's alone.
        clientPrivileges: ({ headers }) => !!env.SETUP_KEY && headers?.get("x-setup-key") === env.SETUP_KEY,
      }) as unknown as BetterAuthPlugin,
      idJagIssuer({
        authorize: ({ audience, resource, client, user }) => {
          if (audience !== env.MCP_AS_ISSUER) return { decision: "deny", reason: "unknown audience" };
          if (resource !== undefined && resource !== env.MCP_RESOURCE) return { decision: "deny", reason: "unknown resource" };
          const atResource = client.metadata?.clientIdAtResource;
          if (typeof atResource !== "string") return { decision: "deny", reason: "client not registered at the MCP server" };
          // Who may do what is the IdP's decision: read for everyone, write only for the listed users.
          const writers = (env.WRITERS ?? "").split(",").map((e) => e.trim().toLowerCase()).filter(Boolean);
          const scopes = writers.includes(String(user.email).toLowerCase()) ? ["read", "write"] : ["read"];
          // An AI agent is named as the actor (act); an ordinary app acting for the user is not.
          const agent = client.metadata?.agent === true;
          return { decision: "allow", scopes, resource: env.MCP_RESOURCE, clientIdAtResource: atResource, claims: { email: true, ...(agent ? { act: { sub_profile: "ai_agent" } } : {}) } };
        },
        auditLog: { retentionDays: 30 },
      }),
    ],
  });
}
