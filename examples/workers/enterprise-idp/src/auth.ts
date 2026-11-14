// The enterprise IdP: an OAuth 2.1 / OIDC provider (oauthProvider + jwt, ES256) that also issues
// ID-JAGs (idJagIssuer). Its policy is a code hook: a registered client may reach the MCP server's
// authorization server (MCP_AS_ISSUER) for the `read` scope (`write` for WRITERS); the client's id
// *there* is kept in its metadata (`clientIdAtResource`), because the MCP server issues the client its
// own id. A client registered as an AI agent (metadata `agent: true`) is named in the ID-JAG's `act`
// (D-036), as Okta does, so the MCP server can treat agents differently from apps (D-037).
// With TESTER_AS_ISSUER and TESTER_RESOURCE set, it also issues ID-JAGs for the public tester
// (docs/test-your-idp.md), only to clients registered for it (metadata `for: "tester"`), whose id there is
// the tester registration's client id; the tester grants `read` only. A client registered for one of the two
// audiences can't get an ID-JAG for the other.
import { betterAuth, type BetterAuthPlugin } from "better-auth";
import { backgroundTasks } from "../../background";
import { jwt } from "better-auth/plugins";
import { oauthProvider } from "@better-auth/oauth-provider";
import { type AuthorizeInput, type AuthorizeResult, idJagIssuer } from "better-auth-id-jag";

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
  /** Optional, with TESTER_RESOURCE: the public tester's authorization server issuer identifier, a second audience. */
  TESTER_AS_ISSUER?: string;
  /** The public tester's protected resource. */
  TESTER_RESOURCE?: string;
}

/** The IdP's policy: the issuer's `authorize` hook. Exported for its test. */
export function policy(env: Env) {
  return ({ audience, resource, client, user }: Pick<AuthorizeInput, "audience" | "resource" | "client" | "user">): AuthorizeResult => {
    const atResource = client.metadata?.clientIdAtResource;
    const forTester = client.metadata?.for === "tester";
    // An AI agent is named as the actor (act); an ordinary app acting for the user is not.
    const act = client.metadata?.agent === true ? { act: { sub_profile: "ai_agent" } } : {};
    if (env.TESTER_AS_ISSUER && env.TESTER_RESOURCE && audience === env.TESTER_AS_ISSUER) {
      if (resource !== undefined && resource !== env.TESTER_RESOURCE) return { decision: "unknown_resource", reason: "not the tester's resource" };
      if (!forTester || typeof atResource !== "string") return { decision: "deny", reason: "client not registered for the tester" };
      return { decision: "allow", scopes: ["read"], resource: env.TESTER_RESOURCE, clientIdAtResource: atResource, claims: { email: true, ...act } };
    }
    if (audience !== env.MCP_AS_ISSUER) return { decision: "unknown_audience", reason: "not the MCP server" };
    if (resource !== undefined && resource !== env.MCP_RESOURCE) return { decision: "unknown_resource", reason: "not the MCP server's resource" };
    if (forTester || typeof atResource !== "string") return { decision: "deny", reason: "client not registered at the MCP server" };
    // Who may do what is the IdP's decision: read for everyone, write only for the listed users.
    const writers = (env.WRITERS ?? "").split(",").map((e) => e.trim().toLowerCase()).filter(Boolean);
    const scopes = writers.includes(String(user.email).toLowerCase()) ? ["read", "write"] : ["read"];
    return { decision: "allow", scopes, resource: env.MCP_RESOURCE, clientIdAtResource: atResource, claims: { email: true, ...act } };
  };
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
        authorize: policy(env),
        auditLog: { retentionDays: 30 },
      }),
    ],
  });
}
