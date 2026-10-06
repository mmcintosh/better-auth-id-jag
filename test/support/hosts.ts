// Two Better Auth hosts on in-memory SQLite: one on oauthProvider() + jwt(), one on mcp() + cimd() +
// jwt() (+ sso, for the ssoProvider desk check). Each registers the ping plugin.
import { DatabaseSync } from "node:sqlite";
import { betterAuth } from "better-auth";
import type { BetterAuthPlugin } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import { jwt } from "better-auth/plugins";
import { cimd } from "@better-auth/cimd";
import { mcp } from "@better-auth/mcp";
import { oauthProvider } from "@better-auth/oauth-provider";
import { sso } from "@better-auth/sso";
import { ping, type PingObservation } from "./ping";

export const BASE = "http://localhost:3000";
/** The issuer identifier is ctx.context.baseURL, which includes the base path. */
export const ISSUER = `${BASE}/api/auth`;
export const MCP_RESOURCE = "http://localhost:3000/mcp";

type ClientMetadataFetch = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

export async function createHost(kind: "oauth-provider" | "mcp", o: { extra?: BetterAuthPlugin[]; observe?: (seen: PingObservation) => void; fetchClientMetadata?: ClientMetadataFetch } = {}) {
  const common = { loginPage: "/login", consentPage: "/consent", allowDynamicClientRegistration: false, scopes: ["openid", "profile", "email", "offline_access", "read"] };
  // `as unknown as BetterAuthPlugin`: oauthProvider()/mcp() don't typecheck in a host with
  // exactOptionalPropertyTypes (upstream; docs/phase-0.md).
  const provider: BetterAuthPlugin[] =
    kind === "mcp"
      ? [mcp({ ...common, resource: MCP_RESOURCE }) as unknown as BetterAuthPlugin, cimd({ fetchClientMetadataResource: o.fetchClientMetadata ?? (() => Promise.reject(new Error("no fetch"))) }), sso() as unknown as BetterAuthPlugin]
      : [oauthProvider(common) as unknown as BetterAuthPlugin];
  const auth = betterAuth({
    baseURL: BASE,
    secret: "test-secret-that-is-at-least-32-characters-long",
    telemetry: { enabled: false },
    database: new DatabaseSync(":memory:") as never,
    emailAndPassword: { enabled: true },
    plugins: [jwt(), ...provider, ping(o.observe ? { observe: o.observe } : {}), ...(o.extra ?? [])],
  });
  const ctx = await auth.$context;
  await (await getMigrations(ctx.options)).runMigrations();
  return auth;
}

export type Host = Awaited<ReturnType<typeof createHost>>;

/** A user, and a confidential client (client_secret_basic) allowed the given grants. */
export async function seed(auth: Host, grantTypes: string[]) {
  const { headers: set } = await auth.api.signUpEmail({ body: { email: "ada@example.com", password: "password-1234", name: "Ada" }, returnHeaders: true });
  const headers = new Headers({ cookie: (set.get("set-cookie") ?? "").split(";")[0] ?? "" });
  return { ...(await createClient(auth, headers, grantTypes)), headers };
}

export async function createClient(auth: Host, headers: Headers, grantTypes: string[]) {
  // The provider is cast to BetterAuthPlugin above, so its endpoints aren't inferred on auth.api.
  const api = auth.api as unknown as { adminCreateOAuthClient: (o: { headers: Headers; body: Record<string, unknown> }) => Promise<unknown> };
  return (await api.adminCreateOAuthClient({
    headers,
    body: { client_name: "spike", redirect_uris: ["https://app.example/cb"], grant_types: grantTypes, token_endpoint_auth_method: "client_secret_basic", scope: "read", skip_consent: true },
  })) as { client_id: string; client_secret: string };
}

export function tokenRequest(form: Record<string, string>, basic?: { id: string; secret: string }) {
  return new Request(`${BASE}/api/auth/oauth2/token`, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      ...(basic ? { authorization: `Basic ${btoa(`${encodeURIComponent(basic.id)}:${encodeURIComponent(basic.secret)}`)}` } : {}),
    },
    body: new URLSearchParams(form),
  });
}
