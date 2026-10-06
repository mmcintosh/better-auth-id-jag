// Interop hosts: our issuer (an IdP on oauthProvider() + jwt() + idJagIssuer()) and our receiver (an
// MCP server's authorization server on mcp() + cimd() + jwt() + idJagGrant()), as two separate Better
// Auth instances, built only from the package's public entry point.
//
// Each host has its own database. On Node, two in-memory node:sqlite databases. In workerd a test file
// has one D1, and two hosts on it would share the user, jwks and oauthClient tables (the MCP server
// would sign with the IdP's key, and see its clients), so there the IdP runs on Better Auth's memory
// adapter and the MCP host keeps the D1: the receiver's single-use check needs a database that
// enforces UNIQUE (the memory adapter doesn't; D-009).
import { betterAuth } from "better-auth";
import type { BetterAuthPlugin } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { getAuthTables } from "better-auth/db";
import { getMigrations } from "better-auth/db/migration";
import { admin, jwt } from "better-auth/plugins";
import { cimd } from "@better-auth/cimd";
import { mcp } from "@better-auth/mcp";
import { oauthProvider } from "@better-auth/oauth-provider";
import {
  type AcceptedEvent,
  type FetchLike,
  ID_JAG_TOKEN_TYPE,
  ID_TOKEN_TOKEN_TYPE,
  type IdJagGrantOptions,
  type IdJagIssuerOptions,
  type IssuedEvent,
  idJagGrant,
  idJagIssuer,
  JWT_BEARER_GRANT,
  type RefusedEvent,
  TOKEN_EXCHANGE_GRANT,
} from "../../src";
import type { IssuerHost } from "./issuer-host";

export const SECRET = "test-secret-that-is-at-least-32-characters-long";
export const isWorkerd = () => navigator.userAgent === "Cloudflare-Workers";

async function sqlite(): Promise<unknown> {
  const { DatabaseSync } = await import("node:sqlite");
  return new DatabaseSync(":memory:");
}

/** A memory-adapter database; its tables are added from the host's schema once the host exists. */
function memoryDb() {
  const tables: Record<string, Record<string, unknown>[]> = {};
  return { tables, adapter: memoryAdapter(tables) };
}

function backgroundTasks() {
  const pending = new Set<Promise<unknown>>();
  return {
    handler: (p: Promise<unknown>) => {
      const t = p.finally(() => pending.delete(t));
      pending.add(t);
    },
    async settle() {
      while (pending.size) await Promise.allSettled([...pending]);
    },
  };
}

export interface IdpOptions {
  /** Origin of the IdP; its issuer is `${base}/api/auth`. */
  base: string;
  issuer: Omit<IdJagIssuerOptions, "events">;
  /** jwt() key configuration. Default ES256 (D-004: the issuer example signs ES256). */
  keyPairConfig?: Record<string, unknown>;
  /** Force a database (Node tests that serve the IdP over HTTP pass nothing and get node:sqlite). */
  database?: "sqlite" | "memory";
}

/** Our issuer. Shaped like issuer-host's IssuerHost, so its Browser / signUp / createClient / getIdToken work. */
export async function idpHost(o: IdpOptions) {
  const recorded = { issued: [] as IssuedEvent[], refused: [] as RefusedEvent[], admin: [] as unknown[] };
  const tasks = backgroundTasks();
  const kind = o.database ?? (isWorkerd() ? "memory" : "sqlite");
  const memory = kind === "memory" ? memoryDb() : undefined;
  const auth = betterAuth({
    baseURL: o.base,
    secret: SECRET,
    telemetry: { enabled: false },
    database: (memory ? memory.adapter : await sqlite()) as never,
    emailAndPassword: { enabled: true },
    plugins: [
      jwt({ jwks: { keyPairConfig: (o.keyPairConfig ?? { alg: "ES256" }) as never } }),
      oauthProvider({ loginPage: "/login", consentPage: "/consent", allowDynamicClientRegistration: false, scopes: ["openid", "profile", "email", "offline_access"] }) as unknown as BetterAuthPlugin,
      admin() as unknown as BetterAuthPlugin,
      idJagIssuer({
        ...o.issuer,
        events: { onIssued: (e) => void recorded.issued.push(e), onRefused: (e) => void recorded.refused.push(e), onAdminChanged: (e) => void recorded.admin.push(e) },
      }) as unknown as BetterAuthPlugin,
    ],
    advanced: { backgroundTasks: { handler: tasks.handler } },
  });
  const ctx = await auth.$context;
  if (memory) for (const t of Object.values(getAuthTables(ctx.options))) memory.tables[t.modelName] ??= [];
  else await (await getMigrations(ctx.options)).runMigrations();
  const host = { auth, ctx, recorded, settle: tasks.settle, base: o.base, issuerUrl: `${o.base}/api/auth` };
  return host as typeof host & IssuerHost;
}

export type IdpHost = Awaited<ReturnType<typeof idpHost>>;

/** The token exchange at our issuer, as the requesting client sends it. Returns status and body. */
export async function exchangeAt(idp: IdpHost, client: { client_id: string; client_secret: string }, idToken: string, form: { audience: string; resource?: string; scope?: string }) {
  const body = new URLSearchParams({ grant_type: TOKEN_EXCHANGE_GRANT, requested_token_type: ID_JAG_TOKEN_TYPE, subject_token: idToken, subject_token_type: ID_TOKEN_TOKEN_TYPE, ...form });
  const res = await idp.auth.handler(
    new Request(`${idp.issuerUrl}/oauth2/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", authorization: basicAuth(client.client_id, client.client_secret) },
      body,
    }),
  );
  const json = (await res.json()) as Record<string, unknown>;
  await idp.settle();
  return { status: res.status, body: json };
}

export const basicAuth = (id: string, secret: string) => `Basic ${btoa(`${encodeURIComponent(id)}:${encodeURIComponent(secret)}`)}`;

export interface McpOptions {
  base: string;
  resource: string;
  receiver: Omit<IdJagGrantOptions, "events">;
}

/** Our receiver: an MCP server's authorization server. */
export async function mcpHost(o: McpOptions) {
  const accepted: AcceptedEvent[] = [];
  const refused: RefusedEvent[] = [];
  const tasks = backgroundTasks();
  const database = isWorkerd() ? (await import("cloudflare:test")).env.DB : await sqlite();
  const auth = betterAuth({
    baseURL: o.base,
    secret: SECRET,
    telemetry: { enabled: false },
    database: database as never,
    emailAndPassword: { enabled: true },
    plugins: [
      jwt(),
      mcp({ loginPage: "/login", consentPage: "/consent", allowDynamicClientRegistration: false, resource: o.resource, scopes: ["openid", "profile", "email", "offline_access", "read", "write"] }) as unknown as BetterAuthPlugin,
      cimd({ fetchClientMetadataResource: () => Promise.reject(new Error("no client metadata fetch in this test")) }),
      idJagGrant({ ...o.receiver, events: { onAccepted: (e) => void accepted.push(e), onRefused: (e) => void refused.push(e) } }),
    ],
    advanced: { backgroundTasks: { handler: tasks.handler } },
  });
  const ctx = await auth.$context;
  await (await getMigrations(ctx.options)).runMigrations();
  return { auth, ctx, accepted, refused, settle: tasks.settle, base: o.base, issuerUrl: `${o.base}/api/auth`, resource: o.resource };
}

export type McpHost = Awaited<ReturnType<typeof mcpHost>>;

/** A confidential client registered at the MCP server's AS for jwt-bearer, under the AS's own client id. */
export async function mcpClient(h: McpHost) {
  const { headers: set } = await h.auth.api.signUpEmail({ body: { email: `owner+${crypto.randomUUID()}@example.com`, password: "password-1234", name: "Owner" }, returnHeaders: true });
  const headers = new Headers({ cookie: (set.get("set-cookie") ?? "").split(";")[0] ?? "" });
  const api = h.auth.api as unknown as { adminCreateOAuthClient: (o: { headers: Headers; body: Record<string, unknown> }) => Promise<unknown> };
  return (await api.adminCreateOAuthClient({
    headers,
    body: {
      client_name: "agent at the MCP server",
      redirect_uris: ["https://app.example/cb"],
      grant_types: [JWT_BEARER_GRANT],
      token_endpoint_auth_method: "client_secret_basic",
      scope: "read write",
      skip_consent: true,
    },
  })) as { client_id: string; client_secret: string };
}

/** The jwt-bearer grant at our receiver. */
export async function redeemAt(h: McpHost, client: { client_id: string; client_secret: string }, assertion: string) {
  const res = await h.auth.handler(
    new Request(`${h.issuerUrl}/oauth2/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", authorization: basicAuth(client.client_id, client.client_secret) },
      body: new URLSearchParams({ grant_type: JWT_BEARER_GRANT, assertion }),
    }),
  );
  const text = await res.text();
  let body: Record<string, unknown> = {};
  try {
    body = JSON.parse(text) as Record<string, unknown>;
  } catch {}
  await h.settle();
  return { status: res.status, body, text };
}

/** A fetch that only reaches the given hosts' handlers (by origin), recording every URL. */
export function routedFetch(...hosts: { base: string; auth: { handler: (r: Request) => Promise<Response> } }[]) {
  const urls: string[] = [];
  const fetch: FetchLike = async (url, init) => {
    urls.push(url);
    const host = hosts.find((h) => url.startsWith(`${h.base}/`));
    if (!host) throw new Error(`unexpected fetch: ${url}`);
    return host.auth.handler(new Request(url, { method: init?.method ?? "GET", ...(init?.headers ? { headers: init.headers } : {}) }));
  };
  return { fetch, urls };
}

export const decodeJwtPart = (jwt: string, part: 0 | 1) => JSON.parse(atob((jwt.split(".")[part] ?? "").replace(/-/g, "+").replace(/_/g, "/"))) as Record<string, unknown>;
