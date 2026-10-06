// Track A test support: a test IdP (a jose key pair whose JWKS is served only through the
// receiver's injected fetch), and receiver hosts on mcp() + cimd() + jwt() (+ sso(), admin()) or on
// oauthProvider(), optionally with organization(). In workerd the hosts of one test file share a D1, so every IdP gets a unique
// issuer and every user a unique email.
import { exportJWK, generateKeyPair, type JWK, type JWTPayload, SignJWT } from "jose";
import type { CryptoKey } from "jose";
import { betterAuth } from "better-auth";
import type { BetterAuthOptions, BetterAuthPlugin } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import { admin, jwt, organization } from "better-auth/plugins";
import { cimd } from "@better-auth/cimd";
import { mcp } from "@better-auth/mcp";
import { oauthProvider } from "@better-auth/oauth-provider";
import { sso } from "@better-auth/sso";
import { JWT_BEARER_GRANT, newJti, type RefusedEvent, type AcceptedEvent } from "../../src/core";
import { type FetchLike, type IdJagGrantOptions, idJagGrant } from "../../src/receiver";

export const BASE = "http://localhost:3000";
export const ISSUER = `${BASE}/api/auth`;
export const MCP_RESOURCE = "http://localhost:3000/mcp";
export const OTHER_RESOURCE = "http://localhost:3000/other";
export const SCOPES = ["openid", "profile", "email", "offline_access", "read", "write"];

export const uniqueEmail = (domain = "example.com") => `ada+${crypto.randomUUID()}@${domain}`;
export const now = () => Math.floor(Date.now() / 1000);

export async function database(): Promise<unknown> {
  if (navigator.userAgent === "Cloudflare-Workers") return (await import("cloudflare:test")).env.DB;
  const { DatabaseSync } = await import("node:sqlite");
  return new DatabaseSync(":memory:");
}

type Alg = "ES256" | "RS256" | "EdDSA";

interface SigningKey {
  kid: string;
  alg: Alg;
  privateKey: CryptoKey;
  jwk: JWK;
}

async function signingKey(alg: Alg, kid = `k-${crypto.randomUUID().slice(0, 8)}`): Promise<SigningKey> {
  const { publicKey, privateKey } = await generateKeyPair(alg, { extractable: true });
  return { kid, alg, privateKey, jwk: { ...(await exportJWK(publicKey)), kid, alg, use: "sig" } };
}

export type Route = (url: string, init: RequestInit) => Response | Promise<Response>;

/** A test IdP: its keys, JWKS and discovery document, and an ID-JAG minter. */
export async function testIdp(o: { alg?: Alg; issuer?: string } = {}) {
  const issuer = o.issuer ?? `https://idp-${crypto.randomUUID().slice(0, 8)}.example`;
  const jwksUri = `${issuer}/jwks`;
  const discoveryUri = `${issuer}/.well-known/openid-configuration`;
  let current = await signingKey(o.alg ?? "ES256");
  let published: JWK[] = [current.jwk];
  const idp = {
    issuer,
    jwksUri,
    discoveryUri,
    get key() {
      return current;
    },
    /** Override how this IdP answers (status, redirects, sizes, hangs). */
    override: undefined as Route | undefined,
    published: () => published,
    publish(keys: JWK[]) {
      published = keys;
    },
    /** A new key, published alongside the old one (rotation). */
    async rotate() {
      current = await signingKey(o.alg ?? "ES256");
      published = [...published, current.jwk];
      return current;
    },
    route: (async (url, init) => {
      if (idp.override) return idp.override(url, init);
      if (url === jwksUri) return Response.json({ keys: published });
      if (url === discoveryUri) return Response.json({ issuer, jwks_uri: jwksUri, token_endpoint: `${issuer}/token` });
      return new Response("not found", { status: 404 });
    }) as Route,
    /** The claims of a valid ID-JAG for our receiver; override any. */
    claims(over: Record<string, unknown> = {}): Record<string, unknown> {
      const t = now();
      return { iss: issuer, sub: `sub-${crypto.randomUUID()}`, aud: ISSUER, client_id: "unset", jti: newJti(), iat: t, exp: t + 300, scope: "read", resource: MCP_RESOURCE, ...over };
    },
    /** Sign claims as an ID-JAG (typ oauth-id-jag+jwt) with this IdP's current key, or another. */
    async mint(claims: Record<string, unknown>, header: Record<string, unknown> = {}, key: SigningKey = current): Promise<string> {
      const payload = Object.fromEntries(Object.entries(claims).filter(([, v]) => v !== undefined)) as JWTPayload;
      return new SignJWT(payload).setProtectedHeader({ alg: key.alg, kid: key.kid, typ: "oauth-id-jag+jwt", ...header }).sign(key.privateKey);
    },
    signingKey,
  };
  return idp;
}

export type TestIdp = Awaited<ReturnType<typeof testIdp>>;

/** The receiver's network: only the given IdPs answer; every call is recorded; anything else throws. */
export function network(...idps: TestIdp[]) {
  const calls: { url: string; init: RequestInit }[] = [];
  const fetch: FetchLike = async (url, init) => {
    calls.push({ url, init });
    const idp = idps.find((i) => url.startsWith(`${i.issuer}/`));
    if (!idp) throw new Error(`unexpected fetch: ${url}`);
    return idp.route(url, init);
  };
  return { fetch, calls, urls: () => calls.map((c) => c.url) };
}

/** Captured audit events, with a settle() for the background tasks they run in. */
export function recorder() {
  const refused: RefusedEvent[] = [];
  const accepted: AcceptedEvent[] = [];
  const pending = new Set<Promise<unknown>>();
  return {
    refused,
    accepted,
    events: { onRefused: (e: RefusedEvent) => void refused.push(e), onAccepted: (e: AcceptedEvent) => void accepted.push(e) },
    backgroundTasks: (p: Promise<unknown>) => {
      const t = p.finally(() => pending.delete(t));
      pending.add(t);
    },
    async settle() {
      while (pending.size) await Promise.allSettled([...pending]);
    },
    async lastReason(): Promise<string | undefined> {
      while (pending.size) await Promise.allSettled([...pending]);
      return refused.at(-1)?.reason;
    },
  };
}

export type Recorder = ReturnType<typeof recorder>;

export interface HostOptions {
  receiver: IdJagGrantOptions;
  database?: unknown;
  sso?: boolean | { domainVerification?: boolean; organizationProvisioning?: SsoOrganizationProvisioning };
  admin?: boolean;
  /** Install the organization plugin. */
  organization?: boolean;
  /** Capture the host's log lines ("level: message"). */
  logs?: string[];
  recorder?: Recorder;
  fetchClientMetadata?: (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;
  /** oauthProvider() only: its resources. */
  resources?: string[];
  /** Better Auth's `databaseHooks` (the concurrency tests hold inserts at a barrier with them). */
  databaseHooks?: BetterAuthOptions["databaseHooks"];
  /** Better Auth's `account` options (account linking). */
  account?: BetterAuthOptions["account"];
  /** The organization plugin's options (custom roles, dynamic access control). */
  organizationOptions?: Parameters<typeof organization>[0];
}

/** `@better-auth/sso`'s `organizationProvisioning` option. */
export type SsoOrganizationProvisioning = NonNullable<NonNullable<Parameters<typeof sso>[0]>["organizationProvisioning"]>;

export async function receiverHost(kind: "mcp" | "oauth-provider", o: HostOptions) {
  const common = { loginPage: "/login", consentPage: "/consent", allowDynamicClientRegistration: false, scopes: SCOPES };
  const rec = o.recorder;
  const receiver: IdJagGrantOptions = { ...o.receiver, ...(rec && !o.receiver.events ? { events: rec.events } : {}) };
  // `as unknown as BetterAuthPlugin`: these don't typecheck under exactOptionalPropertyTypes (docs/phase-0.md).
  const provider: BetterAuthPlugin[] =
    kind === "mcp"
      ? [
          mcp({ ...common, resource: MCP_RESOURCE }) as unknown as BetterAuthPlugin,
          cimd({ fetchClientMetadataResource: o.fetchClientMetadata ?? (() => Promise.reject(new Error("no client metadata fetch"))) }),
        ]
      : [oauthProvider({ ...common, resources: o.resources ?? [MCP_RESOURCE], clientRegistrationDefaultResources: o.resources ?? [MCP_RESOURCE] }) as unknown as BetterAuthPlugin];
  const ssoOptions = typeof o.sso === "object" ? { ...(o.sso.domainVerification ? { domainVerification: { enabled: true } } : {}), ...(o.sso.organizationProvisioning ? { organizationProvisioning: o.sso.organizationProvisioning } : {}) } : {};
  const ssoPlugin = o.sso ? [sso(ssoOptions) as unknown as BetterAuthPlugin] : [];
  const logs = o.logs;
  const auth = betterAuth({
    baseURL: BASE,
    secret: "test-secret-that-is-at-least-32-characters-long",
    telemetry: { enabled: false },
    database: (o.database ?? (await database())) as never,
    emailAndPassword: { enabled: true },
    plugins: [jwt(), ...provider, ...ssoPlugin, ...(o.admin ? [admin() as unknown as BetterAuthPlugin] : []), ...(o.organization ? [organization(o.organizationOptions) as unknown as BetterAuthPlugin] : []), idJagGrant(receiver)],
    ...(logs ? { logger: { level: "warn" as const, log: (level: string, message: string) => void logs.push(`${level}: ${message}`) } } : {}),
    ...(rec ? { advanced: { backgroundTasks: { handler: rec.backgroundTasks } } } : {}),
    ...(o.databaseHooks ? { databaseHooks: o.databaseHooks } : {}),
    ...(o.account ? { account: o.account } : {}),
  });
  const ctx = await auth.$context;
  await (await getMigrations(ctx.options)).runMigrations();
  return { auth, ctx };
}

export type ReceiverHost = Awaited<ReturnType<typeof receiverHost>>;

/** A fresh organization id, to configure a trust entry with before the organization exists. */
export const newOrgId = () => `org-${crypto.randomUUID()}`;

/** An organization (the organization plugin's own table) with this id and a unique slug. */
export async function createOrganization(h: ReceiverHost, id = newOrgId(), name = "Acme"): Promise<string> {
  await h.ctx.adapter.create({ model: "organization", data: { id, name, slug: `slug-${crypto.randomUUID()}`, createdAt: new Date() }, forceAllowId: true });
  return id;
}

/** The organization's members, as the organization plugin stores them. */
export async function membersOf(h: ReceiverHost, organizationId: string): Promise<{ userId: string; role: string }[]> {
  return h.ctx.adapter.findMany<{ userId: string; role: string }>({ model: "member", where: [{ field: "organizationId", value: organizationId }] });
}

/** A signed-in user (for admin-created clients), returning its session headers. */
export async function signUp(h: ReceiverHost, email = uniqueEmail()) {
  const { headers: set, response } = await h.auth.api.signUpEmail({ body: { email, password: "password-1234", name: "Ada" }, returnHeaders: true });
  return { userId: response.user.id, email, headers: new Headers({ cookie: (set.get("set-cookie") ?? "").split(";")[0] ?? "" }) };
}

export interface Client {
  client_id: string;
  client_secret: string;
}

/** A confidential client (client_secret_basic) at the receiver, registered for the jwt-bearer grant. */
export async function createClient(h: ReceiverHost, o: { headers?: Headers; grantTypes?: string[]; scope?: string | null; authMethod?: string } = {}): Promise<Client> {
  const headers = o.headers ?? (await signUp(h)).headers;
  const api = h.auth.api as unknown as { adminCreateOAuthClient: (o: { headers: Headers; body: Record<string, unknown> }) => Promise<unknown> };
  return (await api.adminCreateOAuthClient({
    headers,
    body: {
      client_name: "agent",
      redirect_uris: ["https://app.example/cb"],
      grant_types: o.grantTypes ?? [JWT_BEARER_GRANT, "authorization_code", "refresh_token"],
      token_endpoint_auth_method: o.authMethod ?? "client_secret_basic",
      ...(o.scope === null ? {} : { scope: o.scope ?? "read write openid offline_access profile" }),
      skip_consent: true,
      ...(o.authMethod === "none" ? { application_type: "native" } : {}),
    },
  })) as Client;
}

/** A local user whose account is linked to `sub` at the given account provider id. */
export async function linkedUser(h: ReceiverHost, providerId: string, sub: string, email = uniqueEmail()) {
  const user = await h.ctx.internalAdapter.createUser({ email, name: "Linked", emailVerified: true }, { method: "admin" });
  await h.ctx.internalAdapter.linkAccount({ userId: user.id, providerId, accountId: sub });
  return user;
}

/**
 * A barrier for `n` arrivals: each `wait()` resolves once `n` have arrived (or after `timeoutMs`, so
 * a test that sends fewer can't hang). The concurrency tests use it in database hooks to hold every
 * request at the same step, so a race happens on every run and runtime, not only when D1 is slow.
 */
export function barrier(n: number, timeoutMs = 5000) {
  let arrived = 0;
  let release: () => void = () => {};
  const open = new Promise<void>((resolve) => {
    release = resolve;
  });
  let timer: ReturnType<typeof setTimeout> | undefined;
  return {
    arrived: () => arrived,
    async wait() {
      arrived += 1;
      if (arrived === 1) timer = setTimeout(release, timeoutMs);
      if (arrived >= n) {
        clearTimeout(timer);
        release();
      }
      await open;
    },
  };
}

export function tokenRequest(form: Record<string, string>, basic?: { id: string; secret: string }) {
  return new Request(`${ISSUER}/oauth2/token`, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      ...(basic ? { authorization: `Basic ${btoa(`${encodeURIComponent(basic.id)}:${encodeURIComponent(basic.secret)}`)}` } : {}),
    },
    body: new URLSearchParams(form),
  });
}

/** POST the jwt-bearer grant with an assertion, as a client. */
export async function redeem(h: ReceiverHost, client: Client | null, assertion: string | undefined, extra: Record<string, string> = {}) {
  const form: Record<string, string> = { grant_type: JWT_BEARER_GRANT, ...(assertion === undefined ? {} : { assertion }), ...extra };
  const res = await h.auth.handler(tokenRequest(form, client ? { id: client.client_id, secret: client.client_secret } : undefined));
  const text = await res.text();
  let body: Record<string, unknown> = {};
  try {
    body = JSON.parse(text) as Record<string, unknown>;
  } catch {}
  return { status: res.status, text, body };
}

export const decodePayload = (jwt: string) => JSON.parse(atob((jwt.split(".")[1] ?? "").replace(/-/g, "+").replace(/_/g, "/"))) as Record<string, unknown>;
