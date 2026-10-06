// Issuer test hosts: oauthProvider() + jwt() (+ admin()) + idJagIssuer(), on node:sqlite or the
// test file's D1. ID tokens are obtained the way a client obtains them: a signed-in user's session
// cookie, GET /oauth2/authorize (PKCE, skip_consent client), then the authorization_code grant at
// /oauth2/token with the client's secret. Nothing is minted by hand.
import { betterAuth } from "better-auth";
import type { BetterAuthPlugin } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import { admin, jwt } from "better-auth/plugins";
import { oauthProvider } from "@better-auth/oauth-provider";
import { ID_JAG_TOKEN_TYPE, ID_TOKEN_TOKEN_TYPE, type RefusedEvent, type IssuedEvent, type AdminChangedEvent, type RefreshIssuedEvent, type ReasonCode, SAML2_TOKEN_TYPE, TOKEN_EXCHANGE_GRANT } from "../../src/core";
import { type IdJagIssuerOptions, idJagIssuer } from "../../src/issuer";

export const BASE = "http://localhost:3000";
export const ISSUER = `${BASE}/api/auth`;
export const AUDIENCE = "https://rs.example/api/auth";
export const RESOURCE = "https://mcp.example/mcp";
export const REDIRECT = "https://app.example/cb";
export const SECRET = "test-secret-that-is-at-least-32-characters-long";

export type Alg = "ES256" | "RS256" | "EdDSA";
const KEY_CONFIG = { ES256: { alg: "ES256" }, RS256: { alg: "RS256", modulusLength: 2048 }, EdDSA: { alg: "EdDSA", crv: "Ed25519" } } as const;

export async function database(): Promise<unknown> {
  if (navigator.userAgent === "Cloudflare-Workers") return (await import("cloudflare:test")).env.DB;
  const { DatabaseSync } = await import("node:sqlite");
  return new DatabaseSync(":memory:");
}

export const uniqueEmail = () => `u+${crypto.randomUUID()}@example.com`;

export interface Recorded {
  issued: IssuedEvent[];
  refused: RefusedEvent[];
  admin: AdminChangedEvent[];
  refreshIssued: RefreshIssuedEvent[];
}

export interface HostOptions {
  alg?: Alg;
  /** Extra jwt-plugin key configurations (for signingAlgorithm). */
  keyPairConfigs?: Alg[];
  issuer?: Omit<IdJagIssuerOptions, "events"> | undefined;
  provider?: Record<string, unknown>;
  jwt?: Record<string, unknown>;
  auth?: Record<string, unknown>;
  database?: unknown;
  /** Leave the issuer plugin out (for a host whose ID tokens are "another issuer's"). */
  withoutIssuer?: boolean;
  baseURL?: string;
  extra?: BetterAuthPlugin[];
  /** Plugins installed before the issuer (e.g. the stub SAML IdP: its init must run first). */
  before?: BetterAuthPlugin[];
}

export async function createIssuerHost(o: HostOptions = {}) {
  const recorded: Recorded = { issued: [], refused: [], admin: [], refreshIssued: [] };
  const alg = o.alg ?? "ES256";
  const pending = new Set<Promise<unknown>>();
  const provider = oauthProvider({
    loginPage: "/login",
    consentPage: "/consent",
    allowDynamicClientRegistration: false,
    scopes: ["openid", "profile", "email", "offline_access"],
    ...o.provider,
  }) as unknown as BetterAuthPlugin;
  const issuerPlugin = o.withoutIssuer
    ? []
    : [
        idJagIssuer({
          ...o.issuer,
          events: {
            onIssued: (e) => void recorded.issued.push(e),
            onRefreshIssued: (e) => void recorded.refreshIssued.push(e),
            onRefused: (e) => void recorded.refused.push(e),
            onAdminChanged: (e) => void recorded.admin.push(e),
          },
        }) as unknown as BetterAuthPlugin,
      ];
  const auth = betterAuth({
    baseURL: o.baseURL ?? BASE,
    secret: SECRET,
    telemetry: { enabled: false },
    database: (o.database ?? (await database())) as never,
    emailAndPassword: { enabled: true },
    plugins: [
      jwt({ jwks: { keyPairConfig: KEY_CONFIG[alg], ...(o.keyPairConfigs ? { keyPairConfigs: o.keyPairConfigs.map((a) => KEY_CONFIG[a]) } : {}) }, ...o.jwt }),
      provider,
      admin() as unknown as BetterAuthPlugin,
      ...(o.before ?? []),
      ...issuerPlugin,
      ...(o.extra ?? []),
    ],
    advanced: {
      backgroundTasks: {
        handler: (p: Promise<unknown>) => {
          const t = p.finally(() => pending.delete(t));
          pending.add(t);
        },
      },
    },
    ...o.auth,
  });
  const ctx = await auth.$context;
  await (await getMigrations(ctx.options)).runMigrations();
  /** Wait for background tasks (events, audit rows). */
  const settle = async () => {
    while (pending.size) await Promise.allSettled([...pending]);
  };
  const base = o.baseURL ?? BASE;
  return { auth, ctx, recorded, settle, base, issuerUrl: `${base}/api/auth` };
}

export type IssuerHost = Awaited<ReturnType<typeof createIssuerHost>>;
type Auth = IssuerHost["auth"];

/** A cookie jar for one browser. */
export class Browser {
  private jar = new Map<string, string>();
  constructor(
    private readonly auth: Auth,
    private readonly origin = BASE,
  ) {}
  get cookie() {
    return [...this.jar].map(([k, v]) => `${k}=${v}`).join("; ");
  }
  headers() {
    return new Headers({ cookie: this.cookie });
  }
  async fetch(url: string, init: RequestInit = {}) {
    const headers = new Headers(init.headers);
    if (this.cookie) headers.set("cookie", this.cookie);
    if (!headers.has("origin") && init.method && init.method !== "GET") headers.set("origin", this.origin);
    const res = await this.auth.handler(new Request(url, { ...init, headers, redirect: "manual" }));
    for (const c of res.headers.getSetCookie()) {
      const [pair] = c.split(";");
      const i = pair!.indexOf("=");
      const name = pair!.slice(0, i).trim();
      const value = pair!.slice(i + 1).trim();
      if (/max-age=0/i.test(c) || value === "") this.jar.delete(name);
      else this.jar.set(name, value);
    }
    return res;
  }
}

/** A signed-up user, signed in in its own browser. */
export async function signUp(host: IssuerHost, o: { role?: string } = {}) {
  const browser = new Browser(host.auth, host.base);
  const email = uniqueEmail();
  const res = await browser.fetch(`${host.issuerUrl}/sign-up/email`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ email, password: "password-1234", name: "Ada" }) });
  if (res.status !== 200) throw new Error(`sign-up: ${res.status} ${await res.text()}`);
  const { user } = (await res.json()) as { user: { id: string } };
  if (o.role) await host.ctx.adapter.update({ model: "user", where: [{ field: "id", value: user.id }], update: { role: o.role } });
  return { browser, email, id: user.id };
}

export interface Client {
  client_id: string;
  client_secret: string;
}

/** A client created by an admin (adminCreateOAuthClient needs a session). */
export async function createClient(host: IssuerHost, owner: Browser, o: { grantTypes?: string[]; authMethod?: string; extra?: Record<string, unknown> } = {}): Promise<Client> {
  const api = host.auth.api as unknown as { adminCreateOAuthClient: (o: { headers: Headers; body: Record<string, unknown> }) => Promise<unknown> };
  return (await api.adminCreateOAuthClient({
    headers: owner.headers(),
    body: {
      client_name: "agent",
      redirect_uris: [REDIRECT],
      grant_types: o.grantTypes ?? ["authorization_code", TOKEN_EXCHANGE_GRANT],
      response_types: ["code"],
      token_endpoint_auth_method: o.authMethod ?? "client_secret_basic",
      scope: "openid profile email",
      skip_consent: true,
      ...o.extra,
    },
  })) as Client;
}

const b64url = (bytes: Uint8Array) => {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};

export const basic = (c: { client_id: string; client_secret: string }) => `Basic ${btoa(`${encodeURIComponent(c.client_id)}:${encodeURIComponent(c.client_secret)}`)}`;

/** An ID token for this user and client, through /oauth2/authorize and the authorization_code grant. */
export async function getIdToken(host: IssuerHost, browser: Browser, client: Client, o: { scope?: string; post?: boolean } = {}): Promise<string> {
  const body = await getTokens(host, browser, client, o);
  if (!body.id_token) throw new Error(`token: no id_token ${JSON.stringify(body)}`);
  return body.id_token;
}

/** The authorization_code grant's whole response (id_token, refresh_token with offline_access). */
export async function getTokens(host: IssuerHost, browser: Browser, client: Client, o: { scope?: string; post?: boolean } = {}): Promise<{ id_token?: string; refresh_token?: string; access_token?: string }> {
  const verifier = b64url(crypto.getRandomValues(new Uint8Array(32)));
  const challenge = b64url(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))));
  const q = new URLSearchParams({ response_type: "code", client_id: client.client_id, redirect_uri: REDIRECT, scope: o.scope ?? "openid profile email", state: "s1", code_challenge: challenge, code_challenge_method: "S256" });
  const res = await browser.fetch(`${host.issuerUrl}/oauth2/authorize?${q}`);
  const location = res.headers.get("location") ?? "";
  const code = new URL(location, host.base).searchParams.get("code");
  if (!code) throw new Error(`authorize: ${res.status} ${location} ${await res.text()}`);
  const token = await host.auth.handler(
    new Request(`${host.issuerUrl}/oauth2/token`, {
      method: "POST",
      // A public client (no secret) names itself in the body.
      headers: { "content-type": "application/x-www-form-urlencoded", ...(client.client_secret && !o.post ? { authorization: basic(client) } : {}) },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: REDIRECT,
        code_verifier: verifier,
        ...(client.client_secret && !o.post ? {} : { client_id: client.client_id }),
        ...(o.post ? { client_secret: client.client_secret } : {}),
      }),
    }),
  );
  const body = (await token.json()) as { id_token?: string; refresh_token?: string; access_token?: string };
  if (token.status !== 200) throw new Error(`token: ${token.status} ${JSON.stringify(body)}`);
  return body;
}

/** The refresh_token grant at the token endpoint, as the client uses it. */
export async function refresh(host: IssuerHost, client: Client, refreshToken: string) {
  const res = await host.auth.handler(
    new Request(`${host.issuerUrl}/oauth2/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", authorization: basic(client) },
      body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: refreshToken }),
    }),
  );
  return { status: res.status, body: (await res.json()) as Record<string, unknown> };
}

/** A user, a confidential client allowed refresh tokens, and a real refresh token (scope openid offline_access). */
export async function setupRefresh(host: IssuerHost, o: { scope?: string; clientExtra?: Record<string, unknown> } = {}) {
  const owner = await signUp(host);
  const client = await createClient(host, owner.browser, {
    grantTypes: ["authorization_code", "refresh_token", TOKEN_EXCHANGE_GRANT],
    extra: { scope: "openid profile email offline_access", ...o.clientExtra },
  });
  const user = await signUp(host);
  const tokens = await getTokens(host, user.browser, client, { scope: o.scope ?? "openid profile email offline_access" });
  if (!tokens.refresh_token) throw new Error(`no refresh_token: ${JSON.stringify(tokens)}`);
  return { user, owner, client, refreshToken: tokens.refresh_token, idToken: tokens.id_token ?? "" };
}

/** The token-exchange request for an ID-JAG. `form` overrides or (with undefined) removes fields. */
export function exchangeRequest(client: Partial<Client> | null, idToken: string, form: Record<string, string | string[] | undefined> = {}, o: { headers?: Record<string, string> } = {}) {
  const base: Record<string, string | string[] | undefined> = {
    grant_type: TOKEN_EXCHANGE_GRANT,
    requested_token_type: ID_JAG_TOKEN_TYPE,
    subject_token: idToken,
    subject_token_type: ID_TOKEN_TOKEN_TYPE,
    audience: AUDIENCE,
    ...form,
  };
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(base)) {
    if (v === undefined) continue;
    for (const x of Array.isArray(v) ? v : [v]) params.append(k, x);
  }
  const headers: Record<string, string> = { "content-type": "application/x-www-form-urlencoded", ...o.headers };
  if (client?.client_id && client.client_secret) headers.authorization = basic(client as Client);
  return new Request(`${ISSUER}/oauth2/token`, { method: "POST", headers, body: params });
}

/** The exchange of a refresh token instead of an ID token. */
export const exchangeRefresh = (host: IssuerHost, client: Partial<Client> | null, refreshToken: string, form: Record<string, string | string[] | undefined> = {}) =>
  exchange(host, client, refreshToken, { subject_token_type: REFRESH_TOKEN_TYPE, ...form });

export const REFRESH_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:refresh_token";

/** POST the exchange; returns status, headers and JSON body. */
export async function exchange(host: IssuerHost, client: Partial<Client> | null, idToken: string, form: Record<string, string | string[] | undefined> = {}, o: { headers?: Record<string, string> } = {}) {
  const res = await host.auth.handler(exchangeRequest(client, idToken, form, o));
  const body = (await res.json()) as Record<string, unknown>;
  await host.settle();
  return { status: res.status, headers: res.headers, body };
}

/** A user, a confidential client, and a real ID token. */
export async function setup(host: IssuerHost, o: { clientExtra?: Record<string, unknown>; role?: string; grantTypes?: string[] } = {}) {
  // The client's owner (an administrator) and the user are different people: deleting the user
  // must not take the client with it.
  const owner = await signUp(host);
  const client = await createClient(host, owner.browser, { ...(o.clientExtra ? { extra: o.clientExtra } : {}), ...(o.grantTypes ? { grantTypes: o.grantTypes } : {}) });
  const user = await signUp(host, o.role ? { role: o.role } : {});
  const idToken = await getIdToken(host, user.browser, client);
  return { user, owner, client, idToken };
}

/** The exit criterion's check: the core's verifyIdJag against the host's JWKS, fetched over its own /jwks route. */
export async function verifyWithHostJwks(host: IssuerHost, token: string, o: { audience?: string; issuer?: string } = {}) {
  const { createLocalJWKSet } = await import("jose");
  const { verifyIdJag } = await import("../../src/core");
  const res = await host.auth.handler(new Request(`${ISSUER}/jwks`));
  if (res.status !== 200) throw new Error(`jwks: ${res.status}`);
  const jwks = createLocalJWKSet((await res.json()) as { keys: never[] });
  return verifyIdJag(token, jwks, { issuer: o.issuer ?? ISSUER, audience: o.audience ?? AUDIENCE });
}

/** The reasons of the refusals recorded since the last call (and clears them). */
export function takeReasons(host: IssuerHost): string[] {
  const reasons = host.recorded.refused.map((e) => e.reason);
  host.recorded.refused.length = 0;
  return reasons;
}

// ---------------------------------------------------------------------------------------------
// A stub of better-auth-saml-idp's exchange capability (its SamlIdpExchange, version 1), for the
// SAML subject-token paths. Not the real package: it puts a controllable fake on the context from
// `init`, as the real plugin does. Its "assertions" are not real SAML: an XML-ish string carrying an
// ID it recorded at issue(). It mimics the real verifier's order: shape, our record exists, time
// window, SP → client mapping, then consume (single use).

export const SAML_SP_ENTITY_ID = "https://agent.example/saml/sp";
export const SAML_IDP_ENTITY_ID = `${ISSUER}/saml2/idp/metadata`;
export const PERSISTENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";

/** Every code better-auth-saml-idp's verifyIssuedAssertion can throw, and the refusal it becomes here (D-B26). */
export const CODE_MAP: [string, ReasonCode][] = [
  ["MALFORMED", "invalid_subject_token"],
  ["NOT_OURS", "invalid_subject_token"],
  ["BAD_SIGNATURE", "invalid_subject_token"],
  ["NOT_EXCHANGEABLE", "invalid_subject_token"],
  ["WRONG_CLIENT", "invalid_subject_token"],
  ["ACCOUNT_INACTIVE", "invalid_subject_token"],
  ["ALREADY_EXCHANGED", "replay"],
  ["EXPIRED", "subject_token_expired"],
  ["NOT_YET_VALID", "not_yet_valid"],
];

export class FakeAssertionExchangeError extends Error {
  constructor(
    readonly code: string,
    message?: string,
  ) {
    super(message ?? code);
    this.name = "AssertionExchangeError";
  }
}

interface FakeRecord {
  id: string;
  userId: string;
  clientId: string;
  spEntityId: string;
  notBefore: Date;
  notOnOrAfter: Date;
  authnInstant: Date;
  acr?: string | undefined;
  consumed: boolean;
}

export class FakeSamlIdp {
  readonly calls: { xml: string; clientId: string; now: Date | undefined }[] = [];
  private readonly records = new Map<string, FakeRecord>();
  /** When set, every verification throws: a code string (as an AssertionExchangeError), or this value itself. */
  failWith: unknown = undefined;
  /** When set, replaces verification entirely (e.g. a fake that accepts anything). */
  override: ((xml: string, expected: { clientId: string; now?: Date }) => unknown) | undefined = undefined;
  /** What the plugin puts on the context; replace before boot to test the startup check. */
  capability: Record<string, unknown> = { version: 1, verifyIssuedAssertion: (_ctx: unknown, xml: string, expected: { clientId: string; now?: Date }) => this.verify(xml, expected) };

  /** An assertion this "IdP" issued for the user, to the SP mapped to `clientId`. */
  issue(o: { userId: string; clientId: string; spEntityId?: string; lifetimeSeconds?: number; authnInstant?: Date; notBefore?: Date; acr?: string; filler?: number }): { id: string; xml: string } {
    const id = `_${crypto.randomUUID()}`;
    const now = Date.now();
    this.records.set(id, {
      id,
      userId: o.userId,
      clientId: o.clientId,
      spEntityId: o.spEntityId ?? SAML_SP_ENTITY_ID,
      notBefore: o.notBefore ?? new Date(now - 60_000),
      notOnOrAfter: new Date(now + (o.lifetimeSeconds ?? 300) * 1000),
      authnInstant: o.authnInstant ?? new Date(Math.floor(now / 1000) * 1000 - 5000),
      acr: o.acr,
      consumed: false,
    });
    const xml = `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${id}" Version="2.0"><saml:Issuer>${SAML_IDP_ENTITY_ID}</saml:Issuer><!--é ✓ ${"x".repeat(o.filler ?? 0)}--></saml:Assertion>`;
    return { id, xml };
  }

  private async verify(xml: string, expected: { clientId: string; now?: Date }) {
    this.calls.push({ xml, clientId: expected.clientId, now: expected.now });
    if (this.override) return this.override(xml, expected);
    if (this.failWith !== undefined) throw typeof this.failWith === "string" ? new FakeAssertionExchangeError(this.failWith, `forced ${this.failWith}`) : this.failWith;
    const id = /^<saml:Assertion [^>]*ID="([^"]+)"/.exec(xml)?.[1];
    if (!id) throw new FakeAssertionExchangeError("MALFORMED");
    const r = this.records.get(id);
    if (!r) throw new FakeAssertionExchangeError("NOT_OURS");
    const now = expected.now ?? new Date();
    if (now.getTime() < r.notBefore.getTime()) throw new FakeAssertionExchangeError("NOT_YET_VALID");
    if (now.getTime() >= r.notOnOrAfter.getTime()) throw new FakeAssertionExchangeError("EXPIRED");
    if (r.clientId !== expected.clientId) throw new FakeAssertionExchangeError("WRONG_CLIENT");
    if (r.consumed) throw new FakeAssertionExchangeError("ALREADY_EXCHANGED");
    r.consumed = true;
    return this.verified(r);
  }

  /** The VerifiedAssertion for a record (also what an accept-anything override may return). */
  verified(r: { id: string; userId: string; spEntityId?: string; authnInstant?: Date; notOnOrAfter?: Date; acr?: string | undefined }) {
    return {
      assertionId: r.id,
      issuer: SAML_IDP_ENTITY_ID,
      tenantId: null,
      serviceProvider: { id: "sp-agent", entityId: r.spEntityId ?? SAML_SP_ENTITY_ID },
      userId: r.userId,
      nameId: `nameid-${r.userId}`,
      nameIdFormat: PERSISTENT,
      authnInstant: r.authnInstant ?? new Date(Date.now() - 5000),
      ...(r.acr !== undefined ? { authnContextClassRef: r.acr } : {}),
      notOnOrAfter: r.notOnOrAfter ?? new Date(Date.now() + 300_000),
    };
  }

  plugin(): BetterAuthPlugin {
    return { id: "saml-idp-stub", init: () => ({ context: { samlIdpExchange: this.capability } }) } as unknown as BetterAuthPlugin;
  }
}

const b64Bytes = (bytes: Uint8Array) => {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
};
/** base64url without padding (RFC 8693 §3). */
export const samlToken = (xml: string) => b64url(new TextEncoder().encode(xml));
/** Standard base64 with padding (the draft's example). */
export const samlTokenStd = (xml: string) => b64Bytes(new TextEncoder().encode(xml));

/** A host with the stub SAML IdP installed before the issuer. Both paths on unless `saml` says otherwise. */
export async function createSamlHost(o: HostOptions & { saml?: IdJagIssuerOptions["saml"] } = {}) {
  const idp = new FakeSamlIdp();
  const host = await createIssuerHost({ ...o, before: [idp.plugin(), ...(o.before ?? [])], issuer: { ...o.issuer, saml: o.saml ?? { subjectTokens: true, refreshTokens: {} } } });
  return { ...host, idp };
}
export type SamlHost = Awaited<ReturnType<typeof createSamlHost>>;

/** A user, and a confidential client allowed refresh_token and token exchange (scopes include offline_access). */
export async function setupSaml(host: IssuerHost, o: { grantTypes?: string[]; clientExtra?: Record<string, unknown>; authMethod?: string } = {}) {
  const owner = await signUp(host);
  const client = await createClient(host, owner.browser, {
    grantTypes: o.grantTypes ?? ["authorization_code", "refresh_token", TOKEN_EXCHANGE_GRANT],
    ...(o.authMethod ? { authMethod: o.authMethod } : {}),
    extra: { scope: "openid profile email offline_access", ...o.clientExtra },
  });
  const user = await signUp(host);
  return { owner, client, user };
}

/** Path (a): a SAML assertion for an ID-JAG. */
export const exchangeSaml = (host: IssuerHost, client: Partial<Client> | null, token: string, form: Record<string, string | string[] | undefined> = {}) =>
  exchange(host, client, token, { subject_token_type: SAML2_TOKEN_TYPE, ...form });

/** Path (b): a SAML assertion for a refresh token (draft -04 §4.5). */
export const requestSamlRefresh = (host: IssuerHost, client: Partial<Client> | null, token: string, form: Record<string, string | string[] | undefined> = {}) =>
  exchange(host, client, token, { requested_token_type: REFRESH_TOKEN_TYPE, subject_token_type: SAML2_TOKEN_TYPE, audience: undefined, scope: "openid offline_access", ...form });

/** RFC 7009 revocation at the provider, as the client does it. */
export async function revoke(host: IssuerHost, client: Client, token: string, hint = "refresh_token") {
  const res = await host.auth.handler(
    new Request(`${host.issuerUrl}/oauth2/revoke`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", authorization: basic(client) },
      body: new URLSearchParams({ token, token_type_hint: hint }),
    }),
  );
  return res.status;
}
