// "Test your IdP": a public, locked-down ID-JAG receiver for people building an ID-JAG issuer. A tester signs in
// with GitHub or GitLab, registers their issuer, gets a client here for 24 hours, redeems ID-JAGs at the token endpoint, and
// reads a rule-by-rule report next to what the real receiver (this package) decided. docs/test-your-idp.md.
//
// Routes: / (home), POST /signin, POST /signout, /register, /results, POST /delete, POST /api/auth/oauth2/token (the
// receiver, wrapped), /mcp, the Better Auth paths a sign-in and a client need (nothing else under /api/auth), /admin/*
// (bearer keys). While the tester is closed, only /, /admin, sign-out and /delete answer. Limits are in LIMITS.
import { decodeBasicCredentials, encodeBasicCredentials } from "@better-auth/core/oauth2";
import { createLocalJWKSet, jwtVerify } from "jose";
import { JWT_BEARER_GRANT, TRUSTED_ISSUER_MODEL } from "better-auth-id-jag";
import { withExecutionContext } from "../../background";
import { createAuth, type Env, internalKey, providers, SCOPES } from "./auth";
import { checkIdJag, checkIssuerMetadata, type RuleResult } from "./checks";
import { checkPublicHttpsUrl, fetchJsonCapped, oauthMetadataUrl, openIdConfigurationUrl } from "./guard";
import { APP_JS } from "./app";
import { CHECKED_AGAINST, LIMITS } from "./limits";
import { LOGO_SVG } from "./logo";
import { landing, message, page, registered, registerForm, results, type ResultView } from "./pages";
import { ageBucket, BLOCK_KEY_ID, fingerprint, fingerprintKey, network, weekKeyId } from "./privacy";
import { open, seal } from "./seal";
import * as store from "./store";

const cache = new Map<string, ReturnType<typeof createAuth>>();
const authFor = (env: Env, origin: string) => {
  let auth = cache.get(origin);
  if (!auth) {
    auth = createAuth(env, origin);
    cache.set(origin, auth);
  }
  return auth;
};

const oauthError = (status: number, error: string, description: string) => Response.json({ error, error_description: description }, { status, headers: { "cache-control": "no-store" } });
const clientIp = (request: Request) => request.headers.get("cf-connecting-ip") ?? "unknown";
const newId = () => [...crypto.getRandomValues(new Uint8Array(12))].map((b) => b.toString(36).padStart(2, "0")).join("").slice(0, 20);
const redirect = (location: string) => new Response(null, { status: 302, headers: { location } });

/** A request body, read up to the limit whether or not it declares its length; null when it is larger. */
async function readBody(request: Request): Promise<string | null> {
  if (Number(request.headers.get("content-length") ?? "0") > LIMITS.maxBodyBytes) return null;
  const reader = request.body?.getReader();
  if (!reader) return "";
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > LIMITS.maxBodyBytes) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const c of chunks) {
    bytes.set(c, offset);
    offset += c.byteLength;
  }
  return new TextDecoder().decode(bytes);
}

/** Is the tester open? The deploy-level switch (TESTER_ENABLED) and the stored one (closed by a rule, the watcher or the operator). */
async function openState(env: Env): Promise<{ open: boolean; reason: string | null }> {
  if (env.TESTER_ENABLED !== "true") return { open: false, reason: "disabled in the deployment" };
  const s = await store.isClosed(env.DB);
  return { open: !s.closed, reason: s.reason };
}

async function session(env: Env, origin: string, request: Request) {
  return authFor(env, origin).api.getSession({ headers: request.headers });
}

/** The same origin, for every POST a browser makes (cookies are SameSite=Lax; this closes the rest to other sites). */
const sameOrigin = (request: Request, origin: string) => request.headers.get("origin") === origin;

async function signIn(request: Request, env: Env, origin: string): Promise<Response> {
  if (!sameOrigin(request, origin)) return message("Not allowed", "Sign in from this site's own page.", 403);
  const body = await readBody(request);
  const provider = new URLSearchParams(body ?? "").get("provider");
  if (provider !== "github" && provider !== "gitlab") return message("Not allowed", "Sign in with GitHub or GitLab.", 400);
  if (!providers(env).includes(provider)) return message("Not available", "That sign-in isn't offered here.", 400);
  const { headers, response } = await authFor(env, origin).api.signInSocial({ body: { provider, callbackURL: "/register", errorCallbackURL: "/?signin=failed" }, headers: request.headers, returnHeaders: true });
  const out = redirect((response as { url: string }).url);
  for (const c of headers.getSetCookie()) out.headers.append("set-cookie", c);
  return out;
}

async function signOut(request: Request, env: Env, origin: string): Promise<Response> {
  if (!sameOrigin(request, origin)) return message("Not allowed", "Sign out from this site's own page.", 403);
  const out = redirect("/");
  try {
    const { headers } = await authFor(env, origin).api.signOut({ headers: request.headers, returnHeaders: true });
    for (const c of headers.getSetCookie()) out.headers.append("set-cookie", c);
  } catch {
    // Not signed in: nothing to do.
  }
  return out;
}

/** The provider account behind a session: which provider, and its account id there (for the fingerprints). */
async function testerAccount(env: Env, origin: string, userId: string): Promise<{ provider: "github" | "gitlab"; accountId: string } | null> {
  const ctx = await authFor(env, origin).$context;
  const account = (await ctx.internalAdapter.findAccounts(userId)).find((a) => a.providerId === "github" || a.providerId === "gitlab");
  return account ? { provider: account.providerId as "github" | "gitlab", accountId: account.accountId } : null;
}

async function verifyTurnstile(env: Env, token: string | null): Promise<boolean> {
  if (!token) return false;
  try {
    const r = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", { method: "POST", body: new URLSearchParams({ secret: env.TURNSTILE_SECRET_KEY, response: token.slice(0, 2048) }), signal: AbortSignal.timeout(5_000) });
    return r.ok && ((await r.json()) as { success?: boolean }).success === true;
  } catch {
    return false;
  }
}

const isJwks = (v: unknown): v is { keys: Record<string, unknown>[] } => typeof v === "object" && v !== null && Array.isArray((v as { keys?: unknown }).keys);

async function register(request: Request, env: Env, origin: string): Promise<Response> {
  const s = await session(env, origin, request);
  if (!s) return redirect("/");
  if (request.method === "GET") return registerForm(env.TURNSTILE_SITE_KEY);
  if (!sameOrigin(request, origin)) return message("Not allowed", "Register from this site's own page.", 403);
  const body = await readBody(request);
  if (body === null) return registerForm(env.TURNSTILE_SITE_KEY, "The form is too large.");
  const form = new URLSearchParams(body);
  const ip = clientIp(request);
  if (!(await verifyTurnstile(env, form.get("cf-turnstile-response")))) {
    store.bump("register.turnstile_failed");
    return registerForm(env.TURNSTILE_SITE_KEY, "The bot check failed. Try again.");
  }

  const now = Date.now();
  if (await store.activeByUser(env.DB, s.user.id, now)) return registerForm(env.TURNSTILE_SITE_KEY, "You already have an active registration: one at a time. See your results.");
  const account = await testerAccount(env, origin, s.user.id);
  const createdRaw = (s.user as { accountCreatedAt?: unknown }).accountCreatedAt;
  const accountCreatedAt = createdRaw instanceof Date ? createdRaw.getTime() : typeof createdRaw === "string" || typeof createdRaw === "number" ? new Date(createdRaw).getTime() : Number.NaN;
  if (!account || !Number.isFinite(accountCreatedAt)) return registerForm(env.TURNSTILE_SITE_KEY, "Couldn't read your account's details. Sign out and sign in again.");
  if (now - accountCreatedAt < LIMITS.accountMinAgeDays * store.DAY_MS) {
    store.bump("register.young_account");
    return registerForm(env.TURNSTILE_SITE_KEY, `Accounts must be at least ${LIMITS.accountMinAgeDays} days old.`);
  }
  // The blocklist, by fingerprint: an account or network caught abusing the tester stays out for 30 days.
  const accountRef = `${account.provider}:${account.accountId}`;
  const blockKey = await fingerprintKey(env.DB, BLOCK_KEY_ID, now);
  const blockAccountFp = await fingerprint(blockKey, accountRef);
  const blockNetFp = await fingerprint(blockKey, network(ip));
  if (await store.isBlocked(env.DB, [blockAccountFp, blockNetFp], now)) {
    store.bump("register.blocked");
    return registerForm(env.TURNSTILE_SITE_KEY, "This account or network can't register here for now.");
  }

  const issuer = (form.get("issuer") ?? "").trim();
  const authMethod = form.get("authMethod") === "client_secret_post" ? "client_secret_post" : "client_secret_basic";
  const urlCheck = checkPublicHttpsUrl(issuer);
  if (!urlCheck.ok) return registerForm(env.TURNSTILE_SITE_KEY, `The issuer ${urlCheck.why}.`);
  if (urlCheck.url.search) return registerForm(env.TURNSTILE_SITE_KEY, "An issuer identifier has no query string (RFC 8414 section 2).");
  // Only a registration that proved the issuer (its first ID-JAG signed with the issuer's key) holds it.
  if (await store.confirmedByIssuer(env.DB, issuer, now)) return registerForm(env.TURNSTILE_SITE_KEY, "Another tester has proven that issuer (with an ID-JAG signed by its key) and holds it for now. Registrations last 24 hours.");

  // The issuer's metadata: RFC 8414's location first, then OpenID Connect Discovery's. Nothing is written before this.
  let source: "oauth-authorization-server" | "openid-configuration" = "oauth-authorization-server";
  let meta = await fetchJsonCapped(fetch, oauthMetadataUrl(urlCheck.url));
  if (!meta.ok) {
    source = "openid-configuration";
    meta = await fetchJsonCapped(fetch, openIdConfigurationUrl(urlCheck.url));
  }
  if (!meta.ok || typeof meta.json !== "object" || meta.json === null || Array.isArray(meta.json)) return registerForm(env.TURNSTILE_SITE_KEY, `No metadata found at ${oauthMetadataUrl(urlCheck.url)} or ${openIdConfigurationUrl(urlCheck.url)}${meta.ok ? "" : ` (${meta.why})`}.`);
  const metadata = meta.json as Record<string, unknown>;
  const jwksUri = typeof metadata.jwks_uri === "string" ? metadata.jwks_uri : "";
  const jwks = jwksUri ? await fetchJsonCapped(fetch, jwksUri) : ({ ok: false, why: "no jwks_uri" } as const);
  const check = checkIssuerMetadata({ issuer, source, metadata, jwks: jwks.ok ? jwks.json : null });
  if (!jwks.ok) check.results.push({ id: "jwks.fetch", level: "MUST", cite: "draft -06 section 7.1", outcome: "fail", message: `Your JWKS ${jwks.why}.` });
  if (check.blocking.length > 0 || !jwks.ok) return registerForm(env.TURNSTILE_SITE_KEY, `Not registered: ${check.results.filter((r) => r.outcome === "fail").map((r) => r.message).join(" ")}`);

  // Reserve the registration (pending) and its abuse record first, in one transaction that checks every limit: two
  // requests at once can't both pass. The abuse record holds fingerprints under this week's key, never the account
  // or the address.
  const id = newId();
  // A registration ends when the sign-in does (at most 24 hours), so nothing about the tester outlives their day.
  const expiresAt = Math.min(now + LIMITS.registrationHours * 3_600_000, new Date(s.session.expiresAt).getTime());
  const keyId = weekKeyId(now);
  const weekKey = await fingerprintKey(env.DB, keyId, now);
  const abuse = { id, at: now, keyId, provider: account.provider, accountFp: await fingerprint(weekKey, accountRef), ipFp: await fingerprint(weekKey, ip), netFp: await fingerprint(weekKey, network(ip)), blockAccountFp, blockNetFp, accountAge: ageBucket(accountCreatedAt, now), issuerHost: urlCheck.url.host };
  const reserved = await store.reserve(env.DB, { id, userId: s.user.id, issuer, jwksUri, jwks: JSON.stringify(jwks.json), jwksFetchedAt: now, clientId: "", trustRowId: "", authMethod, metadataReport: JSON.stringify(check.results), createdAt: now, expiresAt, confirmedAt: null, revokedAt: null, revokedReason: null }, abuse, { day: store.utcDayStart(now), perDay: LIMITS.registrationsPerDay, perAccount: LIMITS.registrationsPerAccountPerDay, perIp: LIMITS.registrationsPerIpPerDay });
  if (!reserved) {
    store.bump("register.limit");
    return registerForm(env.TURNSTILE_SITE_KEY, "Not registered: you already have one, another tester has proven the issuer, or today's registrations are used up (they reset at 00:00 UTC).");
  }

  // The client here, owned by the tester's user, only for redeeming ID-JAGs. The trust row comes when the registration
  // is confirmed (token endpoint).
  const auth = authFor(env, origin);
  let clientId: string | undefined;
  try {
    const headers = new Headers({ cookie: request.headers.get("cookie") ?? "", "x-tester-internal": internalKey() });
    const api = auth.api as unknown as { adminCreateOAuthClient(o: { headers: Headers; body: Record<string, unknown> }): Promise<{ client_id: string; client_secret: string }> };
    const client = await api.adminCreateOAuthClient({
      headers,
      body: { client_name: `Tester registration ${id}`, grant_types: [JWT_BEARER_GRANT], response_types: [], token_endpoint_auth_method: authMethod, scope: SCOPES.join(" ") },
    });
    clientId = client.client_id;
    await store.setClient(env.DB, id, clientId, await seal(env.BETTER_AUTH_SECRET, client.client_secret));
    console.log(JSON.stringify({ event: "tester.registered", id, issuerHost: urlCheck.url.host }));
    return registered({ origin, registrationId: id, clientId, clientSecret: client.client_secret, authMethod, issuer, expiresAt, report: check.results });
  } catch (e) {
    await store.abandon(env.DB, id, clientId);
    throw e;
  }
}

/** The trust row for a confirmed registration: its issuer, its JWKS, its client alone. */
async function createTrustRow(env: Env, origin: string, reg: store.Registration, now: number): Promise<string> {
  const ctx = await authFor(env, origin).$context;
  const trust = await ctx.adapter.create<Record<string, unknown>, { id: string }>({
    model: TRUSTED_ISSUER_MODEL,
    data: { issuer: reg.issuer, jwksUri: reg.jwksUri, allowedClientIds: JSON.stringify([reg.clientId]), jitProvisioning: false, jitTrustEmailVerified: false, enabled: true, createdAt: new Date(now), updatedAt: new Date(now) },
  });
  return trust.id;
}

/**
 * The client a token request names, read exactly as the receiver reads it (Better Auth's own decodeBasicCredentials),
 * so the request the tester charges is the request the receiver authenticates. An Authorization header together with
 * client fields in the body is refused (RFC 6749 section 2.3: one method), whatever the header's scheme.
 */
function requestClientId(request: Request, form: URLSearchParams): { clientId?: string; both: boolean } {
  const authorization = request.headers.get("authorization");
  const inBody = form.has("client_id") || form.has("client_secret") || form.has("client_assertion");
  if (authorization) {
    if (inBody) return { both: true };
    try {
      return { clientId: decodeBasicCredentials(authorization).clientId, both: false };
    } catch {
      return { both: false };
    }
  }
  const id = form.get("client_id");
  return id ? { clientId: id, both: false } : { both: false };
}

/**
 * The receiver's token endpoint, with limits in front and the rule-by-rule report recorded after. Only a request the
 * receiver authenticated is counted or recorded: a client id is no secret (it is in every ID-JAG), so nobody else's
 * requests can use up a tester's budget or appear in their results.
 */
async function token(request: Request, env: Env, origin: string, ctx: ExecutionContext): Promise<Response> {
  const body = await readBody(request);
  if (body === null) return oauthError(400, "invalid_request", "The request is too large.");
  const form = new URLSearchParams(body);
  if (form.get("grant_type") !== JWT_BEARER_GRANT) return oauthError(400, "unsupported_grant_type", `This tester only redeems ID-JAGs (grant_type ${JWT_BEARER_GRANT}).`);
  const named = requestClientId(request, form);
  if (named.both) return oauthError(400, "invalid_request", "Use one client authentication method, not two (RFC 6749 section 2.3).");
  const clientId = named.clientId;
  const now = Date.now();
  const reg = clientId ? await store.activeByClient(env.DB, clientId, now) : null;
  if (!reg || !clientId) {
    store.bump("token.unknown_client");
    return oauthError(401, "invalid_client", "Unknown or expired client. Register at the tester's home page.");
  }
  const ip = clientIp(request);
  if (!(await env.TOKEN_LIMIT.limit({ key: `client:${clientId}:${ip}` })).success) {
    store.bump("ratelimited.client");
    return oauthError(429, "slow_down", "At most 10 redemptions a minute per client.");
  }
  const day = store.utcDayStart(now);
  if ((await store.countChecks(env.DB, day, reg.id)) >= LIMITS.redemptionsPerRegistrationPerDay) return oauthError(429, "slow_down", `At most ${LIMITS.redemptionsPerRegistrationPerDay} redemptions a day per registration; more after 00:00 UTC.`);
  if ((await store.countChecks(env.DB, day)) >= LIMITS.redemptionsPerDay) {
    store.bump("token.daily_budget");
    console.log(JSON.stringify({ event: "tester.budget_reached", day: new Date(day).toISOString().slice(0, 10) }));
    return oauthError(503, "temporarily_unavailable", "Today's redemptions are used up; more after 00:00 UTC.");
  }

  // The report: every rule, with the issuer's keys (refetched at most once a minute when the kid is new).
  const assertion = form.get("assertion") ?? "";
  let jwks: unknown = null;
  try {
    jwks = JSON.parse(reg.jwks);
  } catch {
    jwks = null;
  }
  const kid = (() => {
    try {
      return (JSON.parse(atob((assertion.split(".")[0] ?? "").replace(/-/g, "+").replace(/_/g, "/"))) as { kid?: unknown }).kid;
    } catch {
      return undefined;
    }
  })();
  if ((!isJwks(jwks) || (typeof kid === "string" && !jwks.keys.some((k) => k.kid === kid))) && now - reg.jwksFetchedAt > 60_000) {
    const fresh = await fetchJsonCapped(fetch, reg.jwksUri);
    if (fresh.ok && isJwks(fresh.json)) {
      jwks = fresh.json;
      await store.updateJwks(env.DB, reg.id, JSON.stringify(fresh.json), now);
    }
  }
  const report = await checkIdJag(assertion, {
    issuer: reg.issuer,
    audience: `${origin}/api/auth`,
    resource: `${origin}/mcp`,
    grantableScopes: SCOPES,
    clientId,
    jwks: isJwks(jwks) ? (jwks as never) : null,
    now: Math.floor(now / 1000),
  });

  // The real decision: the published receiver, unchanged.
  const headers = new Headers(request.headers);
  headers.delete("content-length");
  // The receiver's audit would keep the caller's user agent: it isn't needed, so it isn't sent.
  headers.delete("user-agent");
  const forward = () => authFor(env, origin).handler(new Request(request.url, { method: "POST", headers, body }));
  let response = await forward();
  let answer = (await response.clone().json().catch(() => null)) as { error?: unknown } | null;
  if (response.status === 401 || answer?.error === "invalid_client") {
    store.bump("token.auth_failed");
    ctx.waitUntil(store.flushCounters(env.DB, Date.now()));
    return response;
  }
  const jti = typeof report.claims?.jti === "string" ? report.claims.jti.replace(/[^\x20-\x7e]/g, "").slice(0, 200) : null;
  const record = (status: number, error: string | null) =>
    ctx.waitUntil(
      (async () => {
        await store.insertCheck(env.DB, { id: newId(), registrationId: reg.id, at: now, jti, httpStatus: status, error, results: JSON.stringify(report.results), checkedAgainst: CHECKED_AGAINST });
        if (status >= 500 && (await store.countServerErrors(env.DB, now - 600_000)) >= LIMITS.serverErrorsPer10Min) {
          await store.setClosed(env.DB, true, `${LIMITS.serverErrorsPer10Min} server errors in 10 minutes`, "worker", Date.now());
          console.log(JSON.stringify({ event: "tester.closed", by: "worker", reason: "server errors" }));
        }
        await store.flushCounters(env.DB, Date.now());
      })(),
    );

  // A pending registration has no trust row, so the receiver refused it (after authenticating the client, which is
  // why it was asked). It is confirmed by an ID-JAG signed with a key from the issuer's own JWKS: proof that the
  // tester runs the issuer. Then the trust row is made and the same request goes to the receiver again.
  if (reg.confirmedAt === null) {
    const proven = ["signature", "claim.iss", "claim.client_id"].every((id) => report.results.find((r) => r.id === id)?.outcome === "pass");
    if (!proven) {
      record(400, "not_confirmed");
      return oauthError(400, "invalid_grant", "This registration is pending: it is confirmed by an ID-JAG signed with a key from your issuer's published JWKS, with your issuer as iss and this client as client_id. See your results for what this one got wrong.");
    }
    await store.purge(env.DB, now, reg.issuer);
    if (await store.confirm(env.DB, reg.id, now)) {
      let trustRowId: string | undefined;
      try {
        trustRowId = await createTrustRow(env, origin, { ...reg, confirmedAt: now }, now);
        await store.setTrustRow(env.DB, reg.id, trustRowId);
      } catch (e) {
        await store.unconfirm(env.DB, reg.id, trustRowId);
        throw e;
      }
      console.log(JSON.stringify({ event: "tester.confirmed", id: reg.id }));
    } else {
      // Not confirmed by this request: either another tester proved the issuer first, or another request of this same
      // registration just did (then this one is redeemed like any other once the trust row exists).
      const fresh = await store.byId(env.DB, reg.id);
      if (!fresh?.confirmedAt || !fresh.trustRowId) {
        record(400, fresh?.confirmedAt ? "confirming" : "issuer_taken");
        return fresh?.confirmedAt
          ? oauthError(400, "invalid_grant", "Your registration is being confirmed by another request right now: try this one again.")
          : oauthError(400, "invalid_grant", "Another tester has proven this issuer first and holds it for now. Registrations last 24 hours.");
      }
    }
    response = await forward();
    answer = (await response.clone().json().catch(() => null)) as { error?: unknown } | null;
  }
  record(response.status, typeof answer?.error === "string" ? answer.error.slice(0, 64) : null);
  return response;
}

/** The MCP server: whoami and checks (the latest reports for the token's client), read-only, while the registration lasts. */
async function mcpEndpoint(request: Request, env: Env, origin: string): Promise<Response> {
  const challenge = { "WWW-Authenticate": `Bearer resource_metadata="${origin}/.well-known/oauth-protected-resource/mcp"` };
  const bearer = request.headers.get("authorization")?.match(/^Bearer (.+)$/i)?.[1];
  if (!bearer) return Response.json({ jsonrpc: "2.0", id: null, error: { code: -32001, message: "unauthorized" } }, { status: 401, headers: challenge });
  const invalid = () => Response.json({ jsonrpc: "2.0", id: null, error: { code: -32001, message: "invalid token" } }, { status: 401, headers: { "WWW-Authenticate": `${challenge["WWW-Authenticate"]}, error="invalid_token"` } });
  const auth = authFor(env, origin);
  const keys = (await (await auth.handler(new Request(`${origin}/api/auth/jwks`))).json()) as Parameters<typeof createLocalJWKSet>[0];
  let claims: Record<string, unknown>;
  try {
    claims = (await jwtVerify(bearer, createLocalJWKSet(keys), { issuer: `${origin}/api/auth`, audience: `${origin}/mcp` })).payload;
  } catch {
    return invalid();
  }
  const clientId = typeof claims.azp === "string" ? claims.azp : typeof claims.client_id === "string" ? claims.client_id : "";
  // A revoked or expired registration's tokens stop here at once, not when they expire.
  const reg = clientId ? await store.activeByClient(env.DB, clientId, Date.now()) : null;
  if (!reg) return invalid();
  if (!(await env.MCP_LIMIT.limit({ key: `mcp:${clientId}` })).success) {
    store.bump("ratelimited.mcp");
    return Response.json({ jsonrpc: "2.0", id: null, error: { code: -32000, message: "at most 30 calls a minute" } }, { status: 429 });
  }
  if (request.method !== "POST") return new Response(null, { status: 405, headers: { allow: "POST" } });
  const raw = await readBody(request);
  let rpc: { id?: unknown; method?: string; params?: { protocolVersion?: string; name?: string } } = {};
  try {
    rpc = raw ? JSON.parse(raw) : {};
  } catch {
    rpc = {};
  }
  const reply = (result: unknown) => Response.json({ jsonrpc: "2.0", id: rpc.id ?? null, result });
  const text = (value: unknown) => ({ content: [{ type: "text", text: JSON.stringify(value) }] });
  switch (rpc.method) {
    case "initialize":
      return reply({ protocolVersion: typeof rpc.params?.protocolVersion === "string" ? rpc.params.protocolVersion.slice(0, 20) : "2025-06-18", capabilities: { tools: {} }, serverInfo: { name: "idjag-tester", version: "0.1.0" } });
    case "notifications/initialized":
      return new Response(null, { status: 202 });
    case "ping":
      return reply({});
    case "tools/list":
      return reply({
        tools: [
          { name: "whoami", description: "The access token's claims: who the receiver says you are (scope: read)", inputSchema: { type: "object", properties: {} } },
          { name: "checks", description: "The latest rule-by-rule reports for your client (scope: read)", inputSchema: { type: "object", properties: {} } },
        ],
      });
    case "tools/call": {
      if (rpc.params?.name === "whoami") return reply(text({ sub: claims.sub, scope: claims.scope, act: claims.act ?? null, aud: claims.aud, idjag: claims.idjag ?? null, exp: claims.exp }));
      if (rpc.params?.name === "checks") {
        const rows = await store.recentChecks(env.DB, reg.id, 5);
        return reply(text(rows.map((c) => ({ at: new Date(c.at).toISOString(), checkedAgainst: c.checkedAgainst, jti: c.jti, httpStatus: c.httpStatus, error: c.error, failed: (JSON.parse(c.results) as RuleResult[]).filter((r) => r.outcome === "fail").map((r) => ({ id: r.id, cite: r.cite, message: r.message })) }))));
      }
      return Response.json({ jsonrpc: "2.0", id: rpc.id ?? null, error: { code: -32602, message: "unknown tool" } });
    }
    default:
      return Response.json({ jsonrpc: "2.0", id: rpc.id ?? null, error: { code: -32601, message: "method not found" } });
  }
}

async function resultsPage(request: Request, env: Env, origin: string): Promise<Response> {
  const s = await session(env, origin, request);
  if (!s) return redirect("/");
  const now = Date.now();
  const views: ResultView[] = [];
  for (const reg of await store.byUser(env.DB, s.user.id)) {
    if (!reg.clientId) continue;
    const refusals = await store.receiverRefusals(env.DB, reg.clientId);
    views.push({
      registrationId: reg.id,
      active: reg.revokedAt === null && reg.expiresAt > now && !!reg.clientSecretEnc,
      issuer: reg.issuer,
      clientId: reg.clientId,
      expiresAt: reg.expiresAt,
      pending: reg.confirmedAt === null,
      ended: reg.revokedAt ? `revoked (${reg.revokedReason ?? "no reason given"})` : reg.expiresAt <= now ? "expired; deleted within minutes" : null,
      metadata: JSON.parse(reg.metadataReport) as RuleResult[],
      checks: (await store.recentChecks(env.DB, reg.id)).map((c) => ({ at: c.at, checkedAgainst: c.checkedAgainst, jti: c.jti, httpStatus: c.httpStatus, error: c.error, results: JSON.parse(c.results) as RuleResult[], receiver: TESTER_REFUSALS.has(c.error ?? "") ? null : store.decisionFor(c, refusals) })),
    });
  }
  return results(views, s.user.name, origin);
}

/** Refusals the tester makes itself, before the receiver decides: the page shows these, not the receiver's. */
const TESTER_REFUSALS = new Set(["not_confirmed", "issuer_taken", "confirming"]);

/**
 * "Check an ID-JAG": the tester redeems a pasted ID-JAG with the registration's own client, through the same token
 * endpoint (limits, report, confirmation and all), then shows the results page.
 */
async function checkPasted(request: Request, env: Env, origin: string, ctx: ExecutionContext): Promise<Response> {
  if (!sameOrigin(request, origin)) return message("Not allowed", "Check from this site's own page.", 403);
  const s = await session(env, origin, request);
  if (!s) return redirect("/");
  const body = await readBody(request);
  if (body === null) return message("Too large", "That's larger than any ID-JAG.", 400);
  const form = new URLSearchParams(body);
  const now = Date.now();
  const reg = await store.byId(env.DB, form.get("registration") ?? "");
  if (!reg || reg.userId !== s.user.id || reg.revokedAt !== null || reg.expiresAt <= now || !reg.clientId || !reg.clientSecretEnc) return message("Not found", "No such active registration of yours.", 404);
  const secret = await open(env.BETTER_AUTH_SECRET, reg.clientSecretEnc);
  if (!secret) return message("Can't check", "This registration's client can't be used here. Register again.", 409);
  const params = new URLSearchParams({ grant_type: JWT_BEARER_GRANT, assertion: (form.get("assertion") ?? "").replace(/\s+/g, "") });
  const headers = new Headers({ "content-type": "application/x-www-form-urlencoded", "cf-connecting-ip": clientIp(request) });
  if (reg.authMethod === "client_secret_post") {
    params.set("client_id", reg.clientId);
    params.set("client_secret", secret);
  } else headers.set("authorization", encodeBasicCredentials(reg.clientId, secret));
  // The report is written in the background: wait for it, so the results page shows it.
  const pending: Promise<unknown>[] = [];
  const local = { waitUntil: (p: Promise<unknown>) => pending.push(p), passThroughOnException: () => {}, props: {} } as unknown as ExecutionContext;
  const response = await token(new Request(`${origin}/api/auth/oauth2/token`, { method: "POST", headers, body: params.toString() }), env, origin, local);
  await Promise.allSettled(pending);
  if (response.status === 429 || response.status === 503) {
    const answer = (await response.json().catch(() => ({}))) as { error_description?: string };
    return message("Not checked", answer.error_description ?? "Try again in a minute.", response.status);
  }
  return redirect("/results");
}

/** "Delete my data now": the tester's registrations, everything they made, and the tester's own records, at once. */
async function deleteMyData(request: Request, env: Env, origin: string): Promise<Response> {
  if (!sameOrigin(request, origin)) return message("Not allowed", "Use the button on this site's own page.", 403);
  const s = await session(env, origin, request);
  if (!s) return redirect("/");
  const out = message("Deleted", "Your registrations, their results, and your sign-in record are deleted. Only the anonymous abuse record remains, for up to 7 days.", 200);
  try {
    const { headers } = await authFor(env, origin).api.signOut({ headers: request.headers, returnHeaders: true });
    for (const c of headers.getSetCookie()) out.headers.append("set-cookie", c);
  } catch {
    // The session is deleted below either way.
  }
  await store.deleteTester(env.DB, s.user.id, Date.now());
  console.log(JSON.stringify({ event: "tester.deleted_own_data" }));
  return out;
}

/** Constant-time comparison of a bearer key against a configured one; an unset or short key never matches. */
async function keyMatches(request: Request, expected: string | undefined): Promise<boolean> {
  const given = request.headers.get("authorization")?.match(/^Bearer (.+)$/)?.[1];
  if (!given || !expected || expected.length < 32) return false;
  const digest = async (s: string) => new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)));
  return crypto.subtle.timingSafeEqual(await digest(given), await digest(expected));
}

/**
 * The watcher's and the operator's controls. STATS reads; CLOSE closes the tester, revokes or blocks, and can never
 * reopen anything; OPEN (the operator's alone) reopens. The key is checked before the body is read.
 */
async function admin(request: Request, env: Env, url: URL): Promise<Response> {
  if (!(await env.IP_LIMIT.limit({ key: `admin:${clientIp(request)}` })).success) return new Response("slow down", { status: 429 });
  const now = Date.now();
  const route = `${request.method} ${url.pathname}`;
  const allowed =
    route === "GET /admin/stats" ? await keyMatches(request, env.ADMIN_STATS_KEY)
    : route === "POST /admin/close" || route === "POST /admin/revoke" || route === "POST /admin/block" ? (await keyMatches(request, env.ADMIN_CLOSE_KEY)) || (await keyMatches(request, env.ADMIN_OPEN_KEY))
    : route === "POST /admin/open" ? await keyMatches(request, env.ADMIN_OPEN_KEY)
    : null;
  if (allowed === null) return new Response("not found", { status: 404 });
  if (!allowed) return new Response("forbidden", { status: 403 });
  if (route === "GET /admin/stats") return Response.json(await store.stats(env.DB, now), { headers: { "cache-control": "no-store" } });
  const raw = await readBody(request);
  let body: { reason?: unknown; registrationId?: unknown; kinds?: unknown } = {};
  try {
    body = raw ? JSON.parse(raw) : {};
  } catch {
    body = {};
  }
  const reason = typeof body.reason === "string" && body.reason ? body.reason : "no reason given";
  if (route === "POST /admin/close") {
    await store.setClosed(env.DB, true, reason, "admin", now);
    console.log(JSON.stringify({ event: "tester.closed", by: "admin", reason }));
    return Response.json({ closed: true });
  }
  if (route === "POST /admin/block") {
    // Blocks the account and/or network behind a registration (by its id, which is also its abuse record's) for 30
    // days, and ends the registration if it still exists. Works for the abuse record's 7 days.
    if (typeof body.registrationId !== "string") return new Response("registrationId required", { status: 400 });
    const reg = await store.abuseById(env.DB, body.registrationId);
    if (!reg) return new Response("no such registration in the last 7 days", { status: 404 });
    const kinds = Array.isArray(body.kinds) ? body.kinds.filter((k): k is "account" | "network" => k === "account" || k === "network") : ["account" as const];
    if (kinds.length === 0) return new Response("kinds: account and/or network", { status: 400 });
    await store.block(env.DB, reg, kinds, reason, now);
    console.log(JSON.stringify({ event: "tester.blocked", registrationId: reg.id, kinds, reason }));
    return Response.json({ blocked: kinds, revoked: true });
  }
  if (route === "POST /admin/revoke") {
    if (typeof body.registrationId !== "string") return new Response("registrationId required", { status: 400 });
    const done = await store.revoke(env.DB, body.registrationId, reason, now);
    console.log(JSON.stringify({ event: "tester.revoked", registrationId: body.registrationId, reason, done }));
    return Response.json({ revoked: done });
  }
  await store.setClosed(env.DB, false, reason, "operator", now);
  console.log(JSON.stringify({ event: "tester.opened", reason }));
  return Response.json({ closed: false });
}

/** Better Auth paths the tester needs, and only those: a GitHub or GitLab sign-in, keys and metadata. (The token endpoint is wrapped.) */
const AUTH_GET = /^\/api\/auth\/(callback\/(github|gitlab)|jwks|\.well-known\/[a-z-]+(\/.*)?)$/;

async function dispatch(request: Request, env: Env, url: URL, ctx: ExecutionContext): Promise<Response> {
  // One public origin: requests to any other host name (workers.dev, a preview) are not served.
  if (env.PUBLIC_ORIGIN && url.origin !== env.PUBLIC_ORIGIN) return new Response("not found", { status: 404 });
  const origin = url.origin;
  const path = url.pathname;
  if (path.startsWith("/admin/")) return admin(request, env, url);
  if (path === "/logo.svg" && request.method === "GET") return new Response(LOGO_SVG, { headers: { "content-type": "image/svg+xml", "cache-control": "public, max-age=86400", "x-content-type-options": "nosniff" } });
  if (path === "/app.js" && request.method === "GET") return new Response(APP_JS, { headers: { "content-type": "text/javascript; charset=utf-8", "cache-control": "public, max-age=3600", "x-content-type-options": "nosniff" } });
  if (!(await env.IP_LIMIT.limit({ key: `ip:${clientIp(request)}` })).success) {
    store.bump("ratelimited.ip");
    return new Response("Too many requests from your address. Try again in a minute.", { status: 429 });
  }
  // Leaving works even while the tester is closed: signing out, and deleting your data.
  if (path === "/signout" && request.method === "POST") return signOut(request, env, origin);
  if (path === "/delete" && request.method === "POST") return deleteMyData(request, env, origin);
  const state = await openState(env);
  if (path === "/" && request.method === "GET") return landing(state.open && !!(await session(env, origin, request)), !state.open, providers(env), url.searchParams.get("signin") === "failed");
  // Everything else is closed while the tester is.
  if (!state.open) return path.startsWith("/api/") ? oauthError(503, "temporarily_unavailable", "The tester is closed for now.") : message("Closed", "The tester is closed for now.", 503);
  if (path === "/signin" && request.method === "POST") return signIn(request, env, origin);
  if (path === "/register" && (request.method === "GET" || request.method === "POST")) return register(request, env, origin);
  if (path === "/results" && request.method === "GET") return resultsPage(request, env, origin);
  if (path === "/check" && request.method === "POST") return checkPasted(request, env, origin, ctx);
  if (path === "/mcp") return mcpEndpoint(request, env, origin);
  if (path === "/api/auth/oauth2/token" && request.method === "POST") return token(request, env, origin, ctx);
  if (request.method === "GET" && (AUTH_GET.test(path) || path.startsWith("/.well-known/"))) return authFor(env, origin).handler(request);
  return message("Not found", "Nothing here.", 404);
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    return withExecutionContext(ctx, async () => {
      try {
        // HEAD is answered as GET without the body (link checkers and uptime monitors send it).
        if (request.method === "HEAD") {
          const got = await dispatch(new Request(request.url, { method: "GET", headers: request.headers }), env, new URL(request.url), ctx);
          return new Response(null, { status: got.status, headers: got.headers });
        }
        return await dispatch(request, env, new URL(request.url), ctx);
      } catch (e) {
        console.error(JSON.stringify({ event: "tester.error", message: e instanceof Error ? e.message : String(e) }));
        return page("Error", "<h1>Something went wrong</h1><p>Try again later.</p>", { status: 500 });
      }
    });
  },
  async scheduled(_event: ScheduledController, env: Env): Promise<void> {
    const n = await store.purge(env.DB, Date.now());
    if (n > 0) console.log(JSON.stringify({ event: "tester.purged", registrations: n }));
  },
} satisfies ExportedHandler<Env>;
