// "Test your IdP": a public, locked-down ID-JAG receiver for people building an ID-JAG issuer. A tester signs in
// with GitHub, registers their issuer, gets a client here for 24 hours, redeems ID-JAGs at the token endpoint, and
// reads a rule-by-rule report next to what the real receiver (this package) decided. docs/test-your-idp.md.
//
// Routes: / (home), POST /signin, /signout, /register, /results, POST /api/auth/oauth2/token (the receiver, wrapped),
// /mcp, the Better Auth paths a sign-in and a client need (nothing else under /api/auth), /admin/* (bearer keys).
// Limits, the kill switch and the purge are all here; see LIMITS.
import { createLocalJWKSet, jwtVerify } from "jose";
import { JWT_BEARER_GRANT, TRUSTED_ISSUER_MODEL } from "better-auth-id-jag";
import { withExecutionContext } from "../../background";
import { createAuth, type Env, INTERNAL_KEY, SCOPES } from "./auth";
import { checkIdJag, checkIssuerMetadata, type RuleResult } from "./checks";
import { checkPublicHttpsUrl, fetchJsonCapped, oauthMetadataUrl, openIdConfigurationUrl } from "./guard";
import { landing, message, page, registered, registerForm, results, type ResultView } from "./pages";
import * as store from "./store";

/** Every limit in one place. The rate-limit bindings (wrangler.jsonc) add per-minute limits on top. */
export const LIMITS = {
  registrationHours: 24,
  registrationsPerDay: 3,
  registrationsPerUserPerDay: 2,
  registrationsPerIpPerDay: 3,
  githubAccountMinAgeDays: 30,
  redemptionsPerRegistrationPerDay: 50,
  /** Past this, across everyone, the tester closes itself: far more than real testing needs. */
  redemptionsPerDay: 300,
  /** This many 5xx answers in 10 minutes closes the tester. */
  serverErrorsPer10Min: 10,
  maxFormBytes: 20_000,
};

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

async function readForm(request: Request): Promise<URLSearchParams | null> {
  if (Number(request.headers.get("content-length") ?? "0") > LIMITS.maxFormBytes) return null;
  const bytes = await request.arrayBuffer();
  return bytes.byteLength > LIMITS.maxFormBytes ? null : new URLSearchParams(new TextDecoder().decode(bytes));
}

/** Is the tester open? The deploy-level switch (TESTER_ENABLED) and the stored one (closed by a rule, the watcher or Mark). */
async function openState(env: Env): Promise<{ open: boolean; reason: string | null }> {
  if (env.TESTER_ENABLED !== "true") return { open: false, reason: "disabled in the deployment" };
  const s = await store.isClosed(env.DB);
  return { open: !s.closed, reason: s.reason };
}

async function session(env: Env, origin: string, request: Request) {
  return authFor(env, origin).api.getSession({ headers: request.headers });
}

/** The same origin, for every POST that a browser makes (cookies are SameSite=Lax; this closes the rest). */
const sameOrigin = (request: Request, origin: string) => request.headers.get("origin") === origin;

async function signIn(request: Request, env: Env, origin: string): Promise<Response> {
  if (!sameOrigin(request, origin)) return message("Not allowed", "Sign in from this site's own page.", 403);
  const { headers, response } = await authFor(env, origin).api.signInSocial({ body: { provider: "github", callbackURL: "/register" }, headers: request.headers, returnHeaders: true });
  const out = new Response(null, { status: 302, headers: { location: (response as { url: string }).url } });
  for (const c of headers.getSetCookie()) out.headers.append("set-cookie", c);
  return out;
}

async function signOut(request: Request, env: Env, origin: string): Promise<Response> {
  const out = new Response(null, { status: 302, headers: { location: "/" } });
  try {
    const { headers } = await authFor(env, origin).api.signOut({ headers: request.headers, returnHeaders: true });
    for (const c of headers.getSetCookie()) out.headers.append("set-cookie", c);
  } catch {
    // Not signed in: nothing to do.
  }
  return out;
}

/** The GitHub account behind a session: its login and age, from GitHub itself with the user's own token. */
async function githubAccount(env: Env, origin: string, userId: string): Promise<{ login: string; createdAt: number } | null> {
  const ctx = await authFor(env, origin).$context;
  const account = (await ctx.internalAdapter.findAccounts(userId)).find((a) => a.providerId === "github");
  if (!account?.accessToken) return null;
  const r = await fetch("https://api.github.com/user", { headers: { authorization: `Bearer ${account.accessToken}`, accept: "application/vnd.github+json", "user-agent": "idjag-tester" } });
  if (!r.ok) return null;
  const u = (await r.json()) as { login?: unknown; created_at?: unknown };
  const createdAt = typeof u.created_at === "string" ? Date.parse(u.created_at) : Number.NaN;
  return typeof u.login === "string" && Number.isFinite(createdAt) ? { login: u.login, createdAt } : null;
}

async function verifyTurnstile(env: Env, token: string | null, ip: string): Promise<boolean> {
  if (!token) return false;
  const r = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", { method: "POST", body: new URLSearchParams({ secret: env.TURNSTILE_SECRET_KEY, response: token, remoteip: ip }) });
  return r.ok && ((await r.json()) as { success?: boolean }).success === true;
}

async function register(request: Request, env: Env, origin: string): Promise<Response> {
  const state = await openState(env);
  if (!state.open) return message("Closed", "The tester is closed for now.", 503);
  const s = await session(env, origin, request);
  if (!s) return new Response(null, { status: 302, headers: { location: "/" } });
  if (request.method === "GET") return registerForm(env.TURNSTILE_SITE_KEY);
  if (!sameOrigin(request, origin)) return message("Not allowed", "Register from this site's own page.", 403);
  const ip = clientIp(request);
  if (!(await env.IP_LIMIT.limit({ key: `ip:${ip}` })).success) {
    store.bump("ratelimited.ip");
    return message("Slow down", "Too many requests from your address. Try again in a minute.", 429);
  }
  const form = await readForm(request);
  if (!form) return registerForm(env.TURNSTILE_SITE_KEY, "The form is too large.");
  if (!(await verifyTurnstile(env, form.get("cf-turnstile-response"), ip))) {
    store.bump("register.turnstile_failed");
    return registerForm(env.TURNSTILE_SITE_KEY, "The bot check failed. Try again.");
  }

  const now = Date.now();
  const day = store.utcDayStart(now);
  const gh = await githubAccount(env, origin, s.user.id);
  if (!gh) return registerForm(env.TURNSTILE_SITE_KEY, "Couldn't read your GitHub account. Sign out and in again.");
  if (now - gh.createdAt < LIMITS.githubAccountMinAgeDays * store.DAY_MS) {
    store.bump("register.young_github_account");
    return registerForm(env.TURNSTILE_SITE_KEY, `GitHub accounts must be at least ${LIMITS.githubAccountMinAgeDays} days old.`);
  }
  if (await store.activeByUser(env.DB, s.user.id, now)) return registerForm(env.TURNSTILE_SITE_KEY, "You already have an active registration: one at a time. See your results.");
  if ((await store.countRegistrations(env.DB, day, { userId: s.user.id })) >= LIMITS.registrationsPerUserPerDay) return registerForm(env.TURNSTILE_SITE_KEY, "You've registered enough for today. Try again tomorrow (UTC).");
  if ((await store.countRegistrations(env.DB, day, { ip })) >= LIMITS.registrationsPerIpPerDay) return registerForm(env.TURNSTILE_SITE_KEY, "Enough registrations from your address today. Try again tomorrow (UTC).");
  if ((await store.countRegistrations(env.DB, day)) >= LIMITS.registrationsPerDay) {
    store.bump("register.daily_full");
    return registerForm(env.TURNSTILE_SITE_KEY, "Today's registrations are taken. Try again tomorrow (UTC).");
  }

  const issuer = (form.get("issuer") ?? "").trim();
  const authMethod = form.get("authMethod") === "client_secret_post" ? "client_secret_post" : "client_secret_basic";
  const urlCheck = checkPublicHttpsUrl(issuer);
  if (!urlCheck.ok) return registerForm(env.TURNSTILE_SITE_KEY, `The issuer ${urlCheck.why}.`);
  if (urlCheck.url.search) return registerForm(env.TURNSTILE_SITE_KEY, "An issuer identifier has no query string (RFC 8414 section 2).");
  if (await store.activeByIssuer(env.DB, issuer, now)) return registerForm(env.TURNSTILE_SITE_KEY, "That issuer is registered by someone else right now. Registrations last 24 hours.");

  // The issuer's metadata: RFC 8414's location first, then OpenID Connect Discovery's.
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
  if (check.blocking.length > 0 || !jwks.ok) {
    const fails = check.results.filter((r) => r.outcome === "fail").map((r) => r.message);
    return registerForm(env.TURNSTILE_SITE_KEY, `Not registered: ${fails.join(" ")}`);
  }

  // The client here, owned by the tester's GitHub user, only for redeeming ID-JAGs.
  const auth = authFor(env, origin);
  const headers = new Headers({ cookie: request.headers.get("cookie") ?? "", "x-tester-internal": INTERNAL_KEY });
  const api = auth.api as unknown as { adminCreateOAuthClient(o: { headers: Headers; body: Record<string, unknown> }): Promise<{ client_id: string; client_secret: string }> };
  const client = await api.adminCreateOAuthClient({
    headers,
    body: { client_name: `Tester: ${gh.login}`, grant_types: [JWT_BEARER_GRANT], response_types: [], token_endpoint_auth_method: authMethod, scope: SCOPES.join(" ") },
  });
  const ctx = await auth.$context;
  const id = newId();
  try {
    const trust = await ctx.adapter.create<Record<string, unknown>, { id: string }>({
      model: TRUSTED_ISSUER_MODEL,
      data: { issuer, jwksUri, allowedClientIds: JSON.stringify([client.client_id]), jitProvisioning: false, jitTrustEmailVerified: false, enabled: true, createdAt: new Date(now), updatedAt: new Date(now) },
      forceAllowId: false,
    });
    const expiresAt = now + LIMITS.registrationHours * 3_600_000;
    await store.insertRegistration(env.DB, { id, userId: s.user.id, githubLogin: gh.login, issuer, jwksUri, jwks: JSON.stringify(jwks.json), jwksFetchedAt: now, clientId: client.client_id, trustRowId: trust.id, authMethod, metadataReport: JSON.stringify(check.results), ip, createdAt: now, expiresAt, revokedAt: null, revokedReason: null, purgedAt: null });
    console.log(JSON.stringify({ event: "tester.registered", id, github: gh.login, issuer, ip }));
    return registered({ origin, clientId: client.client_id, clientSecret: client.client_secret, authMethod, issuer, expiresAt, report: check.results });
  } catch (e) {
    await env.DB.prepare(`delete from "oauthClient" where clientId = ?`).bind(client.client_id).run();
    throw e;
  }
}

/** The client a token request authenticates as: HTTP Basic (RFC 6749 section 2.3.1, form-encoded) or the body. */
function requestClientId(request: Request, form: URLSearchParams): string | undefined {
  const basic = request.headers.get("authorization")?.match(/^Basic ([A-Za-z0-9+/=]+)$/i)?.[1];
  if (basic) {
    try {
      const decoded = atob(basic);
      const colon = decoded.indexOf(":");
      if (colon > 0) return decodeURIComponent(decoded.slice(0, colon).replace(/\+/g, " "));
    } catch {
      return undefined;
    }
  }
  return form.get("client_id") ?? undefined;
}

/** The receiver's token endpoint, with the limits in front and the rule-by-rule report recorded after. */
async function token(request: Request, env: Env, origin: string, ctx: ExecutionContext): Promise<Response> {
  const state = await openState(env);
  if (!state.open) return oauthError(503, "temporarily_unavailable", "The tester is closed for now.");
  const ip = clientIp(request);
  if (!(await env.IP_LIMIT.limit({ key: `ip:${ip}` })).success) {
    store.bump("ratelimited.ip");
    return oauthError(429, "slow_down", "Too many requests from your address. Try again in a minute.");
  }
  const form = await readForm(request);
  if (!form) return oauthError(400, "invalid_request", "The request is too large.");
  if (form.get("grant_type") !== JWT_BEARER_GRANT) return oauthError(400, "unsupported_grant_type", `This tester only redeems ID-JAGs (grant_type ${JWT_BEARER_GRANT}).`);
  const clientId = requestClientId(request, form);
  const now = Date.now();
  const reg = clientId ? await store.activeByClient(env.DB, clientId, now) : null;
  if (!reg || !clientId) {
    store.bump("token.unknown_client");
    return oauthError(401, "invalid_client", "Unknown or expired client. Register at the tester's home page.");
  }
  if (!(await env.TOKEN_LIMIT.limit({ key: `client:${clientId}` })).success) {
    store.bump("ratelimited.client");
    return oauthError(429, "slow_down", "At most 10 redemptions a minute per client.");
  }
  const day = store.utcDayStart(now);
  if ((await store.countChecks(env.DB, day, reg.id)) >= LIMITS.redemptionsPerRegistrationPerDay) return oauthError(429, "slow_down", `At most ${LIMITS.redemptionsPerRegistrationPerDay} redemptions a day per registration.`);
  if ((await store.countChecks(env.DB, day)) >= LIMITS.redemptionsPerDay) {
    await store.setClosed(env.DB, true, `daily redemption budget (${LIMITS.redemptionsPerDay}) reached`, "worker", now);
    console.log(JSON.stringify({ event: "tester.closed", by: "worker", reason: "daily budget" }));
    return oauthError(503, "temporarily_unavailable", "The tester is closed for now.");
  }

  // The report: every rule, with the issuer's keys (refetched at most once a minute when the kid is new).
  const assertion = form.get("assertion") ?? "";
  let jwks = JSON.parse(reg.jwks) as { keys?: { kid?: string }[] };
  const kid = (() => {
    try {
      return (JSON.parse(atob((assertion.split(".")[0] ?? "").replace(/-/g, "+").replace(/_/g, "/"))) as { kid?: unknown }).kid;
    } catch {
      return undefined;
    }
  })();
  if (typeof kid === "string" && !jwks.keys?.some((k) => k.kid === kid) && now - reg.jwksFetchedAt > 60_000) {
    const fresh = await fetchJsonCapped(fetch, reg.jwksUri);
    if (fresh.ok) {
      jwks = fresh.json as typeof jwks;
      await store.updateJwks(env.DB, reg.id, JSON.stringify(fresh.json), now);
    }
  }
  const report = await checkIdJag(assertion, {
    issuer: reg.issuer,
    audience: `${origin}/api/auth`,
    resource: `${origin}/mcp`,
    grantableScopes: SCOPES,
    clientId,
    jwks: Array.isArray(jwks.keys) ? (jwks as never) : null,
    now: Math.floor(now / 1000),
  });

  // The real decision: the published receiver, unchanged.
  const forwardHeaders = new Headers(request.headers);
  forwardHeaders.delete("content-length");
  const forwarded = new Request(request.url, { method: "POST", headers: forwardHeaders, body: form.toString() });
  const response = await authFor(env, origin).handler(forwarded);
  const body = (await response.clone().json().catch(() => null)) as { error?: unknown } | null;
  const jti = typeof report.claims?.jti === "string" ? report.claims.jti.replace(/[^\x20-\x7e]/g, "").slice(0, 200) : null;
  ctx.waitUntil(
    (async () => {
      await store.insertCheck(env.DB, { id: newId(), registrationId: reg.id, at: now, jti, httpStatus: response.status, error: typeof body?.error === "string" ? body.error.slice(0, 64) : null, results: JSON.stringify(report.results) });
      if (response.status >= 500 && (await store.countServerErrors(env.DB, now - 600_000)) >= LIMITS.serverErrorsPer10Min) {
        await store.setClosed(env.DB, true, `${LIMITS.serverErrorsPer10Min} server errors in 10 minutes`, "worker", Date.now());
        console.log(JSON.stringify({ event: "tester.closed", by: "worker", reason: "server errors" }));
      }
      await store.flushCounters(env.DB, Date.now());
    })(),
  );
  return response;
}

/** The MCP server: whoami and checks (the latest reports for the token's client), read-only. */
async function mcpEndpoint(request: Request, env: Env, origin: string): Promise<Response> {
  const challenge = { "WWW-Authenticate": `Bearer resource_metadata="${origin}/.well-known/oauth-protected-resource/mcp"` };
  const state = await openState(env);
  if (!state.open) return Response.json({ jsonrpc: "2.0", id: null, error: { code: -32000, message: "the tester is closed" } }, { status: 503 });
  const bearer = request.headers.get("authorization")?.match(/^Bearer (.+)$/i)?.[1];
  if (!bearer) return Response.json({ jsonrpc: "2.0", id: null, error: { code: -32001, message: "unauthorized" } }, { status: 401, headers: challenge });
  const auth = authFor(env, origin);
  const keys = (await (await auth.handler(new Request(`${origin}/api/auth/jwks`))).json()) as Parameters<typeof createLocalJWKSet>[0];
  let claims: Record<string, unknown>;
  try {
    claims = (await jwtVerify(bearer, createLocalJWKSet(keys), { issuer: `${origin}/api/auth`, audience: `${origin}/mcp` })).payload;
  } catch {
    return Response.json({ jsonrpc: "2.0", id: null, error: { code: -32001, message: "invalid token" } }, { status: 401, headers: { "WWW-Authenticate": `${challenge["WWW-Authenticate"]}, error="invalid_token"` } });
  }
  const clientId = typeof claims.azp === "string" ? claims.azp : typeof claims.client_id === "string" ? claims.client_id : "";
  if (!(await env.MCP_LIMIT.limit({ key: `mcp:${clientId}` })).success) {
    store.bump("ratelimited.mcp");
    return Response.json({ jsonrpc: "2.0", id: null, error: { code: -32000, message: "at most 30 calls a minute" } }, { status: 429 });
  }
  if (request.method !== "POST") return new Response(null, { status: 405, headers: { allow: "POST" } });
  const rpc = (await request.json().catch(() => ({}))) as { id?: unknown; method?: string; params?: { protocolVersion?: string; name?: string } };
  const reply = (result: unknown) => Response.json({ jsonrpc: "2.0", id: rpc.id ?? null, result });
  const text = (value: unknown) => ({ content: [{ type: "text", text: JSON.stringify(value) }] });
  switch (rpc.method) {
    case "initialize":
      return reply({ protocolVersion: rpc.params?.protocolVersion ?? "2025-06-18", capabilities: { tools: {} }, serverInfo: { name: "idjag-tester", version: "0.1.0" } });
    case "notifications/initialized":
      return new Response(null, { status: 202 });
    case "ping":
      return reply({});
    case "tools/list":
      return reply({ tools: [
        { name: "whoami", description: "The access token's claims: who the receiver says you are (scope: read)", inputSchema: { type: "object", properties: {} } },
        { name: "checks", description: "The latest rule-by-rule reports for your client (scope: read)", inputSchema: { type: "object", properties: {} } },
      ] });
    case "tools/call": {
      if (rpc.params?.name === "whoami") return reply(text({ sub: claims.sub, scope: claims.scope, act: claims.act ?? null, aud: claims.aud, idjag: claims.idjag ?? null, exp: claims.exp }));
      if (rpc.params?.name === "checks") {
        const reg = await store.activeByClient(env.DB, clientId, Date.now());
        const rows = reg ? await store.recentChecks(env.DB, reg.id, 5) : [];
        return reply(text(rows.map((c) => ({ at: new Date(c.at).toISOString(), jti: c.jti, httpStatus: c.httpStatus, error: c.error, failed: (JSON.parse(c.results) as RuleResult[]).filter((r) => r.outcome === "fail").map((r) => ({ id: r.id, cite: r.cite, message: r.message })) }))));
      }
      return Response.json({ jsonrpc: "2.0", id: rpc.id ?? null, error: { code: -32602, message: "unknown tool" } });
    }
    default:
      return Response.json({ jsonrpc: "2.0", id: rpc.id ?? null, error: { code: -32601, message: "method not found" } });
  }
}

async function resultsPage(request: Request, env: Env, origin: string): Promise<Response> {
  const s = await session(env, origin, request);
  if (!s) return new Response(null, { status: 302, headers: { location: "/" } });
  const now = Date.now();
  const views: ResultView[] = [];
  for (const reg of await store.unpurgedByUser(env.DB, s.user.id)) {
    const decisions = await store.receiverDecisions(env.DB, reg.clientId);
    views.push({
      issuer: reg.issuer,
      clientId: reg.clientId,
      expiresAt: reg.expiresAt,
      ended: reg.revokedAt ? `revoked (${reg.revokedReason ?? "no reason given"})` : reg.expiresAt <= now ? "expired; deleted within minutes" : null,
      metadata: JSON.parse(reg.metadataReport) as RuleResult[],
      checks: (await store.recentChecks(env.DB, reg.id)).map((c) => ({ at: c.at, jti: c.jti, httpStatus: c.httpStatus, error: c.error, results: JSON.parse(c.results) as RuleResult[], receiver: c.jti ? (decisions.get(c.jti) ?? null) : null })),
    });
  }
  return results(views);
}

/** Constant-time comparison of a bearer key against a configured one; an unset key never matches. */
async function keyMatches(request: Request, expected: string | undefined): Promise<boolean> {
  const given = request.headers.get("authorization")?.match(/^Bearer (.+)$/)?.[1];
  if (!given || !expected || expected.length < 32) return false;
  const digest = async (s: string) => new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)));
  return crypto.subtle.timingSafeEqual(await digest(given), await digest(expected));
}

/**
 * The watcher's and Mark's controls. STATS reads; CLOSE closes the tester or revokes one registration and can never
 * reopen anything; OPEN (Mark's alone) reopens.
 */
async function admin(request: Request, env: Env, url: URL): Promise<Response> {
  if (!(await env.IP_LIMIT.limit({ key: `admin:${clientIp(request)}` })).success) return new Response("slow down", { status: 429 });
  const now = Date.now();
  if (url.pathname === "/admin/stats" && request.method === "GET") {
    if (!(await keyMatches(request, env.ADMIN_STATS_KEY))) return new Response("forbidden", { status: 403 });
    return Response.json(await store.stats(env.DB, now), { headers: { "cache-control": "no-store" } });
  }
  if (request.method !== "POST") return new Response("not found", { status: 404 });
  const body = (await request.json().catch(() => ({}))) as { reason?: unknown; registrationId?: unknown };
  const reason = typeof body.reason === "string" && body.reason ? body.reason : "no reason given";
  if (url.pathname === "/admin/close" || url.pathname === "/admin/revoke") {
    if (!(await keyMatches(request, env.ADMIN_CLOSE_KEY)) && !(await keyMatches(request, env.ADMIN_OPEN_KEY))) return new Response("forbidden", { status: 403 });
    if (url.pathname === "/admin/close") {
      await store.setClosed(env.DB, true, reason, "admin", now);
      console.log(JSON.stringify({ event: "tester.closed", by: "admin", reason }));
      return Response.json({ closed: true });
    }
    if (typeof body.registrationId !== "string") return new Response("registrationId required", { status: 400 });
    const done = await store.revoke(env.DB, body.registrationId, reason, now);
    console.log(JSON.stringify({ event: "tester.revoked", registrationId: body.registrationId, reason, done }));
    return Response.json({ revoked: done });
  }
  if (url.pathname === "/admin/open") {
    if (!(await keyMatches(request, env.ADMIN_OPEN_KEY))) return new Response("forbidden", { status: 403 });
    await store.setClosed(env.DB, false, reason, "mark", now);
    console.log(JSON.stringify({ event: "tester.opened", reason }));
    return Response.json({ closed: false });
  }
  return new Response("not found", { status: 404 });
}

/** Better Auth paths the tester needs, and only those: a GitHub sign-in, the token endpoint, keys and metadata. */
const AUTH_GET = /^\/api\/auth\/(callback\/github|jwks|\.well-known\/[a-z-]+(\/.*)?)$/;

async function dispatch(request: Request, env: Env, url: URL, ctx: ExecutionContext): Promise<Response> {
  const origin = url.origin;
  const path = url.pathname;
  if (path.startsWith("/admin/")) return admin(request, env, url);
  if (path === "/" && request.method === "GET") {
    const state = await openState(env);
    return landing(!!(await session(env, origin, request)), !state.open);
  }
  if (path === "/signin" && request.method === "POST") return signIn(request, env, origin);
  if (path === "/signout" && request.method === "GET") return signOut(request, env, origin);
  if (path === "/register" && (request.method === "GET" || request.method === "POST")) return register(request, env, origin);
  if (path === "/results" && request.method === "GET") return resultsPage(request, env, origin);
  if (path === "/mcp") return mcpEndpoint(request, env, origin);
  if (path === "/api/auth/oauth2/token" && request.method === "POST") return token(request, env, origin, ctx);
  if (request.method === "GET" && (AUTH_GET.test(path) || path.startsWith("/.well-known/"))) return authFor(env, origin).handler(request);
  return message("Not found", "Nothing here.", 404);
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    return withExecutionContext(ctx, async () => {
      try {
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
