// Routes: Better Auth under /api/auth (and its /.well-known documents), plus POST /setup, which creates a demo user
// and an OAuth client, an AI agent's or an app's (x-setup-key), /login, the sign-in page a browser is sent to during
// authorization, and /consent, where a request with prompt=consent (the tester's run asks for offline_access with it)
// is allowed or denied. With `"for": "tester"`, /setup registers a client for the public tester instead of the MCP
// server (auth.ts): `clientIdAtResource` is then the tester registration's client id, and its sign-in comes back to
// the tester's /flow/callback.
//
// Every client here authenticates with client_secret_post, and the metadata says so. Claude Code's Cross
// App Access picks Basic for its sign-in when the IdP lists it, but always sends the secret in the body
// for the ID-JAG request; Better Auth holds a client to one registered method, so a client registered for
// Basic would fail one of the two steps (examples/workers/README.md, "Claude Code").
import { withExecutionContext } from "../../background";
import { createAuth, type Env, isNative, redirectUrisFor, testerCallbackOf } from "./auth";

const cache = new Map<string, ReturnType<typeof createAuth>>();
const authFor = (env: Env, origin: string) => {
  let auth = cache.get(origin);
  if (!auth) {
    auth = createAuth(env, origin);
    cache.set(origin, auth);
  }
  return auth;
};

async function setup(request: Request, env: Env, origin: string): Promise<Response> {
  if (!env.SETUP_KEY || request.headers.get("x-setup-key") !== env.SETUP_KEY) return new Response("forbidden", { status: 403 });
  const body = (await request.json()) as { email: string; password: string; clientIdAtResource: string; agent?: boolean; redirectUris?: string[]; for?: "tester" };
  const agent = body.agent === true;
  const forTester = body.for === "tester";
  if (body.for !== undefined && !forTester) return new Response('for: only "tester"', { status: 400 });
  if (forTester && !(testerCallbackOf(env) && env.TESTER_RESOURCE)) return new Response("this IdP isn't set up for the tester (TESTER_AS_ISSUER, an absolute URL, and TESTER_RESOURCE)", { status: 400 });
  const redirectUris = redirectUrisFor(env, origin, forTester, body.redirectUris);
  if (!Array.isArray(redirectUris)) return new Response(redirectUris.error, { status: 400 });
  const native = isNative(origin, redirectUris);
  const auth = authFor(env, origin);
  const ctx = await auth.$context;
  let user = (await ctx.internalAdapter.findUserByEmail(body.email, { includeAccounts: false }))?.user;
  if (!user) {
    // Sign-up is closed to the public; the setup route creates the one demo user.
    const hash = await ctx.password.hash(body.password);
    user = await ctx.internalAdapter.createUser({ email: body.email, name: body.email.split("@")[0] ?? "user", emailVerified: true }, { method: "example-setup" });
    await ctx.internalAdapter.linkAccount({ userId: user.id, providerId: "credential", accountId: user.id, password: hash });
  }
  const signIn = await auth.api.signInEmail({ body: { email: body.email, password: body.password }, returnHeaders: true });
  const headers = new Headers({ cookie: (signIn.headers.get("set-cookie") ?? "").split(";")[0] ?? "", "x-setup-key": env.SETUP_KEY });
  const api = auth.api as unknown as { adminCreateOAuthClient(o: { headers: Headers; body: Record<string, unknown> }): Promise<{ client_id: string; client_secret: string }> };
  const client = await api.adminCreateOAuthClient({
    headers,
    body: {
      client_name: `${forTester ? "Example tester client" : "Example MCP client"} (${agent ? "AI agent" : "app"})`,
      redirect_uris: redirectUris,
      // An http redirect (run locally, or a loopback one): Better Auth takes that from a native client only.
      ...(native ? { application_type: "native" } : {}),
      grant_types: ["authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:token-exchange"],
      response_types: ["code"],
      token_endpoint_auth_method: "client_secret_post",
      scope: "openid profile email offline_access",
      skip_consent: true,
      metadata: { clientIdAtResource: body.clientIdAtResource, agent, ...(forTester ? { for: "tester" } : {}) },
    },
  });
  return Response.json({ userId: user.id, client_id: client.client_id, client_secret: client.client_secret });
}

export default {
  fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    return withExecutionContext(ctx, () => route(request, env));
  },
} satisfies ExportedHandler<Env>;

async function route(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  // One address: with PUBLIC_ORIGIN set, the issuer never depends on the address a request used (env.PUBLIC_ORIGIN).
  if (env.PUBLIC_ORIGIN && url.origin !== env.PUBLIC_ORIGIN) return Response.redirect(`${env.PUBLIC_ORIGIN}${url.pathname}${url.search}`, 308);
  if (url.pathname === "/setup" && request.method === "POST") return setup(request, env, url.origin);
  if (url.pathname === "/login") return new Response(LOGIN_PAGE, { headers: PAGE_HEADERS });
  if (url.pathname === "/consent") return new Response(CONSENT_PAGE, { headers: PAGE_HEADERS });
  if (url.pathname === "/callback") return new Response("ok", { status: 200 });
  const response = await authFor(env, url.origin).handler(request);
  return url.pathname.includes("/.well-known/") ? postOnlyMetadata(response) : response;
}

// The metadata lists the one method every client here is registered for (see the top of this file).
async function postOnlyMetadata(response: Response): Promise<Response> {
  if (!response.ok || !(response.headers.get("content-type") ?? "").includes("json")) return response;
  const body = (await response.json()) as Record<string, unknown>;
  if (Array.isArray(body.token_endpoint_auth_methods_supported)) body.token_endpoint_auth_methods_supported = ["client_secret_post"];
  const headers = new Headers(response.headers);
  headers.delete("content-length");
  return new Response(JSON.stringify(body), { status: response.status, headers });
}

const PAGE_HEADERS = { "content-type": "text/html; charset=utf-8", "content-security-policy": "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; form-action 'none'; frame-ancestors 'none'" };

/** The part of the provider's query that it signed: sig, ba_param, and the names ba_param lists (as its client reads it). */
const SIGNED_QUERY = `const params = new URLSearchParams(location.search);
const names = new Set(params.getAll("ba_param"));
const signed = new URLSearchParams();
for (const [k, v] of params) if (k === "sig" || k === "ba_param" || names.has(k)) signed.append(k, v);`;

// The two pages' look: the same family as the public tester's (its logo's charcoal and cyans, system fonts, light and
// dark from the system), lighter, and with its own mark, since this plays a company's own IdP, not the tester. Nothing
// is loaded from anywhere: the mark is inline SVG, and the policy allows no images or fonts.
const IDP_STYLE = `:root { --ink: #18181b; --cyan: #22d3ee; --bg: #f6f7f8; --card: #ffffff; --fg: #18181b; --muted: #52525b; --line: #e4e4e7;
  --accent: #0e7490; --error: #b91c1c; --button: #18181b; --button-fg: #ffffff; }
@media (prefers-color-scheme: dark) { :root { --bg: #0f0f11; --card: #18181b; --fg: #f4f4f5; --muted: #a1a1aa; --line: #2e2e33; --accent: #22d3ee;
  --error: #f87171; --button: #22d3ee; --button-fg: #18181b; } }
* { box-sizing: border-box; }
body { margin: 0; min-height: 100vh; background: var(--bg); color: var(--fg); font: 16px/1.6 ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
  display: flex; flex-direction: column; align-items: center; padding: 48px 16px; }
.card { width: 100%; max-width: 24rem; background: var(--card); border: 1px solid var(--line); border-top: 4px solid var(--cyan); border-radius: 14px; padding: 24px; }
.mark { display: flex; align-items: center; gap: 10px; margin-bottom: 16px; font-weight: 650; }
.mark small { font-weight: 400; color: var(--muted); font-size: 0.8rem; border: 1px solid var(--line); border-radius: 999px; padding: 0 8px; }
h1 { font-size: 1.4rem; margin: 0 0 6px; letter-spacing: -0.01em; }
p, li { color: var(--fg); } .muted { color: var(--muted); }
label { display: block; font-weight: 600; font-size: 0.95rem; }
input { display: block; width: 100%; margin: 4px 0 16px; padding: 10px; font: inherit; border: 1px solid var(--line); border-radius: 8px; background: var(--card); color: var(--fg); }
input:focus { outline: 2px solid var(--cyan); outline-offset: 1px; }
button { font: inherit; font-weight: 600; padding: 10px 18px; border-radius: 10px; border: 1px solid var(--button); background: var(--button); color: var(--button-fg); cursor: pointer; }
button.quiet { background: transparent; color: var(--fg); border-color: var(--line); }
button:focus-visible { outline: 3px solid var(--cyan); outline-offset: 2px; }
form button, .actions button { width: 100%; } .actions { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
ul { padding-left: 1.2rem; } #error { color: var(--error); min-height: 1.6em; margin: 12px 0 0; }
footer { max-width: 24rem; margin-top: 16px; font-size: 0.85rem; color: var(--muted); text-align: center; }`;

const IDP_MARK = `<div class="mark"><svg width="28" height="28" viewBox="0 0 28 28" aria-hidden="true"><rect width="28" height="28" rx="7" fill="#18181b"/><circle cx="14" cy="11" r="4.5" fill="#22d3ee"/><path d="M6.5 22c1.2-4 4.2-6 7.5-6s6.3 2 7.5 6" fill="none" stroke="#0891b2" stroke-width="3" stroke-linecap="round"/></svg>Example IdP <small>demo</small></div>`;

const IDP_FOOTER = `<footer>A demo identity provider for better-auth-id-jag's examples. Use the demo users only.</footer>`;

// The sign-in page. oauth-provider sends the browser here with a signed copy of the authorization request;
// signing in with that copy (oauth_query) makes the provider answer with where to go next: the client's
// redirect with a code. The demo users are created by /setup; there is no sign-up.
const LOGIN_PAGE = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Example IdP: sign in</title>
<style>${IDP_STYLE}</style>
</head><body><main class="card">
${IDP_MARK}
<h1>Sign in</h1>
<p class="muted">Sign in to continue to the application that sent you here.</p>
<form id="f"><label>Email <input id="email" type="email" autocomplete="username" required></label>
<label>Password <input id="password" type="password" autocomplete="current-password" required></label>
<button type="submit">Sign in</button></form>
<p id="error" role="alert"></p></main>
${IDP_FOOTER}
<script>
${SIGNED_QUERY}
document.getElementById("f").addEventListener("submit", async (e) => {
  e.preventDefault();
  const error = document.getElementById("error");
  error.textContent = "";
  if (!params.has("sig")) { error.textContent = "Open this page from an application's sign-in, not directly."; return; }
  const r = await fetch("/api/auth/sign-in/email", { method: "POST", headers: { "content-type": "application/json" }, credentials: "same-origin",
    body: JSON.stringify({ email: document.getElementById("email").value, password: document.getElementById("password").value, oauth_query: signed.toString() }) });
  const body = await r.json().catch(() => ({}));
  if (r.ok && typeof body.url === "string") location.assign(body.url);
  else error.textContent = body.message || "Sign-in failed.";
});
</script>
</body></html>`;

// The consent page. oauth-provider sends the browser here, signed in, when the authorization request has
// prompt=consent (the tester's run asks for offline_access with it, as OpenID Connect Core section 11 says); the
// clients /setup makes skip consent otherwise. Allow or Deny posts the signed query to /oauth2/consent, which answers
// with where to go next: the client's redirect, with a code or with access_denied.
const CONSENT_PAGE = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Example IdP: allow access</title>
<style>${IDP_STYLE}</style>
</head><body><main class="card">
${IDP_MARK}
<h1>Allow access?</h1>
<p class="muted">An application sent you here to sign in with your Example IdP account.<span id="who"></span></p>
<p><strong id="client"></strong> asks to:</p>
<ul id="scopes"></ul>
<p class="muted">Allow lets it continue; Deny sends you back to it with no access.</p>
<div class="actions"><button id="allow" type="button">Allow</button><button id="deny" type="button" class="quiet">Deny</button></div>
<p id="error" role="alert"></p></main>
${IDP_FOOTER}
<script>
${SIGNED_QUERY}
document.getElementById("client").textContent = params.get("client_id") || "(unknown)";
// The client's name, where the provider gives it (its public client fields, for the signed-in user).
if (params.get("client_id")) fetch("/api/auth/oauth2/public-client?client_id=" + encodeURIComponent(params.get("client_id")), { credentials: "same-origin" })
  .then((r) => (r.ok ? r.json() : null)).then((c) => { if (c && typeof c.client_name === "string" && c.client_name) document.getElementById("client").textContent = c.client_name; }).catch(() => {});
// Each scope in plain words, with its name.
const SCOPES = { openid: "confirm who you are", profile: "see your name", email: "see your email address", offline_access: "keep access while you're away (a refresh token)" };
for (const s of (params.get("scope") || "").split(" ").filter(Boolean)) {
  const li = document.createElement("li");
  li.textContent = Object.hasOwn(SCOPES, s) ? SCOPES[s] + " (" + s + ")" : s;
  document.getElementById("scopes").append(li);
}
// Who is signed in here: an earlier sign-in can skip the password, and this says why.
fetch("/api/auth/get-session", { credentials: "same-origin" })
  .then((r) => (r.ok ? r.json() : null)).then((x) => { if (x && x.user && typeof x.user.email === "string") document.getElementById("who").textContent = " You're signed in as " + x.user.email + "."; }).catch(() => {});
async function answer(accept) {
  const error = document.getElementById("error");
  error.textContent = "";
  if (!params.has("sig")) { error.textContent = "Open this page from an application's sign-in, not directly."; return; }
  const r = await fetch("/api/auth/oauth2/consent", { method: "POST", headers: { "content-type": "application/json" }, credentials: "same-origin",
    body: JSON.stringify({ accept, oauth_query: signed.toString() }) });
  const body = await r.json().catch(() => ({}));
  if (r.ok && typeof body.url === "string") location.assign(body.url);
  else error.textContent = body.message || "That didn't work. Start again from the application.";
}
document.getElementById("allow").addEventListener("click", () => answer(true));
document.getElementById("deny").addEventListener("click", () => answer(false));
</script>
</body></html>`;
