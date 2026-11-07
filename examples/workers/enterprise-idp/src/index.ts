// Routes: Better Auth under /api/auth (and its /.well-known documents), plus POST /setup, which
// creates a demo user and an OAuth client, an AI agent's or an app's (x-setup-key), and /login, the
// sign-in page a browser is sent to during authorization.
//
// Every client here authenticates with client_secret_post, and the metadata says so. Claude Code's Cross
// App Access picks Basic for its sign-in when the IdP lists it, but always sends the secret in the body
// for the ID-JAG request; Better Auth holds a client to one registered method, so a client registered for
// Basic would fail one of the two steps (examples/workers/README.md, "Claude Code").
import { withExecutionContext } from "../../background";
import { createAuth, type Env } from "./auth";

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
  const body = (await request.json()) as { email: string; password: string; clientIdAtResource: string; agent?: boolean; redirectUris?: string[] };
  const agent = body.agent === true;
  // Our own /callback, or a native client's loopback redirect (Claude Code's is http://localhost:<port>/callback).
  const redirectUris = body.redirectUris ?? [`${origin}/callback`];
  const loopback = /^http:\/\/(localhost|127\.0\.0\.1):\d{1,5}\/callback$/;
  if (!Array.isArray(redirectUris) || redirectUris.length === 0 || !redirectUris.every((u) => u === `${origin}/callback` || (typeof u === "string" && loopback.test(u))))
    return new Response(`redirectUris: only ${origin}/callback or http://localhost:<port>/callback`, { status: 400 });
  const native = new URL(origin).protocol === "http:" || redirectUris.some((u) => loopback.test(u));
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
      client_name: agent ? "Example MCP client (AI agent)" : "Example MCP client (app)",
      redirect_uris: redirectUris,
      // An http redirect (run locally, or a loopback one): Better Auth takes that from a native client only.
      ...(native ? { application_type: "native" } : {}),
      grant_types: ["authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:token-exchange"],
      response_types: ["code"],
      token_endpoint_auth_method: "client_secret_post",
      scope: "openid profile email offline_access",
      skip_consent: true,
      metadata: { clientIdAtResource: body.clientIdAtResource, agent },
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
  if (url.pathname === "/setup" && request.method === "POST") return setup(request, env, url.origin);
  if (url.pathname === "/login") return new Response(LOGIN_PAGE, { headers: { "content-type": "text/html; charset=utf-8", "content-security-policy": "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; form-action 'none'; frame-ancestors 'none'" } });
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

// The sign-in page. oauth-provider sends the browser here with a signed copy of the authorization request;
// signing in with that copy (oauth_query) makes the provider answer with where to go next: the client's
// redirect with a code. The demo users are created by /setup; there is no sign-up.
const LOGIN_PAGE = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Example IdP: sign in</title>
<style>body{font:16px system-ui,sans-serif;max-width:22rem;margin:4rem auto;padding:0 1rem}label,input,button{display:block;width:100%;box-sizing:border-box}input{margin:.25rem 0 1rem;padding:.5rem}button{padding:.6rem}#error{color:#b00020}</style>
</head><body>
<h1>Example IdP</h1>
<p>Sign in to continue to the application that sent you here.</p>
<form id="f"><label>Email <input id="email" type="email" autocomplete="username" required></label>
<label>Password <input id="password" type="password" autocomplete="current-password" required></label>
<button type="submit">Sign in</button></form>
<p id="error" role="alert"></p>
<script>
const params = new URLSearchParams(location.search);
// Only the signed part of the query: sig, ba_param, and the names ba_param lists (as oauth-provider's client does).
const names = new Set(params.getAll("ba_param"));
const signed = new URLSearchParams();
for (const [k, v] of params) if (k === "sig" || k === "ba_param" || names.has(k)) signed.append(k, v);
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
