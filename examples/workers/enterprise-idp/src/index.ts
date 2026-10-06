// Routes: Better Auth under /api/auth (and its /.well-known documents), plus POST /setup, which
// creates the demo user and the agent's OAuth client (x-setup-key).
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
  const body = (await request.json()) as { email: string; password: string; clientIdAtResource: string };
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
      client_name: "Example MCP client (agent)",
      redirect_uris: [`${origin}/callback`],
      grant_types: ["authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:token-exchange"],
      response_types: ["code"],
      token_endpoint_auth_method: "client_secret_basic",
      scope: "openid profile email offline_access",
      skip_consent: true,
      metadata: { clientIdAtResource: body.clientIdAtResource },
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
  // The scripted client signs in programmatically; a real IdP has a sign-in page here.
  if (url.pathname === "/login") return new Response("Sign in through the API (see examples/workers/client.mjs).", { status: 200 });
  if (url.pathname === "/callback") return new Response("ok", { status: 200 });
  return authFor(env, url.origin).handler(request);
}
