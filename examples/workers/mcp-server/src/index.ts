// Routes: Better Auth under /api/auth (and the /.well-known documents), POST /setup (registers the
// agent as a confidential client here, x-setup-key), and /mcp: one tool, `whoami`, for an access
// token audience-bound to this server's /mcp.
//
// The token check is the one requireMcpAuth (@better-auth/mcp) makes: signature with this
// server's JWKS, `iss` = this authorization server, `aud` = this /mcp, unexpired; a 401 carries
// the RFC 9728 challenge. It's done in-process here because requireMcpAuth fetches the JWKS by
// URL, and a Worker can't fetch its own workers.dev URL (the request never completes). A resource
// server deployed apart from its authorization server uses requireMcpAuth as is
// (test/receiver/exit.test.ts runs it against these tokens).
import { createLocalJWKSet, jwtVerify } from "jose";
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
  const { email, password } = (await request.json()) as { email: string; password: string };
  const auth = authFor(env, origin);
  const ctx = await auth.$context;
  // A local operator account owns the client registration (creating a client needs a session).
  let operator = (await ctx.internalAdapter.findUserByEmail(email, { includeAccounts: false }))?.user;
  if (!operator) {
    operator = await ctx.internalAdapter.createUser({ email, name: "operator", emailVerified: true }, { method: "example-setup" });
    await ctx.internalAdapter.linkAccount({ userId: operator.id, providerId: "credential", accountId: operator.id, password: await ctx.password.hash(password) });
  }
  const signIn = await auth.api.signInEmail({ body: { email, password }, returnHeaders: true });
  const headers = new Headers({ cookie: (signIn.headers.get("set-cookie") ?? "").split(";")[0] ?? "", "x-setup-key": env.SETUP_KEY });
  const api = auth.api as unknown as { adminCreateOAuthClient(o: { headers: Headers; body: Record<string, unknown> }): Promise<{ client_id: string; client_secret: string }> };
  const client = await api.adminCreateOAuthClient({
    headers,
    body: {
      client_name: "Example MCP client (agent)",
      redirect_uris: [`${origin}/callback`],
      grant_types: ["urn:ietf:params:oauth:grant-type:jwt-bearer"],
      response_types: [],
      token_endpoint_auth_method: "client_secret_basic",
      scope: "read",
    },
  });
  return Response.json({ client_id: client.client_id, client_secret: client.client_secret });
}

async function mcpEndpoint(request: Request, env: Env, origin: string): Promise<Response> {
  const challenge = { "WWW-Authenticate": `Bearer resource_metadata="${origin}/.well-known/oauth-protected-resource/mcp"` };
  const token = request.headers.get("authorization")?.match(/^Bearer (.+)$/i)?.[1];
  if (!token) return Response.json({ jsonrpc: "2.0", id: null, error: { code: -32001, message: "unauthorized" } }, { status: 401, headers: challenge });
  const auth = authFor(env, origin);
  const jwks = (await (await auth.handler(new Request(`${origin}/api/auth/jwks`))).json()) as Parameters<typeof createLocalJWKSet>[0];
  let claims: Record<string, unknown>;
  try {
    claims = (await jwtVerify(token, createLocalJWKSet(jwks), { issuer: `${origin}/api/auth`, audience: `${origin}/mcp` })).payload;
  } catch {
    return Response.json({ jsonrpc: "2.0", id: null, error: { code: -32001, message: "invalid token" } }, { status: 401, headers: { "WWW-Authenticate": `${challenge["WWW-Authenticate"]}, error="invalid_token"` } });
  }
  const rpc = (await request.json().catch(() => ({}))) as { id?: unknown };
  return Response.json({ jsonrpc: "2.0", id: rpc.id ?? null, result: { content: [{ type: "text", text: JSON.stringify({ tool: "whoami", sub: claims.sub, scope: claims.scope, aud: claims.aud, idjag: claims.idjag }) }] } });
}

export default {
  fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    return withExecutionContext(ctx, () => route(request, env));
  },
} satisfies ExportedHandler<Env>;

async function route(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  if (url.pathname === "/setup" && request.method === "POST") return setup(request, env, url.origin);
  if (url.pathname === "/mcp") return mcpEndpoint(request, env, url.origin);
  return authFor(env, url.origin).handler(request);
}
