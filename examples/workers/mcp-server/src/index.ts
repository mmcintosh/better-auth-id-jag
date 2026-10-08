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
      scope: "read write",
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
  const rpc = (await request.json().catch(() => ({}))) as { id?: unknown; method?: string; params?: { protocolVersion?: string; name?: string; arguments?: Record<string, unknown> } };
  // The minimum of MCP's Streamable HTTP: initialize, the initialized notification (202, no body),
  // ping, tools/list and tools/call. Any other method is "method not found".
  const reply = (result: unknown) => Response.json({ jsonrpc: "2.0", id: rpc.id ?? null, result });
  const text = (value: unknown) => ({ content: [{ type: "text", text: JSON.stringify(value) }] });
  // The layers this package doesn't decide (README, "What ID-JAG controls"): which tool a scope
  // unlocks, and what an agent (the token's `act`, as Okta sends) may do compared with a person.
  const scopes = typeof claims.scope === "string" ? claims.scope.split(" ") : [];
  const forbid = (scope: string, message: string) =>
    Response.json(
      { jsonrpc: "2.0", id: rpc.id ?? null, error: { code: -32003, message } },
      { status: 403, headers: { "WWW-Authenticate": `${challenge["WWW-Authenticate"]}, error="insufficient_scope", scope="${scope}"` } },
    );
  switch (rpc.method) {
    case "initialize":
      return reply({ protocolVersion: rpc.params?.protocolVersion ?? "2025-06-18", capabilities: { tools: {} }, serverInfo: { name: "id-jag-example-mcp", version: "0.1.0" } });
    case "notifications/initialized":
      return new Response(null, { status: 202 });
    case "ping":
      return reply({});
    case "tools/list":
      return reply({ tools: TOOLS.map(({ name, description, scope }) => ({ name, description: `${description} (scope: ${scope})`, inputSchema: { type: "object", properties: name === "add_note" ? { text: { type: "string" } } : {} } })) });
    case "tools/call": {
      const tool = TOOLS.find((t) => t.name === rpc.params?.name);
      if (!tool) return Response.json({ jsonrpc: "2.0", id: rpc.id ?? null, error: { code: -32602, message: "unknown tool" } });
      if (!scopes.includes(tool.scope)) return forbid(tool.scope, `${tool.name} needs the ${tool.scope} scope; this token has: ${scopes.join(" ") || "none"}`);
      if (tool.scope === "write" && claims.act !== undefined && env.AGENTS_MAY_WRITE !== "true") return forbid(tool.scope, `${tool.name}: an agent (act) may only read here`);
      if (tool.name === "whoami") return reply(text({ tool: "whoami", sub: claims.sub, scope: claims.scope, act: claims.act ?? null, aud: claims.aud, idjag: claims.idjag, exp: claims.exp }));
      if (tool.name === "list_notes") return reply(text({ tool: "list_notes", notes: ["(the demo keeps no notes)"] }));
      return reply(text({ tool: "add_note", accepted: true, text: String(rpc.params?.arguments?.text ?? "").slice(0, 200), note: "the demo doesn't store it" }));
    }
    default:
      return Response.json({ jsonrpc: "2.0", id: rpc.id ?? null, error: { code: -32601, message: "method not found" } });
  }
}

/** The demo's tools and the scope each needs. */
const TOOLS = [
  { name: "whoami", description: "Returns the authenticated user and the token's scopes", scope: "read" },
  { name: "list_notes", description: "Lists notes", scope: "read" },
  { name: "add_note", description: "Adds a note", scope: "write" },
] as const;

export default {
  fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    return withExecutionContext(ctx, () => route(request, env));
  },
} satisfies ExportedHandler<Env>;

// CORS for browser-based testers (CORS_ORIGINS): only the token endpoint, the metadata documents
// and /mcp, and no credentials (cookies) — what these callers send is a client secret or a bearer token.
const CORS_PATHS = /^\/(api\/auth\/oauth2\/token|mcp|\.well-known\/.*)$/;
function corsHeaders(request: Request, env: Env, url: URL): Record<string, string> | null {
  const origin = request.headers.get("origin");
  const allowed = (env.CORS_ORIGINS ?? "").split(",").map((o) => o.trim()).filter(Boolean);
  if (!origin || !allowed.includes(origin) || !CORS_PATHS.test(url.pathname)) return null;
  return { "access-control-allow-origin": origin, "access-control-allow-methods": "GET, POST, OPTIONS", "access-control-allow-headers": "authorization, content-type, accept, mcp-protocol-version", "access-control-expose-headers": "www-authenticate", "access-control-max-age": "600", vary: "origin" };
}

async function route(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const cors = corsHeaders(request, env, url);
  if (request.method === "OPTIONS" && cors) return new Response(null, { status: 204, headers: cors });
  const response = await dispatch(request, env, url);
  if (!cors) return response;
  const out = new Response(response.body, response);
  for (const [k, v] of Object.entries(cors)) out.headers.set(k, v);
  return out;
}

async function dispatch(request: Request, env: Env, url: URL): Promise<Response> {
  if (url.pathname === "/setup" && request.method === "POST") return setup(request, env, url.origin);
  if (url.pathname === "/mcp") return mcpEndpoint(request, env, url.origin);
  return authFor(env, url.origin).handler(request);
}
