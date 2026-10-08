// The MCP client's side of Enterprise-Managed Authorization, step by step, against the two example
// Workers. It prints every token it gets (decoded) and calls the MCP server's tools.
//
//   SETUP_KEY_FILE=<file> node examples/workers/client.mjs <idp-origin> <mcp-origin> [--setup] [--as=reader] [--scope="read write"] [--cutoff]
//
// --setup registers the agent at both servers first (the MCP server issues it its own client id,
// which the IdP records as the client's id "at the resource": the ID-JAG's client_id), and creates the
// two demo users: agent-user@ (the IdP's WRITERS lets its agent have write) and reader-user@ (read only).
// --as=reader signs in as the read-only user. --scope is what the agent asks for (default "read write").
// The layers (README, "What ID-JAG controls"): the IdP decides who may have write; the MCP server decides
// which tool each scope unlocks (add_note needs write: 403 insufficient_scope without it).
// --cutoff then calls whoami every 10 s until the access token stops working, and reports how long that
// took: how long an agent keeps access after the IdP stops issuing it ID-JAGs.
import { readFileSync, writeFileSync } from "node:fs";

const [idp, mcp] = process.argv.slice(2, 4);
if (!idp || !mcp) throw new Error("usage: node client.mjs <idp-origin> <mcp-origin> [--setup]");
const STATE = new URL("./.client-state.json", import.meta.url);
const key = process.env.SETUP_KEY_FILE ? readFileSync(process.env.SETUP_KEY_FILE, "utf8").trim() : "";
const asReader = process.argv.includes("--as=reader");
const user = { email: asReader ? "reader-user@example.com" : "agent-user@example.com", password: "example-password-1234" };
const scope = (process.argv.find((a) => a.startsWith("--scope=")) ?? "--scope=read write").slice("--scope=".length);
const cutoff = process.argv.includes("--cutoff");
const b64url = (bytes) => Buffer.from(bytes).toString("base64url");
const decode = (jwt) => jwt.split(".").slice(0, 2).map((p) => JSON.parse(Buffer.from(p, "base64url").toString()));
const basic = (c) => `Basic ${btoa(`${encodeURIComponent(c.client_id)}:${encodeURIComponent(c.client_secret)}`)}`;
const step = (n, what, value) => console.log(`\n${n}. ${what}\n${typeof value === "string" ? value : JSON.stringify(value, null, 2)}`);

async function post(url, body, headers = {}) {
  const r = await fetch(url, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", ...headers }, body: new URLSearchParams(body), redirect: "manual" });
  const text = await r.text();
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    json = { raw: text };
  }
  return { status: r.status, json, headers: r.headers };
}

let state;
if (process.argv.includes("--setup")) {
  if (!key) throw new Error("--setup needs SETUP_KEY_FILE");
  const json = (url, body) => fetch(url, { method: "POST", headers: { "content-type": "application/json", "x-setup-key": key }, body: JSON.stringify(body) }).then(async (r) => (r.ok ? r.json() : Promise.reject(new Error(`${url}: ${r.status} ${await r.text()}`))));
  const atMcp = await json(`${mcp}/setup`, { email: "operator@example.com", password: user.password });
  const atIdp = await json(`${idp}/setup`, { email: "agent-user@example.com", password: user.password, clientIdAtResource: atMcp.client_id });
  // The second demo user (the setup route also registers a client for it, which this script doesn't use).
  await json(`${idp}/setup`, { email: "reader-user@example.com", password: user.password, clientIdAtResource: atMcp.client_id });
  state = { atIdp, atMcp };
  writeFileSync(STATE, JSON.stringify(state, null, 2), { mode: 0o600 });
  step(0, "Registered the agent at the MCP server, then at the IdP (with its MCP client id)", { idpClientId: atIdp.client_id, mcpClientId: atMcp.client_id });
} else state = JSON.parse(readFileSync(STATE, "utf8"));

// What the MCP client discovers first: the MCP server's protected resource metadata, and its AS.
const prm = await (await fetch(`${mcp}/.well-known/oauth-protected-resource/mcp`)).json();
const asIssuer = prm.authorization_servers[0];
const asMeta = await (await fetch(`${new URL(asIssuer).origin}/.well-known/oauth-authorization-server${new URL(asIssuer).pathname}`)).json();
step(1, "MCP server metadata: resource, its authorization server, and that it takes ID-JAGs", { resource: prm.resource, authorization_server: asIssuer, authorization_grant_profiles_supported: asMeta.authorization_grant_profiles_supported });

// 2. Single sign-on at the IdP (programmatic here; a person in a browser in real life), then an ID token.
const signIn = await fetch(`${idp}/api/auth/sign-in/email`, { method: "POST", headers: { "content-type": "application/json", origin: idp }, body: JSON.stringify(user) });
const signInBody = await signIn.text();
if (!signIn.ok) throw new Error(`sign-in: ${signIn.status} ${signInBody}`);
const cookie = signIn.headers.getSetCookie().map((c) => c.split(";")[0]).join("; ");
const verifier = b64url(crypto.getRandomValues(new Uint8Array(32)));
const challenge = b64url(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))));
const redirect = `${idp}/callback`;
const q = new URLSearchParams({ response_type: "code", client_id: state.atIdp.client_id, redirect_uri: redirect, scope: "openid email offline_access", state: "s", code_challenge: challenge, code_challenge_method: "S256" });
const authz = await fetch(`${idp}/api/auth/oauth2/authorize?${q}`, { headers: { cookie }, redirect: "manual" });
// A browser gets a 302; a fetch without Accept: text/html gets { redirect: true, url }.
// Read every response body: an unread one keeps Node's connection busy and later requests stall.
const authzBody = await authz.text();
const location = authz.headers.get("location") ?? (() => { try { return JSON.parse(authzBody).url; } catch { return ""; } })() ?? "";
const code = new URL(location, idp).searchParams.get("code");
if (!code) throw new Error(`authorize: ${authz.status} ${location} ${authzBody}`);
const tokens = await post(`${idp}/api/auth/oauth2/token`, { grant_type: "authorization_code", code, redirect_uri: redirect, code_verifier: verifier }, { authorization: basic(state.atIdp) });
if (!tokens.json.id_token) throw new Error(`token: ${tokens.status} ${JSON.stringify(tokens.json)}`);
step(2, "Signed in at the IdP: ID token (payload)", decode(tokens.json.id_token)[1]);

// 3. Token exchange at the IdP: ID token → ID-JAG for the MCP server's authorization server.
const exchanged = await post(
  `${idp}/api/auth/oauth2/token`,
  {
    grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
    requested_token_type: "urn:ietf:params:oauth:token-type:id-jag",
    audience: asIssuer,
    resource: prm.resource,
    scope,
    subject_token: tokens.json.id_token,
    subject_token_type: "urn:ietf:params:oauth:token-type:id_token",
  },
  { authorization: basic(state.atIdp) },
);
if (exchanged.status !== 200) throw new Error(`exchange: ${exchanged.status} ${JSON.stringify(exchanged.json)}`);
const [jagHeader, jagClaims] = decode(exchanged.json.access_token);
step(3, "Token exchange at the IdP: ID-JAG (header and claims)", { response: { ...exchanged.json, access_token: "…" }, header: jagHeader, claims: jagClaims });

// 4. JWT bearer grant at the MCP server's AS: ID-JAG → access token for the MCP server.
const granted = await post(`${asMeta.token_endpoint}`, { grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion: exchanged.json.access_token }, { authorization: basic(state.atMcp) });
if (granted.status !== 200) throw new Error(`jwt-bearer: ${granted.status} ${JSON.stringify(granted.json)}`);
step(4, "JWT bearer grant at the MCP server: access token (claims)", { response: { ...granted.json, access_token: "…" }, claims: decode(granted.json.access_token)[1] });

if (process.env.DEBUG_TOKEN_FILE) writeFileSync(process.env.DEBUG_TOKEN_FILE, granted.json.access_token, { mode: 0o600 });

// 5. Call the MCP server's tools: whoami and list_notes need read, add_note needs write.
const tool = async (name, args = {}) => {
  const r = await fetch(prm.resource, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${granted.json.access_token}` },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } }),
  });
  const body = await r.json();
  return { status: r.status, body, challenge: r.headers.get("www-authenticate") };
};
const call = await tool("whoami");
step(5, `MCP tools/call whoami → ${call.status}`, call.body);
const notes = await tool("list_notes");
step("5a", `MCP tools/call list_notes (read) → ${notes.status}`, notes.body);
const write = await tool("add_note", { text: "from the agent" });
step("5b", `MCP tools/call add_note (write) → ${write.status}`, { ...write.body, ...(write.challenge ? { "WWW-Authenticate": write.challenge } : {}) });
const hasWrite = String(granted.json.scope ?? "").split(" ").includes("write");

// And the same ID-JAG once more: single use.
const replay = await post(`${asMeta.token_endpoint}`, { grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion: exchanged.json.access_token }, { authorization: basic(state.atMcp) });
step(6, `The same ID-JAG again → ${replay.status}`, replay.json);

// 7. How long the access token keeps working (an IdP decision now would only stop new ID-JAGs).
if (cutoff) {
  const issued = decode(granted.json.access_token)[1];
  const started = Date.now();
  step(7, `Polling whoami every 10 s until the access token stops working (expires_in ${granted.json.expires_in} s)`, "");
  for (;;) {
    const r = await tool("whoami");
    const elapsed = Math.round((Date.now() - issued.iat * 1000) / 1000);
    if (r.status !== 200) {
      step("7a", `Stopped working ${elapsed} s after it was issued (${Math.round((Date.now() - started) / 1000)} s of polling) → ${r.status}`, r.challenge ?? r.body);
      break;
    }
    if (Date.now() - started > 15 * 60_000) throw new Error("still working after 15 minutes");
    await new Promise((resolve) => setTimeout(resolve, 10_000));
  }
}
// Expected: whoami 200; add_note 200 only with write, else 403; the replay refused.
if (call.status !== 200 || notes.status !== 200 || write.status !== (hasWrite ? 200 : 403) || replay.status !== 400) process.exit(1);
