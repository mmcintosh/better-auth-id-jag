// Plays the AI agent against Okta Cross App Access and our MCP server (the receiver):
//   1. you sign in at Okta in a browser (authorization code + PKCE, to http://localhost:8765/callback);
//   2. ID token → ID-JAG by token exchange at Okta (the agent's Okta client credentials);
//   3. ID-JAG → access token by jwt-bearer at the MCP server (the agent's client there);
//   4. tools/call whoami on the MCP server.
//
//   OKTA_ORG=https://<org>.okta.com OKTA_CLIENT_ID=<agent's Okta client id> \
//   OKTA_SECRET_FILE=<file> MCP_CREDENTIALS_FILE=<json {client_id, client_secret}> \
//   node examples/workers/okta-agent.mjs https://<mcp-origin>
//
// Add http://localhost:8765/callback as a sign-in redirect URI of the agent in Okta first.
import { createServer } from "node:http";
import { readFileSync } from "node:fs";

const mcp = process.argv[2];
const org = process.env.OKTA_ORG;
const oktaClient = { client_id: process.env.OKTA_CLIENT_ID, client_secret: readFileSync(process.env.OKTA_SECRET_FILE, "utf8").trim() };
const mcpClient = JSON.parse(readFileSync(process.env.MCP_CREDENTIALS_FILE, "utf8"));
if (!mcp || !org || !oktaClient.client_id) throw new Error("see the header for usage");
const redirect = "http://localhost:8765/callback";
const b64url = (b) => Buffer.from(b).toString("base64url");
const decode = (jwt) => jwt.split(".").slice(0, 2).map((p) => JSON.parse(Buffer.from(p, "base64url").toString()));
const basic = (c) => `Basic ${btoa(`${encodeURIComponent(c.client_id)}:${encodeURIComponent(c.client_secret)}`)}`;
const step = (n, what, value) => console.log(`\n${n}. ${what}\n${JSON.stringify(value, null, 2)}`);
const post = async (url, form, auth) => {
  const r = await fetch(url, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json", authorization: auth }, body: new URLSearchParams(form) });
  const text = await r.text();
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    json = { raw: text.slice(0, 500) };
  }
  return { status: r.status, json };
};

// The receiver's metadata: the audience for the ID-JAG and the token endpoint.
const prm = await (await fetch(`${mcp}/.well-known/oauth-protected-resource/mcp`)).json();
const asIssuer = prm.authorization_servers[0];
const asMeta = await (await fetch(`${new URL(asIssuer).origin}/.well-known/oauth-authorization-server${new URL(asIssuer).pathname}`)).json();
step(0, "MCP server", { resource: prm.resource, issuer: asIssuer, grant_profiles: asMeta.authorization_grant_profiles_supported });

// 1. Sign in at Okta.
const verifier = b64url(crypto.getRandomValues(new Uint8Array(32)));
const challenge = b64url(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))));
const state = b64url(crypto.getRandomValues(new Uint8Array(16)));
const authorize = `${org}/oauth2/v1/authorize?${new URLSearchParams({ response_type: "code", client_id: oktaClient.client_id, redirect_uri: redirect, scope: "openid profile email offline_access", state, code_challenge: challenge, code_challenge_method: "S256" })}`;
const code = await new Promise((resolve, reject) => {
  const server = createServer((req, res) => {
    const u = new URL(req.url, redirect);
    if (u.pathname !== "/callback") return void res.writeHead(404).end();
    res.writeHead(200, { "content-type": "text/plain" }).end("Signed in. You can close this tab; the script carries on.");
    server.close();
    if (u.searchParams.get("state") !== state) return reject(new Error("state mismatch"));
    if (u.searchParams.get("error")) return reject(new Error(`${u.searchParams.get("error")}: ${u.searchParams.get("error_description")}`));
    resolve(u.searchParams.get("code"));
  }).listen(8765, "127.0.0.1", () => console.log(`\nOpen this in your browser and sign in:\n\n${authorize}\n`));
});
const tokens = await post(`${org}/oauth2/v1/token`, { grant_type: "authorization_code", code, redirect_uri: redirect, code_verifier: verifier }, basic(oktaClient));
if (!tokens.json.id_token) throw new Error(`Okta token: ${tokens.status} ${JSON.stringify(tokens.json)}`);
step(1, "Okta ID token (claims)", decode(tokens.json.id_token)[1]);

// 2. Token exchange at Okta: ID token → ID-JAG for our MCP server's authorization server.
const exchange = (subject, type) =>
  post(
    `${org}/oauth2/v1/token`,
    { grant_type: "urn:ietf:params:oauth:grant-type:token-exchange", requested_token_type: "urn:ietf:params:oauth:token-type:id-jag", audience: asIssuer, resource: prm.resource, scope: "read", subject_token: subject, subject_token_type: type },
    basic(oktaClient),
  );
let jag = await exchange(tokens.json.id_token, "urn:ietf:params:oauth:token-type:id_token");
if (jag.status !== 200 && tokens.json.refresh_token) {
  step("2a", "Exchange of the ID token refused; trying the refresh token", jag.json);
  jag = await exchange(tokens.json.refresh_token, "urn:ietf:params:oauth:token-type:refresh_token");
}
if (jag.status !== 200) throw new Error(`Okta token exchange: ${jag.status} ${JSON.stringify(jag.json)}`);
const [h, c] = decode(jag.json.access_token);
step(2, "Okta ID-JAG (header and claims)", { response: { ...jag.json, access_token: "…" }, header: h, claims: c });

// 3. jwt-bearer at our MCP server.
const granted = await post(asMeta.token_endpoint, { grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion: jag.json.access_token }, basic(mcpClient));
step(3, `jwt-bearer at the MCP server → ${granted.status}`, granted.status === 200 ? { ...granted.json, access_token: "…", claims: decode(granted.json.access_token)[1] } : granted.json);
if (granted.status !== 200) process.exit(1);

// 4. The tool.
const call = await fetch(prm.resource, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${granted.json.access_token}` }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "whoami", arguments: {} } }) });
step(4, `MCP tools/call whoami → ${call.status}`, await call.json());
