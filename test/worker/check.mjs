// Phase 0: the spike's checks over HTTP against the deployed Worker.
// Usage: SPIKE_KEY_FILE=<file> node test/worker/check.mjs https://<worker>.workers.dev [rounds]
import { readFileSync } from "node:fs";
import { createRemoteJWKSet, decodeProtectedHeader, jwtVerify } from "jose";

const origin = process.argv[2];
const rounds = Number(process.argv[3] ?? 20);
const key = readFileSync(process.env.SPIKE_KEY_FILE, "utf8").trim();
const issuer = `${origin}/api/auth`;
const resource = `${origin}/mcp`;
const GRANT = "urn:example:ping";
let failures = 0;
const check = (name, ok, detail = "") => {
  if (!ok) failures++;
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? `  (${detail})` : ""}`);
};
const post = (path, body, headers = {}) =>
  fetch(`${origin}${path}`, { method: "POST", headers: { origin, ...headers }, body });
const json = (path, body, headers = {}) => post(path, JSON.stringify(body), { "content-type": "application/json", ...headers });
const token = (form, basic) =>
  post("/api/auth/oauth2/token", new URLSearchParams(form), {
    "content-type": "application/x-www-form-urlencoded",
    ...(basic ? { authorization: `Basic ${btoa(`${encodeURIComponent(basic.id)}:${encodeURIComponent(basic.secret)}`)}` } : {}),
  });

const email = `ada+${Date.now()}@example.com`;
const signUp = await json("/api/auth/sign-up/email", { email, password: "password-1234-spike", name: "Ada" });
check("sign-up", signUp.ok, String(signUp.status));
const cookie = (signUp.headers.get("set-cookie") ?? "").split(";")[0];
const createClient = async (grant_types, method = "client_secret_basic", extra = {}) => {
  const r = await json(
    "/api/auth/oauth2/create-client",
    { client_name: "spike", redirect_uris: ["https://app.example/cb"], grant_types, token_endpoint_auth_method: method, scope: "read", ...extra },
    { cookie, "x-spike-key": key },
  );
  return { status: r.status, body: await r.json() };
};
const noKey = await json("/api/auth/oauth2/create-client", { client_name: "x", redirect_uris: ["https://app.example/cb"], grant_types: [GRANT] }, { cookie });
check("client creation refused without the spike key", noKey.status === 401, String(noKey.status));
const c = await createClient([GRANT]);
check("confidential client created", c.status === 201, String(c.status));
const basic = { id: c.body.client_id, secret: c.body.client_secret };

// The grant, verified end to end.
const r = await token({ grant_type: GRANT, username: email, resource }, basic);
const body = await r.json();
check("ping grant dispatched on workerd", r.status === 200, `${r.status} ${body.error ?? ""} ${body.error_description ?? ""}`);
const jwks = createRemoteJWKSet(new URL(`${issuer}/jwks`));
if (r.ok) {
  check("ID-JAG typ header", decodeProtectedHeader(body.id_jag).typ === "oauth-id-jag+jwt");
  const v = await jwtVerify(body.id_jag, jwks, { typ: "oauth-id-jag+jwt", issuer, audience: "https://receiver.example" }).then((x) => x, (e) => e);
  check("ID-JAG verifies against the Worker's JWKS", !(v instanceof Error), v instanceof Error ? v.message : v.protectedHeader.alg);
  const at = await jwtVerify(body.access_token, jwks, { issuer, audience: resource }).then((x) => x, (e) => e);
  check("access token audience-bound to the MCP resource", !(at instanceof Error), at instanceof Error ? at.message : "");
}

// Refusals.
const e = async (res) => (await res.json()).error;
check("no credentials → invalid_client", (await e(await token({ grant_type: GRANT, client_id: basic.id, username: email }))) === "invalid_client");
check("wrong secret → invalid_client", (await e(await token({ grant_type: GRANT, username: email }, { id: basic.id, secret: "nope" }))) === "invalid_client");
const other = await createClient(["client_credentials"]);
check("client not registered for the grant → unauthorized_client", (await e(await token({ grant_type: GRANT, username: email }, { id: other.body.client_id, secret: other.body.client_secret }))) === "unauthorized_client");
const pub = await createClient([GRANT], "none", { application_type: "native" });
check("public client created", pub.status === 201 && pub.body.token_endpoint_auth_method === "none", String(pub.status));
check("public client → invalid_client", (await e(await token({ grant_type: GRANT, client_id: pub.body.client_id, username: email, resource }))) === "invalid_client");

// Discovery.
for (const path of ["/.well-known/oauth-authorization-server/api/auth", "/api/auth/.well-known/openid-configuration"]) {
  const d = await (await fetch(`${origin}${path}`)).json();
  check(`${path}: grant_types_supported has the grant`, d.grant_types_supported?.includes(GRANT));
  check(`${path}: extension metadata present`, d.example_ping_supported === true);
}
const prm = await (await fetch(`${origin}/.well-known/oauth-protected-resource/mcp`)).json();
check("protected resource metadata names the AS", prm.resource === resource && prm.authorization_servers?.includes(issuer));

// Timing rounds (CPU time comes from `wrangler tail`; wall time here includes the network).
const walls = [];
for (let i = 0; i < rounds; i++) {
  const t = performance.now();
  const res = await token({ grant_type: GRANT, username: email, resource }, basic);
  await res.arrayBuffer();
  walls.push(performance.now() - t);
}
walls.sort((a, b) => a - b);
console.log(`wall ms over ${rounds} ping requests: p50 ${walls[Math.floor(rounds / 2)].toFixed(0)}, p90 ${walls[Math.floor(rounds * 0.9)].toFixed(0)}`);
console.log(failures ? `${failures} FAILED` : "all passed");
process.exit(failures ? 1 : 0);
