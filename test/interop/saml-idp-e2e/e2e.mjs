// Cross-repo end to end: better-auth-saml-idp (feat/assertion-exchange) + better-auth-id-jag (main).
// A real SAML SSO at the IdP → the Assertion → our issuer's two SAML paths → our receiver.
import { readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { DOMParser, XMLSerializer } from "@xmldom/xmldom";
import { betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import { jwt } from "better-auth/plugins";
import { mcp } from "@better-auth/mcp";
import { oauthProvider } from "@better-auth/oauth-provider";
import { samlIdp } from "better-auth-saml-idp";
import { idJagGrant, idJagIssuer } from "better-auth-id-jag";
import { createLocalJWKSet, decodeJwt, decodeProtectedHeader, jwtVerify } from "jose";

const IDP = "https://idp.test";
const IDP_ISSUER = `${IDP}/api/auth`;
const MCP = "https://mcp.test";
const MCP_ISSUER = `${MCP}/api/auth`;
const RESOURCE = `${MCP}/mcp`;
const SP = { id: "agent-sp", entityId: "https://agent.test/sp", acs: "https://agent.test/acs" };
const SECRET = "e2e-secret-that-is-at-least-32-characters-long";
const signing = { privateKey: readFileSync(new URL("./idp.key", import.meta.url), "utf8"), certificate: readFileSync(new URL("./idp.crt", import.meta.url), "utf8") };
let failures = 0;
const check = (name, ok, detail = "") => {
  if (!ok) failures++;
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? `  (${detail})` : ""}`);
};
const basic = (c) => `Basic ${btoa(`${encodeURIComponent(c.client_id)}:${encodeURIComponent(c.client_secret)}`)}`;
const form = (o) => new URLSearchParams(Object.entries(o).filter(([, v]) => v !== undefined));
const b64url = (s) => Buffer.from(s, "utf8").toString("base64url");
const migrate = async (auth) => (await getMigrations((await auth.$context).options)).runMigrations();
const refused = [];
const events = { onRefused: (e) => void refused.push(e) };

// ---- The IdP: oauthProvider + jwt + samlIdp + idJagIssuer, on one database (two boots: the SP's
// tokenExchange names an OAuth client, which must exist first).
const idpDb = new DatabaseSync(":memory:");
const idpBase = (plugins) =>
  betterAuth({ baseURL: IDP, secret: SECRET, telemetry: { enabled: false }, database: idpDb, emailAndPassword: { enabled: true }, plugins });
const provider = () => oauthProvider({ loginPage: "/sign-in", consentPage: "/consent", scopes: ["openid", "profile", "email", "offline_access"] });
const boot1 = idpBase([jwt({ jwks: { keyPairConfig: { alg: "ES256" } } }), provider(), idJagIssuer({ authorize: () => ({ decision: "deny" }) })]);
await migrate(boot1);

// A user, and the agent's confidential OAuth client at the IdP (it signs in by SAML, so its SP is agent-sp).
const jar = new Map();
const browser = async (auth, url, init = {}) => {
  const headers = new Headers(init.headers);
  if (jar.size) headers.set("cookie", [...jar].map(([k, v]) => `${k}=${v}`).join("; "));
  if (init.method && init.method !== "GET") headers.set("origin", IDP);
  const r = await auth.handler(new Request(url, { ...init, headers, redirect: "manual" }));
  for (const c of r.headers.getSetCookie()) {
    const [pair] = c.split(";");
    const i = pair.indexOf("=");
    jar.set(pair.slice(0, i).trim(), pair.slice(i + 1).trim());
  }
  return r;
};
const email = "ada@corp.example";
const su = await browser(boot1, `${IDP_ISSUER}/sign-up/email`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ email, password: "password-1234-e2e", name: "Ada" }) });
check("IdP: user signed up", su.status === 200, String(su.status));
const ctx1 = await boot1.$context;
const user = (await ctx1.internalAdapter.findUserByEmail(email)).user;
await ctx1.internalAdapter.updateUser(user.id, { emailVerified: true });
const agent = await boot1.api.adminCreateOAuthClient({
  headers: new Headers({ cookie: [...jar].map(([k, v]) => `${k}=${v}`).join("; ") }),
  body: { client_name: "agent", redirect_uris: ["https://agent.test/cb"], grant_types: ["authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:token-exchange"], token_endpoint_auth_method: "client_secret_basic", scope: "openid profile email offline_access", skip_consent: true },
});
check("IdP: agent client created", typeof agent.client_id === "string");

// ---- The MCP server's AS, with the agent registered there under its own id.
const mcpDb = new DatabaseSync(":memory:");
let idpAuth; // the second boot, used for JWKS routing below
const mcpAuth = betterAuth({
  baseURL: MCP,
  secret: SECRET,
  telemetry: { enabled: false },
  database: mcpDb,
  emailAndPassword: { enabled: true },
  plugins: [
    jwt({ jwks: { keyPairConfig: { alg: "ES256" } } }),
    mcp({ loginPage: "/l", consentPage: "/c", resource: RESOURCE, scopes: ["read"] }),
    idJagGrant({ trustedIssuers: [{ issuer: IDP_ISSUER, jwksUri: `${IDP_ISSUER}/jwks`, jitProvisioning: { trustEmailVerified: true } }], fetch: (url, init) => idpAuth.handler(new Request(url, init)), events }),
  ],
});
await migrate(mcpAuth);
const mjar = new Map();
await mcpAuth.api.signUpEmail({ body: { email: "op@mcp.test", password: "password-1234-e2e", name: "op" } });
const opSignIn = await mcpAuth.api.signInEmail({ body: { email: "op@mcp.test", password: "password-1234-e2e" }, returnHeaders: true });
const mcpClient = await mcpAuth.api.adminCreateOAuthClient({
  headers: new Headers({ cookie: (opSignIn.headers.get("set-cookie") ?? "").split(";")[0] }),
  body: { client_name: "agent", redirect_uris: ["https://agent.test/cb"], grant_types: ["urn:ietf:params:oauth:grant-type:jwt-bearer"], token_endpoint_auth_method: "client_secret_basic", scope: "read" },
});
void mjar;

// ---- Second IdP boot: the SAML IdP with the exchange on for agent-sp → the agent client; our issuer with both SAML paths.
idpAuth = idpBase([
  jwt({ jwks: { keyPairConfig: { alg: "ES256" } } }),
  provider(),
  samlIdp({ entityId: `${IDP_ISSUER}/saml2/idp`, loginPage: "/sign-in", signing, serviceProviders: [{ id: SP.id, entityId: SP.entityId, acsUrls: [SP.acs], allowIdpInitiated: true, tokenExchange: { clientId: agent.client_id } }] }),
  idJagIssuer({
    saml: { subjectTokens: true, refreshTokens: {} },
    authorize: ({ audience }) => (audience === MCP_ISSUER ? { decision: "allow", scopes: ["read"], resource: RESOURCE, clientIdAtResource: mcpClient.client_id, claims: { email: true } } : { decision: "deny" }),
    events,
  }),
]);
await migrate(idpAuth);

// A SAML sign-in (IdP-initiated to agent-sp), as the agent's SAML library receives it: the Assertion element.
const sso = async () => {
  const r = await browser(idpAuth, `${IDP_ISSUER}/saml2/idp/init?sp=${SP.id}`);
  const html = await r.text();
  const v = /name="SAMLResponse" value="([^"]*)"/.exec(html)?.[1];
  if (!v) throw new Error(`no auto-POST (status ${r.status}): ${html.slice(0, 200)}`);
  const xml = Buffer.from(v.replace(/&#x2B;|&amp;/g, (m) => (m === "&amp;" ? "&" : "+")), "base64").toString("utf8");
  const doc = new DOMParser().parseFromString(xml, "text/xml");
  return new XMLSerializer().serializeToString(doc.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "Assertion")[0]);
};
const token = (auth, issuer, body, client) => auth.handler(new Request(`${issuer}/oauth2/token`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", authorization: basic(client) }, body: form(body) })).then(async (r) => ({ status: r.status, body: await r.json() }));
const exchange = (o) => token(idpAuth, IDP_ISSUER, { grant_type: "urn:ietf:params:oauth:grant-type:token-exchange", ...o }, o.client ?? agent);
const redeem = (assertion) => token(mcpAuth, MCP_ISSUER, { grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion }, mcpClient);
const mcpJwks = async () => createLocalJWKSet(await (await mcpAuth.handler(new Request(`${MCP_ISSUER}/jwks`))).json());
const idpJwks = async () => createLocalJWKSet(await (await idpAuth.handler(new Request(`${IDP_ISSUER}/jwks`))).json());

// ---- Path (b): SAML assertion → refresh token (draft -04 §4.5) → ID-JAG → access token.
const a1 = await sso();
check("SSO: an Assertion from the SAML IdP", a1.includes("Assertion") && a1.includes(SP.entityId));
const rt = await exchange({ requested_token_type: "urn:ietf:params:oauth:token-type:refresh_token", subject_token_type: "urn:ietf:params:oauth:token-type:saml2", subject_token: b64url(a1), scope: "openid offline_access" });
check("path (b): assertion → refresh token", rt.status === 200 && rt.body.issued_token_type === "urn:ietf:params:oauth:token-type:refresh_token" && rt.body.token_type === "N_A" && typeof rt.body.access_token === "string", `${rt.status} ${JSON.stringify(rt.body).slice(0, 200)}`);
const replayB = await exchange({ requested_token_type: "urn:ietf:params:oauth:token-type:refresh_token", subject_token_type: "urn:ietf:params:oauth:token-type:saml2", subject_token: b64url(a1), scope: "openid offline_access" });
check("path (b): the same assertion again is refused", replayB.status === 400 && replayB.body.error === "invalid_grant", `${replayB.status} ${JSON.stringify(replayB.body)}`);
if (rt.status === 200) {
  const jag = await exchange({ requested_token_type: "urn:ietf:params:oauth:token-type:id-jag", subject_token_type: "urn:ietf:params:oauth:token-type:refresh_token", subject_token: rt.body.access_token, audience: MCP_ISSUER, resource: RESOURCE, scope: "read" });
  check("refresh token → ID-JAG", jag.status === 200 && jag.body.issued_token_type === "urn:ietf:params:oauth:token-type:id-jag", `${jag.status} ${JSON.stringify(jag.body).slice(0, 200)}`);
  if (jag.status === 200) {
    const v = await jwtVerify(jag.body.access_token, await idpJwks(), { issuer: IDP_ISSUER, audience: MCP_ISSUER, typ: "oauth-id-jag+jwt" }).then((x) => x, (e) => e);
    check("ID-JAG verifies against the IdP's JWKS, sub = the SAML user, client_id = the agent's id at the MCP AS", !(v instanceof Error) && v.payload.sub === user.id && v.payload.client_id === mcpClient.client_id, v instanceof Error ? v.message : JSON.stringify(v.payload).slice(0, 160));
    const at = await redeem(jag.body.access_token);
    check("receiver: ID-JAG → access token", at.status === 200, `${at.status} ${JSON.stringify(at.body).slice(0, 160)} ${refused.at(-1)?.reason ?? ""}`);
    if (at.status === 200) {
      const a = await jwtVerify(at.body.access_token, await mcpJwks(), { issuer: MCP_ISSUER, audience: RESOURCE }).then((x) => x, (e) => e);
      check("access token audience-bound to the MCP resource, no refresh token", !(a instanceof Error) && at.body.refresh_token === undefined, a instanceof Error ? a.message : `scope ${a.payload.scope}`);
    }
  }
}

// ---- Path (a): SAML assertion → ID-JAG directly → access token.
const a2 = await sso();
const direct = await exchange({ requested_token_type: "urn:ietf:params:oauth:token-type:id-jag", subject_token_type: "urn:ietf:params:oauth:token-type:saml2", subject_token: b64url(a2), audience: MCP_ISSUER, resource: RESOURCE, scope: "read" });
check("path (a): assertion → ID-JAG", direct.status === 200 && direct.body.issued_token_type === "urn:ietf:params:oauth:token-type:id-jag", `${direct.status} ${JSON.stringify(direct.body).slice(0, 200)}`);
if (direct.status === 200) {
  check("ID-JAG header typ", decodeProtectedHeader(direct.body.access_token).typ === "oauth-id-jag+jwt");
  check("ID-JAG sub = the SAML user", decodeJwt(direct.body.access_token).sub === user.id);
  const at = await redeem(direct.body.access_token);
  check("receiver: path (a) ID-JAG → access token", at.status === 200, `${at.status} ${JSON.stringify(at.body).slice(0, 160)}`);
}
const replayA = await exchange({ requested_token_type: "urn:ietf:params:oauth:token-type:id-jag", subject_token_type: "urn:ietf:params:oauth:token-type:saml2", subject_token: b64url(a2), audience: MCP_ISSUER, resource: RESOURCE, scope: "read" });
check("path (a): the same assertion again is refused", replayA.status === 400 && replayA.body.error === "invalid_grant", `${replayA.status} ${JSON.stringify(replayA.body)}`);

// ---- Attacks that cross the repos.
const a3 = await sso();
const tampered = a3.replace(email, "eve@corp.example");
const t = await exchange({ requested_token_type: "urn:ietf:params:oauth:token-type:id-jag", subject_token_type: "urn:ietf:params:oauth:token-type:saml2", subject_token: b64url(tampered), audience: MCP_ISSUER, resource: RESOURCE, scope: "read" });
check("a tampered assertion is refused", t.status === 400 && t.body.error === "invalid_grant", `${t.status} ${JSON.stringify(t.body)}`);
const afterTamper = await exchange({ requested_token_type: "urn:ietf:params:oauth:token-type:id-jag", subject_token_type: "urn:ietf:params:oauth:token-type:saml2", subject_token: b64url(a3), audience: MCP_ISSUER, resource: RESOURCE, scope: "read" });
check("…and didn't burn the real one (consumed only after the signature)", afterTamper.status === 200, `${afterTamper.status} ${JSON.stringify(afterTamper.body).slice(0, 160)}`);
const other = await ctx1.internalAdapter; void other;
const a4 = await sso();
const wrongClient = await idpAuth.api.adminCreateOAuthClient({
  headers: new Headers({ cookie: [...jar].map(([k, v]) => `${k}=${v}`).join("; ") }),
  body: { client_name: "other", redirect_uris: ["https://other.test/cb"], grant_types: ["urn:ietf:params:oauth:grant-type:token-exchange", "refresh_token"], token_endpoint_auth_method: "client_secret_basic", scope: "openid offline_access" },
});
const wc = await exchange({ client: wrongClient, requested_token_type: "urn:ietf:params:oauth:token-type:id-jag", subject_token_type: "urn:ietf:params:oauth:token-type:saml2", subject_token: b64url(a4), audience: MCP_ISSUER, resource: RESOURCE, scope: "read" });
check("another client presenting the agent's assertion is refused", wc.status === 400 && wc.body.error === "invalid_grant", `${wc.status} ${JSON.stringify(wc.body)}`);
const own = await exchange({ requested_token_type: "urn:ietf:params:oauth:token-type:id-jag", subject_token_type: "urn:ietf:params:oauth:token-type:saml2", subject_token: b64url(a4), audience: MCP_ISSUER, resource: RESOURCE, scope: "read" });
check("…and the right client can still use it (a wrong client doesn't consume)", own.status === 200, `${own.status}`);

const reasons = [...new Set(refused.map((r) => r.reason))].join(", ");
console.log(`\nrefusal reasons seen: ${reasons}`);
console.log(failures ? `${failures} FAILED` : "all passed");
process.exit(failures ? 1 : 0);
