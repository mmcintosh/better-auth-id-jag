// The tester's pages, server-rendered. Everything a tester or their IdP sent is escaped. The only scripts are the
// tester's own /app.js (copy buttons) and Cloudflare Turnstile's; the Content-Security-Policy allows nothing else.
import { type RuleResult, SUPPORTED_DRAFT } from "better-auth-id-jag";
import { APP_JS_URL } from "./app";

export const esc = (v: unknown): string =>
  String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c] as string);

// form-action also applies to where a form's answer redirects (Chrome checks it): the sign-in form posts here and is
// redirected to GitHub or GitLab, so those two are allowed, on the home page only.
const csp = (formAction: string) => `default-src 'none'; img-src 'self'; style-src 'unsafe-inline'; script-src 'self' https://challenges.cloudflare.com; frame-src https://challenges.cloudflare.com; connect-src https://challenges.cloudflare.com; form-action ${formAction}; base-uri 'none'; frame-ancestors 'none'`;
const SIGN_IN_FORM_ACTION = "'self' https://github.com https://gitlab.com";

const STYLE = `
:root { --bg: #fbfbf9; --fg: #1d1d1b; --muted: #5d5d58; --line: #ddddd6; --pass: #1f7a3a; --fail: #b3261e; --warn: #8a5a00; --code: #f0f0eb; }
@media (prefers-color-scheme: dark) { :root { --bg: #161615; --fg: #ecece6; --muted: #a3a39c; --line: #34342f; --pass: #6fcf8a; --fail: #ff8a80; --warn: #e8b85a; --code: #23231f; } }
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--fg); font: 16px/1.55 system-ui, sans-serif; }
main { max-width: 860px; margin: 0 auto; padding: 24px 16px 64px; }
h1 { font-size: 1.6rem; margin: 0 0 4px; } h2 { font-size: 1.15rem; margin: 32px 0 8px; }
p, li { color: var(--fg); } .muted { color: var(--muted); }
code, pre { background: var(--code); border-radius: 4px; font: 0.88em ui-monospace, monospace; }
code { padding: 1px 4px; overflow-wrap: anywhere; } pre { padding: 12px; overflow-x: auto; }
table { border-collapse: collapse; width: 100%; font-size: 0.92rem; } td, th { border-top: 1px solid var(--line); padding: 6px 8px; text-align: left; vertical-align: top; }
.pass { color: var(--pass); } .fail { color: var(--fail); } .warn { color: var(--warn); } .info, .skip { color: var(--muted); }
input[type=url], input[type=text], input[type=password], select { width: 100%; padding: 8px; font: inherit; border: 1px solid var(--line); border-radius: 4px; background: var(--bg); color: var(--fg); }
button { padding: 8px 16px; font: inherit; border-radius: 4px; border: 1px solid var(--fg); background: var(--fg); color: var(--bg); cursor: pointer; }
.box { border: 1px solid var(--line); border-radius: 6px; padding: 16px; margin: 16px 0; }
.wrap { overflow-x: auto; }
.copy { display: inline-flex; gap: 6px; align-items: center; flex-wrap: wrap; }
button.small { padding: 2px 8px; font-size: 0.8rem; background: var(--bg); color: var(--fg); border-color: var(--line); }
textarea { width: 100%; font: 0.88em ui-monospace, monospace; padding: 8px; border: 1px solid var(--line); border-radius: 4px; background: var(--bg); color: var(--fg); }
`;

export function page(title: string, body: string, { turnstile = false, status = 200, headers = {} as Record<string, string>, formAction = "'self'" } = {}): Response {
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${esc(title)}</title><link rel="icon" href="/logo.svg" type="image/svg+xml"><style>${STYLE}</style><script src="${APP_JS_URL}" defer></script>${turnstile ? '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>' : ""}</head><body><main>${body}</main></body></html>`;
  // Referrer-Policy same-origin, not no-referrer: under no-referrer a browser sends "Origin: null" on a form post (the
  // Fetch standard), and every form here is checked for this site's own origin. Other sites still get no referrer.
  return new Response(html, { status, headers: { "content-type": "text/html; charset=utf-8", "content-security-policy": csp(formAction), "x-content-type-options": "nosniff", "referrer-policy": "same-origin", "cache-control": "no-store", ...headers } });
}

const FOOTER = `<p class="muted" style="margin-top:48px">Checked against ${esc(SUPPORTED_DRAFT)} as <a href="https://github.com/mmcintosh/better-auth-id-jag">better-auth-id-jag</a> reads it: <a href="https://github.com/mmcintosh/better-auth-id-jag/blob/main/docs/test-your-idp.md#the-rules">the rules</a>, each with its source, and <a href="https://github.com/mmcintosh/better-auth-id-jag/blob/main/src/core/check.ts">their code</a>. A testing aid, not a conformance or certification test. Test data only. A registration lasts 24 hours; then its client, users, results and logs are deleted. Results are visible only to the account that registered. No uptime promise: the tester may close at any time.</p>`;

/** A value with a copy button (the script at /app.js). */
const copyable = (value: string) => `<span class="copy"><code>${esc(value)}</code><button type="button" class="small" data-copy="${esc(value)}">Copy</button></span>`;

/** Paste an ID-JAG and the tester redeems it with this registration's own client: no curl, no secret to handle. */
const checkForm = (registrationId: string) => `<form method="post" action="/check" class="box">
<input type="hidden" name="registration" value="${esc(registrationId)}">
<p><label><strong>Check an ID-JAG.</strong> Paste one your IdP minted for this registration, then press Check: the tester redeems it with your client here and adds the report below.<br><textarea name="assertion" rows="4" required maxlength="16384" placeholder="eyJ..."></textarea></label></p>
<p><button>Check</button></p>
</form>`;

/**
 * "Run the whole flow": the tester plays the client. The tester's IdP needs a client for it, which this form names;
 * its secret is kept only for the run (sealed, at most 10 minutes).
 */
const runForm = (origin: string, registrationId: string, clientId: string) => `<form method="post" action="/flow/start" class="box">
<input type="hidden" name="registration" value="${esc(registrationId)}">
<p><strong>Run the whole flow.</strong> The tester plays the client: it sends you to your IdP to sign in, exchanges the ID token for an ID-JAG, checks your IdP's answer, and redeems the ID-JAG here.</p>
<details><summary>Your IdP needs a client for the tester</summary>
<table><tr><td>Redirect URI</td><td>${copyable(`${origin}/flow/callback`)}</td></tr>
<tr><td>Grants</td><td>the authorization code grant (scope <code>openid</code>, PKCE S256) and the token exchange</td></tr>
<tr><td>ID-JAGs for</td><td>audience ${copyable(`${origin}/api/auth`)}<br>resource ${copyable(`${origin}/mcp`)}<br><code>client_id</code> in the ID-JAG: ${copyable(clientId)}</td></tr></table>
<p class="muted">The tester asks your IdP for the ID-JAG with that audience and resource, and redeems it with this registration's client. Your IdP's tokens are never stored or shown.</p>
</details>
<p><label>Your IdP client's id<br><input type="text" name="client_id" required maxlength="256" autocomplete="off"></label></p>
<p><label>Its secret (kept only for this run)<br><input type="password" name="client_secret" required maxlength="512" autocomplete="off"></label></p>
<p><label>How it authenticates at your token endpoint<br><select name="auth_method"><option value="client_secret_basic">client_secret_basic (HTTP Basic)</option><option value="client_secret_post">client_secret_post (in the form body)</option></select></label></p>
<p><label>Scope to ask for<br><input type="text" name="scope" value="read" maxlength="256"></label></p>
<p><button>Run</button></p>
</form>`;

/** "Run the whole flow", between the form and the IdP: the pages' policy lets forms post only to this site. */
export function continueToIdp(to: string, host: string): Response {
  return page("Sign in at your IdP", `<h1>Sign in at your IdP</h1><p>The tester has started the run. Continue to your IdP's sign-in at <code>${esc(host)}</code>; it sends you back here, and the tester does the rest.</p><p><a href="${esc(to)}"><strong>Continue to ${esc(host)}</strong></a></p><p class="muted">The run waits 10 minutes.</p>${FOOTER}`);
}

/** The values a tester's IdP mints with, each with a copy button, and all of them as one JSON template. */
const idpValues = (origin: string, issuer: string, clientId: string) => {
  const audience = `${origin}/api/auth`;
  const resource = `${origin}/mcp`;
  const template = JSON.stringify({ header: { typ: "oauth-id-jag+jwt" }, claims: { iss: issuer, aud: audience, client_id: clientId, resource, scope: "read" } }, null, 2);
  return `<table><tr><td><code>aud</code></td><td>${copyable(audience)}<br><span class="muted">this authorization server's issuer, exactly</span></td></tr>
<tr><td><code>client_id</code></td><td>${copyable(clientId)}<br><span class="muted">your client here, not your IdP's own</span></td></tr>
<tr><td><code>resource</code></td><td>${copyable(resource)} <span class="muted">(optional)</span></td></tr>
<tr><td><code>scope</code></td><td>${copyable("read")}</td></tr>
<tr><td>header <code>typ</code></td><td>${copyable("oauth-id-jag+jwt")}</td></tr></table>
<p>All of it at once, for your IdP's configuration: <button type="button" class="small" data-copy="${esc(template)}">Copy as JSON</button></p>
<pre>${esc(template)}</pre>`;
};

const PROVIDER_NAMES = { github: "GitHub", gitlab: "GitLab" } as const;

export function landing(signedIn: boolean, closed: boolean, providers: (keyof typeof PROVIDER_NAMES)[], signInFailed = false): Response {
  const names = providers.map((p) => PROVIDER_NAMES[p]).join(" or ");
  const signIn = providers.map((p) => `<form method="post" action="/signin" style="display:inline-block;margin-right:8px"><input type="hidden" name="provider" value="${p}"><button>Sign in with ${PROVIDER_NAMES[p]}</button></form>`).join("");
  return page(
    "Test your IdP",
    `<h1><img src="/logo.svg" alt="" width="40" height="40" style="vertical-align:middle;margin-right:10px">Test your IdP</h1>
<p class="muted">For people building an ID-JAG issuer (draft-ietf-oauth-identity-assertion-authz-grant-06).</p>
<p>Register your IdP, send this receiver an ID-JAG, and see every rule it passed or failed, with the draft section for each, next to what a real receiver decided.</p>
<ol><li>Sign in with ${names} (accounts at least 30 days old).</li><li>Enter your issuer. You get a client id and secret here, for 24 hours.</li><li>Mint an ID-JAG for this receiver and redeem it at the token endpoint. The first one signed with your issuer's published key confirms that you run it.</li><li>Read the report.</li></ol>
${signInFailed ? '<p class="fail">The sign-in didn\'t complete. Try again.</p>' : ""}
${closed ? '<p class="fail">The tester is closed for now.</p>' : signedIn ? '<p><a href="/register">Register an IdP</a> &middot; <a href="/results">Your results</a></p><form method="post" action="/signout"><button>Sign out</button></form>' : signIn}
${FOOTER}`,
    { formAction: SIGN_IN_FORM_ACTION },
  );
}

export function registerForm(siteKey: string, error?: string): Response {
  return page(
    "Register your IdP",
    `<h1>Register your IdP</h1>
${error ? `<p class="fail">${esc(error)}</p>` : ""}
<form method="post" action="/register" class="box">
<p><label>Issuer identifier (exactly as your ID-JAGs' <code>iss</code>)<br><input type="url" name="issuer" required maxlength="512" placeholder="https://idp.example.com"></label></p>
<p class="muted">The tester reads your metadata (RFC 8414's location, else OpenID Connect Discovery's), checks it, and fetches your JWKS. https only, a public DNS name, no redirects.</p>
<details><summary class="muted">Advanced</summary>
<p><label>Only if you will also redeem from your own code: how that code authenticates its client here<br><select name="authMethod"><option value="client_secret_basic">client_secret_basic (HTTP Basic, the default)</option><option value="client_secret_post">client_secret_post (in the form body)</option></select></label></p>
</details>
<div class="cf-turnstile" data-sitekey="${esc(siteKey)}"></div>
<p><button>Register</button></p>
</form>
<p class="muted">One active IdP per account. Registering again later is fine.</p>
${FOOTER}`,
    { turnstile: true, status: error ? 400 : 200 },
  );
}

const ruleRows = (results: RuleResult[]) =>
  results.map((r) => `<tr><td class="${esc(r.outcome)}">${esc(r.outcome)}</td><td><code>${esc(r.id)}</code><br><span class="muted">${esc(r.level)}, ${esc(r.cite)}</span></td><td>${esc(r.message)}</td></tr>`).join("");

export function registered(o: { origin: string; registrationId: string; clientId: string; clientSecret: string; authMethod: string; issuer: string; expiresAt: number; report: RuleResult[] }): Response {
  const resource = `${o.origin}/mcp`;
  const auth = o.authMethod === "client_secret_post" ? `-d client_id=${o.clientId} -d client_secret=YOUR_SECRET` : `-u ${o.clientId}:YOUR_SECRET`;
  return page(
    "Registered",
    `<h1>Registered, pending</h1>
<p>Until ${esc(new Date(o.expiresAt).toISOString().replace("T", " ").slice(0, 16))} UTC. Your first ID-JAG signed with a key from your issuer's published JWKS confirms the registration (proof that you run the issuer). Until then, anyone else may register the same issuer too; the first to confirm holds it.</p>
<h2>1. Have your IdP mint an ID-JAG with these values</h2>
${idpValues(o.origin, o.issuer, o.clientId)}
<h2>2. Paste it here</h2>
${checkForm(o.registrationId)}
<p>Every check is kept on <a href="/results">your results page</a>, with each rule and the receiver's own decision.</p>
<details><summary>Redeem from your own code instead</summary>
<p><strong>Client secret, shown once:</strong> ${copyable(o.clientSecret)}</p>
<pre>curl ${esc(o.origin)}/api/auth/oauth2/token ${esc(auth)} \\
  -d grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer \\
  -d assertion=YOUR_ID_JAG</pre>
<p>Then, optionally, call the MCP server at <code>${esc(resource)}</code> with the access token (tools <code>whoami</code> and <code>checks</code>).</p>
</details>
<h2>Your metadata and keys</h2>
<div class="wrap"><table>${ruleRows(o.report)}</table></div>
${FOOTER}`,
  );
}

export interface ResultView {
  registrationId: string;
  /** Still active: the "Check an ID-JAG" box is shown. */
  active: boolean;
  issuer: string;
  clientId: string;
  expiresAt: number;
  pending: boolean;
  ended: string | null;
  metadata: RuleResult[];
  checks: { at: number; checkedAgainst: string; jti: string | null; httpStatus: number; error: string | null; results: RuleResult[]; receiver: { type: string; reason: string | null } | null }[];
}

export function results(views: ResultView[], name: string, origin: string): Response {
  const body = views.length
    ? views
        .map(
          (v) => `<div class="box"><h2 style="margin-top:0">${esc(v.issuer)}</h2>
<p class="muted">Client <code>${esc(v.clientId)}</code>. ${v.ended ? `Ended: ${esc(v.ended)}.` : `Until ${esc(new Date(v.expiresAt).toISOString().replace("T", " ").slice(0, 16))} UTC.`} ${v.pending ? '<span class="warn">Pending: confirmed by your first ID-JAG signed with your issuer\'s published key.</span>' : '<span class="pass">Confirmed.</span>'}</p>
<details><summary>Metadata and keys</summary><div class="wrap"><table>${ruleRows(v.metadata)}</table></div></details>
${v.active ? `<details><summary>Values for your IdP</summary>${idpValues(origin, v.issuer, v.clientId)}</details>${checkForm(v.registrationId)}${runForm(origin, v.registrationId, v.clientId)}` : ""}
${
  v.checks.length
    ? v.checks
        .map((c) => {
          const decision = c.error === "exchange_failed" ? '<span class="fail">not reached: your IdP issued no ID-JAG</span>' : c.receiver ? (c.receiver.type === "id-jag.accepted" ? '<span class="pass">accepted</span>' : `<span class="fail">refused: <code>${esc(c.receiver.reason)}</code></span>`) : c.httpStatus === 200 ? '<span class="pass">accepted</span>' : `<span class="fail">HTTP ${esc(c.httpStatus)} <code>${esc(c.error)}</code></span>`;
          const run = c.results.some((r) => r.id.startsWith("exchange.")) ? " &middot; whole flow" : "";
          const fails = c.results.filter((r) => r.outcome === "fail").length;
          return `<h3 style="font-size:1rem;margin:20px 0 4px">${esc(new Date(c.at).toISOString().replace("T", " ").slice(0, 19))} UTC${run} &middot; receiver: ${decision} &middot; ${fails ? `<span class="fail">${fails} rule(s) failed</span>` : '<span class="pass">every rule passed</span>'}</h3>
<p class="muted">jti <code>${esc(c.jti ?? "(none)")}</code> &middot; checked against ${esc(c.checkedAgainst)}</p>
<details${fails ? " open" : ""}><summary>Rules</summary><div class="wrap"><table>${ruleRows(c.results)}</table></div></details>`;
        })
        .join("")
    : '<p class="muted">No ID-JAGs redeemed yet.</p>'
}</div>`,
        )
        .join("")
    : '<p class="muted">No registrations. <a href="/register">Register an IdP</a>.</p>';
  const deleteForm = `<div class="box"><p><strong>Delete my data now.</strong> Ends your registrations and deletes them, their results, and your sign-in record at once. Only the anonymous abuse record remains, for up to 7 days.</p><form method="post" action="/delete"><button>Delete my data now</button></form></div>`;
  return page("Your results", `<h1>Your results</h1><p class="muted">Signed in as ${esc(name)}.</p><p><a href="/">Home</a> &middot; <a href="/register">Register</a></p>${body}${deleteForm}${FOOTER}`);
}

export function message(title: string, text: string, status: number): Response {
  return page(title, `<h1>${esc(title)}</h1><p>${esc(text)}</p><p><a href="/">Home</a></p>`, { status });
}
