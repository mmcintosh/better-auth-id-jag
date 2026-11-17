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

// The look comes from the logo (/logo.svg): its charcoal for the header band and the main buttons, its cyans for the
// accents (the info link is a small cyan dot, like the logo's check), and its bricks for the home page's steps. System
// fonts only: the policy loads nothing from other sites. Text colours meet WCAG AA contrast in both themes.
const STYLE = `
:root { --ink: #18181b; --cyan: #22d3ee; --cyan-2: #06b6d4; --cyan-3: #0891b2;
  --bg: #f6f7f8; --card: #ffffff; --fg: #18181b; --muted: #52525b; --line: #e4e4e7; --accent: #0e7490; --accent-soft: #ecfeff;
  --pass: #15803d; --pass-bg: #dcfce7; --fail: #b91c1c; --fail-bg: #fee2e2; --warn: #92400e; --warn-bg: #fef3c7; --info: #3f3f46; --info-bg: #f4f4f5;
  --code: #f4f4f5; --button: #18181b; --button-fg: #ffffff; }
@media (prefers-color-scheme: dark) { :root { --bg: #0f0f11; --card: #18181b; --fg: #f4f4f5; --muted: #a1a1aa; --line: #2e2e33; --accent: #22d3ee; --accent-soft: #0b2a31;
  --pass: #4ade80; --pass-bg: #0f2a19; --fail: #f87171; --fail-bg: #331414; --warn: #fbbf24; --warn-bg: #2e2208; --info: #d4d4d8; --info-bg: #27272a;
  --code: #27272a; --button: #22d3ee; --button-fg: #18181b; } }
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--fg); font: 16px/1.6 ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif; }
a { color: var(--accent); text-underline-offset: 3px; }
header.top { background: var(--ink); border-bottom: 3px solid var(--cyan); }
header.top .in { max-width: 920px; margin: 0 auto; padding: 12px 16px; display: flex; align-items: center; gap: 14px; flex-wrap: wrap; }
header.top .brand { display: flex; align-items: center; gap: 10px; color: #f4f4f5; text-decoration: none; font-weight: 650; }
header.top .brand small { color: #a1a1aa; font-weight: 400; }
header.top nav { margin-left: auto; display: flex; gap: 18px; font-size: 0.95rem; }
header.top nav a { color: #d4d4d8; text-decoration: none; }
header.top nav a:hover { color: var(--cyan); }
main { max-width: 920px; margin: 0 auto; padding: 28px 16px 64px; }
h1 { font-size: clamp(1.6rem, 4vw, 2.2rem); line-height: 1.2; margin: 0 0 8px; letter-spacing: -0.02em; }
h2 { font-size: 1.2rem; margin: 32px 0 8px; } h3 { font-size: 1.05rem; }
p, li { color: var(--fg); } .muted { color: var(--muted); }
code, pre { background: var(--code); border-radius: 6px; font: 0.88em ui-monospace, "SF Mono", Menlo, monospace; }
code { padding: 1px 6px; overflow-wrap: anywhere; } pre { padding: 12px; overflow-x: auto; }
table { border-collapse: collapse; width: 100%; font-size: 0.93rem; } td, th { border-top: 1px solid var(--line); padding: 8px; text-align: left; vertical-align: top; }
.pass { color: var(--pass); } .fail { color: var(--fail); } .warn { color: var(--warn); } .info, .skip { color: var(--muted); }
td.pass, td.fail, td.warn, td.info, td.skip { width: 1%; white-space: nowrap; }
.badge { display: inline-block; min-width: 52px; text-align: center; font-size: 0.78rem; font-weight: 700; letter-spacing: 0.02em; border-radius: 999px; padding: 2px 10px; }
.pass .badge { color: var(--pass); background: var(--pass-bg); } .fail .badge { color: var(--fail); background: var(--fail-bg); }
.warn .badge { color: var(--warn); background: var(--warn-bg); } .info .badge, .skip .badge { color: var(--info); background: var(--info-bg); }
input[type=url], input[type=text], input[type=password], select, textarea { width: 100%; padding: 9px 10px; font: inherit; border: 1px solid var(--line); border-radius: 8px; background: var(--card); color: var(--fg); }
textarea { font: 0.88em ui-monospace, monospace; }
input:focus, select:focus, textarea:focus { outline: 2px solid var(--cyan-2); outline-offset: 1px; border-color: var(--cyan-2); }
button { padding: 9px 18px; font: inherit; font-weight: 600; border-radius: 10px; border: 1px solid var(--button); background: var(--button); color: var(--button-fg); cursor: pointer; }
button:hover { box-shadow: 0 0 0 3px color-mix(in srgb, var(--cyan) 45%, transparent); }
button.quiet, button.small { background: transparent; color: var(--fg); border-color: var(--line); }
button.small { padding: 2px 10px; font-size: 0.8rem; font-weight: 500; border-radius: 8px; }
a:focus-visible, button:focus-visible, summary:focus-visible { outline: 3px solid var(--cyan); outline-offset: 2px; }
.box { background: var(--card); border: 1px solid var(--line); border-radius: 14px; padding: 18px 20px; margin: 16px 0; }
details > summary { cursor: pointer; }
.wrap { overflow-x: auto; }
.copy { display: inline-flex; gap: 6px; align-items: center; flex-wrap: wrap; }
a.help { display: inline-grid; place-items: center; width: 18px; height: 18px; margin-left: 6px; border-radius: 50%; background: var(--accent-soft); color: var(--accent);
  border: 1px solid color-mix(in srgb, var(--accent) 40%, transparent); font: 700 11px/1 ui-sans-serif, system-ui, sans-serif; text-decoration: none; vertical-align: 2px; }
a.help:hover { background: var(--cyan); color: var(--ink); }
.hero { display: grid; grid-template-columns: 1fr auto; gap: 24px; align-items: center; margin-bottom: 24px; }
.hero .art { filter: drop-shadow(0 10px 24px rgba(8, 145, 178, 0.25)); }
.hero p { color: var(--muted); max-width: 60ch; }
.tag { display: inline-block; font-size: 0.8rem; color: var(--accent); background: var(--accent-soft); border-radius: 999px; padding: 2px 10px; margin-bottom: 12px; }
.steps { list-style: none; padding: 0; margin: 0 0 24px; display: grid; grid-template-columns: repeat(2, 1fr); gap: 10px; }
.steps li { background: var(--card); border: 1px solid var(--line); border-left: 6px solid var(--cyan-3); border-radius: 10px; padding: 14px 16px; }
.steps li:nth-child(even) { border-left-color: var(--cyan); }
.steps b { display: block; margin-bottom: 2px; } .steps span { color: var(--muted); font-size: 0.95rem; }
.tiles { display: flex; gap: 10px; flex-wrap: wrap; margin: 8px 0 12px; }
.tile { flex: 1 1 140px; border: 1px solid var(--line); border-radius: 10px; padding: 8px 14px; background: var(--card); }
.tile b { display: block; font-size: 1.25rem; } .tile span { color: var(--muted); font-size: 0.85rem; }
footer.site { margin-top: 48px; padding-top: 16px; border-top: 1px solid var(--line); font-size: 0.9rem; }
@media (max-width: 640px) { .hero { grid-template-columns: 1fr; } .hero .art { display: none; } .steps { grid-template-columns: 1fr; } header.top nav { margin-left: 0; } }
`;

export function page(title: string, body: string, { turnstile = false, status = 200, headers = {} as Record<string, string>, formAction = "'self'" } = {}): Response {
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${esc(title)}</title><link rel="icon" href="/logo.svg" type="image/svg+xml"><style>${STYLE}</style><script src="${APP_JS_URL}" defer></script>${turnstile ? '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>' : ""}</head><body>${HEADER}<main>${body}</main></body></html>`;
  // Referrer-Policy same-origin, not no-referrer: under no-referrer a browser sends "Origin: null" on a form post (the
  // Fetch standard), and every form here is checked for this site's own origin. Other sites still get no referrer.
  return new Response(html, { status, headers: { "content-type": "text/html; charset=utf-8", "content-security-policy": csp(formAction), "x-content-type-options": "nosniff", "referrer-policy": "same-origin", "cache-control": "no-store", ...headers } });
}

/** An info link to a section of /help (help.ts, HELP; a test checks every one points at a section there). */
export const helpLink = (id: string, about: string) => `<a class="help" href="/help#${id}" title="Help: ${esc(about)}" aria-label="Help: ${esc(about)}">i</a>`;

/** The band at the top of every page, in the logo's charcoal. */
const HEADER = `<header class="top"><div class="in"><a class="brand" href="/"><img src="/logo.svg" alt="" width="34" height="34">ID-JAG tester <small>by Infowall</small></a><nav><a href="/">Home</a><a href="/results">Your results</a><a href="/help">Help</a></nav></div></header>`;

export const FOOTER = `<footer class="site"><p class="muted"><a href="/help">Help</a>${helpLink("what", "what the tester is")} &middot; <a href="/llms.txt">For AI assistants</a>${helpLink("assistants", "for AI assistants")}</p><p class="muted">Checked against ${esc(SUPPORTED_DRAFT)} as <a href="https://github.com/mmcintosh/better-auth-id-jag">better-auth-id-jag</a> reads it: <a href="https://github.com/mmcintosh/better-auth-id-jag/blob/main/docs/test-your-idp.md#the-rules">the rules</a>, each with its source, and <a href="https://github.com/mmcintosh/better-auth-id-jag/blob/main/src/core/check.ts">their code</a>. A testing aid, not a conformance or certification test. Test data only. A registration lasts 24 hours; then its client, users, results and logs are deleted. Results are visible only to the account that registered. No uptime promise: the tester may close at any time.</p></footer>`;


/** A value with a copy button (the script at /app.js). */
const copyable = (value: string) => `<span class="copy"><code>${esc(value)}</code><button type="button" class="small" data-copy="${esc(value)}">Copy</button></span>`;

/** Paste an ID-JAG and the tester redeems it with this registration's own client: no curl, no secret to handle. */
const checkForm = (registrationId: string) => `<form method="post" action="/check" class="box">
<input type="hidden" name="registration" value="${esc(registrationId)}">
<p><label><strong>Check an ID-JAG.</strong> Paste one your IdP minted for this registration (with the values above), then press Check: the tester redeems it with your client here and adds the report below.<br><textarea name="assertion" rows="4" required maxlength="16384" placeholder="eyJ..."></textarea></label></p>
<p><button>Check</button></p>
</form>`;

/**
 * "Run the whole flow": the tester plays the client. Laid out as steps, each field saying where its value comes from:
 * the tester's IdP needs a client for it first. The client's secret is kept only for the run (sealed; the run expires
 * after 10 minutes and is deleted within 5 more).
 */
const runForm = (origin: string, registrationId: string, clientId: string) => `<form method="post" action="/flow/start" id="run">
<input type="hidden" name="registration" value="${esc(registrationId)}">
<p>The tester plays the client, as an AI agent would: it sends you to your IdP to sign in, asks your IdP for an ID-JAG, checks your IdP's answer, and redeems the ID-JAG here. Your IdP's ID token, access token and refresh token are never stored or shown. <a href="/help#run">Step-by-step help</a>.</p>
<p><strong>Step 1. At your IdP, create a client for the tester</strong>${helpLink("run-client", "a client at your IdP")} (an "application" in most admin consoles), with:</p>
<table><tr><td>Redirect URI</td><td>${copyable(`${origin}/flow/callback`)}</td></tr>
<tr><td>Grant types</td><td>authorization code (scope <code>openid</code>, PKCE S256) and token exchange (<code>urn:ietf:params:oauth:grant-type:token-exchange</code>)</td></tr>
<tr><td>Allowed to get</td><td>ID-JAGs for audience ${copyable(`${origin}/api/auth`)}<br>and resource ${copyable(`${origin}/mcp`)}<br>with <code>client_id</code> ${copyable(clientId)} in the ID-JAG <span class="muted">(your client here, from this registration)</span></td></tr></table>
<p><strong>Step 2. Enter that client's details</strong>${helpLink("run-details", "that client's details")}</p>
<p><label>Client id <span class="muted">(from step 1, at your IdP)</span><br><input type="text" name="client_id" required maxlength="256" autocomplete="off"></label></p>
<p><label>Client secret <span class="muted">(from step 1; kept encrypted for this run only, then deleted)</span><br><input type="password" name="client_secret" required maxlength="512" autocomplete="off"></label></p>
<p><label>How the client sends its secret<br><select name="auth_method"><option value="auto">Automatic: as your IdP's published settings say</option><option value="client_secret_basic">client_secret_basic (HTTP Basic)</option><option value="client_secret_post">client_secret_post (in the form body)</option></select></label><br><span class="muted">Leave on Automatic unless the client is set up differently from what your IdP publishes (<code>token_endpoint_auth_methods_supported</code>).</span></p>
<p><label>Scope to ask for<br><input type="text" name="scope" value="read" maxlength="256"></label><br><span class="muted"><code>read</code> is the scope the tester grants; change it only to see how your IdP handles another.</span></p>
<p><strong>Step 3. Extra checks</strong> <span class="muted">(each adds lines to the report)</span>${helpLink("run-checks", "extra checks")}</p>
<p><label><input type="checkbox" name="probes" value="1"> <strong>Recommended: check that your IdP refuses wrong requests.</strong> After the run's ID-JAG is redeemed, the tester sends 7 token exchanges with one thing wrong each (no client authentication, two audiences, an untrusted audience, a foreign resource, the wrong kind of subject token) and checks each is refused with the right error. Sent only once the registration is confirmed, which this run does. They may appear in your IdP's security logs.</label></p>
<p><label><input type="checkbox" name="refresh" value="1"> <strong>Optional: try a refresh token.</strong> Only if your IdP issues refresh tokens. The sign-in then also asks for <code>offline_access</code>, with a consent prompt at your IdP, and the report says whether your IdP gives an ID-JAG for a refresh token (the draft allows it, but doesn't require it).</label></p>
<p><strong>Step 4. Press Run, then Continue.</strong>${helpLink("run-sign-in", "signing in at your IdP")} You sign in <strong>at your IdP</strong>, with one of your IdP's own users, not your GitHub or GitLab account (that sign-in was only for this site). If you're already signed in there, your IdP may only ask you to allow the tester's client. Then you come back here, and the report appears on your results page.</p>
<p><button>Run</button></p>
</form>`;

/** "Run the whole flow", between the form and the IdP: the pages' policy lets forms post only to this site. */
export function continueToIdp(to: string, host: string, minutes: number, authNote: string): Response {
  return page("Sign in at your IdP", `<h1>Sign in at your IdP${helpLink("run-sign-in", "signing in at your IdP")}</h1><p>The tester has started the run. Continue to your IdP's sign-in at <code>${esc(host)}</code>; it sends you back here, and the tester does the rest.</p><p>There you sign in with one of <strong>your IdP's own users</strong>, not your GitHub or GitLab account (that sign-in was only for this site). If you're already signed in there, your IdP may only ask you to allow the tester's client; if you ticked "try a refresh token", it also asks for <code>offline_access</code>, which is that refresh token.</p><p><a href="${esc(to)}"><strong>Continue to ${esc(host)}</strong></a></p><p class="muted">${esc(authNote)} The run waits ${minutes} minutes.</p>${FOOTER}`);
}

/** A run's ID-JAG that the tester's own token endpoint kept from the receiver, and why (index.ts, notRedeemed). */
const NOT_REACHED: Record<string, string> = {
  not_redeemed: "the tester's limits kept the ID-JAG back",
  too_large: "the ID-JAG is too large for the tester's token endpoint",
  client_refused: "the tester's own client for this registration couldn't redeem it; register again",
};

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

/** "Mint an ID-JAG yourself and paste it", folded: the run is the recommended way. */
const mintBox = (origin: string, registrationId: string, issuer: string, clientId: string) =>
  `<details class="box"><summary><strong>Or mint an ID-JAG yourself and paste it</strong>${helpLink("mint", "minting an ID-JAG yourself")}</summary><p>Have your IdP mint one with these values, then paste it below.</p>${idpValues(origin, issuer, clientId)}${checkForm(registrationId)}</details>`;

const PROVIDER_NAMES = { github: "GitHub", gitlab: "GitLab" } as const;

export function landing(signedIn: boolean, closed: boolean, providers: (keyof typeof PROVIDER_NAMES)[], signInFailed = false): Response {
  const names = providers.map((p) => PROVIDER_NAMES[p]).join(" or ");
  const signIn = providers.map((p, i) => `<form method="post" action="/signin" style="display:inline-block;margin:0 8px 8px 0"><input type="hidden" name="provider" value="${p}"><button${i ? ' class="quiet"' : ""}>Sign in with ${PROVIDER_NAMES[p]}</button></form>`).join("");
  return page(
    "Test your IdP",
    `<section class="hero"><div>
<span class="tag">${esc(SUPPORTED_DRAFT)}</span>
<h1>Test your IdP's ID-JAGs</h1>
<p>For people building an ID-JAG issuer.${helpLink("what", "what the tester is")} Register your IdP, send this receiver an ID-JAG, and see every rule it passed or failed, with the draft section for each, next to what a real receiver decided.</p>
</div><img class="art" src="/logo.svg" alt="" width="132" height="132"></section>
<ol class="steps"><li><b>1. Sign in${helpLink("sign-in", "signing in")}</b><span>With ${names}, accounts at least 30 days old.</span></li><li><b>2. Register your issuer${helpLink("register", "registering your issuer")}</b><span>You get a client id and secret here, for 24 hours.</span></li><li><b>3. Send an ID-JAG${helpLink("run", "running the whole flow")}</b><span>Let the tester run the whole flow with a client at your IdP, or mint one and paste it. The first one signed with your issuer's published key confirms that you run it.</span></li><li><b>4. Read the report${helpLink("report", "reading a report")}</b><span>Every rule, with its source, next to the receiver's own decision.</span></li></ol>
<div class="box"><h2 style="margin-top:0">Start</h2>
${signInFailed ? '<p class="fail">The sign-in didn\'t complete. Try again.</p>' : ""}
${closed ? '<p class="fail">The tester is closed for now.</p>' : signedIn ? '<p><a href="/register">Register an IdP</a> &middot; <a href="/results">Your results</a></p><form method="post" action="/signout"><button class="quiet">Sign out</button></form>' : `<p class="muted">This sign-in is only for this site: your IdP's users never sign in here.</p>${signIn}`}
<p style="margin-bottom:0"><a href="/help">Help: every step in detail</a></p></div>
${FOOTER}`,
    { formAction: SIGN_IN_FORM_ACTION },
  );
}

export function registerForm(siteKey: string, error?: string): Response {
  return page(
    "Register your IdP",
    `<h1>Register your IdP</h1>
<p class="muted">Registered before and it's not on <a href="/results">your results page</a>? A registration ends after 24 hours, with its results; register again.</p>
${error ? `<p class="fail">${esc(error)}</p>` : ""}
<form method="post" action="/register" class="box">
<p><label>Issuer identifier (exactly as your ID-JAGs' <code>iss</code>)${helpLink("register", "registering your issuer")}<br><input type="url" name="issuer" required maxlength="512" placeholder="https://idp.example.com"></label></p>
<p class="muted">The tester reads your metadata (RFC 8414's location, else OpenID Connect Discovery's), checks it, and fetches your JWKS. https only, a public DNS name, no redirects.</p>
<details><summary class="muted">Advanced${helpLink("own-code", "redeeming from your own code")}</summary>
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

/** The registration's metadata and keys, open (folded, they were missed), with a one-line summary. */
const metadataSection = (rules: RuleResult[]) => {
  const fails = rules.filter((r) => r.outcome === "fail").length;
  return `<details open><summary>Your metadata and keys: ${fails ? `<span class="fail">${fails} rule(s) failed</span>` : '<span class="pass">every rule passed</span>'}${helpLink("register", "your metadata and keys")}</summary><div class="wrap"><table>${ruleRows(rules)}</table></div></details>`;
};

const ruleRows = (results: RuleResult[]) =>
  results.map((r) => `<tr><td class="${esc(r.outcome)}"><span class="badge">${esc(r.outcome)}</span></td><td><code>${esc(r.id)}</code><br><span class="muted">${esc(r.level)}, ${esc(r.cite)}</span></td><td>${esc(r.message)}</td></tr>`).join("");

/** A report's summary: the receiver's decision, the rules passed, and the refusal checks when the run sent them. */
const reportTiles = (decision: string, results: RuleResult[]) => {
  const scored = results.filter((r) => r.outcome === "pass" || r.outcome === "fail" || r.outcome === "warn");
  const probes = results.filter((r) => r.id.startsWith("probe."));
  const tile = (value: string, label: string) => `<div class="tile"><b>${value}</b><span>${label}</span></div>`;
  return `<div class="tiles">${tile(decision, "receiver's decision")}${tile(`${scored.filter((r) => r.outcome === "pass").length} / ${scored.length}`, "rules passed")}${probes.length ? tile(`${probes.filter((r) => r.outcome === "pass").length} / ${probes.length}`, "refusal checks") : ""}</div>`;
};

export function registered(o: { origin: string; registrationId: string; clientId: string; clientSecret: string; authMethod: string; issuer: string; expiresAt: number; report: RuleResult[] }): Response {
  const resource = `${o.origin}/mcp`;
  const auth = o.authMethod === "client_secret_post" ? `-d client_id=${o.clientId} -d client_secret=YOUR_SECRET` : `-u ${o.clientId}:YOUR_SECRET`;
  return page(
    "Registered",
    `<h1>Registered, pending${helpLink("confirm", "pending and confirmed")}</h1>
<p>Until ${esc(new Date(o.expiresAt).toISOString().replace("T", " ").slice(0, 16))} UTC. Your first ID-JAG signed with a key from your issuer's published JWKS confirms the registration (proof that you run the issuer). Until then, anyone else may register the same issuer too; the first to confirm holds it.</p>
<h2>Next: test your IdP</h2>
<div class="box"><h3 style="margin-top:0">Run the whole flow (recommended)</h3>${runForm(o.origin, o.registrationId, o.clientId)}</div>
${mintBox(o.origin, o.registrationId, o.issuer, o.clientId)}
<p>Every report is kept on <a href="/results">your results page</a>, with each rule and the receiver's own decision.</p>
<details><summary>Redeem from your own code instead${helpLink("own-code", "redeeming from your own code")}</summary>
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
${metadataSection(v.metadata)}
${v.active && !v.checks.length ? `<div class="box"><h3 style="margin-top:0">Run the whole flow (recommended)</h3>${runForm(origin, v.registrationId, v.clientId)}</div>${mintBox(origin, v.registrationId, v.issuer, v.clientId)}` : ""}
${v.checks.length ? `<h3>Reports${helpLink("report", "reading a report")}</h3>` : ""}
${
  v.checks.length
    ? v.checks
        .map((c, i) => {
          const decision = c.error === "exchange_failed" ? '<span class="fail">not reached: your IdP issued no ID-JAG</span>' : NOT_REACHED[c.error ?? ""] ? `<span class="warn">not reached: ${esc(NOT_REACHED[c.error ?? ""])}</span>` : c.receiver ? (c.receiver.type === "id-jag.accepted" ? '<span class="pass">accepted</span>' : `<span class="fail">refused: <code>${esc(c.receiver.reason)}</code></span>`) : c.httpStatus === 200 ? '<span class="pass">accepted</span>' : `<span class="fail">HTTP ${esc(c.httpStatus)} <code>${esc(c.error)}</code></span>`;
          const run = c.results.some((r) => r.id.startsWith("exchange.")) ? " &middot; whole flow" : "";
          const fails = c.results.filter((r) => r.outcome === "fail").length;
          return `<h3 style="font-size:1rem;margin:20px 0 4px">${esc(new Date(c.at).toISOString().replace("T", " ").slice(0, 19))} UTC${run} &middot; receiver: ${decision} &middot; ${fails ? `<span class="fail">${fails} rule(s) failed</span>` : '<span class="pass">every rule passed</span>'}</h3>
<p class="muted">jti <code>${esc(c.jti ?? "(none)")}</code> &middot; checked against ${esc(c.checkedAgainst)}</p>${reportTiles(decision, c.results)}
<details${fails || i === 0 ? " open" : ""}><summary>Rules</summary><div class="wrap"><table>${ruleRows(c.results)}</table></div></details>`;
        })
        .join("")
    : '<p class="muted">No ID-JAGs redeemed yet.</p>'
}
${v.active && v.checks.length ? `<details class="box"><summary><strong>Test again: run the whole flow</strong>${helpLink("run", "running the whole flow")}</summary>${runForm(origin, v.registrationId, v.clientId)}</details>${mintBox(origin, v.registrationId, v.issuer, v.clientId)}` : ""}</div>`,
        )
        .join("")
    : '<p class="muted">No registrations. <a href="/register">Register an IdP</a>.</p>';
  const deleteForm = `<div class="box"><p><strong>Delete my data now.</strong>${helpLink("data", "your data")} Ends your registrations and deletes them, their results, and your sign-in record at once. Only the anonymous abuse record remains, for up to 7 days.</p><form method="post" action="/delete"><button>Delete my data now</button></form></div>`;
  return page("Your results", `<h1>Your results</h1><p class="muted">Signed in as ${esc(name)}.</p><p><a href="/">Home</a> &middot; <a href="/register">Register</a></p>${body}${deleteForm}${FOOTER}`);
}

export function message(title: string, text: string, status: number): Response {
  return page(title, `<h1>${esc(title)}</h1><p>${esc(text)}</p><p><a href="/">Home</a></p>`, { status });
}
