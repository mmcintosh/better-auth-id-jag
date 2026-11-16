// The tester's help, from one source: the /help page, the same text as Markdown at /help.md (for a builder's AI
// assistant, or anyone who'd rather read it raw), and /llms.txt (llmstxt.org), which points an assistant at both and at
// the full guide. docs/test-your-idp.md is the long reference: every rule with its source, the limits, the privacy
// details. Each step on the tester's pages has an info link to its section here (pages.ts, helpLink).
import { esc, FOOTER, page } from "./pages";

const REPO = "https://github.com/mmcintosh/better-auth-id-jag";
const GUIDE = `${REPO}/blob/main/docs/test-your-idp.md`;
const GUIDE_RAW = "https://raw.githubusercontent.com/mmcintosh/better-auth-id-jag/main/docs/test-your-idp.md";
const DRAFT = "https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/06/";

/**
 * A block of a section. Text uses a small Markdown subset, the same in both outputs: `code`, **bold**, and
 * [text](url). `{origin}` is this deployment's origin.
 */
type Block = { p: string } | { ul: string[] } | { table: [string, string][]; head: [string, string] } | { pre: string };

export interface HelpSection {
  /** The anchor: /help#id. The pages' info links point at these. */
  id: string;
  title: string;
  blocks: Block[];
}

export const HELP: HelpSection[] = [
  {
    id: "what",
    title: "What the tester is",
    blocks: [
      { p: `A public receiver for people building an ID-JAG issuer: an IdP that implements [draft-ietf-oauth-identity-assertion-authz-grant-06](${DRAFT}). You register your IdP, it sends this receiver an ID-JAG, and you see every rule the ID-JAG passed or failed, each with its source, next to what a real receiver decided.` },
      { p: `It is a testing aid, not a conformance or certification test. Use test data only. [The full guide](${GUIDE}) lists every rule with its source, the limits, and what is kept.` },
    ],
  },
  {
    id: "sign-in",
    title: "Step 1. Sign in",
    blocks: [{ p: "Sign in with GitHub or GitLab (gitlab.com). The account must be at least 30 days old. This sign-in is only for this site: your IdP's users never sign in here. It lasts 24 hours." }],
  },
  {
    id: "register",
    title: "Step 2. Register your issuer",
    blocks: [
      { p: "Enter your issuer identifier exactly as your ID-JAGs' `iss`. The tester reads your metadata (RFC 8414's location, else OpenID Connect Discovery's), checks it, and fetches your JWKS: https only, a public DNS name, no redirects. Some failed rules stop the registration (the guide marks them *blocks*); the others are reported." },
      { p: "You get a client here, with a client id and a secret, for 24 hours. One registration is active at a time per account. Leave **Advanced** alone unless your own code will redeem ID-JAGs and sends its secret in the request body (`client_secret_post`)." },
    ],
  },
  {
    id: "confirm",
    title: "Pending and confirmed",
    blocks: [
      { p: "A new registration is **pending**. The first ID-JAG signed with a key from your issuer's published JWKS, with your issuer as `iss` and your client here as `client_id`, **confirms** it: proof that you run the issuer. Until then, others may register the same issuer too, and the first to confirm holds it while the registration lasts." },
      { p: "A run of the whole flow can confirm the registration. The refusal checks are sent only once it is confirmed." },
    ],
  },
  {
    id: "run",
    title: "Step 3. Run the whole flow (recommended)",
    blocks: [
      { p: "The tester plays the client, as an AI agent would: it sends you to your IdP to sign in, asks your IdP for an ID-JAG by token exchange, checks your IdP's answer, and redeems the ID-JAG here. Your IdP's ID token, access token and refresh token are never stored or shown. The run's form has four steps, below." },
    ],
  },
  {
    id: "run-client",
    title: "Run, step 1: a client at your IdP",
    blocks: [
      { p: 'At your IdP, create a client for the tester (an "application" in most admin consoles), or reuse one. It needs:' },
      {
        ul: [
          "the redirect URI `{origin}/flow/callback`;",
          "the authorization code grant, with scope `openid` and PKCE S256;",
          "the token exchange grant, `urn:ietf:params:oauth:grant-type:token-exchange`;",
          "permission to get ID-JAGs for audience `{origin}/api/auth` and resource `{origin}/mcp`, with your registration's client id here as the ID-JAG's `client_id`.",
        ],
      },
      { p: "The form shows each value with a copy button. The ID-JAG's `client_id` is the client id the tester gave you when you registered, not the id of the client at your IdP." },
    ],
  },
  {
    id: "run-details",
    title: "Run, step 2: that client's details",
    blocks: [
      { p: "Enter the client id and secret from step 1. The secret is kept encrypted for this run only, and deleted when your IdP sends you back; a run nobody comes back to expires after 10 minutes." },
      { p: 'Leave "How the client sends its secret" on **Automatic**: the tester uses what your IdP publishes in `token_endpoint_auth_methods_supported` (`client_secret_basic` when it is listed or nothing is, else `client_secret_post`), and the next page says which. Choose a method only if the client is set up differently. Leave the scope as `read`, the scope the tester grants.' },
    ],
  },
  {
    id: "run-checks",
    title: "Run, step 3: extra checks",
    blocks: [
      { p: "**Refusal checks (recommended).** After the run's ID-JAG is redeemed, the tester sends your IdP 7 token exchanges with one thing wrong each, and checks that each is refused with the right error. They are sent only for a confirmed registration, and they may appear in your IdP's security logs. The guide lists each one and the error it expects." },
      { p: "**A refresh token (optional).** Only if your IdP issues refresh tokens. The sign-in then also asks for `offline_access`, with a consent prompt at your IdP, and the report says whether your IdP gives an ID-JAG for a refresh token. The draft allows that, but doesn't require it." },
    ],
  },
  {
    id: "run-sign-in",
    title: "Run, step 4: sign in at your IdP",
    blocks: [
      { p: "Press **Run**, then **Continue**. Sign in at your IdP as one of your IdP's own users, not with your GitHub or GitLab account. If you're already signed in there, your IdP may only ask you to allow the tester's client. Your IdP sends you back here, and the report appears on your results page." },
      { p: "A sign-in that doesn't complete (an error from your IdP, no ID token, or one that doesn't verify) stops the run with a message and records nothing: that part is OpenID Connect, not ID-JAG. If your IdP refuses the token exchange, the report shows the refusal." },
    ],
  },
  {
    id: "mint",
    title: "Or mint an ID-JAG yourself and paste it",
    blocks: [
      { p: "Have your IdP mint an ID-JAG with the values the page shows, each with a copy button (or all at once, as JSON):" },
      {
        ul: [
          "`aud` is `{origin}/api/auth`, exactly;",
          "`client_id` is your client id here, not your IdP's own;",
          "`scope` is `read`;",
          "`resource`, if you send one, is `{origin}/mcp`;",
          "the header's `typ` is `oauth-id-jag+jwt`.",
        ],
      },
      { p: 'Paste it under **Check an ID-JAG** and press Check. The tester redeems it with your client here, through the same token endpoint anyone would use, and adds the report to your results page. Each ID-JAG works once (by its `jti`).' },
    ],
  },
  {
    id: "own-code",
    title: "Or redeem from your own code",
    blocks: [
      { p: "The page after you register shows the client secret, once, and how to redeem with it:" },
      { pre: "curl {origin}/api/auth/oauth2/token -u <client_id>:<client_secret> \\\n  -d grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer \\\n  -d assertion=<your ID-JAG>" },
      { p: "Then call the MCP server at `{origin}/mcp` with the access token: `whoami` shows what the receiver made of your ID-JAG, and `checks` your latest reports. If your code sends the secret in the request body, choose `client_secret_post` under **Advanced** when you register." },
    ],
  },
  {
    id: "report",
    title: "Reading the report",
    blocks: [
      { p: "A report lists every rule with its outcome, its level, and its source (a draft section or an RFC). The level is the source's own word (MUST, SHOULD, RECOMMENDED, OPTIONAL), or POLICY for this receiver's own choice." },
      {
        head: ["Outcome", "Meaning"],
        table: [
          ["pass", "The rule holds."],
          ["fail", "It doesn't."],
          ["warn", "Not a failure, but worth a look: a SHOULD not met, or something this receiver accepts that others may not."],
          ["info", "For your information, nothing to fix."],
          ["skip", "Not checked: something it needs was missing, or your IdP answered a refusal check with HTTP 429 or a server error."],
        ],
      },
      { p: "Next to the rules is the receiver's own decision: **accepted** (it issued an access token), or **refused** with its reason. **Not reached** means no ID-JAG got to the receiver: your IdP issued none, or the tester kept it back (its limits, an ID-JAG too large for it, or a problem with your registration's client here), and the report says which." },
    ],
  },
  {
    id: "problems",
    title: "Common problems",
    blocks: [
      {
        head: ["What you see", "What to check"],
        table: [
          ["The registration stops at `metadata.issuer`", "Your metadata's `issuer` must be exactly what you entered, including the path and any trailing slash."],
          ["`jwks.fetch` fails", "Your `jwks_uri` must be https, on a public DNS name, and answer without a redirect."],
          ["Your IdP says the redirect URI is invalid", "The client at your IdP needs `{origin}/flow/callback`, exactly."],
          ["Your IdP refuses the token exchange (`exchange.status`)", "The client at your IdP must be allowed the token exchange, and ID-JAGs for audience `{origin}/api/auth` and resource `{origin}/mcp`."],
          ["`claim.client_id` fails, or the receiver refuses with `client_mismatch`", "The ID-JAG's `client_id` must be your client id here, from your registration, not the id of your IdP's client."],
          ["`claim.aud` fails", "`aud` must be `{origin}/api/auth`, the receiver's issuer: not its token endpoint, and not `/mcp`."],
          ["`header.typ` fails", "The ID-JAG's header needs `typ` `oauth-id-jag+jwt`."],
          ["`signature` fails, or the registration stays pending", "Sign with a key in your published JWKS, and name it in the header (`kid`)."],
          ["`claim.scope` fails, or the receiver refuses with `no_scope`", "Ask for `read`, the scope the tester grants."],
          ["The receiver refuses with `replay`", "Each ID-JAG works once: mint a new one."],
          ["HTTP 429", "A limit was reached. The guide lists them."],
        ],
      },
    ],
  },
  {
    id: "data",
    title: "Your data",
    blocks: [
      { p: "A registration lasts 24 hours; then its client, users, results and logs are deleted. Results are visible only to the account that registered. Your email, your provider's tokens, and your IdP's ID, access and refresh tokens are never stored." },
      { p: `**Delete my data now**, on your results page, ends your registrations and deletes them at once; only an anonymous abuse record remains, for up to 7 days. [The guide's Privacy section](${GUIDE}#privacy) has the details.` },
    ],
  },
  {
    id: "assistants",
    title: "For AI assistants",
    blocks: [{ p: "This help is also plain Markdown at [{origin}/help.md]({origin}/help.md), and [{origin}/llms.txt]({origin}/llms.txt) lists what an assistant helping you build an issuer should read. Point yours there." }],
  },
];

const fill = (text: string, origin: string) => text.replaceAll("{origin}", origin);

/** Escaped text with the subset's markup made HTML: `code`, **bold**, *emphasis*, [text](url). */
const inline = (text: string) =>
  esc(text)
    .replace(/`([^`]+)`/g, "<code>$1</code>")
    .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
    .replace(/\*([^*]+)\*/g, "<em>$1</em>")
    .replace(/\[([^\]]+)\]\(((?:https:\/\/|\/)[^)\s]*)\)/g, '<a href="$2">$1</a>');

const blockHtml = (b: Block, origin: string): string => {
  if ("p" in b) return `<p>${inline(fill(b.p, origin))}</p>`;
  if ("ul" in b) return `<ul>${b.ul.map((i) => `<li>${inline(fill(i, origin))}</li>`).join("")}</ul>`;
  if ("pre" in b) return `<pre>${esc(fill(b.pre, origin))}</pre>`;
  const row = (cells: string[], tag: string) => `<tr>${cells.map((c) => `<${tag}>${inline(fill(c, origin))}</${tag}>`).join("")}</tr>`;
  return `<div class="wrap"><table>${row(b.head, "th")}${b.table.map((r) => row(r, "td")).join("")}</table></div>`;
};

const blockMd = (b: Block, origin: string): string => {
  if ("p" in b) return fill(b.p, origin);
  if ("ul" in b) return b.ul.map((i) => `- ${fill(i, origin)}`).join("\n");
  if ("pre" in b) return `\`\`\`sh\n${fill(b.pre, origin)}\n\`\`\``;
  const row = (cells: string[]) => `| ${cells.map((c) => fill(c, origin).replaceAll("|", "\\|")).join(" | ")} |`;
  return [row(b.head), `|${b.head.map(() => "---").join("|")}|`, ...b.table.map(row)].join("\n");
};

const CACHE = { "cache-control": "public, max-age=3600" };

export function helpPage(origin: string): Response {
  const toc = HELP.map((s) => `<li><a href="#${s.id}">${esc(s.title)}</a></li>`).join("");
  const sections = HELP.map((s) => `<h2 id="${s.id}">${esc(s.title)}</h2>${s.blocks.map((b) => blockHtml(b, origin)).join("")}`).join("");
  return page("Help: test your IdP", `<h1>Help</h1><p><a href="/">Home</a> &middot; <a href="/results">Your results</a> &middot; <a href="/help.md">This page as Markdown</a></p><ul>${toc}</ul>${sections}${FOOTER}`, { headers: CACHE });
}

export function helpMarkdown(origin: string): Response {
  const body = [`# Help: test your IdP (${origin})`, ...HELP.map((s) => [`## ${s.title}`, ...s.blocks.map((b) => blockMd(b, origin))].join("\n\n"))].join("\n\n");
  return new Response(`${body}\n`, { headers: { "content-type": "text/markdown; charset=utf-8", "x-content-type-options": "nosniff", ...CACHE } });
}

/** llmstxt.org: a title, a one-line summary, a few facts, then links. */
export function llmsTxt(origin: string): Response {
  const text = `# Test your IdP: an ID-JAG tester

> A public receiver for people building an ID-JAG issuer (draft-ietf-oauth-identity-assertion-authz-grant-06). Register an IdP, send this receiver an ID-JAG, and get a report of every rule it passed or failed, each with its source, next to the receiver's own decision.

This deployment's values: the ID-JAG's \`aud\` is \`${origin}/api/auth\`; its \`resource\`, if sent, is \`${origin}/mcp\`; its \`client_id\` is the client id the tester gives at registration (not the IdP's own); its \`scope\` is \`read\`; its header \`typ\` is \`oauth-id-jag+jwt\`. A run of the whole flow needs a client at the IdP with the redirect URI \`${origin}/flow/callback\`. ID-JAGs are redeemed at \`${origin}/api/auth/oauth2/token\` with the jwt-bearer grant. Registering and running need a person signed in with GitHub or GitLab in a browser.

## Docs

- [Help](${origin}/help.md): how to use the tester, step by step, how to read a report, and common problems
- [Full guide](${GUIDE_RAW}): every rule with its level and source, what isn't checked, the limits, and what is kept
- [The draft](${DRAFT}): draft-ietf-oauth-identity-assertion-authz-grant-06, which the rules come from

## Optional

- [The rules as code](${REPO}/blob/main/src/core/check.ts): the checker the tester runs
- [better-auth-id-jag](${REPO}): the package whose receiver the tester is
`;
  return new Response(text, { headers: { "content-type": "text/plain; charset=utf-8", "x-content-type-options": "nosniff", ...CACHE } });
}
