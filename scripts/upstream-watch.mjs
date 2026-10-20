// Fails when an upstream Better Auth change this package depends on lands, so it is noticed without anyone watching
// (#20): better-auth/better-auth#9935 (the jwt default EdDSA → RS256, ID-token authentication context; #19) merged or
// closed; #8023 (RFC 8693 token exchange as an official plugin) or #11267 (authentication context in access tokens)
// closed, or a pull request linked to either merged; or a 1.8 version of better-auth or @better-auth/oauth-provider on
// npm (the peer range stops at <1.8.0). Public GitHub and npm APIs only; GITHUB_TOKEN, when set, only raises the rate
// limit. Run weekly by .github/workflows/draft-watch.yml; by hand: node scripts/upstream-watch.mjs
// Once a finding has been looked at, add its key (printed with it) to ACKNOWLEDGED so the watch goes quiet.

const REPO = "better-auth/better-auth";
const PR = 9935;
const ISSUES = [8023, 11267];
const PACKAGES = ["better-auth", "@better-auth/oauth-provider"];
const ACKNOWLEDGED = [
  // D-046: idJagIssuer({ otherTokenExchange: tokenExchangeFrom(oauthTokenExchange()) }) is how both coexist.
  "issue:8023:pr:11742",
  "issue:8023:pr:11763",
];

const what = {
  9935: "run the full suite against it, check the issuer's signing (#19, D-038) and ID-token acr/amr (D-033), then widen the peer range",
  8023: "move the issuer's token exchange onto the official plugin, or document how both coexist",
  11267: "carry auth_time/acr/amr into the receiver's access token, update docs/security.md and the #26 test",
  npm: "run the full suite against it (scripts/use-better-auth.sh), fix what breaks, then widen the peer range (a 0.x minor)",
};

const headers = { accept: "application/vnd.github+json", "user-agent": "better-auth-id-jag-upstream-watch", ...(process.env.GITHUB_TOKEN ? { authorization: `Bearer ${process.env.GITHUB_TOKEN}` } : {}) };
async function json(url, h = headers) {
  const res = await fetch(url, { headers: h });
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  return res.json();
}

const findings = new Map();
const found = (key, message) => {
  if (!ACKNOWLEDGED.includes(key)) findings.set(key, message);
};

const pr = await json(`https://api.github.com/repos/${REPO}/pulls/${PR}`);
console.log(`${REPO}#${PR}: ${pr.state}${pr.merged_at ? ", merged" : ""}`);
const next = (n) => what[n] ?? "check what it changes here";
if (pr.merged_at) found(`pr:${PR}:merged`, `${REPO}#${PR} was merged (${pr.merged_at.slice(0, 10)}): ${next(PR)}`);
else if (pr.state === "closed") found(`pr:${PR}:closed`, `${REPO}#${PR} was closed without merging: check what replaced it, then ${next(PR)}`);

for (const n of ISSUES) {
  const issue = await json(`https://api.github.com/repos/${REPO}/issues/${n}`);
  // Pull requests that mention the issue (cross-referenced). One linked only through GitHub's "Development" sidebar
  // leaves no number in the timeline; it shows when the issue closes.
  const merged = new Set();
  for (let page = 1; page <= 10; page++) {
    const events = await json(`https://api.github.com/repos/${REPO}/issues/${n}/timeline?per_page=100&page=${page}`);
    for (const e of events) {
      const source = e.event === "cross-referenced" ? e.source?.issue : undefined;
      if (source?.pull_request?.merged_at && source.repository?.full_name === REPO) merged.add(source.number);
    }
    if (events.length < 100) break;
  }
  console.log(`${REPO}#${n}: ${issue.state}; merged pull requests linked: ${merged.size ? [...merged].map((m) => `#${m}`).join(", ") : "none"}`);
  if (issue.state === "closed") found(`issue:${n}:closed`, `${REPO}#${n} was closed (${issue.state_reason ?? "no reason"}): ${next(n)}`);
  for (const m of merged) found(`issue:${n}:pr:${m}`, `${REPO}#${m}, linked to #${n}, was merged: ${next(n)}`);
}

// A version at or above 1.8.0, pre-releases included (1.8.0-beta.1 counts).
const atLeast18 = (v) => {
  const [major, minor] = v.split(/[.-]/).map(Number);
  return major > 1 || (major === 1 && minor >= 8);
};
for (const name of PACKAGES) {
  // The abbreviated document: versions and dist-tags, without every version's full manifest.
  const doc = await json(`https://registry.npmjs.org/${name.replaceAll("/", "%2F")}`, { accept: "application/vnd.npm.install-v1+json" });
  const newer = Object.keys(doc.versions ?? {}).filter(atLeast18);
  console.log(`npm ${name}: latest ${doc["dist-tags"]?.latest}; versions >= 1.8.0-0: ${newer.length ? newer.join(", ") : "none"}`);
  // One finding per minor line, pre-releases apart from releases: 1.8 betas once, then 1.8.0 itself again.
  const lines = new Map();
  for (const v of newer) {
    const [major, minor] = v.split(/[.-]/);
    const line = `${major}.${minor}${v.includes("-") ? "-pre" : ""}`;
    lines.set(line, [...(lines.get(line) ?? []), v]);
  }
  for (const [line, versions] of lines) found(`npm:${name}@${line}`, `npm ${name} ${line.endsWith("-pre") ? "pre-releases" : "releases"} of ${line.replace("-pre", "")}: ${versions.slice(-5).join(", ")}: ${what.npm}`);
}

for (const [key, message] of findings) console.log(`::error::${message}. When done, acknowledge "${key}" in scripts/upstream-watch.mjs.`);
process.exit(findings.size > 0 ? 1 : 0);
