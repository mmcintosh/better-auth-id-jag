// Fails when Microsoft Entra's release notes mention ID-JAG, so Entra becoming an ID-JAG issuer (a second
// production IdP to test against, after Okta) is noticed without anyone watching. The notes are the public
// MicrosoftDocs/entra-docs source of https://learn.microsoft.com/en-us/entra/fundamentals/whats-new.
// Run weekly by .github/workflows/draft-watch.yml; by hand: node scripts/entra-watch.mjs
// Once a match has been looked at, add its line to ACKNOWLEDGED so the watch goes quiet until the next one.

const SOURCE = "https://raw.githubusercontent.com/MicrosoftDocs/entra-docs/main/docs/fundamentals/whats-new.md";
// Exact names only: "identity assertions" alone also matches unrelated federation items.
const TERMS = [/\bID-JAG\b/i, /oauth-id-jag/i, /identity assertion (JWT )?authorization grant/i, /cross[- ]app access/i, /enterprise[- ]managed authori[sz]ation/i];
const ACKNOWLEDGED = [];

const res = await fetch(SOURCE);
if (!res.ok) throw new Error(`entra-docs: HTTP ${res.status}`);
const lines = (await res.text()).split("\n");
const hits = lines.flatMap((line, i) => (TERMS.some((t) => t.test(line)) && !ACKNOWLEDGED.some((a) => line.includes(a)) ? [{ n: i + 1, line: line.trim() }] : []));
console.log(`Entra release notes: ${lines.length} lines, ${hits.length} new ID-JAG mention(s)`);
for (const h of hits) {
  console.log(`::error::Entra's release notes mention ID-JAG (whats-new.md line ${h.n}): ${h.line.slice(0, 300)}. Check whether Entra issues ID-JAGs, test it against our receiver, add it to docs/interop.md, then acknowledge it in scripts/entra-watch.mjs.`);
}
process.exit(hits.length > 0 ? 1 : 0);
