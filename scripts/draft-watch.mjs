// Fails when the IETF has a newer revision of the ID-JAG draft than the one this package implements
// (SUPPORTED_DRAFT in src/core/urns.ts), or when the implemented one is within 30 days of expiring.
// Run weekly by .github/workflows/draft-watch.yml; by hand: node scripts/draft-watch.mjs
import { readFileSync } from "node:fs";

const urns = readFileSync(new URL("../src/core/urns.ts", import.meta.url), "utf8");
const match = /SUPPORTED_DRAFT = "(draft-[a-z0-9-]+)-(\d{2})"/.exec(urns);
if (!match) throw new Error("SUPPORTED_DRAFT not found in src/core/urns.ts");
const [, name, ours] = match;

const res = await fetch(`https://datatracker.ietf.org/api/v1/doc/document/${name}/?format=json`, { headers: { accept: "application/json" } });
if (!res.ok) throw new Error(`datatracker: HTTP ${res.status}`);
const doc = await res.json();
const latest = String(doc.rev);
const expires = new Date(doc.expires);
const days = Math.floor((expires.getTime() - Date.now()) / 86_400_000);
console.log(`implemented: ${name}-${ours}; latest: ${name}-${latest}; expires ${expires.toISOString().slice(0, 10)} (${days} days)`);

let failed = false;
if (Number(latest) > Number(ours)) {
  console.log(`::error::A newer revision is out: ${name}-${latest} (https://datatracker.ietf.org/doc/${name}/${latest}/). Compare it with -${ours} and update SUPPORTED_DRAFT, the claims and URNs, the conformance table and docs/versioning.md.`);
  failed = true;
}
if (Number(latest) === Number(ours) && days < 30) {
  console.log(`::warning::${name}-${ours} expires in ${days} days; a new revision is likely soon.`);
}
process.exit(failed ? 1 : 0);
