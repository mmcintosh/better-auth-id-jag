// Prepares a release: bumps package.json, dates CHANGELOG.md's [Unreleased] section, and opens the
// "Release X.Y.Z" pull request. Merging it releases (tag-release.yml tags it and starts release.yml).
// The first release also drops "private": true and the README's pre-release lines.
//
//   pnpm release patch|minor|major ["One sentence for the top of the version's section."]
//
// Run on an up-to-date, clean main, with `gh` signed in, in a terminal: it lists the open pull requests and other
// branches on GitHub first, and goes on only when you confirm each is deferred on purpose.
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { createInterface } from "node:readline/promises";

const run = (cmd, args, o = {}) => String(execFileSync(cmd, args, { encoding: "utf8", stdio: ["ignore", "pipe", "inherit"], ...o }) ?? "").trim();
const fail = (msg) => {
  console.error(`release: ${msg}`);
  process.exit(1);
};

const [bump, summary] = process.argv.slice(2);
if (!["patch", "minor", "major"].includes(bump)) fail('usage: pnpm release patch|minor|major ["summary"]');

if (run("git", ["branch", "--show-current"]) !== "main") fail("run it on main");
if (run("git", ["status", "--porcelain"])) fail("the working tree isn't clean");
run("git", ["fetch", "--quiet", "origin", "main"]);
if (run("git", ["rev-parse", "HEAD"]) !== run("git", ["rev-parse", "origin/main"])) fail("main isn't up to date with origin/main (git pull)");

// Open work: every open pull request (drafts too) and every other branch on GitHub is listed, and the release goes on
// only once it's confirmed that each one is deferred on purpose. Finished README work waiting in a draft once shipped
// in neither of two releases, because only merged changes were checked.
const openPrs = JSON.parse(run("gh", ["pr", "list", "--state", "open", "--limit", "100", "--json", "number,title,isDraft,headRefName"]));
const otherBranches = run("git", ["ls-remote", "--heads", "origin"])
  .split("\n")
  .map((line) => line.split("refs/heads/")[1])
  .filter((b) => b && b !== "main" && !openPrs.some((p) => p.headRefName === b));
if (openPrs.length > 0 || otherBranches.length > 0) {
  console.log("Open work on GitHub that this release would leave out:");
  for (const p of openPrs) console.log(`  #${p.number}${p.isDraft ? " (draft)" : ""}: ${p.title}`);
  for (const b of otherBranches) console.log(`  branch ${b} (no open pull request)`);
  if (!process.stdin.isTTY) fail("there is open work to confirm, and no terminal to confirm it in: run this in a terminal");
  const prompt = createInterface({ input: process.stdin, output: process.stdout });
  const answer = await prompt.question("Is each one deferred on purpose? Type yes to release without them: ");
  prompt.close();
  if (answer.trim().toLowerCase() !== "yes") fail("stopped: merge what belongs in this release first, then run it again");
}

const pkg = readFileSync("package.json", "utf8");
const current = JSON.parse(pkg).version;
const m = /^(\d+)\.(\d+)\.(\d+)$/.exec(current);
if (!m) fail(`package.json's version ${current} isn't a plain X.Y.Z`);
const [major, minor, patch] = m.slice(1).map(Number);
const next = bump === "major" ? `${major + 1}.0.0` : bump === "minor" ? `${major}.${minor + 1}.0` : `${major}.${minor}.${patch + 1}`;

const changelog = readFileSync("CHANGELOG.md", "utf8");
const head = "## [Unreleased]\n";
const at = changelog.indexOf(head);
if (at < 0) fail("CHANGELOG.md has no ## [Unreleased] section");
const rest = changelog.slice(at + head.length);
const end = rest.search(/^## \[/m);
const unreleased = (end < 0 ? rest : rest.slice(0, end)).trim();
if (!unreleased) fail("the [Unreleased] section is empty: there's nothing to release");

const date = new Date().toISOString().slice(0, 10);
const section = `## [${next}] - ${date}\n\n${summary ? `${summary}\n\n` : ""}${unreleased}\n\n`;
writeFileSync("CHANGELOG.md", `${changelog.slice(0, at)}${head}\n${section}${end < 0 ? "" : rest.slice(end)}`);
let nextPkg = pkg.replace(/("version":\s*")[^"]+(")/, `$1${next}$2`);

// The first release (package.json still "private": true): publishable from here on, and the README
// that ships in the tarball stops saying the package isn't released. Each passage must be found
// exactly, so a reworded README stops the release instead of shipping the old text.
const FIRST_RELEASE_README = [
  [
    "Status: **pre-release**: npm has only a 0.0.1 placeholder under this name; 0.1.0 is the first usable release.",
    "Status: **0.x, before 1.0**.",
  ],
  [
    "> The 0.0.1 on npm is a name placeholder with no code. Until 0.1.0, install from a clone (`pnpm build`, then `pnpm add ../better-auth-id-jag`).\n\n",
    "",
  ],
];
let firstRelease = false;
if (JSON.parse(pkg).private === true) {
  firstRelease = true;
  nextPkg = nextPkg.replace(/^\s*"private":\s*true,\n/m, "");
  if (JSON.parse(nextPkg).private !== undefined) fail('couldn\'t remove "private": true from package.json');
  let readme = readFileSync("README.md", "utf8");
  for (const [from, to] of FIRST_RELEASE_README) {
    if (!readme.includes(from)) fail(`the README's pre-release passage has changed; update FIRST_RELEASE_README in scripts/release.mjs:\n  ${from}`);
    readme = readme.replace(from, to);
  }
  writeFileSync("README.md", readme);
}
writeFileSync("package.json", nextPkg);

const branch = `release/${next}`;
run("git", ["checkout", "-b", branch]);
run("git", ["commit", "-am", `Release ${next}`]);
run("git", ["push", "-u", "origin", branch], { stdio: ["ignore", "ignore", "inherit"] });
// The README is packed into the tarball, so the npm page shows it as it is now until the next release.
const docsCheck = [
  "**Before merging: do the docs cover everything in this section?**",
  "- [ ] README: features, the options tables and defaults, the events, the conformance and interoperability tables",
  "- [ ] docs/security.md (threats and known limitations), docs/interop.md, docs/versioning.md",
  "- [ ] Nothing in the README still describes the package as unreleased",
  "- [ ] `pnpm docs:check` passes",
  "- [ ] Open pull requests and branches (the release script listed them): each one is in this release or deferred on purpose",
].join("\n");
const what = firstRelease ? `Version ${next} in package.json (no longer \`"private": true\`), its dated CHANGELOG section, and the README's release status.` : `Version ${next} in package.json and its dated CHANGELOG section.`;
const url = run("gh", ["pr", "create", "--draft", "--base", "main", "--title", `Release ${next}`, "--body", `${what}\n\n${docsCheck}\n\n**Merging this releases it:** tag-release.yml tags v${next} on main and starts the release run. Then approve the \`npm\` environment in GitHub, and the staged publish on npmjs.com.`]);
console.log(`${current} → ${next}: ${url}\nCheck the docs against the release (the checklist in the PR); the npm page shows this README until the next release.\nWhen CI is green, mark it ready and merge it to release.`);
