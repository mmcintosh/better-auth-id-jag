# Contributing

Thanks for helping. Bug reports, interop reports, docs fixes and code are all welcome.

For **security vulnerabilities**, don't open an issue: see [SECURITY.md](SECURITY.md).

## Ways to help without writing code

- **Tell us another implementation works (or doesn't).** Open an [interop report](https://github.com/mmcintosh/better-auth-id-jag/issues/new?template=interop.yml): an IdP whose ID-JAGs you sent to our receiver, an authorization server you sent our ID-JAGs to, or an MCP client that ran the flow. A "works with X" report with the settings you used is as valuable as a bug report: it becomes a row in [docs/interop.md](docs/interop.md).
- **Improve the docs.** If something in the [README](README.md) was unclear or wrong for you, it will be for others.
- **Follow the draft.** ID-JAG is an IETF draft (-04 today). If a new draft or an implementation changes a claim, a URN or a rule, an issue pointing at it helps.

## Setup

You need Node 24 (22 works) and pnpm 10 (`corepack enable` gives you the pinned version).

```sh
git clone https://github.com/mmcintosh/better-auth-id-jag.git
cd better-auth-id-jag
pnpm install
pnpm test
```

## Checks

Everything CI runs, locally:

| Command | What it does |
|---|---|
| `pnpm typecheck` | TypeScript. |
| `pnpm lint` | Biome; warnings fail. |
| `pnpm test` | Unit, integration and interop tests, on Node (`node:sqlite`) and on workerd (D1). |
| `pnpm test:node` / `pnpm test:workerd` | One runtime only: quicker while iterating. |
| `pnpm build` | The `dist/` build with type declarations. |
| `scripts/use-better-auth.sh 1.7.5` | Install another Better Auth version (and its plugins) for the suite: a version, `latest-1.7`, `latest` or `next`. CI runs 1.7.5 and `latest-1.7`. |

Three suites need something extra:

- **Mutations.** Each security check is listed in `test/mutations/*.json`. The script breaks each one in turn and fails if no test notices, if an entry no longer matches the code, or if a known survivor is now caught:

  ```sh
  python3 scripts/mutate.py test/mutations/core.json test/mutations/issuer.json test/mutations/receiver.json
  ```

  It takes a while (CI runs it weekly, about 40 minutes). Run the list for the side you changed.

- **Keycloak**, which needs Docker: start Keycloak as [docs/interop.md](docs/interop.md#run-it) shows, then:

  ```sh
  INTEROP_KEYCLOAK=1 npx vitest run --project node test/interop/keycloak.test.ts
  ```

- **node-oauth2-server**, against the unreleased pull request that adds ID-JAG, installed into a directory of your choice as [docs/interop.md](docs/interop.md#our-issuer--node-oauth2-server) shows:

  ```sh
  INTEROP_NODE_OAUTH2=1 INTEROP_NODE_OAUTH2_DIR=<dir> npx vitest run --project node test/interop/node-oauth2-server.test.ts
  ```

## How changes are made here

- **Tests with every change.** A bug fix comes with the test that would have caught it.
- **Security checks are mutation-checked.** For a check that refuses something, add it to the side's list in `test/mutations/` and confirm `scripts/mutate.py` catches it. Say in the PR that you did.
- **Refusals don't leak.** A new refusal reason goes in `REASONS` ([src/core/errors.ts](src/core/errors.ts)), and it's `public: true` only when the caller learns nothing it didn't send. Anything about trust, keys, users or policy stays generic for the caller and specific in the audit event.
- **Decisions are recorded.** A design choice, an interop finding or a security trade-off gets an entry in [DECISIONS.md](DECISIONS.md): what was found, what was decided, and the evidence. Look at recent entries for the shape.
- **Docs move with the code.** A new option, table, event or error code goes in the [README](README.md); an interop result goes in [docs/interop.md](docs/interop.md), with the date and version. Add a line under `[Unreleased]` in [CHANGELOG.md](CHANGELOG.md).
- **Draft identifiers live in one place.** Claim names, URNs and metadata fields are in [src/core/urns.ts](src/core/urns.ts), with the draft they come from.
- **Breaking?** Check [Versioning](docs/versioning.md).
- **No real secrets, ever.** Tests generate their keys. Use throwaway keys, client secrets, tokens and users in fixtures and issue reports. gitleaks runs on every push.
- **Commits:** small, with an imperative subject ("Accept act and carry it into the access token") and a body that says why.

## Pull requests

1. Fork the repository and branch from `main`.
2. Make the change with its tests and docs.
3. Run `pnpm typecheck && pnpm lint && pnpm test && pnpm build`.
4. Open the PR and fill in the template.

CI runs the suite on Node 22 and 24, on Better Auth 1.7.5 and the latest 1.7.x, plus a dependency review. A new **runtime** dependency needs a good reason: every one is attack surface for something that hands out access tokens, and must be MIT-compatible.

## Releasing (maintainers)

Releases come only from CI ([release.yml](.github/workflows/release.yml)), so every npm version carries provenance, built from the same commit the tests ran on.

One-time setup, before the first release:

1. Claim the name with the placeholder `0.0.1`, published by hand: npm can't trust-publish a package that doesn't exist yet. There is no npm token in this repository, and none is needed.
2. **Trusted publishing** on npmjs.com: package settings → Trusted publishing → GitHub Actions, user `mmcintosh`, repository `better-auth-id-jag`, workflow `release.yml`, environment `npm`, with **"allow npm publish" left unchecked**: the workflow can only *stage* a version (`npm stage publish`), authenticating with GitHub's short-lived OIDC identity.
3. GitHub **Settings → Environments → `npm`**: the maintainer is a required reviewer, and only `v*` tags may deploy, so every publish waits for an approval.

Each release:

1. Keep CHANGELOG.md's `[Unreleased]` section up to date as changes land.
2. On an up-to-date, clean `main`: `pnpm release patch|minor|major ["One sentence for the top of the section."]`. It bumps `version` in package.json, dates the `[Unreleased]` section, and opens the **Release X.Y.Z** pull request. On the first release (package.json still `"private": true`) it also removes `"private": true` and the README's two pre-release passages; it stops if either passage has been reworded. The PR carries a docs checklist: the README is in the tarball, so the npm page shows it until the next release.
3. Run **Actions → Release → Run workflow** on `main` for a dry run (optional later; do it once before the first release): it tests, packs, and builds the SBOM without publishing.
4. **Merge the release PR when CI is green: that's the go-ahead.** [tag-release.yml](.github/workflows/tag-release.yml) tags `vX.Y.Z` on `main` and starts the release run on the tag. It checks the tag matches package.json, tests and packs. After your approval in the `npm` environment, it **stages** the tested tarball with provenance and creates the GitHub release with its CycloneDX SBOM.
5. Approve the staged version on npmjs.com (Staged packages, with your security key) or with `npm stage approve <id>`. Only then is it installable.
6. Before 0.1 and at each draft change: check that [src/core/urns.ts](src/core/urns.ts) and the README name the draft the release implements.
