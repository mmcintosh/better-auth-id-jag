# Security policy

This package decides which AI agents get access tokens, for whom, and at which servers. A flaw in it can let an agent act as someone it shouldn't, reach a tool it wasn't allowed, or keep access after it was taken away. Reports are welcome and taken seriously.

## Reporting a vulnerability

**Please don't open a public issue.** Report privately through GitHub:

1. Go to the repository's **[Security](https://github.com/mmcintosh/better-auth-id-jag/security) tab**.
2. Choose **Report a vulnerability**.

Please include, as far as you can:

- the version or commit, the runtime (Node or Workers) and the database;
- which side is affected (the issuer, `idJagIssuer()`, or the receiver, `idJagGrant()`) and, for an interop issue, the other implementation and its version;
- the request or token that triggers it, with every key, client secret, token and piece of personal data replaced by throwaway ones;
- what an attacker gains: an ID-JAG or access token for another user, a wider scope or another audience than the policy allows, a replayed ID-JAG, a forged one accepted, a way round a block, learning which users exist or what a policy allows, denial of service, …

What happens next:

- The maintainer aims to acknowledge a report within **7 days** and to agree on a fix and a disclosure date with you.
- Fixes are developed in a private GitHub security advisory and released with a CVE where one applies.
- You're credited in the advisory and the changelog, unless you'd rather not be.

## Supported versions

Until 1.0, only the latest release gets security fixes. The package implements an IETF draft
(`draft-ietf-oauth-identity-assertion-authz-grant`, currently -04). A security issue in the draft itself is still
worth reporting here: we'll take it to the OAuth working group with you.

## Scope

In scope:

- The plugins and the shared core (`src/`): `idJagIssuer()`, `idJagGrant()` and the client plugin.
- The published package's configuration, defaults and startup validation.
- The example Workers' code (`examples/`), as far as someone could reasonably copy it.

Out of scope, but still worth telling us about:

- Better Auth itself, `@better-auth/oauth-provider`, `@better-auth/mcp` and `@better-auth/sso`. Report these to their projects; we'll help coordinate if this package is affected.
- Another implementation's ID-JAG handling (Okta, Keycloak, node-oauth2-server, …). Where ours interoperates with it in an unsafe way, that part is in scope.
- The example Workers' deployments, as opposed to their code.
- Behaviour the [README](README.md) or [DECISIONS.md](DECISIONS.md) documents as intended: for example, that a block stops new ID-JAGs but doesn't revoke access tokens a receiver has already issued.

## What the package already defends against

The [README](README.md) describes the controls on each side: what the receiver checks and in what order, the policy
and blocks at the issuer, and refusals that don't tell the caller why. [DECISIONS.md](DECISIONS.md) records the
evidence for each: tests, mutation checks and review findings. Reading these first helps tell a new issue from a known
limitation.

Every security check is on a mutation list (`test/mutations/`). Each week, `scripts/mutate.py` breaks each check in
turn on `main`, and the run fails if no test notices.

## Supply chain

- **Actions:** every GitHub Action is pinned to a commit SHA, with least-privilege tokens.
- **Automated checks:**
  - Runtime dependencies are audited on every push and PR, and daily; a vulnerability blocks the build.
  - Dependency review on every PR blocks a vulnerable or wrongly licensed runtime dependency.
  - OSV-Scanner scans the whole lockfile, development tools included, daily.
- **Releases:** they will be published from CI with **npm provenance**, and each GitHub release carries a CycloneDX **SBOM** of the installed dependency tree.
- **Other:** gitleaks scans the full history on every push.
