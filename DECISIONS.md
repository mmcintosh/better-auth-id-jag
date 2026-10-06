# Decisions

Every entry is an agent's choice unless it says the maintainer decided it, and each agent's choice is raised with the maintainer.

## D-001: Phase 0 scaffold, name and licence used provisionally (2026-10-05) — agent's choice

Scaffolded from `better-auth-scim-provisioning`: pnpm, biome (its `biome.jsonc` unchanged), vitest, strict tsconfig
(`noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`), `SECURITY.md`, `.gitleaks.toml`, `LICENSE`, `scripts/build.mjs`.
`package.json` is `"private": true`, version `0.0.0`, name `better-auth-id-jag` and licence MIT — the plan's
recommendations for Questions 1 and 2, used so the scaffold has a name; **not decided**, the maintainer's call. CI workflows,
CHANGELOG and README are not copied yet: they come with Phase 1, when there is code to gate.

`git init` locally (no remote, nothing pushed), as the handoff allows once Phase 0 starts. No GitHub repository, no npm
name claimed.

## D-002: Better Auth pinned to 1.7.6 (2026-10-05) — agent's choice

The siblings' dev dependencies and the first issuer consumer are on 1.7.6, and the measured extension
API (plan §2.3) is 1.7.6's. 1.7.7 was published the same day; CI's matrix (1.7.5 and latest-1.7, as the siblings) will
cover it once CI exists. Peer range stays `>=1.7.5 <1.8.0`. Every `@better-auth/*` is pinned exactly to 1.7.6.

## D-003: Phase 0 result — extension grants work under both providers, on Node and workerd (2026-10-05)

Kill criteria not hit. Details, measurements and each guard broken once: `docs/phase-0.md`. Raised with the maintainer: Phase 1
does not start without the maintainer's go.

## D-004: After the Phase 0 review — the maintainer's decisions (2026-10-05)

Decided by the maintainer, after an independent review of Phase 0 (go for Phase 1, with conditions):

- **Name** `better-auth-id-jag`, **licence** MIT (D-001's provisional choices confirmed).
- **Policy depth:** code hook **and** registry with an admin API.
- **Plans and handoffs stay private:** `plans/` and `HANDOFF-*.md` are git-ignored, as `private/` is. Public docs never
  link to them.
- **GitHub repository private at first;** npm name reserved with a placeholder, as `better-auth-saml-idp` did.
- **Signing algorithm is a visible choice** (review condition 4, added to S4): the receiver accepts RS256, ES256 and
  EdDSA only and requires `kid`; the issuer's algorithm is an option (default: the jwt plugin's), the docs say EdDSA may
  not interoperate, and the issuer example signs ES256.
- **Client ids differ across the two servers** (review condition 2, plan Question 6): Okta's resource-app guides say the
  resource authorization server issues the requesting app its client id, and the ID-JAG's `client_id` is "the client's
  ID at your resource authorization server, which might differ from its ID at the IdP". The issuer stores a
  client-id-at-resource per (requesting client, resource server), defaulting to the client's own id.


## D-005: Vitest 4 with @cloudflare/vitest-plugin; CI scope; first consumer (2026-10-05) — the maintainer's decisions

- **Vitest 4.1.11 and `@cloudflare/vitest-plugin` 1.3.6**, as `better-auth-saml-idp` (its D-069): the plugin peers
  `vitest ^4.1`, and it runs the **whole** suite inside workerd, which the plan asks for (§4). Two projects over the same
  files: `node` (node:sqlite) and `workerd` (D1, migrated by Better Auth's own `getMigrations`). The siblings on Vitest 5
  (`better-auth-scim-provisioning`, `better-auth-digital-credentials`) drive workerd through Miniflare from Node for
  specific tests instead. Vitest 5 when the plugin supports it (cloudflare/workers-sdk#15500, #15618).
  - In workerd the hosts in one test file share a D1, so test users get unique emails.
  - workerd logs "Called .text() on an HTTP body which does not appear to be text" for every form POST Better Auth
    reads: noise, not a failure.
- **CI now:** `ci.yml` (typecheck, lint, both test projects, build; Better Auth 1.7.5 and latest-1.7, every
  `@better-auth/*` switched with it; Node 22 and 24; gitleaks), `dependencies.yml` (runtime audit, dependency review;
  dependency review and OSV skipped while the repository is private, since both need Advanced Security there), Dependabot.
  **Wired but dormant:** `release.yml` (tags and manual dry runs only) and `tag-release.yml` (does nothing while
  `package.json` is `"private": true`). **Later:** CodeQL and Scorecard when the repository is public; adapters,
  runtimes and the example jobs when there is code for them.
- **First receiver consumer:** the example in this repository. A real MCP server when there is one to name.
- **npm:** a 0.0.1 placeholder, published by the maintainer, only to hold the name.
