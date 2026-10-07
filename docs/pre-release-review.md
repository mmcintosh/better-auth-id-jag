# Pre-release review: 0.1.0 (2026-10-06)

**Pinned at `a7a22ee`.** This review comes before the first usable release, 0.1.0, which is planned for Fri
2026-10-09. The previous review was Phase 3 (`95d46f0`, note `docs/phase-3.md`). Its findings are fixed in D-022.
CI is green at `a7a22ee`: all 11 jobs, including the test matrix (Better Auth 1.7.5 and latest 1.7 × Node 22 and 24),
`pack:check`, the six-database adapter matrix, the example Workers, and secrets. Dependencies and Interop are green
too (Interop was dispatched by hand at `a7a22ee`).

**Not in this review, and still to come before the release** (they need the maintainer): the live Okta and xaa.dev
evidence session, making the repository public, npm trusted publishing, and the release PR (version 0.1.0,
`private: false`, a dated CHANGELOG section). The release PR changes only `package.json` and `CHANGELOG.md`.

## The question for this review

Is `a7a22ee` fit to publish as 0.1.0: the receiver as a usable pre-1.0 plugin, the issuer as **experimental**?

## What to review, in order

1. **The Phase 3 fixes since `95d46f0`** (5 commits, 26 files, +422 / −41):
   - D-022: the six findings. The test for finding 3 is in `test/issuer/saml-subject.test.ts` ("the verifier gets the
     authenticated client"). The end-to-end check forging the body's `client_id` is in
     `test/interop/saml-idp-e2e/e2e.mjs`.
   - The commits made during the last review: README audit and conformance table (`6398bec`), SECURITY.md, a
     neutral example client id in a test (`ef40b14`), the examples' xaa.dev trust and the `okta-agent.mjs` evidence
     modes (`2979afb`), CodeQL and Scorecard gated on the repository being public, and the CI `example` job
     (`74ece4e`).
2. **The published package, as npm will see it.** Run `pnpm build && npm pack --dry-run`: 40 files, 170 kB packed,
   made up of `dist/` (ESM, `.d.ts`, source maps), README, LICENSE and `package.json`. Things to check:
   - the `exports` (`.` and `./client`);
   - the peer ranges (`better-auth`, `@better-auth/core` and `@better-auth/oauth-provider` at `>=1.7.5 <1.8.0`);
   - the optional peers (`@better-auth/mcp`, `@better-auth/sso`, `better-auth-saml-idp >=1.2.0 <2`);
   - `engines`;
   - nothing private or test-only in the tarball;
   - whether CHANGELOG.md and SECURITY.md should also ship.
3. **The README, claim by claim, against the code.** This includes the quick start, the options tables and their
   defaults, the conformance table (draft -04 and MCP Enterprise-Managed Authorization), the interop table, the
   "what stops an exchange" lists, and the new paragraph on path (b) refresh tokens. A claim the code doesn't back is
   a release blocker.
4. **`docs/security.md` and SECURITY.md.** Check the threat tables, the known limitations (including the new SAML,
   `sub_id`, JIT and concurrency entries), and the pre-1.0 support statement. The supply-chain claims are marked as
   applying once the repository is public.
5. **What going public exposes.** The full history was checked: gitleaks over every commit, no file under
   `private/`, `plans/` or `HANDOFF-*` ever committed. The author email is the same as on the public
   better-auth-saml-idp. One real Okta client id (not a secret) is in the history, from before `ef40b14`. The example
   Workers' deploy configs are git-ignored. Decide whether anything in `examples/` or `docs/` should not be public.
6. **The workflows once public:** `release.yml` (npm provenance, the `npm` environment), `tag-release.yml`, the
   dependency review and OSV gates, CodeQL and Scorecard.

## Evidence at `a7a22ee`

- **Tests:** 866 passing on Node (node:sqlite) and workerd (D1), and 36 skipped (Docker interop, and the adapter
  matrix without a database URL). Typecheck (TypeScript 7 and 5.9 strict host), lint and `pack:check` are clean.
- **The SAML end-to-end test** against npm better-auth-saml-idp 1.2.0: every check passes.
- **Mutations:** the six D-022 entries are all caught. The full weekly run was dispatched at `a7a22ee`.

## Known and recorded (not blockers, by decision)

- The issuer is experimental. Single use of ID-JAGs stays, with no reuse option (oauth-wg issue #130).
- The known gaps: JIT for one `sub` with different emails, arriving concurrently, can leave two users (D-A24). SAML
  users without an email can't be JIT-provisioned (SCIM is planned). MongoDB runs without adapter transactions,
  because of an upstream problem (D-019).
- A path (b) refresh token is an ordinary provider refresh token. A block doesn't stop its `grant_type=refresh_token`
  use; revoking it does (README, `docs/security.md`).
- The Better Auth #8023 comment stays on hold.
