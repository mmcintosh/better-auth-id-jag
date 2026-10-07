# Phase 3: SAML, the Phase 2 review's fixes, and Phase 4 groundwork (2026-10-06, before review)

**Status:** the code is complete and pinned for review at **`95d46f0`**. Since the last review (`de31e58`) there are 30
commits and 77 files (+9,361 / −419). CI is green on main: tests on Node and workerd, package checks, the six-database
adapter matrix, and dependencies.

**Not done, and not reviewable yet** (they need the maintainer): the live xaa.dev SAML-variant run, the Okta SAML
requesting-app run, and the planned Okta evidence session (`docs/phase-2.md`, "Next").

## What to review, in order

1. **The Phase 2 review's defects** (D-014, D-015; receiver D-A23–D-A26, D-A32; issuer D-B22–D-B25):
   - email fallback requires a verified local email and respects `account.accountLinking`;
   - concurrent first use converges on one link and never returns a 500 (`test/receiver/concurrency.test.ts`, which
     forces the race with a barrier);
   - `jwks.maxStaleSeconds`;
   - `jitRole` validation;
   - `maxIdTokenAgeSeconds` and `sid`;
   - block-from-jti falls back to the audit row;
   - `blocks: { canManage }`.

   Also the review's test gaps: email only when every allowing source opts in; an expired invitation; two equivalent
   survivors, shown equivalent by behaviour tests.
2. **`cnf` refused, and `iss` from `getIssuer()`** (D-012). The ID-token issuer is now kept apart from the ID-JAG's
   `iss`: the provider signs ID tokens with the raw value but publishes a normalised one.
3. **Receiver: `sub_id` (saml-nameid) resolution** (D-A27–D-A31):
   - mappings come only from the already-matched trust entry (§9.5);
   - qualifiers are compared null-safely;
   - transient NameIDs are refused;
   - a malformed `sub_id` never falls back to `sub`;
   - links use the mapping key, and the convergence rules apply to it.
4. **Issuer: both SAML paths** (D-016; `docs/tracks/issuer.md` D-B26 onward):
   - **(a):** a saml2 assertion → an ID-JAG;
   - **(b):** a saml2 assertion → a refresh token (draft -04 §4.5), then the existing refresh-token path;
   - `scope_required`, the `id-jag.refresh-issued` event, and the duck-typed `SamlIdpExchange`.

   better-auth-saml-idp 1.2.0 (the maintainer's other repository, released today) does the verification. The
   end-to-end test across both repositories is `test/interop/saml-idp-e2e`; every check passes against npm 1.2.0
   (D-017, D-020).
5. **Phase 4 groundwork:**
   - the package checks (D-018: TypeScript 7 and 5.9 strict host, publint, Are the Types Wrong), which found that the
     receiver's options rejected `undefined`;
   - the adapter matrix (D-019; MongoDB runs without adapter transactions, because of an upstream oauth-provider
     problem described there);
   - the audit overrides (D-021);
   - Better Auth's lint rules (D-013).

## Evidence at `95d46f0`

- **Tests:** 860 passing, on Node with node:sqlite and in workerd with D1. 36 are skipped: the interop suites need
  Docker, and the adapter matrix needs a database URL.
- **Typecheck:** TypeScript 7 and 5.9 (strict host).
- **Lint:** clean.
- **pack:check:** green.
- **Adapter matrix:** 4/4 on Postgres, MySQL, MongoDB, Drizzle on Postgres and on MySQL, and Prisma, locally and in
  CI.
- **Mutations:** each fix's mutations were run, all caught or explained. The issuer SAML work's run, before it was
  committed, was 252 mutations, 241 caught, 11 expected survivors, 0 problems. The weekly job runs the whole list.
- **The cross-repository SAML end-to-end test:** all checks pass against better-auth-saml-idp 1.2.0 from npm.

## Known and recorded

- **A known gap:** JIT for one `sub` with different emails, arriving concurrently, can leave two users (D-A24).
- **A known gap:** a SAML user with no `email` can't be JIT-provisioned (Better Auth users need an email); SCIM
  provisioning is the planned answer (`docs/phase-2.md`, "After Phase 3").
- **An upstream issue for the maintainer:** MongoDB plus oauth-provider transactions (D-019).
- **The #8023 comment** stays on hold (D-012).
