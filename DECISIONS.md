# Decisions

Every entry is an implementation choice unless it says the maintainer decided it, and each implementation choice is raised with the maintainer.

## D-001: Phase 0 scaffold, name and licence used provisionally (2026-10-05) — implementation choice

Scaffolded from `better-auth-scim-provisioning`: pnpm, biome (its `biome.jsonc` unchanged), vitest, strict tsconfig
(`noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`), `SECURITY.md`, `.gitleaks.toml`, `LICENSE`, `scripts/build.mjs`.
`package.json` is `"private": true`, version `0.0.0`, name `better-auth-id-jag` and licence MIT — the plan's
recommendations for Questions 1 and 2, used so the scaffold has a name; **not decided**, the maintainer's call. CI workflows,
CHANGELOG and README are not copied yet: they come with Phase 1, when there is code to gate.

`git init` locally (no remote, nothing pushed), as planned for Phase 0. No GitHub repository, no npm
name claimed.

## D-002: Better Auth pinned to 1.7.6 (2026-10-05) — implementation choice

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
- **Working notes stay private:** they are git-ignored, and public docs never link to them.
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

## D-006: The shared core (2026-10-05) — implementation choices

`src/core/`: `urns.ts`, `errors.ts`, `jwt.ts`, `replay.ts`, `audit.ts`. Choices made here, both tracks follow:

- **Errors.** Every refusal is an `IdJagRefusal(reason, detail?)`; `toApiError()` turns it into Better Auth's
  `APIError` (a plain `Error` from a grant handler is an empty HTTP 500, measured). 401 for `invalid_client`, 400 for
  the rest. Each reason is `public` (the caller sent the defect: a missing parameter, a malformed token, an expired
  one) or not; a non-public reason shows only its error code's generic text (S8). Reason codes and details go to the
  audit event only.
- **`typ`** is compared as a media type: case-insensitive, `application/` optional (RFC 7515 §4.1.9). Missing = refused.
- **Parse before verify.** `parseIdJag` checks shape, `typ`, `alg` (RS256, ES256, EdDSA only), `kid`, `crit` (refused:
  we understand no extensions), required claims, `aud` as a string or one-element array, `0 < exp - iat <= 900`.
  `verifyIdJag` then checks `iss` against the issuer the caller resolved **before** using any key, the signature
  (jose `compactVerify`, signature only), `aud` by exact string, then `exp`/`nbf`/`iat` with skew (default 60 s).
  `client_id` continuity and `jti` are the receiver's, after this. **Order differs from the plan's §3.4:** time
  checks come before the `jti` insert, so the replay row never records a token refused for its age.
- **jti table** `idJagJti`: key = SHA-256 of `id-jag:<side>\0<iss>\0<jti>`, insert-first, unique at field level and as
  a named table-level index (MongoDB), `expiresAt` = token `exp` + skew, `sweepJtis` deletes expired rows. Shared:
  `side` is `issued` or `accepted`.
- **Audit** as better-auth-saml-idp's D-038: `onIssued`, `onAccepted`, `onRefused`, `onAdminChanged`, run through
  `runInBackground`; optional `idJagAudit` table with retention; refusals with no authenticated client aren't stored;
  caller-controlled text is made log-safe. `IssuedEvent` carries both the client's id at the IdP and its id at the
  resource (D-004).
- **Build:** `buildIdJag(claims, signer)` takes a signer function, so the core has no Better Auth signing dependency;
  the issuer passes one built on the jwt plugin's `signJWT`.

**Evidence:** 90 tests (45 per runtime: Node/SQLite and workerd/D1), including 1,500 fast-check runs per runtime on
the parser, and 10 concurrent jti records across two auth instances on one database. **Each guard broken once**
(`test/mutations/core.json`, `scripts/mutate.py`): 18 mutations, 16 caught at first; the parse-time `alg` check and
log-safe refusal details survived, a test was added for each, and both are now caught.

## D-007: Review of the core, and its fixes (2026-10-05)

An independent adversarial review (a separate reviewer, read-only, reproducing each finding against a bundle of
`src/core`) found 14 issues and weak tests. The committed tree also failed `pnpm typecheck` (a test typing under
`exactOptionalPropertyTypes`, so CI was red on 39fe6eb). Every finding is fixed except where noted:

- **High: `authorization_details` and `act` were passed through unchecked.** The draft says a receiver MUST process
  `authorization_details` (RFC 9396), and ignoring it or `act` could grant more than the IdP authorised. Both are now
  refused at parse (`unsupported_claim`, public), and `buildIdJag` won't mint them. `sub_id` is typed as an RFC 9493
  object and is informational only (draft §8: never a source of trust).
- **NaN/Infinity options switched checks off.** `clockSkewSeconds` must be an integer in [0, 300], `maxLifetimeSeconds`
  in [1, 900], `now` a non-negative integer. Anything else is a configuration error.
- **Self-issued ID-JAGs (draft §9.3)** are refused (`self_issued`).
- **S8 oracles.**
  - The time checks now run before trust, so `expired` can't confirm that an issuer is trusted. **This amends D-006's
    order:** parse, time, `iss`, signature, `aud`.
  - An algorithm the trusted issuer doesn't publish is now `bad_signature` (non-public), not the public
    `disallowed_alg`.
  - The set of public reasons is pinned by a test, so changing it is a deliberate edit.
  - **For Track A:** compute the scope intersection before subject resolution, so `no_scope` doesn't distinguish known
    users.
  - **Not fixed:** a JWKS fetch adds timing for trusted issuers. That's inherent; the cache narrows it.
- **Audit retention was never enforced.** Added `sweepAudit`. Both plugins must run it with `sweepJtis`.
- **A handler could delay or alter the audit row.** The row is now written before the handler runs.
- **Log safety.**
  - Every string field of an event is made log-safe, not only `detail` and the user agent.
  - `IdJagRefusal` caps and cleans its detail and message.
  - `logSafe` also strips U+2028, U+2029 and U+061C.
- **Storing refusals keyed on `clientId`** is replaced by an explicit `authenticated: true`, set only after
  `authenticateClient` succeeds.
- **Replay key.**
  - It's a hash of `JSON.stringify(["id-jag", side, iss, jti])`. The NUL-joined form could collide.
  - Control characters are refused in `iss`, `jti` and other identifiers.
  - `recordJti` now computes `expiresAt` itself as `exp + skew + 300 s margin`, so slightly fast clocks can't sweep a
    row early.
- **JWKS errors.** A fetch failure, a non-200 response or bad JSON is now `jwks_unavailable`, not `bad_signature`.
  Several keys with one `kid` (rotation) are tried in turn.
- **401 `invalid_client`** carries a `WWW-Authenticate: Basic` challenge. `Ed25519` (RFC 9864) is added to the allowed
  algorithms.
- **Found by the improved property test:** a header value whose `toString` throws (`{"typ":{"toString":"x"}}`) made
  `parseIdJag` throw a `TypeError` instead of refusing. Fixed, with a regression test.
- **Tests.**
  - The clock is injected, so time tests don't flake at a second boundary.
  - The property test now changes one field of a valid token, so its deep checks run in about 95 of every 1,000 runs
    (0.25 before).
  - The length cap is tested exactly at the limit and one character over.
  - Boundary tests cover `exp` + skew, `nbf`, `iat`, exactly 900 s and a zero lifetime.

**Open, for the maintainer:**
- **Re-presentation (finding 5).** Draft §4.4.3 lets a client re-submit an unexpired ID-JAG once its access token
  expires. Our receiver enforces strict single use (S3). The implementation choice is to keep strict single use and document
  it: the client gets a new ID-JAG from the IdP, which keeps revocation at the IdP.
- **Adapters that don't enforce UNIQUE (finding 12):** Better Auth's memory adapter, or a MongoDB without the named
  index. On those, replays are accepted silently. To be documented in the guide (Phase 4). A startup self-test was
  considered but not added, because it would write at boot.

**Evidence.** 120 tests (60 per runtime). **Each guard broken once** (`test/mutations/core.json`): 42 mutations, all
caught. Of the 43 in the first run, two survived:
- `no_scope` made public: a test now pins the public reasons.
- The handler receiving the original object: harmless once the row is written first, so the defensive copy was
  removed, along with that mutation.

## D-008: Phase 1 merged (2026-10-06)

Track A (receiver, `docs/tracks/receiver.md`, D-A01–D-A17) and Track B (issuer, `docs/tracks/issuer.md`, D-B01–D-B13)
merged into main, each re-checked independently first (typecheck, lint, full suite, only its own files changed).
Merge-time changes: `src/index.ts` exports the core, issuer and receiver;
`better-auth-id-jag/client` exports the issuer's client plugin; the build script rewrites nested and directory
declaration imports for NodeNext consumers (it only handled top-level files); worktree directories are ignored;
`test/merge/both-plugins.test.ts` proves both plugins on one host share one jti table and one audit table. Evidence,
the decisions to review, the open questions and the core change requests: `docs/phase-1.md`. Phase 2 does not
start without the maintainer's go.

## D-009: Phase 2 begins — the maintainer's decisions on the Phase 1 questions (2026-10-06)

Decided by the maintainer, on the Phase 1 review's recommendations (`docs/phase-1.md` numbering):

1. Strict single use of an ID-JAG stays. The client gets a fresh one, which keeps revocation at the IdP.
2. Adapters that don't enforce UNIQUE are documented, plus a startup warning on the memory adapter (no write).
3. sso trust stays opt-in (D-A01).
4. The `resource` claim isn't required yet: a `requireResourceClaim` option, default off, revisited after Phase 2.
5. JIT provisioning adds the user to the trust entry's organization.
6. No access-token lifetime cap in 0.1: the provider's hour, documented. Per-issuance expiry is raised upstream later.
7. No admin API for `idJagTrustedIssuer` before 0.1.
8. Both policy sources must allow; the narrower grant wins (D-B04).
9. No pairwise subjects (D-B02).
10. The ambiguous host-versus-organization resource server stays refused.
11. No wildcard client ids.
12. "Revoke" becomes real: a block keyed on (user, client, audience) that the policy step checks.
13. `email` only when verified.

Also decided for Phase 2:
- **Refresh-token subject tokens** move from Phase 3 into Phase 2.
- **The mutation lists** are re-run on main, then weekly in CI.
- **Two Workers on the demo account** (an example IdP and an example MCP server) stay up through Phase 2. The receiver
  is publicly reachable for Okta and xaa.dev.
- **Keycloak and Authelia** run in Docker; node-oauth2-server runs in a Node test.
- **The track worktrees** are removed.

**Audit gap closed** (the review's finding 1, both tracks' core change request 1):
- **What's added:** the provider's own refusals (a wrong secret, a client not registered for the grant, any other
  provider `APIError`) are now emitted as `id-jag.refused` with `client_authentication_failed`,
  `client_not_allowed_grant` or `provider_refused`, `authenticated: false`, the client id the caller named, and the
  provider's error code. The response itself is unchanged.
- **Storage:** these reach handlers, which is the brute-force signal a SIEM wants, but not the table (D-007: only
  refusals after authentication are stored).
- **Found by the new tests:** `instanceof APIError` missed some of the provider's errors, because it throws APIErrors
  from more than one module copy. Detection now uses Better Auth's `isAPIError`.
- **Issuer:** an expired ID token now has its own public reason, `subject_token_expired`.
- **Each guard broken once:** three new mutations, all caught.

## D-010: `act` accepted — found live against Okta Cross App Access (2026-10-06)

Okta's ID-JAG for an AI agent always carries `act: { sub: <the agent's Okta client id>, sub_profile: "ai_agent web_app" }`.
D-007 refused `act` (with `authorization_details`), so the receiver refused every Okta ID-JAG. `act` records who acts
on the user's behalf (RFC 8693 §4.1) and widens nothing, so the core now accepts it: an object with a string `sub`,
optional `sub_profile`, nested prior actors up to 4 deep, anything else `invalid_claim`. The receiver carries it into
the access token as `act`, so the resource server sees that an agent acts for the user. `authorization_details` stays
refused (the draft says it MUST be processed; nothing sends it yet). `buildIdJag` may now mint `act`; our issuer
doesn't yet (it has no agent identity to name). After the fix, the whole flow passed live: `docs/interop.md`.

## D-011: Phase 2 merged (2026-10-06)

- **Issuer** (`docs/tracks/issuer.md`, D-B14–D-B21):
  - **Refresh tokens this provider issued** are accepted as subject tokens. They must belong to the authenticated
    client, not be revoked or rotated, carry no sender constraint, include `openid`, and be unexpired. The exchange
    never touches the stored token.
  - **"Revoke" is replaced by blocks:** user, client and/or audience, with an optional expiry, checked first on
    every exchange, with their own admin endpoints. A block stops new ID-JAGs at once; ones already issued live out
    their 5–15 minutes.
  - **Core change requests 4–6 made:** `REFRESH_TOKEN_TOKEN_TYPE` in `urns.ts`, a non-public `blocked` reason, and
    `block` as an admin-event target (`revoke` and `jti` removed).
- **Receiver** (`docs/tracks/receiver.md`, D-A18–D-A22):
  - **JIT adds organization membership** with the sso row's `organizationProvisioning` role, or `jitRole`. It's
    only done at creation and is idempotent. A failed membership deletes the new user and refuses the grant.
  - **`requireResourceClaim`** (default off) refuses an ID-JAG without `resource`, as the public `missing_claim`,
    before trust.
- **Interop** (`docs/interop.md`):
  - **Verified:** our issuer → our receiver (in CI), → Keycloak 26.8.0, → node-oauth2-server PR #462; **Okta
    Cross App Access → our receiver live**.
  - **Not possible yet:** Authelia (no release ships ID-JAG).
  - **Weekly CI:** `.github/workflows/interop.yml`.
- **Examples:** `examples/workers/`: an enterprise IdP and an MCP server on Workers and D1, verified over HTTP on
  deployed Workers. They are up on the demo account through Phase 2.
- **Merge:** one conflict (both sides appended to `test/mutations/receiver.json`); kept both.

## D-012: `cnf` refused; the ID-JAG's `iss` from the provider's getIssuer (2026-10-06) — implementation choices, from a review note

Two gaps, found by reviewing an external reference note on ID-JAG for Better Auth.
- **`cnf` (draft §9.8.1.2).** An ID-JAG bound to a key must be refused unless the client presents a matching DPoP
  proof, which is a MUST. We ignored `cnf`, so a key-bound ID-JAG got a plain bearer token, stripping the binding the
  IdP asked for. Until DPoP is supported, `cnf` is refused like `authorization_details` (public `unsupported_claim`),
  and `buildIdJag` won't mint it.
- **`iss`.** The issuer computed `iss` as `jwt.issuer ?? baseURL`, a copy of the provider's logic without its
  normalisation. It now uses the provider's own `getIssuer()`, the function that publishes `issuer` in the RFC 8414
  metadata. Authelia shipped this trap and fixed it (authelia/oauth2-provider#834).
  - **Found while fixing it:** `getIssuer()` normalises (https, no trailing slash) but the provider signs its ID
    tokens with the raw value. So our own ID tokens are verified against the raw issuer, while the ID-JAG carries the
    metadata's normal form. A test covers a trailing-slash `jwt.issuer`.
- **Evidence:** each guard broken once, three new mutations, all caught. 594 tests pass, plus two new ones per
  runtime.

**Also from that note, decided by the maintainer:**
- **Version 0.1.0** ships both plugins, with the issuer marked **experimental**.
- **Better Auth issue #8023** (token exchange in core, open, assigned) gets a comment, drafted for approval and
  **not posted**.

**Decided by the maintainer:**
- **Single use stays, with no reuse option** (oauth-wg issue #130). Every receiver tested (Keycloak, node-oauth2-server,
  Authelia's library) enforces single use too. The README must state this position and link #130.
- **The #8023 comment is on hold.** The draft needs work, and as written it would commit us to building things. It is
  not to be posted, or reworked into a commitment, without the maintainer.

## D-013: Better Auth's substantive lint rules adopted; its formatting not (2026-10-06) — the maintainer agreed

Checked against Better Auth's own `biome.json`.
- **Adopted** in `biome.jsonc`:
  - `noFloatingPromises` and `noMisusedPromises`: unawaited or misused promises hide bugs in the JWKS cache and the
    audit path.
  - `useNodejsImportProtocol`.
  - `Buffer` refused under `src/**` (`noRestrictedGlobals`): Workers don't have it without `nodejs_compat`. Node-only
    test helpers may use it, as Better Auth scopes the rule to package source.

  Our code already met them: there was one finding, `if (entry.inflight)` on a promise-or-null in
  `src/receiver/jwks.ts`, now `!== null`. Both rules were shown to fire on a probe file.
- **Not adopted:** tabs, `import * as z from "zod"`, separated `import type` lines. They would churn every file, and the
  siblings (whose conventions this repository follows) use 2-space indentation and `import { z }`.
  They only matter for code going upstream, which would be written in Better Auth's repository through its own
  formatter.
- **No Lefthook.** CI already enforces lint, typecheck, tests and the secret scan on every push.
- **If an upstream PR ever happens** (the maintainer's call; none planned):
  - Conventional Commits, with a lowercase subject and `!` for breaking changes;
  - a changeset for anything under `packages/**`;
  - `main` for non-breaking changes, `next` for features and breaking changes;
  - Better Auth's AI policy: whoever submits must understand the change well enough to discuss it.

## D-014: Phase 2 review — response (2026-10-06)

An independent review at `de31e58` gave a conditional go. It re-ran the suite, CI, the live demo and the Okta audit
rows, and reproduced five defects with probe tests.

**Defects**, all being fixed, receiver and issuer in parallel; D-A23… and D-B22… record the evidence:
1. **Email fallback could link an ID-JAG to an unverified local account (security).** It now requires the local
   user's `emailVerified`.
2. **Concurrent first use** could leave two account links and every later grant an empty, unaudited HTTP 500 (on D1).
   Resolution must converge on one link, and never escape as a 500.
3. **Stale JWKS keys were used indefinitely while the IdP's JWKS was unreachable.** New `jwks.maxStaleSeconds`,
   default 3600.
4. **An ID token kept minting ID-JAGs after sign-out (up to its 10-hour lifetime).** New `maxIdTokenAgeSeconds`,
   default 3600; older sign-ins use the refresh token. This is an implementation choice over
   documentation-only, raised with the maintainer.
5. **"Block from a jti" stopped working when the jti row was swept.** It now falls back to the audit row.

**Claims that didn't hold, corrected:**
- **The mutation and interop workflows had never run.** Both dispatched by hand on 2026-10-06; see their runs.
- **The npm name isn't reserved:** the placeholder was never published. The maintainer publishes it; the README no
  longer claims it.
- **README gaps:** the issuer wasn't marked experimental; the single-use position and oauth-wg #130 were missing; the
  receiver's check order was wrong; the CHANGELOG had nothing from Phase 2. All fixed.
- **Commits after the review pin:** `52bd35e` (README, SECURITY, CONTRIBUTING, threat model, templates) was separate
  docs work in the same checkout. `294efe1` is D-013.
- **The Okta agent secret:** the maintainer rotates it.

**The ten Phase 2 questions**, as the review recommended (the maintainer asked to proceed on its recommendations):
1. **Membership for existing users:** no (D-A19 stays).
2. **`jitRole`:** checked against the organization plugin's roles at startup; sso and table rows checked at
   provisioning.
3. **The membership write skips the organization plugin's hooks and `membershipLimit`:** accepted for 0.1, and
   documented as a limitation.
4. **No membership while an invitation is pending:** kept.
5. **Sender-constrained refresh tokens:** deferred until DPoP.
6. **`openid` required on refresh-token subjects:** kept; revisit in Phase 3.
7. **Blocks get their own option** before 0.1.
8. **A block doesn't revoke refresh tokens** in 0.1: a block can expire, a revocation can't.
9. **The Okta secret:** rotated now.
10. **The demo Workers:** kept through the next Okta session, then decided.

## D-015: the Phase 2 review's defects fixed (2026-10-06)

Each test was written first and seen to fail.
- **Receiver** (`docs/tracks/receiver.md` D-A23–D-A26):
  - **Email fallback:** requires the local user's `emailVerified`, and never falls through to JIT.
  - **Concurrent first use:** converges on one link (oldest row wins, losers delete their own rows), and never
    escapes as an HTTP 500. Shown under a barrier that forces the race on Node, and on D1.
    - **Remaining gap:** JIT for one `sub` with *different* emails, in an unlucky order, can leave two users. It
      stays deterministic and error-free.
  - **`jwks.maxStaleSeconds`** (default 3600).
  - **`jitRole`:** checked against the organization plugin's roles at startup, and at provisioning for sso and table
    rows.
- **Issuer** (`docs/tracks/issuer.md` D-B22–D-B25):
  - **`maxIdTokenAgeSeconds`** (default 3600; `subject_token_expired`). Its 3600 s default is an implementation
    choice, to be confirmed by the maintainer.
  - **`sid`:** an ID token that carries one is refused once its session has ended. Oauth-provider 1.7.6 sets `sid`
    only for clients with end-session or back-channel logout.
  - **Block from a jti:** falls back to the `id-jag.issued` audit row once the jti row is swept, with an explanatory
    404 otherwise.
  - **`blocks: { canManage }`** is separate from `registry.canManage`. **Breaking before 0.1:** blocks routes no
    longer mount from the registry option.
  - **Open:** the audit route accepts either `canManage`.
- **Evidence:** 668 tests pass (334 per runtime). The mutation lists exit 0: receiver 121 (117 caught, 4 expected),
  issuer 141 (133 caught, 8 expected), each reason recorded in the list. Typecheck and lint are clean. The demo Workers
  were redeployed, and the scripted flow passed afterwards.

## D-016: Phase 3 decisions (2026-10-06) — the maintainer's

On the Phase 3 design:
1. **Both SAML paths:**
   - **(a)** assertion → ID-JAG directly;
   - **(b)** assertion → refresh token (draft -04 §4.5, RFC 8693, what Okta and the MCP extension use), then the
     existing refresh-token path.
   - They share one verifier.
2. **The SP-to-client mapping** lives on the SAML IdP's SP configuration (`tokenExchange: { clientId }`).
3. **A failed record at SAML sign-in** doesn't fail the sign-in; that assertion just isn't exchangeable.
4. **The SP's `authorize()` hook** isn't re-run at exchange.
5. **The sign-in session must still be alive at exchange,** where sessions are in the database.
6. **Minting `sub_id` at our issuer** is deferred until a receiver needs it.

Also confirmed:
- **`maxIdTokenAgeSeconds`** defaults to 3600.
- **The audit route** stays open to either `canManage`.
- **The `better-auth-saml-idp` side** (the SP opt-in, the record at issuance, `verifyIssuedAssertion` and its 1.2.0
  minor release) is built in that repository by its maintainer. This repository builds against the interface agreed between the
  two.

## D-017: SAML, verified end to end across the two repositories (2026-10-06)

`test/interop/saml-idp-e2e` (its own project, one Better Auth via pnpm overrides) ran a real SAML sign-in at
better-auth-saml-idp `feat/assertion-exchange` (`2d54cb4`, the D-071 assertion exchange, unreleased) with this
repository's main. **17/17 passed:**
- **Path (b):** the Assertion → a refresh token (`issued_token_type` refresh_token, `token_type` N_A, 30-day
  `expires_in`) → an ID-JAG (verified against the IdP's JWKS; `sub` = the SAML user; `client_id` = the agent's id at
  the MCP AS) → an access token audience-bound to the resource, with no refresh token.
- **Path (a):** the Assertion → an ID-JAG directly → an access token.
- **Replays:** refused on both paths.
- **Tampering:** a tampered Assertion is refused and doesn't burn the real one (consumed only after the signature).
- **Another client** presenting the agent's Assertion is refused and doesn't consume it.

**The refusals seen** were only the non-public `replay` and `invalid_subject_token`, one generic body.

**Remaining for Phase 3:** the live xaa.dev SAML run and the Okta SAML run (the maintainer), the 1.2.0 release of
better-auth-saml-idp (the maintainer), a Phase 3 review, and the Phase 3 note.

## D-018: package checks (Phase 4 groundwork) (2026-10-06) — implementation choice, as the siblings

- **TypeScript 7.0.2 is the compiler**, with **5.9.3 kept as `typescript-5`**. The whole repository typechecks
  clean under 7.
- **`pnpm pack:check`** runs in CI and in the release job: the dist build, then `test/types/strict-host.ts` (a host
  with `exactOptionalPropertyTypes`, compiled against `dist/` under TypeScript 7 **and** 5.9), then
  `publint --strict` and Are the Types Wrong (`--profile esm-only`).
- **The strict-host test found a real consumer defect on its first run.** The receiver's option types (`StaticTrustedIssuer`
  and the rest of `src/receiver/options.ts`) didn't accept `undefined` for optional fields, so a host passing its own
  optional value (for example `organizationId: maybeOrg`) failed to compile. Every optional option field now
  accepts `undefined`, as the issuer's already did.
- **The results:** publint "All good"; Are the Types Wrong green for ESM and bundlers on `.` and `./client`.
- Dependabot's TypeScript 7 PR is superseded by this. Closing it on GitHub is the maintainer's action.

## D-019: the adapter matrix (Phase 4 groundwork) (2026-10-06) — implementation choice, as the siblings

`test/adapters/matrix.adapters.test.ts`, in CI's `adapters` job (a new job; the siblings' images and setup):
- **Databases:** Postgres 17, MySQL 8.4, MongoDB 8.2 (a replica set), Drizzle on Postgres and on MySQL, and Prisma 7
  on Postgres.
- **What it tests:**
  - the jti unique key, with 10 concurrent records across two instances (exactly one wins), then a replay;
  - the jti and audit sweeps' date comparisons;
  - concurrent first use, JIT and email fallback, converging on one user and one link with no 500.
- **Not in the matrix:** D1 and SQLite, which run the whole suite in the test job.
- **Result:** run locally against each database in Docker, **4/4 on all six**.

**Fixed in the test harness:** the ORM schema builder (copied from better-auth-scim-provisioning) declared Better Auth's
`string[]` and `json` fields as `text`, where Better Auth's migrator creates `jsonb` on Postgres. That broke the
oauthClient table, which the sibling never had. They're now `jsonb` (Drizzle) and `Json` (Prisma).

**Upstream, not ours (for the maintainer; nothing reported):** on MongoDB, creating an OAuth client with
`@better-auth/oauth-provider` 1.7.6 inside the adapter's transaction fails at commit on an empty database. The
adapter's `abortTransaction` after a failed commit then masks the real error. Once the collections exist, it hangs. No
ID-JAG code is involved: it happens in the test's own client registration. The matrix runs MongoDB with
`transaction: false`; our code uses no transactions, and the unique keys under test are MongoDB's indexes. Worth an
upstream issue, drafted for approval, after a minimal reproduction.

## D-020: better-auth-saml-idp 1.2.0 (2026-10-06)

The maintainer released better-auth-saml-idp **1.2.0** (assertion exchange, unchanged from `2d54cb4`; npm, with SLSA
provenance).
- **Peers:** this package lists `better-auth-saml-idp >=1.2.0 <2` as an **optional** peer, with `@better-auth/mcp`
  and `@better-auth/sso` (`>=1.7.5 <1.8.0`), also optional. None is imported at runtime: the SAML IdP is detected
  through the plugin context, and mcp and sso by plugin id.
- **The cross-repository test** (`test/interop/saml-idp-e2e`) now installs 1.2.0 from npm. Every check passes
  against it.
- `pnpm pack:check` is still clean with the new peers.

## D-021: audit overrides (2026-10-06)

The Dependencies workflow's runtime audit failed on `96d138d`. Declaring `better-auth-saml-idp` as an (optional) peer
(D-020) let pnpm install it with Better Auth's own optional peers (Prisma, mysql2), which brought `deepmerge-ts` <8
(GHSA-ggr8-5vv4-36mx, high) and `mysql2` <3.23.1 (two advisories) into what `pnpm audit --prod` counts. None of them is
shipped by this package.

The fix is the same pnpm overrides as better-auth-scim-provisioning: `deepmerge-ts@<8.0.0 → ^8.0.0`,
`mysql2@<3.23.1 → ^3.24.5`, and, for development, `sharp@<0.35.5 → ^0.35.5` (librsvg advisory, through Miniflare).
`pnpm audit` is now clean at every level, and the tests pass on both runtimes. These overrides should be revisited
when Better Auth or Miniflare move to patched versions (the siblings' upstream-watch does this; ours has none yet).

## D-022: the Phase 3 review's findings (2026-10-06)

The review of `95d46f0` against `de31e58` found two defects, two test gaps and a hardening idea; all are fixed with a
test that fails first and a mutation entry each, all caught.

1. **One `events` object for both plugins failed at startup.** The receiver's options schema is strict and didn't list
   the core's `onRefreshIssued` (D-B31 left it out without weighing this). It is now accepted and never called;
   `test/merge/both-plugins.test.ts` passes one handlers object to both plugins.
2. **The issuer's audit route couldn't filter on `id-jag.refresh-issued`** (a 400). Added to the enum; the registry
   test requests every type.
3. **Nothing pinned "the SAML verifier gets the authenticated client, never the body's `client_id`".** The code was
   right, and the case is reachable: the provider authenticates Basic credentials and ignores a `client_id` in the
   body. New test on both paths (Basic as another client, the mapped client's id in the body: `WRONG_CLIENT`, not
   consumed), two mutations, and the cross-repository end-to-end test now forges the body id on both paths.
4. **Path (b)'s provider-scope bound was untested when the client lists scopes.** New test (a client registered with
   a scope the provider later withdrew).
5. **Hardening:** the ID token's `sid` session must also belong to the token's `sub`. The signature already binds
   them; this is defence in depth, as better-auth-saml-idp does it.

Docs: the README states the npm placeholder plainly, and says what a path (b) refresh token is: an ordinary provider
refresh token, usable at `grant_type=refresh_token` within its scopes, with no consent row, which a block doesn't stop
(revoke it). `docs/security.md` covers both SAML paths, `sub_id`, and the known gaps; the CHANGELOG has the Phase 3
entry.

## D-023: the live evidence session (2026-10-06)

Okta Cross App Access (the lifecycle checks A1–A7) and xaa.dev's resource-app tester (OIDC and SAML), against the
example Workers. Every check passed; the details are in [docs/interop.md](docs/interop.md). What it established
that tests couldn't:

- **The enterprise controls are the IdP's, and they work:** Okta refused the exchange when the connection was
  off, the scope wasn't granted, the audience wasn't connected, the user was unassigned or deactivated. Our
  receiver adds the checks that are its own: single use (`replay`) and the client (`client_mismatch`, met in
  the wild when Okta's connection carried the wrong client id).
- **The account-takeover protection holds against a real third-party IdP:** xaa.dev asserting an email already
  linked to an Okta user was refused (`unknown_subject`), not linked.
- **SAML `sub_id` resolution works with a real IdP's claim:** xaa.dev's `sub_id` matched a `samlSubjects`
  mapping, and the user resolved through it alone.
- **Interop requirements for browser testers** (CORS, `client_secret_post`, MCP's Streamable HTTP) are the
  example's to meet, not the package's; the example Worker now meets them (opt-in CORS, a minimal MCP endpoint).

Not changed: no package code. A demo-database client was switched to `client_secret_post`, and one NameID link
was made by hand, as an operator would. The xaa.dev tester's client secret is rotated afterwards.

## D-024: Socket Firewall, and a wait before taking new versions (2026-10-07)

The siblings' standard (better-auth-saml-idp D-073, better-auth-scim-provisioning), the reviewer's "where id-jag
falls short" list, and the maintainer's request.

- **Socket Firewall** (`sfw`, the free edition, `SocketDev/action` pinned by SHA, `mode: firewall-free`) wraps
  every dependency install: the `ci.yml` jobs, `scripts/use-better-auth.sh` (it installs fresh Better Auth
  versions in the latest-1.7 row), the interop and mutation workflows, both `pnpm install` steps of the release,
  and the `npm ci` of the npm CLI in the publish job, which holds the identity that can stage a version. It
  refuses packages Socket has confirmed as malware before they download; suspected ones get a warning.
- **A minimum release age:** pnpm 10.34.6 (was 10.10.0) with `minimumReleaseAge: 1440` in a settings-only
  `pnpm-workspace.yaml`, Better Auth exempt; Dependabot `cooldown: { default-days: 3 }` on every entry. Lockfile
  installs are unchanged. `test/interop/saml-idp-e2e` (its own lockfile) still installs and passes.
- **Risk accepted:** a Socket outage or a false positive blocks CI until resolved.

## D-025: the external pre-release review (2026-10-07)

A deep review of `21326cb`: "ship 0.1.0, after two one-line doc fixes". Nothing lets an attacker obtain a token as
the wrong user, for the wrong resource or scope, or replay one. Its run: 870 tests, the SAML end-to-end test (19/19)
and all three mutation lists (402 caught, 15 expected survivors, 0 problems). Its findings, all fixed:

1. **Low: one refused request per minute during a JWKS outage.** Past the cache TTL, the request that triggered the
   refetch was refused (`jwks_unavailable`) when the fetch failed, although the cached keys were within
   `maxStaleSeconds`; only the following requests got them. Now that request gets the cached keys too, and the
   failure goes to the host's logger as a warning (`JwksCache.keysFor`'s `onStaleRefetchError`). Past the stale
   window it is refused as before. Tests rewritten failing-first; three new mutations, three updated.
2. **Low: `trustEmailVerified` described as reading `email_verified`.** No such claim is read: the new user's
   email is marked verified on the trusted issuer's word. `docs/security.md` and the option's comment say so.
3. **Low: the issuer's audit filter couldn't select `id-jag.accepted`** (both plugins share one audit table). The
   allowed types now come from the core's event map (`AUDIT_EVENT_TYPES`), so they can't drift again.
4. **Info: the public API is wide** (105 exports, internals included). Fine for 0.x; trim before 1.0 (agenda).

Also from the review: the Mutations workflow runs its three lists in parallel (a matrix), and it is dispatched at
the release commit so a green run is on record.

## D-026: the repository public; its settings and the first scans (2026-10-07)

The maintainer made the repository public. Settings, matched to better-auth-saml-idp: private vulnerability
reporting, Dependabot alerts and security updates, **secret scanning with push protection**, merged branches
deleted, and an **`npm` environment** (the maintainer as required reviewer, deployments only from `v*` tags). The
private-repository gates came out of CodeQL, Scorecard, dependency review and OSV; they had also skipped the weekly
CodeQL and Scorecard runs (a scheduled event carries no repository).

The first scans:
- **CodeQL, two `js/polynomial-redos` in shipped code**, neither reachable: `decodeSaml2SubjectToken` strips padding
  only after a pattern that allows at most two `=`; `openIdConfigurationUrl` sees only configured or stored issuers.
  Both now strip trailing characters with a loop, and a test pins the URL helper's linear time.
- **CodeQL, dismissed with reasons:** the link checker's HTML stripping (a slug, never rendered), the demo CLIs
  saving the user's own tokens to a file they name, the interop job's commit-pinned `npm install`.
- **Scorecard, Vulnerabilities:** the 12 advisories in npm's bundled dependencies (`.github/npm-cli`, release job
  only), already dismissed in Dependabot. `.github/npm-cli/osv-scanner.toml` ignores them, each with a reason and an
  expiry (2027-01-06), as in better-auth-saml-idp.
- **Scorecard, left to resolve:** Maintained (the repository is new), SAST (CodeQL has just started), Branch
  protection and Code review (a ruleset, the maintainer's decision), CII Best Practices (the badge, registered by the
  maintainer at bestpractices.dev).

## D-027: SCIM-provisioned users at the receiver (2026-10-08) — the maintainer asked for it now

The shape agreed with the better-auth-scim-provisioning maintainer on 2026-10-06 (`docs/phase-2.md`, "After Phase 3"),
built straight after 0.1.0. It should have been flagged as unbuilt before the release; it wasn't.

- **The option.** A trusted issuer (static or table) gets `scim: { connectionId, required? }`. The ID-JAG's `sub` is
  the SCIM `externalId`: our issuer's `sub` is the IdP's user id, better-auth-scim-provisioning's default `externalId`.
- **The lookup is Better Auth's.** `@better-auth/scim`'s `acquireActiveSCIMUserLink({ connectionId, externalId: sub })`
  finds the user that connection provisioned while the SCIM user is active, the connection isn't decommissioned and
  no deletion tombstone exists; it never falls back to email or userName. It is **passed in**
  (`idJagGrant({ scim: { acquireActiveSCIMUserLink } })`), not imported: a dynamic import of an optional peer breaks
  bundling (Workers) for hosts without it. An entry with `scim` and no function, or no `scim` plugin, fails at startup;
  a table row with `scimConnectionId` and no function is refused at runtime (fail closed).
- **Where.** After the `resolveSubject` hook, before the account, email and JIT steps. A user found by SCIM is still
  refused when banned locally. **Required by default:** none found is `unknown_subject`, so a deprovisioned user can't
  return through an older account link, the email fallback or JIT. `required: false` falls through (a migration aid;
  documented that a deprovisioned user linked by `sub` is then found). SCIM-found users are not linked by `sub`.
- **Transactions.** The function bumps the SCIM subject's revision (optimistic), so it runs in
  `adapter.transaction`; a 409 SCIM conflict (a concurrent lifecycle change) is retried once, then `subject_rejected`.
  Any other error is the usual audited `subject_rejected`. **`@better-auth/scim` refuses adapters without native
  transactions**, so this works on Postgres, MySQL and SQLite (Drizzle and Prisma with `transaction: true`), not D1.
- **Audit:** `id-jag.accepted` gains `resolvedBy` (`hook`, `scim`, `account`, `email`, `jit`).
- **Evidence.** `test/receiver/scim.test.ts` against the real `@better-auth/scim` 1.7.6 server, users provisioned
  over its SCIM API: active, unprovisioned, deactivated and reactivated, deleted, another connection, banned locally,
  `required: false`, the conflict retry, other errors, table rows, startup checks (Node; skipped on workerd, which
  can't run the SCIM server). The adapter matrix: Postgres, MySQL, Drizzle (both) and Prisma. The cross-package test
  `test/interop/scim-provisioning.test.ts`: better-auth-scim-provisioning 1.0.0 at the IdP, our issuer, `@better-auth/scim`
  and our receiver: provisioned → resolved by SCIM; banned or deleted at the IdP → an ID-JAG issued before is refused;
  unbanned → the same user. Fourteen mutations: 13 caught, 1 expected survivor (a race guard; reason recorded).
- **Independent test** by the better-auth-scim-provisioning maintainer at `c9a38e9`, from the packed tarball with
  their 1.1.0 and only public entry points, through the real sign-in → code → ID token → exchange → jwt-bearer flow,
  three runs: 14 scenarios passed, no defects. Among them: another connection's or another IdP's user with the same
  externalId never matches; an organization-scoped target (member, added, removed); a `mapUser` overriding
  `externalId`; a same-email unprovisioned local user with the email fallback and JIT on (refused while required);
  20 users deprovisioned while redeeming concurrently (200s before delivery, 400s after, never a 500); an old
  account link not bringing a banned user back. Their mutations on our built `dist` (the SCIM step skipped,
  `required` ignored) were caught. Two notes became README lines: SCIM-created users have `emailVerified: false`
  (so the email fallback never matches them), and the fallbacks need the issuer to send `email`.

## D-028: the fresh-eyes review of the SCIM step (2026-10-08)

A review of PR #8 at `7dd6289`: "merge and release 0.2.0 after one low finding". A deprovisioned, wrong or
unprovisioned user can't get a token through the SCIM step, and hosts without `scim` are unchanged (the built bundle
doesn't import `@better-auth/scim`). Its run: 890 tests, the 14 D-027 mutations as recorded, PR CI green.

1. **Low: the SCIM step ran before the `sub_id` rules.** On an entry with both `scim` and `samlSubjects`, a
   provisioned user was accepted with no `sub_id` under `requireSubId`, a malformed one, or an unmapped SAML issuer's
   (three documented refusals). Not a wrong user (SCIM maps the trusted issuer's `sub`), but the refusals must hold.
   Fixed by computing the subject key, which applies those rules, before the SCIM step; combined entries keep
   working. A test (fails before the fix) and a mutation that restores the old order.
2. **Info:** the hook's `trustedIssuer` view now has `scimConnectionId`, so a hook can tell its `link` overrides SCIM.
3. **Info:** the README's sentence on the table's columns rewritten.

Also, after the review (from the better-auth-scim-provisioning maintainer): their 1.1.0 is published, but our
minimum release age (D-024, one day) holds the end-to-end test on 1.0.0 until it is a day old; and the README says how to run the SCIM step on Cloudflare (Postgres through Hyperdrive, verified locally
under wrangler dev only; harness `~/Infowall/backups/hyperdrive-scim-test-2026-10-07/`).

## D-029: SCIM lookups of one user conflicting with each other (2026-10-08)

Found after 0.2.0 was tagged and staged (not yet approved on npm), by the better-auth-scim-provisioning maintainer on
a deployed Worker with Neon Postgres through Hyperdrive, then reproduced on Neon from Node, and here on Postgres 17:
8 parallel redemptions for one active, untouched user got 2–3 tokens; every refusal was "SCIM: the provisioned
identity changed concurrently".

- **Cause.** `acquireActiveSCIMUserLink` takes the link with an optimistic `incrementOne` on `scimSubject.revision`
  on every lookup. Lifecycle changes bump the same revision, which is the point (D-027), but so does every other
  lookup: readers conflict with readers. D-027's single retry without delay assumed conflicts were rare lifecycle
  races. node:sqlite runs one transaction at a time, so the unit tests couldn't see it; Postgres and MySQL run them
  concurrently.
- **Fix.** Retry a 409 from fresh state with exponential backoff and full jitter (random within
  [0, min(250, 10·2ⁿ)] ms), for up to `SCIM_RETRY_BUDGET_MS` (5 s) or `MAX_SCIM_ATTEMPTS` (40), then refuse as
  before. A deprovisioning makes the next attempt return null, so only racing readers keep retrying; the budget is
  how many arrive at once. Ten attempts weren't enough for 32 at once on MySQL; the time budget is.
- **Evidence.** The adapter matrix's SCIM test redeems 16 at once for one user (`SCIM_PARALLEL`), asserting all
  succeed: before the fix 3 of 8 on Postgres; after it, Postgres, MySQL, Drizzle and Prisma pass, and 16 and 32 at
  once pass repeatedly on Postgres and MySQL. Unit tests: a few conflicts then accepted; endless conflicts refused
  within the budget. Mutations: no retry and no bound are caught; no backoff is an expected survivor (only real
  concurrency shows it; the matrix does).
- **Considered.** A row lock (`SELECT … FOR UPDATE` on the subject) would serialize lookups instead, but the adapter
  has no locking API, so it means raw SQL per dialect. Upstream, a non-mutating lookup (readers not conflicting with
  readers) would remove the hotspot: an issue draft for the maintainer's approval.
- **0.2.0** is not approved on npm; 0.2.1 replaces it. Also from that test: Hyperdrive's default query cache kept a
  revoked Better Auth session valid for about a minute; the README now says to disable caching for the auth database.

## D-030: one in-flight SCIM lookup per user (2026-10-08)

The better-auth-scim-provisioning maintainer ran D-029's fix against Neon Postgres 45 ms away (median): 8 at once
8/8, but 16 at once 12–14/16 and 32 at once 10–12/32, the slowest after 5–7 s, whatever the pool size. Lookups of
one user commit strictly one at a time (each bumps the same revision), about 8–10 round trips each, so about two a
second at that distance: a 5 s budget yields 10–12 whatever the fan-out. Locally (under 1 ms) 32 fit, which is why
the matrix passed. A row lock wouldn't raise that throughput either.

- **Single-flight.** Concurrent requests for the same (connection, externalId) on the same database adapter share
  one in-flight lookup; the entry is removed when it settles, so a later request always looks up again (a cached
  answer would miss a deprovisioning). The shared answer is no staler than if the request had arrived a moment
  earlier. On one Node server this removes same-user contention; on Workers, within each isolate.
- **The retries stay** (D-029) for lookups across processes.
- **The limit is documented:** lookups of one user commit one at a time across processes; keep the auth server
  near its database. The real fix is upstream (a lookup that doesn't conflict with other lookups): an issue drafted
  for the maintainer's approval.
- **Evidence.** A unit test with a 30 ms lookup (node:sqlite otherwise answers at once, so lookups never overlap):
  8 at once all succeed with fewer than 8 lookups, and a later one looks up again. Two mutations (no
  single-flight; a settled lookup kept) caught.
- **On Neon** (the better-auth-scim-provisioning maintainer, `bc85fd6`, 45 ms away, 3 runs each): one receiver,
  8/16/32 at once all succeeded, the slowest 0.9 / 1.4 / 1.9 s (a single redemption takes 0.84–0.95 s); two
  receivers on the same database, requests alternating, all succeeded too, the slowest 1.5 / 1.5 / 1.9 s. Before:
  3/8; with D-029 alone 8/8 at 5.2 s and 11/32.

## D-031: the public API as an explicit list (2026-10-08) — the maintainer's

Both pre-release reviews noted that the package re-exported everything (106 runtime names, 71 types) while
`docs/versioning.md` declared every export public, so 1.0 would have frozen the internals. The maintainer approved the
proposal: keep 52, remove 54 (`private/exports-proposal.md`).

- **Kept:** the plugins and the composition layer (the escape hatch and a future grant router depend on it), the
  tables, the protocol constants and documented defaults, `REASONS` and the events, and a small toolkit
  (`parseIdJag`, `verifyIdJag`, `buildIdJag`) in the main entry point, not a new `/core` one. `BlockConfig` stays
  public (the admin API's block input), and the SCIM option types, missing in 0.2, are added.
- **Removed:** audit, error and replay plumbing, JWT and SAML internals, issuer and receiver internals, including
  `IdJagRefusal` (it never leaves the package) and `publicDescription`.
- **Why now:** published two days ago; the README, the examples and the sibling packages use only kept names.
  Breaking, so 0.3.0, with every removed name in the CHANGELOG; adding one back is never breaking.
- **Evidence:** `src/index.ts` lists exactly the API; `test/api/public-api.test.ts` pins the 52 names (on both
  runtimes); the strict-host types and Are the Types Wrong pass, so every kept signature names only public or
  declared types; the full suite passes.

## D-032: layered permissions in the demo, and a draft watch (2026-10-08)

The layers README "What ID-JAG controls" describes, shown on the deployed example rather than only written down
(the solo part of the planned "session 2"; the Okta part needs the maintainer).

- **The IdP** (`enterprise-idp`): `read` for everyone, `write` only for `WRITERS`. **The MCP server**: a scope per
  tool (`add_note` needs `write`), a 403 `insufficient_scope` challenge naming the scope, agents (`act`) read-only
  unless `AGENTS_MAY_WRITE`, and `accessTokenExpiresIn: 300` with `scopeExpirations: { write: "2m" }`.
- **Measured on the deployed demo:** the writer's agent got `read write`, a 120 s token, `add_note` 200; the reader's
  asked for `read write` and got `read`, a 300 s token, `add_note` 403. With `--cutoff`, the tokens stopped working
  125 s and 305 s after issue (polled every 10 s). No package change was needed: these are host settings.
- **Still to do with the maintainer (Okta):** different scopes per Okta group on the resource connection, if Okta
  supports it; the `act` rule with Okta's agent tokens (our issuer doesn't mint `act`); a cutoff timed through Okta.
- **Draft watch:** `scripts/draft-watch.mjs`, weekly (`.github/workflows/draft-watch.yml`), fails when the
  datatracker lists a newer revision than `SUPPORTED_DRAFT`, and warns 30 days before the implemented one expires.
  2026-10-08: -04 is the latest, expiring 2026-11-22.

## D-033: how the person signed in: copied, never derived (2026-10-10)

From the Microsoft 365 findings of a sibling deployment (2026-10-08 to 2026-10-11), approved by the maintainer as
docs and tests only.

- **What we found in our own code:** the issuer copies `auth_time`/`acr`/`amr` from the subject token. oauth-provider
  1.7.5 and 1.7.6 write `acr: "0"` into every ID token, never `amr`, and strip both from `customIdTokenClaims`; a
  refresh token carries neither. So an ID-JAG from those paths never claims MFA. Only path (a), a SAML Assertion, can
  (its AuthnContextClassRef). The comment in `id-token.ts` said a host claim could override `acr`; corrected.
- **Docs:** `docs/security.md` "How the person signed in": copied, never derived; the SAML IdP states only what the
  session did, from its own second-factor marker (Microsoft 365 skips its own MFA on `multipleauthn`, verified live
  with per-user MFA and with Conditional Access); upstream Microsoft sign-in proves MFA only by a v1.0 token's `amr`;
  a rule requiring MFA treats a missing value as not proven, at the receiver in `resolveSubject` (the access token
  doesn't carry `acr`/`amr`). README points there from the issuer policy and the receiver's subject steps.
- **Evidence:** `test/issuer/exchange.test.ts` (a host's `acr`/`amr` are stripped; the ID-JAG says `acr: "0"`, no
  `amr`), `test/issuer/saml-subject.test.ts` (`multipleauthn` passes unchanged; no class, no `acr`),
  `test/receiver/grant.test.ts` (the documented `resolveSubject` rule: `mfa` passes; `["pwd"]`, none, `acr: "0"`
  refused). No runtime change.

## D-034: an Entra watch (2026-10-10)

The maintainer's request. Entra is expected to be the second production ID-JAG issuer after Okta, with no public
preview or date yet (its release notes, Microsoft's July 2026 MCP post and the MCP announcement were checked
2026-10-10).

- **`scripts/entra-watch.mjs`**, a second job in the weekly draft watch: fails when the MicrosoftDocs/entra-docs
  source of Entra's release notes names ID-JAG, the grant, Cross App Access or Enterprise-Managed Authorization.
  Exact names only, because "identity assertions" alone matches an unrelated External ID item. A match that has
  been looked at goes in `ACKNOWLEDGED`.
- **docs/interop.md:** a "not possible yet" row for Entra as issuer. Its on-behalf-of flow is jwt-bearer too but
  not ID-JAG; our receiver refuses those tokens by `typ`.

## D-035: MCPJam and identity-provider.net in the weekly interop (2026-10-14)

The maintainer's request: as much independent coverage of the receiver as early as possible. Until now its only
non-Okta evidence was our own issuer.

- **MCPJam** (`test/interop/mcpjam.test.ts`): its Cross App Access debugger is an independent client and IdP with a
  negative mode for each check a receiver must make. The test drives its engine, `@mcpjam/sdk`, pinned at 9.3.0 and
  installed outside the lockfile (as node-oauth2-server, Interop row 4), over real HTTP on 127.0.0.1, for OIDC and
  SAML: 24 tests. Each attack is asserted by our audit reason, not only by "refused". MCPJam's `expired` ID-JAG
  also lives 3600 s, so it exercises the lifetime cap, not `exp`; recorded rather than worked around. Its telemetry
  is off (`DO_NOT_TRACK`).
- **identity-provider.net** (`test/interop/zipidp.test.ts`): a free stub IdP for Cross App Access, independent of
  Okta and of us, and the first second issuer for #24 that needs no trial. Live: a fresh sandbox per run, every
  record deleted afterwards. It can fail because the service is down or changed its forms; it runs weekly, not on
  pushes, for that reason.
- **Probed but not added:** `@atlasauth/pca-idjag` 0.4.1 as a verifier of our issuer refuses every ID-JAG without
  `act`, which our issuer doesn't mint (D-036 changes that); with `act` it accepts ES256, RS256 and EdDSA.

## D-036: the issuer can send `act` (2026-10-14)

The maintainer's decision, after a probe on 2026-10-14: `@atlasauth/pca-idjag` 0.4.1's verifier refuses every
ID-JAG without `act`, and our issuer never minted one, while Okta always sends `act` for an AI agent
(`{ sub: <the agent's client id at Okta>, sub_profile: "ai_agent web_app" }`, docs/interop.md).

- **Opt-in, from the `authorize` hook only:** `claims.act`, `true` or `{ sub_profile }`. The issuer can't tell an
  agent from any other client; the host's policy can (client metadata, its registry of agents). The registry has
  no setting for it yet; with both sources, the hook's answer is used.
- **The actor is always the requesting client**, by its id at the IdP (as Okta's `act.sub`), while `client_id` stays
  its id at the resource (D-004). A policy can describe it (`sub_profile`, 1 to 256 characters, no control
  characters) but not name another actor: any other key, or a malformed value, is a malformed verdict
  (`policy_denied`). No nested `act` (a delegation chain): nothing asks for one yet.
- **Every subject path gets it** (ID token, refresh token, SAML), since all mint in one place (exchange.ts).
- **Evidence:** `test/issuer/exchange.test.ts` (none by default, `true`, `sub_profile`), `test/issuer/refusals.test.ts`
  (eight malformed values), `test/interop/self.test.ts` (our receiver carries it into the access token). Mutations:
  not minting it fails two tests; accepting extra keys fails one.
- **Not changed:** the example IdP doesn't send `act`. Its demo keeps agents read-only when `act` is present
  (D-032), so turning it on there changes the demo's documented results; a separate decision (D-037).

## D-037: the example IdP tells AI agents from apps (2026-10-14)

The maintainer chose this (option D of four) once the issuer could send `act` (D-036). Before, the example IdP never
sent `act`, so its demo agent could write, while Okta's agents, which always carry `act`, could only read (D-032).
Sending `act` for every client would have hidden the `WRITERS` layer (every write a 403). So:

- **The IdP's `/setup` takes `agent`**, stored in the client's metadata; the policy adds `claims.act` (`sub_profile`
  `"ai_agent"`) for those clients only.
- **`client.mjs --setup` registers two clients**, an AI agent and an app, each with its own client id at the MCP
  server. `--client=app` runs as the app; the default is the agent. Its pass check expects `add_note` 403 for an
  agent unless `AGENTS_MAY_WRITE=true` is mirrored in its environment.
- **Verified locally** under `wrangler dev` (both Workers, the service binding connected), 2026-10-14, all four runs
  passing their check: app + writer → `add_note` 200; agent + writer → 403 ("an agent (act) may only read here");
  agent or app + reader → 403 `insufficient_scope`. `act` = `{ sub: <the agent's client id at the IdP>, sub_profile:
  "ai_agent" }` in the ID-JAG and the access token. A fresh-eyes review found the first version of the script's
  check took "agent" from the token's `act`, so it passed even when the IdP named nobody; it now checks `act`
  against the role it plays and prints each failure (verified: an agent run without `act`, and a mismatched
  `AGENTS_MAY_WRITE`, both fail). Running the demo locally needed probe-only patches: the
  example's `/setup` registers an http redirect URI, which oauth-provider refuses for web clients on loopback, and
  the receiver takes only an https `jwksUri`. Making the example runnable locally is a separate decision.
- **Deployed** 2026-10-14 with the maintainer's go-ahead (a new `SETUP_KEY` on both Workers, then `--setup`): the
  four runs pass on the live demo, the writer's tokens 120 s, the reader's 300 s.

## D-038: no assumption about Better Auth's signing default (2026-10-14)

Issue #19. Better Auth 1.7's jwt plugin defaults to EdDSA; better-auth/better-auth#9935 (open, base `next`, breaking)
makes it RS256. The issuer assumed EdDSA in two places, which would break on that release.

- **Startup:** `signingAlgorithm` is checked against `keyPairConfig.alg` and `keyPairConfigs` only when
  `keyPairConfig.alg` is set. When it isn't, the host's algorithm is Better Auth's to choose, and Better Auth itself
  refuses a `signingAlgorithm` it can't mint a key for, at the first exchange.
- **Every ID-JAG:** after `signJWT`, the header's `alg` must be RS256, ES256 or EdDSA (S4), or the exchange fails with
  a server error naming the key's algorithm and no ID-JAG leaves. A misconfigured host can't issue ID-JAGs receivers
  would refuse, whatever Better Auth's default.
- **The host's own ID tokens (subject tokens):** a stored key without `alg` takes the configured `keyPairConfig.alg`
  when it fits the key type, else the key type's own (RSA → RS256, P-256/384/521 → ES256/384/512, Ed25519 → EdDSA),
  else it's refused (`key alg unknown`). Better Auth's own fallback (`?? "EdDSA"`) is not copied.
- **Evidence:** `test/issuer/startup.test.ts` (no default assumed), `test/issuer/signing-default.test.ts` (a host
  with no `keyPairConfig` signs ID-JAGs with its own key's algorithm, compared with its ID tokens, not hard-coded;
  RS256 from `keyPairConfigs`), `test/issuer/signing-unaccepted.test.ts` (a PS256 key: 500, nothing issued),
  `test/issuer/id-token.test.ts` (`keyAlgorithm` table; RS256, ES256, EdDSA and PS256 keys stored without `alg`).
  Mutations: restoring each EdDSA assumption fails 1, 1 and 3 tests.
- **Still to do for 1.8:** run the suite against the release that contains #9935 before widening the peer range
  (the upstream watch, #20).

## D-039: a weekly watch for upstream changes (2026-10-14)

Issue #20. Three Better Auth items change what this package does, and the peer range (`<1.8.0`) needs a deliberate
test-and-widen step, so a third job in the weekly draft watch (`scripts/upstream-watch.mjs`) fails when:

- better-auth/better-auth#9935 (the jwt default → RS256, ID-token authentication context; D-038) is merged or closed;
- #8023 (RFC 8693 token exchange as an official plugin) or #11267 (authentication context in access tokens) is closed,
  or a pull request in better-auth/better-auth linked to either is merged;
- npm has a `better-auth` or `@better-auth/oauth-provider` version at or above 1.8.0, pre-releases included: one
  finding per minor line, pre-releases apart from releases, so 1.8 betas fail once and 1.8.0 fails again.

Each finding prints its next step and a key; acknowledging the key (`ACKNOWLEDGED`, as the Entra watch) makes it green.
Public GitHub and npm APIs only; the workflow's token only raises the rate limit. Verified: green on 2026-10-14; a probe
copy pointed at a merged PR, a closed issue with a merged linked PR, and the 1.6/1.7 lines fails with one finding each.

