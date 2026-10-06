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

## D-006: The shared core (2026-10-05) — agent's choices

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

An independent adversarial review (a separate agent, read-only, reproducing each finding against a bundle of
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
  expires. Our receiver enforces strict single use (S3). The agent's choice is to keep strict single use and document
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
Merge-time changes by the orchestrating session: `src/index.ts` exports the core, issuer and receiver;
`better-auth-id-jag/client` exports the issuer's client plugin; the build script rewrites nested and directory
declaration imports for NodeNext consumers (it only handled top-level files); `.claude/` (agent worktrees) is ignored;
`test/merge/both-plugins.test.ts` proves both plugins on one host share one jti table and one audit table. Evidence,
the agents' decisions to review, the open questions and the core change requests: `docs/phase-1.md`. Phase 2 does not
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
- **The agent worktrees** are removed.

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

## D-012: `cnf` refused; the ID-JAG's `iss` from the provider's getIssuer (2026-10-06) — agent's choices, from a review note

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
  siblings (whose conventions this repository follows, per the handoff) use 2-space indentation and `import { z }`.
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
   default 3600; older sign-ins use the refresh token. This is the orchestrating session's choice over
   documentation-only, raised with the maintainer.
5. **"Block from a jti" stopped working when the jti row was swept.** It now falls back to the audit row.

**Claims that didn't hold, corrected:**
- **The mutation and interop workflows had never run.** Both dispatched by hand on 2026-10-06; see their runs.
- **The npm name isn't reserved:** the placeholder was never published. The maintainer publishes it; the README no
  longer claims it.
- **README gaps:** the issuer wasn't marked experimental; the single-use position and oauth-wg #130 were missing; the
  receiver's check order was wrong; the CHANGELOG had nothing from Phase 2. All fixed.
- **"The build agent did not stop":** `52bd35e` (README, SECURITY, CONTRIBUTING, threat model, templates) came from a
  separate docs agent the maintainer was running in the same checkout, now stopped. `294efe1` is D-013.
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
  - **`maxIdTokenAgeSeconds`** (default 3600; `subject_token_expired`). Its 3600 s default is the orchestrating
    session's choice, to be confirmed by the maintainer.
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

On the Phase 3 design (`plans/phase-3-design.md`, private):
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
  minor release) is built by the maintainer's own SAML agent in that repository, from the brief at
  `private/saml-idp-exchange-brief.md`. This repository builds against the interface frozen in that brief.
