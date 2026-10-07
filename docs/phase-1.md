# Phase 1: the core and both plugins (2026-10-06)

**Verdict: both exit criteria met, on Node and inside workerd.** The receiver turns a hand-minted ID-JAG into an access
token that `@better-auth/mcp`'s `requireMcpAuth` accepts for the right resource and rejects for another. The issuer
turns a real ID token, from a confidential client that went through `/oauth2/authorize` and `authorization_code`, into
an ID-JAG that the core's `verifyIdJag` accepts against the host's own `/jwks`, carrying the policy's narrowed scopes
and the mapped `client_id`.

Built as planned: the core first (written, then reviewed separately and fixed: D-006, D-007), then Track A
(receiver) and Track B (issuer) in parallel, each in its own git worktree, then merged and checked
together.

## What exists

| | Entry | Details |
|---|---|---|
| Core | `src/core/` | ID-JAG parse/verify/build, RFC 6749 errors with S8 non-distinguishability, `idJagJti` replay table, audit events and `idJagAudit` table. D-006, D-007. |
| Receiver | `idJagGrant()`, `handleIdJagGrant()` | jwt-bearer grant on `mcp()` or `oauthProvider()`; trust from static config, `@better-auth/sso` rows (opt-in) and an `idJagTrustedIssuer` table (read-only); JWKS under the S10 network rules; subject resolution; audience-restricted access tokens. `docs/tracks/receiver.md` (D-A01–D-A17). |
| Issuer | `idJagIssuer()`, `handleTokenExchange()` | RFC 8693 token exchange on `oauthProvider()`; ID-token subject tokens this IdP issued; deny-by-default policy from a code hook and/or a registry (`idJagResourceServer`, `idJagPolicy`) with an admin API; client-id-at-resource mapping; signing algorithm option. `docs/tracks/issuer.md` (D-B01–D-B13). |
| Client | `better-auth-id-jag/client` | `idJagIssuerClient()` for the admin API (176 bytes, no server code). |

## Evidence

- **Tests:** 484 passing, 242 per runtime: Node with node:sqlite, and workerd with D1 through `@cloudflare/vitest-plugin`.

  | Tests per runtime | Count |
  |---|---|
  | Core and Phase 0 | 60 |
  | Receiver | 92 |
  | Issuer | 89 |
  | Both plugins on one host (merge check) | 1 |

  `pnpm typecheck` and `pnpm lint` are clean, and the build succeeds.
- **Each guard broken once** (`scripts/mutate.py`), each list on its own branch. The merged code is identical, so the
  lists weren't re-run after the merge (about 40 minutes).

  | List | Mutations | Result |
  |---|---|---|
  | `test/mutations/core.json` | 42 | All caught, after review fixes and two added tests |
  | `test/mutations/receiver.json` | 63 | All caught (56 at first; six tests added, one equivalent mutant replaced) |
  | `test/mutations/issuer.json` | 79 | 69 at first, 10 survived. Five were caught after new tests. Two pairs of guards caught only when broken together. One equivalent. Four halves of pairs survive alone. Table in `docs/tracks/issuer.md`. |
- **Every S-item** that applies to a side has at least one caught mutation on that side. S9 is covered by fast-check
  tests on every inbound parser. S11 doesn't apply (the package has no secrets of its own).
- **Merge checks:**
  - **One host, both plugins:** a host with `mcp()`, `idJagIssuer()` and `idJagGrant()` boots, migrates **one**
    `idJagJti` and **one** `idJagAudit` table (Better Auth merges the identical declarations), and advertises both
    metadata fields and both grant types.
  - **Built package:** typechecks for a `NodeNext` consumer and imports at runtime through `.` and `./client`.
  - **Build script fix:** it now rewrites nested and directory declaration imports. They were broken for `NodeNext`
    once declarations moved into subfolders.
- **Independent re-run:** each track's branch was re-run independently before merging (typecheck, lint,
  full suite). Each changed only its own files.

## Decisions to look at

- **Receiver, D-A01: sso trust is opt-in.** sso providers exist for sign-in, so trusting every one for ID-JAGs by
  default widens what they can do.
- **Receiver, D-A02: sso's discovery helpers aren't used.** They fetch through Better Auth's global fetch, which breaks
  S10's single injectable fetch. A discovery document's `issuer` must match exactly.
- **Receiver, D-A04:** an issuer matched by two trust entries is refused, rather than one being picked.
- **Receiver, D-A06:** a token without a `resource` claim is accepted when one resource can be chosen: the request's,
  `defaultResource`, or the only registered one.
- **Receiver, D-A07:** there's no `issueRefreshToken` option. `offline_access` and `openid` are always removed, and a
  regression test checks for neither a refresh token nor an ID token.
- **Issuer, D-B02:** pairwise-subject clients are refused explicitly.
- **Issuer, D-B04:** with both a code hook and a registry configured, both must allow, and the narrower grant wins.
- **Issuer, D-B05 (S8):** `no_scope` and `unknown_resource` come only after a policy has allowed.
- **Issuer, D-B09, D-B11, D-B12:**
  - one resource per request;
  - "revoke" only records the revocation in the audit log, since there's no protocol a receiver could see;
  - a missing `requested_token_type` is refused, so we don't shadow a future generic token-exchange grant.

## Questions for the maintainer (before Phase 2)

From the core review (D-007):
1. Keep strict single use of an ID-JAG? The draft lets a client re-present an unexpired one. Recommended: yes.
2. Document, rather than guard against, adapters that don't enforce UNIQUE? Recommended: document.

Receiver (`docs/tracks/receiver.md`):

3. Should sso trust stay opt-in, or be on by default when sso is installed?
4. Should the `resource` claim be required? The MCP extension implies it.
5. Should JIT provisioning add the user to the trust entry's organization? Not done today.
6. Should the access-token lifetime be capped? Today it's the provider's 1 hour, and `issueTokens` has no per-call
   expiry, so a cap needs a workaround or an upstream change.
7. Is an admin API for `idJagTrustedIssuer` wanted before 0.1? The table is read-only today.

Issuer (`docs/tracks/issuer.md`):

8. Is it right that both policy sources must allow (D-B04), or should one allowing source be enough?
9. Should pairwise subjects be supported?
10. When a host-level and an organization-level resource server both allow one audience, should the organization's
    win? Today it's refused as ambiguous.
11. Should policy `clientIds` accept a wildcard for CIMD clients?
12. Should "revoke" also block further exchanges, for that user, client or audience?
13. Should `email` be sent only when it's verified (today's behaviour)?

## Core change requests from the tracks (not yet made)

1. **Both tracks:** add a `client_authentication_failed` reason, plus `unauthorized_client` on the receiver side.
   Today the provider's own client-authentication errors pass through unchanged and **aren't audited**, on either side.
   This is the one known audit gap.
2. **Issuer:** add a `subject_token_expired` reason. The issuer reuses `expired`, whose text says "The assertion has
   expired."
3. **Receiver, optional:** a `verifyParsedIdJag` that takes an already-parsed token, to avoid parsing twice.
4. **Receiver:** a shared tables plugin if two plugins on one host ever clash. The merge check above shows they don't
   today.

## Not done in Phase 1, as planned

- Our issuer against our receiver over HTTP, Keycloak, Authelia, node-oauth2-server and Okta (Phase 2).
- SAML and refresh-token subject tokens (Phase 3).
- The example Workers, the guide and the release (Phase 4).
- Adapter-matrix CI for the new tables.
- The strict-host types check, and Are the Types Wrong (`pack:check`).
