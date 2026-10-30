# Changelog

## [Unreleased]

## [0.5.3] - 2026-10-30

### Fixed

- **Issuer: a subject token's `acr` or `amr` the ID-JAG can't carry is refused, never a 500** (D-056). An ID token
  whose `acr` or an `amr` entry has a control character, or a SAML Assertion whose class is empty or has one, passed
  the subject-token check and then failed the ID-JAG's own claim check: HTTP 500, no ID-JAG issued. Now it's
  `invalid_subject_token`. The ID-token case needs Better Auth 1.8's `authenticationContext` (1.7 always says
  `acr: "0"`); the SAML case needs a SAML IdP configured with such a class.

### Documentation

- **How the person signed in, on Better Auth 1.8** (D-056): with oauth-provider's `authenticationContext`, an
  ID-JAG from an ID token carries exactly the `acr`/`amr` your resolver returned, so it can claim MFA. A refresh-token
  subject still carries neither. `docs/security.md` and the README's policy section.

## [0.5.2] - 2026-10-27

### Changed

- **Requires `zod` 4.6.6 or later** (`^4.6.6`, was `^4.6.5`, D-053).
  [GHSA-mrhx-c7xc-m3w5](https://github.com/advisories/GHSA-mrhx-c7xc-m3w5) (high) covers zod 4.6.5 and earlier:
  a large array can exhaust memory while zod collects its validation issues. This package caps the size of outside
  input before zod parses it, so it isn't exposed itself, but the old range let a host install the affected zod.
  A host whose lockfile still has zod 4.6.5 gets a second copy until it runs `pnpm update zod` (or the npm or yarn
  equivalent); Better Auth accepts 4.6.6 and later.

## [0.5.1] - 2026-10-23

### Changed

- **`zod` and `jose` are ranges now** (`^4.6.5` and `^6.2.12`, were exact `4.6.7` and `6.2.12`), so a host whose
  tree has an older zod or jose within those ranges shares one copy instead of installing a second (D-050).

## [0.5.0] - 2026-10-20

### Changed

- **Requires Better Auth 1.7.10 or later** (`>=1.7.10 <1.8.0`, was `>=1.7.5`), for `better-auth` and every
  `@better-auth/*` peer (D-044). Better Auth 1.7.7 fixed account-takeover advisories that 1.7.5 and 1.7.6 have:
  [GHSA-965c-763c-88jm](https://github.com/better-auth/better-auth/security/advisories/GHSA-965c-763c-88jm)
  (critical; the Magic Link plugin with social or Generic OAuth sign-in) and
  [GHSA-r4xp-prcw-77qf](https://github.com/better-auth/better-auth/security/advisories/GHSA-r4xp-prcw-77qf)
  (high; the OAuth Proxy plugin). This package uses neither plugin, but the old floor let a host install an affected
  Better Auth next to it. **On an older 1.7.x, upgrade Better Auth and its plugins together first**; npm warns about
  the peer range until you do. No code or schema change in this package.

### Fixed

- **Issuer: a malformed `resource` is a 400, never a 500** (D-045). A `resource` longer than 2048 characters or
  with a control character passed Better Auth's own check (1.7.x) and reached the ID-JAG builder, whose claim check
  threw: HTTP 500 (no ID-JAG was issued). On Better Auth 1.8 an empty `resource=` did the same. The issuer now checks
  `resource` itself (an absolute URI without a fragment, at most 2048 characters) and refuses anything else with
  `invalid_target` and the new public reason `invalid_resource`.

### Added

- **Issuer: another token exchange beside ours** (D-046). Better Auth 1.8's `oauthTokenExchange()` registers the same
  token-exchange grant as `idJagIssuer()`, and oauth-provider allows one handler per grant type, so listing both
  stops startup. New option `idJagIssuer({ otherTokenExchange })`: requests this plugin doesn't serve (a
  `requested_token_type` other than an ID-JAG, or a refresh token with SAML path (b)) go to that handler instead of
  being refused. New export `tokenExchangeFrom(plugin)` takes the handler out of a plugin like
  `oauthTokenExchange()`, and refuses one with parts it would lose. Listing both plugins now fails with a message
  saying this. Nothing changes without the option. Tested against `oauthTokenExchange()` on Better Auth
  1.8.0-beta.1 (the CI's 1.8 row); this release's peer range is still 1.7.
- **Issuer: step-up** (draft -04 §9.2, D-043). The `authorize` hook can deny with
  `stepUp: { maxAge?, acrValues?, description?, uri? }`. The client then gets `insufficient_user_authentication`
  with `max_age`, `acr_values`, `error_description` and `error_uri` (RFC 9470's parameters), not the generic
  `invalid_grant`, so it can send the person back to sign in again, for example to a "confirm it's you" page. Off
  unless the hook asks; a deny without it is unchanged. Audited as the new reason `step_up_required`. A malformed
  `stepUp` is a malformed verdict (`policy_denied`).

## [0.4.0] - 2026-10-18

### Added

- **Issuer: `act` for agents** (D-036). The `authorize` hook can return `claims: { act: true }` (or
  `{ act: { sub_profile } }`) to name the requesting client as the actor in the ID-JAG, RFC 8693 `act` with `sub` =
  its client id at the IdP, as Okta does for AI agents. Off unless the hook asks; the actor is always the requesting
  client, never one the policy names. Receivers that require `act` (some do) now accept our ID-JAGs, and ours
  carries it into the access token. `sub_profile` is space-separated names of letters, digits, punctuation and
  symbols (D-040); anything else (blank, padded or doubled spaces, invisible, combining or blank-rendering characters)
  is a malformed verdict (`policy_denied`). On 0.3.0 a hook returning `claims: { act: … }` got no error and no `act`
  (the claim was dropped silently, and the agent's ID-JAGs looked like an app's): upgrade before relying on it.
- **Receiver: ID-JAGs that name their key by certificate thumbprint** (D-042). A header without `kid` is accepted
  when it carries `x5t` or `x5t#S256`; the key is the issuer's with that thumbprint (published, or worked out from its
  `x5c`). PingFederate never sends `kid`, so every PingFederate ID-JAG was refused (`missing_kid`); verified live with
  13.1.3 (docs/interop.md). `IdJagHeader.kid` is now optional.
- **Audit: `act`** (D-040). `id-jag.issued` and `id-jag.accepted` events (and audit rows' `details`) carry the
  ID-JAG's `act` as `{ sub, sub_profile? }`: the current actor only, log-safe. New exported type `ActSummary`.

### Fixed

- **Receiver: JWKS keys with `key_ops`, and no 500 on a key WebCrypto refuses** (D-041). A key published for
  `["wrapKey", "encrypt", "verify"]` (Oracle OCI IAM's) failed every ID-JAG it signed, as a 500: WebCrypto won't import
  an RSA or EC signing key for those usages, and the error's numeric `code` crashed the log sanitiser. A key whose
  `key_ops` includes `verify` is now used for verify only; one without `verify` is skipped; any key WebCrypto still
  refuses is `jwks_unavailable`.

- **Audit: strings are cut in code points, and lone surrogates repaired** (D-040). An event string over the cap
  (300; a refusal's detail, a long client id) could end in half a surrogate pair; a lone surrogate sent as a JSON
  escape reached handlers and the audit table as is. Both are now valid UTF-16, cut whole, a lone surrogate as U+FFFD.

- **Issuer: no assumption about Better Auth's default signing algorithm** (#19). The startup check took an unset
  `keyPairConfig.alg` to mean EdDSA, so `signingAlgorithm: "RS256"` would be refused on a Better Auth whose default is
  RS256 (better-auth#9935); and verifying the host's own ID tokens assumed EdDSA for a stored key without `alg`. Now
  an unset `keyPairConfig.alg` means Better Auth's own default, read from Better Auth (its `DEFAULT_JWT_ALGORITHM`
  where exported, else 1.7's EdDSA); each ID-JAG's actual algorithm is also checked when it is signed (not
  RS256/ES256/EdDSA: none is issued, a 500 with the algorithm in the server log); and a stored key's
  algorithm comes from the key (its `alg`, else the configured one when it fits the key type, else the key type).
- **README: the Okta trust-entry examples named `/oauth2/default`** (#21). Cross App Access ID-JAGs come from the
  org authorization server (`iss` `https://<org>.okta.com`, keys at `/oauth2/v1/keys`), so the examples refused every
  Okta ID-JAG (`untrusted_issuer`). Also: the org's `/.well-known/oauth-authorization-server` has no `jwks_uri`, so
  `discoveryUri` must be its `/.well-known/openid-configuration`.

### Example

- **The example MCP server lists the Enterprise-Managed Authorization extension** in its `initialize` reply
  (`capabilities.extensions["io.modelcontextprotocol/enterprise-managed-authorization"]`); MCPJam now reports it as
  advertised. The receiver already met the extension's discovery rule (its metadata's ID-JAG grant profile).
- **The example IdP tells AI agents from apps** (D-037): `--setup` registers both, the IdP names the agent in
  `act` (from client metadata `agent: true`), and the demo MCP server keeps agents read-only. `client.mjs
  --client=app` runs as the app. Re-run `--setup` once.
- **The example MCP server works with VS Code** (#25): `/setup` takes `"tokenEndpointAuthMethod":
  "client_secret_post"` (VS Code and xaa.dev's tester send the secret in the body), its clients carry no redirect URI
  (they only redeem ID-JAGs), and `GET /mcp` answers 405 instead of 200 (no server-to-client stream; VS Code polled
  it). The example IdP's `/setup` now also works on `http://localhost`. README: VS Code setup, running locally.

### Documentation

- **`docs/okta.md`: the receiver behind Okta Cross App Access** (#22): the trust entry (the org issuer, its keys),
  finding users, the Okta console values, what Okta's ID-JAG carries, cutoffs, and what each refusal means, from
  the live runs and the code. The console steps moved there from `docs/interop.md`.
- **The receiver's access token doesn't carry `auth_time` either** (#26), only `acr`/`amr` were named: README and
  `docs/security.md`. A test pins that none of the three reaches the access token or its introspection, so an
  upstream change that lets `auth_time` through (better-auth#11267) is noticed (the grant passes no `acr`/`amr`); `authTime` at `grant.ts` stays, with a comment that it has no effect yet.
- **How the person signed in** (`docs/security.md`, README; D-033): an ID-JAG's `auth_time`, `acr` and `amr` are
  copied from the subject token, never derived. From an ID token that is always `acr: "0"` and no `amr` (oauth-provider
  fixes them); only a SAML Assertion's class can claim MFA, so the SAML IdP must state only what the session did. A
  rule that requires MFA treats a missing value as not proven: at the receiver, in `resolveSubject`. Tests pin each
  of these.

### Interoperability

- **Two more ID-JAG implementations against the receiver**, in the weekly Interop workflow (`docs/interop.md`;
  D-035): MCPJam's Cross App Access debugger (`@mcpjam/sdk` 9.3.0), the whole flow to an MCP `initialize` and each of
  its ten attacks refused with the matching reason, for an ID token and for a SAML `sub_id`
  (`test/interop/mcpjam.test.ts`); and identity-provider.net, live, an independent issuer: ID token and refresh token
  subjects accepted, replay, another client id and an ML-DSA-signed ID-JAG refused (`test/interop/zipidp.test.ts`).
  Tests only; no runtime change.
- **A real MCP client: VS Code 1.141.0 with Okta** (#25), live, through to `initialize` and `tools/list` on the
  example MCP server (`docs/interop.md`): what a server must allow for it (`client_secret_post`, every advertised
  scope, the loopback redirect URI at the IdP).

## [0.3.0] - 2026-10-10

A smaller, explicit public API (breaking: internals no longer exported), the SCIM option types, and the layered-permissions example.

### Breaking

- **The public API is now an explicit list** (`src/index.ts`, `docs/versioning.md`; D-031): 52 runtime exports
  instead of 106. Removed, as internals nothing documented uses: `emit`, `auditRow`, `sweepAudit`, `refuse`,
  `logSafe`, `toApiError`, `providerErrorCode`, `providerRefusalReason`, `publicDescription`, `IdJagRefusal`, `jtiKey`,
  `recordJti`, `hasJti`, `jtiExpiresAt`, `sweepJtis`, `warnIfReplayUnsafe`, `JTI_RETENTION_MARGIN_SECONDS`,
  `checkTimes`, `newJti`, `isIdJagTyp`, `idJagClaimsSchema`, `lifetimeOption`, `skewOption`, `MAX_TOKEN_LENGTH`,
  `MAX_ACT_DEPTH`, `UNSUPPORTED_CLAIMS`, `parseSamlNameIdSubId`, `samlNameIdSubIdSchema`, `TRANSIENT_NAMEID_FORMAT`,
  `decide`, `checkBlocks`, `checkBlocksWithoutAudience`, `RegistryDirectory`, `normalizeAudience`,
  `verifyOwnIdToken`, `verifyOwnRefreshToken`, `verifyOwnSamlAssertion`, `decodeSaml2SubjectToken`,
  `MAX_SAML2_TOKEN_LENGTH`, `getSamlIdpExchange`, `assertionExchangeErrorCode`, `ASSERTION_EXCHANGE_ERROR_CODES`,
  `SAML_IDP_EXCHANGE_KEY`, `resolveSubject` (the function; the option is unchanged), `subjectKey`,
  `findTrustedIssuer`, `openIdConfigurationUrl`, `registeredResources`, `STRIPPED_SCOPES`, `addJitMembership`,
  `organizationRoles`, `unknownRoles`, `BUILT_IN_ORGANIZATION_ROLES`, `JwksCache`, and the internal types that went
  with them. If you used one of these, open an issue: adding an export back is not a breaking change.

### Added

- The SCIM option types `ScimTrustInput` and `AcquireActiveScimUserLink` are exported (they were missing in 0.2).

## [0.2.1] - 2026-10-08

Fixes the SCIM step from 0.2.0: parallel redemptions for one user are no longer refused.

- **Fix (SCIM, new in 0.2.0): parallel redemptions for one user were refused.** `acquireActiveSCIMUserLink` bumps the
  SCIM subject's revision on every lookup, so concurrent lookups of the same user conflict with each other, not only
  with a lifecycle change; on Postgres, 8 parallel redemptions for one active user got 3 tokens and 5
  `invalid_grant`. A conflict is now retried with exponential backoff and full jitter for up to 5 seconds (at most 40
  attempts), then refused, as before, and concurrent redemptions for the same user in one process share a single
  lookup (D-030). Found by the better-auth-scim-provisioning maintainer on Cloudflare with Postgres through
  Hyperdrive (D-029).
- Docs: on Cloudflare, create the auth database's Hyperdrive config with caching disabled.

## [0.2.0] - 2026-10-08

SCIM-provisioned users at the receiver: deprovisioning at the IdP stops the agent at your app too.

- Receiver: **SCIM-provisioned users** (D-027). A trusted issuer with `scim: { connectionId, required? }` resolves the
  ID-JAG's `sub` as the SCIM `externalId` through `@better-auth/scim`'s `acquireActiveSCIMUserLink` (passed in as
  `idJagGrant({ scim: { acquireActiveSCIMUserLink } })`): only an active provisioned user is found, and by default a
  subject with none is refused, so deprovisioning at the IdP stops the agent here too. The `idJagTrustedIssuer`
  table gains `scimConnectionId` and `scimRequired`. Needs a database with transactions (not D1). The
  `id-jag.accepted` event gains `resolvedBy`.
- **Migration, only with `trustedIssuerTable: true`:** the `idJagTrustedIssuer` table has two new nullable columns
  (`scimConnectionId`, `scimRequired`). Run `npx auth migrate` (or `npx auth generate` for Drizzle and Prisma).

## [0.1.0] - 2026-10-08

The first release: Identity Assertion JWT Authorization Grants for Better Auth, an issuer (experimental) and a receiver, draft -04.

- `idJagIssuer()`: issue ID-JAGs from a Better Auth IdP (RFC 8693 token exchange, ID-token subject tokens, policy hook
  and registry with an admin API, `better-auth-id-jag/client`).
- `idJagGrant()`: accept ID-JAGs at an MCP server's authorization server (RFC 7523 jwt-bearer, trusted issuers from
  config, `@better-auth/sso` or a table, audience-restricted access tokens).
- The shared core: ID-JAG parse/verify/build, errors, jti replay table, audit events. Draft -04.
- Issuer: refresh tokens this provider issued are accepted as subject tokens; **blocks** (a user, a client, an
  audience, or any combination, optionally until a date) stop new ID-JAGs and replace "revoke", which never revoked
  anything; `iss` is always the issuer the metadata publishes. The issuer is **experimental**.
- Receiver: `act` (who acts for the user, as Okta sends for an AI agent) is accepted and carried into the access
  token; an ID-JAG with `cnf` (key-bound) or `authorization_details` is refused until those are supported. Just-in-time
  provisioning adds the user to the trust entry's organization. New option `requireResourceClaim`. Single use stays,
  deliberately (oauth-wg issue #130).
- Both: the OAuth provider's own client-authentication refusals reach the audit events; a startup warning on database
  adapters that don't enforce unique keys.
- Issuer, experimental: **SAML assertions** from better-auth-saml-idp ≥ 1.2.0 as subject tokens, directly to an
  ID-JAG, or to a refresh token first (draft -04 §4.5, MCP's SAML path; `saml: { subjectTokens, refreshTokens }`,
  `scope_required`, the `id-jag.refresh-issued` event). `maxIdTokenAgeSeconds` (an hour by default) and the `sid`
  session check stop old sign-ins; `blocks: { canManage }`; blocking from a `jti` falls back to the audit log.
- Receiver: users resolved by SAML NameID (`sub_id`, `samlSubjects`, `requireSubId`); the email fallback needs a
  verified local email and respects `account.accountLinking`; concurrent first use converges on one user and link
  instead of a 500; `jwks.maxStaleSeconds`; `jitRole`.
- Both: options accept `undefined` for every optional field (strict TypeScript hosts); one `events` object can serve
  both plugins. Tested on Postgres, MySQL, MongoDB, Drizzle and Prisma.
- Receiver: while an issuer's key set can't be fetched, its cached keys answer every request for up to
  `jwks.maxStaleSeconds` past their TTL, including the one whose refetch failed (logged as a warning). Core:
  `AUDIT_EVENT_TYPES`, every audit event type.
- Verified live against Okta Cross App Access (including the refresh-token subject and Okta's connection, assignment
  and deactivation controls) and Okta's xaa.dev testers (OIDC and SAML), and against Keycloak 26.8.0 and
  node-oauth2-server in the interop suite.
- Published from CI with npm provenance and a CycloneDX SBOM; every install in CI runs through Socket Firewall.

