# Changelog

## [Unreleased]

## [0.3.0] - 2026-10-10

A smaller, explicit public API (breaking: 
  internals no longer exported), the SCIM option types, and the layered-permissions example.

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

