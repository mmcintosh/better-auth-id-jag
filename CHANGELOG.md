# Changelog

## [Unreleased]

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

