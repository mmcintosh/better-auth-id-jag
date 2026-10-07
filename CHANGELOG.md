# Changelog

## [Unreleased]

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
- Verified live against Okta Cross App Access, and against Keycloak 26.8.0 and node-oauth2-server in the interop suite.
