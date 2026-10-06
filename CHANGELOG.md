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
- Verified live against Okta Cross App Access, and against Keycloak 26.8.0 and node-oauth2-server in the interop suite.
