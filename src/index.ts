// better-auth-id-jag: Identity Assertion JWT Authorization Grants for Better Auth.
// - idJagIssuer(): an IdP on @better-auth/oauth-provider issues ID-JAGs (RFC 8693 token exchange).
// - idJagGrant(): an MCP server's authorization server accepts them (RFC 7523 jwt-bearer).
// - the shared core: ID-JAG parse/verify/build, errors, jti replay table, audit events.
export * from "./core";
export * from "./issuer";
export * from "./receiver";
