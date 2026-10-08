// better-auth-id-jag: Identity Assertion JWT Authorization Grants for Better Auth.
// - idJagIssuer(): an IdP on @better-auth/oauth-provider issues ID-JAGs (RFC 8693 token exchange).
// - idJagGrant(): an MCP server's authorization server accepts them (RFC 7523 jwt-bearer).
//
// This file is the public API (docs/versioning.md, D-031): exactly what is listed here. Everything
// else in src/ is internal and may change in any release.

// The plugins, and composing them yourself.
export { idJagIssuer, createIssuerState, checkIssuerHost, ISSUER_PLUGIN_ID } from "./issuer/plugin";
export { handleTokenExchange, type IssuerState } from "./issuer/exchange";
export { resolveIssuerOptions, DEFAULT_MAX_ID_TOKEN_AGE_SECONDS, DEFAULT_SAML_REFRESH_SCOPES, ISSUER_SIGNING_ALGORITHMS } from "./issuer/options";
export { idJagGrant, idJagGrantExtension, RECEIVER_PLUGIN_ID } from "./receiver/plugin";
export { handleIdJagGrant } from "./receiver/grant";
export { resolveReceiverOptions } from "./receiver/options";

// Tables.
export { issuerSchema, blockSchema, registrySchema, BLOCK_MODEL, POLICY_MODEL, RESOURCE_SERVER_MODEL } from "./issuer/schema";
export { trustedIssuerSchema, TRUSTED_ISSUER_MODEL } from "./receiver/schema";
export { jtiSchema, JTI_MODEL } from "./core/replay";
export { auditSchema, AUDIT_MODEL, AUDIT_EVENT_TYPES } from "./core/audit";

// Protocol constants, defaults and limits.
export {
  SUPPORTED_DRAFT,
  ID_JAG_TYP,
  ID_JAG_TOKEN_TYPE,
  ID_TOKEN_TOKEN_TYPE,
  REFRESH_TOKEN_TOKEN_TYPE,
  SAML2_TOKEN_TYPE,
  SAML_NAMEID_SUB_ID_FORMAT,
  TOKEN_EXCHANGE_GRANT,
  JWT_BEARER_GRANT,
  ID_JAG_GRANT_PROFILE,
  ISSUER_METADATA_FIELD,
  RECEIVER_METADATA_FIELD,
  ALLOWED_ALGORITHMS,
  DEFAULT_LIFETIME_SECONDS,
  MAX_LIFETIME_SECONDS,
  DEFAULT_CLOCK_SKEW_SECONDS,
  MAX_CLOCK_SKEW_SECONDS,
  type IdJagAlgorithm,
} from "./core/urns";
export { DEFAULT_JIT_ROLE } from "./receiver/membership";
export { MAX_ASSERTION_BYTES, type SamlIdpExchange, type VerifiedAssertion } from "./issuer/saml-exchange";
export { SUBJECT_KINDS, type PolicyConfig, type PolicyRecord, type ResourceServerConfig, type ResourceServerRecord, type SubjectKind } from "./issuer/records";
export { ID_JAG_REGISTRY_ERROR_CODES } from "./issuer/registry";

// Refusal reasons and audit events.
export { REASONS, type ReasonCode, type OAuthErrorCode } from "./core/errors";
export type { AuditOptions, IdJagEvent, IdJagEventHandlers, IssuedEvent, RefreshIssuedEvent, AcceptedEvent, RefusedEvent, AdminChangedEvent } from "./core/audit";

// An ID-JAG toolkit, for building or testing another issuer or receiver.
export { parseIdJag, verifyIdJag, buildIdJag } from "./core/jwt";
export type { ActClaim, IdJagClaims, IdJagHeader, IdJagKey, IdJagSigner, ParsedIdJag, SamlNameIdSubId, VerifyExpectations } from "./core/jwt";

// Option and record types.
export type {
  AuthorizeAllow,
  AuthorizeDeny,
  AuthorizeInput,
  AuthorizeResult,
  BlocksOptions,
  CanManage,
  IdJagIssuerOptions,
  IssuerSigningAlgorithm,
  PolicyClient,
  RegistryOptions,
  ResolvedIssuerOptions,
  SamlOptions,
  SubjectTokenClaims,
} from "./issuer/options";
export type { BlockConfig, BlockRecord } from "./issuer/blocks";
export type {
  AcquireActiveScimUserLink,
  IdJagGrantOptions,
  ResolvedReceiverOptions,
  ResolveSubjectInput,
  SamlSubjectMapping,
  SamlSubjectMappingInput,
  ScimTrustInput,
  SsoTrustOptions,
  StaticTrustedIssuer,
  SubjectResolution,
  TrustedIssuerView,
} from "./receiver/options";
export type { FetchLike } from "./receiver/jwks";
