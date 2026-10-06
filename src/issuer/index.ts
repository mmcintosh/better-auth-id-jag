// The ID-JAG issuer: plugin, plain-function grant handler, options and record types.
export { RegistryDirectory } from "./directory";
export { handleTokenExchange, type IssuerState } from "./exchange";
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
  SubjectTokenClaims,
} from "./options";
export { DEFAULT_MAX_ID_TOKEN_AGE_SECONDS, ISSUER_SIGNING_ALGORITHMS, resolveIssuerOptions } from "./options";
export { checkIssuerHost, createIssuerState, ISSUER_PLUGIN_ID, idJagIssuer } from "./plugin";
export type { Grant, PolicyRequest } from "./policy";
export { decide } from "./policy";
export type { PolicyConfig, PolicyRecord, ResourceServerConfig, ResourceServerRecord, SubjectKind } from "./records";
export { SUBJECT_KINDS } from "./records";
export { ID_JAG_REGISTRY_ERROR_CODES } from "./registry";
export { BLOCK_MODEL, blockSchema, issuerSchema, POLICY_MODEL, RESOURCE_SERVER_MODEL, registrySchema } from "./schema";
export { type BlockConfig, type BlockRecord, checkBlocks } from "./blocks";
export { type IdTokenClaims, verifyOwnIdToken } from "./subject/id-token";
export { REFRESH_TOKEN_TOKEN_TYPE, type RefreshTokenSubject, verifyOwnRefreshToken } from "./subject/refresh-token";
export { normalizeAudience } from "./url";
