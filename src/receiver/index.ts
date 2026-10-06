// The receiver (Track A): accept ID-JAGs over the jwt-bearer grant and issue audience-restricted
// access tokens.
export { handleIdJagGrant, registeredResources, STRIPPED_SCOPES } from "./grant";
export { type FetchLike, type IssuerKeys, JwksCache, type JwksSettings, type KeySource } from "./jwks";
export {
  type IdJagGrantOptions,
  type ResolvedReceiverOptions,
  type ResolveSubjectInput,
  resolveReceiverOptions,
  type SsoTrustOptions,
  type StaticTrustedIssuer,
  type SubjectResolution,
  type TrustedIssuerView,
  type TrustEntry,
} from "./options";
export { addJitMembership, BUILT_IN_ORGANIZATION_ROLES, DEFAULT_JIT_ROLE, type MembershipOutcome, type OrganizationRoles, organizationRoles, unknownRoles } from "./membership";
export { idJagGrant, idJagGrantExtension, RECEIVER_PLUGIN_ID } from "./plugin";
export { type ResolvedSubject, resolveSubject } from "./resolve";
export { TRUSTED_ISSUER_MODEL, trustedIssuerSchema } from "./schema";
export { findTrustedIssuer, openIdConfigurationUrl } from "./trust";
