// The identifiers ID-JAG and the MCP extension use, in one place: a renamed claim or URN in a later
// draft changes here.

/** The draft this package implements. It expires 2026-11-22; -05 may move a name. */
export const SUPPORTED_DRAFT = "draft-ietf-oauth-identity-assertion-authz-grant-04";

/** The JWS `typ` of an ID-JAG. */
export const ID_JAG_TYP = "oauth-id-jag+jwt";
/** The token type an issuer is asked for, and the one it reports as issued (RFC 8693). */
export const ID_JAG_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:id-jag";
/** The subject token type v1 accepts at the issuer: an ID token this IdP issued. */
export const ID_TOKEN_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:id_token";
/** The other subject token type the issuer accepts: a refresh token this IdP issued (draft's MAY). */
export const REFRESH_TOKEN_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:refresh_token";
/** A SAML 2.0 assertion as a subject token (RFC 8693 §3; draft -04 §4.3.1, §4.5). */
export const SAML2_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:saml2";
/** The `sub_id` format for a SAML NameID (draft -04 §3.2.1). */
export const SAML_NAMEID_SUB_ID_FORMAT = "saml-nameid";
/** The issuer's grant (RFC 8693). */
export const TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange";
/** The receiver's grant (RFC 7523). */
export const JWT_BEARER_GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer";
/** Advertised by the receiver in `authorization_grant_profiles_supported`. */
export const ID_JAG_GRANT_PROFILE = "urn:ietf:params:oauth:grant-profile:id-jag";

/** Issuer metadata: the token types it can be asked for. */
export const ISSUER_METADATA_FIELD = "identity_chaining_requested_token_types_supported";
/** Receiver metadata: the grant profiles it accepts. */
export const RECEIVER_METADATA_FIELD = "authorization_grant_profiles_supported";

/** Signature algorithms accepted on an ID-JAG (S4). No HS*, no `none`. `Ed25519` is RFC 9864's name for EdDSA on Ed25519. */
export const ALLOWED_ALGORITHMS = ["RS256", "ES256", "EdDSA", "Ed25519"] as const;
export type IdJagAlgorithm = (typeof ALLOWED_ALGORITHMS)[number];

/** Lifetime: the draft's examples use five minutes; we refuse more than fifteen (S7). */
export const DEFAULT_LIFETIME_SECONDS = 300;
export const MAX_LIFETIME_SECONDS = 900;
export const DEFAULT_CLOCK_SKEW_SECONDS = 60;
export const MAX_CLOCK_SKEW_SECONDS = 300;
/** Extra life for a jti row beyond `exp + skew`, for clocks that differ between instances. */
export const JTI_RETENTION_MARGIN_SECONDS = 300;
