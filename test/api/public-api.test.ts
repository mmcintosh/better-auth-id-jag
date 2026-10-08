// The public API, pinned (D-031; docs/versioning.md): exactly these runtime exports, from src/index.ts.
// A new export is a decision (it becomes part of what 1.0 promises); a removed one is a breaking change.
// Update this list on purpose, with a CHANGELOG line, never just to make the test pass.
import { describe, expect, it } from "vitest";
import * as api from "../../src";

const PUBLIC = [
  "ALLOWED_ALGORITHMS",
  "AUDIT_EVENT_TYPES",
  "AUDIT_MODEL",
  "BLOCK_MODEL",
  "DEFAULT_CLOCK_SKEW_SECONDS",
  "DEFAULT_JIT_ROLE",
  "DEFAULT_LIFETIME_SECONDS",
  "DEFAULT_MAX_ID_TOKEN_AGE_SECONDS",
  "DEFAULT_SAML_REFRESH_SCOPES",
  "ID_JAG_GRANT_PROFILE",
  "ID_JAG_REGISTRY_ERROR_CODES",
  "ID_JAG_TOKEN_TYPE",
  "ID_JAG_TYP",
  "ID_TOKEN_TOKEN_TYPE",
  "ISSUER_METADATA_FIELD",
  "ISSUER_PLUGIN_ID",
  "ISSUER_SIGNING_ALGORITHMS",
  "JTI_MODEL",
  "JWT_BEARER_GRANT",
  "MAX_ASSERTION_BYTES",
  "MAX_CLOCK_SKEW_SECONDS",
  "MAX_LIFETIME_SECONDS",
  "POLICY_MODEL",
  "REASONS",
  "RECEIVER_METADATA_FIELD",
  "RECEIVER_PLUGIN_ID",
  "REFRESH_TOKEN_TOKEN_TYPE",
  "RESOURCE_SERVER_MODEL",
  "SAML2_TOKEN_TYPE",
  "SAML_NAMEID_SUB_ID_FORMAT",
  "SUBJECT_KINDS",
  "SUPPORTED_DRAFT",
  "TOKEN_EXCHANGE_GRANT",
  "TRUSTED_ISSUER_MODEL",
  "auditSchema",
  "blockSchema",
  "buildIdJag",
  "checkIssuerHost",
  "createIssuerState",
  "handleIdJagGrant",
  "handleTokenExchange",
  "idJagGrant",
  "idJagGrantExtension",
  "idJagIssuer",
  "issuerSchema",
  "jtiSchema",
  "parseIdJag",
  "registrySchema",
  "resolveIssuerOptions",
  "resolveReceiverOptions",
  "trustedIssuerSchema",
  "verifyIdJag",
];

describe("the public API", () => {
  it("is exactly the listed runtime exports", () => {
    expect(Object.keys(api).sort()).toEqual([...PUBLIC].sort());
  });
});
