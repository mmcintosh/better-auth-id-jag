// The optional `idJagTrustedIssuer` table (plan §3.5), the third trust source beside code and
// `@better-auth/sso`. Phase 1 reads it; rows are written by the host (an admin API comes later).
// List-valued columns are JSON strings, as `@better-auth/sso` stores `oidcConfig`.
import type { BetterAuthPluginDBSchema } from "better-auth";

export const TRUSTED_ISSUER_MODEL = "idJagTrustedIssuer";

export function trustedIssuerSchema() {
  return {
    [TRUSTED_ISSUER_MODEL]: {
      fields: {
        issuer: { type: "string", required: true, input: false, index: true },
        jwksUri: { type: "string", required: false, input: false },
        discoveryUri: { type: "string", required: false, input: false },
        /** Accounts are linked under this sso providerId when set, else `id-jag:<issuer>`. */
        ssoProviderId: { type: "string", required: false, input: false },
        /** JSON array of client ids, or null for any. */
        allowedClientIds: { type: "string", required: false, input: false },
        /** JSON array of email domains for the email fallback, or null for none. */
        emailDomains: { type: "string", required: false, input: false },
        jitProvisioning: { type: "boolean", required: true, defaultValue: false, input: false },
        jitTrustEmailVerified: { type: "boolean", required: true, defaultValue: false, input: false },
        /** The organization role of a user JIT creates for this row's organizationId; null = "member". */
        jitRole: { type: "string", required: false, input: false },
        /** JSON array of SAML NameID `sub_id` mappings (the `samlSubjects` option's shape), or null for none. */
        samlSubjects: { type: "string", required: false, input: false },
        /** Refuse ID-JAGs without a SAML NameID `sub_id` (needs samlSubjects); null = false. */
        requireSubId: { type: "boolean", required: false, input: false },
        /** The `@better-auth/scim` connection that provisions this issuer's users (`scim.connectionId`); null = no SCIM step. */
        scimConnectionId: { type: "string", required: false, input: false },
        /** Refuse a subject with no active SCIM-provisioned user (`scim.required`); null = true. */
        scimRequired: { type: "boolean", required: false, input: false },
        tenant: { type: "string", required: false, input: false },
        organizationId: { type: "string", required: false, input: false },
        enabled: { type: "boolean", required: true, defaultValue: true, input: false },
        createdAt: { type: "date", required: true, input: false },
        updatedAt: { type: "date", required: true, input: false },
      },
    },
  } satisfies BetterAuthPluginDBSchema;
}
