// The issuer's tables (plan §3.5): the core's jti and audit tables, plus the registry's two when
// it is enabled. Unique columns are declared at field level (SQL migrators) and as named
// table-level indexes (Better Auth 1.7's MongoDB adapter creates only those: better-auth-saml-idp
// D-033).
import type { BetterAuthPluginDBSchema } from "better-auth";
import { auditSchema, jtiSchema } from "../core";

export const RESOURCE_SERVER_MODEL = "idJagResourceServer";
export const POLICY_MODEL = "idJagPolicy";

export function registrySchema() {
  return {
    [RESOURCE_SERVER_MODEL]: {
      fields: {
        // SHA-256 of (organizationId ?? "", audience): an audience is unique per organization.
        lookupKey: { type: "string", required: true, unique: true, input: false },
        audience: { type: "string", required: true, input: false, index: true },
        name: { type: "string", required: true, input: false },
        // JSON: string[] (RFC 8707 resources a request may name), string[] (scopes), and
        // Record<client id here, client id at the resource authorization server> (D-004).
        resources: { type: "string", required: true, input: false },
        scopes: { type: "string", required: true, input: false },
        clientIdsAtResource: { type: "string", required: true, input: false },
        requireResource: { type: "boolean", required: true, input: false },
        enabled: { type: "boolean", required: true, input: false },
        organizationId: { type: "string", required: false, input: false },
        createdBy: { type: "string", required: true, input: false },
        updatedBy: { type: "string", required: true, input: false },
        createdAt: { type: "date", required: true, input: false },
        updatedAt: { type: "date", required: true, input: false },
      },
      indexes: [{ fields: ["lookupKey"], unique: true, name: "id_jag_resource_server_lookup_key_unique" }],
    },
    [POLICY_MODEL]: {
      fields: {
        resourceServerId: { type: "string", required: true, input: false, index: true },
        name: { type: "string", required: true, input: false },
        // everyone | organization | role | users; subjectRef is JSON string[] (organization ids,
        // roles, or user ids; [] for everyone).
        subjectKind: { type: "string", required: true, input: false },
        subjectRef: { type: "string", required: true, input: false },
        // JSON string[]: requesting clients (their ids here).
        clientIds: { type: "string", required: true, input: false },
        scopes: { type: "string", required: true, input: false },
        lifetimeSeconds: { type: "number", required: false, input: false },
        includeEmail: { type: "boolean", required: true, input: false },
        enabled: { type: "boolean", required: true, input: false },
        createdBy: { type: "string", required: true, input: false },
        updatedBy: { type: "string", required: true, input: false },
        createdAt: { type: "date", required: true, input: false },
        updatedAt: { type: "date", required: true, input: false },
      },
    },
  } satisfies BetterAuthPluginDBSchema;
}

/** The jti table always; the audit table only with `auditLog`, the registry's only with `registry.enabled`. */
export function issuerSchema(o: { registry: boolean; auditLog: boolean }) {
  return { ...jtiSchema(), ...(o.auditLog ? auditSchema() : {}), ...(o.registry ? registrySchema() : {}) };
}
