// The registry's records: input schemas (zod) for the admin API, and the re-validation of stored
// rows on every (cache-missing) read. A row edited by hand into something invalid is reported with
// its issues and never used (better-auth-saml-idp D-027): stored rows are data, not code.
import { z } from "zod";
import { MAX_LIFETIME_SECONDS } from "../core";
import { isResourceUri, normalizeAudience } from "./url";

export const MAX_RESOURCES = 100;
export const MAX_SCOPES = 200;
export const MAX_CLIENTS = 1000;
export const MAX_SUBJECTS = 1000;

// RFC 6749 §3.3 scope-token.
const scopeToken = z.string().regex(/^[\x21\x23-\x5b\x5d-\x7e]{1,256}$/, "not a scope token");
// biome-ignore lint/suspicious/noControlCharactersInRegex: refusing them is the point.
const ident = z.string().min(1).max(512).regex(/^[^\u0000-\u001f\u007f-\u009f]+$/, "control characters");
const unique = <T>(a: T[]) => new Set(a).size === a.length;

export const SUBJECT_KINDS = ["everyone", "organization", "role", "users"] as const;
export type SubjectKind = (typeof SUBJECT_KINDS)[number];

export function resourceServerInput(o: { allowLoopbackHttp: boolean }) {
  return z.strictObject({
    audience: z.string().transform((v, c) => {
      const n = normalizeAudience(v, { allowLoopbackHttp: o.allowLoopbackHttp });
      if (!n.ok) {
        c.addIssue({ code: "custom", message: `not an issuer identifier (${n.why})` });
        return z.NEVER;
      }
      return n.audience;
    }),
    name: z.string().min(1).max(200),
    resources: z
      .array(z.string().refine(isResourceUri, "an absolute URI without a fragment"))
      .max(MAX_RESOURCES)
      .refine(unique, "duplicates")
      .default([]),
    scopes: z.array(scopeToken).max(MAX_SCOPES).refine(unique, "duplicates"),
    clientIdsAtResource: z
      .record(ident, ident)
      .refine((m) => Object.keys(m).length <= MAX_CLIENTS, `at most ${MAX_CLIENTS} clients`)
      .default({}),
    requireResource: z.boolean().default(false),
    organizationId: ident.optional(),
  });
}
export type ResourceServerConfig = z.infer<ReturnType<typeof resourceServerInput>>;

export const policyInput = z
  .strictObject({
    resourceServerId: ident,
    name: z.string().min(1).max(200),
    subjectKind: z.enum(SUBJECT_KINDS),
    subjectRef: z.array(ident).max(MAX_SUBJECTS).refine(unique, "duplicates").default([]),
    clientIds: z.array(ident).min(1).max(MAX_CLIENTS).refine(unique, "duplicates"),
    scopes: z.array(scopeToken).max(MAX_SCOPES).refine(unique, "duplicates"),
    lifetimeSeconds: z.number().int().min(1).max(MAX_LIFETIME_SECONDS).optional(),
    includeEmail: z.boolean().default(false),
  })
  .superRefine((p, c) => {
    if (p.subjectKind === "everyone" && p.subjectRef.length > 0) c.addIssue({ code: "custom", path: ["subjectRef"], message: "must be empty for everyone" });
    if (p.subjectKind !== "everyone" && p.subjectRef.length === 0) c.addIssue({ code: "custom", path: ["subjectRef"], message: `must name at least one ${p.subjectKind === "users" ? "user" : p.subjectKind}` });
  });
export type PolicyConfig = z.infer<typeof policyInput>;

export const issuesOf = (e: z.ZodError) => e.issues.map((i) => `${i.path.join(".") || "(root)"}: ${i.message}`);

const truthy = (v: unknown) => v === true || v === 1 || v === "1" || v === "true";

function json(v: unknown): unknown {
  if (typeof v !== "string") return v;
  try {
    return JSON.parse(v);
  } catch {
    return undefined;
  }
}

const dateOf = (v: unknown) => (v instanceof Date ? v : typeof v === "string" || typeof v === "number" ? new Date(v) : null);

interface Stamps {
  createdBy: string | null;
  updatedBy: string | null;
  createdAt: Date | null;
  updatedAt: Date | null;
}
const stamps = (row: Record<string, unknown>): Stamps => ({
  createdBy: typeof row.createdBy === "string" ? row.createdBy : null,
  updatedBy: typeof row.updatedBy === "string" ? row.updatedBy : null,
  createdAt: dateOf(row.createdAt),
  updatedAt: dateOf(row.updatedAt),
});

export interface ResourceServerRecord extends Stamps {
  id: string;
  enabled: boolean;
  /** Re-validated on read: an invalid row is never used. */
  valid: boolean;
  issues: string[];
  /** The config, as stored (null when it didn't parse). */
  config: ResourceServerConfig | null;
}

export interface PolicyRecord extends Stamps {
  id: string;
  enabled: boolean;
  valid: boolean;
  issues: string[];
  config: PolicyConfig | null;
}

async function sha256b64url(input: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input)));
  let s = "";
  for (const b of digest) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** The unique key of a resource server: one audience per organization (plan §3.5). */
export const lookupKeyOf = (organizationId: string | undefined | null, audience: string) => sha256b64url(JSON.stringify(["id-jag-rs", organizationId ?? "", audience]));

export function resourceServerColumns(c: ResourceServerConfig) {
  return {
    audience: c.audience,
    name: c.name,
    resources: JSON.stringify(c.resources),
    scopes: JSON.stringify(c.scopes),
    clientIdsAtResource: JSON.stringify(c.clientIdsAtResource),
    requireResource: c.requireResource,
    organizationId: c.organizationId ?? null,
  };
}

export function policyColumns(c: PolicyConfig) {
  return {
    resourceServerId: c.resourceServerId,
    name: c.name,
    subjectKind: c.subjectKind,
    subjectRef: JSON.stringify(c.subjectRef),
    clientIds: JSON.stringify(c.clientIds),
    scopes: JSON.stringify(c.scopes),
    lifetimeSeconds: c.lifetimeSeconds ?? null,
    includeEmail: c.includeEmail,
  };
}

/** A stored resource-server row, re-validated: the same schema as the API, plus its key columns. */
export async function readResourceServer(row: Record<string, unknown>, o: { allowLoopbackHttp: boolean }): Promise<ResourceServerRecord> {
  const input = {
    audience: row.audience,
    name: row.name,
    resources: json(row.resources),
    scopes: json(row.scopes),
    clientIdsAtResource: json(row.clientIdsAtResource),
    requireResource: truthy(row.requireResource),
    ...(typeof row.organizationId === "string" && row.organizationId !== "" ? { organizationId: row.organizationId } : {}),
  };
  const parsed = resourceServerInput(o).safeParse(input);
  const issues = parsed.success ? [] : issuesOf(parsed.error);
  if (parsed.success) {
    // The audience column is matched exactly (a collation could widen a lookup) and must already be normalised.
    if (parsed.data.audience !== row.audience) issues.push("audience: not normalised (edited by hand?)");
    if ((await lookupKeyOf(parsed.data.organizationId, parsed.data.audience)) !== row.lookupKey) issues.push("lookupKey: doesn't match audience and organizationId (edited by hand?)");
  }
  return {
    id: String(row.id),
    enabled: truthy(row.enabled),
    valid: issues.length === 0,
    issues,
    config: parsed.success ? parsed.data : null,
    ...stamps(row),
  };
}

export function readPolicy(row: Record<string, unknown>): PolicyRecord {
  const input = {
    resourceServerId: row.resourceServerId,
    name: row.name,
    subjectKind: row.subjectKind,
    subjectRef: json(row.subjectRef),
    clientIds: json(row.clientIds),
    scopes: json(row.scopes),
    ...(row.lifetimeSeconds === null || row.lifetimeSeconds === undefined ? {} : { lifetimeSeconds: Number(row.lifetimeSeconds) }),
    includeEmail: truthy(row.includeEmail),
  };
  const parsed = policyInput.safeParse(input);
  const issues = parsed.success ? [] : issuesOf(parsed.error);
  return { id: String(row.id), enabled: truthy(row.enabled), valid: issues.length === 0, issues, config: parsed.success ? parsed.data : null, ...stamps(row) };
}
