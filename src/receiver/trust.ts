// Which issuer an ID-JAG claims to come from, and whether we trust it (plan §3.4 step 3). The
// lookup uses the **unverified** `iss` (Okta's resource-app guide: bind the issuer first, then
// verify with its keys). Sources, union, each optional:
// - static `trustedIssuers` in code;
// - `@better-auth/sso` OIDC providers (opt-in), read through `ctx.context.adapter`;
// - the `idJagTrustedIssuer` table (opt-in).
// No match is `untrusted_issuer`; more than one match is refused too (an ambiguous configuration
// must not pick keys or account links by accident). There is no "trust any issuer whose JWKS we
// can fetch" (S1).
import type { GenericEndpointContext } from "better-auth";
import { z } from "zod";
import { type IdJagClaims, refuse } from "../core";
import { defaultAccountProviderId, normaliseSamlSubjects, type ResolvedReceiverOptions, samlSubjectSchema, type TrustEntry } from "./options";
import { TRUSTED_ISSUER_MODEL } from "./schema";

const MAX_ROWS = 10;

const oidcConfigSchema = z.looseObject({
  issuer: z.string().optional(),
  jwksEndpoint: z.string().optional(),
  discoveryEndpoint: z.string().optional(),
});
const ssoRowSchema = z.looseObject({
  providerId: z.string().min(1),
  issuer: z.string().min(1),
  domain: z.string().optional().nullable(),
  domainVerified: z.boolean().optional().nullable(),
  organizationId: z.string().optional().nullable(),
  oidcConfig: z.union([z.string(), z.record(z.string(), z.unknown())]).optional().nullable(),
});
const jsonList = z
  .string()
  .nullable()
  .optional()
  .transform((s, ctx) => {
    if (s === null || s === undefined) return null;
    try {
      const v = z.array(z.string().min(1)).min(1).parse(JSON.parse(s));
      return v;
    } catch {
      ctx.addIssue({ code: "custom", message: "not a JSON array of strings" });
      return z.NEVER;
    }
  });
const tableRowSchema = z.looseObject({
  id: z.union([z.string(), z.number()]).transform(String),
  issuer: z.string().min(1),
  jwksUri: z.string().nullable().optional(),
  discoveryUri: z.string().nullable().optional(),
  ssoProviderId: z.string().nullable().optional(),
  allowedClientIds: jsonList,
  emailDomains: jsonList,
  jitProvisioning: z.union([z.boolean(), z.number()]).transform(Boolean),
  jitTrustEmailVerified: z.union([z.boolean(), z.number()]).transform(Boolean).optional(),
  jitRole: z.string().min(1).max(256).nullable().optional(),
  samlSubjects: z
    .string()
    .nullable()
    .optional()
    .transform((s, ctx) => {
      if (s === null || s === undefined) return null;
      try {
        return z.array(samlSubjectSchema).min(1).max(100).parse(JSON.parse(s));
      } catch {
        ctx.addIssue({ code: "custom", message: "not a JSON array of samlSubjects mappings" });
        return z.NEVER;
      }
    }),
  requireSubId: z.union([z.boolean(), z.number()]).nullable().optional().transform((v) => v === true || v === 1),
  tenant: z.string().nullable().optional(),
  organizationId: z.string().nullable().optional(),
});

const orUndef = <T>(v: T | null | undefined): T | undefined => (v === null ? undefined : v);

/** The well-known OpenID configuration URL of an issuer (OIDC Discovery §4). */
export function openIdConfigurationUrl(issuer: string): string {
  return `${issuer.replace(/\/+$/, "")}/.well-known/openid-configuration`;
}

async function fromSso(ctx: GenericEndpointContext, o: ResolvedReceiverOptions, iss: string): Promise<TrustEntry[]> {
  if (!o.sso || !ctx.context.hasPlugin("sso")) return [];
  const sso = o.sso;
  const rows = await ctx.context.adapter.findMany<Record<string, unknown>>({ model: "ssoProvider", where: [{ field: "issuer", value: iss }], limit: MAX_ROWS });
  const out: TrustEntry[] = [];
  for (const raw of rows) {
    const row = ssoRowSchema.safeParse(raw);
    if (!row.success || row.data.issuer !== iss) continue;
    if (sso.providerIds && !sso.providerIds.includes(row.data.providerId)) continue;
    // OIDC providers only: a SAML provider's `issuer` is an entity ID, not an ID-JAG issuer.
    if (!row.data.oidcConfig) continue;
    let config: z.infer<typeof oidcConfigSchema>;
    try {
      const parsed = oidcConfigSchema.safeParse(typeof row.data.oidcConfig === "string" ? JSON.parse(row.data.oidcConfig) : row.data.oidcConfig);
      if (!parsed.success) continue;
      config = parsed.data;
    } catch {
      continue;
    }
    if (config.issuer !== undefined && config.issuer !== iss) continue;
    const domains = sso.emailFallback && row.data.domainVerified === true && row.data.domain ? row.data.domain.split(",").map((d) => d.trim().toLowerCase()).filter(Boolean) : null;
    out.push({
      source: "sso",
      id: row.data.providerId,
      issuer: iss,
      jwksUri: config.jwksEndpoint,
      discoveryUri: config.jwksEndpoint ? undefined : (config.discoveryEndpoint ?? openIdConfigurationUrl(iss)),
      organizationId: orUndef(row.data.organizationId),
      allowedClientIds: sso.allowedClientIds,
      accountProviderId: row.data.providerId,
      emailDomains: domains && domains.length > 0 ? domains : null,
      jit: sso.jit,
    });
  }
  return out;
}

async function fromTable(ctx: GenericEndpointContext, o: ResolvedReceiverOptions, iss: string): Promise<TrustEntry[]> {
  if (!o.trustedIssuerTable) return [];
  const rows = await ctx.context.adapter.findMany<Record<string, unknown>>({
    model: TRUSTED_ISSUER_MODEL,
    where: [
      { field: "issuer", value: iss },
      { field: "enabled", value: true },
    ],
    limit: MAX_ROWS,
  });
  const out: TrustEntry[] = [];
  for (const raw of rows) {
    const row = tableRowSchema.safeParse(raw);
    if (!row.success) {
      ctx.context.logger.warn(`[id-jag] ignoring an invalid ${TRUSTED_ISSUER_MODEL} row`);
      continue;
    }
    const r = row.data;
    if (r.issuer !== iss) continue;
    const accountProviderId = orUndef(r.ssoProviderId) ?? defaultAccountProviderId(iss);
    const samlSubjects = r.samlSubjects ? normaliseSamlSubjects(r.samlSubjects, accountProviderId) : null;
    if (typeof samlSubjects === "string" || (r.requireSubId && !samlSubjects)) {
      ctx.context.logger.warn(`[id-jag] ignoring an invalid ${TRUSTED_ISSUER_MODEL} row (${typeof samlSubjects === "string" ? samlSubjects : "requireSubId needs samlSubjects"})`);
      continue;
    }
    out.push({
      source: "table",
      id: r.id,
      issuer: iss,
      jwksUri: orUndef(r.jwksUri),
      discoveryUri: r.jwksUri ? undefined : (orUndef(r.discoveryUri) ?? openIdConfigurationUrl(iss)),
      organizationId: orUndef(r.organizationId),
      allowedClientIds: r.allowedClientIds ?? undefined,
      tenant: orUndef(r.tenant),
      accountProviderId,
      emailDomains: r.emailDomains ? r.emailDomains.map((d) => d.toLowerCase()) : null,
      jit: r.jitProvisioning ? { trustEmailVerified: r.jitTrustEmailVerified === true } : false,
      jitRole: orUndef(r.jitRole),
      samlSubjects,
      requireSubId: r.requireSubId,
    });
  }
  return out;
}

/** The one trust entry for this ID-JAG's (unverified) `iss` and `tenant`, or a refusal. */
export async function findTrustedIssuer(ctx: GenericEndpointContext, o: ResolvedReceiverOptions, claims: Pick<IdJagClaims, "iss" | "tenant">): Promise<TrustEntry> {
  const iss = claims.iss;
  const candidates = [...o.trustedIssuers.filter((t) => t.issuer === iss), ...(await fromSso(ctx, o, iss)), ...(await fromTable(ctx, o, iss))].filter(
    (t) => t.tenant === undefined || t.tenant === claims.tenant,
  );
  if (candidates.length === 0) refuse("untrusted_issuer", iss);
  if (candidates.length > 1) {
    ctx.context.logger.warn(`[id-jag] ${candidates.length} trust entries match one issuer (${candidates.map((c) => `${c.source}:${c.id}`).join(", ")}); refusing`);
    refuse("untrusted_issuer", `ambiguous: ${candidates.length} trust entries for ${iss}`);
  }
  return candidates[0] as TrustEntry;
}
