// The receiver's options: typed for hosts, validated with zod at startup (a typo or an unsafe value
// is a configuration error, not a silently ignored key), and resolved once into the state the grant
// handler uses (the JWKS cache, the clock, the sweep throttle).
import type { GenericEndpointContext } from "better-auth";
import { z } from "zod";
import type { AuditOptions, IdJagClaims } from "../core";
import { lifetimeOption, skewOption } from "../core";
import { type FetchLike, JwksCache, type JwksSettings } from "./jwks";

/** A trusted issuer configured in code (plan §3.4 step 3). */
export interface StaticTrustedIssuer {
  /** The exact `iss` of its ID-JAGs. */
  issuer: string;
  /** Its JWKS (https). One of `jwksUri` or `discoveryUri` is required. */
  jwksUri?: string;
  /** Its OpenID / RFC 8414 metadata document (https); its `issuer` must equal `issuer` exactly. */
  discoveryUri?: string;
  /**
   * Recorded on the accepted event and passed to `resolveSubject`. With JIT provisioning and the
   * organization plugin, a user JIT creates becomes a member of it (with `jitRole`).
   */
  organizationId?: string;
  /** If set, only these clients (their id here) may present this issuer's ID-JAGs. */
  allowedClientIds?: string[];
  /** If set, the ID-JAG's `tenant` claim must equal it (multi-tenant IdPs). */
  tenant?: string;
  /** `providerId` of the accounts that link a local user to this issuer's `sub`. Default `id-jag:<issuer>`. */
  accountProviderId?: string;
  /** Match an unlinked subject by its `email` claim, only for these domains (exact, lowercase). Off when absent. */
  emailFallback?: { domains: string[] };
  /** Create a user for an unknown subject. Off by default. */
  jitProvisioning?: boolean | { trustEmailVerified?: boolean };
  /** The organization role of a user JIT creates (needs `organizationId`). Default "member". */
  jitRole?: string;
}

/** Trust the OIDC providers registered in `@better-auth/sso` (opt-in). */
export interface SsoTrustOptions {
  /** Only these sso `providerId`s. Default: every OIDC provider. */
  providerIds?: string[];
  /** Email fallback for providers whose domain is verified (`domainVerified`). Default false. */
  emailFallback?: boolean;
  jitProvisioning?: boolean | { trustEmailVerified?: boolean };
  allowedClientIds?: string[];
}

export type SubjectResolution = { action: "link"; userId: string } | { action: "continue" } | { action: "reject" };

/** What a host's `resolveSubject` hook sees. Runs before the default resolution. */
export interface ResolveSubjectInput {
  ctx: GenericEndpointContext;
  iss: string;
  sub: string;
  claims: IdJagClaims;
  /** The authenticated client's id. */
  clientId: string;
  trustedIssuer: TrustedIssuerView;
}

/** The trust entry an ID-JAG was accepted under, as hooks and events see it. */
export interface TrustedIssuerView {
  source: "static" | "sso" | "table";
  /** The sso providerId, the table row id, or the issuer for static entries. */
  id: string;
  issuer: string;
  organizationId?: string | undefined;
  accountProviderId: string;
}

export interface IdJagGrantOptions extends AuditOptions {
  trustedIssuers?: StaticTrustedIssuer[];
  /** `true` or settings: trust `@better-auth/sso` OIDC providers too. Default off. */
  sso?: boolean | SsoTrustOptions;
  /** Also read trusted issuers from the `idJagTrustedIssuer` table (adds the table). Default false. */
  trustedIssuerTable?: boolean;
  resolveSubject?: (input: ResolveSubjectInput) => SubjectResolution | Promise<SubjectResolution>;
  /** The resource used when neither the ID-JAG nor the request names one. Must be a registered resource. */
  defaultResource?: string;
  /** Accept public clients (the draft: SHOULD be confidential only). Default false; logs a warning when set. */
  allowPublicClients?: boolean;
  /** Issue a token with no scope when the intersection is empty, instead of `invalid_scope`. Default false. */
  allowEmptyScope?: boolean;
  /** Refuse an ID-JAG without a `resource` claim (public `missing_claim`). Default false (D-A06). */
  requireResourceClaim?: boolean;
  clockSkewSeconds?: number;
  maxLifetimeSeconds?: number;
  /** The only fetch the receiver uses (JWKS and discovery of trusted issuers). Default: global fetch. */
  fetch?: FetchLike;
  /**
   * JWKS fetching and caching. `maxStaleSeconds` (default 3600): while the issuer's JWKS can't be
   * fetched, cached keys are used for at most this long past `cacheTtlSeconds`; then refused.
   */
  jwks?: { timeoutMs?: number; maxBytes?: number; cacheTtlSeconds?: number; minRefetchIntervalSeconds?: number; maxStaleSeconds?: number };
  /** The receiver's clock. For tests. */
  clock?: () => Date;
}

const fn = z.custom<(...args: never[]) => unknown>((v) => typeof v === "function", "must be a function");
const httpsUrl = z.string().refine((s) => {
  try {
    const u = new URL(s);
    return u.protocol === "https:" && !u.username && !u.password && !u.hash;
  } catch {
    return false;
  }
}, "must be an absolute https URL without credentials or fragment");
const id = z.string().min(1).max(2048);
const jit = z.union([z.boolean(), z.strictObject({ trustEmailVerified: z.boolean().optional() })]);

const staticIssuer = z
  .strictObject({
    issuer: id,
    jwksUri: httpsUrl.optional(),
    discoveryUri: httpsUrl.optional(),
    organizationId: id.optional(),
    allowedClientIds: z.array(id).min(1).optional(),
    tenant: id.optional(),
    accountProviderId: id.optional(),
    emailFallback: z.strictObject({ domains: z.array(z.string().min(1).max(253)).min(1) }).optional(),
    jitProvisioning: jit.optional(),
    jitRole: z.string().min(1).max(256).optional(),
  })
  .refine((t) => t.jwksUri !== undefined || t.discoveryUri !== undefined, "jwksUri or discoveryUri is required")
  .refine((t) => t.jitRole === undefined || t.organizationId !== undefined, "jitRole needs organizationId");

const optionsSchema = z.strictObject({
  trustedIssuers: z.array(staticIssuer).optional(),
  sso: z
    .union([
      z.boolean(),
      z.strictObject({ providerIds: z.array(id).min(1).optional(), emailFallback: z.boolean().optional(), jitProvisioning: jit.optional(), allowedClientIds: z.array(id).min(1).optional() }),
    ])
    .optional(),
  trustedIssuerTable: z.boolean().optional(),
  resolveSubject: fn.optional(),
  defaultResource: id.optional(),
  allowPublicClients: z.boolean().optional(),
  allowEmptyScope: z.boolean().optional(),
  requireResourceClaim: z.boolean().optional(),
  clockSkewSeconds: z.number().optional(),
  maxLifetimeSeconds: z.number().optional(),
  fetch: fn.optional(),
  jwks: z
    .strictObject({
      timeoutMs: z.number().int().min(100).max(30_000).optional(),
      maxBytes: z.number().int().min(1024).max(1024 * 1024).optional(),
      cacheTtlSeconds: z.number().int().min(0).max(86_400).optional(),
      minRefetchIntervalSeconds: z.number().int().min(1).max(3600).optional(),
      maxStaleSeconds: z.number().int().min(0).optional(),
    })
    .optional(),
  clock: fn.optional(),
  events: z.strictObject({ onIssued: fn.optional(), onAccepted: fn.optional(), onRefused: fn.optional(), onAdminChanged: fn.optional() }).optional(),
  auditLog: z.strictObject({ retentionDays: z.number().int().min(1).max(3650) }).optional(),
});

/** A trust entry from any source, normalised. */
export interface TrustEntry extends TrustedIssuerView {
  jwksUri?: string | undefined;
  discoveryUri?: string | undefined;
  allowedClientIds?: string[] | undefined;
  tenant?: string | undefined;
  /** Email fallback domains (lowercase); null = no email fallback. */
  emailDomains: string[] | null;
  jit: false | { trustEmailVerified: boolean };
  /** The role for JIT membership (static and table entries); sso entries use sso's own setting. */
  jitRole?: string | undefined;
}

export interface ResolvedSsoTrust {
  providerIds?: string[] | undefined;
  emailFallback: boolean;
  jit: false | { trustEmailVerified: boolean };
  allowedClientIds?: string[] | undefined;
}

export interface ResolvedReceiverOptions {
  options: IdJagGrantOptions;
  trustedIssuers: TrustEntry[];
  sso: ResolvedSsoTrust | null;
  trustedIssuerTable: boolean;
  clockSkewSeconds: number;
  maxLifetimeSeconds: number;
  allowPublicClients: boolean;
  allowEmptyScope: boolean;
  requireResourceClaim: boolean;
  defaultResource?: string | undefined;
  resolveSubject?: IdJagGrantOptions["resolveSubject"];
  audit: AuditOptions;
  jwks: JwksCache;
  clock: () => Date;
  /** Opportunistic sweeps: at most one per interval per instance. */
  sweep: { lastAt: number; intervalMs: number };
}

export const defaultAccountProviderId = (issuer: string) => `id-jag:${issuer}`;

export function jitOption(v: boolean | { trustEmailVerified?: boolean } | undefined): false | { trustEmailVerified: boolean } {
  if (!v) return false;
  return { trustEmailVerified: v === true ? false : v.trustEmailVerified === true };
}

/** Validates the options (throws on any defect) and builds the receiver's state. */
export function resolveReceiverOptions(options: IdJagGrantOptions = {}): ResolvedReceiverOptions {
  const parsed = optionsSchema.safeParse(options);
  if (!parsed.success) throw new Error(`id-jag receiver: invalid options: ${parsed.error.issues.map((i) => `${i.path.join(".") || "(root)"}: ${i.message}`).join("; ")}`);
  const clockSkewSeconds = skewOption(options.clockSkewSeconds);
  const maxLifetimeSeconds = lifetimeOption(options.maxLifetimeSeconds);
  const seen = new Set<string>();
  const trustedIssuers: TrustEntry[] = (options.trustedIssuers ?? []).map((t) => {
    const key = `${t.issuer}\u0000${t.tenant ?? ""}`;
    if (seen.has(key)) throw new Error(`id-jag receiver: trusted issuer listed twice: ${t.issuer}`);
    seen.add(key);
    return {
      source: "static",
      id: t.issuer,
      issuer: t.issuer,
      jwksUri: t.jwksUri,
      discoveryUri: t.discoveryUri,
      organizationId: t.organizationId,
      allowedClientIds: t.allowedClientIds,
      tenant: t.tenant,
      accountProviderId: t.accountProviderId ?? defaultAccountProviderId(t.issuer),
      emailDomains: t.emailFallback ? t.emailFallback.domains.map((d) => d.toLowerCase()) : null,
      jit: jitOption(t.jitProvisioning),
      jitRole: t.jitRole,
    };
  });
  const sso = options.sso === undefined || options.sso === false ? null : options.sso === true ? {} : options.sso;
  const settings: JwksSettings = {
    timeoutMs: options.jwks?.timeoutMs ?? 5000,
    maxBytes: options.jwks?.maxBytes ?? 64 * 1024,
    cacheTtlMs: (options.jwks?.cacheTtlSeconds ?? 600) * 1000,
    minRefetchMs: (options.jwks?.minRefetchIntervalSeconds ?? 60) * 1000,
    maxStaleMs: (options.jwks?.maxStaleSeconds ?? 3600) * 1000,
  };
  const clock = options.clock ?? (() => new Date());
  const fetchImpl: FetchLike = options.fetch ?? ((input, init) => fetch(input, init));
  return {
    options,
    trustedIssuers,
    sso: sso && { providerIds: sso.providerIds, emailFallback: sso.emailFallback === true, jit: jitOption(sso.jitProvisioning), allowedClientIds: sso.allowedClientIds },
    trustedIssuerTable: options.trustedIssuerTable === true,
    clockSkewSeconds,
    maxLifetimeSeconds,
    allowPublicClients: options.allowPublicClients === true,
    allowEmptyScope: options.allowEmptyScope === true,
    requireResourceClaim: options.requireResourceClaim === true,
    defaultResource: options.defaultResource,
    resolveSubject: options.resolveSubject,
    audit: { ...(options.events ? { events: options.events } : {}), ...(options.auditLog ? { auditLog: options.auditLog } : {}) },
    jwks: new JwksCache(fetchImpl, settings, () => clock().getTime()),
    clock,
    sweep: { lastAt: 0, intervalMs: 60_000 },
  };
}
