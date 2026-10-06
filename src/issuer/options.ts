// The issuer's options: their types, and their validation at startup (zod), so a typo or an
// out-of-range number is a configuration error, not a silently switched-off check.
import type { GenericEndpointContext, User } from "better-auth";
import { z } from "zod";
import type { AuditOptions } from "../core";
import { DEFAULT_LIFETIME_SECONDS, MAX_LIFETIME_SECONDS } from "../core";

type Awaitable<T> = T | Promise<T>;

/** Signing algorithms the issuer may be told to use: what this package's receiver (and most) accept. */
export const ISSUER_SIGNING_ALGORITHMS = ["RS256", "ES256", "EdDSA"] as const;
export type IssuerSigningAlgorithm = (typeof ISSUER_SIGNING_ALGORITHMS)[number];

/** The requesting client, as the policy sees it. */
export interface PolicyClient {
  /** Its id at this IdP. */
  clientId: string;
  name?: string | undefined;
  /** The provider's `referenceId` (e.g. an organization that owns the client), when set. */
  referenceId?: string | undefined;
  metadata?: Record<string, unknown> | undefined;
}

/**
 * What the subject token said about the authentication, carried into the ID-JAG. For a refresh
 * token: `auth_time` as the provider stored it, no `acr`/`amr` (not stored), and `raw` holds
 * `{ token_type, client_id, scope, iat, exp }` (never the token or its hash).
 */
export interface SubjectTokenClaims {
  /** Which kind of subject token was exchanged (its RFC 8693 token type URN). */
  tokenType: "urn:ietf:params:oauth:token-type:id_token" | "urn:ietf:params:oauth:token-type:refresh_token";
  sub: string;
  auth_time?: number | undefined;
  acr?: string | undefined;
  amr?: string[] | undefined;
  /** Every claim of the verified ID token (or the refresh token's summary above), for hosts that need more. */
  raw: Record<string, unknown>;
}

/** Input of the `authorize` hook (the same role as better-auth-saml-idp's per-SP `authorize`). */
export interface AuthorizeInput {
  ctx: GenericEndpointContext;
  /** The user, as the database has it now. */
  user: User & Record<string, unknown>;
  client: PolicyClient;
  /** The resource authorization server's issuer identifier (normalised). */
  audience: string;
  /** The RFC 8707 resource, when the client sent one. */
  resource?: string | undefined;
  /** The scopes the client asked for (empty: it asked for none). */
  requestedScopes: string[];
  subjectToken: SubjectTokenClaims;
}

export interface AuthorizeAllow {
  decision: "allow";
  /** The most this source allows. The ID-JAG gets these ∩ the requested ones (when any were requested). */
  scopes: string[];
  /** Only when the client sent no `resource`; otherwise it must equal the one it sent. */
  resource?: string | undefined;
  /** At most 900 (S7); shorter wins when several sources allow. */
  lifetimeSeconds?: number | undefined;
  /** The client's id at the resource authorization server (D-004). Default: its id here. */
  clientIdAtResource?: string | undefined;
  claims?: { email?: boolean | undefined; tenant?: string | undefined } | undefined;
}

export interface AuthorizeDeny {
  decision: "deny";
  /** For the audit log only (log-safe there); never sent to the caller. */
  reason?: string | undefined;
}

export type AuthorizeResult = AuthorizeAllow | AuthorizeDeny;

export interface RegistryOptions {
  enabled: boolean;
  /**
   * Who may manage the registry and the blocks over the API. Without it the API isn't mounted (the
   * tables are still used). With `enabled: false`, only the blocks and audit routes are mounted.
   * Must return exactly `true`; a throw denies.
   */
  canManage?: ((input: { user: User & Record<string, unknown>; session: Record<string, unknown> }) => Awaitable<boolean>) | undefined;
  /** Per-isolate cache of looked-up audiences (hits and misses). Default 60; 0 turns it off. */
  cacheSeconds?: number | undefined;
}

export interface IdJagIssuerOptions extends AuditOptions {
  /** Code policy. With `registry` too, both must allow and the narrower outcome wins. */
  authorize?: ((input: AuthorizeInput) => Awaitable<AuthorizeResult>) | undefined;
  /** Database policy: resource servers and policies, with an admin API. */
  registry?: RegistryOptions | undefined;
  /**
   * The draft: "SHOULD only be supported for confidential clients". Off by default (S5); turning
   * it on logs a warning at startup.
   */
  allowPublicClients?: boolean | undefined;
  /**
   * The JWS algorithm of the ID-JAG. Default: the jwt plugin's configured one. It must be the jwt
   * plugin's `keyPairConfig.alg` or one of its `keyPairConfigs`. EdDSA may not interoperate with
   * some receivers (several accept RS256 and ES256 only).
   */
  signingAlgorithm?: IssuerSigningAlgorithm | undefined;
  /** When neither source sets a lifetime. Default 300, at most 900 (S7). */
  defaultLifetimeSeconds?: number | undefined;
  /**
   * Allow `http://` audiences on loopback hosts (localhost, 127.0.0.1, [::1]), for local
   * development. Off by default: audiences are https.
   */
  allowLoopbackHttpAudiences?: boolean | undefined;
  /** Seconds between opportunistic sweeps of expired jti and audit rows, per isolate. Default 3600; 0 never. */
  sweepIntervalSeconds?: number | undefined;
}

const fn = z.custom<(...args: never[]) => unknown>((v) => typeof v === "function", "must be a function");
const intIn = (min: number, max: number) => z.number().int().min(min).max(max);

const optionsSchema = z.strictObject({
  authorize: fn.optional(),
  registry: z
    .strictObject({
      enabled: z.boolean(),
      canManage: fn.optional(),
      cacheSeconds: intIn(0, 3600).optional(),
    })
    .optional(),
  allowPublicClients: z.boolean().optional(),
  signingAlgorithm: z.enum(ISSUER_SIGNING_ALGORITHMS).optional(),
  defaultLifetimeSeconds: intIn(1, MAX_LIFETIME_SECONDS).optional(),
  allowLoopbackHttpAudiences: z.boolean().optional(),
  sweepIntervalSeconds: intIn(0, 7 * 86_400).optional(),
  events: z
    .strictObject({ onIssued: fn.optional(), onAccepted: fn.optional(), onRefused: fn.optional(), onAdminChanged: fn.optional() })
    .optional(),
  auditLog: z.strictObject({ retentionDays: intIn(1, 3650) }).optional(),
});

/** Options after validation, with defaults filled in. */
export interface ResolvedIssuerOptions extends IdJagIssuerOptions {
  defaultLifetimeSeconds: number;
  allowPublicClients: boolean;
  allowLoopbackHttpAudiences: boolean;
  sweepIntervalSeconds: number;
  registryEnabled: boolean;
  cacheSeconds: number;
}

/** Validates the options (throws with every issue) and fills in defaults. */
export function resolveIssuerOptions(options: IdJagIssuerOptions = {}): ResolvedIssuerOptions {
  const parsed = optionsSchema.safeParse(options);
  if (!parsed.success) {
    const issues = parsed.error.issues.map((i) => `${i.path.join(".") || "(options)"}: ${i.message}`).join("; ");
    throw new Error(`idJagIssuer: invalid options: ${issues}`);
  }
  return {
    ...options,
    defaultLifetimeSeconds: options.defaultLifetimeSeconds ?? DEFAULT_LIFETIME_SECONDS,
    allowPublicClients: options.allowPublicClients ?? false,
    allowLoopbackHttpAudiences: options.allowLoopbackHttpAudiences ?? false,
    sweepIntervalSeconds: options.sweepIntervalSeconds ?? 3600,
    registryEnabled: options.registry?.enabled === true,
    cacheSeconds: options.registry?.cacheSeconds ?? 60,
  };
}
