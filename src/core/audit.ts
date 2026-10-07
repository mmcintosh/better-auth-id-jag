// What each side did, for hosts' audit trails and SIEMs: callbacks, and an optional table. The same
// design as better-auth-saml-idp's events (its D-038):
// - handlers are observers, never gates: they run through Better Auth's `runInBackground`
//   (`waitUntil` on Workers), a throw is logged and changes nothing;
// - refusals of an unauthenticated caller reach the handler but not the table, so the table can't
//   grow at an attacker's pace (the event says `authenticated: true` explicitly, set only after
//   client authentication succeeded);
// - the row is written before the handler runs: a handler can neither delay nor alter it;
// - every string a caller could have sent is made log-safe;
// - queryable fields are columns, the whole event is JSON in `details`, rows expire.
import type { BetterAuthPluginDBSchema, DBAdapter, GenericEndpointContext } from "better-auth";
import { getIPFromHeader } from "@better-auth/core/utils/ip";
import { logSafe, type ReasonCode } from "./errors";

export const AUDIT_MODEL = "idJagAudit";

interface EventBase {
  at: Date;
  ipAddress?: string | undefined;
  userAgent?: string | undefined;
}

/** The issuer minted an ID-JAG. */
export interface IssuedEvent extends EventBase {
  type: "id-jag.issued";
  userId: string;
  /** The requesting client at this IdP. */
  clientId: string;
  /** The `client_id` claim: the client's id at the resource authorization server. */
  clientIdAtResource: string;
  audience: string;
  resource?: string | undefined;
  scopes: string[];
  jti: string;
  expiresAt: Date;
  organizationId?: string | undefined;
}

/**
 * The issuer exchanged a SAML assertion it issued for a refresh token (draft -04 §4.5). Never the
 * token or the assertion: the assertion's ID and the SP it was issued to identify it.
 */
export interface RefreshIssuedEvent extends EventBase {
  type: "id-jag.refresh-issued";
  userId: string;
  /** The requesting client at this IdP: the refresh token's client. */
  clientId: string;
  /** The refresh token's scopes. */
  scopes: string[];
  /** The SAML SP (entity ID) the assertion was issued to. */
  spEntityId: string;
  /** The SAML assertion's ID. */
  assertionId: string;
}

/** The receiver accepted an ID-JAG and issued an access token. */
export interface AcceptedEvent extends EventBase {
  type: "id-jag.accepted";
  iss: string;
  sub: string;
  userId: string;
  clientId: string;
  resource?: string | undefined;
  scopes: string[];
  jti: string;
  organizationId?: string | undefined;
}

/** Either side refused. `reason` is ours; the caller only saw the public description. */
export interface RefusedEvent extends EventBase {
  type: "id-jag.refused";
  side: "issuer" | "receiver";
  reason: ReasonCode;
  /** True only once client authentication succeeded; only such refusals are stored. */
  authenticated: boolean;
  /** The authenticated client, or (when `authenticated` is false) the id the caller claimed. */
  clientId?: string | undefined;
  userId?: string | undefined;
  iss?: string | undefined;
  audience?: string | undefined;
  jti?: string | undefined;
  /** Log-safe, at most 300 characters. */
  detail?: string | undefined;
}

/** An administrator changed a policy, resource server or trusted issuer. */
export interface AdminChangedEvent extends EventBase {
  type: "id-jag.admin";
  actorUserId: string;
  action: "create" | "update" | "delete";
  target: "resource-server" | "policy" | "trusted-issuer" | "block";
  targetId: string;
}

export type IdJagEvent = IssuedEvent | RefreshIssuedEvent | AcceptedEvent | RefusedEvent | AdminChangedEvent;
export type EventInput = IdJagEvent extends infer E ? (E extends IdJagEvent ? Omit<E, keyof EventBase> : never) : never;

export interface IdJagEventHandlers {
  onIssued?: (e: IssuedEvent) => unknown;
  onRefreshIssued?: (e: RefreshIssuedEvent) => unknown;
  onAccepted?: (e: AcceptedEvent) => unknown;
  onRefused?: (e: RefusedEvent) => unknown;
  onAdminChanged?: (e: AdminChangedEvent) => unknown;
}

export interface AuditOptions {
  events?: IdJagEventHandlers | undefined;
  auditLog?: { retentionDays: number } | undefined;
}

const HANDLER = {
  "id-jag.issued": "onIssued",
  "id-jag.refresh-issued": "onRefreshIssued",
  "id-jag.accepted": "onAccepted",
  "id-jag.refused": "onRefused",
  "id-jag.admin": "onAdminChanged",
} as const satisfies Record<IdJagEvent["type"], keyof IdJagEventHandlers>;

/** Every audit event type (both plugins write to one table). */
export const AUDIT_EVENT_TYPES = Object.keys(HANDLER) as [IdJagEvent["type"], ...IdJagEvent["type"][]];

export function auditSchema() {
  return {
    [AUDIT_MODEL]: {
      fields: {
        type: { type: "string", required: true, input: false, index: true },
        at: { type: "date", required: true, input: false, index: true },
        side: { type: "string", required: false, input: false },
        reason: { type: "string", required: false, input: false },
        userId: { type: "string", required: false, input: false, index: true },
        clientId: { type: "string", required: false, input: false, index: true },
        iss: { type: "string", required: false, input: false },
        audience: { type: "string", required: false, input: false },
        jti: { type: "string", required: false, input: false },
        actorUserId: { type: "string", required: false, input: false },
        ipAddress: { type: "string", required: false, input: false },
        userAgent: { type: "string", required: false, input: false },
        details: { type: "string", required: true, input: false },
        expiresAt: { type: "date", required: true, input: false, index: true },
      },
    },
  } satisfies BetterAuthPluginDBSchema;
}

function clientIp(ctx: GenericEndpointContext): string | undefined {
  const opts = ctx.context.options as { advanced?: { ipAddress?: { disableIpTracking?: boolean; ipAddressHeaders?: string[]; ipv6Subnet?: number; trustedProxies?: string[] } } };
  const ip = opts.advanced?.ipAddress;
  if (ip?.disableIpTracking) return undefined;
  const headers = ctx.request?.headers ?? ctx.headers;
  for (const name of ip?.ipAddressHeaders ?? ["x-forwarded-for"]) {
    const value = headers?.get(name);
    if (!value) continue;
    const found = getIPFromHeader(value, { ...(ip?.ipv6Subnet !== undefined ? { ipv6Subnet: ip.ipv6Subnet } : {}), ...(ip?.trustedProxies ? { trustedProxies: ip.trustedProxies } : {}) });
    if (found) return logSafe(found, 64);
  }
  return undefined;
}

type Sink = {
  logger: { error(message: string, ...args: unknown[]): void };
  adapter: { create(a: { model: string; data: Record<string, unknown> }): Promise<unknown> };
  runInBackground(p: Promise<unknown>): void;
};

/** Every string (top level and in arrays) made log-safe; dates and numbers kept. */
function safeEvent<T extends Record<string, unknown>>(e: T): T {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(e)) out[k] = typeof v === "string" ? logSafe(v) : Array.isArray(v) ? v.map((x) => (typeof x === "string" ? logSafe(x) : x)) : v;
  return out as T;
}

/** Hand the event to its handler and the audit table, in the background. Never throws. */
export function emit(ctx: GenericEndpointContext, options: AuditOptions, event: EventInput): void {
  const userAgent = (ctx.request?.headers ?? ctx.headers)?.get("user-agent");
  const full = safeEvent({ ...event, at: new Date(), ipAddress: clientIp(ctx), userAgent: userAgent ?? undefined }) as IdJagEvent;
  deliver(ctx.context as unknown as Sink, options, full);
}

function deliver(sink: Sink, options: AuditOptions, full: IdJagEvent): void {
  const name = HANDLER[full.type];
  const handler = options.events?.[name] as ((e: IdJagEvent) => unknown) | undefined;
  const audit = options.auditLog && !(full.type === "id-jag.refused" && full.authenticated !== true);
  if (!handler && !audit) return;
  const run = async () => {
    // The row first: a handler that never settles (or mutates its event) can't touch it.
    if (audit && options.auditLog) {
      try {
        await sink.adapter.create({ model: AUDIT_MODEL, data: auditRow(full, options.auditLog.retentionDays) });
      } catch (e) {
        sink.logger.error(`[id-jag] could not write the audit log (${full.type})`, e);
      }
    }
    if (handler) {
      try {
        await handler(full);
      } catch (e) {
        sink.logger.error(`[id-jag] events.${name} threw`, e);
      }
    }
  };
  sink.runInBackground(run());
}

/** Deletes audit rows past their retention. Run it from the same scheduled job as `sweepJtis`. */
export async function sweepAudit(adapter: Pick<DBAdapter, "deleteMany">, now = new Date()): Promise<void> {
  await adapter.deleteMany({ model: AUDIT_MODEL, where: [{ field: "expiresAt", value: now, operator: "lt" }] });
}

/** The table row: indexed columns for querying, the rest of the event as JSON. */
export function auditRow(event: IdJagEvent, retentionDays: number) {
  const { type, at, ipAddress, userAgent, ...rest } = event;
  const pick = (k: string) => {
    const v = (rest as Record<string, unknown>)[k];
    return typeof v === "string" ? v : null;
  };
  // A refresh token from a SAML assertion: the assertion's Audience (the SP's entity ID) and its
  // ID are what identify it, so they fill the audience and jti columns, and can be queried.
  const refresh = type === "id-jag.refresh-issued";
  return {
    type,
    at,
    side: pick("side"),
    reason: pick("reason"),
    userId: pick("userId"),
    clientId: pick("clientId"),
    iss: pick("iss"),
    audience: pick(refresh ? "spEntityId" : "audience"),
    jti: pick(refresh ? "assertionId" : "jti"),
    actorUserId: pick("actorUserId"),
    ipAddress: ipAddress ?? null,
    userAgent: userAgent ?? null,
    details: JSON.stringify(rest),
    expiresAt: new Date(at.getTime() + retentionDays * 86_400_000),
  };
}
