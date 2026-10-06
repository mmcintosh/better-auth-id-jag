// The registry's management API (better-auth-saml-idp D-027's pattern), the blocks API and the
// audit API. Each has its own access decision (D-B24): the registry's routes are mounted with
// `registry.canManage` (and `registry.enabled`), the blocks routes with `blocks.canManage`, the
// audit route with either, and allowed by either. Every route:
// - needs an authoritative session (`sensitiveSessionMiddleware` reads it from the database, so a
//   demoted administrator loses access at once, cookie cache or not);
// - refuses impersonated sessions, and banned users;
// - asks `canManage` about the user as the database has it now: only `true` allows, a throw denies;
// - keeps Better Auth's origin check on mutations (no skipOriginCheck).
// Every change is logged and emitted as `id-jag.admin` with the acting user. UNIQUE columns
// decide create races; reads only classify the failure.
import type { GenericEndpointContext, User } from "better-auth";
import { APIError, createAuthEndpoint, sensitiveSessionMiddleware } from "better-auth/api";
import { z } from "zod";
import { AUDIT_MODEL, type AdminChangedEvent, emit, JTI_MODEL, jtiKey } from "../core";
import { type BlockConfig, blockColumns, blockInput, readBlock } from "./blocks";
import { type IssuerState, issuerOf } from "./exchange";
import type { CanManage } from "./options";
import {
  issuesOf,
  lookupKeyOf,
  type PolicyRecord,
  policyColumns,
  policyInput,
  readPolicy,
  readResourceServer,
  type ResourceServerRecord,
  resourceServerColumns,
  resourceServerInput,
} from "./records";
import { BLOCK_MODEL, POLICY_MODEL, RESOURCE_SERVER_MODEL } from "./schema";

const MAX_LIST = 1000;
const MAX_AUDIT = 500;
const MAX_BODY_BYTES = 256 * 1024;

export const ID_JAG_REGISTRY_ERROR_CODES = {
  NOT_ALLOWED: { code: "ID_JAG_REGISTRY_NOT_ALLOWED", message: "You may not manage ID-JAG policies." },
  INVALID: { code: "ID_JAG_INVALID_RECORD", message: "The record is invalid." },
  NOT_FOUND: { code: "ID_JAG_NOT_FOUND", message: "Not found." },
  EXISTS: { code: "ID_JAG_RESOURCE_SERVER_EXISTS", message: "A resource server with this audience already exists (in this organization)." },
  HAS_POLICIES: { code: "ID_JAG_RESOURCE_SERVER_HAS_POLICIES", message: "Delete the resource server's policies first." },
} as const;

const fail = (status: "FORBIDDEN" | "BAD_REQUEST" | "CONFLICT" | "NOT_FOUND", code: keyof typeof ID_JAG_REGISTRY_ERROR_CODES, extra: Record<string, unknown> = {}) =>
  new APIError(status, { ...ID_JAG_REGISTRY_ERROR_CODES[code], ...extra });

const truthy = (v: unknown) => v === true || v === 1 || v === "1" || v === "true";
const isBanned = (user: Record<string, unknown>) => {
  if (!truthy(user.banned)) return false;
  const exp = user.banExpires;
  if (exp === null || exp === undefined) return true;
  const t = exp instanceof Date ? exp.getTime() : new Date(exp as string | number).getTime();
  return Number.isNaN(t) || t > Date.now();
};

/** Which access decision a route asks: the registry's, the blocks', or (the audit log) either. */
type Area = "registry" | "blocks" | "audit";

/** The configured `canManage` decisions for an area: any one answering exactly `true` allows. */
function deciders(state: IssuerState, area: Area): { name: string; canManage: CanManage }[] {
  const registry = state.options.registry?.canManage;
  const blocks = state.options.blocks?.canManage;
  const all = [
    ...(registry && area !== "blocks" ? [{ name: "registry.canManage", canManage: registry }] : []),
    ...(blocks && area !== "registry" ? [{ name: "blocks.canManage", canManage: blocks }] : []),
  ];
  return all;
}

/** The acting administrator, or a 403. */
async function actor(ctx: GenericEndpointContext, state: IssuerState, area: Area): Promise<{ id: string }> {
  const asked = deciders(state, area);
  const s = (ctx.context as { session?: { user: { id: string }; session: Record<string, unknown> } | null }).session;
  if (!s || asked.length === 0) throw fail("FORBIDDEN", "NOT_ALLOWED");
  // An administrator acting as another user must not manage policies under that identity.
  if (s.session.impersonatedBy) throw fail("FORBIDDEN", "NOT_ALLOWED");
  const user = (await ctx.context.internalAdapter.findUserById(s.user.id)) as (User & Record<string, unknown>) | null;
  if (!user || isBanned(user)) throw fail("FORBIDDEN", "NOT_ALLOWED");
  let allowed = false;
  for (const d of asked) {
    try {
      allowed = (await d.canManage({ user, session: s.session })) === true;
    } catch (e) {
      ctx.context.logger.error(`[id-jag] ${d.name} threw; denied`, e);
    }
    if (allowed) break;
  }
  if (!allowed) throw fail("FORBIDDEN", "NOT_ALLOWED");
  return { id: user.id };
}

const tooBig = (v: unknown) => JSON.stringify(v ?? null).length > MAX_BODY_BYTES;
const idSchema = z.string().min(1).max(256);
const record = z.record(z.string(), z.unknown());

/** The row whose id is exactly `id` (a collation must not widen the match). */
async function findById(ctx: GenericEndpointContext, model: string, id: string): Promise<Record<string, unknown> | null> {
  const row = await ctx.context.adapter.findOne<Record<string, unknown>>({ model, where: [{ field: "id", value: id }] });
  return row && String(row.id) === id ? row : null;
}

export function registryEndpoints(state: IssuerState) {
  const allowLoopbackHttp = state.options.allowLoopbackHttpAudiences;
  const rsInput = resourceServerInput({ allowLoopbackHttp });
  const changed = (ctx: GenericEndpointContext, actorId: string, action: AdminChangedEvent["action"], target: AdminChangedEvent["target"], targetId: string, what: string) => {
    state.directory?.invalidate();
    ctx.context.logger.info(`[id-jag] registry: user ${actorId} ${what}`);
    emit(ctx, state.options, { type: "id-jag.admin", actorUserId: actorId, action, target, targetId });
  };
  const parseRs = (input: unknown) => {
    if (tooBig(input)) throw fail("BAD_REQUEST", "INVALID", { issues: [`larger than ${MAX_BODY_BYTES} bytes`] });
    const r = rsInput.safeParse(input);
    if (!r.success) throw fail("BAD_REQUEST", "INVALID", { issues: issuesOf(r.error) });
    return r.data;
  };
  /** A policy's input, checked against its resource server (which must exist and validate). */
  const parsePolicy = async (ctx: GenericEndpointContext, input: unknown) => {
    if (tooBig(input)) throw fail("BAD_REQUEST", "INVALID", { issues: [`larger than ${MAX_BODY_BYTES} bytes`] });
    const r = policyInput.safeParse(input);
    if (!r.success) throw fail("BAD_REQUEST", "INVALID", { issues: issuesOf(r.error) });
    const rsRow = await findById(ctx, RESOURCE_SERVER_MODEL, r.data.resourceServerId);
    if (!rsRow) throw fail("BAD_REQUEST", "INVALID", { issues: ["resourceServerId: no such resource server"] });
    const rs = await readResourceServer(rsRow, { allowLoopbackHttp });
    if (!rs.config) throw fail("BAD_REQUEST", "INVALID", { issues: ["resourceServerId: that resource server doesn't validate", ...rs.issues] });
    const extra = r.data.scopes.filter((s) => !rs.config?.scopes.includes(s));
    if (extra.length) throw fail("BAD_REQUEST", "INVALID", { issues: [`scopes: not allowed by the resource server: ${extra.join(" ")}`] });
    return r.data;
  };
  const rsView = (row: Record<string, unknown>): Promise<ResourceServerRecord> => readResourceServer(row, { allowLoopbackHttp });
  const policyView = (row: Record<string, unknown>): PolicyRecord => readPolicy(row);
  const use = [sensitiveSessionMiddleware];

  return {
    idJagListResourceServers: createAuthEndpoint("/id-jag/resource-servers", { method: "GET", use }, async (ctx) => {
      await actor(ctx, state, "registry");
      const rows = await ctx.context.adapter.findMany<Record<string, unknown>>({ model: RESOURCE_SERVER_MODEL, limit: MAX_LIST, sortBy: { field: "createdAt", direction: "asc" } });
      return ctx.json({ resourceServers: await Promise.all(rows.map(rsView)) });
    }),

    idJagGetResourceServer: createAuthEndpoint("/id-jag/resource-servers/get", { method: "GET", use, query: z.object({ id: idSchema }) }, async (ctx) => {
      await actor(ctx, state, "registry");
      const row = await findById(ctx, RESOURCE_SERVER_MODEL, ctx.query.id);
      if (!row) throw fail("NOT_FOUND", "NOT_FOUND");
      return ctx.json({ resourceServer: await rsView(row) });
    }),

    idJagCreateResourceServer: createAuthEndpoint(
      "/id-jag/resource-servers/create",
      { method: "POST", use, body: z.object({ resourceServer: record, enabled: z.boolean().optional() }) },
      async (ctx) => {
        const who = await actor(ctx, state, "registry");
        const config = parseRs(ctx.body.resourceServer);
        const now = new Date();
        const lookupKey = await lookupKeyOf(config.organizationId, config.audience);
        const data = { lookupKey, ...resourceServerColumns(config), enabled: ctx.body.enabled ?? true, createdBy: who.id, updatedBy: who.id, createdAt: now, updatedAt: now };
        let created: Record<string, unknown>;
        try {
          created = await ctx.context.adapter.create<Record<string, unknown>>({ model: RESOURCE_SERVER_MODEL, data });
        } catch (e) {
          // The UNIQUE lookupKey decides; the read only classifies the failure.
          if (await ctx.context.adapter.findOne({ model: RESOURCE_SERVER_MODEL, where: [{ field: "lookupKey", value: lookupKey }] })) throw fail("CONFLICT", "EXISTS");
          throw e;
        }
        const id = String(created.id);
        changed(ctx, who.id, "create", "resource-server", id, `created resource server ${id} (${config.audience})`);
        // What was written, not a re-read (a replica could lag).
        return ctx.json({ resourceServer: await rsView({ ...data, id }) });
      },
    ),

    idJagUpdateResourceServer: createAuthEndpoint(
      "/id-jag/resource-servers/update",
      { method: "POST", use, body: z.object({ id: idSchema, resourceServer: record.optional(), enabled: z.boolean().optional() }) },
      async (ctx) => {
        const who = await actor(ctx, state, "registry");
        const row = await findById(ctx, RESOURCE_SERVER_MODEL, ctx.body.id);
        if (!row) throw fail("NOT_FOUND", "NOT_FOUND");
        if (ctx.body.resourceServer === undefined && ctx.body.enabled === undefined) throw fail("BAD_REQUEST", "INVALID", { issues: ["send resourceServer, enabled, or both"] });
        // Only switching it on or off: no re-validation, so an invalid row can still be disabled.
        let update: Record<string, unknown> = { updatedBy: who.id, updatedAt: new Date() };
        if (ctx.body.enabled !== undefined) update.enabled = ctx.body.enabled;
        let lookupKey: string | undefined;
        if (ctx.body.resourceServer !== undefined) {
          const config = parseRs(ctx.body.resourceServer);
          lookupKey = await lookupKeyOf(config.organizationId, config.audience);
          update = { ...update, lookupKey, ...resourceServerColumns(config) };
        }
        try {
          await ctx.context.adapter.update({ model: RESOURCE_SERVER_MODEL, where: [{ field: "id", value: String(row.id) }], update });
        } catch (e) {
          const other = lookupKey && (await ctx.context.adapter.findOne<Record<string, unknown>>({ model: RESOURCE_SERVER_MODEL, where: [{ field: "lookupKey", value: lookupKey }] }));
          if (other && String(other.id) !== String(row.id)) throw fail("CONFLICT", "EXISTS");
          throw e;
        }
        const action = ctx.body.resourceServer === undefined ? (ctx.body.enabled ? "enabled" : "disabled") : "updated";
        changed(ctx, who.id, "update", "resource-server", String(row.id), `${action} resource server ${String(row.id)}`);
        return ctx.json({ resourceServer: await rsView({ ...row, ...update }) });
      },
    ),

    idJagDeleteResourceServer: createAuthEndpoint("/id-jag/resource-servers/delete", { method: "POST", use, body: z.object({ id: idSchema }) }, async (ctx) => {
      const who = await actor(ctx, state, "registry");
      const row = await findById(ctx, RESOURCE_SERVER_MODEL, ctx.body.id);
      if (!row) throw fail("NOT_FOUND", "NOT_FOUND");
      const policies = await ctx.context.adapter.findMany({ model: POLICY_MODEL, where: [{ field: "resourceServerId", value: String(row.id) }], limit: 1 });
      if (policies.length > 0) throw fail("CONFLICT", "HAS_POLICIES");
      await ctx.context.adapter.delete({ model: RESOURCE_SERVER_MODEL, where: [{ field: "id", value: String(row.id) }] });
      changed(ctx, who.id, "delete", "resource-server", String(row.id), `deleted resource server ${String(row.id)} (${String(row.audience)})`);
      return ctx.json({ deleted: String(row.id) });
    }),

    idJagListPolicies: createAuthEndpoint("/id-jag/policies", { method: "GET", use, query: z.object({ resourceServerId: idSchema.optional() }).optional() }, async (ctx) => {
      await actor(ctx, state, "registry");
      const rsId = ctx.query?.resourceServerId;
      const rows = await ctx.context.adapter.findMany<Record<string, unknown>>({
        model: POLICY_MODEL,
        ...(rsId !== undefined ? { where: [{ field: "resourceServerId", value: rsId }] } : {}),
        limit: MAX_LIST,
        sortBy: { field: "createdAt", direction: "asc" },
      });
      return ctx.json({ policies: rows.filter((r) => rsId === undefined || r.resourceServerId === rsId).map(policyView) });
    }),

    idJagGetPolicy: createAuthEndpoint("/id-jag/policies/get", { method: "GET", use, query: z.object({ id: idSchema }) }, async (ctx) => {
      await actor(ctx, state, "registry");
      const row = await findById(ctx, POLICY_MODEL, ctx.query.id);
      if (!row) throw fail("NOT_FOUND", "NOT_FOUND");
      return ctx.json({ policy: policyView(row) });
    }),

    idJagCreatePolicy: createAuthEndpoint("/id-jag/policies/create", { method: "POST", use, body: z.object({ policy: record, enabled: z.boolean().optional() }) }, async (ctx) => {
      const who = await actor(ctx, state, "registry");
      const config = await parsePolicy(ctx, ctx.body.policy);
      const now = new Date();
      const data = { ...policyColumns(config), enabled: ctx.body.enabled ?? true, createdBy: who.id, updatedBy: who.id, createdAt: now, updatedAt: now };
      const created = await ctx.context.adapter.create<Record<string, unknown>>({ model: POLICY_MODEL, data });
      const id = String(created.id);
      changed(ctx, who.id, "create", "policy", id, `created policy ${id} for resource server ${config.resourceServerId}`);
      return ctx.json({ policy: policyView({ ...data, id }) });
    }),

    idJagUpdatePolicy: createAuthEndpoint(
      "/id-jag/policies/update",
      { method: "POST", use, body: z.object({ id: idSchema, policy: record.optional(), enabled: z.boolean().optional() }) },
      async (ctx) => {
        const who = await actor(ctx, state, "registry");
        const row = await findById(ctx, POLICY_MODEL, ctx.body.id);
        if (!row) throw fail("NOT_FOUND", "NOT_FOUND");
        if (ctx.body.policy === undefined && ctx.body.enabled === undefined) throw fail("BAD_REQUEST", "INVALID", { issues: ["send policy, enabled, or both"] });
        let update: Record<string, unknown> = { updatedBy: who.id, updatedAt: new Date() };
        if (ctx.body.enabled !== undefined) update.enabled = ctx.body.enabled;
        if (ctx.body.policy !== undefined) {
          const config = await parsePolicy(ctx, ctx.body.policy);
          if (config.resourceServerId !== row.resourceServerId) throw fail("BAD_REQUEST", "INVALID", { issues: ["resourceServerId: can't be changed (create a new policy instead)"] });
          update = { ...update, ...policyColumns(config) };
        }
        await ctx.context.adapter.update({ model: POLICY_MODEL, where: [{ field: "id", value: String(row.id) }], update });
        changed(ctx, who.id, "update", "policy", String(row.id), `updated policy ${String(row.id)}`);
        return ctx.json({ policy: policyView({ ...row, ...update }) });
      },
    ),

    idJagDeletePolicy: createAuthEndpoint("/id-jag/policies/delete", { method: "POST", use, body: z.object({ id: idSchema }) }, async (ctx) => {
      const who = await actor(ctx, state, "registry");
      const row = await findById(ctx, POLICY_MODEL, ctx.body.id);
      if (!row) throw fail("NOT_FOUND", "NOT_FOUND");
      await ctx.context.adapter.delete({ model: POLICY_MODEL, where: [{ field: "id", value: String(row.id) }] });
      changed(ctx, who.id, "delete", "policy", String(row.id), `deleted policy ${String(row.id)}`);
      return ctx.json({ deleted: String(row.id) });
    }),
  };
}

/** The core's AdminChangedEvent has no "block" target yet (a core change request); the event carries it as is. */
const BLOCK_TARGET: AdminChangedEvent["target"] = "block";
const JTI_FIELDS = ["userId", "clientId", "audience"] as const;

interface IssuedRecord {
  userId: string;
  clientId: string;
  audience: string;
}

/** All three, or nothing: a missing field must not turn into "any" and widen the block. */
const issuedOf = (userId: unknown, clientId: unknown, audience: unknown): IssuedRecord | null =>
  typeof userId === "string" && userId !== "" && typeof clientId === "string" && clientId !== "" && typeof audience === "string" && audience !== "" ? { userId, clientId, audience } : null;

/**
 * Who and what an ID-JAG this issuer minted was for, by its jti (D-B25): the jti row while it
 * lasts (until the token's exp + 5 minutes), then the `id-jag.issued` audit row (with `auditLog`,
 * for its retention). Only issued rows count: the audit table also holds jtis a receiver on this
 * host accepted or refused, which name other issuers' tokens. Matched exactly, whatever the collation.
 */
async function issuedRecord(ctx: GenericEndpointContext, state: IssuerState, jti: string): Promise<IssuedRecord | null> {
  const key = await jtiKey("issued", issuerOf(ctx), jti);
  const row = await ctx.context.adapter.findOne<Record<string, unknown>>({ model: JTI_MODEL, where: [{ field: "key", value: key }] });
  if (row && row.key === key) return issuedOf(row.sub, row.clientId, row.aud);
  if (!state.options.auditLog) return null;
  const rows = await ctx.context.adapter.findMany<Record<string, unknown>>({
    model: AUDIT_MODEL,
    where: [
      { field: "type", value: "id-jag.issued" },
      { field: "jti", value: jti },
    ],
    limit: 10,
  });
  const hit = rows.find((r) => r.type === "id-jag.issued" && r.jti === jti);
  if (!hit) return null;
  return issuedOf(hit.userId, hit.clientId, hit.audience);
}

/** Why create-from-jti found nothing (D-B25). */
const JTI_NOT_FOUND = {
  withAudit: "No ID-JAG with this jti was issued here, or its audit row is past retention.",
  withoutAudit: "No ID-JAG with this jti is on record. jti rows expire minutes after the token; enable auditLog to block from older ones.",
} as const;

/**
 * Blocks (D-B16): mounted with `blocks.canManage`, registry or not (a code-policy host can block
 * too), and decided by it alone (D-B24). Same access control as the registry routes otherwise.
 */
export function blockEndpoints(state: IssuerState) {
  const allowLoopbackHttp = state.options.allowLoopbackHttpAudiences;
  const input = blockInput({ allowLoopbackHttp, now: () => Date.now() });
  const use = [sensitiveSessionMiddleware];
  const changed = (ctx: GenericEndpointContext, actorId: string, action: "create" | "delete", blockId: string, what: string) => {
    ctx.context.logger.info(`[id-jag] blocks: user ${actorId} ${what}`);
    emit(ctx, state.options, { type: "id-jag.admin", actorUserId: actorId, action, target: BLOCK_TARGET, targetId: blockId });
  };
  const create = async (ctx: GenericEndpointContext, who: { id: string }, config: BlockConfig) => {
    const data = { ...blockColumns(config), createdBy: who.id, createdAt: new Date() };
    const created = await ctx.context.adapter.create<Record<string, unknown>>({ model: BLOCK_MODEL, data });
    const id = String(created.id);
    const what = JTI_FIELDS.filter((k) => config[k] !== undefined)
      .map((k) => `${k} ${config[k]}`)
      .join(", ");
    changed(ctx, who.id, "create", id, `blocked ${what}${config.expiresAt ? ` until ${config.expiresAt.toISOString()}` : ""}`);
    return readBlock({ ...data, id });
  };
  const parse = (value: unknown) => {
    if (tooBig(value)) throw fail("BAD_REQUEST", "INVALID", { issues: [`larger than ${MAX_BODY_BYTES} bytes`] });
    const r = input.safeParse(value);
    if (!r.success) throw fail("BAD_REQUEST", "INVALID", { issues: issuesOf(r.error) });
    return r.data;
  };

  return {
    // Newest first. Filters match exactly; expired blocks are listed (active: false) until swept.
    idJagListBlocks: createAuthEndpoint(
      "/id-jag/blocks",
      { method: "GET", use, query: z.object({ userId: idSchema.optional(), clientId: idSchema.optional(), audience: z.string().min(1).max(2048).optional() }).optional() },
      async (ctx) => {
        await actor(ctx, state, "blocks");
        const filters = JTI_FIELDS.flatMap((k) => (ctx.query?.[k] !== undefined ? [{ field: k, value: ctx.query[k] as string }] : []));
        const rows = await ctx.context.adapter.findMany<Record<string, unknown>>({ model: BLOCK_MODEL, ...(filters.length ? { where: filters } : {}), limit: MAX_LIST, sortBy: { field: "createdAt", direction: "desc" } });
        const blocks = rows.filter((r) => filters.every((f) => r[f.field] === f.value)).map((r) => readBlock(r));
        return ctx.json({ blocks });
      },
    ),

    idJagGetBlock: createAuthEndpoint("/id-jag/blocks/get", { method: "GET", use, query: z.object({ id: idSchema }) }, async (ctx) => {
      await actor(ctx, state, "blocks");
      const row = await findById(ctx, BLOCK_MODEL, ctx.query.id);
      if (!row) throw fail("NOT_FOUND", "NOT_FOUND");
      return ctx.json({ block: readBlock(row) });
    }),

    // { block: { userId?, clientId?, audience?, reason, expiresAt? } }: at least one of the three.
    idJagCreateBlock: createAuthEndpoint("/id-jag/blocks/create", { method: "POST", use, body: z.object({ block: record }) }, async (ctx) => {
      const who = await actor(ctx, state, "blocks");
      return ctx.json({ block: await create(ctx, who, parse(ctx.body.block)) });
    }),

    // A convenience: block the user, client and/or audience of an ID-JAG this issuer recorded (a
    // jti alone means nothing to a receiver). `fields` picks which (default all three).
    idJagCreateBlockFromJti: createAuthEndpoint(
      "/id-jag/blocks/create-from-jti",
      {
        method: "POST",
        use,
        body: z.object({
          jti: z.string().min(1).max(256),
          fields: z.array(z.enum(JTI_FIELDS)).min(1).max(3).optional(),
          reason: z.string(),
          expiresAt: z.string().optional(),
        }),
      },
      async (ctx) => {
        const who = await actor(ctx, state, "blocks");
        const issued = await issuedRecord(ctx, state, ctx.body.jti);
        if (!issued) throw fail("NOT_FOUND", "NOT_FOUND", { message: state.options.auditLog ? JTI_NOT_FOUND.withAudit : JTI_NOT_FOUND.withoutAudit });
        const fields = new Set(ctx.body.fields ?? JTI_FIELDS);
        const config = parse({
          ...(fields.has("userId") ? { userId: issued.userId } : {}),
          ...(fields.has("clientId") ? { clientId: issued.clientId } : {}),
          ...(fields.has("audience") ? { audience: issued.audience } : {}),
          reason: ctx.body.reason,
          ...(ctx.body.expiresAt !== undefined ? { expiresAt: ctx.body.expiresAt } : {}),
        });
        return ctx.json({ block: await create(ctx, who, config) });
      },
    ),

    idJagDeleteBlock: createAuthEndpoint("/id-jag/blocks/delete", { method: "POST", use, body: z.object({ id: idSchema }) }, async (ctx) => {
      const who = await actor(ctx, state, "blocks");
      const row = await findById(ctx, BLOCK_MODEL, ctx.body.id);
      if (!row) throw fail("NOT_FOUND", "NOT_FOUND");
      await ctx.context.adapter.delete({ model: BLOCK_MODEL, where: [{ field: "id", value: String(row.id) }] });
      changed(ctx, who.id, "delete", String(row.id), `deleted block ${String(row.id)}`);
      return ctx.json({ deleted: String(row.id) });
    }),
  };
}

/**
 * The audit log (core audit table): mounted with `registry.canManage` or `blocks.canManage`, and
 * allowed by either (D-B24): it is where a blocks administrator finds the jti to block from, and
 * where a registry administrator sees the effect of a policy. 404 without `auditLog`.
 */
export function auditEndpoints(state: IssuerState) {
  const use = [sensitiveSessionMiddleware];
  return {
    // The audit log (core audit table), newest first. Only with `auditLog`.
    idJagListAudit: createAuthEndpoint(
      "/id-jag/audit",
      {
        method: "GET",
        use,
        query: z.object({ type: z.enum(["id-jag.issued", "id-jag.refused", "id-jag.admin"]).optional(), limit: z.coerce.number().int().min(1).max(MAX_AUDIT).optional(), before: z.iso.datetime().optional() }).optional(),
      },
      async (ctx) => {
        await actor(ctx, state, "audit");
        if (!state.options.auditLog) throw fail("NOT_FOUND", "NOT_FOUND");
        const where: { field: string; value: string | Date; operator?: "lt" }[] = [];
        if (ctx.query?.type) where.push({ field: "type", value: ctx.query.type });
        if (ctx.query?.before) where.push({ field: "at", value: new Date(ctx.query.before), operator: "lt" });
        const rows = await ctx.context.adapter.findMany<Record<string, unknown>>({ model: AUDIT_MODEL, ...(where.length ? { where } : {}), limit: ctx.query?.limit ?? 100, sortBy: { field: "at", direction: "desc" } });
        return ctx.json({
          events: rows.map((r) => {
            let details: unknown = null;
            try {
              details = JSON.parse(String(r.details));
            } catch {}
            return { type: r.type, at: r.at, reason: r.reason ?? null, userId: r.userId ?? null, clientId: r.clientId ?? null, audience: r.audience ?? null, jti: r.jti ?? null, actorUserId: r.actorUserId ?? null, details };
          }),
        });
      },
    ),
  };
}
