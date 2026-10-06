// Blocks: an administrator stops further ID-JAGs for a user, a client, an audience, or any
// combination (D-B16, the maintainer's D-009 #12). The policy step checks them before any policy
// source, on every exchange, with no cache: a block takes effect at the next exchange, on every
// instance.
//
// A block stops **new** ID-JAGs only. One already issued stays valid at its receiver until it
// expires (default 5 minutes, at most 15): there is no ID-JAG revocation protocol, so a receiver
// can't see the block.
//
// Matching: each of userId, clientId, audience is either a value (matched exactly, whatever the
// collation) or null (any). At least one is set. So (user), (user, client), (user, client,
// audience), (client), (audience), (client, audience) … all work; "everything" is not a block.
import type { GenericEndpointContext } from "better-auth";
import { z } from "zod";
import { refuse } from "../core";
import { BLOCK_MODEL } from "./schema";
import { normalizeAudience } from "./url";

/** Rows read per lookup; reaching it refuses (fail closed) rather than missing a block. */
export const MAX_BLOCK_ROWS = 1000;
export const MAX_BLOCK_REASON = 500;

// biome-ignore lint/suspicious/noControlCharactersInRegex: refusing them is the point.
const ident = z.string().min(1).max(512).regex(/^[^\u0000-\u001f\u007f-\u009f]+$/, "control characters");

export function blockInput(o: { allowLoopbackHttp: boolean; now: () => number }) {
  return z
    .strictObject({
      userId: ident.optional(),
      clientId: ident.optional(),
      audience: z
        .string()
        .transform((v, c) => {
          const n = normalizeAudience(v, { allowLoopbackHttp: o.allowLoopbackHttp });
          if (!n.ok) {
            c.addIssue({ code: "custom", message: `not an issuer identifier (${n.why})` });
            return z.NEVER;
          }
          return n.audience;
        })
        .optional(),
      // biome-ignore lint/suspicious/noControlCharactersInRegex: refusing them is the point.
      reason: z.string().min(1).max(MAX_BLOCK_REASON).regex(/^[^\u0000-\u0008\u000b-\u001f\u007f-\u009f]+$/, "control characters"),
      expiresAt: z.iso
        .datetime({ offset: true })
        .transform((v) => new Date(v))
        .refine((d) => d.getTime() > o.now(), "must be in the future")
        .optional(),
    })
    .refine((b) => b.userId !== undefined || b.clientId !== undefined || b.audience !== undefined, "name at least one of userId, clientId, audience");
}
export type BlockConfig = z.infer<ReturnType<typeof blockInput>>;

export interface BlockRecord {
  id: string;
  userId: string | null;
  clientId: string | null;
  audience: string | null;
  reason: string;
  createdBy: string | null;
  createdAt: Date | null;
  expiresAt: Date | null;
  /** Not expired. */
  active: boolean;
}

const str = (v: unknown) => (typeof v === "string" && v !== "" ? v : null);
const dateOf = (v: unknown) => (v instanceof Date ? v : typeof v === "string" || typeof v === "number" ? new Date(v) : null);

export function blockColumns(c: BlockConfig) {
  return { userId: c.userId ?? null, clientId: c.clientId ?? null, audience: c.audience ?? null, reason: c.reason, expiresAt: c.expiresAt ?? null };
}

/** A stored row as the API shows it. */
export function readBlock(row: Record<string, unknown>, now = Date.now()): BlockRecord {
  const expiresAt = dateOf(row.expiresAt);
  // An unreadable expiry counts as no expiry: a block that can't be read as expired stays on.
  const active = !expiresAt || Number.isNaN(expiresAt.getTime()) || expiresAt.getTime() > now;
  return {
    id: String(row.id),
    userId: str(row.userId),
    clientId: str(row.clientId),
    audience: str(row.audience),
    reason: typeof row.reason === "string" ? row.reason : "",
    createdBy: str(row.createdBy),
    createdAt: dateOf(row.createdAt),
    expiresAt,
    active,
  };
}

/** Whether a stored block applies to this exchange: every field it sets equals the request's. */
export function blockMatches(b: BlockRecord, r: { userId: string; clientId: string; audience: string }): boolean {
  if (!b.active) return false;
  if (b.userId === null && b.clientId === null && b.audience === null) return false;
  return (b.userId === null || b.userId === r.userId) && (b.clientId === null || b.clientId === r.clientId) && (b.audience === null || b.audience === r.audience);
}

/**
 * Refuses (`blocked`, detail the block's id) when an active block matches. Three indexed
 * reads cover every combination: the user's blocks; any-user blocks of this client; any-user,
 * any-client blocks of this audience.
 */
export async function checkBlocks(ctx: GenericEndpointContext, r: { userId: string; clientId: string; audience: string }, now = Date.now()): Promise<void> {
  const adapter = ctx.context.adapter;
  const queries = [
    [{ field: "userId", value: r.userId }],
    [
      { field: "userId", value: null },
      { field: "clientId", value: r.clientId },
    ],
    [
      { field: "userId", value: null },
      { field: "clientId", value: null },
      { field: "audience", value: r.audience },
    ],
  ];
  for (const where of queries) {
    const rows = await adapter.findMany<Record<string, unknown>>({ model: BLOCK_MODEL, where, limit: MAX_BLOCK_ROWS });
    if (rows.length >= MAX_BLOCK_ROWS) refuse("policy_denied", "too many blocks to evaluate");
    const hit = rows.map((row) => readBlock(row, now)).find((b) => blockMatches(b, r));
    if (hit) refuse("blocked", hit.id);
  }
}

/** Deletes blocks past their expiry (opportunistic, from the exchange's sweep). */
export async function sweepBlocks(ctx: GenericEndpointContext, now = new Date()): Promise<void> {
  await ctx.context.adapter.deleteMany({ model: BLOCK_MODEL, where: [{ field: "expiresAt", value: now, operator: "lt" }] });
}
