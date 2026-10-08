// The SCIM step of subject resolution (D-027): with `scim` on a trust entry, the ID-JAG's `sub` is a
// SCIM `externalId`, and the user is the one that `@better-auth/scim` provisioned for it on that
// connection, while that SCIM user is active. `acquireActiveSCIMUserLink` (passed in by the host)
// never falls back to userName, email or tombstones; it returns null for an unknown, inactive,
// deleted or decommissioned source. It also bumps the SCIM subject's revision, so it runs in the
// adapter's transaction. Two lookups of the same user conflict with each other (each bumps the
// revision), not only a lookup and a lifecycle change, so lookups of one user commit one at a time.
// Hence (D-029, D-030): concurrent requests for the same user in this process share one in-flight
// lookup, and a 409 SCIM conflict is retried from fresh state with jittered exponential backoff
// within SCIM_RETRY_BUDGET_MS, then refused. A retry after a deprovisioning sees it and returns null. (@better-auth/scim itself refuses to start on an adapter without
// native transactions, such as D1.) A database-level transaction error isn't a SCIM conflict: it
// goes to resolveSubject's catch, an audited subject_rejected.
import type { GenericEndpointContext } from "better-auth";
import { isAPIError } from "better-auth/api";
import { refuse } from "../core";
import type { AcquireActiveScimUserLink } from "./options";

const isConflict = (e: unknown): boolean => isAPIError(e) && (e.statusCode === 409 || e.status === "CONFLICT");

/**
 * On a SCIM conflict, retries go on while both last: at most MAX_SCIM_ATTEMPTS attempts and
 * SCIM_RETRY_BUDGET_MS since the first one; then refused. Only lookups racing each other keep
 * conflicting (a deprovisioning makes the next attempt return null), so the budget is about how many
 * redemptions for one user arrive at once: 32 at once on MySQL needed more than ten attempts.
 */
export const MAX_SCIM_ATTEMPTS = 40;
export const SCIM_RETRY_BUDGET_MS = 5000;
/** Backoff before retry n (1-based): exponential with full jitter, random within [0, min(250, 10·2ⁿ)] ms. */
const backoffMs = (n: number) => Math.random() * Math.min(250, 10 * 2 ** n);
const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

/**
 * In-flight lookups by database adapter and (connection, externalId): requests for the same user that
 * arrive while a lookup runs share its answer instead of racing it (D-030). The answer is no staler
 * than if they had arrived a moment earlier; nothing is kept once the lookup settles.
 */
const inflight = new WeakMap<object, Map<string, Promise<string | null>>>();

/** The local user id SCIM links to this subject, or null when there's no active provisioned user. */
export async function scimLinkedUserId(ctx: GenericEndpointContext, acquire: AcquireActiveScimUserLink | undefined, connectionId: string, externalId: string): Promise<string | null> {
  const adapter = ctx.context.adapter as object;
  let byKey = inflight.get(adapter);
  if (!byKey) {
    byKey = new Map();
    inflight.set(adapter, byKey);
  }
  const key = JSON.stringify([connectionId, externalId]);
  const running = byKey.get(key);
  if (running) return running;
  const lookup = acquireWithRetries(ctx, acquire, connectionId, externalId).finally(() => byKey.delete(key));
  byKey.set(key, lookup);
  return lookup;
}

async function acquireWithRetries(ctx: GenericEndpointContext, acquire: AcquireActiveScimUserLink | undefined, connectionId: string, externalId: string): Promise<string | null> {
  if (!acquire) {
    // A table row with scimConnectionId on a host that didn't pass the function: fail closed.
    ctx.context.logger.error("[id-jag] a trusted issuer has a SCIM connection, but scim.acquireActiveSCIMUserLink is not set; refusing");
    refuse("subject_rejected", "SCIM: acquireActiveSCIMUserLink not configured");
  }
  const reference = { connectionId, externalId };
  const started = Date.now();
  for (let attempt = 1; ; attempt++) {
    try {
      const link = await ctx.context.adapter.transaction((trx) => acquire(reference, { database: trx as never }));
      return link?.userId ?? null;
    } catch (e) {
      if (!isConflict(e)) throw e;
      if (attempt >= MAX_SCIM_ATTEMPTS || Date.now() - started >= SCIM_RETRY_BUDGET_MS) refuse("subject_rejected", "SCIM: the provisioned identity changed concurrently");
      await sleep(backoffMs(attempt));
    }
  }
}
