// The SCIM step of subject resolution (D-027): with `scim` on a trust entry, the ID-JAG's `sub` is a
// SCIM `externalId`, and the user is the one that `@better-auth/scim` provisioned for it on that
// connection, while that SCIM user is active. `acquireActiveSCIMUserLink` (passed in by the host)
// never falls back to userName, email or tombstones; it returns null for an unknown, inactive,
// deleted or decommissioned source. It also bumps the SCIM subject's revision, so it runs in the
// adapter's transaction, and a concurrent lifecycle change (a 409 SCIM conflict) is retried once
// from fresh state, then refused. (@better-auth/scim itself refuses to start on an adapter without
// native transactions, such as D1.) A database-level transaction error isn't a SCIM conflict: it
// goes to resolveSubject's catch, an audited subject_rejected.
import type { GenericEndpointContext } from "better-auth";
import { isAPIError } from "better-auth/api";
import { refuse } from "../core";
import type { AcquireActiveScimUserLink } from "./options";

const isConflict = (e: unknown): boolean => isAPIError(e) && (e.statusCode === 409 || e.status === "CONFLICT");

/** The local user id SCIM links to this subject, or null when there's no active provisioned user. */
export async function scimLinkedUserId(ctx: GenericEndpointContext, acquire: AcquireActiveScimUserLink | undefined, connectionId: string, externalId: string): Promise<string | null> {
  if (!acquire) {
    // A table row with scimConnectionId on a host that didn't pass the function: fail closed.
    ctx.context.logger.error("[id-jag] a trusted issuer has a SCIM connection, but scim.acquireActiveSCIMUserLink is not set; refusing");
    refuse("subject_rejected", "SCIM: acquireActiveSCIMUserLink not configured");
  }
  const reference = { connectionId, externalId };
  for (let attempt = 1; ; attempt++) {
    try {
      const link = await ctx.context.adapter.transaction((trx) => acquire(reference, { database: trx as never }));
      return link?.userId ?? null;
    } catch (e) {
      if (!isConflict(e)) throw e;
      if (attempt >= 2) refuse("subject_rejected", "SCIM: the provisioned identity changed concurrently");
    }
  }
}
