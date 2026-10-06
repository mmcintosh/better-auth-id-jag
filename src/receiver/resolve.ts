// The ID-JAG's subject → a local user (plan §3.4 step 10), first hit wins:
// 1. the host's `resolveSubject` hook: link / continue / reject (a throw is a reject: gates fail closed);
// 2. an account linked with providerId = the trust entry's account provider id (the sso providerId
//    for sso-trusted issuers) and accountId = `sub`: what `@better-auth/sso` creates at sign-in;
// 3. the `email` claim, only when the trust entry allows it and the domain is listed or verified;
//    links the account on success;
// 4. JIT provisioning, only when enabled (off by default); a JIT user joins the trust entry's
//    organization (membership.ts). Users found by 1–3 are left as they are (D-A19);
// otherwise `unknown_subject`. A banned user is refused whichever way it was found. Every refusal
// reaches the caller with the same generic wording (S8); the reason goes to the audit event.
//
// Concurrency (D-A24): Better Auth's adapters give no transaction that works on D1, and nothing
// makes (providerId, accountId) unique, so concurrent first uses of one subject can each link an
// account. Lookups therefore tolerate several matching rows (the oldest wins, by createdAt then id),
// and after linking, a request that finds it lost removes what it created and continues with the
// winner's user. Anything unexpected is an audited `subject_rejected`, never an empty 500.
import type { GenericEndpointContext, User } from "better-auth";
import { type IdJagClaims, IdJagRefusal, refuse } from "../core";
import { addJitMembership, type MembershipOutcome } from "./membership";
import type { ResolvedReceiverOptions, SubjectResolution, TrustEntry, TrustedIssuerView } from "./options";

export interface ResolvedSubject {
  user: User;
  via: "hook" | "account" | "email" | "jit";
}

function view(t: TrustEntry): TrustedIssuerView {
  return { source: t.source, id: t.id, issuer: t.issuer, organizationId: t.organizationId, accountProviderId: t.accountProviderId };
}

function assertNotBanned(user: User, now: Date): User {
  const u = user as User & { banned?: boolean | null; banExpires?: Date | string | number | null };
  if (u.banned === true) {
    const expires = u.banExpires === null || u.banExpires === undefined ? null : new Date(u.banExpires);
    if (!expires || Number.isNaN(expires.getTime()) || expires.getTime() > now.getTime()) refuse("banned_user", user.id);
  }
  return user;
}

const emailDomain = (email: string): string | undefined => {
  const at = email.lastIndexOf("@");
  return at > 0 ? email.slice(at + 1).toLowerCase() : undefined;
};

interface AccountRow {
  id: string;
  userId: string;
  createdAt?: Date | string | number | null;
}

/** Enough to find the oldest of any realistic number of duplicates; they are sorted here too. */
const MAX_LINKED_ROWS = 100;

const createdAtMs = (r: AccountRow): number => {
  const t = r.createdAt === null || r.createdAt === undefined ? Number.NaN : new Date(r.createdAt).getTime();
  return Number.isNaN(t) ? Number.POSITIVE_INFINITY : t;
};

/** The deterministic order of duplicate links: the oldest by createdAt, then the lowest id. */
function byAge(a: AccountRow, b: AccountRow): number {
  const d = createdAtMs(a) - createdAtMs(b);
  if (d !== 0 && !Number.isNaN(d)) return d;
  const [x, y] = [String(a.id), String(b.id)];
  return x < y ? -1 : x > y ? 1 : 0;
}

/** Every account linking this subject at this issuer, the winner first. Never throws on duplicates. */
async function linkedAccounts(ctx: GenericEndpointContext, providerId: string, accountId: string): Promise<AccountRow[]> {
  const rows = await ctx.context.adapter.findMany<AccountRow>({
    model: "account",
    where: [
      { field: "providerId", value: providerId },
      { field: "accountId", value: accountId },
    ],
    sortBy: { field: "createdAt", direction: "asc" },
    limit: MAX_LINKED_ROWS,
  });
  return [...rows].sort(byAge);
}

type Owner = { kind: "owned"; user: User } | { kind: "orphaned" } | null;

/** The user the winning account row belongs to (as Better Auth's findAccountOwnerByKey, but tolerant of duplicates). */
async function findAccountOwner(ctx: GenericEndpointContext, providerId: string, accountId: string): Promise<Owner> {
  const winner = (await linkedAccounts(ctx, providerId, accountId))[0];
  if (!winner) return null;
  const user = await ctx.context.internalAdapter.findUserById(winner.userId);
  return user ? { kind: "owned", user } : { kind: "orphaned" };
}

interface Linked {
  /** The account row this request created. */
  account: AccountRow;
  user: User;
  /** JIT: this request created the user (and maybe a membership), so it removes them if it lost. */
  created?: { membershipOrganizationId: string | undefined };
}

/**
 * After linking: if concurrent requests linked the same subject too, the oldest row wins. Exact
 * duplicates of the winner (same user) are removed by whoever sees them; a request whose own row lost
 * also removes the user and membership it created (JIT), then continues with the winner's user.
 */
async function converge(ctx: GenericEndpointContext, trust: TrustEntry, sub: string, mine: Linked): Promise<User> {
  const { adapter, internalAdapter, logger } = ctx.context;
  const rows = await linkedAccounts(ctx, trust.accountProviderId, sub);
  const winner = rows[0];
  if (!winner) refuse("subject_rejected", "the account just linked is gone");
  if (rows.length === 1) return mine.user;
  const lost = winner.id !== mine.account.id;
  const remove = rows.slice(1).filter((r) => r.userId === winner.userId || (lost && r.id === mine.account.id));
  logger.warn(`[id-jag] ${rows.length} accounts link one subject of ${trust.accountProviderId} (concurrent first use); keeping the oldest`);
  try {
    for (const r of remove) await adapter.delete({ model: "account", where: [{ field: "id", value: r.id }] });
    if (lost && mine.created) {
      const organizationId = mine.created.membershipOrganizationId;
      if (organizationId !== undefined)
        await adapter.deleteMany({
          model: "member",
          where: [
            { field: "organizationId", value: organizationId },
            { field: "userId", value: mine.user.id },
          ],
        });
      await internalAdapter.deleteUser(mine.user.id);
    }
  } catch (e) {
    // Leftovers don't break lookups (the winner is still found first); an administrator can see them here.
    logger.error(`[id-jag] removing the losing link of a concurrent first use failed (account ${mine.account.id}, user ${mine.user.id})`, e);
  }
  if (!lost) return mine.user;
  const user = await internalAdapter.findUserById(winner.userId);
  if (!user) refuse("unknown_subject", "the winning account's user is gone");
  return user;
}

export async function resolveSubject(ctx: GenericEndpointContext, o: ResolvedReceiverOptions, trust: TrustEntry, claims: IdJagClaims, clientId: string): Promise<ResolvedSubject> {
  try {
    return await resolve(ctx, o, trust, claims, clientId);
  } catch (e) {
    if (e instanceof IdJagRefusal) throw e;
    // A database error, a unique violation lost to a concurrent request, anything unforeseen:
    // refused and audited like any other refusal, not an empty HTTP 500 (D-A24).
    ctx.context.logger.error("[id-jag] subject resolution failed unexpectedly; refusing", e);
    refuse("subject_rejected", "unexpected error in subject resolution");
  }
}

async function resolve(ctx: GenericEndpointContext, o: ResolvedReceiverOptions, trust: TrustEntry, claims: IdJagClaims, clientId: string): Promise<ResolvedSubject> {
  const internal = ctx.context.internalAdapter;
  const now = o.clock();

  if (o.resolveSubject) {
    let decision: SubjectResolution;
    try {
      decision = await o.resolveSubject({ ctx, iss: claims.iss, sub: claims.sub, claims, clientId, trustedIssuer: view(trust) });
    } catch (e) {
      ctx.context.logger.error("[id-jag] resolveSubject threw; refusing", e);
      refuse("subject_rejected", "resolveSubject threw");
    }
    if (decision?.action === "reject") refuse("subject_rejected", "resolveSubject");
    if (decision?.action === "link") {
      const user = typeof decision.userId === "string" ? await internal.findUserById(decision.userId) : null;
      if (!user) refuse("unknown_subject", "resolveSubject linked a missing user");
      return { user: assertNotBanned(user, now), via: "hook" };
    }
    if (decision?.action !== "continue") refuse("subject_rejected", "resolveSubject returned no decision");
  }

  const owner = await findAccountOwner(ctx, trust.accountProviderId, claims.sub);
  if (owner?.kind === "owned") return { user: assertNotBanned(owner.user, now), via: "account" };
  // An account row whose user is gone: never re-link it to someone else by email.
  if (owner?.kind === "orphaned") refuse("unknown_subject", "orphaned account");

  const email = claims.email?.toLowerCase();
  const domain = email ? emailDomain(email) : undefined;

  if (email && domain && trust.emailDomains?.includes(domain)) {
    const found = await internal.findUserByEmail(email, { includeAccounts: true });
    if (found) {
      // The user already has an account at this issuer under another subject: not this person's to take.
      if (found.accounts.some((a) => a.providerId === trust.accountProviderId)) refuse("unknown_subject", "email matches a user linked to another subject");
      // Only a local user who proved the address (D-A23): anyone can register an unverified
      // account with a victim's email, and linking it would hand them the victim's ID-JAGs while
      // their password still signs in. As Better Auth's own linking (requireLocalEmailVerified).
      // Refused, not passed on to JIT, which refuses an existing email anyway.
      if (found.user.emailVerified !== true) refuse("unknown_subject", "email fallback: the local user's email is not verified");
      assertNotBanned(found.user, now);
      const account = await internal.linkAccount({ userId: found.user.id, providerId: trust.accountProviderId, accountId: claims.sub });
      const user = await converge(ctx, trust, claims.sub, { account, user: found.user });
      return { user: assertNotBanned(user, now), via: "email" };
    }
  }

  if (trust.jit && email) {
    // An existing user with this email is only ever matched through the email fallback above.
    if (await internal.findUserByEmail(email)) refuse("unknown_subject", "JIT: email belongs to an existing user");
    const name = typeof claims.name === "string" && claims.name.length > 0 ? claims.name.slice(0, 256) : email;
    const user = await internal.createUser({ email, name, emailVerified: trust.jit.trustEmailVerified }, { method: "id-jag" });
    // Membership before the account link (D-A20): if it fails, the new user is removed and the
    // grant refused. Should the removal fail too, the leftover user has no linked account, so a
    // retry can't find it by `sub` and JIT refuses its email: it is never accepted half-provisioned.
    let membershipFailed = false;
    let membership: MembershipOutcome | undefined;
    try {
      membership = await addJitMembership(ctx, trust, user, claims, now);
    } catch (e) {
      membershipFailed = true;
      ctx.context.logger.error(`[id-jag] JIT: adding the new user to organization ${trust.organizationId ?? ""} failed (${e instanceof Error ? e.message : "error"}); removing the user and refusing`, e);
      try {
        await internal.deleteUser(user.id);
      } catch (e2) {
        ctx.context.logger.error(`[id-jag] JIT: removing the half-provisioned user ${user.id} failed; it has no linked account and won't be accepted`, e2);
      }
    }
    if (membershipFailed) refuse("subject_rejected", "JIT: organization membership failed");
    const account = await internal.linkAccount({ userId: user.id, providerId: trust.accountProviderId, accountId: claims.sub });
    const winner = await converge(ctx, trust, claims.sub, { account, user, created: { membershipOrganizationId: membership === "added" ? trust.organizationId : undefined } });
    return { user: assertNotBanned(winner, now), via: "jit" };
  }

  refuse("unknown_subject", claims.sub);
}
