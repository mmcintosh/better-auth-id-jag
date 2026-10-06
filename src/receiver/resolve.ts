// The ID-JAG's subject → a local user (plan §3.4 step 10), first hit wins:
// 1. the host's `resolveSubject` hook: link / continue / reject (a throw is a reject: gates fail closed);
// 2. an account linked with providerId = the trust entry's account provider id (the sso providerId
//    for sso-trusted issuers) and accountId = `sub`: what `@better-auth/sso` creates at sign-in;
// 3. the `email` claim, only when the trust entry allows it and the domain is listed or verified;
//    links the account on success;
// 4. JIT provisioning, only when enabled (off by default);
// otherwise `unknown_subject`. A banned user is refused whichever way it was found. Every refusal
// reaches the caller with the same generic wording (S8); the reason goes to the audit event.
import type { GenericEndpointContext, User } from "better-auth";
import { type IdJagClaims, refuse } from "../core";
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

export async function resolveSubject(ctx: GenericEndpointContext, o: ResolvedReceiverOptions, trust: TrustEntry, claims: IdJagClaims, clientId: string): Promise<ResolvedSubject> {
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

  const key = { providerId: trust.accountProviderId, accountId: claims.sub };
  const owner = await internal.findAccountOwnerByKey(key);
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
      assertNotBanned(found.user, now);
      await internal.linkAccount({ userId: found.user.id, providerId: trust.accountProviderId, accountId: claims.sub });
      return { user: found.user, via: "email" };
    }
  }

  if (trust.jit && email) {
    // An existing user with this email is only ever matched through the email fallback above.
    if (await internal.findUserByEmail(email)) refuse("unknown_subject", "JIT: email belongs to an existing user");
    const name = typeof claims.name === "string" && claims.name.length > 0 ? claims.name.slice(0, 256) : email;
    const user = await internal.createUser({ email, name, emailVerified: trust.jit.trustEmailVerified }, { method: "id-jag" });
    await internal.linkAccount({ userId: user.id, providerId: trust.accountProviderId, accountId: claims.sub });
    return { user, via: "jit" };
  }

  refuse("unknown_subject", claims.sub);
}
