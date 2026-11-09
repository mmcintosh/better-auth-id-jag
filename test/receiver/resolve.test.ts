// Subject resolution (plan §3.4 step 10): hook first, then the linked account, then the email
// fallback (only when allowed, only for listed domains), then JIT (off by default). Banned users
// refused whichever way they were found.
import { describe, expect, it } from "vitest";
import type { GenericEndpointContext } from "better-auth";
import type { IdJagClaims, IdJagRefusal } from "../../src/core";
import { type IdJagGrantOptions, resolveReceiverOptions, resolveSubject, type StaticTrustedIssuer, type SubjectResolution } from "../../src/receiver";
import { createClient, type HostOptions, linkedUser, network, receiverHost, recorder, redeem, testIdp, uniqueEmail } from "../support/receiver-host";

async function host(o: { trust?: Partial<StaticTrustedIssuer>; receiver?: Partial<IdJagGrantOptions>; admin?: boolean; account?: HostOptions["account"] } = {}) {
  const idp = await testIdp();
  const net = network(idp);
  const rec = recorder();
  const h = await receiverHost("mcp", { receiver: { trustedIssuers: [{ issuer: idp.issuer, jwksUri: idp.jwksUri, ...o.trust }], fetch: net.fetch, ...o.receiver }, recorder: rec, ...(o.admin ? { admin: true } : {}), ...(o.account ? { account: o.account } : {}) });
  const client = await createClient(h);
  const providerId = `id-jag:${idp.issuer}`;
  const attempt = async (over: Record<string, unknown>) => {
    const r = await redeem(h, client, await idp.mint(idp.claims({ client_id: client.client_id, ...over })));
    await rec.settle();
    return { ...r, reason: r.status === 200 ? "accepted" : rec.refused.at(-1)?.reason, userId: r.status === 200 ? rec.accepted.at(-1)?.userId : undefined };
  };
  return { idp, h, rec, client, providerId, attempt };
}

describe("subject resolution: the host hook runs first", () => {
  it("link wins over the linked account; continue falls through; reject refuses; a throw refuses", async () => {
    let decision: SubjectResolution | (() => never) = { action: "continue" };
    const seen: unknown[] = [];
    const s = await host({
      receiver: {
        resolveSubject: (input) => {
          seen.push({ iss: input.iss, sub: input.sub, clientId: input.clientId, source: input.trustedIssuer.source });
          if (typeof decision === "function") return decision();
          return decision;
        },
      },
    });
    const sub = crypto.randomUUID();
    const linked = await linkedUser(s.h, s.providerId, sub);
    const chosen = await s.h.ctx.internalAdapter.createUser({ email: uniqueEmail(), name: "Chosen" }, { method: "admin" });

    expect(await s.attempt({ sub })).toMatchObject({ reason: "accepted", userId: linked.id });
    expect(seen.at(-1)).toEqual({ iss: s.idp.issuer, sub, clientId: s.client.client_id, source: "static" });
    decision = { action: "link", userId: chosen.id };
    expect(await s.attempt({ sub })).toMatchObject({ reason: "accepted", userId: chosen.id });
    decision = { action: "link", userId: "no-such-user" };
    expect((await s.attempt({ sub })).reason).toBe("unknown_subject");
    decision = { action: "reject" };
    expect((await s.attempt({ sub })).reason).toBe("subject_rejected");
    // Refused as the hook's own decision, not as "no decision".
    expect(s.rec.refused.at(-1)?.detail).toBe("resolveSubject");
    decision = () => {
      throw new Error("hook bug");
    };
    // A throw may be transient: invalid_grant, not access_denied (D-059).
    expect((await s.attempt({ sub })).reason).toBe("subject_unavailable");
    decision = { action: "maybe" } as unknown as SubjectResolution;
    expect((await s.attempt({ sub })).reason).toBe("subject_rejected");
  });

  it("a hook-linked banned user is refused", async () => {
    let target = "";
    const s = await host({ admin: true, receiver: { resolveSubject: () => ({ action: "link", userId: target }) } });
    const u = await s.h.ctx.internalAdapter.createUser({ email: uniqueEmail(), name: "B" }, { method: "admin" });
    target = u.id;
    await s.h.ctx.internalAdapter.updateUser(u.id, { banned: true });
    expect((await s.attempt({ sub: crypto.randomUUID() })).reason).toBe("banned_user");
  });
});

describe("subject resolution: email fallback", () => {
  it("off by default: a matching email doesn't link", async () => {
    const s = await host();
    const email = uniqueEmail("corp.example");
    await s.h.ctx.internalAdapter.createUser({ email, name: "E" }, { method: "admin" });
    expect((await s.attempt({ sub: crypto.randomUUID(), email })).reason).toBe("unknown_subject");
  });

  it("on for listed domains only; links the account; case-insensitive; never takes a user linked to another sub", async () => {
    const s = await host({ trust: { emailFallback: { domains: ["Corp.Example"] } } });
    const email = uniqueEmail("corp.example");
    const u = await s.h.ctx.internalAdapter.createUser({ email, name: "E", emailVerified: true }, { method: "admin" });
    const sub = crypto.randomUUID();
    expect(await s.attempt({ sub, email: email.toUpperCase() })).toMatchObject({ reason: "accepted", userId: u.id });
    expect(await s.h.ctx.internalAdapter.findAccountByKey({ providerId: s.providerId, accountId: sub })).toMatchObject({ userId: u.id });
    // Another subject of the same issuer presenting the same email: refused.
    expect((await s.attempt({ sub: crypto.randomUUID(), email })).reason).toBe("unknown_subject");
    // A subdomain or another domain: not listed.
    for (const domain of ["eu.corp.example", "corp.example.evil", "other.example"]) {
      const e = uniqueEmail(domain);
      await s.h.ctx.internalAdapter.createUser({ email: e, name: "X", emailVerified: true }, { method: "admin" });
      expect((await s.attempt({ sub: crypto.randomUUID(), email: e })).reason).toBe("unknown_subject");
    }
  });

  it("a banned user found by email is refused, and not linked", async () => {
    const s = await host({ admin: true, trust: { emailFallback: { domains: ["corp.example"] } } });
    const email = uniqueEmail("corp.example");
    const u = await s.h.ctx.internalAdapter.createUser({ email, name: "E", emailVerified: true }, { method: "admin" });
    await s.h.ctx.internalAdapter.updateUser(u.id, { banned: true });
    const sub = crypto.randomUUID();
    expect((await s.attempt({ sub, email })).reason).toBe("banned_user");
    expect(await s.h.ctx.internalAdapter.findAccountByKey({ providerId: s.providerId, accountId: sub })).toBeNull();
  });

  it("an orphaned account (its user gone) is never re-linked by email", async () => {
    // Unit level: whether a deleted user's accounts survive depends on the adapter's cascades.
    const s = await host();
    const o = resolveReceiverOptions({ trustedIssuers: [{ issuer: s.idp.issuer, jwksUri: s.idp.jwksUri, emailFallback: { domains: ["corp.example"] } }] });
    const trust = o.trustedIssuers[0]!;
    const linked: unknown[] = [];
    const internalAdapter = {
      findUserById: async () => null,
      findUserByEmail: async () => ({ user: { id: "someone", email: "a@corp.example", emailVerified: true }, accounts: [] }),
      linkAccount: async (a: unknown) => void linked.push(a),
    };
    const claims = s.idp.claims({ email: "a@corp.example" }) as unknown as IdJagClaims;
    // The row as a database returns it: with its key, which the lookup compares exactly.
    const adapter = { ...s.h.ctx.adapter, findMany: async () => [{ id: "acc-1", userId: "gone", providerId: trust.accountProviderId, accountId: claims.sub, createdAt: new Date() }] };
    const ctx = { context: { ...s.h.ctx, adapter, internalAdapter } } as unknown as GenericEndpointContext;
    const outcome = await resolveSubject(ctx, o, trust, claims, "c").then(
      () => "accepted",
      (e: IdJagRefusal) => e.reason,
    );
    expect(outcome).toBe("unknown_subject");
    expect(linked).toHaveLength(0);
  });
});

describe("subject resolution: the email fallback needs a verified local email (D-A23)", () => {
  it("an unverified local account is never taken over: refused, nothing linked, its password still works; not JIT either", async () => {
    // The attack: someone self-registers victim@corp.example with a password and never verifies it.
    // The victim's ID-JAG must not be linked to that account (Better Auth's own account linking
    // requires a verified local email the same way: requireLocalEmailVerified).
    const s = await host({ trust: { emailFallback: { domains: ["corp.example"] }, jitProvisioning: true } });
    const email = uniqueEmail("corp.example");
    const squatter = await s.h.auth.api.signUpEmail({ body: { email, password: "attacker-password-1", name: "Squatter" } });
    expect(squatter.user.emailVerified).toBe(false);
    const sub = crypto.randomUUID();
    const r = await s.attempt({ sub, email });
    expect(r.reason).toBe("unknown_subject");
    expect(r.body).toEqual({ error: "access_denied", error_description: "The subject or client is not authorized for this request." });
    expect(s.rec.refused.at(-1)?.detail).toBe("email fallback: the local user's email is not verified");
    expect(await s.h.ctx.internalAdapter.findAccountByKey({ providerId: s.providerId, accountId: sub })).toBeNull();
    // Not JIT-provisioned instead: still exactly the one local user with that email, and its only account is the password one.
    const found = await s.h.ctx.internalAdapter.findUserByEmail(email, { includeAccounts: true });
    expect(found?.user.id).toBe(squatter.user.id);
    expect(found?.accounts.map((a) => a.providerId)).toEqual(["credential"]);
    const signIn = await s.h.auth.api.signInEmail({ body: { email, password: "attacker-password-1" } });
    expect(signIn.user.id).toBe(squatter.user.id);
  });

  it("a verified local user is linked", async () => {
    const s = await host({ trust: { emailFallback: { domains: ["corp.example"] } } });
    const email = uniqueEmail("corp.example");
    const u = await s.h.ctx.internalAdapter.createUser({ email, name: "V", emailVerified: true }, { method: "admin" });
    const sub = crypto.randomUUID();
    expect(await s.attempt({ sub, email })).toMatchObject({ reason: "accepted", userId: u.id });
    expect(await s.h.ctx.internalAdapter.findAccountByKey({ providerId: s.providerId, accountId: sub })).toMatchObject({ userId: u.id });
  });
});

describe("subject resolution: the email fallback links only the address asked for (D-064)", () => {
  // A database whose collation ignores accents (MySQL's default) answers a lookup for josé@ with jose@. Better Auth's
  // findUserByEmail refuses such a row since 1.7.16 (GHSA-2f9c-7xj7-gh55); before, it returned it. The lookup is
  // made to answer as it did then, so this proves our own check (test/adapters runs it on real databases).
  const lookAlike = (s: Awaited<ReturnType<typeof host>>, answer: (email: string) => string) => {
    const internal = s.h.ctx.internalAdapter;
    const original = internal.findUserByEmail.bind(internal);
    internal.findUserByEmail = ((email: string, options?: { includeAccounts: boolean }) => original(answer(email), options)) as typeof internal.findUserByEmail;
  };

  it("a look-alike the database matched is refused, and not linked", async () => {
    const s = await host({ trust: { emailFallback: { domains: ["corp.example"] } } });
    const local = `jose-${crypto.randomUUID().slice(0, 8)}@corp.example`;
    const u = await s.h.ctx.internalAdapter.createUser({ email: local, name: "Jose", emailVerified: true }, { method: "admin" });
    lookAlike(s, (email) => email.replace("josé", "jose"));
    const sub = crypto.randomUUID();
    const r = await s.attempt({ sub, email: local.replace("jose", "josé") });
    expect(r.reason).toBe("unknown_subject");
    expect(r.body).toEqual({ error: "access_denied", error_description: "The subject or client is not authorized for this request." });
    expect(s.rec.refused.at(-1)?.detail).toBe("email fallback: the database matched a different address");
    expect(await s.h.ctx.internalAdapter.findAccountByKey({ providerId: s.providerId, accountId: sub })).toBeNull();
    expect((await s.h.ctx.internalAdapter.findUserByEmail(local, { includeAccounts: true }))?.accounts).toEqual([]);
    // The real jose@ still links.
    expect(await s.attempt({ sub: crypto.randomUUID(), email: local })).toMatchObject({ reason: "accepted", userId: u.id });
  });

  it("the same address in another Unicode form or case is linked", async () => {
    const s = await host({ trust: { emailFallback: { domains: ["corp.example"] } } });
    const tag = crypto.randomUUID().slice(0, 8);
    const composed = `jos\u00e9-${tag}@corp.example`; // é as one code point (NFC)
    const decomposed = `jose\u0301-${tag}@corp.example`; // e + combining acute (NFD)
    const u = await s.h.ctx.internalAdapter.createUser({ email: composed, name: "José", emailVerified: true }, { method: "admin" });
    lookAlike(s, (email) => email.normalize("NFC"));
    const sub = crypto.randomUUID();
    expect(await s.attempt({ sub, email: decomposed.toUpperCase() })).toMatchObject({ reason: "accepted", userId: u.id });
    expect(await s.h.ctx.internalAdapter.findAccountByKey({ providerId: s.providerId, accountId: sub })).toMatchObject({ userId: u.id });
  });
});

describe("subject resolution: the host's account-linking settings (D-A32)", () => {
  for (const [name, account] of [["linking disabled", { accountLinking: { enabled: false } }], ["implicit linking disabled", { accountLinking: { disableImplicitLinking: true } }]] as const) {
    it(`${name}: no email fallback, even to a verified local user`, async () => {
      const s = await host({ trust: { emailFallback: { domains: ["corp.example"] } }, account });
      const email = uniqueEmail("corp.example");
      await s.h.ctx.internalAdapter.createUser({ email, name: "V", emailVerified: true }, { method: "admin" });
      const sub = crypto.randomUUID();
      expect((await s.attempt({ sub, email })).reason).toBe("unknown_subject");
      expect(s.rec.refused.at(-1)?.detail).toBe("email fallback: the host disabled implicit account linking");
      expect(await s.h.ctx.internalAdapter.findAccountByKey({ providerId: s.providerId, accountId: sub })).toBeNull();
    });
  }
});

describe("subject resolution: only the exact subject's account (RFC 7519 section 4.1.2: sub is case-sensitive)", () => {
  // A database whose collation ignores case and accents (MySQL's default) answers a lookup for the account of "José"
  // with the account of "jose" too. The account lookup is made to answer that way here; test/adapters runs it on real
  // databases.
  const fold = (v: unknown) => (typeof v === "string" ? v.normalize("NFD").replace(/\p{M}/gu, "").toLowerCase() : v);
  const looseAccounts = (s: Awaited<ReturnType<typeof host>>) => {
    const adapter = s.h.ctx.adapter;
    const original = adapter.findMany.bind(adapter);
    adapter.findMany = (async (q: Parameters<typeof original>[0]) => {
      const wanted = q.where?.find((w) => w.field === "accountId");
      if (q.model !== "account" || !wanted) return original(q);
      // Every row of the provider, then the loose match, then the limit asked for: as such a database answers.
      const rows = await original({ ...q, where: q.where?.filter((w) => w !== wanted), limit: 100_000 });
      return (rows as Record<string, unknown>[]).filter((r) => fold(r.accountId) === fold(wanted.value)).slice(0, q.limit);
    }) as typeof adapter.findMany;
  };

  it("an ID-JAG for José never gets jose's user, though the database matched jose's account", async () => {
    const s = await host();
    const tag = crypto.randomUUID().slice(0, 8);
    const jose = await linkedUser(s.h, s.providerId, `jose-${tag}`);
    looseAccounts(s);
    // The hazard is emulated: the lookup for José returns jose's row.
    expect(await s.h.ctx.adapter.findMany<{ userId: string }>({ model: "account", where: [{ field: "providerId", value: s.providerId }, { field: "accountId", value: `JOSÉ-${tag}` }] })).toMatchObject([{ userId: jose.id }]);
    expect((await s.attempt({ sub: `JOSÉ-${tag}` })).reason).toBe("unknown_subject");
    expect(await s.attempt({ sub: `jose-${tag}` })).toMatchObject({ reason: "accepted", userId: jose.id });
  });

  it("more loose matches than the lookup reads: refused, never taken for no account (nor provisioned)", async () => {
    const s = await host({ trust: { jitProvisioning: true } });
    const tag = crypto.randomUUID().slice(0, 8);
    // 101 case variants of one subject, all older than its own account: on such a database they fill the lookup.
    const variants = new Set<string>();
    for (let i = 0; variants.size < 101; i++) variants.add(`abcdefgh-${tag}`.replace(/[a-h]/g, (c, at: number) => ((i >> at) & 1 ? c.toUpperCase() : c)));
    variants.delete(`abcdefgh-${tag}`);
    for (const v of [...variants].slice(0, 101)) await linkedUser(s.h, s.providerId, v);
    const own = await linkedUser(s.h, s.providerId, `abcdefgh-${tag}`);
    looseAccounts(s);
    const r = await s.attempt({ sub: `abcdefgh-${tag}`, email: uniqueEmail() });
    expect(r.reason).toBe("subject_unavailable");
    expect(s.rec.refused.at(-1)?.detail).toMatch(/more than 100 accounts/);
    void own;
  });

  it("with JIT, José gets a user of his own, and jose's link is left alone", async () => {
    const s = await host({ trust: { jitProvisioning: true } });
    const tag = crypto.randomUUID().slice(0, 8);
    const jose = await linkedUser(s.h, s.providerId, `jose-${tag}`);
    looseAccounts(s);
    const r = await s.attempt({ sub: `José-${tag}`, email: uniqueEmail() });
    expect(r.reason).toBe("accepted");
    expect(r.userId).not.toBe(jose.id);
    expect(await s.attempt({ sub: `jose-${tag}` })).toMatchObject({ reason: "accepted", userId: jose.id });
    expect(await s.attempt({ sub: `José-${tag}` })).toMatchObject({ reason: "accepted", userId: r.userId });
  });
});

describe("subject resolution: JIT provisioning", () => {
  it("off by default", async () => {
    const s = await host();
    expect((await s.attempt({ sub: crypto.randomUUID(), email: uniqueEmail() })).reason).toBe("unknown_subject");
  });

  it("on: creates the user (email not verified unless trusted) and links it; never for an existing email", async () => {
    const s = await host({ trust: { jitProvisioning: true } });
    const email = uniqueEmail();
    const sub = crypto.randomUUID();
    const r = await s.attempt({ sub, email, name: "New Person" });
    expect(r.reason).toBe("accepted");
    const user = await s.h.ctx.internalAdapter.findUserById(r.userId!);
    expect(user).toMatchObject({ email, name: "New Person", emailVerified: false });
    expect(await s.h.ctx.internalAdapter.findAccountByKey({ providerId: s.providerId, accountId: sub })).toMatchObject({ userId: r.userId });
    // The same subject again: found by the account, no second user.
    expect(await s.attempt({ sub, email })).toMatchObject({ reason: "accepted", userId: r.userId });
    // Another subject with an email that already exists here: refused (only the email fallback may match it).
    expect((await s.attempt({ sub: crypto.randomUUID(), email })).reason).toBe("unknown_subject");
    // No email claim: nothing to provision.
    expect((await s.attempt({ sub: crypto.randomUUID() })).reason).toBe("unknown_subject");
  });

  it("a failed account link removes the new user and refuses as subject_unavailable, so a retry can work", async () => {
    const s = await host({ trust: { jitProvisioning: true } });
    const internal = s.h.ctx.internalAdapter;
    const original = internal.linkAccount.bind(internal);
    internal.linkAccount = (async () => {
      throw new Error("database briefly down");
    }) as typeof internal.linkAccount;
    const email = uniqueEmail();
    const sub = crypto.randomUUID();
    expect((await s.attempt({ sub, email })).reason).toBe("subject_unavailable");
    expect(await internal.findUserByEmail(email)).toBeNull();
    internal.linkAccount = original;
    const r = await s.attempt({ sub, email });
    expect(r.reason).toBe("accepted");
    expect(await internal.findAccountByKey({ providerId: s.providerId, accountId: sub })).toMatchObject({ userId: r.userId });
  });

  it("trustEmailVerified: the IdP's say-so marks the email verified", async () => {
    const s = await host({ trust: { jitProvisioning: { trustEmailVerified: true } } });
    const r = await s.attempt({ sub: crypto.randomUUID(), email: uniqueEmail() });
    expect(r.reason).toBe("accepted");
    expect((await s.h.ctx.internalAdapter.findUserById(r.userId!))?.emailVerified).toBe(true);
  });
});
