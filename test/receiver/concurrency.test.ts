// Subject resolution under concurrency (D-A24): first use of a new subject from several requests at
// once, across two auth instances on one database. Found by review on workerd/D1: two concurrent
// email-fallback grants both linked an account, and every later grant for that user was then an
// empty HTTP 500 ("Multiple accounts match"); with JIT, the request that lost the email's UNIQUE
// insert was an empty 500. Node's synchronous SQLite rarely interleaves the requests, so each
// scenario runs twice: as it comes (where D1 shows it) and with every request held at the same
// step by a barrier in Better Auth's database hooks (so the race happens on every run and runtime).
import type { BetterAuthOptions, GenericEndpointContext } from "better-auth";
import { describe, expect, it } from "vitest";
import type { IdJagClaims, IdJagRefusal } from "../../src/core";
import { resolveReceiverOptions, resolveSubject, type StaticTrustedIssuer } from "../../src/receiver";
import {
  barrier,
  createClient,
  createOrganization,
  database,
  membersOf,
  network,
  newOrgId,
  type ReceiverHost,
  receiverHost,
  recorder,
  redeem,
  testIdp,
  uniqueEmail,
} from "../support/receiver-host";

const N = 6;

interface Setup {
  trust: Partial<StaticTrustedIssuer>;
  hooks?: (providerId: string) => BetterAuthOptions["databaseHooks"];
  organization?: boolean;
}

async function twoInstances(o: Setup) {
  const idp = await testIdp();
  const providerId = `id-jag:${idp.issuer}`;
  const db = await database();
  const recs = [recorder(), recorder()] as const;
  const trustedIssuers = [{ issuer: idp.issuer, jwksUri: idp.jwksUri, ...o.trust }];
  const databaseHooks = o.hooks?.(providerId);
  const make = (i: 0 | 1) =>
    receiverHost("mcp", {
      receiver: { trustedIssuers, fetch: network(idp).fetch },
      database: db,
      recorder: recs[i],
      ...(o.organization ? { organization: true } : {}),
      ...(databaseHooks ? { databaseHooks } : {}),
    });
  const a = await make(0);
  const b = await make(1);
  const client = await createClient(a);
  const mint = (over: Record<string, unknown>) => idp.mint(idp.claims({ client_id: client.client_id, ...over }));
  /** N requests at once, alternating between the two instances, each with its own ID-JAG. */
  const burst = async (claims: (i: number) => Record<string, unknown>) => {
    const tokens = await Promise.all(Array.from({ length: N }, (_, i) => mint(claims(i))));
    const results = await Promise.all(tokens.map((t, i) => redeem(i % 2 ? a : b, client, t)));
    for (const r of recs) await r.settle();
    return results;
  };
  const accounts = (sub: string) => a.ctx.adapter.findMany<{ id: string; userId: string }>({ model: "account", where: [{ field: "providerId", value: providerId }, { field: "accountId", value: sub }] });
  const later = async (claims: Record<string, unknown>) => {
    const r = await redeem(a, client, await mint(claims));
    await recs[0].settle();
    return { ...r, userId: r.status === 200 ? recs[0].accepted.at(-1)?.userId : undefined };
  };
  const refusedReasons = () => recs.flatMap((r) => r.refused.map((e) => e.reason));
  const acceptedUsers = () => new Set(recs.flatMap((r) => r.accepted.map((e) => e.userId)));
  return { idp, providerId, a, b, client, burst, accounts, later, refusedReasons, acceptedUsers };
}

/** Every request either succeeded or was refused cleanly: never a 500, never an empty body. */
function expectClean(results: { status: number; text: string; body: Record<string, unknown> }[]) {
  for (const r of results) {
    expect(r.status, r.text).not.toBe(500);
    if (r.status !== 200) expect(r.body).toEqual({ error: "invalid_grant", error_description: "The grant is invalid." });
  }
}

/** Hold every request whose account insert is for this provider until all N reach it, and again after it, before any re-reads. */
const accountRace =
  () =>
  (providerId: string): BetterAuthOptions["databaseHooks"] => {
    const before = barrier(N);
    const after = barrier(N);
    return {
      account: {
        create: {
          before: async (account) => {
            if (account.providerId === providerId) await before.wait();
          },
          after: async (account) => {
            if (account.providerId === providerId) await after.wait();
          },
        },
      },
    };
  };

/** Hold every JIT user insert for this email domain until all N reach it (all have passed the email check). */
const userRace =
  (domain: string) =>
  (): BetterAuthOptions["databaseHooks"] => {
    const before = barrier(N);
    return {
      user: {
        create: {
          before: async (user) => {
            if (user.email.endsWith(`@${domain}`)) await before.wait();
          },
        },
      },
    };
  };

async function verifiedUser(h: ReceiverHost, email: string) {
  return h.ctx.internalAdapter.createUser({ email, name: "Verified", emailVerified: true }, { method: "admin" });
}

describe("concurrent first use through the email fallback converges on one link", () => {
  for (const forced of [false, true]) {
    it(`${N} parallel grants for one new subject, two instances, ${forced ? "held at the account insert" : "as they come"}: one account row, a later grant succeeds`, async () => {
      const domain = `corp-${crypto.randomUUID().slice(0, 8)}.example`;
      const s = await twoInstances({ trust: { emailFallback: { domains: [domain] } }, ...(forced ? { hooks: accountRace() } : {}) });
      const email = uniqueEmail(domain);
      const user = await verifiedUser(s.a, email);
      const sub = crypto.randomUUID();
      const results = await s.burst(() => ({ sub, email }));
      expectClean(results);
      expect(results.filter((r) => r.status === 200).length).toBeGreaterThan(0);
      expect([...s.acceptedUsers()]).toEqual([user.id]);
      const rows = await s.accounts(sub);
      expect(rows).toHaveLength(1);
      expect(rows[0]?.userId).toBe(user.id);
      expect(await s.later({ sub, email })).toMatchObject({ status: 200, userId: user.id });
    });
  }
});

describe("concurrent first use through JIT converges on one user", () => {
  for (const forced of [false, true]) {
    it(`${N} parallel grants for one new subject, two instances, ${forced ? "held at the user insert" : "as they come"}: no 500, one user, one account, one membership`, async () => {
      const domain = `jit-${crypto.randomUUID().slice(0, 8)}.example`;
      const org = newOrgId();
      const s = await twoInstances({ trust: { jitProvisioning: true, organizationId: org }, organization: true, ...(forced ? { hooks: userRace(domain) } : {}) });
      await createOrganization(s.a, org);
      const email = uniqueEmail(domain);
      const sub = crypto.randomUUID();
      const results = await s.burst(() => ({ sub, email }));
      expectClean(results);
      expect(results.filter((r) => r.status === 200).length).toBeGreaterThan(0);
      // The ones that lost the race to create the user were refused (audited), never a 500.
      for (const reason of s.refusedReasons()) expect(["subject_rejected", "unknown_subject"]).toContain(reason);
      if (forced) expect(s.refusedReasons().filter((r) => r === "subject_rejected").length).toBeGreaterThan(0);
      const found = await s.a.ctx.internalAdapter.findUserByEmail(email);
      expect(found).not.toBeNull();
      expect([...s.acceptedUsers()]).toEqual([found?.user.id]);
      expect(await s.accounts(sub)).toMatchObject([{ userId: found?.user.id }]);
      expect(await membersOf(s.a, org)).toMatchObject([{ userId: found?.user.id }]);
      expect(await s.later({ sub, email })).toMatchObject({ status: 200, userId: found?.user.id });
    });
  }

  it(`${N} parallel JIT grants for one subject with different emails, held at the account insert: the losers' users, memberships and accounts are removed`, async () => {
    const domain = `jit-${crypto.randomUUID().slice(0, 8)}.example`;
    const org = newOrgId();
    const s = await twoInstances({ trust: { jitProvisioning: true, organizationId: org }, organization: true, hooks: accountRace() });
    await createOrganization(s.a, org);
    const emails = Array.from({ length: N }, () => uniqueEmail(domain));
    const sub = crypto.randomUUID();
    const results = await s.burst((i) => ({ sub, email: emails[i] }));
    expectClean(results);
    expect(results.every((r) => r.status === 200)).toBe(true);
    const winners = [...s.acceptedUsers()];
    expect(winners).toHaveLength(1);
    const rows = await s.accounts(sub);
    expect(rows).toMatchObject([{ userId: winners[0] }]);
    const remaining = (await Promise.all(emails.map((e) => s.a.ctx.internalAdapter.findUserByEmail(e)))).filter((u) => u !== null);
    expect(remaining.map((u) => u.user.id)).toEqual([winners[0]]);
    expect(await membersOf(s.a, org)).toMatchObject([{ userId: winners[0] }]);
    expect(await s.later({ sub, email: emails[0] })).toMatchObject({ status: 200, userId: winners[0] });
  });
});

describe("duplicate account rows already in the database", () => {
  it("two rows for one (provider, sub): the oldest by createdAt wins, then the lower id; never an error", async () => {
    const s = await twoInstances({ trust: {} });
    const sub = crypto.randomUUID();
    const first = await verifiedUser(s.a, uniqueEmail());
    const second = await verifiedUser(s.a, uniqueEmail());
    const t = Date.now();
    // Inserted newest first, so neither insertion order nor the adapter's default order decides.
    const row = (id: string, userId: string, createdAt: Date) => s.a.ctx.adapter.create({ model: "account", data: { id, userId, providerId: s.providerId, accountId: sub, createdAt, updatedAt: createdAt }, forceAllowId: true });
    await row(`acc-${crypto.randomUUID()}`, first.id, new Date(t));
    await row(`acc-${crypto.randomUUID()}`, second.id, new Date(t - 60_000));
    for (let i = 0; i < 3; i++) expect(await s.later({ sub })).toMatchObject({ status: 200, userId: second.id });
    // A tie on createdAt: the lower id.
    const sub2 = crypto.randomUUID();
    const tie = new Date(t - 120_000);
    const prefix = crypto.randomUUID();
    await s.a.ctx.adapter.create({ model: "account", data: { id: `${prefix}-b`, userId: first.id, providerId: s.providerId, accountId: sub2, createdAt: tie, updatedAt: tie }, forceAllowId: true });
    await s.a.ctx.adapter.create({ model: "account", data: { id: `${prefix}-a`, userId: second.id, providerId: s.providerId, accountId: sub2, createdAt: tie, updatedAt: tie }, forceAllowId: true });
    for (let i = 0; i < 3; i++) expect(await s.later({ sub: sub2 })).toMatchObject({ status: 200, userId: second.id });
    // Lookups only: rows that were already there aren't deleted.
    expect(await s.accounts(sub)).toHaveLength(2);
  });
});

describe("an unexpected error in subject resolution is an audited refusal, not an empty 500", () => {
  it("the adapter throwing: subject_rejected, logged", async () => {
    const s = await twoInstances({ trust: { jitProvisioning: true } });
    const o = resolveReceiverOptions({ trustedIssuers: [{ issuer: s.idp.issuer, jwksUri: s.idp.jwksUri, jitProvisioning: true }] });
    const errors: string[] = [];
    const internalAdapter = {
      ...s.a.ctx.internalAdapter,
      findUserByEmail: async () => {
        throw new Error("D1_ERROR: database is locked");
      },
    };
    const logger = { ...s.a.ctx.logger, error: (m: string) => void errors.push(m) };
    const ctx = { context: { ...s.a.ctx, internalAdapter, logger } } as unknown as GenericEndpointContext;
    const claims = s.idp.claims({ email: uniqueEmail() }) as unknown as IdJagClaims;
    const outcome = await resolveSubject(ctx, o, o.trustedIssuers[0]!, claims, "c").then(
      () => "accepted",
      (e: IdJagRefusal) => `${e.reason}: ${e.detail}`,
    );
    expect(outcome).toBe("subject_rejected: unexpected error in subject resolution");
    expect(errors.some((m) => m.includes("subject resolution failed unexpectedly"))).toBe(true);
  });
});
