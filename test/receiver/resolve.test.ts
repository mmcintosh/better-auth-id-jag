// Subject resolution (plan §3.4 step 10): hook first, then the linked account, then the email
// fallback (only when allowed, only for listed domains), then JIT (off by default). Banned users
// refused whichever way they were found.
import { describe, expect, it } from "vitest";
import type { GenericEndpointContext } from "better-auth";
import type { IdJagClaims, IdJagRefusal } from "../../src/core";
import { type IdJagGrantOptions, resolveReceiverOptions, resolveSubject, type StaticTrustedIssuer, type SubjectResolution } from "../../src/receiver";
import { createClient, linkedUser, network, receiverHost, recorder, redeem, testIdp, uniqueEmail } from "../support/receiver-host";

async function host(o: { trust?: Partial<StaticTrustedIssuer>; receiver?: Partial<IdJagGrantOptions>; admin?: boolean } = {}) {
  const idp = await testIdp();
  const net = network(idp);
  const rec = recorder();
  const h = await receiverHost("mcp", { receiver: { trustedIssuers: [{ issuer: idp.issuer, jwksUri: idp.jwksUri, ...o.trust }], fetch: net.fetch, ...o.receiver }, recorder: rec, ...(o.admin ? { admin: true } : {}) });
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
    expect((await s.attempt({ sub })).reason).toBe("subject_rejected");
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
    const adapter = { ...s.h.ctx.adapter, findMany: async () => [{ id: "acc-1", userId: "gone", createdAt: new Date() }] };
    const ctx = { context: { ...s.h.ctx, adapter, internalAdapter } } as unknown as GenericEndpointContext;
    const claims = s.idp.claims({ email: "a@corp.example" }) as unknown as IdJagClaims;
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
    expect(r.body).toEqual({ error: "invalid_grant", error_description: "The grant is invalid." });
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

  it("trustEmailVerified: the IdP's say-so marks the email verified", async () => {
    const s = await host({ trust: { jitProvisioning: { trustEmailVerified: true } } });
    const r = await s.attempt({ sub: crypto.randomUUID(), email: uniqueEmail() });
    expect(r.reason).toBe("accepted");
    expect((await s.h.ctx.internalAdapter.findUserById(r.userId!))?.emailVerified).toBe(true);
  });
});
