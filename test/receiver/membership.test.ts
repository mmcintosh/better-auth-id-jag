// JIT provisioning adds organization membership (D-009 #5, D-A18–D-A20): a user JIT creates for a
// trust entry naming an organization joins it, as the organization plugin stores members; the role
// is the entry's `jitRole` (default "member") or, for sso rows, sso's `organizationProvisioning`.
// Users found any other way are left alone. A failed membership removes the new user and refuses.
import type { GenericEndpointContext, User } from "better-auth";
import { describe, expect, it } from "vitest";
import type { IdJagClaims, IdJagRefusal } from "../../src/core";
import { addJitMembership, type IdJagGrantOptions, resolveReceiverOptions, resolveSubject, type StaticTrustedIssuer, TRUSTED_ISSUER_MODEL } from "../../src/receiver";
import {
  createClient,
  createOrganization,
  linkedUser,
  membersOf,
  network,
  newOrgId,
  type ReceiverHost,
  receiverHost,
  recorder,
  redeem,
  type SsoOrganizationProvisioning,
  type TestIdp,
  testIdp,
  uniqueEmail,
} from "../support/receiver-host";

interface Setup {
  trust?: Partial<StaticTrustedIssuer> | null;
  receiver?: Partial<IdJagGrantOptions>;
  organization?: boolean;
  sso?: { organizationProvisioning?: SsoOrganizationProvisioning };
  logs?: string[];
}

async function host(o: Setup = {}) {
  const idp = await testIdp();
  const rec = recorder();
  const trustedIssuers = o.trust === null ? [] : [{ issuer: idp.issuer, jwksUri: idp.jwksUri, jitProvisioning: true, ...o.trust }];
  const h = await receiverHost("mcp", {
    receiver: { trustedIssuers, fetch: network(idp).fetch, ...o.receiver },
    recorder: rec,
    organization: o.organization ?? true,
    ...(o.sso ? { sso: o.sso } : {}),
    ...(o.logs ? { logs: o.logs } : {}),
  });
  const client = await createClient(h);
  const attempt = async (over: Record<string, unknown> = {}) => {
    const r = await redeem(h, client, await idp.mint(idp.claims({ client_id: client.client_id, ...over })));
    await rec.settle();
    return { ...r, reason: r.status === 200 ? "accepted" : rec.refused.at(-1)?.reason, userId: r.status === 200 ? rec.accepted.at(-1)?.userId : undefined };
  };
  return { idp, h, rec, client, attempt };
}

async function ssoRow(h: ReceiverHost, idp: TestIdp, organizationId: string) {
  const providerId = `sso-${crypto.randomUUID().slice(0, 8)}`;
  const owner = await h.ctx.internalAdapter.createUser({ email: uniqueEmail(), name: "Owner" }, { method: "admin" });
  await h.ctx.adapter.create({
    model: "ssoProvider",
    data: { userId: owner.id, providerId, issuer: idp.issuer, domain: "corp.example", organizationId, oidcConfig: JSON.stringify({ issuer: idp.issuer, clientId: "rp", clientSecret: "s", pkce: true, jwksEndpoint: idp.jwksUri }) },
  });
  return providerId;
}

describe("JIT membership: static entries", () => {
  it("a JIT user joins the entry's organization as `member` by default", async () => {
    const org = newOrgId();
    const s = await host({ trust: { organizationId: org } });
    await createOrganization(s.h, org);
    const r = await s.attempt({ sub: crypto.randomUUID(), email: uniqueEmail() });
    expect(r.reason).toBe("accepted");
    expect(await membersOf(s.h, org)).toMatchObject([{ userId: r.userId, role: "member" }]);
  });

  it("jitRole sets the role; the same subject again adds nothing", async () => {
    const org = newOrgId();
    const t = await host({ trust: { organizationId: org, jitRole: "admin" } });
    await createOrganization(t.h, org);
    const sub = crypto.randomUUID();
    const email = uniqueEmail();
    const r = await t.attempt({ sub, email });
    expect(r.reason).toBe("accepted");
    expect(await membersOf(t.h, org)).toMatchObject([{ userId: r.userId, role: "admin" }]);
    expect(await t.attempt({ sub, email })).toMatchObject({ reason: "accepted", userId: r.userId });
    expect(await membersOf(t.h, org)).toHaveLength(1);
  });

  it("no organizationId: no membership anywhere; jitRole without organizationId is a configuration error", async () => {
    const s = await host();
    const org = await createOrganization(s.h);
    expect((await s.attempt({ sub: crypto.randomUUID(), email: uniqueEmail() })).reason).toBe("accepted");
    expect(await membersOf(s.h, org)).toHaveLength(0);
    expect(() => resolveReceiverOptions({ trustedIssuers: [{ issuer: "https://idp.example", jwksUri: "https://idp.example/jwks", jitRole: "admin" }] })).toThrow(/jitRole needs organizationId/);
  });

  it("an existing user (linked account, or the email fallback) is not added to the organization", async () => {
    const org = newOrgId();
    const s = await host({ trust: { organizationId: org, emailFallback: { domains: ["corp.example"] } } });
    await createOrganization(s.h, org);
    const sub = crypto.randomUUID();
    const linked = await linkedUser(s.h, `id-jag:${s.idp.issuer}`, sub);
    expect(await s.attempt({ sub, email: uniqueEmail() })).toMatchObject({ reason: "accepted", userId: linked.id });
    const email = uniqueEmail("corp.example");
    const byEmail = await s.h.ctx.internalAdapter.createUser({ email, name: "E" }, { method: "admin" });
    expect(await s.attempt({ sub: crypto.randomUUID(), email })).toMatchObject({ reason: "accepted", userId: byEmail.id });
    expect(await membersOf(s.h, org)).toHaveLength(0);
  });

  it("a pending invitation for the email decides instead (as sso): no membership is added", async () => {
    const org = newOrgId();
    const t = await host({ trust: { organizationId: org } });
    await createOrganization(t.h, org);
    const email = uniqueEmail();
    const inviter = await t.h.ctx.internalAdapter.createUser({ email: uniqueEmail(), name: "Inviter" }, { method: "admin" });
    await t.h.ctx.adapter.create({ model: "invitation", data: { organizationId: org, email, role: "admin", status: "pending", expiresAt: new Date(Date.now() + 3600_000), inviterId: inviter.id, createdAt: new Date() } });
    expect((await t.attempt({ sub: crypto.randomUUID(), email })).reason).toBe("accepted");
    expect(await membersOf(t.h, org)).toHaveLength(0);
  });
});

describe("JIT membership: sso rows and table rows", () => {
  it("an sso row's organization, with sso's organizationProvisioning.defaultRole", async () => {
    const s = await host({ trust: null, receiver: { sso: { jitProvisioning: true } }, sso: { organizationProvisioning: { defaultRole: "admin" } } });
    const org = await createOrganization(s.h);
    await ssoRow(s.h, s.idp, org);
    const r = await s.attempt({ sub: crypto.randomUUID(), email: uniqueEmail() });
    expect(r.reason).toBe("accepted");
    expect(await membersOf(s.h, org)).toMatchObject([{ userId: r.userId, role: "admin" }]);
  });

  it("sso's getRole is asked, with the user, the ID-JAG's claims and the sso provider", async () => {
    const seen: Record<string, unknown>[] = [];
    const getRole = async (data: Record<string, unknown>) => {
      seen.push(data);
      return "admin" as const;
    };
    const s = await host({ trust: null, receiver: { sso: { jitProvisioning: true } }, sso: { organizationProvisioning: { defaultRole: "member", getRole } as SsoOrganizationProvisioning } });
    const org = await createOrganization(s.h);
    const providerId = await ssoRow(s.h, s.idp, org);
    const sub = crypto.randomUUID();
    const email = uniqueEmail();
    const r = await s.attempt({ sub, email });
    expect(r.reason).toBe("accepted");
    expect(await membersOf(s.h, org)).toMatchObject([{ userId: r.userId, role: "admin" }]);
    expect(seen).toHaveLength(1);
    expect(seen[0]).toMatchObject({ user: { id: r.userId, email }, userInfo: { sub, email, iss: s.idp.issuer }, provider: { providerId, organizationId: org, oidcConfig: { issuer: s.idp.issuer } } });
  });

  it("sso's organizationProvisioning.disabled: no membership; no setting: `member`", async () => {
    const off = await host({ trust: null, receiver: { sso: { jitProvisioning: true } }, sso: { organizationProvisioning: { disabled: true } } });
    const org = await createOrganization(off.h);
    await ssoRow(off.h, off.idp, org);
    expect((await off.attempt({ sub: crypto.randomUUID(), email: uniqueEmail() })).reason).toBe("accepted");
    expect(await membersOf(off.h, org)).toHaveLength(0);

    const plain = await host({ trust: null, receiver: { sso: { jitProvisioning: true } }, sso: {} });
    const org2 = await createOrganization(plain.h);
    await ssoRow(plain.h, plain.idp, org2);
    const r = await plain.attempt({ sub: crypto.randomUUID(), email: uniqueEmail() });
    expect(await membersOf(plain.h, org2)).toMatchObject([{ userId: r.userId, role: "member" }]);
  });

  it("a table row's organizationId and jitRole", async () => {
    const s = await host({ trust: null, receiver: { trustedIssuerTable: true } });
    const org = await createOrganization(s.h);
    await s.h.ctx.adapter.create({
      model: TRUSTED_ISSUER_MODEL,
      data: { issuer: s.idp.issuer, jwksUri: s.idp.jwksUri, enabled: true, jitProvisioning: true, jitTrustEmailVerified: false, organizationId: org, jitRole: "owner", createdAt: new Date(), updatedAt: new Date() },
    });
    const r = await s.attempt({ sub: crypto.randomUUID(), email: uniqueEmail() });
    expect(r.reason).toBe("accepted");
    expect(await membersOf(s.h, org)).toMatchObject([{ userId: r.userId, role: "owner" }]);
  });
});

describe("JIT membership: without the organization plugin, and when it fails", () => {
  it("no organization plugin: a startup warning, then the user is created without a membership", async () => {
    const logs: string[] = [];
    const s = await host({ organization: false, trust: { organizationId: "org-elsewhere" }, logs });
    expect(logs.some((l) => l.startsWith("warn") && l.includes("organization plugin is not installed") && l.includes(s.idp.issuer))).toBe(true);
    const email = uniqueEmail();
    const r = await s.attempt({ sub: crypto.randomUUID(), email });
    expect(r.reason).toBe("accepted");
    expect((await s.h.ctx.internalAdapter.findUserByEmail(email))?.user.id).toBe(r.userId);
    expect(logs.filter((l) => l.includes("no membership added"))).toHaveLength(1);
    // With the plugin installed there is no warning.
    const quiet: string[] = [];
    await host({ trust: { organizationId: "org-elsewhere" }, logs: quiet });
    expect(quiet.some((l) => l.includes("organization plugin is not installed"))).toBe(false);
  });

  it("the organization doesn't exist: the new user is removed, the grant refused (subject_rejected), and a retry is refused too", async () => {
    const logs: string[] = [];
    const s = await host({ trust: { organizationId: `missing-${crypto.randomUUID()}` }, logs });
    const sub = crypto.randomUUID();
    const email = uniqueEmail();
    const r = await s.attempt({ sub, email });
    expect(r.reason).toBe("subject_rejected");
    expect(s.rec.refused.at(-1)?.detail).toBe("JIT: organization membership failed");
    expect(r.body).toEqual({ error: "invalid_grant", error_description: "The grant is invalid." });
    expect(await s.h.ctx.internalAdapter.findUserByEmail(email)).toBeNull();
    expect(await s.h.ctx.internalAdapter.findAccountByKey({ providerId: `id-jag:${s.idp.issuer}`, accountId: sub })).toBeNull();
    expect(logs.some((l) => l.startsWith("error") && l.includes("removing the user and refusing"))).toBe(true);
    expect((await s.attempt({ sub, email })).reason).toBe("subject_rejected");
  });

  it("sso's getRole throwing (or returning no role) refuses the same way", async () => {
    let answer: () => unknown = () => {
      throw new Error("role service down");
    };
    const getRole = async () => answer();
    const s = await host({ trust: null, receiver: { sso: { jitProvisioning: true } }, sso: { organizationProvisioning: { getRole } as unknown as SsoOrganizationProvisioning } });
    const org = await createOrganization(s.h);
    await ssoRow(s.h, s.idp, org);
    const email = uniqueEmail();
    expect((await s.attempt({ sub: crypto.randomUUID(), email })).reason).toBe("subject_rejected");
    expect(await s.h.ctx.internalAdapter.findUserByEmail(email)).toBeNull();
    answer = () => "";
    expect((await s.attempt({ sub: crypto.randomUUID(), email })).reason).toBe("subject_rejected");
    expect(await membersOf(s.h, org)).toHaveLength(0);
  });

  it("if removing the user fails too, the account is never linked, so the user is never accepted", async () => {
    const s = await host({ trust: { organizationId: `missing-${crypto.randomUUID()}` } });
    const o = resolveReceiverOptions({ trustedIssuers: [{ issuer: s.idp.issuer, jwksUri: s.idp.jwksUri, jitProvisioning: true, organizationId: "missing" }] });
    const linked: unknown[] = [];
    const errors: string[] = [];
    const internalAdapter = {
      ...s.h.ctx.internalAdapter,
      deleteUser: async () => {
        throw new Error("database gone");
      },
      linkAccount: async (a: unknown) => void linked.push(a),
    };
    const logger = { ...s.h.ctx.logger, error: (m: string) => void errors.push(m) };
    const ctx = { context: { ...s.h.ctx, internalAdapter, logger } } as unknown as GenericEndpointContext;
    const claims = s.idp.claims({ email: uniqueEmail() }) as unknown as IdJagClaims;
    const outcome = await resolveSubject(ctx, o, o.trustedIssuers[0]!, claims, "c").then(
      () => "accepted",
      (e: IdJagRefusal) => e.reason,
    );
    expect(outcome).toBe("subject_rejected");
    expect(linked).toHaveLength(0);
    expect(errors.some((m) => m.includes("removing the half-provisioned user"))).toBe(true);
  });

  it("idempotent: a second call for a member adds nothing", async () => {
    const s = await host({ trust: null });
    const org = await createOrganization(s.h);
    const o = resolveReceiverOptions({ trustedIssuers: [{ issuer: s.idp.issuer, jwksUri: s.idp.jwksUri, jitProvisioning: true, organizationId: org, jitRole: "admin" }] });
    const user = (await s.h.ctx.internalAdapter.createUser({ email: uniqueEmail(), name: "M" }, { method: "admin" })) as User;
    const ctx = { context: s.h.ctx } as unknown as GenericEndpointContext;
    const claims = s.idp.claims() as unknown as IdJagClaims;
    const trust = o.trustedIssuers[0]!;
    expect(await addJitMembership(ctx, trust, user, claims, new Date())).toBe("added");
    expect(await addJitMembership(ctx, trust, user, claims, new Date())).toBe("already-member");
    expect(await membersOf(s.h, org)).toMatchObject([{ userId: user.id, role: "admin" }]);
  });
});
