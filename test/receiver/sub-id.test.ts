// Subject resolution by the SAML NameID `sub_id` (draft -04 §3.2, §9.5; Phase 3 R3-S1–R3-S8,
// D-A27–D-A31). A trust entry with `samlSubjects` resolves users by (mapping.accountProviderId,
// nameid), what `@better-auth/sso` stores for a SAML sign-in, instead of by `sub`.
import type { GenericEndpointContext } from "better-auth";
import { describe, expect, it } from "vitest";
import type { IdJagClaims, IdJagRefusal } from "../../src/core";
import { type IdJagGrantOptions, resolveReceiverOptions, resolveSubject, type StaticTrustedIssuer, subjectKey, TRANSIENT_NAMEID_FORMAT, TRUSTED_ISSUER_MODEL } from "../../src/receiver";
import { createClient, linkedUser, network, receiverHost, recorder, redeem, type TestIdp, testIdp, uniqueEmail } from "../support/receiver-host";

const PERSISTENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
const EMAIL_FORMAT = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
const GENERIC = { error: "invalid_grant", error_description: "The grant is invalid." };

/** A unique SAML namespace (in workerd the hosts of one file share a D1). */
function samlNamespace() {
  const u = crypto.randomUUID().slice(0, 8);
  return { issuer: `https://saml-${u}.example/metadata`, sp: `https://receiver-${u}.example/saml/sp`, providerId: `saml-${u}` };
}

const subId = (over: Record<string, unknown>) => ({ format: "saml-nameid", ...over });

async function host(o: { trust?: Partial<StaticTrustedIssuer>; receiver?: Partial<IdJagGrantOptions>; admin?: boolean } = {}) {
  const idp = await testIdp();
  const net = network(idp);
  const rec = recorder();
  const h = await receiverHost("mcp", {
    receiver: { trustedIssuers: [{ issuer: idp.issuer, jwksUri: idp.jwksUri, ...o.trust }], fetch: net.fetch, ...o.receiver },
    recorder: rec,
    ...(o.admin ? { admin: true } : {}),
  });
  const client = await createClient(h);
  const providerId = `id-jag:${idp.issuer}`;
  const attemptWith = async (from: TestIdp, over: Record<string, unknown>) => {
    const r = await redeem(h, client, await from.mint(from.claims({ client_id: client.client_id, ...over })));
    await rec.settle();
    return { ...r, reason: r.status === 200 ? "accepted" : rec.refused.at(-1)?.reason, detail: r.status === 200 ? undefined : rec.refused.at(-1)?.detail, userId: r.status === 200 ? rec.accepted.at(-1)?.userId : undefined };
  };
  const attempt = (over: Record<string, unknown>) => attemptWith(idp, over);
  const account = (providerId: string, accountId: string) => h.ctx.internalAdapter.findAccountByKey({ providerId, accountId });
  return { idp, net, h, rec, client, providerId, attempt, attemptWith, account };
}

describe("R3-S1: sub_id never establishes trust (§9.5)", () => {
  it("a sub_id mapped only under another trust entry is refused; the same token's namespace is accepted only from that entry", async () => {
    const x = samlNamespace();
    const y = samlNamespace();
    // Two trusted issuers: A maps only Y, B maps X.
    const a = await testIdp();
    const b = await testIdp();
    const rec = recorder();
    const h = await receiverHost("mcp", {
      receiver: {
        trustedIssuers: [
          { issuer: a.issuer, jwksUri: a.jwksUri, samlSubjects: [{ issuer: y.issuer, accountProviderId: y.providerId }] },
          { issuer: b.issuer, jwksUri: b.jwksUri, samlSubjects: [{ issuer: x.issuer, accountProviderId: x.providerId }] },
        ],
        fetch: network(a, b).fetch,
      },
      recorder: rec,
    });
    const client = await createClient(h);
    const nameid = `alice-${crypto.randomUUID()}`;
    const victim = await linkedUser(h, x.providerId, nameid);
    const sub = crypto.randomUUID();
    // The same sub linked at A, so a fallback to sub would be visible as an acceptance.
    await linkedUser(h, `id-jag:${a.issuer}`, sub);
    const go = async (from: TestIdp) => {
      const r = await redeem(h, client, await from.mint(from.claims({ client_id: client.client_id, sub, sub_id: subId({ issuer: x.issuer, nameid }) })));
      await rec.settle();
      return { status: r.status, body: r.body, reason: r.status === 200 ? "accepted" : rec.refused.at(-1)?.reason, detail: rec.refused.at(-1)?.detail, userId: r.status === 200 ? rec.accepted.at(-1)?.userId : undefined };
    };
    const fromA = await go(a);
    expect(fromA).toMatchObject({ status: 400, body: GENERIC, reason: "subject_rejected" });
    expect(fromA.detail).toMatch(/^sub_id not authorized for this issuer/);
    // The log-safe members are in the detail (to configure from), the NameID is not.
    expect(fromA.detail).toContain(x.issuer);
    expect(fromA.detail).not.toContain(nameid);
    // From B, which maps X: the linked SAML account.
    expect(await go(b)).toMatchObject({ reason: "accepted", userId: victim.id });
  });

  it("an untrusted iss with a valid-looking sub_id is untrusted_issuer, and nothing is fetched", async () => {
    const x = samlNamespace();
    const s = await host({ trust: { samlSubjects: [{ issuer: x.issuer, accountProviderId: x.providerId }] } });
    const nameid = `alice-${crypto.randomUUID()}`;
    await linkedUser(s.h, x.providerId, nameid);
    const rogue = await testIdp();
    const r = await s.attemptWith(rogue, { sub_id: subId({ issuer: x.issuer, nameid }) });
    expect(r).toMatchObject({ reason: "untrusted_issuer", body: GENERIC });
    expect(s.net.calls).toHaveLength(0);
  });
});

describe("R3-S2: every configured member compared, null-safe (§3.2.2)", () => {
  it("sp_name_qualifier: mismatch, absent when configured, present when not configured: all refused; exact: accepted", async () => {
    const x = samlNamespace();
    const z = samlNamespace();
    const s = await host({
      trust: {
        samlSubjects: [
          { issuer: x.issuer, spNameQualifier: x.sp, accountProviderId: x.providerId },
          { issuer: z.issuer, accountProviderId: z.providerId },
        ],
      },
    });
    const nameid = `alice-${crypto.randomUUID()}`;
    const ux = await linkedUser(s.h, x.providerId, nameid);
    const uz = await linkedUser(s.h, z.providerId, nameid);
    expect(await s.attempt({ sub_id: subId({ issuer: x.issuer, nameid, sp_name_qualifier: x.sp }) })).toMatchObject({ reason: "accepted", userId: ux.id });
    for (const bad of [
      subId({ issuer: x.issuer, nameid, sp_name_qualifier: `${x.sp}/other` }),
      subId({ issuer: x.issuer, nameid }),
      subId({ issuer: z.issuer, nameid, sp_name_qualifier: x.sp }),
      // The issuer exactly: no trailing slash, no case folding.
      subId({ issuer: `${x.issuer}/`, nameid, sp_name_qualifier: x.sp }),
      subId({ issuer: x.issuer.toUpperCase(), nameid, sp_name_qualifier: x.sp }),
    ]) {
      const r = await s.attempt({ sub_id: bad });
      expect(r, JSON.stringify(bad)).toMatchObject({ reason: "subject_rejected", body: GENERIC });
      expect(r.detail).toMatch(/^sub_id not authorized for this issuer/);
    }
    expect(await s.attempt({ sub_id: subId({ issuer: z.issuer, nameid }) })).toMatchObject({ reason: "accepted", userId: uz.id });
  });

  it("name_qualifier: the same null-safe rule; an explicit null in the configuration means absent", async () => {
    const x = samlNamespace();
    const s = await host({ trust: { samlSubjects: [{ issuer: x.issuer, nameQualifier: "https://nq.example", spNameQualifier: null, accountProviderId: x.providerId }] } });
    const nameid = `alice-${crypto.randomUUID()}`;
    const u = await linkedUser(s.h, x.providerId, nameid);
    expect(await s.attempt({ sub_id: subId({ issuer: x.issuer, nameid, name_qualifier: "https://nq.example" }) })).toMatchObject({ reason: "accepted", userId: u.id });
    for (const bad of [subId({ issuer: x.issuer, nameid }), subId({ issuer: x.issuer, nameid, name_qualifier: "https://other.example" }), subId({ issuer: x.issuer, nameid, name_qualifier: "https://nq.example", sp_name_qualifier: x.sp })])
      expect((await s.attempt({ sub_id: bad })).reason, JSON.stringify(bad)).toBe("subject_rejected");
  });

  it("nameIdFormats: a listed format is accepted; an unlisted or absent one is refused; no list accepts any non-transient format", async () => {
    const x = samlNamespace();
    const z = samlNamespace();
    const s = await host({
      trust: {
        samlSubjects: [
          { issuer: x.issuer, nameIdFormats: [PERSISTENT], accountProviderId: x.providerId },
          { issuer: z.issuer, accountProviderId: z.providerId },
        ],
      },
    });
    const nameid = `alice-${crypto.randomUUID()}`;
    const u = await linkedUser(s.h, x.providerId, nameid);
    const uz = await linkedUser(s.h, z.providerId, nameid);
    expect(await s.attempt({ sub_id: subId({ issuer: x.issuer, nameid, nameid_format: PERSISTENT }) })).toMatchObject({ reason: "accepted", userId: u.id });
    for (const bad of [subId({ issuer: x.issuer, nameid, nameid_format: EMAIL_FORMAT }), subId({ issuer: x.issuer, nameid })]) {
      const r = await s.attempt({ sub_id: bad });
      expect(r.reason).toBe("subject_rejected");
      expect(r.detail).toMatch(/^sub_id nameid_format not allowed/);
    }
    expect(await s.attempt({ sub_id: subId({ issuer: z.issuer, nameid, nameid_format: EMAIL_FORMAT }) })).toMatchObject({ reason: "accepted", userId: uz.id });
    expect(await s.attempt({ sub_id: subId({ issuer: z.issuer, nameid }) })).toMatchObject({ reason: "accepted", userId: uz.id });
  });
});

describe("R3-S3: a malformed sub_id with mappings configured is refused, never a fallback to sub", () => {
  it("an unknown member, an empty nameid, control characters, a missing issuer, a non-string member", async () => {
    const x = samlNamespace();
    const s = await host({ trust: { samlSubjects: [{ issuer: x.issuer, accountProviderId: x.providerId }] } });
    const sub = crypto.randomUUID();
    // Linked by sub: a fallback to sub would be accepted.
    await linkedUser(s.h, s.providerId, sub);
    const nameid = `alice-${crypto.randomUUID()}`;
    await linkedUser(s.h, x.providerId, nameid);
    for (const bad of [
      subId({ issuer: x.issuer, nameid, extra: "x" }),
      subId({ issuer: x.issuer, nameid: "" }),
      subId({ issuer: x.issuer, nameid: `${nameid}\u0001` }),
      subId({ issuer: `${x.issuer}\u0000`, nameid }),
      subId({ nameid }),
      subId({ issuer: x.issuer, nameid, sp_name_qualifier: 7 }),
      subId({ issuer: x.issuer, nameid, nameid_format: "" }),
    ]) {
      const r = await s.attempt({ sub, sub_id: bad });
      expect(r, JSON.stringify(bad)).toMatchObject({ status: 400, body: GENERIC, reason: "subject_rejected" });
      expect(r.detail).toMatch(/^sub_id malformed/);
    }
    // Well formed: resolved by the NameID (not by sub).
    expect((await s.attempt({ sub, sub_id: subId({ issuer: x.issuer, nameid }) })).userId).not.toBe((await s.attempt({ sub })).userId);
  });
});

describe("R3-S4: requireSubId", () => {
  it("absent, or another format: refused even when sub is linked; a mapped sub_id: accepted", async () => {
    const x = samlNamespace();
    const s = await host({ trust: { samlSubjects: [{ issuer: x.issuer, accountProviderId: x.providerId }], requireSubId: true } });
    const sub = crypto.randomUUID();
    await linkedUser(s.h, s.providerId, sub);
    const absent = await s.attempt({ sub });
    expect(absent).toMatchObject({ reason: "subject_rejected", body: GENERIC, detail: "sub_id required: absent" });
    const other = await s.attempt({ sub, sub_id: { format: "email", email: "a@corp.example" } });
    expect(other).toMatchObject({ reason: "subject_rejected", detail: "sub_id required: format email not supported" });
    const nameid = `alice-${crypto.randomUUID()}`;
    const u = await linkedUser(s.h, x.providerId, nameid);
    expect(await s.attempt({ sub, sub_id: subId({ issuer: x.issuer, nameid }) })).toMatchObject({ reason: "accepted", userId: u.id });
  });

  it("without requireSubId: absent or another format falls back to sub", async () => {
    const x = samlNamespace();
    const s = await host({ trust: { samlSubjects: [{ issuer: x.issuer, accountProviderId: x.providerId }] } });
    const sub = crypto.randomUUID();
    const u = await linkedUser(s.h, s.providerId, sub);
    expect(await s.attempt({ sub })).toMatchObject({ reason: "accepted", userId: u.id });
    expect(await s.attempt({ sub, sub_id: { format: "email", email: "a@corp.example" } })).toMatchObject({ reason: "accepted", userId: u.id });
  });
});

describe("R3-S5: no mappings, sub_id ignored", () => {
  it("a sub_id naming an existing linked SAML account isn't used; a malformed one doesn't refuse", async () => {
    const x = samlNamespace();
    const s = await host();
    const nameid = `alice-${crypto.randomUUID()}`;
    await linkedUser(s.h, x.providerId, nameid);
    const r = await s.attempt({ sub: crypto.randomUUID(), sub_id: subId({ issuer: x.issuer, nameid }) });
    expect(r).toMatchObject({ reason: "unknown_subject", body: GENERIC });
    const sub = crypto.randomUUID();
    const u = await linkedUser(s.h, s.providerId, sub);
    expect(await s.attempt({ sub, sub_id: subId({ issuer: x.issuer, nameid, extra: true }) })).toMatchObject({ reason: "accepted", userId: u.id });
    expect(subjectKey(resolveReceiverOptions({ trustedIssuers: [{ issuer: s.idp.issuer, jwksUri: s.idp.jwksUri }] }).trustedIssuers[0]!, s.idp.claims({ sub, sub_id: subId({ issuer: x.issuer, nameid }) }) as unknown as IdJagClaims)).toEqual({
      providerId: s.providerId,
      accountId: sub,
      from: "sub",
    });
  });
});

describe("R3-S6: a transient NameID is refused", () => {
  it("refused whatever the mapping's format list, even when an account for that NameID exists; transient can't be configured", async () => {
    const x = samlNamespace();
    const s = await host({ trust: { samlSubjects: [{ issuer: x.issuer, accountProviderId: x.providerId }] } });
    const nameid = `_t${crypto.randomUUID()}`;
    await linkedUser(s.h, x.providerId, nameid);
    const r = await s.attempt({ sub_id: subId({ issuer: x.issuer, nameid, nameid_format: TRANSIENT_NAMEID_FORMAT }) });
    expect(r).toMatchObject({ reason: "subject_rejected", body: GENERIC, detail: "sub_id: a transient NameID can't identify a user" });
    expect(() => resolveReceiverOptions({ trustedIssuers: [{ issuer: s.idp.issuer, jwksUri: s.idp.jwksUri, samlSubjects: [{ issuer: x.issuer, nameIdFormats: [TRANSIENT_NAMEID_FORMAT], accountProviderId: x.providerId }] }] })).toThrow(/transient/);
  });

  it("an unmapped namespace with a transient NameID is refused too (the transient check comes first)", async () => {
    const x = samlNamespace();
    const s = await host({ trust: { samlSubjects: [{ issuer: x.issuer, accountProviderId: x.providerId }] } });
    const r = await s.attempt({ sub_id: subId({ issuer: "https://elsewhere.example", nameid: "_t1", nameid_format: TRANSIENT_NAMEID_FORMAT }) });
    expect(r.detail).toBe("sub_id: a transient NameID can't identify a user");
  });
});

describe("R3-S7: links use the mapping key", () => {
  it("JIT links (accountProviderId, nameid), not sub; a later ID-JAG with another sub (xaa: sub may change on restart) finds the same user", async () => {
    const x = samlNamespace();
    const s = await host({ trust: { samlSubjects: [{ issuer: x.issuer, spNameQualifier: x.sp, accountProviderId: x.providerId }], jitProvisioning: true } });
    const nameid = `alice-${crypto.randomUUID()}`;
    const email = uniqueEmail();
    const sub = crypto.randomUUID();
    const sid = subId({ issuer: x.issuer, nameid, sp_name_qualifier: x.sp, nameid_format: PERSISTENT });
    const first = await s.attempt({ sub, email, sub_id: sid });
    expect(first.reason).toBe("accepted");
    expect(await s.account(x.providerId, nameid)).toMatchObject({ userId: first.userId });
    expect(await s.account(s.providerId, sub)).toBeNull();
    expect(await s.attempt({ sub: crypto.randomUUID(), email, sub_id: sid })).toMatchObject({ reason: "accepted", userId: first.userId });
    expect(await s.attempt({ sub: crypto.randomUUID(), sub_id: sid })).toMatchObject({ reason: "accepted", userId: first.userId });
  });

  it("xaa.dev: identical NameIDs from different IdP connections are two users (two mappings, two account provider ids)", async () => {
    const x = samlNamespace();
    const y = samlNamespace();
    const s = await host({
      trust: {
        samlSubjects: [
          { issuer: x.issuer, accountProviderId: x.providerId },
          { issuer: y.issuer, accountProviderId: y.providerId },
        ],
        jitProvisioning: true,
      },
    });
    const nameid = `alice-${crypto.randomUUID()}`;
    const sub = crypto.randomUUID();
    const a = await s.attempt({ sub, email: uniqueEmail(), sub_id: subId({ issuer: x.issuer, nameid }) });
    const b = await s.attempt({ sub, email: uniqueEmail(), sub_id: subId({ issuer: y.issuer, nameid }) });
    expect(a.reason).toBe("accepted");
    expect(b.reason).toBe("accepted");
    expect(a.userId).not.toBe(b.userId);
    expect(await s.account(x.providerId, nameid)).toMatchObject({ userId: a.userId });
    expect(await s.account(y.providerId, nameid)).toMatchObject({ userId: b.userId });
    // And each again, with no email: found by its own link.
    expect(await s.attempt({ sub_id: subId({ issuer: x.issuer, nameid }) })).toMatchObject({ reason: "accepted", userId: a.userId });
    expect(await s.attempt({ sub_id: subId({ issuer: y.issuer, nameid }) })).toMatchObject({ reason: "accepted", userId: b.userId });
  });

  it("an account as @better-auth/sso stores a SAML sign-in ({ providerId: sso providerId, accountId: NameID }) is found", async () => {
    const x = samlNamespace();
    const s = await host({ trust: { samlSubjects: [{ issuer: x.issuer, accountProviderId: x.providerId }] } });
    const nameid = `alice@${crypto.randomUUID().slice(0, 8)}.example`;
    const u = await linkedUser(s.h, x.providerId, nameid);
    expect(await s.attempt({ sub_id: subId({ issuer: x.issuer, nameid, nameid_format: EMAIL_FORMAT }) })).toMatchObject({ reason: "accepted", userId: u.id });
  });

  it("known gap: a persistent NameID with no email and JIT is refused cleanly (Better Auth users need an email)", async () => {
    const x = samlNamespace();
    const s = await host({ trust: { samlSubjects: [{ issuer: x.issuer, accountProviderId: x.providerId }], jitProvisioning: true, requireSubId: true } });
    const nameid = `p-${crypto.randomUUID()}`;
    const r = await s.attempt({ sub_id: subId({ issuer: x.issuer, nameid, nameid_format: PERSISTENT }) });
    expect(r).toMatchObject({ status: 400, body: GENERIC, reason: "unknown_subject", detail: `sub_id at ${x.providerId}` });
    expect(await s.account(x.providerId, nameid)).toBeNull();
  });

  it("a banned user found by sub_id is refused; an orphaned link is unknown_subject", async () => {
    const x = samlNamespace();
    const s = await host({ admin: true, trust: { samlSubjects: [{ issuer: x.issuer, accountProviderId: x.providerId }], emailFallback: { domains: ["corp.example"] } } });
    const nameid = `alice-${crypto.randomUUID()}`;
    const u = await linkedUser(s.h, x.providerId, nameid);
    await s.h.ctx.internalAdapter.updateUser(u.id, { banned: true });
    expect((await s.attempt({ sub_id: subId({ issuer: x.issuer, nameid }) })).reason).toBe("banned_user");
    // Orphaned (unit level: cascades differ by adapter): never re-linked by email.
    const o = resolveReceiverOptions({ trustedIssuers: [{ issuer: s.idp.issuer, jwksUri: s.idp.jwksUri, samlSubjects: [{ issuer: x.issuer, accountProviderId: x.providerId }], emailFallback: { domains: ["corp.example"] } }] });
    const queried: unknown[] = [];
    const linked: unknown[] = [];
    const adapter = { ...s.h.ctx.adapter, findMany: async (q: unknown) => {
        queried.push(q);
        return [{ id: "acc-1", userId: "gone", createdAt: new Date() }];
      },
    };
    const internalAdapter = {
      findUserById: async () => null,
      findUserByEmail: async () => ({ user: { id: "someone", email: "a@corp.example", emailVerified: true }, accounts: [] }),
      linkAccount: async (a: unknown) => void linked.push(a),
    };
    const ctx = { context: { ...s.h.ctx, adapter, internalAdapter } } as unknown as GenericEndpointContext;
    const claims = s.idp.claims({ email: "a@corp.example", sub_id: subId({ issuer: x.issuer, nameid }) }) as unknown as IdJagClaims;
    const outcome = await resolveSubject(ctx, o, o.trustedIssuers[0]!, claims, "c").then(
      () => "accepted",
      (e: IdJagRefusal) => e.reason,
    );
    expect(outcome).toBe("unknown_subject");
    expect(linked).toHaveLength(0);
    expect(JSON.stringify(queried[0])).toContain(x.providerId);
    expect(JSON.stringify(queried[0])).toContain(nameid);
  });
});

describe("R3-S8: the email fallback under sub_id keeps D-A23 (a verified local email)", () => {
  it("an unverified local account is not linked (nor JIT-provisioned); a verified one is linked under the mapping key", async () => {
    const x = samlNamespace();
    const s = await host({ trust: { samlSubjects: [{ issuer: x.issuer, accountProviderId: x.providerId }], emailFallback: { domains: ["corp.example"] }, jitProvisioning: true } });
    const email = uniqueEmail("corp.example");
    const squatter = await s.h.auth.api.signUpEmail({ body: { email, password: "attacker-password-1", name: "Squatter" } });
    const nameid = `alice-${crypto.randomUUID()}`;
    const r = await s.attempt({ email, sub_id: subId({ issuer: x.issuer, nameid }) });
    expect(r).toMatchObject({ reason: "unknown_subject", body: GENERIC, detail: "email fallback: the local user's email is not verified" });
    expect(await s.account(x.providerId, nameid)).toBeNull();
    expect((await s.h.ctx.internalAdapter.findUserByEmail(email, { includeAccounts: true }))?.accounts.map((a) => a.providerId)).toEqual(["credential"]);
    expect(squatter.user.emailVerified).toBe(false);

    const email2 = uniqueEmail("corp.example");
    const v = await s.h.ctx.internalAdapter.createUser({ email: email2, name: "V", emailVerified: true }, { method: "admin" });
    const nameid2 = `bob-${crypto.randomUUID()}`;
    const sub = crypto.randomUUID();
    expect(await s.attempt({ sub, email: email2, sub_id: subId({ issuer: x.issuer, nameid: nameid2 }) })).toMatchObject({ reason: "accepted", userId: v.id });
    expect(await s.account(x.providerId, nameid2)).toMatchObject({ userId: v.id });
    expect(await s.account(s.providerId, sub)).toBeNull();
    // Another NameID of the same namespace with that email: the user is already linked there, refused.
    expect((await s.attempt({ email: email2, sub_id: subId({ issuer: x.issuer, nameid: `other-${crypto.randomUUID()}` }) })).reason).toBe("unknown_subject");
  });
});

describe("sub_id and the host hook", () => {
  it("the hook runs first and sees sub_id; its link wins even over a sub_id that would be refused", async () => {
    const x = samlNamespace();
    let target = "";
    const seen: unknown[] = [];
    const s = await host({
      trust: { samlSubjects: [{ issuer: x.issuer, accountProviderId: x.providerId }], requireSubId: true },
      receiver: {
        resolveSubject: (input) => {
          seen.push(input.claims.sub_id);
          return target ? { action: "link", userId: target } : { action: "continue" };
        },
      },
    });
    const u = await s.h.ctx.internalAdapter.createUser({ email: uniqueEmail(), name: "H" }, { method: "admin" });
    const bad = subId({ issuer: "https://unmapped.example", nameid: "n" });
    expect((await s.attempt({ sub_id: bad })).reason).toBe("subject_rejected");
    expect(seen.at(-1)).toEqual(bad);
    target = u.id;
    expect(await s.attempt({ sub_id: bad })).toMatchObject({ reason: "accepted", userId: u.id });
  });
});

describe("samlSubjects in the idJagTrustedIssuer table", () => {
  async function tableHost() {
    const idp = await testIdp();
    const rec = recorder();
    const logs: string[] = [];
    const h = await receiverHost("mcp", { receiver: { trustedIssuerTable: true, fetch: network(idp).fetch }, recorder: rec, logs });
    const client = await createClient(h);
    const row = (data: Record<string, unknown>) =>
      h.ctx.adapter.create<{ id: string }>({ model: TRUSTED_ISSUER_MODEL, data: { issuer: idp.issuer, jwksUri: idp.jwksUri, enabled: true, jitProvisioning: false, jitTrustEmailVerified: false, createdAt: new Date(), updatedAt: new Date(), ...data } });
    const attempt = async (over: Record<string, unknown>) => {
      const r = await redeem(h, client, await idp.mint(idp.claims({ client_id: client.client_id, ...over })));
      await rec.settle();
      return { reason: r.status === 200 ? "accepted" : rec.refused.at(-1)?.reason, userId: r.status === 200 ? rec.accepted.at(-1)?.userId : undefined };
    };
    return { idp, h, row, attempt, logs };
  }

  it("a row's samlSubjects (JSON) and requireSubId are used", async () => {
    const t = await tableHost();
    const x = samlNamespace();
    await t.row({ samlSubjects: JSON.stringify([{ issuer: x.issuer, spNameQualifier: x.sp, accountProviderId: x.providerId }]), requireSubId: true });
    const nameid = `alice-${crypto.randomUUID()}`;
    const u = await linkedUser(t.h, x.providerId, nameid);
    expect(await t.attempt({ sub_id: subId({ issuer: x.issuer, nameid, sp_name_qualifier: x.sp }) })).toMatchObject({ reason: "accepted", userId: u.id });
    expect((await t.attempt({ sub_id: subId({ issuer: x.issuer, nameid }) })).reason).toBe("subject_rejected");
    const sub = crypto.randomUUID();
    await linkedUser(t.h, `id-jag:${t.idp.issuer}`, sub);
    expect((await t.attempt({ sub })).reason).toBe("subject_rejected");
  });

  it("null columns: sub_id ignored, as before", async () => {
    const t = await tableHost();
    await t.row({});
    const sub = crypto.randomUUID();
    const u = await linkedUser(t.h, `id-jag:${t.idp.issuer}`, sub);
    expect(await t.attempt({ sub, sub_id: subId({ issuer: "https://x.example", nameid: "n" }) })).toMatchObject({ reason: "accepted", userId: u.id });
  });

  for (const [what, data] of [
    ["not JSON", { samlSubjects: "nope" }],
    ["an empty list", { samlSubjects: "[]" }],
    ["an unknown key", { samlSubjects: JSON.stringify([{ issuer: "https://x.example", accountProviderId: "p", spNameQualifer: "typo" }]) }],
    ["an empty issuer", { samlSubjects: JSON.stringify([{ issuer: "", accountProviderId: "p" }]) }],
    ["a namespace listed twice", { samlSubjects: JSON.stringify([{ issuer: "https://x.example", accountProviderId: "p" }, { issuer: "https://x.example", spNameQualifier: null, accountProviderId: "q" }]) }],
    ["requireSubId without samlSubjects", { requireSubId: true }],
    ["two SAML namespaces under one accountProviderId", { samlSubjects: JSON.stringify([{ issuer: "https://x.example", accountProviderId: "p" }, { issuer: "https://y.example", accountProviderId: "p" }]) }],
    ["a mapping under the row's own account provider id", { ssoProviderId: "own", samlSubjects: JSON.stringify([{ issuer: "https://x.example", accountProviderId: "own" }]) }],
  ] as const) {
    it(`a row with ${what} is ignored with a warning`, async () => {
      const t = await tableHost();
      await t.row(data);
      expect((await t.attempt({})).reason).toBe("untrusted_issuer");
      expect(t.logs.some((l) => l.includes(`ignoring an invalid ${TRUSTED_ISSUER_MODEL} row`))).toBe(true);
    });
  }
});
