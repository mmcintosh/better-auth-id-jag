// Trust sources (plan §3.4 step 3): static config, @better-auth/sso OIDC provider rows, and the
// idJagTrustedIssuer table; their union, with ambiguity refused; S1: nothing trusted, nothing accepted.
import { describe, expect, it } from "vitest";
import { TRUSTED_ISSUER_MODEL } from "../../src/receiver";
import type { IdJagGrantOptions } from "../../src/receiver";
import { createClient, linkedUser, network, type ReceiverHost, receiverHost, recorder, redeem, type TestIdp, testIdp, uniqueEmail } from "../support/receiver-host";

async function ssoRow(h: ReceiverHost, idp: TestIdp, o: { providerId?: string; jwks?: boolean; saml?: boolean; domain?: string; domainVerified?: boolean; organizationId?: string; configIssuer?: string } = {}) {
  const providerId = o.providerId ?? `sso-${crypto.randomUUID().slice(0, 8)}`;
  const oidcConfig = { issuer: o.configIssuer ?? idp.issuer, clientId: "rp", clientSecret: "rp-secret", pkce: true, ...(o.jwks === false ? { discoveryEndpoint: idp.discoveryUri } : { jwksEndpoint: idp.jwksUri }) };
  const owner = await h.ctx.internalAdapter.createUser({ email: uniqueEmail(), name: "Owner" }, { method: "admin" });
  await h.ctx.adapter.create({
    model: "ssoProvider",
    data: {
      userId: owner.id,
      providerId,
      issuer: idp.issuer,
      domain: o.domain ?? "corp.example",
      ...(o.saml ? { samlConfig: JSON.stringify({ entryPoint: "https://x" }) } : { oidcConfig: JSON.stringify(oidcConfig) }),
      ...(o.domainVerified !== undefined ? { domainVerified: o.domainVerified } : {}),
      ...(o.organizationId ? { organizationId: o.organizationId } : {}),
    },
  });
  return providerId;
}

async function host(idps: TestIdp[], receiver: Partial<IdJagGrantOptions>, o: { sso?: boolean | { domainVerification?: boolean } } = {}) {
  const net = network(...idps);
  const rec = recorder();
  const h = await receiverHost("mcp", { receiver: { fetch: net.fetch, ...receiver }, recorder: rec, sso: o.sso ?? true });
  const client = await createClient(h);
  const attempt = async (idp: TestIdp, over: Record<string, unknown> = {}) => {
    const r = await redeem(h, client, await idp.mint(idp.claims({ client_id: client.client_id, ...over })));
    await rec.settle();
    return { ...r, reason: r.status === 200 ? "accepted" : rec.refused.at(-1)?.reason };
  };
  return { h, net, rec, client, attempt };
}

describe("trust: @better-auth/sso OIDC providers", () => {
  it("an sso row's issuer + jwksEndpoint is trusted; the subject is the account sso links (providerId + sub)", async () => {
    const idp = await testIdp();
    const s = await host([idp], { sso: true });
    const providerId = await ssoRow(s.h, idp, { organizationId: "org-1" });
    const sub = crypto.randomUUID();
    const user = await linkedUser(s.h, providerId, sub);
    const r = await s.attempt(idp, { sub });
    expect(r.reason).toBe("accepted");
    expect(s.rec.accepted.at(-1)).toMatchObject({ userId: user.id, organizationId: "org-1" });
    expect(s.net.urls()).toEqual([idp.jwksUri]);
    // A subject linked under the default static provider id is not this sso provider's.
    const other = crypto.randomUUID();
    await linkedUser(s.h, `id-jag:${idp.issuer}`, other);
    expect((await s.attempt(idp, { sub: other })).reason).toBe("unknown_subject");
  });

  it("without jwksEndpoint the keys come from discovery", async () => {
    const idp = await testIdp();
    const s = await host([idp], { sso: true });
    const providerId = await ssoRow(s.h, idp, { jwks: false });
    const sub = crypto.randomUUID();
    await linkedUser(s.h, providerId, sub);
    expect((await s.attempt(idp, { sub })).reason).toBe("accepted");
    expect(s.net.urls()).toEqual([idp.discoveryUri, idp.jwksUri]);
  });

  it("not trusted: sso trust off (the default), a SAML row, a row outside providerIds, an oidcConfig.issuer that differs", async () => {
    const idp = await testIdp();
    const off = await host([idp], {});
    await ssoRow(off.h, idp);
    expect((await off.attempt(idp)).reason).toBe("untrusted_issuer");

    const saml = await testIdp();
    const s1 = await host([saml], { sso: true });
    await ssoRow(s1.h, saml, { saml: true });
    expect((await s1.attempt(saml)).reason).toBe("untrusted_issuer");

    const listed = await testIdp();
    const s2 = await host([listed], { sso: { providerIds: ["only-this-one"] } });
    await ssoRow(s2.h, listed);
    expect((await s2.attempt(listed)).reason).toBe("untrusted_issuer");

    const mismatch = await testIdp();
    const s3 = await host([mismatch], { sso: true });
    await ssoRow(s3.h, mismatch, { configIssuer: "https://someone-else.example" });
    expect((await s3.attempt(mismatch)).reason).toBe("untrusted_issuer");
    // None of them fetched anything.
    for (const s of [off, s1, s2, s3]) expect(s.net.calls).toHaveLength(0);
  });

  it("sso trust on, but no sso plugin: nothing trusted from it", async () => {
    const idp = await testIdp();
    const s = await host([idp], { sso: true }, { sso: false });
    expect((await s.attempt(idp)).reason).toBe("untrusted_issuer");
  });

  it("email fallback only for a verified domain, and only when enabled", async () => {
    const verified = await testIdp();
    const s = await host([verified], { sso: { emailFallback: true } }, { sso: { domainVerification: true } });
    const providerId = await ssoRow(s.h, verified, { domain: "corp.example", domainVerified: true });
    const email = uniqueEmail("corp.example");
    const existing = await s.h.ctx.internalAdapter.createUser({ email, name: "E", emailVerified: true }, { method: "admin" });
    const sub = crypto.randomUUID();
    const r = await s.attempt(verified, { sub, email });
    expect(r.reason).toBe("accepted");
    expect(s.rec.accepted.at(-1)?.userId).toBe(existing.id);
    // The account is now linked: found without the email next time.
    expect(await s.h.ctx.internalAdapter.findAccountByKey({ providerId, accountId: sub })).toMatchObject({ userId: existing.id });
    expect((await s.attempt(verified, { sub })).reason).toBe("accepted");
    // Another domain at the same provider: no fallback.
    const outsider = uniqueEmail("elsewhere.example");
    await s.h.ctx.internalAdapter.createUser({ email: outsider, name: "O", emailVerified: true }, { method: "admin" });
    expect((await s.attempt(verified, { sub: crypto.randomUUID(), email: outsider })).reason).toBe("unknown_subject");

    const unverified = await testIdp();
    const s2 = await host([unverified], { sso: { emailFallback: true } }, { sso: { domainVerification: true } });
    await ssoRow(s2.h, unverified, { domain: "corp.example", domainVerified: false });
    const email2 = uniqueEmail("corp.example");
    await s2.h.ctx.internalAdapter.createUser({ email: email2, name: "E", emailVerified: true }, { method: "admin" });
    expect((await s2.attempt(unverified, { email: email2 })).reason).toBe("unknown_subject");
  });
});

describe("trust: static config and the idJagTrustedIssuer table", () => {
  it("static entries via discovery; tenant pinning", async () => {
    const idp = await testIdp();
    const s = await host([idp], { trustedIssuers: [{ issuer: idp.issuer, discoveryUri: idp.discoveryUri, tenant: "t-1" }] }, { sso: false });
    const sub = crypto.randomUUID();
    await linkedUser(s.h, `id-jag:${idp.issuer}`, sub);
    expect((await s.attempt(idp, { sub })).reason).toBe("untrusted_issuer");
    expect((await s.attempt(idp, { sub, tenant: "t-2" })).reason).toBe("untrusted_issuer");
    expect((await s.attempt(idp, { sub, tenant: "t-1" })).reason).toBe("accepted");
  });

  it("table rows: enabled rows are trusted, disabled ones aren't; ssoProviderId sets the account link", async () => {
    const idp = await testIdp();
    const s = await host([idp], { trustedIssuerTable: true }, { sso: false });
    const row = await s.h.ctx.adapter.create<{ id: string }>({
      model: TRUSTED_ISSUER_MODEL,
      data: { issuer: idp.issuer, jwksUri: idp.jwksUri, ssoProviderId: "linked-provider", enabled: true, jitProvisioning: false, jitTrustEmailVerified: false, organizationId: "org-t", createdAt: new Date(), updatedAt: new Date() },
    });
    const sub = crypto.randomUUID();
    await linkedUser(s.h, "linked-provider", sub);
    expect((await s.attempt(idp, { sub })).reason).toBe("accepted");
    expect(s.rec.accepted.at(-1)?.organizationId).toBe("org-t");
    await s.h.ctx.adapter.update({ model: TRUSTED_ISSUER_MODEL, where: [{ field: "id", value: row.id }], update: { enabled: false } });
    expect((await s.attempt(idp, { sub })).reason).toBe("untrusted_issuer");
  });

  it("table rows: allowedClientIds as JSON; an invalid row is ignored", async () => {
    const idp = await testIdp();
    const s = await host([idp], { trustedIssuerTable: true }, { sso: false });
    await s.h.ctx.adapter.create({
      model: TRUSTED_ISSUER_MODEL,
      data: { issuer: idp.issuer, jwksUri: idp.jwksUri, allowedClientIds: JSON.stringify(["not-this-client"]), enabled: true, jitProvisioning: false, jitTrustEmailVerified: false, createdAt: new Date(), updatedAt: new Date() },
    });
    const sub = crypto.randomUUID();
    await linkedUser(s.h, `id-jag:${idp.issuer}`, sub);
    expect((await s.attempt(idp, { sub })).reason).toBe("client_mismatch");

    const bad = await testIdp();
    const s2 = await host([bad], { trustedIssuerTable: true }, { sso: false });
    await s2.h.ctx.adapter.create({
      model: TRUSTED_ISSUER_MODEL,
      data: { issuer: bad.issuer, jwksUri: bad.jwksUri, allowedClientIds: "not json", enabled: true, jitProvisioning: false, jitTrustEmailVerified: false, createdAt: new Date(), updatedAt: new Date() },
    });
    expect((await s2.attempt(bad)).reason).toBe("untrusted_issuer");
  });

  it("the same issuer in two sources is ambiguous and refused", async () => {
    const idp = await testIdp();
    const s = await host([idp], { sso: true, trustedIssuers: [{ issuer: idp.issuer, jwksUri: idp.jwksUri }] });
    await ssoRow(s.h, idp);
    expect((await s.attempt(idp)).reason).toBe("untrusted_issuer");
    expect(s.rec.refused.at(-1)?.detail).toMatch(/ambiguous/);
    expect(s.net.calls).toHaveLength(0);
  });

  it("S1: no trusted issuers at all refuses everything", async () => {
    const idp = await testIdp();
    const s = await host([idp], {}, { sso: false });
    expect((await s.attempt(idp)).reason).toBe("untrusted_issuer");
  });
});
