// The SCIM step (D-027): a trust entry with `scim` resolves the ID-JAG's `sub` as a SCIM externalId
// through @better-auth/scim's acquireActiveSCIMUserLink, against Better Auth's real SCIM server in this
// host (users provisioned over its SCIM HTTP API, as an IdP's SCIM client does). Required by default:
// a deprovisioned user is refused, and can't come back through an account link, email or JIT.
import { acquireActiveSCIMUserLink } from "@better-auth/scim";
import { APIError } from "better-auth/api";
import { describe, expect, it } from "vitest";
import type { IdJagGrantOptions } from "../../src/receiver";
import { MAX_SCIM_ATTEMPTS, SCIM_RETRY_BUDGET_MS } from "../../src/receiver/scim";
import { BASE, createClient, decodePayload, linkedUser, network, receiverHost, recorder, redeem, testIdp, uniqueEmail } from "../support/receiver-host";

const CONNECTION = "acme-idp";
const TOKEN = "scim-bearer-token-that-is-long-enough-for-the-plugin";
const SCIM_USER = "urn:ietf:params:scim:schemas:core:2.0:User";
const PATCH_OP = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
const SAML_IDP = "https://saml.acme.example/idp";
const PERSISTENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";

type Acquire = NonNullable<IdJagGrantOptions["scim"]>["acquireActiveSCIMUserLink"];

async function world(o: { required?: boolean; jit?: boolean; acquire?: Acquire | null; connections?: string[]; table?: boolean; admin?: boolean; saml?: { requireSubId?: boolean } } = {}) {
  const idp = await testIdp();
  const rec = recorder();
  const scimEntry = { connectionId: CONNECTION, ...(o.required === undefined ? {} : { required: o.required }) };
  const acquire = o.acquire === undefined ? (acquireActiveSCIMUserLink as unknown as Acquire) : o.acquire;
  const h = await receiverHost("mcp", {
    receiver: {
      ...(o.table
        ? { trustedIssuerTable: true }
        : {
            trustedIssuers: [
              {
                issuer: idp.issuer,
                jwksUri: idp.jwksUri,
                scim: scimEntry,
                ...(o.jit ? { jitProvisioning: { trustEmailVerified: true } } : {}),
                ...(o.saml ? { samlSubjects: [{ issuer: SAML_IDP, accountProviderId: "acme-saml" }], ...(o.saml.requireSubId ? { requireSubId: true } : {}) } : {}),
              },
            ],
          }),
      ...(acquire ? { scim: { acquireActiveSCIMUserLink: acquire } } : {}),
      fetch: network(idp).fetch,
    },
    scim: { connections: (o.connections ?? [CONNECTION]).map((id) => ({ id, credentials: [{ type: "bearer" as const, id: `${id}-token`, token: `${TOKEN}-${id}` }] })) },
    recorder: rec,
    ...(o.admin ? { admin: true } : {}),
  });
  const client = await createClient(h);
  const scimCall = async (method: string, path: string, body?: unknown, connection = CONNECTION) => {
    const res = await h.auth.handler(
      new Request(`${BASE}/api/auth/scim/v2${path}`, {
        method,
        headers: { authorization: `Bearer ${TOKEN}-${connection}`, "content-type": "application/scim+json", accept: "application/scim+json" },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      }),
    );
    const text = await res.text();
    return { status: res.status, body: text ? (JSON.parse(text) as Record<string, unknown>) : {} };
  };
  /** Provision a user over SCIM as the IdP would: externalId = the IdP's user id (the ID-JAG's sub). */
  const provision = async (externalId: string, email = uniqueEmail(), connection = CONNECTION) => {
    const r = await scimCall("POST", "/Users", { schemas: [SCIM_USER], userName: email, externalId, emails: [{ value: email, primary: true }], active: true }, connection);
    expect(r.status, JSON.stringify(r.body)).toBe(201);
    return { scimId: r.body.id as string, email };
  };
  const setActive = async (scimId: string, active: boolean) => {
    const r = await scimCall("PATCH", `/Users/${scimId}`, { schemas: [PATCH_OP], Operations: [{ op: "replace", path: "active", value: active }] });
    expect(r.status, JSON.stringify(r.body)).toBe(200);
  };
  const remove = async (scimId: string) => expect((await scimCall("DELETE", `/Users/${scimId}`)).status).toBe(204);
  const localUserOf = async (email: string) => (await h.ctx.internalAdapter.findUserByEmail(email))?.user;
  const attempt = async (sub: string, extra: Record<string, unknown> = {}) => {
    const r = await redeem(h, client, await idp.mint(idp.claims({ client_id: client.client_id, sub, ...extra })));
    await rec.settle();
    return r.status === 200
      ? { reason: "accepted", userId: decodePayload(r.body.access_token as string).sub as string, resolvedBy: rec.accepted.at(-1)?.resolvedBy }
      : { reason: rec.refused.at(-1)?.reason, detail: rec.refused.at(-1)?.detail, body: r.body };
  };
  return { idp, h, rec, client, provision, setActive, remove, localUserOf, attempt, scimCall };
}

// @better-auth/scim needs an adapter with native transactions, which D1 isn't ("The scim plugin
// requires a database adapter with native transaction support"): no SCIM server on Workers + D1, so
// these run on Node (node:sqlite) and, in CI's adapter matrix, on Postgres and MySQL.
const workerd = typeof navigator !== "undefined" && navigator.userAgent === "Cloudflare-Workers";

describe.skipIf(workerd)("SCIM provisioning resolves the subject (D-027)", () => {
  it("an active provisioned user: accepted as that user, resolved by SCIM; no account is linked by sub", async () => {
    const w = await world();
    const sub = crypto.randomUUID();
    const { email } = await w.provision(sub);
    const local = await w.localUserOf(email);
    expect(local).toBeDefined();
    expect(await w.attempt(sub)).toMatchObject({ reason: "accepted", userId: local?.id, resolvedBy: "scim" });
    const accounts = await w.h.ctx.adapter.findMany<{ providerId: string }>({ model: "account", where: [{ field: "userId", value: local?.id as string }] });
    expect(accounts.filter((a) => a.providerId.startsWith("id-jag:"))).toHaveLength(0);
  });

  it("required (the default): an unprovisioned sub is refused, and neither JIT nor an existing account brings it in", async () => {
    const w = await world({ jit: true });
    expect(await w.attempt(crypto.randomUUID(), { email: uniqueEmail() })).toMatchObject({ reason: "unknown_subject", detail: "SCIM: no active provisioned user for this sub", body: { error: "invalid_grant", error_description: "The grant is invalid." } });
    // A user linked to this issuer by sub (an older link) isn't enough either: SCIM decides.
    const sub = crypto.randomUUID();
    await linkedUser(w.h, `id-jag:${w.idp.issuer}`, sub);
    expect((await w.attempt(sub)).reason).toBe("unknown_subject");
    expect(await w.h.ctx.adapter.count({ model: "user" })).toBe(1 + 1); // the client's owner, and the linked user
  });

  it("deactivated: refused; reactivated: the same user again", async () => {
    const w = await world();
    const sub = crypto.randomUUID();
    const { scimId, email } = await w.provision(sub);
    const local = await w.localUserOf(email);
    await w.setActive(scimId, false);
    expect(await w.attempt(sub)).toMatchObject({ reason: "unknown_subject", detail: "SCIM: no active provisioned user for this sub" });
    await w.setActive(scimId, true);
    expect(await w.attempt(sub)).toMatchObject({ reason: "accepted", userId: local?.id });
  });

  it("deleted over SCIM: refused, and JIT can't re-create the user under the same sub", async () => {
    const w = await world({ jit: true });
    const sub = crypto.randomUUID();
    const { scimId, email } = await w.provision(sub);
    await w.remove(scimId);
    const before = await w.h.ctx.adapter.count({ model: "user" });
    expect((await w.attempt(sub, { email })).reason).toBe("unknown_subject");
    expect((await w.attempt(sub, { email: uniqueEmail() })).reason).toBe("unknown_subject");
    expect(await w.h.ctx.adapter.count({ model: "user" })).toBe(before);
  });

  it("only this entry's connection: a user another connection provisioned with the same externalId isn't found", async () => {
    const w = await world({ connections: [CONNECTION, "other-idp"] });
    const sub = crypto.randomUUID();
    await w.provision(sub, uniqueEmail(), "other-idp");
    expect((await w.attempt(sub)).reason).toBe("unknown_subject");
  });

  it("a banned local user is refused even with an active SCIM user", async () => {
    const w = await world({ admin: true });
    const sub = crypto.randomUUID();
    const { email } = await w.provision(sub);
    const local = await w.localUserOf(email);
    await w.h.ctx.internalAdapter.updateUser(local?.id as string, { banned: true });
    expect((await w.attempt(sub)).reason).toBe("banned_user");
  });

  it("required: false: no SCIM user falls through to the other steps (here JIT)", async () => {
    const w = await world({ required: false, jit: true });
    const email = uniqueEmail();
    const r = await w.attempt(crypto.randomUUID(), { email });
    expect(r).toMatchObject({ reason: "accepted", resolvedBy: "jit" });
    expect(r.userId).toBe((await w.localUserOf(email))?.id);
  });

  it("required: false: no SCIM user falls through to a linked account too (and only then)", async () => {
    const w = await world({ required: false });
    const sub = crypto.randomUUID();
    const linked = await linkedUser(w.h, `id-jag:${w.idp.issuer}`, sub);
    expect(await w.attempt(sub)).toMatchObject({ reason: "accepted", userId: linked.id, resolvedBy: "account" });
    expect((await w.attempt(crypto.randomUUID())).reason).toBe("unknown_subject");
  });

  it("the resolveSubject hook runs before the SCIM step: a link from it overrides scim.required", async () => {
    const idp = await testIdp();
    const rec = recorder();
    const chosen = { id: "" };
    const h = await receiverHost("mcp", {
      receiver: {
        trustedIssuers: [{ issuer: idp.issuer, jwksUri: idp.jwksUri, scim: { connectionId: CONNECTION } }],
        scim: { acquireActiveSCIMUserLink: acquireActiveSCIMUserLink as unknown as Acquire },
        resolveSubject: () => ({ action: "link", userId: chosen.id }),
        fetch: network(idp).fetch,
      },
      scim: { connections: [{ id: CONNECTION, credentials: [{ type: "bearer", id: "t", token: `${TOKEN}-${CONNECTION}` }] }] },
      recorder: rec,
    });
    chosen.id = (await h.ctx.internalAdapter.createUser({ email: uniqueEmail(), name: "Hooked", emailVerified: true }, { method: "admin" })).id;
    const client = await createClient(h);
    const r = await redeem(h, client, await idp.mint(idp.claims({ client_id: client.client_id, sub: crypto.randomUUID() })));
    await rec.settle();
    expect(r.status, r.text).toBe(200);
    expect(rec.accepted.at(-1)).toMatchObject({ userId: chosen.id, resolvedBy: "hook" });
  });

  it("D-028: on an entry with samlSubjects too, the sub_id rules still hold for a SCIM-provisioned user; a valid sub_id resolves by SCIM", async () => {
    const w = await world({ saml: { requireSubId: true } });
    const sub = crypto.randomUUID();
    const { email } = await w.provision(sub);
    const local = await w.localUserOf(email);
    const subId = (over: Record<string, unknown>) => ({ format: "saml-nameid", issuer: SAML_IDP, nameid: `nameid-${sub}`, nameid_format: PERSISTENT, ...over });
    // requireSubId: none at all is refused.
    expect(await w.attempt(sub)).toMatchObject({ reason: "subject_rejected" });
    // Malformed (no nameid), and from a SAML issuer this entry doesn't map: refused, never resolved by SCIM.
    expect(await w.attempt(sub, { sub_id: { format: "saml-nameid", issuer: SAML_IDP } })).toMatchObject({ reason: "subject_rejected" });
    expect(await w.attempt(sub, { sub_id: subId({ issuer: "https://other-saml.example/idp" }) })).toMatchObject({ reason: "subject_rejected" });
    // A valid, mapped sub_id: the SCIM step resolves by sub.
    expect(await w.attempt(sub, { sub_id: subId({}) })).toMatchObject({ reason: "accepted", userId: local?.id, resolvedBy: "scim" });
  });

  it("the hook's trusted-issuer view names the entry's SCIM connection", async () => {
    const idp = await testIdp();
    const seen: unknown[] = [];
    const h = await receiverHost("mcp", {
      receiver: {
        trustedIssuers: [{ issuer: idp.issuer, jwksUri: idp.jwksUri, scim: { connectionId: CONNECTION } }],
        scim: { acquireActiveSCIMUserLink: acquireActiveSCIMUserLink as unknown as Acquire },
        resolveSubject: ({ trustedIssuer }) => {
          seen.push(trustedIssuer);
          return { action: "reject" };
        },
        fetch: network(idp).fetch,
      },
      scim: { connections: [{ id: CONNECTION, credentials: [{ type: "bearer", id: "t", token: `${TOKEN}-${CONNECTION}` }] }] },
    });
    const client = await createClient(h);
    await redeem(h, client, await idp.mint(idp.claims({ client_id: client.client_id, sub: crypto.randomUUID() })));
    expect(seen).toEqual([expect.objectContaining({ issuer: idp.issuer, scimConnectionId: CONNECTION })]);
  });

  it("a SCIM conflict is retried with backoff, within MAX_SCIM_ATTEMPTS and SCIM_RETRY_BUDGET_MS, then refused (D-029)", { timeout: 20_000 }, async () => {
    let conflicts = 0;
    let calls = 0;
    const flaky: Acquire = async (ref, c) => {
      calls++;
      if (conflicts-- > 0) throw new APIError("CONFLICT", { detail: "The SCIM identity changed concurrently; retry the request" });
      return (acquireActiveSCIMUserLink as unknown as Acquire)(ref, c);
    };
    const w = await world({ acquire: flaky });
    const sub = crypto.randomUUID();
    await w.provision(sub);
    // A few conflicts (lookups racing each other): retried, then accepted.
    conflicts = 4;
    calls = 0;
    expect((await w.attempt(sub)).reason).toBe("accepted");
    expect(calls).toBe(5);
    // Conflicts that never end: refused once the attempts or the time budget run out, never more.
    conflicts = Number.POSITIVE_INFINITY;
    calls = 0;
    const started = Date.now();
    expect(await w.attempt(sub)).toMatchObject({ reason: "subject_rejected", detail: "SCIM: the provisioned identity changed concurrently" });
    expect(calls).toBeGreaterThan(1);
    expect(calls).toBeLessThanOrEqual(MAX_SCIM_ATTEMPTS);
    // The budget bounds the wait (plus one backoff, at most 250 ms, and the request itself).
    expect(Date.now() - started).toBeLessThan(SCIM_RETRY_BUDGET_MS + 1500);
  });

  it("any other error from the lookup is an audited subject_rejected, not a 500", async () => {
    let calls = 0;
    const broken: Acquire = async () => {
      calls++;
      throw new Error("database down");
    };
    const w = await world({ acquire: broken });
    expect(await w.attempt(crypto.randomUUID())).toMatchObject({ reason: "subject_rejected", detail: "unexpected error in subject resolution", body: { error: "invalid_grant" } });
    // Only a SCIM conflict is retried.
    expect(calls).toBe(1);
  });

  it("a table entry with scimConnectionId: the same rules; without the function passed in, refused (fail closed)", async () => {
    for (const passFunction of [true, false]) {
      const w = await world({ table: true, ...(passFunction ? {} : { acquire: null }) });
      await w.h.ctx.adapter.create({ model: "idJagTrustedIssuer", data: { issuer: w.idp.issuer, jwksUri: w.idp.jwksUri, scimConnectionId: CONNECTION, jitProvisioning: false, jitTrustEmailVerified: false, enabled: true, createdAt: new Date(), updatedAt: new Date() } });
      const sub = crypto.randomUUID();
      const { email } = await w.provision(sub);
      const r = await w.attempt(sub);
      if (passFunction) {
        expect(r).toMatchObject({ reason: "accepted", userId: (await w.localUserOf(email))?.id, resolvedBy: "scim" });
        // scimRequired null: required, so an unprovisioned sub is refused.
        expect(await w.attempt(crypto.randomUUID())).toMatchObject({ reason: "unknown_subject", detail: "SCIM: no active provisioned user for this sub" });
      }
      else expect(r).toMatchObject({ reason: "subject_rejected", detail: "SCIM: acquireActiveSCIMUserLink not configured" });
    }
  });
});

describe("SCIM options are checked at startup", () => {
  it("an entry with scim needs the function passed in, and the @better-auth/scim plugin installed", async () => {
    const idp = await testIdp();
    const entry = { issuer: idp.issuer, jwksUri: idp.jwksUri, scim: { connectionId: CONNECTION } };
    await expect(receiverHost("mcp", { receiver: { trustedIssuers: [entry] } })).rejects.toThrow(/scim\.acquireActiveSCIMUserLink is not set/);
    await expect(receiverHost("mcp", { receiver: { trustedIssuers: [entry], scim: { acquireActiveSCIMUserLink: acquireActiveSCIMUserLink as unknown as Acquire } } })).rejects.toThrow(/@better-auth\/scim plugin is not installed/);
    await expect(receiverHost("mcp", { receiver: { trustedIssuers: [{ ...entry, scim: { connectionId: "" } }] } })).rejects.toThrow(/invalid options/);
    await expect(receiverHost("mcp", { receiver: { trustedIssuers: [{ ...entry, scim: { connectionId: CONNECTION, requird: false } as never }] } })).rejects.toThrow(/invalid options/);
  });
});
