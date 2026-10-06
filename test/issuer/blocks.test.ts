// Blocks (D-B16): an administrator stops further ID-JAGs for a user, a client, an audience or a
// combination. Checked before every policy source, for both subject token types; managed over the
// admin API with the registry's access control, every change an id-jag.admin event.
import { decodeJwt } from "jose";
import { describe, expect, it } from "vitest";
import { type IdJagIssuerOptions, BLOCK_MODEL } from "../../src/issuer";
import { type Browser, createClient, createIssuerHost, exchange, exchangeRefresh, getTokens, ISSUER, type IssuerHost, setupRefresh, signUp, takeReasons } from "../support/issuer-host";

const GENERIC_GRANT = { error: "invalid_grant", error_description: "The grant is invalid." };
const canManage = ({ user }: { user: Record<string, unknown> }) => user.role === "admin";
const OTHER_AUDIENCE = "https://other-rs.example";

async function host(o: { registry?: Partial<NonNullable<IdJagIssuerOptions["registry"]>> } = {}) {
  return createIssuerHost({
    issuer: {
      authorize: () => ({ decision: "allow", scopes: ["read"] }),
      registry: { enabled: false, canManage, ...o.registry } as NonNullable<IdJagIssuerOptions["registry"]>,
    },
  });
}

type Json = Record<string, any>;
async function api(browser: Browser, path: string, body?: unknown) {
  const res = await browser.fetch(`${ISSUER}/id-jag${path}`, {
    method: body === undefined ? "GET" : "POST",
    headers: { "content-type": "application/json" },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const text = await res.text();
  return { status: res.status, body: (text ? JSON.parse(text) : null) as Json };
}

/** Two users and two clients, each user with both subject token types at both clients. */
async function world(h: IssuerHost) {
  const a = await setupRefresh(h);
  const otherClient = await createClient(h, a.owner.browser, { grantTypes: ["authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:token-exchange"], extra: { scope: "openid profile email offline_access" } });
  const scope = "openid profile email offline_access";
  const aAtOther = await getTokens(h, a.user.browser, otherClient, { scope });
  const b = await signUp(h);
  const bTokens = await getTokens(h, b.browser, a.client, { scope });
  const admin = await signUp(h, { role: "admin" });
  /** Status of an exchange: [ID token, refresh token]. */
  const status = async (who: "a" | "a@other" | "b", audience?: string) => {
    const form = audience ? { audience } : {};
    const [client, t] = who === "a" ? [a.client, { id_token: a.idToken, refresh_token: a.refreshToken }] : who === "a@other" ? [otherClient, aAtOther] : [a.client, bTokens];
    const id = await exchange(h, client, t.id_token as string, form);
    const rt = await exchangeRefresh(h, client, t.refresh_token as string, form);
    return [id.status, rt.status];
  };
  return { a, b, otherClient, admin, status };
}

describe("blocks: enforcement", () => {
  it("a block of (user, client, audience) stops the next exchange for both subject token types; other users, clients, audiences are unaffected", async () => {
    const h = await host();
    const w = await world(h);
    expect(await w.status("a")).toEqual([200, 200]);
    const created = await api(w.admin.browser, "/blocks/create", { block: { userId: w.a.user.id, clientId: w.a.client.client_id, audience: "https://RS.example/api/auth", reason: "lost laptop" } });
    expect(created.status, JSON.stringify(created.body)).toBe(200);
    // The audience is normalised, so it matches what the exchange normalises.
    expect(created.body.block).toMatchObject({ userId: w.a.user.id, clientId: w.a.client.client_id, audience: "https://rs.example/api/auth", reason: "lost laptop", createdBy: w.admin.id, active: true, expiresAt: null });
    takeReasons(h);
    const r = await exchange(h, w.a.client, w.a.idToken);
    expect([r.status, r.body]).toEqual([400, GENERIC_GRANT]);
    expect(h.recorded.refused.at(-1)).toMatchObject({ reason: "policy_denied", detail: `blocked: ${created.body.block.id}`, userId: w.a.user.id });
    expect(await w.status("a")).toEqual([400, 400]);
    expect(await w.status("a", OTHER_AUDIENCE)).toEqual([200, 200]);
    expect(await w.status("a@other")).toEqual([200, 200]);
    expect(await w.status("b")).toEqual([200, 200]);
  });

  it("wildcards: a user (all clients and audiences), a client (all users), an audience (everyone)", async () => {
    const h = await host();
    const w = await world(h);
    const block = async (b: Record<string, unknown>) => (await api(w.admin.browser, "/blocks/create", { block: { reason: "r", ...b } })).body.block.id as string;
    const del = (id: string) => api(w.admin.browser, "/blocks/delete", { id });

    let id = await block({ userId: w.a.user.id });
    expect([await w.status("a"), await w.status("a", OTHER_AUDIENCE), await w.status("a@other"), await w.status("b")]).toEqual([
      [400, 400],
      [400, 400],
      [400, 400],
      [200, 200],
    ]);
    await del(id);
    id = await block({ userId: w.a.user.id, clientId: w.otherClient.client_id });
    expect([await w.status("a"), await w.status("a@other")]).toEqual([
      [200, 200],
      [400, 400],
    ]);
    await del(id);
    id = await block({ clientId: w.a.client.client_id });
    expect([await w.status("a"), await w.status("b"), await w.status("a@other")]).toEqual([
      [400, 400],
      [400, 400],
      [200, 200],
    ]);
    await del(id);
    id = await block({ clientId: w.a.client.client_id, audience: OTHER_AUDIENCE });
    expect([await w.status("a"), await w.status("b", OTHER_AUDIENCE), await w.status("a@other", OTHER_AUDIENCE)]).toEqual([
      [200, 200],
      [400, 400],
      [200, 200],
    ]);
    await del(id);
    id = await block({ audience: OTHER_AUDIENCE });
    expect([await w.status("a"), await w.status("b", OTHER_AUDIENCE), await w.status("a@other", OTHER_AUDIENCE)]).toEqual([
      [200, 200],
      [400, 400],
      [400, 400],
    ]);
    await del(id);
    expect([await w.status("a", OTHER_AUDIENCE), await w.status("b", OTHER_AUDIENCE)]).toEqual([
      [200, 200],
      [200, 200],
    ]);
  });

  it("an expired block no longer applies, and is listed as inactive; a deleted block is gone", async () => {
    const h = await host();
    const w = await world(h);
    const expiresAt = new Date(Date.now() + 3600_000).toISOString();
    const created = (await api(w.admin.browser, "/blocks/create", { block: { userId: w.a.user.id, reason: "for an hour", expiresAt } })).body.block;
    expect(created.expiresAt).toBe(expiresAt);
    expect(await w.status("a")).toEqual([400, 400]);
    await h.ctx.adapter.update({ model: BLOCK_MODEL, where: [{ field: "id", value: created.id }], update: { expiresAt: new Date(Date.now() - 1000) } });
    const got = await api(w.admin.browser, `/blocks/get?id=${created.id}`);
    expect(got.body.block?.active, JSON.stringify(got)).toBe(false);
    expect(await w.status("a")).toEqual([200, 200]);
    // The first exchange that succeeds sweeps expired blocks (sweepIntervalSeconds).
    expect((await api(w.admin.browser, `/blocks/get?id=${created.id}`)).status).toBe(404);

    const second = (await api(w.admin.browser, "/blocks/create", { block: { userId: w.a.user.id, reason: "again" } })).body.block;
    expect(await w.status("a")).toEqual([400, 400]);
    expect((await api(w.admin.browser, "/blocks/delete", { id: second.id })).body).toEqual({ deleted: second.id });
    expect(await w.status("a")).toEqual([200, 200]);
    expect((await api(w.admin.browser, `/blocks/get?id=${second.id}`)).status).toBe(404);
    expect((await api(w.admin.browser, "/blocks/delete", { id: second.id })).status).toBe(404);
  });

  it("blocks are matched exactly, even if the database's collation folds case", async () => {
    const h = await host();
    const w = await world(h);
    // Stored blocks for ids differing only in case must not match, even if the database returns them.
    const fold = (s: string) => (s.toLowerCase() === s ? s.toUpperCase() : s.toLowerCase());
    const row = { reason: "r", createdBy: w.admin.id, createdAt: new Date(), expiresAt: null };
    await h.ctx.adapter.create({ model: BLOCK_MODEL, data: { ...row, userId: fold(w.a.user.id), clientId: null, audience: null } });
    await h.ctx.adapter.create({ model: BLOCK_MODEL, data: { ...row, userId: null, clientId: fold(w.a.client.client_id), audience: null } });
    await h.ctx.adapter.create({ model: BLOCK_MODEL, data: { ...row, userId: null, clientId: null, audience: "https://RS.example/api/auth" } });
    const findMany = h.ctx.adapter.findMany.bind(h.ctx.adapter);
    h.ctx.adapter.findMany = (async (args: { model: string; where?: { field: string; value: unknown }[] }) => {
      if (args.model !== BLOCK_MODEL || !args.where) return findMany(args as never);
      const all = await findMany<Record<string, unknown>>({ model: BLOCK_MODEL, limit: 5000 });
      const eq = (a: unknown, b: unknown) => (a === null || a === undefined ? b === null : typeof a === "string" && typeof b === "string" && a.toLowerCase() === b.toLowerCase());
      return all.filter((r) => args.where?.every((x) => eq(r[x.field], x.value)));
    }) as typeof h.ctx.adapter.findMany;
    try {
      expect(await w.status("a")).toEqual([200, 200]);
    } finally {
      h.ctx.adapter.findMany = findMany;
      await h.ctx.adapter.deleteMany({ model: BLOCK_MODEL, where: [{ field: "createdBy", value: w.admin.id }] });
    }
  });

  it("too many blocks to evaluate is a refusal, not a miss (fail closed)", async () => {
    const h = await host();
    const w = await world(h);
    const now = new Date();
    for (let i = 0; i < 1000; i += 100)
      await Promise.all(
        Array.from({ length: 100 }, (_, j) =>
          h.ctx.adapter.create({ model: BLOCK_MODEL, data: { userId: w.a.user.id, clientId: `nobody-${i + j}`, audience: null, reason: "r", createdBy: w.admin.id, createdAt: now, expiresAt: null } }),
        ),
      );
    takeReasons(h);
    const r = await exchange(h, w.a.client, w.a.idToken);
    expect(r.body).toEqual(GENERIC_GRANT);
    expect(h.recorded.refused.at(-1)).toMatchObject({ reason: "policy_denied", detail: "too many blocks to evaluate" });
  });

  it("with the registry as the policy source too, the block is checked first", async () => {
    const h = await host({ registry: { enabled: true, cacheSeconds: 0 } });
    const w = await world(h);
    await api(w.admin.browser, "/blocks/create", { block: { userId: w.a.user.id, reason: "r" } });
    takeReasons(h);
    await exchange(h, w.a.client, w.a.idToken);
    // Not no_policy (the registry has nothing): the block decided.
    expect(h.recorded.refused.at(-1)?.detail).toMatch(/^blocked: /);
  });
});

describe("blocks: the API", () => {
  it("create-from-jti blocks that ID-JAG's user, client and audience (or the fields asked for); an unknown jti is 404", async () => {
    const h = await host();
    const w = await world(h);
    const jti = decodeJwt((await exchange(h, w.a.client, w.a.idToken)).body.access_token as string).jti as string;
    const all = await api(w.admin.browser, "/blocks/create-from-jti", { jti, reason: "suspicious" });
    expect(all.status, JSON.stringify(all.body)).toBe(200);
    expect(all.body.block).toMatchObject({ userId: w.a.user.id, clientId: w.a.client.client_id, audience: "https://rs.example/api/auth" });
    expect(await w.status("a")).toEqual([400, 400]);
    expect(await w.status("a", OTHER_AUDIENCE)).toEqual([200, 200]);
    await api(w.admin.browser, "/blocks/delete", { id: all.body.block.id });
    const userOnly = await api(w.admin.browser, "/blocks/create-from-jti", { jti, fields: ["userId"], reason: "r" });
    expect(userOnly.body.block).toMatchObject({ userId: w.a.user.id, clientId: null, audience: null });
    expect(await w.status("a", OTHER_AUDIENCE)).toEqual([400, 400]);
    expect((await api(w.admin.browser, "/blocks/create-from-jti", { jti: "nope", reason: "r" })).status).toBe(404);
    expect((await api(w.admin.browser, "/blocks/create-from-jti", { jti, reason: "" })).status).toBe(400);
  });

  it("validation: at least one of userId, clientId, audience; a reason; an https audience; a future expiry; no unknown fields", async () => {
    const h = await host();
    const admin = await signUp(h, { role: "admin" });
    for (const block of [
      { reason: "everything" },
      { userId: "u" },
      { userId: "u", reason: "" },
      { userId: "u", reason: "x".repeat(501) },
      { audience: "http://rs.example", reason: "r" },
      { audience: "https://rs.example#f", reason: "r" },
      { userId: "u", reason: "r", expiresAt: new Date(Date.now() - 1000).toISOString() },
      { userId: "u", reason: "r", expiresAt: "tomorrow" },
      { userId: "u\n", reason: "r" },
      { userId: "u", reason: "r", jti: "x" },
    ]) {
      const r = await api(admin.browser, "/blocks/create", { block });
      expect([r.status, r.body.code], JSON.stringify(block)).toEqual([400, "ID_JAG_INVALID_RECORD"]);
    }
    expect(await h.ctx.adapter.findMany({ model: BLOCK_MODEL, where: [{ field: "createdBy", value: admin.id }] })).toEqual([]);
  });

  it("list (newest first, filtered exactly) and get", async () => {
    const h = await host();
    const admin = await signUp(h, { role: "admin" });
    const u = `user-${crypto.randomUUID()}`;
    const first = (await api(admin.browser, "/blocks/create", { block: { userId: u, reason: "one" } })).body.block;
    const second = (await api(admin.browser, "/blocks/create", { block: { userId: u, clientId: "c", reason: "two" } })).body.block;
    await api(admin.browser, "/blocks/create", { block: { userId: `${u}-other`, reason: "three" } });
    const listed = (await api(admin.browser, `/blocks?userId=${u}`)).body.blocks as Json[];
    expect(listed.map((b) => b.id).sort()).toEqual([first.id, second.id].sort());
    expect((await api(admin.browser, `/blocks?userId=${u}&clientId=c`)).body.blocks.map((b: Json) => b.id)).toEqual([second.id]);
    expect((await api(admin.browser, `/blocks/get?id=${first.id}`)).body.block).toMatchObject({ id: first.id, reason: "one", active: true });
  });

  it("every create and delete emits id-jag.admin with the actor (and reaches the audit table)", async () => {
    const h = await createIssuerHost({ issuer: { authorize: () => ({ decision: "allow", scopes: [] }), registry: { enabled: false, canManage }, auditLog: { retentionDays: 7 } } });
    const admin = await signUp(h, { role: "admin" });
    const id = (await api(admin.browser, "/blocks/create", { block: { clientId: "c-1", reason: "r" } })).body.block.id as string;
    await api(admin.browser, "/blocks/delete", { id });
    await h.settle();
    expect(h.recorded.admin.map((e) => [e.action, e.target, e.targetId, e.actorUserId])).toEqual([
      ["create", "block", id, admin.id],
      ["delete", "block", id, admin.id],
    ]);
    const events = (await api(admin.browser, "/audit?type=id-jag.admin")).body.events as Json[];
    expect(events.filter((e) => e.details?.targetId === id).map((e) => e.actorUserId)).toEqual([admin.id, admin.id]);
  });

  it("mounted with canManage even when the registry is disabled (its routes aren't); not mounted without canManage", async () => {
    const h = await host();
    const admin = await signUp(h, { role: "admin" });
    expect((await api(admin.browser, "/blocks")).status).toBe(200);
    expect((await api(admin.browser, "/resource-servers")).status).toBe(404);
    const bare = await createIssuerHost({ issuer: { authorize: () => ({ decision: "allow", scopes: [] }) } });
    const admin2 = await signUp(bare, { role: "admin" });
    expect((await api(admin2.browser, "/blocks")).status).toBe(404);
  });
});

describe("blocks: who may manage them", () => {
  it("signed out → 401; a non-admin → 403; an impersonated admin session → 403; a banned admin → refused", async () => {
    const h = await host();
    expect((await h.auth.handler(new Request(`${ISSUER}/id-jag/blocks`))).status).toBe(401);
    const anyone = await signUp(h);
    for (const [path, body] of [
      ["/blocks", undefined],
      ["/blocks/create", { block: { userId: anyone.id, reason: "r" } }],
      ["/blocks/create-from-jti", { jti: "x", reason: "r" }],
      ["/blocks/delete", { id: "x" }],
    ] as const) {
      const r = await api(anyone.browser, path, body);
      expect([r.status, r.body.code], path).toEqual([403, "ID_JAG_REGISTRY_NOT_ALLOWED"]);
    }
    const admin = await signUp(h, { role: "admin" });
    await h.ctx.adapter.update({ model: "session", where: [{ field: "userId", value: admin.id }], update: { impersonatedBy: "someone" } });
    expect((await api(admin.browser, "/blocks/create", { block: { userId: anyone.id, reason: "r" } })).status).toBe(403);
    const other = await signUp(h, { role: "admin" });
    await h.ctx.adapter.update({ model: "user", where: [{ field: "id", value: other.id }], update: { banned: true } });
    expect([401, 403]).toContain((await api(other.browser, "/blocks")).status);
    expect(h.recorded.admin).toHaveLength(0);
    expect(await h.ctx.adapter.findMany({ model: BLOCK_MODEL, where: [{ field: "userId", value: anyone.id }] })).toEqual([]);
  });
});
