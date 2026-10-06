// The registry: policy evaluation from stored resource servers and policies, and the admin API's
// access control (better-auth-saml-idp D-027's boundaries).
import type { BetterAuthPlugin } from "better-auth";
import { organization } from "better-auth/plugins";
import { decodeJwt } from "jose";
import { beforeEach, describe, expect, it } from "vitest";
import { publicDescription } from "../../src/core";
import { type IdJagIssuerOptions, POLICY_MODEL, RESOURCE_SERVER_MODEL } from "../../src/issuer";
import { type Browser, createIssuerHost, database, exchange as exchangeAt, ISSUER, type IssuerHost, RESOURCE, setup, signUp, takeReasons, verifyWithHostJwks } from "../support/issuer-host";

// A fresh audience per test: in workerd every host in this file shares one D1, and audiences are unique.
let AUDIENCE = "";
beforeEach(() => {
  AUDIENCE = `https://rs-${crypto.randomUUID()}.example/api/auth`;
});
const exchange: typeof exchangeAt = (h, c, t, form = {}, o = {}) => exchangeAt(h, c, t, { audience: AUDIENCE, ...form }, o);

const canManage = ({ user }: { user: Record<string, unknown> }) => user.role === "admin";

async function host(o: { registry?: Partial<NonNullable<IdJagIssuerOptions["registry"]>>; issuer?: Omit<IdJagIssuerOptions, "events" | "registry">; auth?: Record<string, unknown>; database?: unknown; extra?: BetterAuthPlugin[] } = {}) {
  return createIssuerHost({
    issuer: { ...o.issuer, registry: { enabled: true, canManage, cacheSeconds: 0, ...o.registry } as NonNullable<IdJagIssuerOptions["registry"]> },
    ...(o.auth ? { auth: o.auth } : {}),
    ...(o.database ? { database: o.database } : {}),
    ...(o.extra ? { extra: o.extra } : {}),
  });
}

type Json = Record<string, any>;
async function api(browser: Browser, path: string, body?: unknown, o: { origin?: string } = {}) {
  const res = await browser.fetch(`${ISSUER}/id-jag${path}`, {
    method: body === undefined ? "GET" : "POST",
    headers: { "content-type": "application/json", ...(o.origin ? { origin: o.origin } : {}) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const text = await res.text();
  return { status: res.status, body: (text ? JSON.parse(text) : null) as Json };
}

const rsConfig = (over: Record<string, unknown> = {}) => ({ audience: AUDIENCE, name: "MCP server", resources: [RESOURCE], scopes: ["read", "write", "admin"], ...over });

/** An admin, a resource server and a policy for this client (everyone), through the API. */
async function registered(h: IssuerHost, client: { client_id: string }, o: { rs?: Record<string, unknown>; policy?: Record<string, unknown> } = {}) {
  const admin = await signUp(h, { role: "admin" });
  const rs = await api(admin.browser, "/resource-servers/create", { resourceServer: rsConfig(o.rs) });
  expect(rs.status, JSON.stringify(rs.body)).toBe(200);
  const policy = await api(admin.browser, "/policies/create", {
    policy: { resourceServerId: rs.body.resourceServer.id, name: "everyone", subjectKind: "everyone", clientIds: [client.client_id], scopes: ["read", "write"], ...o.policy },
  });
  expect(policy.status, JSON.stringify(policy.body)).toBe(200);
  return { admin, rsId: rs.body.resourceServer.id as string, policyId: policy.body.policy.id as string };
}

describe("registry: policy evaluation", () => {
  it("issues with the policy's scopes ∩ requested and the resource server's client-id mapping; core verifyIdJag accepts it", async () => {
    const h = await host();
    const { client, idToken } = await setup(h);
    await registered(h, client, { rs: { clientIdsAtResource: { [client.client_id]: "agent-at-rs" } } });
    const r = await exchange(h, client, idToken, { scope: "write admin", resource: RESOURCE });
    expect(r.status, JSON.stringify(r.body)).toBe(200);
    const parsed = await verifyWithHostJwks(h, r.body.access_token as string, { audience: AUDIENCE });
    // admin is in the resource server's scopes but not the policy's: never wider.
    expect(parsed.claims).toMatchObject({ scope: "write", client_id: "agent-at-rs", resource: RESOURCE });
  });

  it("the client id at the resource defaults to the client's own id", async () => {
    const h = await host();
    const { client, idToken } = await setup(h);
    await registered(h, client);
    expect(decodeJwt((await exchange(h, client, idToken)).body.access_token as string).client_id).toBe(client.client_id);
  });

  it("no resource server for the audience: no_policy; one with no policy for this client: policy_denied (one body)", async () => {
    const h = await host();
    const { client, idToken } = await setup(h);
    const a = await exchange(h, client, idToken);
    expect(takeReasons(h)).toEqual(["no_policy"]);
    const other = await setup(h);
    await registered(h, other.client);
    const b = await exchange(h, client, idToken);
    expect(takeReasons(h)).toEqual(["policy_denied"]);
    expect(a.body).toEqual(b.body);
    expect(a.body).toEqual({ error: "invalid_grant", error_description: publicDescription("no_policy") });
  });

  it("subject kinds: users, role, organization", async () => {
    const h = await host({ extra: [organization() as unknown as BetterAuthPlugin] });
    const { client, idToken, user } = await setup(h);
    const { admin, policyId, rsId } = await registered(h, client, { policy: { subjectKind: "users", subjectRef: ["someone-else"] } });
    await exchange(h, client, idToken);
    expect(takeReasons(h)).toEqual(["policy_denied"]);
    const update = (policy: Record<string, unknown>) =>
      api(admin.browser, "/policies/update", { id: policyId, policy: { resourceServerId: rsId, name: "p", clientIds: [client.client_id], scopes: ["read"], ...policy } });
    expect((await update({ subjectKind: "users", subjectRef: [user.id] })).status).toBe(200);
    expect((await exchange(h, client, idToken)).status).toBe(200);
    expect((await update({ subjectKind: "role", subjectRef: ["auditor"] })).status).toBe(200);
    expect((await exchange(h, client, idToken)).status).toBe(400);
    await h.ctx.adapter.update({ model: "user", where: [{ field: "id", value: user.id }], update: { role: "user,auditor" } });
    expect((await exchange(h, client, idToken)).status).toBe(200);
    expect((await update({ subjectKind: "organization", subjectRef: ["org-1"] })).status).toBe(200);
    expect((await exchange(h, client, idToken)).status).toBe(400);
    const org = await h.ctx.adapter.create<{ id: string }>({ model: "organization", data: { name: "Org", slug: `org-${crypto.randomUUID()}`, createdAt: new Date() } });
    expect((await update({ subjectKind: "organization", subjectRef: [org.id] })).status).toBe(200);
    expect((await exchange(h, client, idToken)).status).toBe(400);
    await h.ctx.adapter.create({ model: "member", data: { organizationId: org.id, userId: user.id, role: "member", createdAt: new Date() } });
    expect((await exchange(h, client, idToken)).status).toBe(200);
  });

  it("a resource server of an organization applies to its members only, and its id is the tenant claim; two that both allow are ambiguous", async () => {
    const h = await host({ extra: [organization() as unknown as BetterAuthPlugin] });
    const { client, idToken, user } = await setup(h);
    const org = await h.ctx.adapter.create<{ id: string }>({ model: "organization", data: { name: "Org", slug: `org-${crypto.randomUUID()}`, createdAt: new Date() } });
    const { admin } = await registered(h, client, { rs: { organizationId: org.id } });
    await exchange(h, client, idToken);
    expect(takeReasons(h)).toEqual(["no_policy"]);
    await h.ctx.adapter.create({ model: "member", data: { organizationId: org.id, userId: user.id, role: "member", createdAt: new Date() } });
    const r = await exchange(h, client, idToken);
    expect(r.status).toBe(200);
    expect(decodeJwt(r.body.access_token as string).tenant).toBe(org.id);
    // The same audience for the host as well (unique per organization): both allow → refused.
    const global = await api(admin.browser, "/resource-servers/create", { resourceServer: rsConfig() });
    expect(global.status).toBe(200);
    await api(admin.browser, "/policies/create", { policy: { resourceServerId: global.body.resourceServer.id, name: "g", subjectKind: "everyone", clientIds: [client.client_id], scopes: ["read"] } });
    await exchange(h, client, idToken);
    expect(takeReasons(h)).toEqual(["policy_denied"]);
  });

  it("resource: registered ones only (S7), and required when the resource server says so: unknown_resource", async () => {
    const h = await host();
    const { client, idToken } = await setup(h);
    const { admin, rsId } = await registered(h, client);
    expect((await exchange(h, client, idToken, { resource: RESOURCE })).status).toBe(200);
    const r = await exchange(h, client, idToken, { resource: "https://other.example/mcp" });
    expect(r.body).toEqual({ error: "invalid_target", error_description: publicDescription("unknown_resource") });
    expect(takeReasons(h)).toEqual(["unknown_resource"]);
    expect((await exchange(h, client, idToken)).status).toBe(200);
    await api(admin.browser, "/resource-servers/update", { id: rsId, resourceServer: rsConfig({ requireResource: true }) });
    await exchange(h, client, idToken);
    expect(takeReasons(h)).toEqual(["unknown_resource"]);
  });

  it("disabled resource servers and policies are not used", async () => {
    const h = await host();
    const { client, idToken } = await setup(h);
    const { admin, rsId, policyId } = await registered(h, client);
    await api(admin.browser, "/policies/update", { id: policyId, enabled: false });
    await exchange(h, client, idToken);
    expect(takeReasons(h)).toEqual(["policy_denied"]);
    await api(admin.browser, "/policies/update", { id: policyId, enabled: true });
    await api(admin.browser, "/resource-servers/update", { id: rsId, enabled: false });
    await exchange(h, client, idToken);
    expect(takeReasons(h)).toEqual(["no_policy"]);
  });

  it("lifetime: the shortest of the matching policies; email when a policy opts in", async () => {
    const h = await host();
    const { client, idToken, user } = await setup(h);
    const { admin, rsId } = await registered(h, client, { policy: { lifetimeSeconds: 120 } });
    await api(admin.browser, "/policies/create", { policy: { resourceServerId: rsId, name: "short", subjectKind: "users", subjectRef: [user.id], clientIds: [client.client_id], scopes: ["admin"], lifetimeSeconds: 60, includeEmail: true } });
    await h.ctx.adapter.update({ model: "user", where: [{ field: "id", value: user.id }], update: { emailVerified: true } });
    const r = await exchange(h, client, idToken);
    const c = decodeJwt(r.body.access_token as string);
    expect(r.body.expires_in).toBe(60);
    expect(c.scope).toBe("read write admin");
    expect(c.email).toBe(user.email);
  });

  it("with the authorize hook too: both must allow, and scopes intersect", async () => {
    let verdict: "allow" | "deny" = "allow";
    const h = await host({ issuer: { authorize: () => (verdict === "allow" ? { decision: "allow", scopes: ["read", "admin"] } : { decision: "deny" }) } });
    const { client, idToken } = await setup(h);
    // Registry: read write. Hook: read admin. Both: read.
    await registered(h, client);
    expect((await exchange(h, client, idToken)).body.scope).toBe("read");
    verdict = "deny";
    await exchange(h, client, idToken);
    expect(takeReasons(h)).toEqual(["policy_denied"]);
  });

  it("rows edited by hand into something invalid are reported and never used", async () => {
    const logs: string[] = [];
    const h = await host({ auth: { logger: { level: "warn", log: (_l: string, m: string) => void logs.push(m) } } });
    const { client, idToken } = await setup(h);
    const { admin, rsId, policyId } = await registered(h, client);
    await h.ctx.adapter.update({ model: POLICY_MODEL, where: [{ field: "id", value: policyId }], update: { scopes: "not json" } });
    await exchange(h, client, idToken);
    expect(takeReasons(h)).toEqual(["policy_denied"]);
    expect(logs.some((m) => m.includes(`policy ${policyId} no longer validates`))).toBe(true);
    expect((await api(admin.browser, `/policies/get?id=${policyId}`)).body.policy).toMatchObject({ valid: false });
    // An audience column changed by hand no longer matches its lookup key.
    await h.ctx.adapter.update({ model: RESOURCE_SERVER_MODEL, where: [{ field: "id", value: rsId }], update: { audience: AUDIENCE.replace("https://rs-", "https://RS-") } });
    const rs = (await api(admin.browser, `/resource-servers/get?id=${rsId}`)).body.resourceServer;
    expect(rs.valid).toBe(false);
    expect(rs.issues.join(" ")).toMatch(/normalised|lookupKey/);
    await h.ctx.adapter.update({ model: RESOURCE_SERVER_MODEL, where: [{ field: "id", value: rsId }], update: { audience: AUDIENCE, scopes: JSON.stringify(["bad scope"]) } });
    await exchange(h, client, idToken);
    expect(takeReasons(h)).toEqual(["no_policy"]);
  });

  it("cache: another instance on the same database sees a change after cacheSeconds (0: at once; 60: keeps a miss)", async () => {
    const db = await database();
    const a = await host({ database: db });
    const fresh = await host({ database: db, registry: { cacheSeconds: 0 } });
    const cached = await host({ database: db, registry: { cacheSeconds: 60 } });
    const { client, idToken } = await setup(a);
    expect((await exchange(cached, client, idToken)).status).toBe(400);
    await registered(a, client);
    expect((await exchange(fresh, client, idToken)).status).toBe(200);
    expect((await exchange(cached, client, idToken)).status).toBe(400); // a cached miss, documented
  });
});

describe("registry API: records", () => {
  it("create, list, get, update, delete; every change emits id-jag.admin with the actor", async () => {
    const h = await host();
    const admin = await signUp(h, { role: "admin" });
    const created = await api(admin.browser, "/resource-servers/create", { resourceServer: rsConfig({ audience: AUDIENCE.toUpperCase().replace("/API/AUTH", "/api/auth") }) });
    expect(created.status).toBe(200);
    const rs = created.body.resourceServer;
    expect(rs).toMatchObject({ valid: true, enabled: true, createdBy: admin.id, config: { audience: AUDIENCE, scopes: ["read", "write", "admin"], requireResource: false, clientIdsAtResource: {} } });
    expect((await api(admin.browser, "/resource-servers")).body.resourceServers.map((r: Json) => r.id)).toContain(rs.id);
    expect((await api(admin.browser, `/resource-servers/get?id=${rs.id}`)).body.resourceServer.config.name).toBe("MCP server");
    expect((await api(admin.browser, "/resource-servers/get?id=nope")).status).toBe(404);
    const p = await api(admin.browser, "/policies/create", { policy: { resourceServerId: rs.id, name: "p", subjectKind: "everyone", clientIds: ["c1"], scopes: ["read"] }, enabled: false });
    expect(p.body.policy).toMatchObject({ enabled: false, valid: true });
    expect((await api(admin.browser, `/policies?resourceServerId=${rs.id}`)).body.policies).toHaveLength(1);
    expect((await api(admin.browser, "/resource-servers/delete", { id: rs.id })).status).toBe(409);
    expect((await api(admin.browser, "/policies/delete", { id: p.body.policy.id })).status).toBe(200);
    expect((await api(admin.browser, "/policies/delete", { id: p.body.policy.id })).status).toBe(404);
    expect((await api(admin.browser, "/resource-servers/update", { id: rs.id, resourceServer: rsConfig({ name: "renamed" }) })).body.resourceServer.config.name).toBe("renamed");
    expect((await api(admin.browser, "/resource-servers/delete", { id: rs.id })).status).toBe(200);
    expect(h.recorded.admin.map((e) => [e.action, e.target, e.actorUserId])).toEqual([
      ["create", "resource-server", admin.id],
      ["create", "policy", admin.id],
      ["delete", "policy", admin.id],
      ["update", "resource-server", admin.id],
      ["delete", "resource-server", admin.id],
    ]);
  });

  it("validation: bad audiences, scopes, resources, subjects, lifetimes; policy scopes must be the resource server's", async () => {
    const h = await host();
    const admin = await signUp(h, { role: "admin" });
    for (const bad of [rsConfig({ audience: "http://rs.example" }), rsConfig({ audience: "https://rs.example/#f" }), rsConfig({ scopes: ["a b"] }), rsConfig({ resources: ["x#y"] }), rsConfig({ nope: 1 }), rsConfig({ scopes: ["a", "a"] })]) {
      const r = await api(admin.browser, "/resource-servers/create", { resourceServer: bad });
      expect(r.status, JSON.stringify(bad)).toBe(400);
      expect(r.body.code).toBe("ID_JAG_INVALID_RECORD");
      expect(r.body.issues.length).toBeGreaterThan(0);
    }
    const rs = (await api(admin.browser, "/resource-servers/create", { resourceServer: rsConfig() })).body.resourceServer;
    const policy = (over: Record<string, unknown>) => ({ policy: { resourceServerId: rs.id, name: "p", subjectKind: "everyone", clientIds: ["c1"], scopes: ["read"], ...over } });
    for (const over of [{ scopes: ["delete"] }, { subjectKind: "users" }, { subjectKind: "everyone", subjectRef: ["x"] }, { lifetimeSeconds: 901 }, { lifetimeSeconds: 0 }, { clientIds: [] }, { resourceServerId: "nope" }, { subjectKind: "group" }]) {
      const r = await api(admin.browser, "/policies/create", policy(over));
      expect(r.status, JSON.stringify(over)).toBe(400);
    }
    const ok = await api(admin.browser, "/policies/create", policy({}));
    expect((await api(admin.browser, "/policies/update", { id: ok.body.policy.id, policy: policy({ resourceServerId: "other" }).policy })).status).toBe(400);
  });

  it("an audience is unique per organization: duplicates 409, concurrent creates decided by the UNIQUE key", async () => {
    const h = await host();
    const admin = await signUp(h, { role: "admin" });
    const audience = `https://rs-${crypto.randomUUID()}.example`;
    const results = await Promise.all(Array.from({ length: 5 }, () => api(admin.browser, "/resource-servers/create", { resourceServer: rsConfig({ audience }) })));
    expect(results.map((r) => r.status).sort()).toEqual([200, 409, 409, 409, 409]);
    expect(results.find((r) => r.status === 409)?.body.code).toBe("ID_JAG_RESOURCE_SERVER_EXISTS");
    // Another organization may register the same audience.
    expect((await api(admin.browser, "/resource-servers/create", { resourceServer: rsConfig({ audience, organizationId: "org-x" }) })).status).toBe(200);
    // Updating another one onto a taken audience is a conflict too.
    const other = (await api(admin.browser, "/resource-servers/create", { resourceServer: rsConfig({ audience: `${audience}/b` }) })).body.resourceServer;
    expect((await api(admin.browser, "/resource-servers/update", { id: other.id, resourceServer: rsConfig({ audience }) })).status).toBe(409);
  });

  it("revoke an issued jti: recorded as id-jag.admin; an unknown jti is 404", async () => {
    const h = await host();
    const { client, idToken } = await setup(h);
    const { admin } = await registered(h, client);
    const jti = decodeJwt((await exchange(h, client, idToken)).body.access_token as string).jti as string;
    expect((await api(admin.browser, "/issued/revoke", { jti })).body).toEqual({ jti, revoked: true });
    expect(h.recorded.admin.at(-1)).toMatchObject({ action: "revoke", target: "jti", targetId: jti, actorUserId: admin.id });
    expect((await api(admin.browser, "/issued/revoke", { jti: "nope" })).status).toBe(404);
  });

  it("the audit log: issued, refused and admin events, newest first (with auditLog)", async () => {
    const h = await host({ issuer: { auditLog: { retentionDays: 30 } } });
    const { client, idToken } = await setup(h);
    const { admin } = await registered(h, client);
    await exchange(h, client, idToken);
    await exchange(h, client, idToken, { resource: "https://other.example/mcp" });
    await h.settle();
    const events = (await api(admin.browser, "/audit")).body.events as Json[];
    expect(events.map((e) => e.type)).toEqual(expect.arrayContaining(["id-jag.issued", "id-jag.refused", "id-jag.admin"]));
    expect(events.find((e) => e.type === "id-jag.refused")?.reason).toBe("unknown_resource");
    expect((await api(admin.browser, "/audit?type=id-jag.admin")).body.events.every((e: Json) => e.type === "id-jag.admin")).toBe(true);
  });
});

describe("registry API: who may manage it", () => {
  it("not mounted without canManage (the tables are still used)", async () => {
    const h = await host({ registry: { canManage: undefined } });
    const admin = await signUp(h, { role: "admin" });
    expect((await api(admin.browser, "/resource-servers")).status).toBe(404);
  });

  it("signed out → 401; a non-admin → 403", async () => {
    const h = await host();
    const anyone = await signUp(h);
    const res = await h.auth.handler(new Request(`${ISSUER}/id-jag/resource-servers`));
    expect(res.status).toBe(401);
    const r = await api(anyone.browser, "/resource-servers/create", { resourceServer: rsConfig() });
    expect([r.status, r.body.code]).toEqual([403, "ID_JAG_REGISTRY_NOT_ALLOWED"]);
    expect(h.recorded.admin).toHaveLength(0);
  });

  it("a demoted admin loses access at once, also with Better Auth's cookie cache on", async () => {
    for (const auth of [undefined, { session: { cookieCache: { enabled: true, maxAge: 300 } } }]) {
      const h = await host(auth ? { auth } : {});
      const admin = await signUp(h, { role: "admin" });
      await admin.browser.fetch(`${ISSUER}/get-session`); // the cache holds the admin role
      expect((await api(admin.browser, "/resource-servers")).status).toBe(200);
      await h.ctx.adapter.update({ model: "user", where: [{ field: "id", value: admin.id }], update: { role: "user" } });
      expect((await admin.browser.fetch(`${ISSUER}/get-session`)).status).toBe(200);
      expect((await api(admin.browser, "/resource-servers")).status).toBe(403);
    }
  });

  it("an impersonated session can't manage, even an admin's; nor a banned admin", async () => {
    const h = await host();
    const admin = await signUp(h, { role: "admin" });
    await h.ctx.adapter.update({ model: "session", where: [{ field: "userId", value: admin.id }], update: { impersonatedBy: "someone" } });
    expect((await api(admin.browser, "/resource-servers")).status).toBe(403);
    const other = await signUp(h, { role: "admin" });
    expect((await api(other.browser, "/resource-servers")).status).toBe(200);
    await h.ctx.adapter.update({ model: "user", where: [{ field: "id", value: other.id }], update: { banned: true } });
    expect([401, 403]).toContain((await api(other.browser, "/resource-servers")).status);
  });

  it("canManage throwing, or answering anything but true, denies", async () => {
    for (const cm of [
      () => {
        throw new Error("boom");
      },
      () => "yes" as unknown as boolean,
      async () => 1 as unknown as boolean,
    ]) {
      const h = await host({ registry: { canManage: cm } });
      const admin = await signUp(h, { role: "admin" });
      expect((await api(admin.browser, "/resource-servers")).status).toBe(403);
    }
  });

  it("mutations keep Better Auth's origin check", async () => {
    const h = await host({ auth: { advanced: { disableOriginCheck: false } } });
    const admin = await signUp(h, { role: "admin" });
    expect((await api(admin.browser, "/resource-servers/create", { resourceServer: rsConfig() }, { origin: "https://evil.example" })).status).toBe(403);
    expect((await api(admin.browser, "/resource-servers/create", { resourceServer: rsConfig() })).status).toBe(200);
  });

  it("the registry's tables are in the schema only when it is enabled; the audit table only with auditLog", async () => {
    const { issuerSchema } = await import("../../src/issuer");
    expect(Object.keys(issuerSchema({ registry: false, auditLog: false }))).toEqual(["idJagJti"]);
    expect(Object.keys(issuerSchema({ registry: true, auditLog: true })).sort()).toEqual(["idJagAudit", "idJagJti", "idJagPolicy", "idJagResourceServer"]);
    // A named table-level unique index for MongoDB (better-auth-saml-idp D-033).
    expect(issuerSchema({ registry: true, auditLog: false }).idJagResourceServer?.indexes).toEqual([{ fields: ["lookupKey"], unique: true, name: "id_jag_resource_server_lookup_key_unique" }]);
  });
});
