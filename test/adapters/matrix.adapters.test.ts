// The database-sensitive behaviour on real databases (CI's `adapters` job): the jti unique key under
// concurrency (single use, S3), the date comparisons of the sweeps, and concurrent first use
// converging on one link (D-A24). SQLite and D1 run the whole suite already; these are the ones that
// differ between databases: unique keys (MongoDB builds them only from named table-level indexes,
// D-033 in better-auth-saml-idp), transactions, date and boolean round trips, collations.
// ADAPTER_DB: postgres, mysql, mongodb (Kysely and MongoDB adapters), drizzle-postgres, drizzle-mysql,
// prisma-postgres. ADAPTER_URL: a server where the test may create databases. Skipped without them.
import { afterEach, describe, expect, it } from "vitest";
import { hasJti, recordJti, sweepAudit, sweepJtis, AUDIT_MODEL } from "../../src/core";
import { coreHost } from "../support/core-host";
import { createClient, network, receiverHost, recorder, redeem, testIdp, uniqueEmail } from "../support/receiver-host";

const KIND = process.env.ADAPTER_DB;
const URL_ = process.env.ADAPTER_URL ?? "";
const enabled = !!KIND && !!URL_ && typeof navigator !== "undefined" && navigator.userAgent !== "Cloudflare-Workers";
if (process.env.ADAPTER_REQUIRED && !enabled) throw new Error("ADAPTER_REQUIRED is set, but ADAPTER_DB or ADAPTER_URL is empty");

const fresh = () => `idjag_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 6)}`;
type Raw = { database: unknown; url?: string; kysely: boolean; close(): Promise<void> };
const open: { close(): Promise<void> }[] = [];
afterEach(async () => {
  for (const d of open.splice(0).reverse()) await d.close();
});

async function connect(): Promise<Raw> {
  const kind = KIND as string;
  if (kind.endsWith("postgres")) {
    const { Pool } = await import("pg");
    const name = fresh();
    const admin = new Pool({ connectionString: URL_ });
    await admin.query(`CREATE DATABASE ${name}`);
    const url = new URL(URL_);
    url.pathname = `/${name}`;
    const pool = new Pool({ connectionString: url.toString(), max: 20 });
    pool.on("error", () => {});
    return { database: pool, url: url.toString(), kysely: true, async close() { await pool.end(); await admin.query(`DROP DATABASE IF EXISTS ${name} WITH (FORCE)`); await admin.end(); } };
  }
  if (kind.endsWith("mysql")) {
    const mysql = await import("mysql2/promise");
    const name = fresh();
    const admin = await mysql.createConnection(URL_);
    await admin.query(`CREATE DATABASE ${name}`);
    const url = new URL(URL_);
    url.pathname = `/${name}`;
    const pool = mysql.createPool({ uri: url.toString(), connectionLimit: 20, timezone: "Z" });
    return { database: pool, kysely: true, async close() { await pool.end(); await admin.query(`DROP DATABASE IF EXISTS ${name}`); await admin.end(); } };
  }
  if (kind === "mongodb") {
    const { MongoClient } = await import("mongodb");
    const { mongodbAdapter } = await import("better-auth/adapters/mongodb");
    const client = new MongoClient(URL_);
    await client.connect();
    const db = client.db(fresh());
    // Better Auth's oauth-provider client creation inside a MongoDB transaction fails at commit on
    // an empty database, and hangs once the collections exist (D-019, upstream; no ID-JAG code is
    // involved). The adapter's transactions are off here: our code uses none, and the unique keys
    // under test are MongoDB's own indexes. Collections are created first, as a host's setup would.
    const { getAuthTables } = await import("better-auth/db");
    const { jwt } = await import("better-auth/plugins");
    const { mcp } = await import("@better-auth/mcp");
    const { auditSchema, jtiSchema } = await import("../../src/core");
    const tables = getAuthTables({ plugins: [jwt(), mcp({ loginPage: "/l", consentPage: "/c", resource: "https://x.test/mcp" }) as never, { id: "core", schema: { ...jtiSchema(), ...auditSchema() } }] } as never);
    for (const t of Object.values(tables)) await db.createCollection((t as { modelName: string }).modelName).catch(() => {});
    return { database: mongodbAdapter(db, { client, transaction: false }), kysely: false, async close() { await db.dropDatabase(); await client.close(); } };
  }
  throw new Error(`unknown ADAPTER_DB ${kind}`);
}

/**
 * The database the hosts use, prepared for `build(database, migrate)`: Kysely kinds migrate
 * themselves; MongoDB needs no migrations; Drizzle and Prisma get their tables from Better Auth's
 * migrator on the raw connection first (via a bootstrap host with the same plugins), then an ORM
 * adapter whose schema is built from those same options.
 */
async function prepare<T extends { ctx: { options: unknown } }>(build: (database: unknown, migrate: boolean) => Promise<T>): Promise<(migrateHint?: boolean) => Promise<T>> {
  const raw = await connect();
  open.push(raw);
  const kind = KIND as string;
  if (!kind.startsWith("drizzle") && !kind.startsWith("prisma")) return () => build(raw.database, raw.kysely);
  const bootstrap = await build(raw.database, true);
  const options = bootstrap.ctx.options as never;
  const schemas = await import("./orm-schemas");
  if (kind.startsWith("drizzle")) {
    const { drizzleAdapter } = await import("better-auth/adapters/drizzle");
    const pg = kind === "drizzle-postgres";
    const db = pg ? (await import("drizzle-orm/node-postgres")).drizzle(raw.database as never) : (await import("drizzle-orm/mysql2")).drizzle(raw.database as never);
    const schema = pg ? await schemas.drizzlePgSchema(options) : await schemas.drizzleMysqlSchema(options);
    const adapter = drizzleAdapter(db as never, { provider: pg ? "pg" : "mysql", schema: schema as never });
    return () => build(adapter, false);
  }
  const { mkdirSync, mkdtempSync, writeFileSync, rmSync } = await import("node:fs");
  const { join } = await import("node:path");
  const { execFileSync } = await import("node:child_process");
  const { pathToFileURL } = await import("node:url");
  const cache = join(process.cwd(), "node_modules/.cache");
  mkdirSync(cache, { recursive: true });
  const dir = mkdtempSync(join(cache, "idjag-prisma-"));
  writeFileSync(join(dir, "schema.prisma"), schemas.prismaSchema(options, join(dir, "client")));
  execFileSync(join(process.cwd(), "node_modules/.bin/prisma"), ["generate", "--schema", join(dir, "schema.prisma")], { stdio: "pipe" });
  const { PrismaClient } = (await import(pathToFileURL(join(dir, "client/client.ts")).href)) as { PrismaClient: new (o: unknown) => { $disconnect(): Promise<void> } };
  const { PrismaPg } = await import("@prisma/adapter-pg");
  const prisma = new PrismaClient({ adapter: new PrismaPg({ connectionString: raw.url as string }) });
  open.push({ async close() { await prisma.$disconnect(); rmSync(dir, { recursive: true, force: true }); } });
  const { prismaAdapter } = await import("better-auth/adapters/prisma");
  const adapter = prismaAdapter(prisma as never, { provider: "postgresql" });
  return () => build(adapter, false);
}

const jti = (j: string, o: Partial<Parameters<typeof recordJti>[1]> = {}) => ({ side: "accepted" as const, jti: j, iss: "https://idp.example", aud: "https://as.example", sub: "u1", clientId: "c1", exp: Math.floor(Date.now() / 1000) + 300, clockSkewSeconds: 60, ...o });

describe.skipIf(!enabled)(`adapter matrix: ${KIND}`, () => {
  it("the jti unique key: 10 concurrent records across two instances, exactly one wins; then a replay", async () => {
    const make = await prepare((database, migrate) => coreHost(database, { migrate }));
    const [a, b] = [await make(), await make()];
    const j = crypto.randomUUID();
    const results = await Promise.all(Array.from({ length: 10 }, (_, i) => recordJti((i % 2 ? a : b).ctx.adapter, jti(j))));
    expect(results.filter(Boolean)).toHaveLength(1);
    expect(await recordJti(a.ctx.adapter, jti(j))).toBe(false);
    expect(await hasJti(b.ctx.adapter, "accepted", "https://idp.example", j)).toBe(true);
  });

  it("the sweeps compare dates correctly: expired jti and audit rows go, live ones stay", async () => {
    const make = await prepare((database, migrate) => coreHost(database, { migrate }));
    const h = await make();
    const old = crypto.randomUUID();
    const live = crypto.randomUUID();
    await recordJti(h.ctx.adapter, jti(old, { exp: Math.floor(Date.now() / 1000) - 10_000 }));
    await recordJti(h.ctx.adapter, jti(live));
    await sweepJtis(h.ctx.adapter);
    expect(await hasJti(h.ctx.adapter, "accepted", "https://idp.example", old)).toBe(false);
    expect(await hasJti(h.ctx.adapter, "accepted", "https://idp.example", live)).toBe(true);
    const at = new Date();
    for (const [id, days] of [["gone", -1], ["kept", 30]] as const)
      await h.ctx.adapter.create({ model: AUDIT_MODEL, data: { type: "id-jag.accepted", at, details: JSON.stringify({ id }), jti: id, expiresAt: new Date(at.getTime() + days * 86_400_000) } });
    await sweepAudit(h.ctx.adapter);
    const left = (await h.ctx.adapter.findMany<{ jti: string }>({ model: AUDIT_MODEL })).map((r) => r.jti);
    expect(left).toContain("kept");
    expect(left).not.toContain("gone");
  });

  for (const path of ["jit", "email-fallback"] as const) {
    it(`concurrent first use (${path}) across two instances converges on one user and one link, never a 500`, async () => {
      const idp = await testIdp();
      const providerId = `id-jag:${idp.issuer}`;
      const trust = path === "jit" ? { jitProvisioning: { trustEmailVerified: true } } : { emailFallback: { domains: ["corp.example"] } };
      const recs = [recorder(), recorder()] as const;
      let n = 0;
      const make = await prepare((database, migrate) => receiverHost("mcp", { receiver: { trustedIssuers: [{ issuer: idp.issuer, jwksUri: idp.jwksUri, ...trust }], fetch: network(idp).fetch }, database, migrate, recorder: recs[n++ % 2] as never }));
      const a = await make();
      const b = await make();
      const client = await createClient(a);
      const email = uniqueEmail("corp.example");
      if (path === "email-fallback") await a.ctx.internalAdapter.createUser({ email, name: "V", emailVerified: true }, { method: "admin" });
      const sub = crypto.randomUUID();
      const tokens = await Promise.all(Array.from({ length: Number(process.env.MATRIX_N ?? 6) }, () => idp.mint(idp.claims({ client_id: client.client_id, sub, email, email_verified: true }))));
      const results = await Promise.all(tokens.map((t, i) => redeem(i % 2 ? a : b, client, t)));
      for (const r of recs) await r.settle();
      for (const r of results) {
        expect(r.status, r.text).not.toBe(500);
        if (r.status !== 200) expect(r.body).toEqual({ error: "invalid_grant", error_description: "The grant is invalid." });
      }
      const accounts = await a.ctx.adapter.findMany<{ userId: string }>({ model: "account", where: [{ field: "providerId", value: providerId }, { field: "accountId", value: sub }] });
      expect(accounts).toHaveLength(1);
      const users = await a.ctx.adapter.findMany({ model: "user", where: [{ field: "email", value: email }] });
      expect(users).toHaveLength(1);
      const later = await redeem(a, client, await idp.mint(idp.claims({ client_id: client.client_id, sub, email })));
      expect(later.status, later.text).toBe(200);
    });
  }
});
