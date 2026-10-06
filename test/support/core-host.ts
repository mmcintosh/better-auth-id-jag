// A Better Auth host with only the core's tables (jti, audit), for replay and audit tests. Two
// hosts can share one database, as two Worker isolates share one D1.
import { betterAuth } from "better-auth";
import type { BetterAuthPlugin } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import { auditSchema, jtiSchema } from "../../src/core";

export async function sharedDatabase(): Promise<unknown> {
  if (navigator.userAgent === "Cloudflare-Workers") return (await import("cloudflare:test")).env.DB;
  const { DatabaseSync } = await import("node:sqlite");
  return new DatabaseSync(":memory:");
}

const corePlugin = { id: "id-jag-core-test", schema: { ...jtiSchema(), ...auditSchema() } } satisfies BetterAuthPlugin;

export async function coreHost(database: unknown, o: { backgroundTasks?: (p: Promise<unknown>) => void } = {}) {
  const auth = betterAuth({
    baseURL: "http://localhost:3000",
    secret: "test-secret-that-is-at-least-32-characters-long",
    telemetry: { enabled: false },
    database: database as never,
    plugins: [corePlugin],
    ...(o.backgroundTasks ? { advanced: { backgroundTasks: { handler: o.backgroundTasks } } } : {}),
  });
  const ctx = await auth.$context;
  await (await getMigrations(ctx.options)).runMigrations();
  return { auth, ctx };
}
