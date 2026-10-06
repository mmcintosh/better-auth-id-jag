// One host with both plugins: both declare the core's idJagJti and idJagAudit tables. Better Auth
// must merge them into one table each, and both metadata fields must be served (merge check, Phase 1).
import { betterAuth, type BetterAuthPlugin } from "better-auth";
import { getAuthTables } from "better-auth/db";
import { getMigrations } from "better-auth/db/migration";
import { jwt } from "better-auth/plugins";
import { mcp } from "@better-auth/mcp";
import { describe, expect, it } from "vitest";
import { AUDIT_MODEL, ISSUER_METADATA_FIELD, JTI_MODEL, RECEIVER_METADATA_FIELD, idJagGrant, idJagIssuer } from "../../src";

async function database(): Promise<unknown> {
  if (navigator.userAgent === "Cloudflare-Workers") return (await import("cloudflare:test")).env.DB;
  const { DatabaseSync } = await import("node:sqlite");
  return new DatabaseSync(":memory:");
}

describe("issuer and receiver on one host", () => {
  it("boots, migrates one jti table and one audit table, and advertises both sides", async () => {
    const auth = betterAuth({
      baseURL: "http://localhost:3000",
      secret: "test-secret-that-is-at-least-32-characters-long",
      telemetry: { enabled: false },
      database: (await database()) as never,
      plugins: [
        jwt(),
        mcp({ loginPage: "/login", consentPage: "/consent", resource: "http://localhost:3000/mcp" }) as unknown as BetterAuthPlugin,
        idJagIssuer({ authorize: () => ({ decision: "deny" }), auditLog: { retentionDays: 30 } }),
        idJagGrant({ trustedIssuers: [{ issuer: "https://idp.example", jwksUri: "https://idp.example/jwks" }], auditLog: { retentionDays: 30 } }),
      ],
    });
    const ctx = await auth.$context;
    const tables = Object.keys(getAuthTables(ctx.options));
    await (await getMigrations(ctx.options)).runMigrations();
    expect(tables).toContain(JTI_MODEL);
    expect(tables).toContain(AUDIT_MODEL);
    // Both plugins' fields merged into one definition (identical, so nothing lost).
    expect(Object.keys(getAuthTables(ctx.options)[JTI_MODEL]!.fields)).toEqual(expect.arrayContaining(["key", "side", "jti", "expiresAt"]));
    // Rows from both sides land in the one table.
    await ctx.adapter.create({ model: JTI_MODEL, data: { key: "k1", side: "issued", jti: "a", iss: "i", aud: "a", sub: "s", clientId: "c", expiresAt: new Date(), createdAt: new Date() } });
    await ctx.adapter.create({ model: JTI_MODEL, data: { key: "k2", side: "accepted", jti: "a", iss: "i", aud: "a", sub: "s", clientId: "c", expiresAt: new Date(), createdAt: new Date() } });
    expect(await ctx.adapter.count({ model: JTI_MODEL, where: [{ field: "jti", value: "a" }] })).toBe(2);
    const doc = (await (await auth.handler(new Request("http://localhost:3000/.well-known/oauth-authorization-server/api/auth"))).json()) as Record<string, unknown>;
    expect(doc[ISSUER_METADATA_FIELD]).toBeDefined();
    expect(doc[RECEIVER_METADATA_FIELD]).toBeDefined();
    expect(doc.grant_types_supported).toEqual(expect.arrayContaining(["urn:ietf:params:oauth:grant-type:token-exchange", "urn:ietf:params:oauth:grant-type:jwt-bearer"]));
  });
});
