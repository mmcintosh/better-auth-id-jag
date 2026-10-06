// Prints each example Worker's D1 schema: Better Auth's own migrations for the same plugins,
// compiled against SQLite, from the built package (pnpm build first). node examples/workers/schema.mts idp|mcp > <worker>/migrations/0001_init.sql
import { DatabaseSync } from "node:sqlite";
import { betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import { jwt } from "better-auth/plugins";
import { mcp } from "@better-auth/mcp";
import { oauthProvider } from "@better-auth/oauth-provider";
import { idJagGrant, idJagIssuer } from "../../dist/index.js";

// node examples/workers/schema.mts idp|mcp [<existing migration.sql> ...]: with existing migrations
// applied first, prints only what is still missing (the next migration).
const which = process.argv[2];
const db = new DatabaseSync(":memory:");
const { readFileSync } = await import("node:fs");
for (const f of process.argv.slice(3)) db.exec(readFileSync(f, "utf8"));
const base = { baseURL: "https://schema.invalid", secret: "schema-secret-that-is-at-least-32-characters-long", telemetry: { enabled: false }, database: db, emailAndPassword: { enabled: true } };
const plugins =
  which === "idp"
    ? [jwt(), oauthProvider({ loginPage: "/l", consentPage: "/c" }), idJagIssuer({ authorize: () => ({ decision: "deny" }), auditLog: { retentionDays: 1 } })]
    : [jwt(), mcp({ loginPage: "/l", consentPage: "/c", resource: "https://schema.invalid/mcp" }), idJagGrant({ trustedIssuers: [{ issuer: "https://idp.invalid", jwksUri: "https://idp.invalid/jwks" }], auditLog: { retentionDays: 1 } })];
const auth = betterAuth({ ...base, plugins } as never);
const { compileMigrations } = await getMigrations((await (auth as { $context: Promise<{ options: never }> }).$context).options);
process.stdout.write(await compileMigrations());
