// Prints the SQL for the spike Worker's D1 database: Better Auth's own migrations for the same
// plugin set, compiled against SQLite.
import { DatabaseSync } from "node:sqlite";
import { betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import { jwt } from "better-auth/plugins";
import { cimd } from "@better-auth/cimd";
import { mcp } from "@better-auth/mcp";
import { sso } from "@better-auth/sso";

const auth = betterAuth({
  baseURL: "https://spike.invalid",
  secret: "schema-secret-that-is-at-least-32-characters-long",
  telemetry: { enabled: false },
  database: new DatabaseSync(":memory:"),
  emailAndPassword: { enabled: true },
  plugins: [jwt(), mcp({ loginPage: "/l", consentPage: "/c", resource: "https://spike.invalid/mcp" }), cimd({ fetchClientMetadataResource: () => Promise.reject(new Error("x")) }), sso()],
});
const { compileMigrations } = await getMigrations((await auth.$context).options);
process.stdout.write(await compileMigrations());
