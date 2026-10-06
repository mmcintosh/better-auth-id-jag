import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

// Two projects over the same test files, as better-auth-saml-idp (D-005): Node (node:sqlite) and
// workerd (D1, through @cloudflare/vitest-plugin, which holds Vitest at 4).
const resolve = { alias: { "better-auth-id-jag": fileURLToPath(new URL("./src/index.ts", import.meta.url)) } };
const testTimeout = 60_000;

export default defineConfig({
  test: {
    projects: [
      { resolve, test: { name: "node", testTimeout, include: ["test/**/*.test.ts"], environment: "node" } },
      {
        resolve,
        plugins: [cloudflareTest({ wrangler: { configPath: "./wrangler.test.jsonc" } })],
        test: { name: "workerd", testTimeout, include: ["test/**/*.test.ts"], exclude: ["**/node_modules/**"] },
      },
    ],
  },
});
