// Phase 0 throwaway Worker: mcp() + cimd() + jwt() + sso() + the ping plugin on D1, so the spike's
// checks can run over HTTP on workerd. Deleted at the end of Phase 0 (docs/phase-0.md).
import { betterAuth } from "better-auth";
import type { BetterAuthPlugin } from "better-auth";
import { jwt } from "better-auth/plugins";
import { cimd } from "@better-auth/cimd";
import { mcp } from "@better-auth/mcp";
import { sso } from "@better-auth/sso";
import { ping } from "../../support/ping";

interface Env {
  DB: D1Database;
  BETTER_AUTH_SECRET: string;
  /** Required on client creation, so the open sign-up can't mint clients. */
  SPIKE_KEY: string;
  /** "0" builds the same host without the ping plugin (bundle-size baseline). */
  WITH_PING?: string;
}

function createAuth(env: Env, origin: string) {
  return betterAuth({
    baseURL: origin,
    secret: env.BETTER_AUTH_SECRET,
    telemetry: { enabled: false },
    database: env.DB as never,
    emailAndPassword: { enabled: true },
    plugins: [
      jwt(),
      mcp({
        loginPage: "/login",
        consentPage: "/consent",
        resource: `${origin}/mcp`,
        allowDynamicClientRegistration: false,
        scopes: ["openid", "profile", "email", "offline_access", "read"],
        clientPrivileges: ({ headers }) => !!env.SPIKE_KEY && headers?.get("x-spike-key") === env.SPIKE_KEY,
      }) as unknown as BetterAuthPlugin,
      cimd({ fetchClientMetadataResource: () => Promise.reject(new Error("no CIMD fetch in the spike Worker")) }),
      sso() as unknown as BetterAuthPlugin,
      ...(env.WITH_PING === "0" ? [] : [ping()]),
    ],
  });
}

// One instance per isolate and origin, unless PER_REQUEST=1 (to measure the cost of building it).
const cache = new Map<string, ReturnType<typeof createAuth>>();

export default {
  async fetch(request: Request, env: Env & { PER_REQUEST?: string }): Promise<Response> {
    const origin = new URL(request.url).origin;
    if (env.PER_REQUEST === "1") return createAuth(env, origin).handler(request);
    let auth = cache.get(origin);
    if (!auth) {
      auth = createAuth(env, origin);
      cache.set(origin, auth);
    }
    return auth.handler(request);
  },
} satisfies ExportedHandler<Env>;
