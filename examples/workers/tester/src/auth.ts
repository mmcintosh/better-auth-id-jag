// The tester's authorization server: the published receiver (idJagGrant) behind mcp(), trusting only issuers that
// testers registered (the idJagTrustedIssuer table), each limited to its own client. Testers sign in with GitHub or
// GitLab (gitlab.com).
//
// What sign-in keeps about a tester (docs/test-your-idp.md, "Privacy"): their public login as the name, the
// provider's account id (on the account row), and when the account was created (for the 30-day rule). Not their
// email: a made-up address stands in, at a domain that receives no mail. Not their picture. Not the provider's
// tokens: they are stripped before anything is written. GitHub is asked only for read:user, GitLab for read_user.
//
// Isolation: every ID-JAG's user is a sandbox user made by resolveSubject below, keyed by the registration and a
// hash of `sub`. The receiver's other ways of finding a user (linked accounts, email, JIT) never run, so an ID-JAG
// can't reach a tester's GitHub user, another registration's users, or anything else. No email from an ID-JAG is
// stored.
import { betterAuth, type BetterAuthPlugin } from "better-auth";
import { jwt } from "better-auth/plugins";
import { mcp } from "@better-auth/mcp";
import { idJagGrant, type ResolveSubjectInput, type SubjectResolution } from "better-auth-id-jag";
import { backgroundTasks } from "../../background";
import { guardedFetch } from "./guard";
import { TESTER_EMAIL_DOMAIN } from "./privacy";
import { activeByClient } from "./store";

export interface Env {
  DB: D1Database;
  BETTER_AUTH_SECRET: string;
  GITHUB_CLIENT_ID: string;
  GITHUB_CLIENT_SECRET: string;
  /** Optional: GitLab (gitlab.com) sign-in, when both are set. */
  GITLAB_CLIENT_ID?: string;
  GITLAB_CLIENT_SECRET?: string;
  TURNSTILE_SITE_KEY: string;
  TURNSTILE_SECRET_KEY: string;
  /** Must be "true" for anything to work: the deploy-level kill switch. */
  TESTER_ENABLED: string;
  /** The one origin the tester serves (for example https://idjag-tester.example.org); other host names get 404. */
  PUBLIC_ORIGIN?: string;
  /** Bearer keys for /admin: STATS (read-only), CLOSE (close or revoke only), OPEN (reopen: Mark's alone). */
  ADMIN_STATS_KEY: string;
  ADMIN_CLOSE_KEY: string;
  ADMIN_OPEN_KEY: string;
  TOKEN_LIMIT: RateLimit;
  IP_LIMIT: RateLimit;
  MCP_LIMIT: RateLimit;
}

/** What a registered client may be granted. Read-only: nothing an ID-JAG unlocks can store anything. */
export const SCOPES = ["read"] as const;

/** Per isolate: only in-process calls know it, so the admin client-creation endpoint is closed to the network. */
export const INTERNAL_KEY = crypto.randomUUID();

const sha256hex = async (s: string) => [...new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s)))].map((b) => b.toString(16).padStart(2, "0")).join("");

/** The sandbox user's email: unique per registration and subject, at a name that never receives mail. */
export const sandboxEmail = async (registrationId: string, sub: string) => `${(await sha256hex(sub)).slice(0, 32)}@${registrationId}.sandbox.invalid`;

/** Sign-in providers this deployment offers. */
export const providers = (env: Env): ("github" | "gitlab")[] => ["github" as const, ...(env.GITLAB_CLIENT_ID && env.GITLAB_CLIENT_SECRET ? ["gitlab" as const] : [])];

/** What a provider's profile becomes: the public login and the account's creation time, nothing else. */
const testerUser = (provider: "github" | "gitlab", id: unknown, login: unknown, createdAt: unknown) => ({
  email: `${provider}-${String(id).replace(/[^0-9A-Za-z_-]/g, "")}@${TESTER_EMAIL_DOMAIN}`,
  name: typeof login === "string" ? login.slice(0, 100) : "",
  image: undefined,
  emailVerified: false,
  accountCreatedAt: typeof createdAt === "string" && Number.isFinite(Date.parse(createdAt)) ? new Date(createdAt) : null,
});

/** The provider's tokens, never stored: the tester needs nothing from the provider after sign-in. */
const withoutTokens = <T extends Record<string, unknown>>(data: T): T => ({ ...data, accessToken: null, refreshToken: null, idToken: null });

export function createAuth(env: Env, origin: string) {
  const resolveSubject = async ({ ctx, sub, clientId, trustedIssuer }: ResolveSubjectInput): Promise<SubjectResolution> => {
    // Only the registration's own client, under its own trust row, and only while it is active.
    const reg = await activeByClient(env.DB, clientId, Date.now());
    if (!reg || trustedIssuer.source !== "table" || trustedIssuer.id !== reg.trustRowId) return { action: "reject" };
    const email = await sandboxEmail(reg.id, sub);
    const internal = ctx.context.internalAdapter;
    const found = await internal.findUserByEmail(email);
    if (found) return { action: "link", userId: found.user.id };
    try {
      const user = await internal.createUser({ email, name: "Test user", emailVerified: false }, { method: "idjag-tester" });
      return { action: "link", userId: user.id };
    } catch {
      // Two first uses at once: the other one created it.
      const again = await internal.findUserByEmail(email);
      if (again) return { action: "link", userId: again.user.id };
      throw new Error("sandbox user could not be created");
    }
  };

  return betterAuth({
    baseURL: origin,
    secret: env.BETTER_AUTH_SECRET,
    telemetry: { enabled: false },
    database: env.DB as never,
    advanced: { backgroundTasks, ipAddress: { ipAddressHeaders: ["cf-connecting-ip"] } },
    socialProviders: {
      github: {
        clientId: env.GITHUB_CLIENT_ID,
        clientSecret: env.GITHUB_CLIENT_SECRET,
        disableDefaultScope: true,
        scope: ["read:user"],
        mapProfileToUser: (p) => testerUser("github", p.id, p.login, (p as { created_at?: unknown }).created_at),
      },
      ...(env.GITLAB_CLIENT_ID && env.GITLAB_CLIENT_SECRET
        ? { gitlab: { clientId: env.GITLAB_CLIENT_ID, clientSecret: env.GITLAB_CLIENT_SECRET, mapProfileToUser: (p: { id: unknown; username: unknown; created_at?: unknown }) => testerUser("gitlab", p.id, p.username, p.created_at) } }
        : {}),
    },
    user: { additionalFields: { accountCreatedAt: { type: "date", required: false, input: false } } },
    databaseHooks: {
      account: {
        create: { before: async (account) => ({ data: withoutTokens(account) }) },
        update: { before: async (account) => ({ data: withoutTokens(account) }) },
      },
    },
    // A tester's session lasts a day, like a registration; then the tester's records are deleted (store.purge).
    session: { expiresIn: 86_400, disableSessionRefresh: true },
    plugins: [
      jwt({ jwks: { keyPairConfig: { alg: "ES256" } } }),
      mcp({
        // No sign-in or consent through the authorization server: clients only redeem ID-JAGs.
        loginPage: "/",
        consentPage: "/",
        resource: `${origin}/mcp`,
        allowDynamicClientRegistration: false,
        scopes: [...SCOPES],
        accessTokenExpiresIn: 300,
        clientPrivileges: ({ headers }) => headers?.get("x-tester-internal") === INTERNAL_KEY,
      }) as unknown as BetterAuthPlugin,
      idJagGrant({
        trustedIssuerTable: true,
        resolveSubject,
        fetch: guardedFetch((url, init) => fetch(url, init)),
        jwks: { timeoutMs: 3_000, maxBytes: 65_536, cacheTtlSeconds: 300, minRefetchIntervalSeconds: 60, maxStaleSeconds: 300 },
        auditLog: { retentionDays: 2 },
      }),
    ],
  });
}
