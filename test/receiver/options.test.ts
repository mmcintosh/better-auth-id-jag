// Options validated at startup; the plain-function export composed by a host; the audit table and
// the opportunistic sweeps.
import { betterAuth, type BetterAuthPlugin } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import { jwt } from "better-auth/plugins";
import { extendOAuthProvider, oauthProvider } from "@better-auth/oauth-provider";
import { describe, expect, it } from "vitest";
import { AUDIT_MODEL, hasJti, JWT_BEARER_GRANT, jtiSchema, recordJti } from "../../src/core";
import { handleIdJagGrant, idJagGrant, type IdJagGrantOptions, resolveReceiverOptions } from "../../src/receiver";
import { BASE, createClient, database, linkedUser, MCP_RESOURCE, network, type ReceiverHost, receiverHost, recorder, redeem, testIdp } from "../support/receiver-host";

const TRUST = [{ issuer: "https://idp.example", jwksUri: "https://idp.example/jwks" }];

describe("options are validated when the plugin is built", () => {
  const bad: [string, unknown][] = [
    ["an unknown key", { trustedIssuers: TRUST, trustedIssuer: TRUST }],
    ["an http jwksUri", { trustedIssuers: [{ issuer: "https://idp.example", jwksUri: "http://idp.example/jwks" }] }],
    ["neither jwksUri nor discoveryUri", { trustedIssuers: [{ issuer: "https://idp.example" }] }],
    ["a jwksUri with credentials", { trustedIssuers: [{ issuer: "https://idp.example", jwksUri: "https://u:p@idp.example/jwks" }] }],
    ["an unknown trusted-issuer key", { trustedIssuers: [{ ...TRUST[0], emailFallback: true }] }],
    ["the same issuer twice", { trustedIssuers: [TRUST[0], TRUST[0]] }],
    ["NaN clock skew", { clockSkewSeconds: Number.NaN }],
    ["a skew over 300 s", { clockSkewSeconds: 301 }],
    ["a lifetime over 900 s", { maxLifetimeSeconds: 901 }],
    ["a tiny JWKS size cap", { jwks: { maxBytes: 10 } }],
    ["fetch that isn't a function", { fetch: "https://proxy.example" }],
    ["a non-boolean allowPublicClients", { allowPublicClients: "yes" }],
    ["an audit retention of 0 days", { auditLog: { retentionDays: 0 } }],
    ["a non-boolean requireResourceClaim", { requireResourceClaim: 1 }],
    ["an empty jitRole", { trustedIssuers: [{ ...TRUST[0], organizationId: "org", jitRole: "" }] }],
    ["a jitRole without organizationId", { trustedIssuers: [{ ...TRUST[0], jitRole: "admin" }] }],
  ];
  for (const [what, options] of bad) {
    it(`refuses ${what}`, () => {
      expect(() => idJagGrant(options as IdJagGrantOptions)).toThrow(/id-jag/);
    });
  }

  it("accepts a complete, valid configuration", () => {
    expect(() =>
      idJagGrant({
        trustedIssuers: [{ issuer: "https://idp.example", discoveryUri: "https://idp.example/.well-known/openid-configuration", allowedClientIds: ["c"], emailFallback: { domains: ["corp.example"] }, jitProvisioning: { trustEmailVerified: false }, tenant: "t", organizationId: "org", jitRole: "admin" }],
        sso: { emailFallback: true, providerIds: ["okta"] },
        trustedIssuerTable: true,
        requireResourceClaim: true,
        clockSkewSeconds: 30,
        maxLifetimeSeconds: 300,
        jwks: { timeoutMs: 2000, maxBytes: 32768, cacheTtlSeconds: 300, minRefetchIntervalSeconds: 60 },
        auditLog: { retentionDays: 30 },
        events: { onRefused: () => {} },
      }),
    ).not.toThrow();
  });

  it("a defaultResource that isn't registered fails at startup", async () => {
    const auth = betterAuth({
      baseURL: BASE,
      secret: "test-secret-that-is-at-least-32-characters-long",
      telemetry: { enabled: false },
      database: (await database()) as never,
      plugins: [jwt(), oauthProvider({ loginPage: "/l", consentPage: "/c", resources: [MCP_RESOURCE] }) as unknown as BetterAuthPlugin, idJagGrant({ trustedIssuers: TRUST, defaultResource: "https://nope.example" })],
    });
    await expect(auth.$context).rejects.toThrow(/defaultResource/);
  });
});

describe("handleIdJagGrant as a plain function", () => {
  it("a host can register it in its own extension", async () => {
    const idp = await testIdp();
    const resolved = resolveReceiverOptions({ trustedIssuers: [{ issuer: idp.issuer, jwksUri: idp.jwksUri }], fetch: network(idp).fetch });
    let calls = 0;
    const composed: BetterAuthPlugin = {
      id: "host-composed-grant",
      schema: jtiSchema(),
      init(ctx) {
        extendOAuthProvider(ctx, {
          grants: {
            [JWT_BEARER_GRANT]: (input) => {
              calls++;
              return handleIdJagGrant(input, resolved);
            },
          },
        });
      },
    };
    const auth = betterAuth({
      baseURL: BASE,
      secret: "test-secret-that-is-at-least-32-characters-long",
      telemetry: { enabled: false },
      database: (await database()) as never,
      emailAndPassword: { enabled: true },
      plugins: [jwt(), oauthProvider({ loginPage: "/l", consentPage: "/c", scopes: ["read"], resources: [MCP_RESOURCE], clientRegistrationDefaultResources: [MCP_RESOURCE] }) as unknown as BetterAuthPlugin, composed],
    });
    const ctx = await auth.$context;
    await (await getMigrations(ctx.options)).runMigrations();
    const h = { auth, ctx } as unknown as ReceiverHost;
    const client = await createClient(h, { scope: "read" });
    const sub = crypto.randomUUID();
    await linkedUser(h, `id-jag:${idp.issuer}`, sub);
    const r = await redeem(h, client, await idp.mint(idp.claims({ sub, client_id: client.client_id })));
    expect(r.status, r.text).toBe(200);
    expect(calls).toBe(1);
  });
});

describe("handleIdJagGrant: our own public-client guard (S5), behind the provider's", () => {
  it("a client the provider let through as public (method none) is refused, unauthenticated, and nothing else runs", async () => {
    const h = await receiverHost("mcp", { receiver: {} });
    const refused: { reason: string; authenticated: boolean }[] = [];
    const resolved = resolveReceiverOptions({ trustedIssuers: TRUST, events: { onRefused: (e) => void refused.push(e) } });
    let issued = false;
    const fake = (method: string | undefined, discovered = false) => ({
      ctx: { context: { ...h.ctx, runInBackground: (p: Promise<unknown>) => void p }, body: { assertion: "x" }, headers: new Headers() },
      opts: { scopes: ["read"], resources: [MCP_RESOURCE] },
      grantType: JWT_BEARER_GRANT,
      provider: {
        authenticateClient: async () => ({ clientId: "c", method, client: { clientId: "c", tokenEndpointAuthMethod: method, ...(discovered ? { clientDiscoveryId: "cimd" } : {}) } }),
        issueTokens: async () => {
          issued = true;
          return {};
        },
      },
    });
    for (const [method, discovered] of [["none", false], [undefined, false], ["client_secret_post", true]] as const) {
      const outcome = await handleIdJagGrant(fake(method, discovered) as never, resolved).then(
        () => "accepted",
        (e: { body?: { error?: string } }) => e.body?.error,
      );
      expect(outcome).toBe("invalid_client");
      expect(refused.at(-1)).toMatchObject({ reason: "public_client", authenticated: false });
    }
    expect(issued).toBe(false);
  });
});

describe("audit table and sweeps", () => {
  async function host(receiver: Partial<IdJagGrantOptions>) {
    const idp = await testIdp();
    const rec = recorder();
    const h = await receiverHost("mcp", { receiver: { trustedIssuers: [{ issuer: idp.issuer, jwksUri: idp.jwksUri }], fetch: network(idp).fetch, ...receiver }, recorder: rec });
    const client = await createClient(h);
    return { idp, rec, h, client };
  }

  it("accepted and authenticated refusals are stored; unauthenticated ones aren't", async () => {
    const s = await host({ auditLog: { retentionDays: 7 } });
    const sub = crypto.randomUUID();
    await linkedUser(s.h, `id-jag:${s.idp.issuer}`, sub);
    const jti = crypto.randomUUID();
    expect((await redeem(s.h, s.client, await s.idp.mint(s.idp.claims({ sub, jti, client_id: s.client.client_id })))).status).toBe(200);
    const marker = crypto.randomUUID();
    await redeem(s.h, s.client, await s.idp.mint(s.idp.claims({ sub: marker, client_id: s.client.client_id })));
    await s.rec.settle();
    const rows = await s.h.ctx.adapter.findMany<Record<string, unknown>>({ model: AUDIT_MODEL, where: [{ field: "clientId", value: s.client.client_id }] });
    expect(rows.find((r) => r.type === "id-jag.accepted" && r.jti === jti)).toBeDefined();
    expect(rows.find((r) => r.type === "id-jag.refused" && String(r.details).includes(marker))).toMatchObject({ reason: "unknown_subject", side: "receiver" });
  });

  it("expired jti rows are swept opportunistically, at most once a minute per instance", async () => {
    let t = Date.now();
    const s = await host({ clock: () => new Date(t) });
    const stale = crypto.randomUUID();
    await recordJti(s.h.ctx.adapter, { side: "accepted", jti: stale, iss: s.idp.issuer, aud: "a", sub: "s", clientId: "c", exp: Math.floor(t / 1000) - 10_000, clockSkewSeconds: 60 });
    await redeem(s.h, s.client, "x");
    await s.rec.settle();
    expect(await hasJti(s.h.ctx.adapter, "accepted", s.idp.issuer, stale)).toBe(false);
    // A second stale row within the minute survives until the next sweep.
    const second = crypto.randomUUID();
    await recordJti(s.h.ctx.adapter, { side: "accepted", jti: second, iss: s.idp.issuer, aud: "a", sub: "s", clientId: "c", exp: Math.floor(t / 1000) - 10_000, clockSkewSeconds: 60 });
    await redeem(s.h, s.client, "x");
    await s.rec.settle();
    expect(await hasJti(s.h.ctx.adapter, "accepted", s.idp.issuer, second)).toBe(true);
    t += 60_000;
    await redeem(s.h, s.client, "x");
    await s.rec.settle();
    expect(await hasJti(s.h.ctx.adapter, "accepted", s.idp.issuer, second)).toBe(false);
  });

  it("expired audit rows are swept with them", async () => {
    let t = Date.now();
    const s = await host({ clock: () => new Date(t), auditLog: { retentionDays: 1 } });
    await redeem(s.h, s.client, "garbage");
    await s.rec.settle();
    const reasons = async () => (await s.h.ctx.adapter.findMany<Record<string, unknown>>({ model: AUDIT_MODEL, where: [{ field: "clientId", value: s.client.client_id }] })).map((r) => r.reason);
    expect(await reasons()).toEqual(["malformed_token"]);
    t += 2 * 86_400_000;
    await redeem(s.h, s.client, undefined);
    await s.rec.settle();
    // The first row is past retention and swept.
    expect(await reasons()).not.toContain("malformed_token");
  });
});
