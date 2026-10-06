import { describe, expect, it } from "vitest";
import { hasJti, JTI_MODEL, JTI_RETENTION_MARGIN_SECONDS, jtiExpiresAt, jtiKey, recordJti, sweepJtis } from "../../src/core";
import { coreHost, sharedDatabase } from "../support/core-host";

const record = (jti: string, o: Partial<Parameters<typeof recordJti>[1]> = {}) => ({
  side: "accepted" as const,
  jti,
  iss: "https://idp.example",
  aud: "https://as.example",
  sub: "u1",
  clientId: "c1",
  exp: Math.floor(Date.now() / 1000) + 300,
  clockSkewSeconds: 60,
  ...o,
});

describe("jti single use (S3)", () => {
  it("first record wins; the same (side, iss, jti) again is a replay", async () => {
    const { ctx } = await coreHost(await sharedDatabase());
    const jti = crypto.randomUUID();
    expect(await recordJti(ctx.adapter, record(jti))).toBe(true);
    expect(await recordJti(ctx.adapter, record(jti))).toBe(false);
    expect(await hasJti(ctx.adapter, "accepted", "https://idp.example", jti)).toBe(true);
  });

  it("the same jti from another issuer, or on the other side, is not a replay", async () => {
    const { ctx } = await coreHost(await sharedDatabase());
    const jti = crypto.randomUUID();
    expect(await recordJti(ctx.adapter, record(jti))).toBe(true);
    expect(await recordJti(ctx.adapter, record(jti, { iss: "https://other-idp.example" }))).toBe(true);
    expect(await recordJti(ctx.adapter, record(jti, { side: "issued" }))).toBe(true);
  });

  it("keys can't collide by shifting characters between iss and jti, NUL included", async () => {
    expect(await jtiKey("accepted", "https://a.example/x", "y")).not.toBe(await jtiKey("accepted", "https://a.example/", "xy"));
    expect(await jtiKey("accepted", "a\u0000b", "c")).not.toBe(await jtiKey("accepted", "a", "b\u0000c"));
  });

  it("the row outlives every moment the token is accepted: exp + skew + margin", async () => {
    const { ctx } = await coreHost(await sharedDatabase());
    const exp = Math.floor(Date.now() / 1000) + 120;
    const jti = crypto.randomUUID();
    await recordJti(ctx.adapter, record(jti, { exp, clockSkewSeconds: 60 }));
    const row = await ctx.adapter.findOne<{ expiresAt: Date }>({ model: JTI_MODEL, where: [{ field: "key", value: await jtiKey("accepted", "https://idp.example", jti) }] });
    expect(new Date(row!.expiresAt).getTime()).toBe((exp + 60 + JTI_RETENTION_MARGIN_SECONDS) * 1000);
  });

  it("10 concurrent records across two instances on one database: exactly one wins", async () => {
    const db = await sharedDatabase();
    const [a, b] = [await coreHost(db), await coreHost(db)];
    const jti = crypto.randomUUID();
    const results = await Promise.all(Array.from({ length: 10 }, (_, i) => recordJti((i % 2 ? a : b).ctx.adapter, record(jti))));
    expect(results.filter(Boolean)).toHaveLength(1);
  });

  it("the sweep removes expired rows only", async () => {
    const { ctx } = await coreHost(await sharedDatabase());
    const old = crypto.randomUUID();
    const live = crypto.randomUUID();
    const oldExp = Math.floor(Date.now() / 1000) - 10_000;
    await recordJti(ctx.adapter, record(old, { exp: oldExp }));
    await recordJti(ctx.adapter, record(live));
    // Exactly at a row's expiry it is kept (lt, not lte); a moment later it goes.
    await sweepJtis(ctx.adapter, jtiExpiresAt(oldExp, 60));
    expect(await hasJti(ctx.adapter, "accepted", "https://idp.example", old)).toBe(true);
    await sweepJtis(ctx.adapter);
    expect(await hasJti(ctx.adapter, "accepted", "https://idp.example", old)).toBe(false);
    expect(await hasJti(ctx.adapter, "accepted", "https://idp.example", live)).toBe(true);
    // A swept jti can be recorded again: harmless, its token is past exp + skew.
    expect(await recordJti(ctx.adapter, record(old, { exp: oldExp }))).toBe(true);
  });

  it("a database error that isn't a duplicate is thrown, not reported as a replay", async () => {
    const { ctx } = await coreHost(await sharedDatabase());
    const broken = { ...ctx.adapter, create: () => Promise.reject(new Error("database down")) };
    await expect(recordJti(broken, record(crypto.randomUUID()))).rejects.toThrow("database down");
    expect(JTI_MODEL).toBe("idJagJti");
  });
});

describe("adapters that can't enforce single use (D-009)", () => {
  it("warns on the memory adapter, not on a real database", async () => {
    const { warnIfReplayUnsafe } = await import("../../src/core");
    const warnings: string[] = [];
    const logger = { warn: (m: string) => void warnings.push(m) };
    warnIfReplayUnsafe({ adapter: { id: "memory" }, logger }, "idJagGrant");
    warnIfReplayUnsafe({ adapter: { id: "kysely" }, logger }, "idJagGrant");
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toMatch(/memory.*single use/);
  });

  it("both plugins call it at startup", async () => {
    const { betterAuth } = await import("better-auth");
    const { jwt } = await import("better-auth/plugins");
    const { oauthProvider } = await import("@better-auth/oauth-provider");
    const { idJagGrant, idJagIssuer } = await import("../../src");
    const warnings: string[] = [];
    const auth = betterAuth({
      baseURL: "http://localhost:3000",
      secret: "test-secret-that-is-at-least-32-characters-long",
      telemetry: { enabled: false },
      logger: { level: "warn", log: (level, message) => void (level === "warn" && warnings.push(message)) },
      plugins: [jwt(), oauthProvider({ loginPage: "/l", consentPage: "/c" }) as never, idJagIssuer({ authorize: () => ({ decision: "deny" }) }), idJagGrant({ trustedIssuers: [{ issuer: "https://idp.example", jwksUri: "https://idp.example/jwks" }] })],
    });
    await auth.$context;
    expect(warnings.filter((w) => w.includes("doesn't enforce unique keys"))).toHaveLength(2);
  });
});
