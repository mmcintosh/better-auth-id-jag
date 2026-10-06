import { describe, expect, it } from "vitest";
import { hasJti, JTI_MODEL, jtiKey, recordJti, sweepJtis } from "../../src/core";
import { coreHost, sharedDatabase } from "../support/core-host";

const record = (jti: string, o: Partial<Parameters<typeof recordJti>[1]> = {}) => ({
  side: "accepted" as const,
  jti,
  iss: "https://idp.example",
  aud: "https://as.example",
  sub: "u1",
  clientId: "c1",
  expiresAt: new Date(Date.now() + 360_000),
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

  it("keys can't collide by shifting characters between iss and jti", async () => {
    expect(await jtiKey("accepted", "https://a.example/x", "y")).not.toBe(await jtiKey("accepted", "https://a.example/", "xy"));
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
    await recordJti(ctx.adapter, record(old, { expiresAt: new Date(Date.now() - 1000) }));
    await recordJti(ctx.adapter, record(live));
    await sweepJtis(ctx.adapter);
    expect(await hasJti(ctx.adapter, "accepted", "https://idp.example", old)).toBe(false);
    expect(await hasJti(ctx.adapter, "accepted", "https://idp.example", live)).toBe(true);
    // A swept jti can be recorded again: harmless, its token is past exp + skew.
    expect(await recordJti(ctx.adapter, record(old))).toBe(true);
  });

  it("a database error that isn't a duplicate is thrown, not reported as a replay", async () => {
    const { ctx } = await coreHost(await sharedDatabase());
    const broken = { ...ctx.adapter, create: () => Promise.reject(new Error("database down")) };
    await expect(recordJti(broken, record(crypto.randomUUID()))).rejects.toThrow("database down");
    expect(JTI_MODEL).toBe("idJagJti");
  });
});
