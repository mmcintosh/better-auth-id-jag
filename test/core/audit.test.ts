import type { GenericEndpointContext } from "better-auth";
import { describe, expect, it } from "vitest";
import { AUDIT_MODEL, type AuditOptions, emit, type IdJagEvent, logSafe } from "../../src/core";
import { coreHost, sharedDatabase } from "../support/core-host";

async function setup() {
  const pending = new Set<Promise<unknown>>();
  const { ctx } = await coreHost(await sharedDatabase(), {
    backgroundTasks: (p) => {
      const t = p.finally(() => pending.delete(t));
      pending.add(t);
    },
  });
  const endpoint = (headers: Record<string, string> = {}) => ({ context: ctx, headers: new Headers({ "user-agent": "test-agent", "x-forwarded-for": "203.0.113.7", ...headers }) }) as unknown as GenericEndpointContext;
  const settle = async () => {
    while (pending.size) await Promise.allSettled([...pending]);
  };
  const rows = (type: string) => ctx.adapter.findMany<Record<string, unknown>>({ model: AUDIT_MODEL, where: [{ field: "type", value: type }] });
  return { ctx, endpoint, settle, rows };
}

const accepted = (jti = crypto.randomUUID()) => ({ type: "id-jag.accepted" as const, iss: "https://idp.example", sub: "s", userId: "u1", clientId: "c1", scopes: ["read"], jti });

describe("audit events", () => {
  it("reach the handler and the table, with request fields, only through background tasks", async () => {
    const { endpoint, settle, rows } = await setup();
    const seen: IdJagEvent[] = [];
    // Finishes after a delay: delivered only if the host's background handler is used.
    const options: AuditOptions = { events: { onAccepted: async (e) => { await new Promise((r) => setTimeout(r, 20)); seen.push(e); } }, auditLog: { retentionDays: 30 } };
    const jti = crypto.randomUUID();
    emit(endpoint(), options, accepted(jti));
    await settle();
    expect(seen).toHaveLength(1);
    expect(seen[0]).toMatchObject({ type: "id-jag.accepted", userAgent: "test-agent", ipAddress: "203.0.113.7", jti });
    const [row] = (await rows("id-jag.accepted")).filter((r) => r.jti === jti);
    expect(row).toMatchObject({ userId: "u1", clientId: "c1", iss: "https://idp.example" });
    const days = ((row!.expiresAt as Date).getTime() - (row!.at as Date).getTime()) / 86_400_000;
    expect(Math.round(days)).toBe(30);
  });

  it("a handler that throws changes nothing and is logged", async () => {
    const { endpoint, settle, rows, ctx } = await setup();
    const errors: unknown[] = [];
    const original = ctx.logger.error;
    ctx.logger.error = (...a: unknown[]) => void errors.push(a);
    const jti = crypto.randomUUID();
    expect(() => emit(endpoint(), { events: { onAccepted: () => { throw new Error("boom"); } }, auditLog: { retentionDays: 1 } }, accepted(jti))).not.toThrow();
    await settle();
    ctx.logger.error = original;
    expect(errors).toHaveLength(1);
    expect((await rows("id-jag.accepted")).some((r) => r.jti === jti)).toBe(true);
  });

  it("refusals of an unauthenticated caller go to the handler, not the table", async () => {
    const { endpoint, settle, rows } = await setup();
    const seen: unknown[] = [];
    const options: AuditOptions = { events: { onRefused: (e) => void seen.push(e) }, auditLog: { retentionDays: 1 } };
    const marker = crypto.randomUUID();
    emit(endpoint(), options, { type: "id-jag.refused", side: "receiver", reason: "malformed_token", detail: marker });
    emit(endpoint(), options, { type: "id-jag.refused", side: "receiver", reason: "replay", clientId: "c1", detail: marker });
    await settle();
    expect(seen).toHaveLength(2);
    const stored = (await rows("id-jag.refused")).filter((r) => String(r.details).includes(marker));
    expect(stored).toHaveLength(1);
    expect(stored[0]).toMatchObject({ reason: "replay", side: "receiver", clientId: "c1" });
  });

  it("a refusal's detail (caller-controlled) reaches handlers log-safe", async () => {
    const { endpoint, settle } = await setup();
    const seen: { detail?: string }[] = [];
    emit(endpoint(), { events: { onRefused: (e) => void seen.push(e) } }, { type: "id-jag.refused", side: "receiver", reason: "untrusted_issuer", detail: "https://evil\u202e.example\n[fake log line]" });
    await settle();
    expect(seen[0]?.detail).toBe("https://evil.example[fake log line]");
  });

  it("no table, no handler: nothing runs", async () => {
    const { endpoint, settle, rows } = await setup();
    const jti = crypto.randomUUID();
    emit(endpoint(), {}, accepted(jti));
    await settle();
    expect((await rows("id-jag.accepted")).some((r) => r.jti === jti)).toBe(false);
  });

  it("logSafe strips control and bidi characters and caps length", () => {
    expect(logSafe("a\u0000b\nc‮d")).toBe("abcd");
    expect(logSafe("x".repeat(400))).toHaveLength(301);
  });
});
