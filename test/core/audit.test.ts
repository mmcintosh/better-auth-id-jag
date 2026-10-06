import type { GenericEndpointContext } from "better-auth";
import { describe, expect, it } from "vitest";
import { AUDIT_MODEL, type AuditOptions, emit, type IdJagEvent, type RefusedEvent, sweepAudit } from "../../src/core";
import { coreHost, sharedDatabase } from "../support/core-host";

async function setup(o: { disableIpTracking?: boolean } = {}) {
  const pending = new Set<Promise<unknown>>();
  const { ctx } = await coreHost(await sharedDatabase(), {
    backgroundTasks: (p) => {
      const t = p.finally(() => pending.delete(t));
      pending.add(t);
    },
  });
  if (o.disableIpTracking) (ctx.options as { advanced?: object }).advanced = { ...(ctx.options.advanced ?? {}), ipAddress: { disableIpTracking: true } };
  const endpoint = (headers: Record<string, string> = {}) => ({ context: ctx, headers: new Headers({ "user-agent": "test-agent", "x-forwarded-for": "203.0.113.7", ...headers }) }) as unknown as GenericEndpointContext;
  const settle = async () => {
    while (pending.size) await Promise.allSettled([...pending]);
  };
  const rows = (type: string) => ctx.adapter.findMany<Record<string, unknown>>({ model: AUDIT_MODEL, where: [{ field: "type", value: type }] });
  return { ctx, endpoint, settle, rows, pending };
}

const accepted = (jti = crypto.randomUUID()) => ({ type: "id-jag.accepted" as const, iss: "https://idp.example", sub: "s", userId: "u1", clientId: "c1", scopes: ["read"], jti });

describe("audit events", () => {
  it("reach the handler and the table, with request fields, only through background tasks", async () => {
    const { endpoint, settle, rows } = await setup();
    const seen: IdJagEvent[] = [];
    // Finishes after a delay: delivered only if the host's background handler is used.
    const options: AuditOptions = {
      events: {
        onAccepted: async (e) => {
          await new Promise((r) => setTimeout(r, 20));
          seen.push(e);
        },
      },
      auditLog: { retentionDays: 30 },
    };
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
    const throwing: AuditOptions = {
      events: {
        onAccepted: () => {
          throw new Error("boom");
        },
      },
      auditLog: { retentionDays: 1 },
    };
    expect(() => emit(endpoint(), throwing, accepted(jti))).not.toThrow();
    await settle();
    ctx.logger.error = original;
    expect(errors).toHaveLength(1);
    expect((await rows("id-jag.accepted")).some((r) => r.jti === jti)).toBe(true);
  });

  it("a handler can neither delay nor alter the audit row", async () => {
    const { endpoint, rows, pending } = await setup();
    const jti = crypto.randomUUID();
    const hostile: AuditOptions = {
      events: {
        onAccepted: (e) => {
          (e as { userId: string }).userId = "someone-else";
          return new Promise(() => {}); // never settles
        },
      },
      auditLog: { retentionDays: 1 },
    };
    emit(endpoint(), hostile, accepted(jti));
    // The row is written although the handler never finishes.
    for (let i = 0; i < 50 && !(await rows("id-jag.accepted")).some((r) => r.jti === jti); i++) await new Promise((r) => setTimeout(r, 10));
    const [row] = (await rows("id-jag.accepted")).filter((r) => r.jti === jti);
    expect(row?.userId).toBe("u1");
    expect(String(row?.details)).not.toContain("someone-else");
    pending.clear();
  });

  it("only refusals after client authentication are stored, whatever clientId says", async () => {
    const { endpoint, settle, rows } = await setup();
    const seen: unknown[] = [];
    const options: AuditOptions = { events: { onRefused: (e) => void seen.push(e) }, auditLog: { retentionDays: 1 } };
    const marker = crypto.randomUUID();
    const refused = (o: Partial<RefusedEvent>) => ({ type: "id-jag.refused" as const, side: "receiver" as const, reason: "replay" as const, authenticated: false, detail: marker, ...o });
    emit(endpoint(), options, refused({ reason: "malformed_token" }));
    // A client_id the caller merely claimed (an invalid_client refusal): not stored.
    emit(endpoint(), options, refused({ reason: "public_client", clientId: "claimed-by-caller" }));
    emit(endpoint(), options, refused({ authenticated: true, clientId: "c1" }));
    await settle();
    expect(seen).toHaveLength(3);
    const stored = (await rows("id-jag.refused")).filter((r) => String(r.details).includes(marker));
    expect(stored).toHaveLength(1);
    expect(stored[0]).toMatchObject({ reason: "replay", side: "receiver", clientId: "c1" });
  });

  it("every string field a caller could have sent reaches handlers and rows log-safe", async () => {
    const { endpoint, settle, rows } = await setup();
    const seen: RefusedEvent[] = [];
    const options: AuditOptions = { events: { onRefused: (e) => void seen.push(e) }, auditLog: { retentionDays: 1 } };
    const jti = `j ${crypto.randomUUID()}`;
    emit(endpoint({ "user-agent": "agent\u0007\u0085X-Injected: 1", "x-forwarded-for": "203.0.113.9" }), options, {
      type: "id-jag.refused",
      side: "receiver",
      reason: "untrusted_issuer",
      authenticated: true,
      clientId: "c\u0000lient",
      iss: "https://evil‮.example\n[fake log line]",
      jti,
      detail: "d etail",
    });
    await settle();
    expect(seen[0]).toMatchObject({ iss: "https://evil.example[fake log line]", clientId: "client", detail: "detail", userAgent: "agentX-Injected: 1" });
    expect(seen[0]?.jti).not.toContain(" ");
    const [row] = (await rows("id-jag.refused")).filter((r) => r.clientId === "client");
    expect(row?.iss).toBe("https://evil.example[fake log line]");
  });

  it("disableIpTracking: no IP address recorded", async () => {
    const { endpoint, settle } = await setup({ disableIpTracking: true });
    const seen: IdJagEvent[] = [];
    emit(endpoint(), { events: { onAccepted: (e) => void seen.push(e) } }, accepted());
    await settle();
    expect(seen[0]?.ipAddress).toBeUndefined();
  });

  it("the retention sweep deletes expired rows only", async () => {
    const { endpoint, settle, rows, ctx } = await setup();
    const old = crypto.randomUUID();
    const live = crypto.randomUUID();
    emit(endpoint(), { auditLog: { retentionDays: 1 } }, accepted(old));
    emit(endpoint(), { auditLog: { retentionDays: 30 } }, accepted(live));
    await settle();
    await sweepAudit(ctx.adapter, new Date(Date.now() + 2 * 86_400_000));
    const left = (await rows("id-jag.accepted")).map((r) => r.jti);
    expect(left).not.toContain(old);
    expect(left).toContain(live);
  });

  it("no table, no handler: nothing runs", async () => {
    const { endpoint, settle, rows } = await setup();
    const jti = crypto.randomUUID();
    emit(endpoint(), {}, accepted(jti));
    await settle();
    expect((await rows("id-jag.accepted")).some((r) => r.jti === jti)).toBe(false);
  });
});
