import { describe, expect, it } from "vitest";
import { IdJagRefusal, publicDescription, REASONS, type ReasonCode, toApiError } from "../../src/core";

describe("refusals (S8)", () => {
  it("become RFC 6749 bodies: 401 for invalid_client, 400 otherwise", () => {
    const client = toApiError(new IdJagRefusal("public_client"));
    expect(client.statusCode).toBe(401);
    expect(client.body).toMatchObject({ error: "invalid_client" });
    const grant = toApiError(new IdJagRefusal("expired"));
    expect(grant.statusCode).toBe(400);
    expect(grant.body).toEqual({ error: "invalid_grant", error_description: "The assertion has expired." });
  });

  it("the reasons a caller could probe with all look the same from outside", () => {
    const probe: ReasonCode[] = ["untrusted_issuer", "bad_signature", "wrong_audience", "client_mismatch", "replay", "unknown_subject", "subject_rejected", "banned_user", "jwks_unavailable", "policy_denied", "no_policy", "invalid_subject_token"];
    const bodies = new Set(probe.map((r) => JSON.stringify(toApiError(new IdJagRefusal(r, "secret detail")).body)));
    expect([...bodies]).toEqual([JSON.stringify({ error: "invalid_grant", error_description: "The grant is invalid." })]);
  });

  it("no description carries the detail; a non-public reason shows only its error code's generic text", () => {
    const generic = new Set<string>();
    for (const reason of Object.keys(REASONS) as ReasonCode[]) if (!REASONS[reason].public) generic.add(publicDescription(reason));
    for (const reason of Object.keys(REASONS) as ReasonCode[]) {
      const body = toApiError(new IdJagRefusal(reason, "DETAIL-123")).body as { error_description: string };
      expect(JSON.stringify(body)).not.toContain("DETAIL-123");
      if (!REASONS[reason].public) expect(generic.has(body.error_description), reason).toBe(true);
      expect(publicDescription(reason).length).toBeGreaterThan(0);
    }
    // One generic text per error code, no more.
    expect(generic.size).toBeLessThanOrEqual(new Set(Object.values(REASONS).map((r) => r.error)).size);
  });
});
