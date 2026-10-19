import { describe, expect, it } from "vitest";
import { IdJagRefusal, logSafe, publicDescription, REASONS, type ReasonCode, toApiError } from "../../src/core";

const ALL = Object.keys(REASONS) as ReasonCode[];
const NON_PUBLIC = ALL.filter((r) => !REASONS[r].public);

describe("refusals (S8)", () => {
  it("become RFC 6749 bodies: 401 with a Basic challenge for invalid_client, 400 otherwise", () => {
    const client = toApiError(new IdJagRefusal("public_client"));
    expect(client.statusCode).toBe(401);
    expect(client.body).toMatchObject({ error: "invalid_client" });
    expect(new Headers(client.headers as HeadersInit).get("www-authenticate")).toMatch(/^Basic /);
    const grant = toApiError(new IdJagRefusal("expired"));
    expect(grant.statusCode).toBe(400);
    expect(grant.body).toEqual({ error: "invalid_grant", error_description: "The assertion has expired." });
  });

  it("exactly these reasons are public: the caller sent the defect, so naming it reveals nothing", () => {
    // Changing this list is a security decision (S8): make it here, on purpose. step_up_required is the exception:
    // only the host's authorize hook produces it, by choosing to tell the caller (D-043).
    expect(ALL.filter((r) => REASONS[r].public).sort()).toEqual(
      ["actor_token_unsupported", "disallowed_alg", "expired", "invalid_audience", "invalid_claim", "lifetime_too_long", "malformed_token", "missing_claim", "missing_kid", "missing_parameter", "not_yet_valid", "scope_required", "step_up_required", "subject_token_expired", "unsupported_claim", "unsupported_parameter", "unsupported_requested_token_type", "unsupported_subject_token_type", "wrong_typ"].sort(),
    );
  });

  it("every non-public reason with the same error code has the same body (no hand-picked list)", () => {
    const byCode = new Map<string, Set<string>>();
    for (const r of NON_PUBLIC) {
      const e = toApiError(new IdJagRefusal(r, "secret detail"));
      const key = `${e.statusCode} ${REASONS[r].error}`;
      byCode.set(key, (byCode.get(key) ?? new Set()).add(JSON.stringify(e.body)));
    }
    for (const [code, bodies] of byCode) expect(bodies.size, code).toBe(1);
  });

  it("the reasons that depend on trust, keys or users all share invalid_grant's generic body", () => {
    // A caller must not tell these apart by error code either: a different code is a different answer.
    const trustDependent: ReasonCode[] = ["untrusted_issuer", "self_issued", "bad_signature", "jwks_unavailable", "wrong_audience", "client_mismatch", "replay", "unknown_subject", "subject_rejected", "banned_user", "invalid_subject_token", "policy_denied", "blocked", "no_policy"];
    const bodies = new Set(trustDependent.map((r) => JSON.stringify(toApiError(new IdJagRefusal(r)).body)));
    expect([...bodies]).toEqual([JSON.stringify({ error: "invalid_grant", error_description: "The grant is invalid." })]);
  });

  it("no description carries the detail; a non-public reason shows only its code's generic text", () => {
    const generic = new Set(NON_PUBLIC.map(publicDescription));
    for (const reason of ALL) {
      const body = toApiError(new IdJagRefusal(reason, "DETAIL-123")).body as { error_description: string };
      expect(JSON.stringify(body)).not.toContain("DETAIL-123");
      if (!REASONS[reason].public) expect(generic.has(body.error_description), reason).toBe(true);
    }
    expect(generic.size).toBeLessThanOrEqual(new Set(Object.values(REASONS).map((r) => r.error)).size);
  });

  it("step-up (D-043): insufficient_user_authentication with the challenge's parameters, never the detail", () => {
    const full = toApiError(new IdJagRefusal("step_up_required", "DETAIL-123", { maxAge: 300, acrValues: ["phr", "urn:example:mfa"], description: "Confirm it's you, then try again.", uri: "https://idp.example/confirm" }));
    expect(full.statusCode).toBe(400);
    expect(full.body).toEqual({ error: "insufficient_user_authentication", error_description: "Confirm it's you, then try again.", error_uri: "https://idp.example/confirm", max_age: 300, acr_values: "phr urn:example:mfa" });
    expect(toApiError(new IdJagRefusal("step_up_required")).body).toEqual({ error: "insufficient_user_authentication", error_description: "The subject does not meet the authentication requirements." });
    expect(toApiError(new IdJagRefusal("step_up_required", undefined, { maxAge: 0 })).body).toMatchObject({ max_age: 0 });
    // A challenge on any other reason is never sent.
    expect(toApiError(new IdJagRefusal("policy_denied", undefined, { description: "leak", uri: "https://x.example/" })).body).toEqual({ error: "invalid_grant", error_description: "The grant is invalid." });
  });

  it("a refusal's detail and message are log-safe and capped (they may quote the caller)", () => {
    const r = new IdJagRefusal("wrong_typ", "x\n".repeat(3000));
    expect(r.detail).toHaveLength(301);
    expect(r.message.length).toBeLessThan(400);
    expect(r.message).not.toContain("\n");
  });
});

describe("logSafe", () => {
  it("strips C0/C1 controls, line separators, bidi and invisible formatting characters", () => {
    expect(logSafe("a\u0000b\nc‮d e f؜g​h﻿i")).toBe("abcdefghi");
  });

  it("caps at exactly max characters, plus an ellipsis", () => {
    expect(logSafe("x".repeat(300))).toBe("x".repeat(300));
    expect(logSafe("x".repeat(301))).toBe(`${"x".repeat(300)}…`);
  });

  it("counts and cuts in code points: never half a surrogate pair", () => {
    expect(logSafe("🤖".repeat(300))).toBe("🤖".repeat(300));
    expect(logSafe("🤖".repeat(301))).toBe(`${"🤖".repeat(300)}…`);
    expect(logSafe(`a${"🤖".repeat(3)}`, 3)).toBe("a🤖🤖…");
  });

  it("turns a lone surrogate into U+FFFD, keeping pairs", () => {
    expect(logSafe("a\ud800b\udc00c")).toBe("a\ufffdb\ufffdc");
    expect(logSafe("\udc00\ud800")).toBe("\ufffd\ufffd");
    expect(logSafe("x\ud83e\udd16")).toBe("x🤖");
  });
});
