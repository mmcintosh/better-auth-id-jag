// S9: the issuer's inbound parsers, fuzzed. The token-exchange form (over HTTP: never a 500, never
// a token for a mangled request), the subject-token verifier (only IdJagRefusal), and audience
// normalisation (idempotent, never adds a path).
import fc from "fast-check";
import type { GenericEndpointContext } from "better-auth";
import { describe, expect, it } from "vitest";
import { ID_JAG_TOKEN_TYPE, ID_TOKEN_TOKEN_TYPE, IdJagRefusal, TOKEN_EXCHANGE_GRANT } from "../../src/core";
import { normalizeAudience, verifyOwnIdToken } from "../../src/issuer";
import { AUDIENCE, createIssuerHost, exchange, ISSUER, setup } from "../support/issuer-host";

describe("fuzz: audience normalisation", () => {
  it("is idempotent, keeps the path as sent, and only accepts https (or loopback http when allowed)", () => {
    fc.assert(
      fc.property(fc.oneof(fc.webUrl({ withFragments: true, withQueryParameters: true }), fc.string({ maxLength: 80 })), (s) => {
        const n = normalizeAudience(s);
        if (!n.ok) return;
        expect(n.audience.startsWith("https://")).toBe(true);
        const again = normalizeAudience(n.audience);
        expect(again).toEqual({ ok: true, audience: n.audience });
        expect(n.audience).not.toMatch(/[#?]/);
      }),
      { numRuns: 2000 },
    );
  });
});

describe("fuzz: the subject-token verifier", () => {
  it("refuses garbage with IdJagRefusal only", async () => {
    const host = await createIssuerHost({ issuer: { authorize: () => ({ decision: "deny" }) } });
    const ctx = { context: host.ctx } as unknown as GenericEndpointContext;
    const segment = fc.oneof(fc.base64String({ maxLength: 60 }), fc.json().map((j) => btoa(j).replace(/=+$/, "")), fc.string({ maxLength: 20 }));
    await fc.assert(
      fc.asyncProperty(fc.oneof(fc.string({ maxLength: 200 }), fc.tuple(segment, segment, segment).map((p) => p.join("."))), async (token) => {
        try {
          await verifyOwnIdToken(ctx, token, { issuer: ISSUER, clientId: "c", jwtOptions: undefined, now: Math.floor(Date.now() / 1000) });
          throw new Error("accepted");
        } catch (e) {
          expect(e).toBeInstanceOf(IdJagRefusal);
        }
      }),
      { numRuns: 500 },
    );
  });
});

describe("fuzz: the token-exchange form", () => {
  it("one mangled parameter of a valid request: a 4xx RFC 6749 error or (for harmless changes) an ID-JAG, never a 500", async () => {
    const host = await createIssuerHost({ issuer: { authorize: () => ({ decision: "allow", scopes: ["read"] }) } });
    const { client, idToken } = await setup(host);
    const names = ["requested_token_type", "subject_token", "subject_token_type", "audience", "scope", "resource", "actor_token", "client_id", "extra"];
    const value = fc.oneof(fc.string({ maxLength: 40 }), fc.constantFrom("", ID_JAG_TOKEN_TYPE, ID_TOKEN_TOKEN_TYPE, TOKEN_EXCHANGE_GRANT, AUDIENCE, `${AUDIENCE}#x`, "https://a", "\u0000", "%00", idToken.slice(0, 40)));
    await fc.assert(
      fc.asyncProperty(fc.constantFrom(...names), fc.oneof(value, fc.array(value, { minLength: 2, maxLength: 3 })), async (name, v) => {
        const r = await exchange(host, client, idToken, { [name]: v });
        expect(r.status, JSON.stringify([name, v, r.body])).toBeLessThan(500);
        if (r.status === 200) expect(r.body.issued_token_type).toBe(ID_JAG_TOKEN_TYPE);
        else expect(typeof r.body.error).toBe("string");
      }),
      { numRuns: 60 },
    );
  });
});
