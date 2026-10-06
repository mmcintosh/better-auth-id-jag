// S9: the receiver's own inbound parsers (the JWKS document, the discovery document, the response
// around them) never fail with anything but a refusal, whatever an issuer's endpoint returns.
import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { IdJagRefusal } from "../../src/core";
import { JwksCache } from "../../src/receiver";
import { testIdp } from "../support/receiver-host";

const SETTINGS = { timeoutMs: 1000, maxBytes: 8 * 1024, cacheTtlMs: 0, minRefetchMs: 0 };

async function outcome(p: Promise<unknown>): Promise<string> {
  try {
    await p;
    return "ok";
  } catch (e) {
    if (e instanceof IdJagRefusal) return e.reason;
    throw e;
  }
}

describe("property: JWKS and discovery documents", () => {
  it("arbitrary bodies and statuses: a key set or jwks_unavailable, never a crash", async () => {
    const idp = await testIdp();
    const jwk = idp.key.jwk;
    const keyish = fc.oneof(
      fc.constant(jwk),
      fc.record({ kty: fc.oneof(fc.string(), fc.constant("EC"), fc.constant("RSA"), fc.constant("OKP")), kid: fc.option(fc.string(), { nil: undefined }), alg: fc.option(fc.string(), { nil: undefined }), use: fc.option(fc.string(), { nil: undefined }) }),
      fc.anything(),
    );
    const body = fc.oneof(
      fc.string(),
      fc.json(),
      fc.record({ keys: fc.array(keyish, { maxLength: 5 }) }).map((v) => JSON.stringify(v)),
      fc.record({ keys: fc.anything() }).map((v) => JSON.stringify(v)),
    );
    await fc.assert(
      fc.asyncProperty(body, fc.constantFrom(200, 200, 200, 201, 302, 404, 500), async (text, status) => {
        const fetch = async () => new Response(status === 302 ? null : text, { status, ...(status === 302 ? { headers: { location: "https://x.example" } } : {}) });
        const r = await outcome(new JwksCache(fetch, SETTINGS, () => 0).keysFor({ issuer: idp.issuer, jwksUri: idp.jwksUri }, jwk.kid as string));
        expect(["ok", "jwks_unavailable"]).toContain(r);
        if (status !== 200) expect(r).toBe("jwks_unavailable");
      }),
      { numRuns: 300 },
    );
  });

  it("arbitrary discovery documents: only an exact issuer leads to a JWKS fetch", async () => {
    const idp = await testIdp();
    const doc = fc.oneof(
      fc.json(),
      fc.record({ issuer: fc.oneof(fc.constant(idp.issuer), fc.string(), fc.webUrl()), jwks_uri: fc.oneof(fc.constant(idp.jwksUri), fc.string(), fc.webUrl()) }).map((v) => JSON.stringify(v)),
    );
    await fc.assert(
      fc.asyncProperty(doc, async (text) => {
        const fetch = async (url: string) => (url === idp.discoveryUri ? new Response(text) : url === idp.jwksUri ? Response.json({ keys: idp.published() }) : new Response("no", { status: 404 }));
        const r = await outcome(new JwksCache(fetch, SETTINGS, () => 0).keysFor({ issuer: idp.issuer, discoveryUri: idp.discoveryUri }, idp.key.kid));
        expect(["ok", "jwks_unavailable"]).toContain(r);
        if (r === "ok") {
          const parsed = JSON.parse(text) as { issuer: string; jwks_uri: string };
          expect(parsed.issuer).toBe(idp.issuer);
          expect(parsed.jwks_uri).toBe(idp.jwksUri);
        }
      }),
      { numRuns: 300 },
    );
  });
});
