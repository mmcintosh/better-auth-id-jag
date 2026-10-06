// S4 and S10: a trusted issuer's keys, fetched under the network rules, cached by kid, refetched on
// an unknown kid at most once per interval. Unit tests on JwksCache, then through a host.
import { afterEach, describe, expect, it, vi } from "vitest";
import { IdJagRefusal } from "../../src/core";
import { JwksCache, type JwksSettings } from "../../src/receiver";
import { createClient, linkedUser, network, receiverHost, recorder, redeem, testIdp } from "../support/receiver-host";

const SETTINGS: JwksSettings = { timeoutMs: 200, maxBytes: 64 * 1024, cacheTtlMs: 600_000, minRefetchMs: 60_000 };

async function reasonOf(p: Promise<unknown>): Promise<string> {
  try {
    await p;
    return "ok";
  } catch (e) {
    if (e instanceof IdJagRefusal) return `${e.reason}${e.detail ? `: ${e.detail}` : ""}`;
    throw e;
  }
}

function clock(start = 1_800_000_000_000) {
  let t = start;
  return {
    now: () => t,
    advance: (ms: number) => {
      t += ms;
    },
  };
}

describe("JwksCache: network rules (S10)", () => {
  it("fetches with redirect: manual, a timeout signal, and accept: application/json", async () => {
    const idp = await testIdp();
    const net = network(idp);
    const cache = new JwksCache(net.fetch, SETTINGS, clock().now);
    expect(await reasonOf(cache.keysFor({ issuer: idp.issuer, jwksUri: idp.jwksUri }, idp.key.kid))).toBe("ok");
    const init = net.calls[0]!.init;
    expect(init.redirect).toBe("manual");
    expect(init.signal).toBeInstanceOf(AbortSignal);
    expect(new Headers(init.headers).get("accept")).toBe("application/json");
  });

  it("https only, no credentials in the URL", async () => {
    const net = network();
    const cache = new JwksCache(net.fetch, SETTINGS, clock().now);
    expect(await reasonOf(cache.keysFor({ issuer: "https://idp.example", jwksUri: "http://idp.example/jwks" }, "k"))).toBe("jwks_unavailable: jwks: not https");
    expect(await reasonOf(cache.keysFor({ issuer: "https://idp2.example", jwksUri: "https://u:p@idp2.example/jwks" }, "k"))).toMatch(/credentials/);
    expect(await reasonOf(cache.keysFor({ issuer: "https://idp3.example", jwksUri: "not a url" }, "k"))).toMatch(/not a URL/);
    expect(net.calls).toHaveLength(0);
  });

  it("any redirect is a failure: 3xx on Node, opaque redirect on workerd", async () => {
    const idp = await testIdp();
    const cache = () => new JwksCache(network(idp).fetch, SETTINGS, clock().now);
    for (const status of [301, 302, 303, 307, 308]) {
      idp.override = () => new Response(null, { status, headers: { location: "https://internal.example/jwks" } });
      expect(await reasonOf(cache().keysFor(idp, idp.key.kid))).toBe("jwks_unavailable: jwks: redirect refused");
    }
    idp.override = () => ({ type: "opaqueredirect", status: 0, headers: new Headers(), body: null }) as unknown as Response;
    expect(await reasonOf(cache().keysFor(idp, idp.key.kid))).toBe("jwks_unavailable: jwks: redirect refused");
  });

  it("non-200, not JSON, invalid JWKS, empty JWKS (S1: not 'trust nothing'), only encryption keys", async () => {
    const idp = await testIdp();
    const cases: [() => Response, RegExp][] = [
      [() => new Response("x", { status: 500 }), /HTTP 500/],
      [() => new Response("{}", { status: 201 }), /HTTP 201/],
      [() => new Response("{not json"), /not JSON/],
      [() => Response.json({ nokeys: [] }), /JWKS document invalid/],
      [() => Response.json({ keys: [] }), /no signing keys/],
      [() => Response.json({ keys: [{ ...idp.key.jwk, use: "enc" }] }), /no signing keys/],
      [() => Response.json({ keys: Array.from({ length: 101 }, () => idp.key.jwk) }), /JWKS document invalid/],
    ];
    for (const [answer, why] of cases) {
      idp.override = answer;
      expect(await reasonOf(new JwksCache(network(idp).fetch, SETTINGS, clock().now).keysFor(idp, idp.key.kid))).toMatch(why);
    }
  });

  it("size cap: a declared or an undeclared body over the cap is refused", async () => {
    const idp = await testIdp();
    const big = JSON.stringify({ keys: [idp.key.jwk], pad: "x".repeat(70 * 1024) });
    idp.override = () => new Response(big, { headers: { "content-length": String(big.length) } });
    expect(await reasonOf(new JwksCache(network(idp).fetch, SETTINGS, clock().now).keysFor(idp, idp.key.kid))).toBe("jwks_unavailable: jwks: too large");
    // No content-length: streamed, and cut off at the cap.
    idp.override = () =>
      new Response(
        new ReadableStream({
          start(c) {
            for (let i = 0; i < 80; i++) c.enqueue(new TextEncoder().encode("x".repeat(1024)));
            c.close();
          },
        }),
      );
    expect(await reasonOf(new JwksCache(network(idp).fetch, SETTINGS, clock().now).keysFor(idp, idp.key.kid))).toBe("jwks_unavailable: jwks: too large");
    // Just under the cap is fine.
    const ok = JSON.stringify({ keys: [idp.key.jwk] });
    idp.override = () => new Response(ok.padEnd(SETTINGS.maxBytes, " "));
    expect(await reasonOf(new JwksCache(network(idp).fetch, SETTINGS, clock().now).keysFor(idp, idp.key.kid))).toBe("ok");
  });

  it("timeout: a fetch that hangs is aborted; one that ignores the signal still loses the race", async () => {
    const idp = await testIdp();
    let aborted = false;
    idp.override = (_url, init) =>
      new Promise<Response>((_, reject) => {
        init.signal?.addEventListener("abort", () => {
          aborted = true;
          reject(new Error("aborted"));
        });
      });
    const started = Date.now();
    expect(await reasonOf(new JwksCache(network(idp).fetch, SETTINGS, clock().now).keysFor(idp, idp.key.kid))).toMatch(/^jwks_unavailable: jwks: /);
    expect(aborted).toBe(true);
    idp.override = () => new Promise<Response>(() => {});
    expect(await reasonOf(new JwksCache(network(idp).fetch, SETTINGS, clock().now).keysFor(idp, idp.key.kid))).toBe("jwks_unavailable: jwks: timeout");
    expect(Date.now() - started).toBeLessThan(5_000);
  });

  it("discovery: the document's issuer must match exactly; its jwks_uri must be https", async () => {
    const idp = await testIdp();
    const source = { issuer: idp.issuer, discoveryUri: idp.discoveryUri };
    const net = network(idp);
    expect(await reasonOf(new JwksCache(net.fetch, SETTINGS, clock().now).keysFor(source, idp.key.kid))).toBe("ok");
    expect(net.urls()).toEqual([idp.discoveryUri, idp.jwksUri]);
    for (const doc of [{ issuer: `${idp.issuer}/`, jwks_uri: idp.jwksUri }, { issuer: "https://evil.example", jwks_uri: idp.jwksUri }]) {
      idp.override = (url) => (url === idp.discoveryUri ? Response.json(doc) : Response.json({ keys: idp.published() }));
      expect(await reasonOf(new JwksCache(network(idp).fetch, SETTINGS, clock().now).keysFor(source, idp.key.kid))).toBe("jwks_unavailable: discovery issuer mismatch");
    }
    idp.override = (url) => (url === idp.discoveryUri ? Response.json({ issuer: idp.issuer, jwks_uri: "http://plain.example/jwks" }) : Response.json({ keys: idp.published() }));
    expect(await reasonOf(new JwksCache(network(idp).fetch, SETTINGS, clock().now).keysFor(source, idp.key.kid))).toBe("jwks_unavailable: jwks: not https");
  });
});

describe("JwksCache: caching and refetch (S4)", () => {
  it("cached by kid: a known kid needs no second fetch", async () => {
    const idp = await testIdp();
    const net = network(idp);
    const c = clock();
    const cache = new JwksCache(net.fetch, SETTINGS, c.now);
    await cache.keysFor(idp, idp.key.kid);
    await cache.keysFor(idp, idp.key.kid);
    c.advance(10 * 60_000 - 1);
    await cache.keysFor(idp, idp.key.kid);
    expect(net.calls).toHaveLength(1);
    // Past the TTL: refetched.
    c.advance(1);
    await cache.keysFor(idp, idp.key.kid);
    expect(net.calls).toHaveLength(2);
  });

  it("rotation: a new kid causes one refetch; an unknown kid at most one refetch per interval", async () => {
    const idp = await testIdp();
    const net = network(idp);
    const c = clock();
    const cache = new JwksCache(net.fetch, SETTINGS, c.now);
    await cache.keysFor(idp, idp.key.kid);
    c.advance(60_000);
    const fresh = await idp.rotate();
    await cache.keysFor(idp, fresh.kid);
    expect(net.calls).toHaveLength(2);
    // An attacker's made-up kids: no fetch until the interval has passed, however many.
    for (let i = 0; i < 20; i++) await cache.keysFor(idp, `made-up-${i}`);
    expect(net.calls).toHaveLength(2);
    c.advance(59_999);
    await cache.keysFor(idp, "made-up");
    expect(net.calls).toHaveLength(2);
    c.advance(1);
    await cache.keysFor(idp, "made-up");
    expect(net.calls).toHaveLength(3);
  });

  it("a failed fetch counts toward the interval: no hammering an issuer that's down", async () => {
    const idp = await testIdp();
    const net = network(idp);
    const c = clock();
    const cache = new JwksCache(net.fetch, SETTINGS, c.now);
    idp.override = () => new Response("down", { status: 503 });
    expect(await reasonOf(cache.keysFor(idp, idp.key.kid))).toMatch(/HTTP 503/);
    idp.override = undefined;
    expect(await reasonOf(cache.keysFor(idp, idp.key.kid))).toBe("jwks_unavailable: no keys (a recent fetch failed)");
    expect(net.calls).toHaveLength(1);
    c.advance(60_000);
    expect(await reasonOf(cache.keysFor(idp, idp.key.kid))).toBe("ok");
    expect(net.calls).toHaveLength(2);
  });

  it("concurrent lookups share one fetch", async () => {
    const idp = await testIdp();
    const net = network(idp);
    const cache = new JwksCache(net.fetch, SETTINGS, clock().now);
    await Promise.all(Array.from({ length: 10 }, () => cache.keysFor(idp, idp.key.kid)));
    expect(net.calls).toHaveLength(1);
  });

  it("issuers are cached separately", async () => {
    const [a, b] = [await testIdp(), await testIdp()];
    const net = network(a, b);
    const cache = new JwksCache(net.fetch, SETTINGS, clock().now);
    await cache.keysFor(a, a.key.kid);
    await cache.keysFor(b, b.key.kid);
    // b's kid is not a's: a's entry is not satisfied by b's keys, and vice versa.
    expect(net.urls()).toEqual([a.jwksUri, b.jwksUri]);
  });
});

describe("through the grant", () => {
  afterEach(() => vi.unstubAllGlobals());

  async function host(o: { now?: () => Date } = {}) {
    const idp = await testIdp();
    const net = network(idp);
    const rec = recorder();
    const h = await receiverHost("mcp", { receiver: { trustedIssuers: [{ issuer: idp.issuer, jwksUri: idp.jwksUri }], fetch: net.fetch, ...(o.now ? { clock: o.now } : {}) }, recorder: rec });
    const client = await createClient(h);
    const sub = crypto.randomUUID();
    await linkedUser(h, `id-jag:${idp.issuer}`, sub);
    const mint = (over: Record<string, unknown> = {}, key = idp.key) => idp.mint(idp.claims({ sub, client_id: client.client_id, ...over }), {}, key);
    return { idp, net, rec, h, client, mint };
  }

  it("S10: the global fetch is never used; only the trusted issuer's JWKS is fetched", async () => {
    const s = await host();
    const globalFetch = vi.fn(() => Promise.reject(new Error("global fetch used")));
    vi.stubGlobal("fetch", globalFetch);
    expect((await redeem(s.h, s.client, await s.mint())).status).toBe(200);
    const stranger = await testIdp();
    await redeem(s.h, s.client, await stranger.mint(stranger.claims({ client_id: s.client.client_id })));
    expect(globalFetch).not.toHaveBeenCalled();
    expect(s.net.urls()).toEqual([s.idp.jwksUri]);
  });

  it("key rotation at the IdP: the next ID-JAG with the new kid is accepted after one refetch", async () => {
    let t = Date.now();
    const s = await host({ now: () => new Date(t) });
    expect((await redeem(s.h, s.client, await s.mint())).status).toBe(200);
    t += 61_000;
    const fresh = await s.idp.rotate();
    const r = await redeem(s.h, s.client, await s.mint({ iat: Math.floor(t / 1000), exp: Math.floor(t / 1000) + 300 }, fresh));
    expect(r.status, r.text).toBe(200);
    expect(s.net.calls).toHaveLength(2);
  });

  it("refetch rate limit: unknown kids within a minute cause no fetch and fail as bad_signature", async () => {
    const s = await host();
    expect((await redeem(s.h, s.client, await s.mint())).status).toBe(200);
    const fresh = await s.idp.rotate();
    // Rotated less than a minute after the last fetch: the new kid isn't fetched yet.
    for (let i = 0; i < 3; i++) await redeem(s.h, s.client, await s.mint({}, fresh));
    await s.rec.settle();
    expect(s.rec.refused.map((e) => e.reason)).toEqual(["bad_signature", "bad_signature", "bad_signature"]);
    expect(s.net.calls).toHaveLength(1);
  });

  it("an algorithm the issuer's JWKS doesn't publish is bad_signature (S8: not the public disallowed_alg)", async () => {
    const s = await host();
    const rsa = await s.idp.signingKey("RS256");
    // Every published key names ES256, so ES256 is all this issuer signs with.
    s.idp.publish([s.idp.key.jwk, { ...rsa.jwk, alg: "ES256" }]);
    await redeem(s.h, s.client, await s.mint({}, rsa));
    await s.rec.settle();
    expect(s.rec.refused.at(-1)?.reason).toBe("bad_signature");
    expect(s.rec.refused.at(-1)?.detail).toMatch(/alg RS256 not published/);
  });
});
