// The tester's outbound guard (examples/workers/tester/src/guard.ts): only public https names, no redirects, small
// answers, a timeout.
import { describe, expect, it } from "vitest";
import { checkPublicHttpsUrl, fetchJsonCapped, guardedFetch, oauthMetadataUrl, openIdConfigurationUrl, postFormCapped } from "../../examples/workers/tester/src/guard";

describe("tester: checkPublicHttpsUrl", () => {
  it.each([
    "https://idp.example.org",
    "https://idp.example.org/tenant/a",
    "https://login.okta.com:443/oauth2/default",
  ])("allows %s", (u) => expect(checkPublicHttpsUrl(u).ok).toBe(true));

  it.each([
    ["http://idp.example.org", "https"],
    ["https://127.0.0.1", "IP"],
    ["https://[::1]/", "IP"],
    ["https://0x7f000001/", "IP"],
    ["https://2130706433/", "IP"],
    ["https://localhost/", "fully qualified"],
    ["https://idp.localhost/", "public"],
    ["https://metadata.internal/", "public"],
    ["https://x.local/", "public"],
    ["https://localhost./", "dot"],
    ["https://metadata.internal./x", "dot"],
    ["https://idp.example.org:8443/", "port"],
    ["https://user:pw@idp.example.org/", "user name"],
    ["https://idp.example.org/#x", "fragment"],
    ["not a url", "not a URL"],
    [`https://idp.example.org/${"a".repeat(600)}`, "512"],
  ])("refuses %s", (u, why) => {
    const r = checkPublicHttpsUrl(u);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.why).toContain(why);
  });
});

describe("tester: fetching", () => {
  const json = (body: unknown, init: ResponseInit = {}) => new Response(JSON.stringify(body), { headers: { "content-type": "application/json" }, ...init });

  it("returns small JSON", async () => {
    const r = await fetchJsonCapped(async () => json({ ok: 1 }), "https://idp.example.org/jwks");
    expect(r).toEqual({ ok: true, json: { ok: 1 } });
  });

  it("never follows a redirect, refuses large or non-JSON answers, and refused URLs aren't fetched", async () => {
    let called = 0;
    const count = async () => {
      called++;
      return json({});
    };
    expect((await fetchJsonCapped(async () => new Response(null, { status: 302, headers: { location: "https://elsewhere.example/" } }), "https://idp.example.org/x")).ok).toBe(false);
    expect((await fetchJsonCapped(async () => new Response("x".repeat(70_000)), "https://idp.example.org/x")).ok).toBe(false);
    expect((await fetchJsonCapped(async () => new Response("<html>"), "https://idp.example.org/x")).ok).toBe(false);
    expect((await fetchJsonCapped(count, "https://127.0.0.1/x")).ok).toBe(false);
    expect(called).toBe(0);
  });

  it("gives up after the timeout", async () => {
    const slow = (_: string, init?: RequestInit) => new Promise<Response>((_r, reject) => init?.signal?.addEventListener("abort", () => reject(new Error("aborted"))));
    const r = await fetchJsonCapped(slow, "https://idp.example.org/x", { timeoutMs: 50 });
    expect(r).toEqual({ ok: false, why: "didn't answer within 50 ms" });
  });

  it("the receiver's fetch refuses guarded URLs and redirects", async () => {
    const f = guardedFetch(async () => new Response(null, { status: 301 }));
    await expect(f("https://10.0.0.1/jwks")).rejects.toThrow("refused to fetch");
    await expect(f("https://idp.example.org/jwks")).rejects.toThrow("redirect");
  });

  it("metadata locations: RFC 8414 inserts, OpenID Connect appends", () => {
    expect(oauthMetadataUrl(new URL("https://idp.example.org"))).toBe("https://idp.example.org/.well-known/oauth-authorization-server");
    expect(oauthMetadataUrl(new URL("https://idp.example.org/t/a"))).toBe("https://idp.example.org/.well-known/oauth-authorization-server/t/a");
    expect(openIdConfigurationUrl(new URL("https://idp.example.org/t/a"))).toBe("https://idp.example.org/t/a/.well-known/openid-configuration");
  });

  it("a run's POST to a token endpoint: the guard's URLs only, no redirects, a capped answer, any status as an answer", async () => {
    let called = 0;
    let sent: { url: string; init: RequestInit | undefined } | undefined;
    const answer = (r: Response) => async (url: string, init?: RequestInit) => {
      called++;
      sent = { url, init };
      return r;
    };
    const form = new URLSearchParams({ grant_type: "x" });
    for (const url of ["http://idp.example.org/token", "https://127.0.0.1/token", "https://metadata.internal/token", "https://idp.example.org:8443/token"]) expect((await postFormCapped(answer(json({})), url, form, {})).ok).toBe(false);
    expect(called).toBe(0);
    const ok = await postFormCapped(answer(Response.json({ error: "invalid_grant" }, { status: 400, headers: { "cache-control": "no-store" } })), "https://idp.example.org/token", form, { authorization: "Basic eA==" });
    expect(ok).toEqual({ ok: true, status: 400, contentType: "application/json", cacheControl: "no-store", json: { error: "invalid_grant" } });
    expect(sent?.init).toMatchObject({ method: "POST", redirect: "manual", body: "grant_type=x" });
    expect(new Headers(sent?.init?.headers).get("content-type")).toBe("application/x-www-form-urlencoded");
    expect(new Headers(sent?.init?.headers).get("authorization")).toBe("Basic eA==");
    expect(await postFormCapped(answer(new Response("<html>", { status: 500 })), "https://idp.example.org/token", form, {})).toMatchObject({ ok: true, status: 500, json: undefined });
    expect((await postFormCapped(answer(new Response(null, { status: 307, headers: { location: "https://elsewhere.example.org/" } })), "https://idp.example.org/token", form, {})).ok).toBe(false);
    expect((await postFormCapped(answer(new Response("x".repeat(70_000))), "https://idp.example.org/token", form, {})).ok).toBe(false);
    const slow = (_: string, init?: RequestInit) => new Promise<Response>((_r, reject) => init?.signal?.addEventListener("abort", () => reject(new Error("aborted"))));
    expect(await postFormCapped(slow, "https://idp.example.org/token", form, {}, { timeoutMs: 50 })).toEqual({ ok: false, why: "didn't answer within 50 ms" });
  });
});
