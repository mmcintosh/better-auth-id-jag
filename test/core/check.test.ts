// The rule-by-rule checker (src/core/check.ts; the public tester's report and the id-jag-check Action): each rule
// says pass or fail for the right reason, and the metadata check stops registrations that would never work.
import { exportJWK, generateKeyPair, type JWTPayload, SignJWT } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import { checkExchange, checkIdJag, checkIssuerMetadata, type ExchangeCheckInput, type IdJagCheckInput, type RuleResult, show } from "../../src/core/check";

const ISSUER = "https://idp.example.org";
const AUD = "https://tester.example.net/api/auth";
const RESOURCE = "https://tester.example.net/mcp";
const now = 1_800_000_000;

let key: CryptoKey;
let otherKey: CryptoKey;
let jwks: { keys: Record<string, unknown>[] };

beforeAll(async () => {
  const pair = await generateKeyPair("RS256", { extractable: true });
  key = pair.privateKey;
  otherKey = (await generateKeyPair("RS256")).privateKey;
  jwks = { keys: [{ ...(await exportJWK(pair.publicKey)), kid: "k1", alg: "RS256", use: "sig" }] };
});

const good: JWTPayload & Record<string, unknown> = { iss: ISSUER, sub: "u1", aud: AUD, client_id: "c1", jti: "j1", iat: now - 10, exp: now + 290, resource: RESOURCE, scope: "read", email: "a@example.org" };
const sign = (claims: Record<string, unknown>, header: Record<string, unknown> = {}, k: CryptoKey = key) =>
  new SignJWT(claims).setProtectedHeader({ alg: "RS256", typ: "oauth-id-jag+jwt", kid: "k1", ...header }).sign(k);
const input = (o: Partial<IdJagCheckInput> = {}): IdJagCheckInput => ({ issuer: ISSUER, audience: AUD, resource: RESOURCE, grantableScopes: ["read"], clientId: "c1", jwks: jwks as never, now, ...o });
const outcome = (results: RuleResult[], id: string) => results.find((r) => r.id === id)?.outcome;

describe("checkIdJag", () => {
  it("a correct ID-JAG passes every rule that can fail", async () => {
    const { results } = await checkIdJag(await sign(good), input());
    expect(results.filter((r) => r.outcome === "fail")).toEqual([]);
    for (const id of ["header.typ", "header.alg", "signature", "claim.iss", "claim.sub", "claim.aud", "claim.client_id", "claim.jti", "claim.exp", "claim.iat", "claim.lifetime", "claim.resource", "claim.scope"]) expect(outcome(results, id), id).toBe("pass");
    expect(results.every((r) => r.cite.length > 0)).toBe(true);
  });

  it("reports every failure at once, not just the first", async () => {
    const { results } = await checkIdJag(await sign({ ...good, aud: [AUD, "https://other.example"], client_id: "someone-else", scope: undefined }, { typ: "JWT" }), input());
    expect(outcome(results, "header.typ")).toBe("fail");
    expect(outcome(results, "claim.aud")).toBe("fail");
    expect(outcome(results, "claim.client_id")).toBe("fail");
    expect(outcome(results, "claim.scope")).toBe("fail");
  });

  it("a signature by a key not in the JWKS fails; no JWKS skips the rule", async () => {
    expect(outcome((await checkIdJag(await sign(good, {}, otherKey), input())).results, "signature")).toBe("fail");
    expect(outcome((await checkIdJag(await sign(good), input({ jwks: null }))).results, "signature")).toBe("skip");
  });

  it("aud may be a one-element array; the resource must be ours; scope must be a string", async () => {
    const r = (await checkIdJag(await sign({ ...good, aud: [AUD], resource: [RESOURCE, "https://elsewhere.example/api"], scope: ["read"] }), input())).results;
    expect(outcome(r, "claim.aud")).toBe("pass");
    expect(outcome(r, "claim.resource")).toBe("fail");
    expect(outcome(r, "claim.scope")).toBe("fail");
  });

  it("expired, issued in the future, and too long-lived", async () => {
    expect(outcome((await checkIdJag(await sign({ ...good, iat: now - 1000, exp: now - 500 }), input())).results, "claim.exp")).toBe("fail");
    expect(outcome((await checkIdJag(await sign({ ...good, iat: now + 600, exp: now + 800 }), input())).results, "claim.iat")).toBe("fail");
    expect(outcome((await checkIdJag(await sign({ ...good, exp: now + 3600 }), input())).results, "claim.lifetime")).toBe("fail");
  });

  it("missing required claims each fail; absent optional ones are informational", async () => {
    const { iss: _i, sub: _s, jti: _j, client_id: _c, resource: _r, ...rest } = good;
    const r = (await checkIdJag(await sign(rest), input())).results;
    for (const id of ["claim.iss", "claim.sub", "claim.jti", "claim.client_id"]) expect(outcome(r, id), id).toBe("fail");
    expect(outcome(r, "claim.resource")).toBe("info");
  });

  it("alg none and HS256 are refused; a non-JWT is a structure failure", async () => {
    const none = `${btoa(JSON.stringify({ alg: "none", typ: "oauth-id-jag+jwt" })).replace(/=/g, "")}.${btoa(JSON.stringify(good)).replace(/=/g, "")}.`;
    expect(outcome((await checkIdJag(none, input())).results, "header.alg")).toBe("fail");
    const hs = await new SignJWT(good).setProtectedHeader({ alg: "HS256", typ: "oauth-id-jag+jwt" }).sign(new TextEncoder().encode("x".repeat(32)));
    expect(outcome((await checkIdJag(hs, input())).results, "header.alg")).toBe("fail");
    const junk = await checkIdJag("not a jwt", input());
    expect(junk.results).toHaveLength(1);
    expect(outcome(junk.results, "jwt.structure")).toBe("fail");
  });

  it("matches the receiver: typ in any case or with application/, a key named by x5t, crit, whole seconds, cnf", async () => {
    for (const typ of ["OAUTH-ID-JAG+JWT", "application/oauth-id-jag+jwt"]) {
      const r = (await checkIdJag(await sign(good, { typ }), input())).results;
      expect(outcome(r, "header.typ"), typ).toBe("pass");
      expect(outcome(r, "receiver.parse"), typ).toBe("pass");
    }
    const thumb = "A".repeat(27);
    const byThumb = { keys: [{ ...jwks.keys[0], kid: undefined, x5t: thumb }, { ...jwks.keys[0], kid: undefined, x5t: "B".repeat(27), n: "AQAB" }] };
    const x5tOnly = await new SignJWT(good).setProtectedHeader({ alg: "RS256", typ: "oauth-id-jag+jwt", x5t: thumb }).sign(key);
    const r1 = (await checkIdJag(x5tOnly, input({ jwks: byThumb as never }))).results;
    expect(outcome(r1, "header.kid")).toBe("warn");
    expect(outcome(r1, "signature")).toBe("pass");
    const unnamed = (await checkIdJag(await new SignJWT(good).setProtectedHeader({ alg: "RS256", typ: "oauth-id-jag+jwt" }).sign(key), input())).results;
    expect(outcome(unnamed, "header.kid")).toBe("fail");
    expect(outcome(unnamed, "receiver.parse")).toBe("fail");
    expect(outcome((await checkIdJag(await sign(good, { crit: ["b64"], b64: true }), input())).results, "header.crit")).toBe("fail");
    expect(outcome((await checkIdJag(await sign({ ...good, exp: now + 290.5 }), input())).results, "claim.exp")).toBe("fail");
    const cnf = (await checkIdJag(await sign({ ...good, cnf: { jkt: "x" } }), input())).results;
    expect(outcome(cnf, "claim.cnf")).toBe("fail");
    expect(outcome(cnf, "receiver.parse")).toBe("fail");
  });

  it("an encryption key never verifies, as at the receiver", async () => {
    const enc = { keys: [{ ...jwks.keys[0], use: "enc" }] };
    expect(outcome((await checkIdJag(await sign(good), input({ jwks: enc as never }))).results, "signature")).toBe("fail");
  });

  it("never throws, whatever it is given", async () => {
    for (const t of ["", "a.b.c", "....", "x".repeat(20_000), `${btoa("[]")}.${btoa("{}")}.x`]) await expect(checkIdJag(t, input())).resolves.toBeDefined();
  });

  it("a certificate that isn't base64, even on an unrelated key, gives no thumbprints and doesn't stop the report", async () => {
    const thumb = "A".repeat(27);
    const withBadCert = { keys: [{ ...jwks.keys[0], kid: undefined, x5c: ["not base64!"] }, { ...jwks.keys[0], kid: undefined, x5t: thumb }] };
    const token = await new SignJWT(good).setProtectedHeader({ alg: "RS256", typ: "oauth-id-jag+jwt", x5t: thumb }).sign(key);
    const r = (await checkIdJag(token, input({ jwks: withBadCert as never }))).results;
    expect(outcome(r, "signature")).toBe("pass");
  });

  it("its messages name the receiver, not the tester (the checker runs in the Action too)", async () => {
    const r = (await checkIdJag(await sign({ ...good, client_id: "someone-else", email: undefined, tenant: "t1", sub_id: { format: "email", email: "a@example.org" } }), input())).results;
    expect(outcome(r, "claim.client_id")).toBe("fail");
    expect(r.map((x) => x.message).join("\n")).not.toMatch(/tester/i);
  });
});

describe("show", () => {
  it("never throws: a value nested too deeply for JSON.stringify (or String) is a short placeholder", () => {
    let deep: unknown = [];
    for (let i = 0; i < 200_000; i++) deep = [deep];
    // Where JSON.stringify overflows (Node), the placeholder; where it copes (workerd), the value, cut short.
    const shown = show(deep);
    expect(shown === "(a value too deeply nested to show)" || /^\[\[\[.*\.\.\.$/.test(shown)).toBe(true);
    expect(show("ok")).toBe('"ok"');
  });
});

describe("checkIssuerMetadata", () => {
  const meta = { issuer: ISSUER, jwks_uri: `${ISSUER}/jwks`, identity_chaining_requested_token_types_supported: ["urn:ietf:params:oauth:token-type:id-jag"], id_jag_signing_alg_values_supported: ["RS256", "ES256"] };

  it("good metadata and keys pass and nothing blocks", () => {
    const r = checkIssuerMetadata({ issuer: ISSUER, source: "oauth-authorization-server", metadata: meta, jwks });
    expect(r.blocking).toEqual([]);
    expect(r.results.filter((x) => x.outcome === "fail")).toEqual([]);
  });

  it("metadata that isn't a JSON object (null, an array, a string, a number) gives a report that blocks, never a throw", () => {
    for (const metadata of [null, undefined, [meta], "metadata", 42]) {
      const r = checkIssuerMetadata({ issuer: ISSUER, source: "oauth-authorization-server", metadata, jwks });
      expect(r.blocking, JSON.stringify(metadata)).toContain("metadata.issuer");
      expect(r.results.find((x) => x.id === "metadata.issuer")?.message).toMatch(/must be a JSON object/);
      // The keys are still checked.
      expect(r.results.find((x) => x.id === "jwks.keys")?.outcome).toBe("pass");
    }
  });

  it("an issuer mismatch, private key material, or an empty JWKS blocks the registration", () => {
    expect(checkIssuerMetadata({ issuer: ISSUER, source: "oauth-authorization-server", metadata: { ...meta, issuer: `${ISSUER}/` }, jwks }).blocking).toContain("metadata.issuer");
    expect(checkIssuerMetadata({ issuer: ISSUER, source: "oauth-authorization-server", metadata: meta, jwks: { keys: [{ ...jwks.keys[0], d: "secret" }] } }).blocking).toContain("jwks.no_private");
    expect(checkIssuerMetadata({ issuer: ISSUER, source: "oauth-authorization-server", metadata: meta, jwks: { keys: [] } }).blocking).toContain("jwks.keys");
  });

  it("the OIDC fallback and a missing id-jag token type only warn; signing algs without RS256 fail without blocking", () => {
    const r = checkIssuerMetadata({ issuer: ISSUER, source: "openid-configuration", metadata: { issuer: ISSUER, jwks_uri: `${ISSUER}/jwks`, id_jag_signing_alg_values_supported: ["ES256"] }, jwks });
    expect(outcome(r.results, "metadata.location")).toBe("warn");
    expect(outcome(r.results, "metadata.token_types")).toBe("warn");
    expect(outcome(r.results, "metadata.signing_algs")).toBe("fail");
    expect(r.blocking).toEqual([]);
  });
});

describe("checkExchange", () => {
  const ID_JAG_TYPE = "urn:ietf:params:oauth:token-type:id-jag";
  let jag: string;
  beforeAll(async () => {
    jag = await sign(good);
  });
  const answer = (body: Record<string, unknown> = {}, o: Partial<ExchangeCheckInput> = {}): ExchangeCheckInput => ({
    status: 200,
    contentType: "application/json; charset=utf-8",
    cacheControl: "no-store",
    body: { issued_token_type: ID_JAG_TYPE, access_token: jag, token_type: "N_A", scope: "read", expires_in: 300, ...body },
    requestedScope: "read",
    requestedResources: [RESOURCE],
    ...o,
  });
  const ids = ["exchange.status", "exchange.issued_token_type", "exchange.token_type", "exchange.access_token", "exchange.scope", "exchange.expires_in", "exchange.refresh_token", "exchange.no_store", "exchange.resource_echo"];

  it("a correct answer passes every rule, in order, and gives the ID-JAG", () => {
    const r = checkExchange(answer());
    expect(r.results.map((x) => x.id)).toEqual(ids);
    expect(r.results.filter((x) => x.outcome !== "pass")).toEqual([]);
    expect(r.idJag).toBe(jag);
    expect(r.error).toBeNull();
  });

  it("a refusal: only exchange.status, failing, with the OAuth error", () => {
    const r = checkExchange(answer({}, { status: 400, body: { error: "access_denied", error_description: "not assigned" } }));
    expect(r.results.map((x) => [x.id, x.outcome])).toEqual([["exchange.status", "fail"]]);
    expect(r.results[0]?.message).toContain("access_denied");
    expect(r.error).toEqual({ code: "access_denied", description: "not assigned" });
    expect(r.idJag).toBeNull();
    const bare = checkExchange(answer({}, { status: 500, body: undefined }));
    expect(bare.error).toBeNull();
    expect(bare.results[0]?.message).toContain("without an OAuth error");
    // A 200 is the only success, even with an ID-JAG in the body.
    expect(checkExchange(answer({}, { status: 201 })).results.map((x) => x.outcome)).toEqual(["fail"]);
  });

  it("exchange.status: a JSON object, sent as application/json", () => {
    for (const body of [undefined, null, [], "text"]) {
      const r = checkExchange(answer({}, { body }));
      expect(r.results.map((x) => [x.id, x.outcome])).toEqual([["exchange.status", "fail"]]);
      expect(r.idJag).toBeNull();
    }
    const plain = checkExchange(answer({}, { contentType: "text/plain" }));
    expect(outcome(plain.results, "exchange.status")).toBe("fail");
    // The rest is still checked.
    expect(plain.results.map((x) => x.id)).toEqual(ids);
    expect(outcome(checkExchange(answer({}, { contentType: null })).results, "exchange.status")).toBe("fail");
    expect(outcome(checkExchange(answer({}, { contentType: "application/jsonp" })).results, "exchange.status")).toBe("fail");
    expect(outcome(checkExchange(answer({}, { contentType: "Application/JSON" })).results, "exchange.status")).toBe("pass");
  });

  it("exchange.issued_token_type and exchange.token_type (N_A, any case)", () => {
    expect(outcome(checkExchange(answer({ issued_token_type: "urn:ietf:params:oauth:token-type:jwt" })).results, "exchange.issued_token_type")).toBe("fail");
    expect(outcome(checkExchange(answer({ issued_token_type: undefined })).results, "exchange.issued_token_type")).toBe("fail");
    expect(outcome(checkExchange(answer({ token_type: "n_a" })).results, "exchange.token_type")).toBe("pass");
    expect(outcome(checkExchange(answer({ token_type: "Bearer" })).results, "exchange.token_type")).toBe("fail");
    expect(outcome(checkExchange(answer({ token_type: undefined })).results, "exchange.token_type")).toBe("fail");
  });

  it("exchange.access_token: required; without a readable ID-JAG nothing is compared with it", () => {
    for (const access_token of [undefined, "", 42]) {
      const r = checkExchange(answer({ access_token }));
      expect(outcome(r.results, "exchange.access_token")).toBe("fail");
      expect(r.idJag).toBeNull();
      expect(outcome(r.results, "exchange.scope")).toBe("skip");
      expect(outcome(r.results, "exchange.resource_echo")).toBe("skip");
    }
    const garbled = checkExchange(answer({ access_token: "not.a.jwt" }));
    expect(garbled.idJag).toBe("not.a.jwt");
    expect(outcome(garbled.results, "exchange.scope")).toBe("skip");
  });

  it("exchange.scope: OPTIONAL when the ID-JAG's is the one requested, REQUIRED otherwise, and the same as the ID-JAG's", async () => {
    // null: no scope requested.
    const r = (body: Record<string, unknown>, requested: string | null = "read") => outcome(checkExchange(answer(body, { requestedScope: requested ?? undefined })).results, "exchange.scope");
    expect(r({ scope: undefined })).toBe("pass");
    expect(r({ scope: undefined }, "read write")).toBe("fail");
    expect(r({ scope: undefined }, null)).toBe("fail");
    expect(r({ scope: "read" }, "read write")).toBe("pass");
    expect(r({ scope: "read write" })).toBe("fail");
    expect(r({ scope: ["read"] })).toBe("fail");
    const two = await sign({ ...good, scope: "write read" });
    expect(r({ access_token: two, scope: "read write" })).toBe("pass");
    expect(r({ access_token: two, scope: undefined }, "read  write")).toBe("pass");
    const none = await sign({ ...good, scope: undefined });
    expect(r({ access_token: none, scope: "read" })).toBe("fail");
    expect(r({ access_token: none, scope: undefined }, null)).toBe("pass");
  });

  it("exchange.expires_in: RECOMMENDED, a positive whole number, close to the ID-JAG's lifetime", () => {
    const r = (expires_in: unknown) => outcome(checkExchange(answer({ expires_in })).results, "exchange.expires_in");
    expect(r(undefined)).toBe("warn");
    for (const bad of ["300", 0, -300, 299.5]) expect(r(bad)).toBe("fail");
    expect(r(305)).toBe("pass");
    expect(r(295)).toBe("pass");
    expect(r(306)).toBe("warn");
    expect(r(3600)).toBe("warn");
  });

  it("exchange.refresh_token: SHOULD NOT", () => {
    expect(outcome(checkExchange(answer({ refresh_token: "rt" })).results, "exchange.refresh_token")).toBe("warn");
  });

  it("exchange.no_store: Cache-Control has no-store", () => {
    const r = (cacheControl: string | null) => outcome(checkExchange(answer({}, { cacheControl })).results, "exchange.no_store");
    expect(r(null)).toBe("fail");
    expect(r("no-cache")).toBe("fail");
    expect(r("no-storex")).toBe("fail");
    expect(r("private, NO-STORE")).toBe("pass");
  });

  it("exchange.resource_echo: each resource in the ID-JAG exactly as the client sent it", async () => {
    const r = async (resource: unknown, requestedResources: string[] = [RESOURCE]) => outcome(checkExchange(answer({ access_token: await sign({ ...good, resource }) }, { requestedResources })).results, "exchange.resource_echo");
    expect(await r(RESOURCE)).toBe("pass");
    expect(await r([RESOURCE])).toBe("pass");
    expect(await r([RESOURCE], [RESOURCE, "https://tester.example.net/other"])).toBe("pass");
    expect(await r(`${RESOURCE}/`)).toBe("fail");
    expect(await r("HTTPS://tester.example.net/mcp")).toBe("fail");
    expect(await r([RESOURCE, "https://elsewhere.example"])).toBe("fail");
    expect(await r([RESOURCE, 7])).toBe("fail");
    expect(await r(undefined)).toBe("fail");
    expect(await r([])).toBe("fail");
    expect(await r(RESOURCE, [])).toBe("info");
    expect(await r(undefined, [])).toBe("info");
  });

  it("never throws, whatever the answer holds", () => {
    for (const body of [{ access_token: "a.b.c", scope: 1, expires_in: {}, refresh_token: null }, { access_token: "x".repeat(20_000) }, { error: { nested: true } }]) {
      for (const status of [200, 400]) expect(() => checkExchange(answer({}, { status, body }))).not.toThrow();
    }
  });
});
