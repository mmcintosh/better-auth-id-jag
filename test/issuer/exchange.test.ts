// The issuer's token exchange, the allowed paths (ES256 hosts; one key algorithm per file, since
// the hosts of a workerd test file share one D1 and its jwks table). Refusals: refusals.test.ts.
import { decodeJwt, decodeProtectedHeader } from "jose";
import { describe, expect, it } from "vitest";
import { ID_JAG_TOKEN_TYPE, ISSUER_METADATA_FIELD, JTI_MODEL, hasJti, TOKEN_EXCHANGE_GRANT } from "../../src/core";
import type { AuthorizeInput } from "../../src/issuer";
import { AUDIENCE, BASE, createIssuerHost, exchange, ISSUER, RESOURCE, setup, verifyWithHostJwks } from "../support/issuer-host";

const allowRead = () => ({ decision: "allow" as const, scopes: ["read", "write"] });

describe("token exchange: an ID token from this IdP becomes an ID-JAG", () => {
  it("exit criterion: a confidential client's ID token yields an ID-JAG that core verifyIdJag accepts against the host's /jwks, with the policy's scopes and the mapped client_id", async () => {
    const host = await createIssuerHost({ issuer: { authorize: () => ({ decision: "allow", scopes: ["read"], clientIdAtResource: "agent-at-rs" }) } });
    const { client, idToken, user } = await setup(host);
    const r = await exchange(host, client, idToken, { scope: "read write", resource: RESOURCE });
    expect(r.status, JSON.stringify(r.body)).toBe(200);
    const parsed = await verifyWithHostJwks(host, r.body.access_token as string);
    expect(parsed.header).toMatchObject({ typ: "oauth-id-jag+jwt", alg: "ES256" });
    expect(parsed.header.kid).toBeTypeOf("string");
    expect(parsed.claims).toMatchObject({ iss: ISSUER, sub: user.id, aud: AUDIENCE, client_id: "agent-at-rs", scope: "read", resource: RESOURCE });
    expect(parsed.claims.exp - parsed.claims.iat).toBe(300);
    expect(parsed.claims.jti).toMatch(/^[A-Za-z0-9_-]{22}$/);
  });

  it("answers per RFC 8693 §2.2.1, with no-store caching headers", async () => {
    const host = await createIssuerHost({ issuer: { authorize: allowRead } });
    const { client, idToken } = await setup(host);
    const r = await exchange(host, client, idToken, { scope: "read" });
    expect(Object.keys(r.body).sort()).toEqual(["access_token", "expires_in", "issued_token_type", "scope", "token_type"]);
    expect(r.body).toMatchObject({ issued_token_type: ID_JAG_TOKEN_TYPE, token_type: "N_A", scope: "read", expires_in: 300 });
    expect(r.headers.get("cache-control")).toBe("no-store");
    expect(r.headers.get("pragma")).toBe("no-cache");
    expect(r.headers.get("content-type")).toMatch(/application\/json/);
  });

  it("carries auth_time and acr from the ID token; sub is the user id", async () => {
    const host = await createIssuerHost({ issuer: { authorize: allowRead } });
    const { client, idToken, user } = await setup(host);
    const idClaims = decodeJwt(idToken);
    const claims = decodeJwt((await exchange(host, client, idToken)).body.access_token as string);
    expect(claims.sub).toBe(user.id);
    expect(claims.auth_time).toBe(idClaims.auth_time);
    expect(claims.acr).toBe(idClaims.acr);
    expect(claims.email).toBeUndefined();
  });

  it("client_id defaults to the client's own id here (D-004)", async () => {
    const host = await createIssuerHost({ issuer: { authorize: allowRead } });
    const { client, idToken } = await setup(host);
    const claims = decodeJwt((await exchange(host, client, idToken)).body.access_token as string);
    expect(claims.client_id).toBe(client.client_id);
    expect(host.recorded.issued[0]).toMatchObject({ clientId: client.client_id, clientIdAtResource: client.client_id });
  });

  it("the authorize hook sees the request, and the ID-JAG's scopes only narrow (requested ∩ allowed)", async () => {
    const seen: AuthorizeInput[] = [];
    const host = await createIssuerHost({
      issuer: {
        authorize: (input) => {
          seen.push(input);
          return { decision: "allow", scopes: ["read", "write"] };
        },
      },
    });
    const { client, idToken, user } = await setup(host);
    const narrowed = await exchange(host, client, idToken, { scope: "write admin", resource: RESOURCE });
    expect(narrowed.body.scope).toBe("write");
    expect(seen[0]).toMatchObject({ audience: AUDIENCE, resource: RESOURCE, requestedScopes: ["write", "admin"], client: { clientId: client.client_id }, user: { id: user.id } });
    expect(seen[0]?.subjectToken.sub).toBe(user.id);
    // No scope requested: the policy's.
    expect((await exchange(host, client, idToken)).body.scope).toBe("read write");
  });

  it("lifetime: default 300 s, the policy's when shorter, capped at 900 s (S7)", async () => {
    let lifetime: number | undefined;
    const host = await createIssuerHost({ issuer: { authorize: () => ({ decision: "allow", scopes: ["read"], ...(lifetime !== undefined ? { lifetimeSeconds: lifetime } : {}) }) } });
    const { client, idToken } = await setup(host);
    const life = async () => {
      const r = await exchange(host, client, idToken);
      const c = decodeJwt(r.body.access_token as string);
      return [r.body.expires_in, (c.exp ?? 0) - (c.iat ?? 0)];
    };
    expect(await life()).toEqual([300, 300]);
    lifetime = 60;
    expect(await life()).toEqual([60, 60]);
    lifetime = 3600;
    expect(await life()).toEqual([900, 900]);
  });

  it("defaultLifetimeSeconds applies when no source sets one", async () => {
    const host = await createIssuerHost({ issuer: { authorize: allowRead, defaultLifetimeSeconds: 120 } });
    const { client, idToken } = await setup(host);
    expect((await exchange(host, client, idToken)).body.expires_in).toBe(120);
  });

  it("email only when the policy opts in, and only a verified one; tenant when the policy names one", async () => {
    let email = false;
    const host = await createIssuerHost({ issuer: { authorize: () => ({ decision: "allow", scopes: ["read"], claims: { email, tenant: "org-1" } }) } });
    const { client, idToken, user } = await setup(host);
    const claims = async () => decodeJwt((await exchange(host, client, idToken)).body.access_token as string);
    expect((await claims()).email).toBeUndefined();
    email = true;
    expect((await claims()).email).toBeUndefined(); // not verified yet
    await host.ctx.adapter.update({ model: "user", where: [{ field: "id", value: user.id }], update: { emailVerified: true } });
    const c = await claims();
    expect(c.email).toBe(user.email);
    expect(c.tenant).toBe("org-1");
    expect(host.recorded.issued.at(-1)?.organizationId).toBe("org-1");
  });

  it("a resource the hook names is used when the client sent none", async () => {
    const host = await createIssuerHost({ issuer: { authorize: () => ({ decision: "allow", scopes: [], resource: RESOURCE }) } });
    const { client, idToken } = await setup(host);
    const r = await exchange(host, client, idToken);
    const c = decodeJwt(r.body.access_token as string);
    expect(c.resource).toBe(RESOURCE);
    // No scopes allowed and none requested: no scope claim, no scope in the response.
    expect(c.scope).toBeUndefined();
    expect(r.body.scope).toBeUndefined();
  });

  it("normalises the audience (scheme and host case, default port) without touching the path", async () => {
    const host = await createIssuerHost({ issuer: { authorize: allowRead } });
    const { client, idToken } = await setup(host);
    const aud = async (a: string) => decodeJwt((await exchange(host, client, idToken, { audience: a })).body.access_token as string).aud;
    expect(await aud("HTTPS://RS.Example:443/api/auth")).toBe(AUDIENCE);
    expect(await aud("https://rs.example")).toBe("https://rs.example");
    expect(await aud("https://rs.example/")).toBe("https://rs.example/");
  });

  it("records the jti (side issued) and emits id-jag.issued", async () => {
    const host = await createIssuerHost({ issuer: { authorize: allowRead } });
    const { client, idToken, user } = await setup(host);
    const r = await exchange(host, client, idToken, { scope: "read" });
    const jti = decodeJwt(r.body.access_token as string).jti as string;
    expect(await hasJti(host.ctx.adapter, "issued", ISSUER, jti)).toBe(true);
    const row = await host.ctx.adapter.findOne<Record<string, unknown>>({ model: JTI_MODEL, where: [{ field: "jti", value: jti }] });
    expect(row).toMatchObject({ side: "issued", sub: user.id, clientId: client.client_id, aud: AUDIENCE });
    expect(host.recorded.issued).toHaveLength(1);
    expect(host.recorded.issued[0]).toMatchObject({ type: "id-jag.issued", userId: user.id, audience: AUDIENCE, scopes: ["read"], jti });
  });

  it("the audit table stores issued events with their columns", async () => {
    const host = await createIssuerHost({ issuer: { authorize: allowRead, auditLog: { retentionDays: 7 } } });
    const { client, idToken, user } = await setup(host);
    const jti = decodeJwt((await exchange(host, client, idToken)).body.access_token as string).jti as string;
    const row = await host.ctx.adapter.findOne<Record<string, unknown>>({ model: "idJagAudit", where: [{ field: "jti", value: jti }] });
    expect(row).toMatchObject({ type: "id-jag.issued", userId: user.id, clientId: client.client_id, audience: AUDIENCE });
  });

  it("jwt.issuer, when set, is the ID-JAG's iss (as it is the ID token's)", async () => {
    const iss = "https://idp.example";
    const host = await createIssuerHost({ jwt: { jwt: { issuer: iss } }, issuer: { authorize: allowRead } });
    const { client, idToken } = await setup(host);
    expect(decodeJwt(idToken).iss).toBe(iss);
    const r = await exchange(host, client, idToken);
    expect(r.status, JSON.stringify(r.body)).toBe(200);
    expect((await verifyWithHostJwks(host, r.body.access_token as string, { issuer: iss })).claims.iss).toBe(iss);
  });

  it("S10: the exchange makes no outbound request at all", async () => {
    const host = await createIssuerHost({ issuer: { authorize: allowRead } });
    const { client, idToken } = await setup(host);
    const original = globalThis.fetch;
    const calls: string[] = [];
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      calls.push(String(input instanceof Request ? input.url : input));
      throw new Error("no outbound requests");
    }) as typeof fetch;
    try {
      const r = await exchange(host, client, idToken, { scope: "read", resource: RESOURCE });
      expect(r.status, JSON.stringify(r.body)).toBe(200);
      // A refused one too: a token that fails verification is never "checked" elsewhere.
      expect((await exchange(host, client, `${idToken.slice(0, idToken.lastIndexOf("."))}.AAAA`)).status).toBe(400);
    } finally {
      globalThis.fetch = original;
    }
    expect(calls).toEqual([]);
  });
});

describe("discovery metadata", () => {
  it("advertises identity_chaining_requested_token_types_supported and the grant", async () => {
    const host = await createIssuerHost({ issuer: { authorize: allowRead } });
    for (const path of ["/.well-known/oauth-authorization-server/api/auth", "/api/auth/.well-known/openid-configuration"]) {
      const res = await host.auth.handler(new Request(`${BASE}${path}`));
      expect(res.status, path).toBe(200);
      const doc = (await res.json()) as Record<string, unknown>;
      expect(doc[ISSUER_METADATA_FIELD], path).toEqual([ID_JAG_TOKEN_TYPE]);
      expect(doc.grant_types_supported, path).toContain(TOKEN_EXCHANGE_GRANT);
    }
  });
});

describe("the ID-JAG header", () => {
  it("is typ oauth-id-jag+jwt with a kid that the host's JWKS publishes", async () => {
    const host = await createIssuerHost({ issuer: { authorize: allowRead } });
    const { client, idToken } = await setup(host);
    const token = (await exchange(host, client, idToken)).body.access_token as string;
    const header = decodeProtectedHeader(token);
    const jwks = (await (await host.auth.handler(new Request(`${ISSUER}/jwks`))).json()) as { keys: { kid: string }[] };
    expect(header.typ).toBe("oauth-id-jag+jwt");
    expect(jwks.keys.map((k) => k.kid)).toContain(header.kid);
  });
});
