// The receiver on other hosts and under concurrency: two auth instances on one database (S3),
// a CIMD client with private_key_jwt (S5), and oauthProvider() instead of mcp().
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import { JWT_BEARER_GRANT } from "../../src/core";
import {
  createClient,
  database,
  decodePayload,
  ISSUER,
  linkedUser,
  MCP_RESOURCE,
  network,
  OTHER_RESOURCE,
  receiverHost,
  recorder,
  redeem,
  testIdp,
  tokenRequest,
} from "../support/receiver-host";

describe("replay under concurrency (S3)", () => {
  it("10 concurrent redemptions of one ID-JAG across two instances on one database: exactly one succeeds", async () => {
    const idp = await testIdp();
    const db = await database();
    const recs = [recorder(), recorder()];
    const receiver = { trustedIssuers: [{ issuer: idp.issuer, jwksUri: idp.jwksUri }], fetch: network(idp).fetch };
    const a = await receiverHost("mcp", { receiver, database: db, recorder: recs[0]! });
    const b = await receiverHost("mcp", { receiver: { ...receiver, fetch: network(idp).fetch }, database: db, recorder: recs[1]! });
    const client = await createClient(a);
    const sub = crypto.randomUUID();
    await linkedUser(a, `id-jag:${idp.issuer}`, sub);
    const token = await idp.mint(idp.claims({ sub, client_id: client.client_id }));
    const results = await Promise.all(Array.from({ length: 10 }, (_, i) => redeem(i % 2 ? a : b, client, token)));
    expect(results.filter((r) => r.status === 200)).toHaveLength(1);
    const refused = results.filter((r) => r.status !== 200);
    expect(new Set(refused.map((r) => r.text)).size).toBe(1);
    for (const r of recs) await r.settle();
    const reasons = recs.flatMap((r) => r.refused.map((e) => e.reason));
    expect(reasons).toEqual(Array(9).fill("replay"));
  });
});

describe("a CIMD client (URL client id) authenticating with private_key_jwt", () => {
  it("redeems an ID-JAG whose client_id is its URL; without the assertion it's refused", async () => {
    const idp = await testIdp();
    const { publicKey, privateKey } = await generateKeyPair("ES256");
    const clientId = `https://agent-${crypto.randomUUID().slice(0, 8)}.example/oauth/metadata.json`;
    const doc = {
      client_id: clientId,
      client_name: "CIMD agent",
      redirect_uris: ["https://agent.example/cb"],
      grant_types: [JWT_BEARER_GRANT],
      response_types: [],
      token_endpoint_auth_method: "private_key_jwt",
      jwks: { keys: [{ ...(await exportJWK(publicKey)), kid: "c1", alg: "ES256", use: "sig" }] },
      scope: "read",
    };
    const rec = recorder();
    const h = await receiverHost("mcp", {
      receiver: { trustedIssuers: [{ issuer: idp.issuer, jwksUri: idp.jwksUri }], fetch: network(idp).fetch },
      recorder: rec,
      fetchClientMetadata: async () => new Response(JSON.stringify(doc), { headers: { "content-type": "application/json", "cache-control": "max-age=60" } }),
    });
    const sub = crypto.randomUUID();
    const user = await linkedUser(h, `id-jag:${idp.issuer}`, sub);
    const clientAssertion = () =>
      new SignJWT({}).setProtectedHeader({ alg: "ES256", kid: "c1" }).setIssuer(clientId).setSubject(clientId).setAudience(`${ISSUER}/oauth2/token`).setJti(crypto.randomUUID()).setIssuedAt().setExpirationTime("2m").sign(privateKey);
    const idJag = await idp.mint(idp.claims({ sub, client_id: clientId }));
    const form = async (withAssertion: boolean) => ({
      grant_type: JWT_BEARER_GRANT,
      assertion: idJag,
      client_id: clientId,
      ...(withAssertion ? { client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", client_assertion: await clientAssertion() } : {}),
    });
    const bare = await h.auth.handler(tokenRequest(await form(false)));
    expect(((await bare.json()) as { error: string }).error).toBe("invalid_client");
    const res = await h.auth.handler(tokenRequest(await form(true)));
    const body = (await res.json()) as Record<string, unknown>;
    expect(res.status, JSON.stringify(body)).toBe(200);
    expect(decodePayload(body.access_token as string)).toMatchObject({ aud: MCP_RESOURCE, sub: user.id, client_id: clientId });
    await rec.settle();
    expect(rec.accepted.at(-1)?.clientId).toBe(clientId);
  });
});

describe("on oauthProvider() instead of mcp()", () => {
  it("issues for a configured resource; refuses one that isn't; advertises the grant profile", async () => {
    const idp = await testIdp();
    const rec = recorder();
    const h = await receiverHost("oauth-provider", {
      receiver: { trustedIssuers: [{ issuer: idp.issuer, jwksUri: idp.jwksUri }], fetch: network(idp).fetch, defaultResource: MCP_RESOURCE },
      recorder: rec,
      resources: [MCP_RESOURCE, OTHER_RESOURCE],
    });
    const client = await createClient(h);
    const sub = crypto.randomUUID();
    await linkedUser(h, `id-jag:${idp.issuer}`, sub);
    const mint = (over: Record<string, unknown>) => idp.mint(idp.claims({ sub, client_id: client.client_id, ...over }));
    const r = await redeem(h, client, await mint({ resource: OTHER_RESOURCE }));
    expect(r.status, r.text).toBe(200);
    expect(decodePayload(r.body.access_token as string).aud).toBe(OTHER_RESOURCE);
    expect(r.body).not.toHaveProperty("refresh_token");
    // No resource claim, two registered resources: the defaultResource.
    const d = await redeem(h, client, await mint({ resource: undefined }));
    expect(d.status, d.text).toBe(200);
    expect(decodePayload(d.body.access_token as string).aud).toBe(MCP_RESOURCE);
    const bad = await redeem(h, client, await mint({ resource: "https://unregistered.example/api" }));
    expect(bad.body.error).toBe("invalid_target");
    await rec.settle();
    expect(rec.refused.at(-1)?.reason).toBe("unknown_resource");
    const doc = (await (await h.auth.handler(new Request("http://localhost:3000/.well-known/oauth-authorization-server/api/auth"))).json()) as Record<string, unknown>;
    expect(doc.authorization_grant_profiles_supported).toEqual(["urn:ietf:params:oauth:grant-profile:id-jag"]);
    expect(doc.grant_types_supported).toContain(JWT_BEARER_GRANT);
  });

  it("the request may only pick a resource the ID-JAG names, even a registered one", async () => {
    const idp = await testIdp();
    const rec = recorder();
    const h = await receiverHost("oauth-provider", { receiver: { trustedIssuers: [{ issuer: idp.issuer, jwksUri: idp.jwksUri }], fetch: network(idp).fetch }, recorder: rec, resources: [MCP_RESOURCE, OTHER_RESOURCE] });
    const client = await createClient(h);
    const sub = crypto.randomUUID();
    await linkedUser(h, `id-jag:${idp.issuer}`, sub);
    const r = await redeem(h, client, await idp.mint(idp.claims({ sub, client_id: client.client_id, resource: MCP_RESOURCE })), { resource: OTHER_RESOURCE });
    expect(r.body.error).toBe("invalid_target");
    await rec.settle();
    expect(rec.refused.at(-1)?.reason).toBe("unknown_resource");
  });

  it("a client with no registered scope list still only gets the resource's scopes", async () => {
    const idp = await testIdp();
    const h = await receiverHost("oauth-provider", { receiver: { trustedIssuers: [{ issuer: idp.issuer, jwksUri: idp.jwksUri }], fetch: network(idp).fetch } });
    const client = await createClient(h, { scope: null });
    const sub = crypto.randomUUID();
    await linkedUser(h, `id-jag:${idp.issuer}`, sub);
    const r = await redeem(h, client, await idp.mint(idp.claims({ sub, client_id: client.client_id, scope: "read banana" })));
    expect(r.status, r.text).toBe(200);
    expect(r.body.scope).toBe("read");
  });

  it("two registered resources, no claim, no default: refused rather than guessed", async () => {
    const idp = await testIdp();
    const rec = recorder();
    const h = await receiverHost("oauth-provider", { receiver: { trustedIssuers: [{ issuer: idp.issuer, jwksUri: idp.jwksUri }], fetch: network(idp).fetch }, recorder: rec, resources: [MCP_RESOURCE, OTHER_RESOURCE] });
    const client = await createClient(h);
    const r = await redeem(h, client, await idp.mint(idp.claims({ client_id: client.client_id, resource: undefined })));
    expect(r.body.error).toBe("invalid_target");
    await rec.settle();
    expect(rec.refused.at(-1)?.reason).toBe("unknown_resource");
  });
});
