// How long an access token from an ID-JAG lives: the provider's accessTokenExpiresIn (1 hour by
// default), shortened per scope by scopeExpirations. The ID-JAG's own exp doesn't shorten it. This is
// how long an agent keeps access after the IdP stops issuing it ID-JAGs (README, "What ID-JAG controls").
import { describe, expect, it } from "vitest";
import { createClient, decodePayload, linkedUser, network, receiverHost, redeem, testIdp } from "../support/receiver-host";

async function setup(provider?: Record<string, unknown>) {
  const idp = await testIdp();
  const h = await receiverHost("mcp", { receiver: { trustedIssuers: [{ issuer: idp.issuer, jwksUri: idp.jwksUri }], fetch: network(idp).fetch }, ...(provider ? { provider } : {}) });
  const client = await createClient(h);
  const sub = crypto.randomUUID();
  await linkedUser(h, `id-jag:${idp.issuer}`, sub);
  const lifetime = async (scope: string) => {
    const r = await redeem(h, client, await idp.mint(idp.claims({ client_id: client.client_id, sub, scope })), { scope });
    expect(r.status, r.text).toBe(200);
    const at = decodePayload(r.body.access_token as string);
    return { expiresIn: r.body.expires_in as number, jwt: (at.exp as number) - (at.iat as number) };
  };
  return { lifetime };
}

describe("access-token lifetime", () => {
  it("is the provider's default, an hour, whatever the ID-JAG's 300 s", async () => {
    const { lifetime } = await setup();
    expect(await lifetime("read")).toEqual({ expiresIn: 3600, jwt: 3600 });
  });

  it("follows accessTokenExpiresIn, and scopeExpirations shortens it for a scope", async () => {
    const { lifetime } = await setup({ accessTokenExpiresIn: 600, scopeExpirations: { write: "2m" } });
    expect(await lifetime("read")).toEqual({ expiresIn: 600, jwt: 600 });
    expect(await lifetime("read write")).toEqual({ expiresIn: 120, jwt: 120 });
  });
});
