// The Track A exit criterion (plan §5): a hand-minted ID-JAG from a test IdP yields an access token
// that @better-auth/mcp's requireMcpAuth accepts for the right resource and rejects for another.
import { afterEach, describe, expect, it, vi } from "vitest";
import { requireMcpAuth } from "@better-auth/mcp";
import { ISSUER, MCP_RESOURCE, createClient, linkedUser, network, receiverHost, redeem, testIdp } from "../support/receiver-host";

afterEach(() => vi.unstubAllGlobals());

describe("exit criterion: requireMcpAuth", () => {
  it("accepts the token for the MCP resource, rejects it for another resource", async () => {
    const idp = await testIdp();
    const net = network(idp);
    const h = await receiverHost("mcp", { receiver: { trustedIssuers: [{ issuer: idp.issuer, jwksUri: idp.jwksUri }], fetch: net.fetch } });
    const client = await createClient(h);
    const sub = crypto.randomUUID();
    const user = await linkedUser(h, `id-jag:${idp.issuer}`, sub);
    const r = await redeem(h, client, await idp.mint(idp.claims({ sub, client_id: client.client_id, scope: "read" })));
    expect(r.status, r.text).toBe(200);
    const accessToken = r.body.access_token as string;

    // requireMcpAuth fetches the authorization server's JWKS with the global fetch: route it to the host.
    const asFetched: string[] = [];
    vi.stubGlobal("fetch", async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = input instanceof Request ? input.url : String(input);
      asFetched.push(url);
      if (url !== `${ISSUER}/jwks`) throw new Error(`unexpected fetch ${url}`);
      return h.auth.handler(new Request(url, { method: "GET", ...(init?.headers ? { headers: init.headers } : {}) }));
    });

    const seen: Record<string, unknown>[] = [];
    const tool = async (_req: Request, claims: Record<string, unknown>) => {
      seen.push(claims);
      return Response.json({ ok: true });
    };
    const call = (handler: (req: Request) => Promise<Response>, token = accessToken) => handler(new Request(MCP_RESOURCE, { method: "POST", headers: { authorization: `Bearer ${token}` }, body: "{}" }));

    const right = await call(requireMcpAuth(h.auth, tool, { resource: MCP_RESOURCE }));
    expect(right.status, await right.clone().text()).toBe(200);
    expect(seen[0]).toMatchObject({ sub: user.id, aud: MCP_RESOURCE, iss: ISSUER, scope: "read" });

    const wrong = await call(requireMcpAuth(h.auth, tool, { resource: "http://localhost:3000/other-mcp" }));
    expect(wrong.status).toBe(401);
    expect(wrong.headers.get("www-authenticate")).toMatch(/Bearer/);
    // A tampered token is rejected too: the check is real.
    const tampered = await call(requireMcpAuth(h.auth, tool, { resource: MCP_RESOURCE }), `${accessToken.slice(0, -4)}AAAA`);
    expect(tampered.status).toBe(401);
    expect(seen).toHaveLength(1);
    expect(asFetched.every((u) => u === `${ISSUER}/jwks`)).toBe(true);
  });
});
