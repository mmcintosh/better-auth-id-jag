// The example IdP's policy (examples/workers/enterprise-idp/src/auth.ts): the MCP server's audience as before, and the
// public tester's when TESTER_AS_ISSUER and TESTER_RESOURCE are set, each only for clients registered for it.
import { describe, expect, it } from "vitest";
import { type Env, policy } from "../../examples/workers/enterprise-idp/src/auth";

const MCP_AS = "https://mcp.example.net/api/auth";
const MCP_RESOURCE = "https://mcp.example.net/mcp";
const TESTER_AS = "https://tester.example.net/api/auth";
const TESTER_RESOURCE = "https://tester.example.net/mcp";
const env = { MCP_AS_ISSUER: MCP_AS, MCP_RESOURCE, WRITERS: "writer@example.com", TESTER_AS_ISSUER: TESTER_AS, TESTER_RESOURCE } as Env;

const user = (email = "reader@example.com") => ({ id: "u1", email, emailVerified: true, name: "u", createdAt: new Date(), updatedAt: new Date() });
const mcpClient = (agent = true) => ({ clientId: "c-mcp", metadata: { clientIdAtResource: "id-at-mcp", agent } });
const testerClient = (agent = true) => ({ clientId: "c-tester", metadata: { clientIdAtResource: "id-at-tester", agent, for: "tester" } });
const decide = (e: Env, audience: string, client: ReturnType<typeof mcpClient> | ReturnType<typeof testerClient>, resource?: string, email?: string) =>
  policy(e)({ audience, resource, client, user: user(email) });

describe("example IdP policy", () => {
  it("the MCP server: read, write for WRITERS, the client's id there, act for an agent only", () => {
    expect(decide(env, MCP_AS, mcpClient())).toEqual({ decision: "allow", scopes: ["read"], resource: MCP_RESOURCE, clientIdAtResource: "id-at-mcp", claims: { email: true, act: { sub_profile: "ai_agent" } } });
    expect(decide(env, MCP_AS, mcpClient(), MCP_RESOURCE, "writer@example.com")).toMatchObject({ decision: "allow", scopes: ["read", "write"] });
    expect(decide(env, MCP_AS, mcpClient(false))).toMatchObject({ decision: "allow", claims: { email: true } });
    expect(decide(env, MCP_AS, mcpClient(false))).not.toHaveProperty("claims.act");
    expect(decide(env, MCP_AS, mcpClient(), "https://mcp.example.net/other")).toMatchObject({ decision: "unknown_resource" });
  });

  it("the tester: read only, even for WRITERS, its resource, the registration's client id, act for an agent", () => {
    expect(decide(env, TESTER_AS, testerClient(), undefined, "writer@example.com")).toEqual({ decision: "allow", scopes: ["read"], resource: TESTER_RESOURCE, clientIdAtResource: "id-at-tester", claims: { email: true, act: { sub_profile: "ai_agent" } } });
    expect(decide(env, TESTER_AS, testerClient(), TESTER_RESOURCE)).toMatchObject({ decision: "allow" });
    expect(decide(env, TESTER_AS, testerClient(), MCP_RESOURCE)).toMatchObject({ decision: "unknown_resource" });
  });

  it("a client registered for one audience gets nothing for the other", () => {
    expect(decide(env, TESTER_AS, mcpClient())).toMatchObject({ decision: "deny", reason: "client not registered for the tester" });
    expect(decide(env, MCP_AS, testerClient())).toMatchObject({ decision: "deny", reason: "client not registered at the MCP server" });
  });

  it("without TESTER_AS_ISSUER and TESTER_RESOURCE both set, the tester's audience is unknown", () => {
    const without = (key: "TESTER_AS_ISSUER" | "TESTER_RESOURCE"): Env => {
      const e = { ...env };
      delete e[key];
      return e;
    };
    for (const e of [without("TESTER_AS_ISSUER"), without("TESTER_RESOURCE")]) expect(decide(e, TESTER_AS, testerClient())).toMatchObject({ decision: "unknown_audience" });
    expect(decide(env, "https://elsewhere.example.net", mcpClient())).toMatchObject({ decision: "unknown_audience" });
  });
});
