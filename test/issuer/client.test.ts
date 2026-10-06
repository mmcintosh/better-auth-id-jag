// The client plugin: registry routes typed from the server plugin, over HTTP to a real host.
import { createAuthClient } from "better-auth/client";
import { describe, expect, it } from "vitest";
import { idJagIssuerClient } from "../../src/issuer/client";
import { BASE, createIssuerHost, signUp } from "../support/issuer-host";

describe("idJagIssuerClient", () => {
  it("creates and lists resource servers and policies with typed calls", async () => {
    const host = await createIssuerHost({ issuer: { registry: { enabled: true, canManage: ({ user }) => user.role === "admin", cacheSeconds: 0 } } });
    const admin = await signUp(host, { role: "admin" });
    const client = createAuthClient({
      baseURL: `${BASE}/api/auth`,
      plugins: [idJagIssuerClient()],
      fetchOptions: {
        customFetchImpl: (input, init) => {
          const req = new Request(input, init);
          req.headers.set("cookie", admin.browser.cookie);
          req.headers.set("origin", BASE);
          return host.auth.handler(req);
        },
      },
    });
    const audience = `https://rs-${crypto.randomUUID()}.example`;
    const created = await client.idJag.resourceServers.create({ resourceServer: { audience, name: "rs", scopes: ["read"] } });
    expect(created.error).toBeNull();
    const id = created.data?.resourceServer.id as string;
    const policy = await client.idJag.policies.create({ policy: { resourceServerId: id, name: "p", subjectKind: "everyone", clientIds: ["c"], scopes: ["read"] } });
    expect(policy.data?.policy.valid).toBe(true);
    const listed = await client.idJag.resourceServers();
    expect(listed.data?.resourceServers.map((r) => r.id)).toContain(id);
    const got = await client.idJag.resourceServers.get({ query: { id } });
    expect(got.data?.resourceServer.config?.audience).toBe(audience);
  });
});
