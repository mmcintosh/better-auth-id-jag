// The client plugin: registry routes typed from the server plugin, over HTTP to a real host.
import { createAuthClient } from "better-auth/client";
import { describe, expect, it } from "vitest";
import { idJagIssuerClient } from "../../src/issuer/client";
import { BASE, createIssuerHost, signUp } from "../support/issuer-host";

describe("idJagIssuerClient", () => {
  it("creates and lists resource servers and policies with typed calls", async () => {
    const isAdmin = ({ user }: { user: Record<string, unknown> }) => user.role === "admin";
    // Blocks have their own access decision (D-B24): without blocks.canManage their routes aren't mounted.
    const host = await createIssuerHost({ issuer: { registry: { enabled: true, canManage: isAdmin, cacheSeconds: 0 }, blocks: { canManage: isAdmin } } });
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

    // Blocks: create, list, get, delete; create-from-jti answers 404 for an unknown jti.
    const userId = `user-${crypto.randomUUID()}`;
    const block = await client.idJag.blocks.create({ block: { userId, reason: "lost laptop" } });
    expect(block.error).toBeNull();
    const blockId = block.data?.block.id as string;
    expect(block.data?.block).toMatchObject({ userId, clientId: null, audience: null, active: true });
    expect((await client.idJag.blocks({ query: { userId } })).data?.blocks.map((b) => b.id)).toEqual([blockId]);
    expect((await client.idJag.blocks.get({ query: { id: blockId } })).data?.block.reason).toBe("lost laptop");
    const unknown = await client.idJag.blocks.createFromJti({ jti: "unknown", reason: "r" });
    expect(unknown.error?.status).toBe(404);
    expect(unknown.error?.message).toMatch(/enable auditLog/);
    expect((await client.idJag.blocks.delete({ id: blockId })).data).toEqual({ deleted: blockId });
    expect((await client.idJag.blocks.get({ query: { id: blockId } })).error?.status).toBe(404);
  });
});
