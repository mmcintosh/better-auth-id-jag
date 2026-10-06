// Phase 0: do extension grants registered through extendOAuthProvider run under both oauthProvider()
// and mcp()? Each assertion below names the guard it proves; docs/phase-0.md records each one broken.
import { createLocalJWKSet, decodeProtectedHeader, jwtVerify } from "jose";
import { describe, expect, it } from "vitest";
import { betterAuth, type BetterAuthPlugin } from "better-auth";
import { jwt } from "better-auth/plugins";
import { oauthProvider } from "@better-auth/oauth-provider";
import { BASE, createClient, createHost, ISSUER, MCP_RESOURCE, seed, tokenRequest } from "./support/hosts";
import { PING_GRANT, PING_METADATA_FIELD, ping, type PingObservation } from "./support/ping";

for (const kind of ["oauth-provider", "mcp"] as const) {
  describe(`extension grant under ${kind}()`, () => {
    it("dispatches, authenticates the client, issues tokens, and signs an ID-JAG with jwt()'s key", async () => {
      const seen: PingObservation[] = [];
      const auth = await createHost(kind, { observe: (s: PingObservation) => seen.push(s) });
      const client = await seed(auth, [PING_GRANT]);
      const res = await auth.handler(
        tokenRequest({ grant_type: PING_GRANT, username: "ada@example.com", ...(kind === "mcp" ? { resource: MCP_RESOURCE } : {}) }, { id: client.client_id, secret: client.client_secret }),
      );
      const body = (await res.json()) as Record<string, unknown>;
      expect(res.status, JSON.stringify(body)).toBe(200);
      expect(body.access_token).toBeTypeOf("string");
      expect(body.scope).toBe("read");

      // The ID-JAG: typ header, verified against the host's own JWKS.
      const idJag = body.id_jag as string;
      expect(decodeProtectedHeader(idJag).typ).toBe("oauth-id-jag+jwt");
      expect(decodeProtectedHeader(idJag).kid).toBeTypeOf("string");
      const jwks = (await (await auth.handler(new Request(`${BASE}/api/auth/jwks`))).json()) as { keys: never[] };
      const { payload, protectedHeader } = await jwtVerify(idJag, createLocalJWKSet(jwks), { typ: "oauth-id-jag+jwt", issuer: ISSUER, audience: "https://receiver.example" });
      expect(protectedHeader.alg).toBe("EdDSA");
      expect(payload.client_id).toBe(client.client_id);

      // mcp() puts its `resource` in opts.resources, so an extension sees it there.
      if (kind === "mcp") {
        expect(seen[0]?.resources).toContain(MCP_RESOURCE);
        expect(seen[0]?.ssoProviderReachable).toBe(true);
        // The access token is a JWT audience-bound to the MCP resource.
        const at = await jwtVerify(body.access_token as string, createLocalJWKSet(jwks), { issuer: ISSUER, audience: MCP_RESOURCE });
        expect(at.payload.client_id).toBe(client.client_id);
      }
    });

    it("refuses the grant without client credentials, with a wrong secret, and for a client not registered for it", async () => {
      const auth = await createHost(kind);
      const client = await seed(auth, [PING_GRANT]);
      const none = await auth.handler(tokenRequest({ grant_type: PING_GRANT, client_id: client.client_id, username: "ada@example.com" }));
      // 400, not 401: the provider answers a missing credential with invalid_client over 400.
      expect(none.status).toBe(400);
      expect(((await none.json()) as { error: string }).error).toBe("invalid_client");
      const wrong = await auth.handler(tokenRequest({ grant_type: PING_GRANT, username: "ada@example.com" }, { id: client.client_id, secret: "nope" }));
      expect(((await wrong.json()) as { error: string }).error).toBe("invalid_client");

      const other = await createClient(auth, client.headers, ["client_credentials"]);
      const unauthorized = await auth.handler(tokenRequest({ grant_type: PING_GRANT, username: "ada@example.com" }, { id: other.client_id, secret: other.client_secret }));
      expect(((await unauthorized.json()) as { error: string }).error).toBe("unauthorized_client");
    });

    it("refuses a public client (token_endpoint_auth_method none) registered for the grant: requireCredentials", async () => {
      const auth = await createHost(kind);
      const { headers } = await seed(auth, [PING_GRANT]);
      const api = auth.api as unknown as { adminCreateOAuthClient: (o: { headers: Headers; body: Record<string, unknown> }) => Promise<{ client_id: string }> };
      const pub = await api.adminCreateOAuthClient({
        headers,
        body: { client_name: "public", redirect_uris: ["https://app.example/cb"], grant_types: [PING_GRANT], token_endpoint_auth_method: "none", scope: "read", application_type: "native" },
      });
      const res = await auth.handler(tokenRequest({ grant_type: PING_GRANT, client_id: pub.client_id, username: "ada@example.com", ...(kind === "mcp" ? { resource: MCP_RESOURCE } : {}) }));
      const body = (await res.json()) as { error?: string };
      expect(body.error, JSON.stringify(body)).toBe("invalid_client");
    });

    it("advertises the grant in grant_types_supported and the metadata field in both discovery documents", async () => {
      const auth = await createHost(kind);
      const checked: string[] = [];
      for (const path of ["/.well-known/oauth-authorization-server/api/auth", "/.well-known/openid-configuration/api/auth", "/api/auth/.well-known/openid-configuration"]) {
        const res = await auth.handler(new Request(`${BASE}${path}`));
        if (res.status === 404) continue;
        const doc = (await res.json()) as Record<string, unknown>;
        expect(res.status, path).toBe(200);
        expect(doc.grant_types_supported, path).toContain(PING_GRANT);
        expect(doc[PING_METADATA_FIELD], path).toBe(true);
        checked.push(path);
      }
      // The helpers a host mounts at the origin root give the same.
      const api = auth.api as unknown as Record<string, (o: object) => Promise<Record<string, unknown>>>;
      for (const name of ["getOAuthServerConfig", "getOpenIdConfig"]) {
        if (!api[name]) continue;
        const doc = await api[name]({});
        expect(doc.grant_types_supported, name).toContain(PING_GRANT);
        expect(doc[PING_METADATA_FIELD], name).toBe(true);
        checked.push(name);
      }
      console.log(`[phase-0] ${kind} discovery documents checked:`, checked);
      expect(checked.length).toBeGreaterThanOrEqual(2);
    });
  });
}

// oauthProvider() written inline in `plugins` fails to typecheck under exactOptionalPropertyTypes
// (its endpoints' openapi `items?: undefined` vs OpenAPIParameter); through a variable it doesn't.
// Recorded in docs/phase-0.md.
const provider = () => oauthProvider({ loginPage: "/login", consentPage: "/consent" }) as unknown as BetterAuthPlugin;

describe("two extensions registering the same grant type (plan Question 7)", () => {
  it("fails at startup, naming the grant type", async () => {
    const auth = betterAuth({
      baseURL: BASE,
      secret: "test-secret-that-is-at-least-32-characters-long",
      telemetry: { enabled: false },
      plugins: [jwt(), provider(), ping(), ping({ id: "ping-2" })],
    });
    await expect(auth.$context).rejects.toThrow(/grant type.*urn:example:ping|urn:example:ping.*grant type/i);
  });

  it("refuses a key that is not an absolute URI, so built-in grants cannot be shadowed", async () => {
    const auth = betterAuth({
      baseURL: BASE,
      secret: "test-secret-that-is-at-least-32-characters-long",
      telemetry: { enabled: false },
      plugins: [jwt(), provider(), ping({ grantType: "client_credentials" })],
    });
    const outcome = await auth.$context.then(
      () => "accepted",
      (e: Error) => `rejected: ${e.message}`,
    );
    expect(outcome).toMatch(/must be an absolute URI: client_credentials/);
  });
});

describe("desk check: a CIMD client authenticating with private_key_jwt (receiver step 1)", () => {
  it("reaches the extension grant as an authenticated confidential client", async () => {
    const { exportJWK, generateKeyPair, SignJWT } = await import("jose");
    const { publicKey, privateKey } = await generateKeyPair("ES256");
    const clientId = "https://client.example/oauth/metadata.json";
    const doc = {
      client_id: clientId,
      client_name: "CIMD spike",
      redirect_uris: ["https://client.example/cb"],
      grant_types: [PING_GRANT],
      response_types: [],
      token_endpoint_auth_method: "private_key_jwt",
      jwks: { keys: [{ ...(await exportJWK(publicKey)), kid: "k1", alg: "ES256", use: "sig" }] },
      scope: "read",
    };
    const fetched: string[] = [];
    const auth = await createHost("mcp", {
      fetchClientMetadata: async (input) => {
        fetched.push(String(input));
        return new Response(JSON.stringify(doc), { headers: { "content-type": "application/json", "cache-control": "max-age=60" } });
      },
    });
    await auth.api.signUpEmail({ body: { email: "ada@example.com", password: "password-1234", name: "Ada" } });
    const assertion = async () =>
      new SignJWT({})
        .setProtectedHeader({ alg: "ES256", kid: "k1" })
        .setIssuer(clientId)
        .setSubject(clientId)
        .setAudience(`${ISSUER}/oauth2/token`)
        .setJti(crypto.randomUUID())
        .setIssuedAt()
        .setExpirationTime("2m")
        .sign(privateKey);
    const form = (a: string) => ({
      grant_type: PING_GRANT,
      username: "ada@example.com",
      resource: MCP_RESOURCE,
      client_id: clientId,
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      client_assertion: a,
    });
    const res = await auth.handler(tokenRequest(form(await assertion())));
    const body = (await res.json()) as Record<string, unknown>;
    expect(res.status, JSON.stringify(body)).toBe(200);
    expect(fetched).toEqual([clientId]);
    const idJag = await jwtVerify(body.id_jag as string, createLocalJWKSet((await (await auth.handler(new Request(`${BASE}/api/auth/jwks`))).json()) as never));
    expect(idJag.payload.client_id).toBe(clientId);

    // The same CIMD client with no assertion is refused (requireCredentials).
    const bare = await auth.handler(tokenRequest({ grant_type: PING_GRANT, username: "ada@example.com", client_id: clientId }));
    expect(((await bare.json()) as { error: string }).error).toBe("invalid_client");
    // A replayed assertion is refused (the provider's oauthClientAssertion table).
    const once = await assertion();
    expect((await auth.handler(tokenRequest(form(once)))).status).toBe(200);
    const replay = await auth.handler(tokenRequest(form(once)));
    expect(((await replay.json()) as { error: string }).error).toBe("invalid_client");
  });
});

describe("mcp() serves its protected resource metadata beside the extension", () => {
  it("lists the authorization server and the resource", async () => {
    const auth = await createHost("mcp");
    const res = await auth.handler(new Request(`${BASE}/.well-known/oauth-protected-resource/mcp`));
    const doc = (await res.json()) as Record<string, unknown>;
    expect(res.status, JSON.stringify(doc)).toBe(200);
    expect(doc.resource).toBe(MCP_RESOURCE);
    expect(doc.authorization_servers).toContain(ISSUER);
  });
});
