// Interop: MCPJam's Cross App Access debugger (@mcpjam/sdk, the engine behind `mcpjam xaa run`) → our
// receiver. MCPJam plays the enterprise IdP (it mints and signs the ID-JAG) and the AI agent (it
// redeems the ID-JAG and calls the MCP server with the access token), and has a negative mode for each
// check a receiver must make. Not a dependency of this package: install it in a directory of your own
// and point the test at it (docs/interop.md has the commands). Gated: INTEROP_MCPJAM=1 and
// INTEROP_MCPJAM_DIR, Node only.
//
// Everything is on one machine: our receiver and a minimal MCP endpoint are served over real HTTP on
// 127.0.0.1, and so are MCPJam's issuer metadata and JWKS (MCPJam checks that its issuer publishes its
// signing key before it sends anything). Our receiver only takes an https jwksUri, so the trust entry
// names one and the receiver's `fetch` answers it with the same key.
import { createLocalJWKSet, exportJWK, importSPKI, jwtVerify } from "jose";
import { afterAll, describe, expect, it } from "vitest";
import type { ReasonCode } from "../../src/core";
import type { StaticTrustedIssuer } from "../../src/receiver";
import { type McpHost, mcpClient, mcpHost } from "../support/interop-hosts";
import type { Served } from "../support/interop-http";

const env = typeof process !== "undefined" ? process.env : {};
const enabled = env?.INTEROP_MCPJAM === "1" && !!env?.INTEROP_MCPJAM_DIR && navigator.userAgent !== "Cloudflare-Workers";
const JWKS_URI = "https://mcpjam-issuer.test/jwks";
const PERSISTENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";

type Mode =
  | "valid"
  | "bad_signature"
  | "wrong_audience"
  | "expired"
  | "missing_claims"
  | "invalid_type_header"
  | "wrong_issuer"
  | "resource_mismatch"
  | "client_id_mismatch"
  | "unknown_kid"
  | "unknown_sub"
  | "scope_denial";

interface FlowResult {
  completed: boolean;
  steps: { step: string; ok: boolean; detail?: string }[];
  idJag?: { claims?: Record<string, unknown> };
  redemption?: { status?: number };
  mcp?: { status?: number; ok?: boolean };
  authorizationServerCapabilities?: { idJagProfile?: string; jwtBearerGrant?: string };
  negativeProbe?: { mode: string; outcome: "rejected" | "accepted" | "inconclusive" };
}
type RunXaaFlow = (config: Record<string, unknown>) => Promise<FlowResult>;

/**
 * Each attack MCPJam makes, and the reason our receiver must refuse it with. `expired`: MCPJam's
 * expired ID-JAG also lives 3600 s, so the lifetime cap (900 s) refuses it before `exp` is checked;
 * the `exp` check itself is covered in test/core. `unknown_kid` is a signature MCPJam's issuer JWKS
 * has no key for: `bad_signature`.
 */
const ATTACKS: Record<Exclude<Mode, "valid" | "unknown_sub">, ReasonCode> = {
  bad_signature: "bad_signature",
  wrong_audience: "wrong_audience",
  expired: "lifetime_too_long",
  missing_claims: "missing_claim",
  invalid_type_header: "wrong_typ",
  wrong_issuer: "untrusted_issuer",
  resource_mismatch: "unknown_resource",
  client_id_mismatch: "client_mismatch",
  unknown_kid: "bad_signature",
  scope_denial: "no_scope",
};

const servers: Served[] = [];
afterAll(async () => {
  for (const s of servers) await s.close();
});

async function sdk(): Promise<RunXaaFlow> {
  // MCPJam reads its signing key from XAA_IDP_KEY_DIR, and sends usage telemetry unless told not to.
  env.DO_NOT_TRACK = "1";
  env.MCPJAM_TELEMETRY_DISABLED = "1";
  const { join } = await import("node:path");
  const mod = (await import(/* @vite-ignore */ join(env.INTEROP_MCPJAM_DIR as string, "node_modules/@mcpjam/sdk/dist/index.js"))) as { runXaaFlow: RunXaaFlow };
  return mod.runXaaFlow;
}

/** MCPJam's issuer key, written once where MCPJam reads it; its public JWK (kid `xaa-idp-1`, as MCPJam signs). */
let key: Promise<Record<string, unknown>> | undefined;
const issuerKey = () => (key ??= writeIssuerKey());
async function writeIssuerKey() {
  const [{ generateKeyPairSync }, { mkdtempSync, writeFileSync }, { tmpdir }, { join }] = await Promise.all([import("node:crypto"), import("node:fs"), import("node:os"), import("node:path")]);
  const dir = mkdtempSync(join(tmpdir(), "mcpjam-xaa-"));
  const pair = generateKeyPairSync("rsa", { modulusLength: 2048 });
  writeFileSync(join(dir, "xaa-idp-private.pem"), pair.privateKey.export({ type: "pkcs8", format: "pem" }));
  const publicPem = pair.publicKey.export({ type: "spki", format: "pem" }).toString();
  writeFileSync(join(dir, "xaa-idp-public.pem"), publicPem);
  env.XAA_IDP_KEY_DIR = dir;
  return { ...(await exportJWK(await importSPKI(publicPem, "RS256"))), kid: "xaa-idp-1", alg: "RS256", use: "sig" };
}

/** Our receiver over HTTP, with MCPJam's issuer and a minimal MCP endpoint on the same origin. */
async function world(trust: (issuer: string, asIssuer: string) => Omit<StaticTrustedIssuer, "issuer" | "jwksUri">) {
  const { listen } = await import("../support/interop-http");
  const server = await listen();
  servers.push(server);
  const base = `http://localhost:${server.port}`;
  const issuer = `${base}/api/mcp/xaa`;
  const jwk = await issuerKey();
  const jwks = () => Response.json({ keys: [jwk] });
  const h: McpHost = await mcpHost({
    base,
    resource: `${base}/mcp`,
    receiver: {
      trustedIssuers: [{ issuer, jwksUri: JWKS_URI, ...trust(issuer, `${base}/api/auth`) }],
      fetch: async (url) => {
        if (url === JWKS_URI) return jwks();
        throw new Error(`unexpected fetch: ${url}`);
      },
    },
  });
  server.use(async (r) => {
    const path = new URL(r.url).pathname;
    if (path.startsWith("/api/mcp/xaa/")) {
      if (path.endsWith("/jwks")) return jwks();
      return Response.json({ issuer, jwks_uri: `${issuer}/jwks`, id_token_signing_alg_values_supported: ["RS256"] });
    }
    if (path === "/mcp") return mcpEndpoint(h, r);
    return h.auth.handler(r);
  });
  const client = await mcpClient(h);
  return { base, issuer, h, client };
}

/** The resource: a bearer token from our authorization server, for this resource. Enough for `initialize`. */
async function mcpEndpoint(h: McpHost, r: Request): Promise<Response> {
  const challenge = { "WWW-Authenticate": `Bearer resource_metadata="${h.base}/.well-known/oauth-protected-resource/mcp"` };
  const token = r.headers.get("authorization")?.match(/^Bearer (.+)$/i)?.[1];
  const keys = (await (await h.auth.handler(new Request(`${h.issuerUrl}/jwks`))).json()) as Parameters<typeof createLocalJWKSet>[0];
  try {
    if (!token) throw new Error("no token");
    await jwtVerify(token, createLocalJWKSet(keys), { issuer: h.issuerUrl, audience: h.resource });
  } catch {
    return Response.json({ jsonrpc: "2.0", id: null, error: { code: -32001, message: "unauthorized" } }, { status: 401, headers: challenge });
  }
  const msg = (await r.json()) as { id?: unknown; method?: string; params?: { protocolVersion?: string } };
  if (msg.id === undefined) return new Response(null, { status: 202 });
  return Response.json({ jsonrpc: "2.0", id: msg.id, result: { protocolVersion: msg.params?.protocolVersion ?? "2025-11-25", capabilities: {}, serverInfo: { name: "id-jag-interop", version: "0" } } });
}

async function run(w: Awaited<ReturnType<typeof world>>, mode: Mode, format: "oidc" | "saml") {
  const runXaaFlow = await sdk();
  const before = w.h.refused.length;
  const r = await runXaaFlow({
    serverUrl: `${w.base}/mcp`,
    issuerBaseUrl: `${w.base}/api/mcp`,
    subject: `mcpjam-${format}-user`,
    email: `mcpjam-${format}@example.com`,
    clientId: w.client.client_id,
    clientSecret: w.client.client_secret,
    scope: "read",
    negativeTestMode: mode,
    identityAssertionFormat: format,
    subjectIdentifierFormat: format === "saml" ? "saml-nameid" : "oauth-sub",
    allowPrivateNetwork: true,
    timeoutMs: 15_000,
  });
  await w.h.settle();
  const reasons = w.h.refused.slice(before).map((e) => e.reason);
  console.log(`[mcpjam] ${format} ${mode}: redemption ${r.redemption?.status ?? "-"}, mcp ${r.mcp?.status ?? "-"}, probe ${r.negativeProbe?.outcome ?? "-"}, refused ${reasons.join(",") || "-"}`);
  return { r, reasons };
}

function expectValid(r: FlowResult) {
  expect(r.steps.filter((s) => !s.ok), JSON.stringify(r.steps)).toEqual([]);
  expect(r.completed).toBe(true);
  expect(r.redemption?.status).toBe(200);
  expect(r.mcp?.ok).toBe(true);
  // Capability evidence: our authorization server metadata advertises the grant and the ID-JAG profile.
  expect(r.authorizationServerCapabilities).toMatchObject({ idJagProfile: "advertised", jwtBearerGrant: "advertised" });
}

describe.skipIf(!enabled)("interop: MCPJam (@mcpjam/sdk) → our receiver", () => {
  describe("OIDC: an ID token at MCPJam's IdP, `sub` in the ID-JAG", () => {
    const jit = () => ({ jitProvisioning: { trustEmailVerified: true } });

    it("the whole flow: MCPJam's ID-JAG → our access token → MCP initialize", async () => {
      const w = await world(jit);
      const { r } = await run(w, "valid", "oidc");
      expectValid(r);
      expect(r.idJag?.claims).toMatchObject({ iss: w.issuer, aud: w.h.issuerUrl, client_id: w.client.client_id, resource: `${w.base}/mcp`, scope: "read" });
      expect(w.h.accepted.at(-1)).toMatchObject({ iss: w.issuer, clientId: w.client.client_id });
    });

    for (const [mode, reason] of Object.entries(ATTACKS)) {
      it(`refuses MCPJam's ${mode} ID-JAG (${reason})`, async () => {
        const w = await world(jit);
        const { r, reasons } = await run(w, mode as Mode, "oidc");
        expect(r.negativeProbe?.outcome).toBe("rejected");
        expect(reasons).toEqual([reason]);
      });
    }

    it("unknown_sub: provisioned just in time when the trust entry allows it, refused when it doesn't", async () => {
      const withJit = await world(jit);
      expect((await run(withJit, "unknown_sub", "oidc")).r.negativeProbe?.outcome).toBe("accepted");
      const without = await world(() => ({}));
      const { r, reasons } = await run(without, "unknown_sub", "oidc");
      // Without JIT MCPJam's baseline user is unknown too, so it stops before its probe; ours refused it.
      expect(r.negativeProbe?.outcome).not.toBe("accepted");
      expect(reasons).toEqual(["unknown_subject"]);
    });
  });

  describe("SAML: a SAML assertion at MCPJam's IdP, a saml-nameid `sub_id` in the ID-JAG", () => {
    // MCPJam's NameID namespace: its issuer as the SAML entity, persistent NameIDs, our AS as the SP.
    const saml = (issuer: string, asIssuer: string) => ({
      jitProvisioning: { trustEmailVerified: true },
      requireSubId: true,
      samlSubjects: [{ issuer, spNameQualifier: asIssuer, nameIdFormats: [PERSISTENT], accountProviderId: "mcpjam-saml" }],
    });

    it("the whole flow, the user resolved by NameID", async () => {
      const w = await world(saml);
      const { r } = await run(w, "valid", "saml");
      expectValid(r);
      expect(r.idJag?.claims?.sub_id).toMatchObject({ format: "saml-nameid", issuer: w.issuer, nameid: "mcpjam-saml-user", nameid_format: PERSISTENT });
      const account = await w.h.ctx.adapter.findOne<{ providerId: string; accountId: string }>({
        model: "account",
        where: [{ field: "providerId", value: "mcpjam-saml" }],
      });
      expect(account?.accountId).toBe("mcpjam-saml-user");
    });

    for (const [mode, reason] of Object.entries(ATTACKS)) {
      it(`refuses MCPJam's ${mode} ID-JAG (${reason})`, async () => {
        const w = await world(saml);
        const { r, reasons } = await run(w, mode as Mode, "saml");
        expect(r.negativeProbe?.outcome).toBe("rejected");
        expect(reasons).toEqual([reason]);
      });
    }

    it("unknown_sub: with JIT, an unknown NameID becomes a new user under its own NameID, not the known one", async () => {
      const w = await world(saml);
      const { r, reasons } = await run(w, "unknown_sub", "saml");
      expect(r.negativeProbe?.outcome).toBe("accepted");
      expect(reasons).toEqual([]);
      const accounts = await w.h.ctx.adapter.findMany<{ accountId: string; userId: string }>({ model: "account", where: [{ field: "providerId", value: "mcpjam-saml" }] });
      expect(accounts).toHaveLength(2);
      expect(new Set(accounts.map((a) => a.userId)).size).toBe(2);
    });
  });
});
