// Interop, live: identity-provider.net ("ZipIdP", a stub IdP for testing Cross App Access, listed on
// xaa.rocks) as the issuer → our receiver. A real, independent ID-JAG issuer on the internet: the test
// makes a fresh sandbox there (no account: a cookie), registers our receiver's authorization server,
// the MCP resource and an agent client, signs a user in (any username and 6-digit code), and exchanges
// the ID token, then the refresh token, for ID-JAGs. Our receiver runs in-process; the only thing it
// fetches is ZipIdP's real JWKS. Every record the test made is deleted afterwards (a sandbox itself
// can't be). Gated: INTEROP_ZIPIDP=1, Node only (docs/interop.md).
import { createLocalJWKSet, jwtVerify } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { decodeJwtPart, type McpHost, mcpClient, mcpHost, redeemAt } from "../support/interop-hosts";

const env = typeof process !== "undefined" ? process.env : {};
const enabled = env?.INTEROP_ZIPIDP === "1" && navigator.userAgent !== "Cloudflare-Workers";
const ZIP = env?.INTEROP_ZIPIDP_URL || "https://identity-provider.net";
const REDIRECT = "http://localhost:9/cb"; // never called: the code is read from the redirect
const ID_JAG_TYPE = "urn:ietf:params:oauth:token-type:id-jag";

/** A browser on ZipIdP: its cookies (the sandbox), redirects by hand, forms read from the HTML. */
class Sandbox {
  private cookies = new Map<string, string>();
  readonly made: string[] = [];

  async request(path: string, form?: Record<string, string> | [string, string][]): Promise<{ status: number; location: string; html: string }> {
    const res = await fetch(new URL(path, ZIP), {
      method: form ? "POST" : "GET",
      redirect: "manual",
      headers: { cookie: [...this.cookies].map(([k, v]) => `${k}=${v}`).join("; "), ...(form ? { "content-type": "application/x-www-form-urlencoded" } : {}) },
      ...(form ? { body: new URLSearchParams(form) } : {}),
    });
    for (const c of res.headers.getSetCookie()) {
      const [pair] = c.split(";");
      const at = pair?.indexOf("=") ?? -1;
      if (pair && at > 0) this.cookies.set(pair.slice(0, at), pair.slice(at + 1));
    }
    return { status: res.status, location: res.headers.get("location") ?? "", html: await res.text() };
  }

  /** The CSRF token of a page's first form that has one (some forms have none). */
  static csrf(html: string): Record<string, string> {
    const m = html.match(/name="csrf" value="([^"]*)"/);
    return m?.[1] ? { csrf: m[1] } : {};
  }

  /** Every field of the form posting to `action` as the page has it, then `set` applied (for edits). */
  static fields(html: string, action: string, set: Record<string, string>): [string, string][] {
    const form = [...html.matchAll(/<form[\s\S]*?<\/form>/g)].map((m) => m[0]).find((f) => f.includes(`action="${action}"`)) ?? "";
    const out: [string, string][] = [];
    const attr = (tag: string, a: string) => tag.match(new RegExp(`${a}="([^"]*)"`))?.[1];
    for (const [tag] of form.matchAll(/<input[^>]*>/g)) {
      const name = attr(tag, "name");
      const type = attr(tag, "type") ?? "text";
      if (!name || name.includes("' + idx + '") || ((type === "checkbox" || type === "radio") && !/\bchecked\b/.test(tag))) continue;
      out.push([name, decode(attr(tag, "value") ?? "")]);
    }
    for (const m of form.matchAll(/<textarea[^>]*name="([^"]*)"[^>]*>([\s\S]*?)<\/textarea>/g)) out.push([m[1] as string, decode(m[2] ?? "")]);
    for (const m of form.matchAll(/<select[^>]*name="([^"]*)"([\s\S]*?)<\/select>/g)) {
      if ((m[1] as string).includes("' + idx + '")) continue;
      out.push([m[1] as string, m[2]?.match(/<option value="([^"]*)"[^>]*selected/)?.[1] ?? ""]);
    }
    const kept = out.filter(([k]) => !(k in set));
    return [...kept, ...Object.entries(set)];
  }

  /** Create a record from its "new" form; returns its id (the newest edit link on the list). */
  async create(kind: "resource-as" | "resources" | "clients", form: Record<string, string> | [string, string][]): Promise<string> {
    const page = await this.request(`/admin/${kind}/new`);
    const r = await this.request(`/admin/${kind}`, [...Object.entries(Sandbox.csrf(page.html)), ...(Array.isArray(form) ? form : Object.entries(form))]);
    expect(r.status, r.html.slice(0, 500)).toBe(302);
    const ids = [...(await this.request(`/admin/${kind}`)).html.matchAll(new RegExp(`/admin/${kind}/(\\d+)/edit`, "g"))].map((m) => Number(m[1]));
    const id = String(Math.max(...ids));
    this.made.unshift(`/admin/${kind}/${id}`);
    return id;
  }

  async edit(kind: "resource-as" | "clients", id: string, set: Record<string, string>) {
    const page = await this.request(`/admin/${kind}/${id}/edit`);
    const r = await this.request(`/admin/${kind}/${id}`, Sandbox.fields(page.html, `/admin/${kind}/${id}`, set));
    expect(r.status, r.html.slice(0, 500)).toBe(302);
  }

  async cleanup() {
    for (const path of this.made) {
      const list = await this.request(path.replace(/\/\d+$/, ""));
      expect((await this.request(`${path}/delete`, Sandbox.csrf(list.html))).status, `delete ${path}`).toBe(302);
    }
  }
}

const decode = (s: string) => s.replace(/&quot;/g, '"').replace(/&#0?39;/g, "'").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&");
const b64url = (b: ArrayBuffer) => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

interface World {
  zip: Sandbox;
  h: McpHost;
  receiverClient: { client_id: string; client_secret: string };
  agent: { client_id: string; client_secret: string };
  rasId: string;
  agentId: string;
  tokens: { id_token: string; refresh_token: string };
}

/** Sign a user in at ZipIdP (authorization code + PKCE) as the agent; returns its ID token and refresh token. */
async function signIn(zip: Sandbox, agent: World["agent"]) {
  const verifier = b64url(crypto.getRandomValues(new Uint8Array(32)).buffer);
  const challenge = b64url(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)));
  const q = new URLSearchParams({ response_type: "code", client_id: agent.client_id, redirect_uri: REDIRECT, scope: "openid email profile offline_access", state: "s", nonce: "n", code_challenge: challenge, code_challenge_method: "S256" });
  let r = await zip.request(`/authorize?${q}`);
  for (let i = 0; i < 8 && !r.location.startsWith(REDIRECT); i++) {
    if (r.location) r = await zip.request(r.location);
    else if (r.html.includes('action="/login"')) {
      const ret = decode(r.html.match(/name="return" value="([^"]*)"/)?.[1] ?? "");
      r = await zip.request("/login", { ...Sandbox.csrf(r.html), return: ret, username: "idjag-interop", code: "123456" });
    } else if (r.html.includes('action="/authorize"')) {
      r = await zip.request("/authorize", Sandbox.fields(r.html, "/authorize", {}));
    } else throw new Error(`stuck signing in: ${r.status} ${r.html.slice(0, 300)}`);
  }
  const code = new URL(r.location).searchParams.get("code");
  expect(code, r.location).toBeTruthy();
  const tok = await fetch(`${ZIP}/token`, {
    method: "POST",
    headers: { authorization: `Basic ${btoa(`${agent.client_id}:${agent.client_secret}`)}`, "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "authorization_code", code: code as string, redirect_uri: REDIRECT, code_verifier: verifier }),
  });
  const body = (await tok.json()) as Record<string, string>;
  expect(tok.status, JSON.stringify(body)).toBe(200);
  return body as { id_token: string; refresh_token: string };
}

/** The agent's token exchange at ZipIdP: a subject token for an ID-JAG to our receiver. */
async function exchange(w: World, subject: "id_token" | "refresh_token") {
  const res = await fetch(`${ZIP}/token`, {
    method: "POST",
    headers: { authorization: `Basic ${btoa(`${w.agent.client_id}:${w.agent.client_secret}`)}`, "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
      subject_token: w.tokens[subject],
      subject_token_type: `urn:ietf:params:oauth:token-type:${subject}`,
      requested_token_type: ID_JAG_TYPE,
      audience: w.h.issuerUrl,
      resource: w.h.resource,
      scope: "read",
    }),
  });
  const body = (await res.json()) as Record<string, unknown>;
  expect(res.status, JSON.stringify(body)).toBe(200);
  expect(body).toMatchObject({ issued_token_type: ID_JAG_TYPE, token_type: "N_A" });
  return body.access_token as string;
}

let w: World;
const refusedReason = () => w.h.refused.at(-1)?.reason;

describe.skipIf(!enabled)("interop, live: identity-provider.net (ZipIdP) issuer → our receiver", () => {
  beforeAll(async () => {
    const zip = new Sandbox();
    const signup = await zip.request("/signup");
    expect((await zip.request("/signup", Sandbox.csrf(signup.html))).status).toBe(302);
    // Our receiver, in-process; its audience at ZipIdP is its issuer, which ZipIdP never calls.
    const base = "https://mcp.zipidp-interop.example";
    const h = await mcpHost({ base, resource: `${base}/mcp`, receiver: { trustedIssuers: [{ issuer: ZIP, jwksUri: `${ZIP}/jwks`, jitProvisioning: { trustEmailVerified: true } }] } });
    const receiverClient = await mcpClient(h);
    const rasId = await zip.create("resource-as", { name: "idjag-interop-receiver", audience: h.issuerUrl, id_jag_signed_response_alg: "RS256", emit_email: "1", email_source: "email" });
    await zip.create("resources", { name: "idjag-interop-mcp", resource_uri: h.resource, resource_as_id: rasId, scopes_supported: "read write" });
    const form = (await zip.request("/admin/clients/new")).html;
    const agent = { client_id: decode(form.match(/name="client_id"[^>]*value="([^"]*)"/)?.[1] ?? ""), client_secret: decode(form.match(/name="client_secret"[^>]*value="([^"]*)"/)?.[1] ?? "") };
    // The agent: authorization code, token exchange and refresh tokens, the ID-JAG profile, and its
    // connection to our receiver (our issuer as the audience → the client id our receiver gave it).
    const agentId = await zip.create("clients", [
      ["name", "idjag-interop-agent"],
      ["client_id", agent.client_id],
      ["client_secret", agent.client_secret],
      ["token_endpoint_auth_method", "client_secret_basic"],
      ["client_key_source", "paste"],
      ["redirect_uris", REDIRECT],
      ["grant_types[]", "authorization_code"],
      ["grant_types[]", "urn:ietf:params:oauth:grant-type:token-exchange"],
      ["grant_types[]", "refresh_token"],
      ["authorization_grant_profiles[]", "urn:ietf:params:oauth:grant-profile:id-jag"],
      ["allowed_audiences[0][audience]", h.issuerUrl],
      ["allowed_audiences[0][client_id]", receiverClient.client_id],
      ["id_token_signed_response_alg", "RS256"],
    ]);
    const tokens = await signIn(zip, agent);
    w = { zip, h, receiverClient, agent, rasId, agentId, tokens };
  });
  afterAll(async () => {
    await w?.zip.cleanup();
  });

  it("an ID token → ZipIdP's ID-JAG → our access token; the same ID-JAG again is refused (replay)", async () => {
    const jag = await exchange(w, "id_token");
    expect(decodeJwtPart(jag, 0)).toMatchObject({ typ: "oauth-id-jag+jwt", alg: "RS256" });
    const claims = decodeJwtPart(jag, 1);
    expect(claims).toMatchObject({ iss: ZIP, aud: w.h.issuerUrl, client_id: w.receiverClient.client_id, resource: w.h.resource, scope: "read" });
    expect((claims.exp as number) - (claims.iat as number)).toBeLessThanOrEqual(300);
    console.log(`[zipidp] ID-JAG claims: ${Object.keys(claims).sort().join(", ")}`);
    const r = await redeemAt(w.h, w.receiverClient, jag);
    expect(r.status, r.text).toBe(200);
    const keys = (await (await w.h.auth.handler(new Request(`${w.h.issuerUrl}/jwks`))).json()) as Parameters<typeof createLocalJWKSet>[0];
    const at = await jwtVerify(r.body.access_token as string, createLocalJWKSet(keys), { issuer: w.h.issuerUrl, audience: w.h.resource });
    expect(at.payload).toMatchObject({ scope: "read", idjag: { iss: ZIP, jti: claims.jti } });
    expect((await redeemAt(w.h, w.receiverClient, jag)).status).toBe(400);
    expect(refusedReason()).toBe("replay");
  });

  it("a refresh token as the subject token → the same local user", async () => {
    const first = w.h.accepted.at(-1)?.userId;
    const r = await redeemAt(w.h, w.receiverClient, await exchange(w, "refresh_token"));
    expect(r.status, r.text).toBe(200);
    expect(w.h.accepted.at(-1)?.userId).toBe(first);
  });

  it("refused: the connection names another client id (client_mismatch)", async () => {
    await w.zip.edit("clients", w.agentId, { "allowed_audiences[0][audience]": w.h.issuerUrl, "allowed_audiences[0][client_id]": "another-client" });
    try {
      const jag = await exchange(w, "id_token");
      expect(decodeJwtPart(jag, 1).client_id).toBe("another-client");
      expect((await redeemAt(w.h, w.receiverClient, jag)).status).toBe(400);
      expect(refusedReason()).toBe("client_mismatch");
    } finally {
      await w.zip.edit("clients", w.agentId, { "allowed_audiences[0][audience]": w.h.issuerUrl, "allowed_audiences[0][client_id]": w.receiverClient.client_id });
    }
  });

  it("refused: an ID-JAG signed with ML-DSA-65, which ZipIdP offers (disallowed_alg); its mixed RS256 + ML-DSA JWKS is fine for RS256", async () => {
    await w.zip.edit("resource-as", w.rasId, { id_jag_signed_response_alg: "ML-DSA-65" });
    try {
      const jag = await exchange(w, "id_token");
      expect(decodeJwtPart(jag, 0).alg).toBe("ML-DSA-65");
      expect((await redeemAt(w.h, w.receiverClient, jag)).status).toBe(400);
      expect(refusedReason()).toBe("disallowed_alg");
    } finally {
      await w.zip.edit("resource-as", w.rasId, { id_jag_signed_response_alg: "RS256" });
    }
  });
});
