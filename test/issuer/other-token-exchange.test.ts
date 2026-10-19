// D-046: another token exchange beside ours. Requests this plugin doesn't serve go to `otherTokenExchange`; ID-JAG
// requests never do. tokenExchangeFrom() captures a plugin's token-exchange handler, or refuses what it would lose.
// On Better Auth 1.8 (the CI row), the same against the real oauthTokenExchange().
import type { BetterAuthPlugin } from "better-auth";
import * as oauthProviderModule from "@better-auth/oauth-provider";
import { extendOAuthProvider } from "@better-auth/oauth-provider";
import { describe, expect, it } from "vitest";
import { ID_JAG_TOKEN_TYPE, TOKEN_EXCHANGE_GRANT } from "../../src/core";
import { idJagIssuer, type TokenExchangeHandler, tokenExchangeFrom } from "../../src/issuer";
import type { AuthorizeResult } from "../../src/issuer";
import { basic, createClient, createIssuerHost, createSamlHost, exchange, getTokens, ISSUER, type IssuerHost, REFRESH_TOKEN_TYPE, setup, signUp, takeReasons } from "../support/issuer-host";

const ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";
const allow = (): AuthorizeResult => ({ decision: "allow", scopes: ["read"] });

/** A stand-in for another token exchange: records what reached it. */
function fakeOther() {
  const calls: Record<string, unknown>[] = [];
  const handler: TokenExchangeHandler = async ({ ctx }) => {
    calls.push({ ...(ctx.body as Record<string, unknown>) });
    return { access_token: "from-the-other-exchange", token_type: "Bearer", expires_in: 60, issued_token_type: ACCESS_TOKEN_TYPE } as never;
  };
  return { calls, handler };
}

async function hostWithOther(extra: Parameters<typeof createIssuerHost>[0] = {}) {
  const other = fakeOther();
  const host = await createIssuerHost({ ...extra, issuer: { authorize: allow, ...extra.issuer, otherTokenExchange: other.handler } });
  return { host, other, ...(await setup(host)) };
}

const nothingRecorded = (host: IssuerHost) => {
  expect(host.recorded.issued).toHaveLength(0);
  expect(takeReasons(host)).toEqual([]);
};

describe("otherTokenExchange (D-046): who answers which request", () => {
  it("a requested_token_type this plugin doesn't serve, or none, goes to the other exchange, unaudited here", async () => {
    const { host, other, client, idToken } = await hostWithOther();
    for (const requested_token_type of [ACCESS_TOKEN_TYPE, undefined, "urn:ietf:params:oauth:token-type:jwt", REFRESH_TOKEN_TYPE]) {
      const r = await exchange(host, client, idToken, { requested_token_type, subject_token_type: ACCESS_TOKEN_TYPE });
      expect(r.status, String(requested_token_type)).toBe(200);
      expect(r.body.access_token).toBe("from-the-other-exchange");
      await host.settle();
      nothingRecorded(host);
    }
    expect(other.calls.map((c) => c.requested_token_type)).toEqual([ACCESS_TOKEN_TYPE, undefined, "urn:ietf:params:oauth:token-type:jwt", REFRESH_TOKEN_TYPE]);
  });

  it("an ID-JAG request never reaches it: issued here, or refused here", async () => {
    const { host, other, client, idToken } = await hostWithOther();
    const ok = await exchange(host, client, idToken);
    expect(ok.status).toBe(200);
    expect(ok.body.issued_token_type).toBe(ID_JAG_TOKEN_TYPE);
    const bad = await exchange(host, client, "not-a-token");
    expect(bad.status).toBe(400);
    expect(bad.body.error).toBe("invalid_grant");
    expect(other.calls).toHaveLength(0);
  });

  it("a repeated requested_token_type stays here and is refused, even if one of them is the other exchange's", async () => {
    const { host, other, client, idToken } = await hostWithOther();
    for (const requested_token_type of [[ACCESS_TOKEN_TYPE, ID_JAG_TOKEN_TYPE], [ID_JAG_TOKEN_TYPE, ACCESS_TOKEN_TYPE], [ACCESS_TOKEN_TYPE, ACCESS_TOKEN_TYPE]]) {
      const r = await exchange(host, client, idToken, { requested_token_type });
      // invalid_request: ours (unsupported_parameter) on 1.7, or the provider's own repeated-parameter refusal on 1.8.
      expect(r.status).toBe(400);
      expect(r.body.error).toBe("invalid_request");
    }
    expect(other.calls).toHaveLength(0);
  });

  it("with SAML path (b) on, a refresh-token request stays here", async () => {
    const other = fakeOther();
    const host = await createSamlHost({ issuer: { authorize: allow, otherTokenExchange: other.handler }, saml: { refreshTokens: {} } });
    const { client, idToken } = await setup(host);
    const r = await exchange(host, client, idToken, { requested_token_type: REFRESH_TOKEN_TYPE });
    expect(r.status).toBe(400);
    expect(takeReasons(host)).toEqual(["unsupported_subject_token_type"]);
    expect(other.calls).toHaveLength(0);
  });

  it("without it, nothing changes: other requested types are refused here", async () => {
    const host = await createIssuerHost({ issuer: { authorize: allow } });
    const { client, idToken } = await setup(host);
    const r = await exchange(host, client, idToken, { requested_token_type: ACCESS_TOKEN_TYPE });
    expect(r.body).toEqual({ error: "invalid_request", error_description: "Unsupported requested_token_type." });
    expect(takeReasons(host)).toEqual(["unsupported_requested_token_type"]);
  });

  it("must be a function", () => {
    expect(() => idJagIssuer({ authorize: allow, otherTokenExchange: "oauthTokenExchange" as never })).toThrow(/otherTokenExchange/);
  });
});

describe("tokenExchangeFrom (D-046)", () => {
  const handler: TokenExchangeHandler = async () => ({ access_token: "x", token_type: "Bearer" }) as never;
  const plugin = (extension: Record<string, unknown>, more: Record<string, unknown> = {}) => ({
    id: "some-exchange",
    init(ctx: never) {
      extendOAuthProvider(ctx, extension as never);
    },
    ...more,
  });

  it("returns the handler a plugin registers for the token-exchange grant through extendOAuthProvider", () => {
    expect(tokenExchangeFrom(plugin({ grants: { [TOKEN_EXCHANGE_GRANT]: handler } }))).toBe(handler);
  });

  it("refuses what would be lost: other plugin parts, other grants, other extension parts, more than one extension", () => {
    const cases: [unknown, RegExp][] = [
      [plugin({ grants: { [TOKEN_EXCHANGE_GRANT]: handler } }, { endpoints: {} }), /also has endpoints/],
      [plugin({ grants: { [TOKEN_EXCHANGE_GRANT]: handler } }, { schema: {}, hooks: {} }), /also has schema, hooks/],
      [plugin({ grants: { [TOKEN_EXCHANGE_GRANT]: handler, "urn:example:other": handler } }), /not only/],
      [plugin({ grants: { "urn:example:other": handler } }), /not only/],
      [plugin({ grants: {} }), /no grant/],
      [plugin({ grants: { [TOKEN_EXCHANGE_GRANT]: handler }, metadata: () => ({}) }), /extension also has metadata/],
      [
        {
          id: "two",
          init(ctx: never) {
            extendOAuthProvider(ctx, { grants: { [TOKEN_EXCHANGE_GRANT]: handler } });
            extendOAuthProvider(ctx, { metadata: () => ({}) } as never);
          },
        },
        /2 extensions/,
      ],
      [{ id: "none", init() {} }, /0 extensions/],
      [{ id: "no-init" }, /no init/],
      [{ id: "async", init: async () => {} }, /async/],
      [{ id: "options", init: () => ({ options: {} }) }, /returns options or context/],
      [
        {
          id: "needs-more",
          init(ctx: { options: { plugins: unknown[] } }) {
            void ctx.options.plugins.length;
          },
        },
        /needs more than extendOAuthProvider/,
      ],
    ];
    for (const [p, why] of cases) expect(() => tokenExchangeFrom(p as never), String(why)).toThrow(why);
  });
});

describe("listing both plugins (D-046)", () => {
  it("is refused at startup, saying what to do instead", async () => {
    const lookalike = { id: "oauth-token-exchange", init() {} } as unknown as BetterAuthPlugin;
    await expect(createIssuerHost({ issuer: { authorize: allow }, extra: [lookalike] })).rejects.toThrow(/tokenExchangeFrom\(oauthTokenExchange\(\)\)/);
  });
});

// Better Auth 1.8's own token exchange (not exported before 1.8: these run on the CI's 1.8 row).
const oauthTokenExchange = (oauthProviderModule as Record<string, unknown>).oauthTokenExchange as ((o?: unknown) => { id: string; init?: unknown }) | undefined;

describe.skipIf(!oauthTokenExchange)("with Better Auth 1.8's oauthTokenExchange() (D-046)", () => {
  it("tokenExchangeFrom captures it, and requests for an access token reach it, not us", async () => {
    const real = tokenExchangeFrom((oauthTokenExchange as NonNullable<typeof oauthTokenExchange>)());
    const host = await createIssuerHost({ issuer: { authorize: allow, otherTokenExchange: real } });
    const { client, idToken } = await setup(host);
    // Its own refusal (an ID token isn't an access token) proves the request reached it.
    const r = await exchange(host, client, idToken, { requested_token_type: ACCESS_TOKEN_TYPE });
    expect(r.status).toBe(400);
    expect(JSON.stringify(r.body)).toMatch(/subject_token_type must be/);
    expect(takeReasons(host)).toEqual([]);
    expect((await exchange(host, client, idToken)).body.issued_token_type).toBe(ID_JAG_TOKEN_TYPE);
  });

  it("one host serves both: its access-token exchange through ours, and ID-JAGs", async () => {
    const [A, B] = ["https://api-a.example/", "https://api-b.example/"];
    const host = await createIssuerHost({
      issuer: { authorize: allow, otherTokenExchange: tokenExchangeFrom((oauthTokenExchange as NonNullable<typeof oauthTokenExchange>)()) },
      provider: { resources: [A, B], scopes: ["openid", "profile", "email", "offline_access", "read"] },
    });
    const owner = await signUp(host);
    const client = await createClient(host, owner.browser, { extra: { scope: "openid profile email read", resources: [A, B] } });
    const user = await signUp(host);
    const { access_token } = await getTokens(host, user.browser, client, { scope: "openid profile read" });
    const res = await host.auth.handler(
      new Request(`${ISSUER}/oauth2/token`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded", authorization: basic(client) },
        body: new URLSearchParams({ grant_type: TOKEN_EXCHANGE_GRANT, subject_token: access_token ?? "", subject_token_type: ACCESS_TOKEN_TYPE, resource: B, scope: "read" }),
      }),
    );
    const body = (await res.json()) as Record<string, string>;
    expect(res.status, JSON.stringify(body)).toBe(200);
    expect(body.issued_token_type).toBe(ACCESS_TOKEN_TYPE);
    expect(JSON.parse(atob((body.access_token ?? "").split(".")[1]?.replace(/-/g, "+").replace(/_/g, "/") ?? "")).aud).toBe(B);
    await host.settle();
    nothingRecorded(host);
    const { id_token } = await getTokens(host, user.browser, client, { scope: "openid profile" });
    expect((await exchange(host, client, id_token ?? "")).body.issued_token_type).toBe(ID_JAG_TOKEN_TYPE);
  });

  it("listed beside idJagIssuer, our startup error explains the fix (not oauth-provider's duplicate-grant one)", async () => {
    const both = (order: "ours-first" | "theirs-first") => {
      const theirs = (oauthTokenExchange as NonNullable<typeof oauthTokenExchange>)() as unknown as BetterAuthPlugin;
      return order === "ours-first" ? createIssuerHost({ issuer: { authorize: allow }, extra: [theirs] }) : createIssuerHost({ issuer: { authorize: allow }, before: [theirs] });
    };
    await expect(both("ours-first")).rejects.toThrow(/tokenExchangeFrom/);
    await expect(both("theirs-first")).rejects.toThrow(/tokenExchangeFrom/);
  });
});

