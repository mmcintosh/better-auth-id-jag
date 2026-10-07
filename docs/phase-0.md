# Phase 0: extension grants under oauthProvider() and mcp(), on Node and workerd (2026-10-05)

**Verdict: the kill criteria are not hit.** An extension grant registered through `extendOAuthProvider` from a
companion plugin's `init` runs under both `oauthProvider()` and `mcp()`, on Node and on a deployed Worker, with
client authentication, token issuance, ID-JAG signing and discovery metadata all working. No fork, no patch.

Versions: `better-auth`, `@better-auth/core`, `oauth-provider`, `mcp`, `cimd`, `sso` all **1.7.6** (D-002), `jose` 6.2.12,
Node 24.12, wrangler 4.147.0, compatibility date 2026-10-01.

## What was proven, and how

`test/spike.test.ts` (12 tests, Node, in-memory SQLite) and `test/worker/check.mjs` (17 checks, over HTTP against the
deployed Worker). The plugin under test is `test/support/ping.ts`: it registers `grants["urn:example:ping"]` and one
metadata field, and its handler authenticates the client, looks up a user, signs an ID-JAG-shaped JWT with jwt()'s key,
and calls `provider.issueTokens`.

| Check | Node: oauthProvider() | Node: mcp() | Worker: mcp() |
|---|---|---|---|
| token endpoint dispatches the extension grant | ✓ | ✓ | ✓ |
| `authenticateClient({ requireCredentials: true })`: secret client accepted; no credential, wrong secret → `invalid_client`; client not registered for the grant → `unauthorized_client`; public client → `invalid_client` | ✓ | ✓ | ✓ |
| `issueTokens` from inside the handler; `tokenResponse` extras reach the response | ✓ | ✓ | ✓ |
| access token is a JWT with `aud` = the MCP `resource` when `resources: [resource]` is passed | — | ✓ | ✓ |
| `signJWT(ctx, { header: { typ: "oauth-id-jag+jwt" } })` signs with jwt()'s key; `kid` set; verifies with `jose` against the host's JWKS (EdDSA by default) | ✓ | ✓ | ✓ (remote JWKS) |
| grant listed in `grant_types_supported` automatically | ✓ | ✓ | ✓ |
| `metadata()` field in `/.well-known/oauth-authorization-server/api/auth` and `/api/auth/.well-known/openid-configuration` (and the `getOAuthServerConfig` / `getOpenIdConfig` helpers) | ✓ | ✓ | ✓ |
| `/.well-known/oauth-protected-resource/mcp` names the AS beside the extension | — | ✓ | ✓ |

### Each guard broken once

Each mutation applied to `test/support/ping.ts`, the suite run, the file restored:

| Broken | Caught by |
|---|---|
| `extendOAuthProvider` not called | 9 tests (dispatch, refusals, metadata, duplicate key, CIMD) |
| `typ` header dropped | the dispatch test, both hosts |
| `requireCredentials: false` | the public-client test, both hosts. **Not** caught before that test existed: a confidential client with no secret is refused by the provider regardless, so the flag only matters for public clients. |
| `resources` not passed to `issueTokens` | the mcp() audience check |
| `metadata` contribution removed | the discovery test, both hosts |
| `client_id` claim taken from the request body | the dispatch test, both hosts |

## Answers to the open questions

- **Does `mcp()` share the extension registry?** Yes. `mcp()` is `oauthProvider()` spread with a wrapped `onRequest`;
  the plugin id stays `"oauth-provider"`, so `ctx.getPlugin("oauth-provider")` finds it and `extendOAuthProvider`
  appends to the same `options.extensions`. (`oauthDeviceAuthorization()` relies on the same thing.)
- **Is the grant advertised automatically?** Yes: `grant_types_supported` = `grantTypes` (default) ∪ every extension's
  grant keys. Okta's resource-app requirement (jwt-bearer in `grant_types_supported`) is met by registering the grant.
  The same set governs client registration: a client may register the extension grant type.
- **Two extensions, same grant type (plan Question 7):** `validateOAuthProviderExtensions` **throws at startup**
  (`auth.$context` rejects) naming the grant type. A key that isn't an absolute URI (e.g. `client_credentials`) is also
  refused at startup, so built-ins can't be shadowed. Consequence: if core ever registers its own
  `urn:ietf:params:oauth:grant-type:jwt-bearer` or `token-exchange` extension, a host with both fails loudly at boot —
  no silent shadowing, but also no coexistence. The "typed sub-dispatch" upstream proposal stays relevant; nothing is
  opened without the maintainer's approval.
- **Does `mcp()` expose its `resource` to extensions?** Yes, through `opts.resources` (mcp() appends it). Seen from
  inside the handler.
- **CIMD + `private_key_jwt`:** works. A CIMD client (URL client id, metadata with inline `jwks`,
  `token_endpoint_auth_method: private_key_jwt`) authenticates at the extension grant through `authenticateClient`; the
  same client with no assertion is refused; a replayed assertion is refused (the provider's `oauthClientAssertion`
  table). CIMD permits only `none` and `private_key_jwt`, so a CIMD client at our receiver is confidential exactly when
  it uses `private_key_jwt` — plan §3.4 step 1 holds. (Node only; the Worker had no CIMD fetch.)
- **`ssoProvider` via `ctx.context.adapter`:** yes, `adapter.findMany({ model: "ssoProvider" })` answers from inside the
  grant handler (Node, mcp() + sso()).
- **Issuer identifier:** `ctx.context.baseURL`, which **includes the base path** (`https://host/api/auth`). That is the
  `iss` of our tokens and the `aud` an ID-JAG must carry for our receiver; Okta's Resource Server tab gets this URL.

## Measurements (deployed Worker, Workers Paid)

- **Bundle:** spike Worker (better-auth + mcp + cimd + sso + jwt + ping) 4894 KiB / **871.7 KiB gzip**; without the ping
  plugin 871.1 KiB gzip → **ping adds ~0.6 KiB gzip** (jose is already in Better Auth). The first issuer consumer today (a Better Auth OIDC
  provider on Workers, dry run, nothing changed in that repo): 4312 KiB / **764 KiB gzip**. The real plugins will be larger than
  ping; expect tens of KiB, not hundreds — re-measure in Phase 1.
- **Startup:** 112–221 ms reported by wrangler.
- **CPU per request** (`wrangler tail` samples; tail drops events under load, so n is small):

  | Route | auth built per request | auth cached per isolate |
  |---|---|---|
  | `POST /oauth2/token` (ping: client auth + user lookup + ID-JAG sign + access-token sign + DB writes) | p50 21 ms, p90 29 (n=26) | **p50 4–8 ms, p90 ~18** (n=17, two runs) |
  | discovery documents | 10–12 ms | 1–2 ms |
  | `POST /sign-up/email` (password hashing) | 188 ms | 140–158 ms |

  Building `betterAuth()` per request costs ~10 ms CPU by itself; cache the instance per isolate. Within the plan's
  "a few ms" at p50; the p90 includes fresh isolates. Free plan's 10 ms is not a constraint (Workers Paid).
- **Wall time** from here to the Worker, token request: p50 142–230 ms (network dominated).

## Findings that change or sharpen the plan

1. **workerd refuses `fetch(..., { redirect: "error" })`.** Already found in the first issuer consumer, which
   carries a patch-package patch on `@better-auth/oauth-provider` 1.7.6 for it. Our receiver's JWKS / discovery fetch (S10: "no redirects")
   must use `redirect: "manual"` and treat any 3xx as failure. It also means an unpatched oauth-provider can't fetch a
   client's `jwks_uri` on Workers: CIMD clients with **inline `jwks`** work; `jwks_uri` needs the patch or upstream fix.
2. **`oauthProvider()` / `mcp()` / `sso()` don't typecheck in a host with `exactOptionalPropertyTypes`** (upstream: the
   endpoints' openapi `items?: undefined` vs `OpenAPIParameter`). Hosts cast to `BetterAuthPlugin`; our own package's
   types must not make this worse, and the strict-host check (siblings' `tsconfig.strict-host.json`) will need the cast
   in its fixture. Candidate for an upstream issue (draft only, the maintainer's call).
3. **Refresh tokens:** `issueTokens` issues one only when the scopes include `offline_access` **and** the client is
   allowed `refresh_token`. The receiver's `issueRefreshToken: false` default is enforced by stripping `offline_access`
   from the granted scopes — no provider option needed. (Okta's guide: no refresh token.)
4. `invalid_client` for a missing credential comes back as **400**, not 401; whatever the provider does, our handlers
   inherit it. Fine for RFC 6749 §5.2 except the Basic-auth case (401 + `WWW-Authenticate`), which is the provider's.
5. **Admin client creation** is server-only at `/admin/oauth2/create-client`; over HTTP it's `/oauth2/create-client`
   behind a session and `clientPrivileges`. The example's setup script uses the latter.
6. Better Auth **1.7.7** is out (2026-10-05). Pinned 1.7.6 for now (D-002); CI matrix will cover latest-1.7.

## Okta (plan Question 8)

XAA is self-service Early Access, nothing to request, no lead time.
The maintainer turns it on when Track A has a deployable receiver. What's prepared for it: the receiver's issuer URL (with
`/api/auth`, see above) and a confidential client registration for Okta's "AI Agent" app.

## Throwaway resources

Worker `id-jag-phase0-spike` and D1 `id-jag-phase0-spike` on the maintainer's account, created and **deleted** 2026-10-05
(URL returns 404; `d1 list` shows none). Secrets were generated locally in a scratch directory and never written to
the repository.

## Reproduce

```sh
pnpm install && pnpm test                     # Node
node test/worker/schema.mts > test/worker/schema.sql
# create a D1, put its id in test/worker/wrangler.jsonc, apply schema.sql, deploy, set BETTER_AUTH_SECRET + SPIKE_KEY
SPIKE_KEY_FILE=<file> node test/worker/check.mjs https://<worker>.workers.dev 40
```
