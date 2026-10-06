# better-auth-id-jag

Let AI agents reach your users' tools **with the enterprise's say-so, not a fresh consent screen per app**. This package adds **Identity Assertion JWT Authorization Grants** (ID-JAG: Okta's *Cross App Access*, MCP's *Enterprise-Managed Authorization*) to [Better Auth](https://www.better-auth.com), on both sides of the exchange: **issue them** from your identity provider, and **accept them** at your MCP server's authorization server. Runs on **Cloudflare Workers** and **Node.js 22+**.

[![CI](https://github.com/mmcintosh/better-auth-id-jag/actions/workflows/ci.yml/badge.svg)](https://github.com/mmcintosh/better-auth-id-jag/actions/workflows/ci.yml)
[![Better Auth](https://img.shields.io/badge/better--auth-%E2%89%A51.7.5%20%3C1.8-black)](https://www.better-auth.com)
[![Runs on](https://img.shields.io/badge/runs%20on-Workers%20%7C%20Node%2022%2B-f38020)](#-runtimes-and-databases)
[![ID-JAG](https://img.shields.io/badge/ID--JAG-draft--04-informational)](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

```
person ─sign in─▶ IdP ─ID token─▶ agent ─token exchange─▶ IdP ─ID-JAG─▶ agent ─jwt-bearer─▶ MCP AS ─access token─▶ agent ─▶ /mcp
                  └──────────── idJagIssuer() ────────────┘                    └────── idJagGrant() ──────┘
```

> **Unofficial community plugin.** This project isn't affiliated with or endorsed by Better Auth. Status: **pre-release**, not yet on npm (the name holds a placeholder). It implements [draft-ietf-oauth-identity-assertion-authz-grant-04](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/04/); a later draft may rename a claim or URN before 0.1. Verified live against **Okta Cross App Access** and in CI against **Keycloak 26.8** ([what exactly](#-interoperability)). Every design decision and its evidence is in [DECISIONS.md](DECISIONS.md); every change is in the [CHANGELOG](CHANGELOG.md).

If it's useful to you, a ⭐ on [GitHub](https://github.com/mmcintosh/better-auth-id-jag) helps others find it.

## ✨ Features

- 🔁 **Both roles in one package**: `idJagIssuer()` turns a Better Auth IdP (on `@better-auth/oauth-provider`) into an ID-JAG issuer over RFC 8693 token exchange; `idJagGrant()` lets an MCP server's authorization server (on `mcp()` or `oauthProvider()`) redeem them over the RFC 7523 jwt-bearer grant. Use either alone with any other implementation of the draft.
- 🚦 **Policy you control**: a code hook (`authorize`), a database registry of resource servers and policies with an admin API, or both, where **both must allow** and the narrower outcome wins: fewer scopes, shorter lifetime.
- 🎫 **Two kinds of subject token**: an ID token this IdP issued, or a refresh token it issued (the draft's MAY, which Okta's conformance tooling and long-running agents use).
- 🛑 **Blocks**: stop a user, a client, an audience or any combination from getting ID-JAGs, now or until a date, through the API; or block from a `jti` seen in the audit log.
- 🔐 **Strict at the receiver**: `typ` must be `oauth-id-jag+jwt`; RS256, ES256 and EdDSA only (no `HS*`, no `none`); `aud` compared exactly with the issuer identifier; the ID-JAG's `client_id` must be the authenticated client; lifetime capped at 900 s; **single use** enforced by a database unique key.
- 🤐 **Refusals that don't leak**: the caller can't tell an unknown user from a denied policy from an untrusted issuer. Only defects in what they sent themselves (a missing claim, a malformed JWT) are named; the real reason goes to the audit log.
- 🏛️ **Trusted issuers from three places**: in code, from the OIDC providers you already have in `@better-auth/sso` (opt-in), or from a table, each with optional client allow-lists and `tenant` pinning.
- 👤 **Subject resolution you can reason about**: linked accounts first, then (only if you allow it) email fallback for listed domains, then (only if you allow it) JIT provisioning from a verified email, with organization membership. A `resolveSubject` hook runs before all of it.
- 🤖 **Agent delegation**: an `act` claim (RFC 8693, as Okta sends to name the AI agent) is accepted and carried into the access token.
- 📈 **Audit trail**: `onIssued`, `onAccepted`, `onRefused` and `onAdminChanged` events, and an optional audit table with retention, including the provider's own client-authentication refusals.
- 🧪 **Tested as if it matters**: the suite runs on Node and in workerd with D1; property-based tests; and a weekly mutation run that fails CI when a security check can be removed without a test noticing.
- ☁️ **Runs where your app runs**: a Better Auth plugin, not a separate server. Only `fetch` and Web APIs; the receiver's single outbound request (JWKS and discovery) goes through a `fetch` you can replace, for example with a Workers service binding.

## 📚 Contents

[Install](#-install) · [Quick start](#-quick-start) · [Issuer](#-issuer-idjagissuer) · [Receiver](#-receiver-idjaggrant) · [Database tables](#-database-tables) · [Audit events](#-audit-events) · [Errors](#-errors) · [Interoperability](#-interoperability) · [Example](#-example-two-workers) · [Runtimes and databases](#-runtimes-and-databases) · [Not yet](#-not-yet) · [Security](#-security) · [Development](#-development)

## 📦 Install

> Not on npm yet. Until 0.1.0, install from a clone (`pnpm build`, then `pnpm add ../better-auth-id-jag`).

```sh
npm install better-auth-id-jag
```

Requires Better Auth `>=1.7.5 <1.8.0`, `@better-auth/core` and `@better-auth/oauth-provider` in the same range (peer dependencies), and Node.js 22 or later or Cloudflare Workers. Both sides need Better Auth's `jwt()` plugin.

## ⚡ Quick start

**At the identity provider**, where people sign in:

```ts
import { betterAuth } from "better-auth";
import { jwt } from "better-auth/plugins";
import { oauthProvider } from "@better-auth/oauth-provider";
import { idJagIssuer } from "better-auth-id-jag";

export const auth = betterAuth({
  // …
  plugins: [
    // ES256 or RS256: some receivers don't accept EdDSA, jwt()'s default.
    jwt({ jwks: { keyPairConfig: { alg: "ES256" } } }),
    oauthProvider({ loginPage: "/login", consentPage: "/consent" }),
    idJagIssuer({
      authorize: ({ audience, client }) =>
        audience === "https://mcp.example.com/api/auth"
          ? { decision: "allow", scopes: ["read"], clientIdAtResource: client.metadata?.clientIdAtResource as string }
          : { decision: "deny", reason: "unknown audience" },
    }),
  ],
});
```

**At the MCP server's authorization server**, which turns an ID-JAG into an access token:

```ts
import { betterAuth } from "better-auth";
import { jwt } from "better-auth/plugins";
import { mcp } from "@better-auth/mcp";
import { idJagGrant } from "better-auth-id-jag";

export const auth = betterAuth({
  // …
  plugins: [
    jwt(),
    mcp({ loginPage: "/login", resource: "https://mcp.example.com/mcp", scopes: ["read"] }),
    idJagGrant({
      trustedIssuers: [
        { issuer: "https://idp.example.com/api/auth", jwksUri: "https://idp.example.com/api/auth/jwks" },
      ],
    }),
  ],
});
```

Then create the tables with your usual migration (`npx auth migrate`, or `npx auth generate` for Drizzle and Prisma), and the agent can run the flow:

1. Get an ID token (or a refresh token) for the user from the IdP, as any OAuth client does.
2. **Token exchange** at the IdP's token endpoint: `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`, `requested_token_type=urn:ietf:params:oauth:token-type:id-jag`, `subject_token=<id token>`, `audience=<the MCP authorization server's issuer>`, and optionally `resource` and `scope`.
3. **jwt-bearer** at the MCP authorization server's token endpoint: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`, `assertion=<the ID-JAG>`, authenticating with the client id *that* server issued it.
4. Call `/mcp` with the access token.

> [!IMPORTANT]
> **The audience is the authorization server's issuer, exactly as its metadata publishes it**, path included: the `issuer` field of `/.well-known/oauth-authorization-server/api/auth`, for example `https://mcp.example.com/api/auth`. Not the MCP resource, not the bare origin, not with a trailing slash. The receiver compares it exactly. In Okta, that is the value for the resource app's **Resource Server** tab.

## 🏢 Issuer: `idJagIssuer()`

Adds the token-exchange grant to `@better-auth/oauth-provider`'s token endpoint, advertises `identity_chaining_requested_token_types_supported` in its metadata, and signs ID-JAGs with the `jwt()` plugin's keys.

### Options

| Option | Default | |
|---|---|---|
| `authorize` | | Code policy: `(input) => { decision: "allow", scopes, … } \| { decision: "deny", reason? }`. See [Policy](#policy). |
| `registry` | | Database policy: `{ enabled, canManage?, cacheSeconds? }`. See [Registry and admin API](#registry-and-admin-api). |
| `allowPublicClients` | `false` | The draft: "SHOULD only be supported for confidential clients". Turning it on logs a warning at startup. |
| `signingAlgorithm` | the `jwt()` plugin's | `"RS256"`, `"ES256"` or `"EdDSA"`; must be the jwt plugin's `keyPairConfig.alg` or one of its `keyPairConfigs`. |
| `defaultLifetimeSeconds` | `300` | When no policy sets a lifetime. At most 900. |
| `allowLoopbackHttpAudiences` | `false` | Allow `http://` audiences on `localhost`, `127.0.0.1` and `[::1]`, for local development. Otherwise audiences are https. |
| `sweepIntervalSeconds` | `3600` | Seconds between opportunistic sweeps of expired rows, per isolate. `0` never sweeps. |
| `events` | | `{ onIssued?, onAccepted?, onRefused?, onAdminChanged? }`. See [Audit events](#-audit-events). |
| `auditLog` | | `{ retentionDays }` (1 to 3650): also write events to the `idJagAudit` table. |

Options are checked when the plugin starts: an unknown key, a misspelling or an out-of-range number stops it with a message naming each problem, rather than silently switching a check off.

### Policy

The `authorize` hook gets the user as the database has it now, the requesting client (`clientId`, `name`, `referenceId`, `metadata`), the `audience`, the `resource` and the `requestedScopes`, and what the subject token said (`tokenType`, `sub`, `auth_time`, `acr`, `amr`, `raw`). An allow returns:

| Field | |
|---|---|
| `scopes` | The most this policy allows. The ID-JAG gets these ∩ the requested ones (when any were requested). |
| `resource` | Only when the client sent none; otherwise it must equal the one it sent. |
| `lifetimeSeconds` | At most 900. The shortest wins when several sources allow. |
| `clientIdAtResource` | The client's id **at the resource authorization server**, which is usually not its id here. Default: its id here. |
| `claims` | `{ email?: boolean, tenant?: string }`: opt in to sending the user's email (only when verified) and a tenant. |

A deny's `reason` goes to the audit log only, never to the caller.

**The client has two ids.** The MCP server registers the agent and gives it its own client id; the ID-JAG's `client_id` must be that one, because the receiver checks it against the client that presents the ID-JAG. Keep the mapping somewhere the policy can read it, for example in the IdP client's metadata, as [the example](#-example-two-workers) does.

### Registry and admin API

With `registry: { enabled: true, canManage }`, resource servers (`idJagResourceServer`) and policies (`idJagPolicy`) live in the database, and the admin API is mounted under `/id-jag/*` for users `canManage` returns exactly `true` for (a throw denies). Every change emits `onAdminChanged` with the acting user.

```ts
import { createAuthClient } from "better-auth/client";
import { idJagIssuerClient } from "better-auth-id-jag/client";

const authClient = createAuthClient({ plugins: [idJagIssuerClient()] });

await authClient.idJag.resourceServers.create({ resourceServer: { audience, name, scopes } });
await authClient.idJag.policies.create({ policy: { resourceServerId, name, subjectKind, clientIds, scopes } });
await authClient.idJag.blocks.create({ block: { userId, clientId, audience, reason, expiresAt } });
await authClient.idJag.blocks.createFromJti({ jti, reason });
```

With both `authorize` and `registry`, both must allow. Without `canManage` the API isn't mounted, but the tables are still read; with `registry.enabled: false`, only the blocks and audit routes are mounted.

### Blocks

A block (`idJagBlock`) refuses new ID-JAGs for a user, optionally narrowed to a client and an audience, until `expiresAt` or until it is deleted. `createFromJti` builds one from an issued ID-JAG's audit record. A block stops **issuance**: an ID-JAG already issued lives at most its lifetime (300 s by default), and an access token already issued by the receiver is the receiver's to revoke.

## 🔑 Receiver: `idJagGrant()`

Adds the jwt-bearer grant to the host's token endpoint (`mcp()` or `oauthProvider()`) and advertises `authorization_grant_profiles_supported`. For each ID-JAG it checks, in order: the format (`typ`, `alg`, `kid`, required claims, lifetime), that the issuer is trusted, the signature against the issuer's JWKS, `aud`, that `client_id` is the authenticated client, single use of `jti`, the resource, the subject, and the scopes. The access token it issues is audience-restricted to the resource.

### Options

| Option | Default | |
|---|---|---|
| `trustedIssuers` | `[]` | Issuers configured in code. See [Trusted issuers](#trusted-issuers). |
| `sso` | `false` | `true` or `{ providerIds?, emailFallback?, jitProvisioning?, allowedClientIds? }`: also trust `@better-auth/sso`'s OIDC providers. |
| `trustedIssuerTable` | `false` | Also read trusted issuers from the `idJagTrustedIssuer` table (adds the table). |
| `resolveSubject` | | `(input) => { action: "link", userId } \| { action: "continue" } \| { action: "reject" }`. Runs before the default resolution. |
| `defaultResource` | | The resource when neither the ID-JAG nor the request names one. Must be a registered resource. |
| `requireResourceClaim` | `false` | Refuse an ID-JAG without a `resource` claim. |
| `allowEmptyScope` | `false` | Issue a token with no scope when the intersection is empty, instead of `invalid_scope`. |
| `allowPublicClients` | `false` | Logs a warning at startup when set. |
| `clockSkewSeconds` | | Allowed skew on `iat`, `nbf` and `exp`. |
| `maxLifetimeSeconds` | `900` | The longest `exp − iat` accepted. |
| `fetch` | the global `fetch` | The only fetch the receiver uses (JWKS and discovery). |
| `jwks` | | `{ timeoutMs: 5000, maxBytes: 65536, cacheTtlSeconds: 600, minRefetchIntervalSeconds: 60 }`. An unknown `kid` refetches, at most once per interval. |
| `events`, `auditLog` | | As for the issuer. |

### Trusted issuers

```ts
idJagGrant({
  trustedIssuers: [
    {
      issuer: "https://acme.okta.com/oauth2/default", // the exact `iss`
      discoveryUri: "https://acme.okta.com/oauth2/default/.well-known/oauth-authorization-server", // or jwksUri
      allowedClientIds: ["agent-1"],          // only these clients may present its ID-JAGs
      organizationId: "org_acme",             // recorded, and where JIT puts new users
      jitRole: "member",
      emailFallback: { domains: ["acme.com"] },
      jitProvisioning: { trustEmailVerified: true },
    },
  ],
});
```

`issuer` and `tenant` (for multi-tenant IdPs) together identify an entry; listing one twice is a startup error. `jwksUri` and `discoveryUri` must be https; a discovery document's `issuer` must equal `issuer` exactly. An ID-JAG whose `iss` is this server itself is refused.

### Who the subject is

1. `resolveSubject`, if set, can link, reject, or continue.
2. A linked account: `providerId` = `accountProviderId` (default `id-jag:<issuer>`), `accountId` = the ID-JAG's `sub`.
3. Only if `emailFallback` lists the domain: a local user with that verified email, which is then linked.
4. Only if `jitProvisioning` is on: a new user, from the `email` claim, marked verified only with `trustEmailVerified`, and linked. With `organizationId` and the organization plugin, they become a member with `jitRole`.

Otherwise the grant is refused (`unknown_subject`). A banned user (the admin plugin) is refused too.

## 🗄️ Database tables

| Table | Side | When |
|---|---|---|
| `idJagJti` | receiver | Always: single use of each ID-JAG. **Needs a database that enforces UNIQUE**; the plugin warns at startup on an adapter that doesn't. |
| `idJagTrustedIssuer` | receiver | With `trustedIssuerTable: true`. |
| `idJagResourceServer`, `idJagPolicy` | issuer | With `registry`. |
| `idJagBlock` | issuer | Always. |
| `idJagAudit` | both | With `auditLog`. |

Generate them with `npx auth generate` or `npx auth migrate`. Expired `jti` and audit rows are swept opportunistically.

## 📈 Audit events

```ts
idJagIssuer({
  events: {
    onIssued: (e) => log("id-jag.issued", e),
    onRefused: (e) => log("id-jag.refused", e), // e.reason: the real reason code
    onAdminChanged: (e) => log("id-jag.admin", e),
  },
  auditLog: { retentionDays: 90 },
});
```

Events carry the `jti`, the issuer, subject, client, audience, resource and scopes, never a token; every string a caller could have sent is made log-safe. Handlers observe and never gate: they run in the background, and a throw is logged and changes nothing. Refusals by the OAuth provider itself (a wrong client secret, a client not allowed the grant) reach `onRefused` too, while the provider's response goes out unchanged. A refusal of a caller that never authenticated goes to the handler but **not** to the table (`authenticated` is `true` only after client authentication succeeded), so nobody can grow your audit table at their own pace.

**On Workers, give Better Auth `waitUntil`**, or the audit writes are cancelled when the response is sent:

```ts
import { waitUntil } from "cloudflare:workers";

betterAuth({ advanced: { backgroundTasks: { handler: waitUntil } } /* … */ });
```

## 🚫 Errors

Refusals are standard RFC 6749 / RFC 8693 error responses (`invalid_request`, `invalid_client`, `invalid_grant`, `unauthorized_client`, `invalid_scope`, `invalid_target`). The `error_description` names the problem only when the caller sent it: a missing parameter, a malformed JWT, a wrong `typ`, an expired assertion. Trust, binding, subject and policy failures all get the generic description for their code, so an agent can't probe which users exist or what a policy allows. The specific reason (`untrusted_issuer`, `bad_signature`, `wrong_audience`, `client_mismatch`, `replay`, `unknown_subject`, `policy_denied`, `blocked`, …) is in the `onRefused` event and the audit table. The full list is `REASONS` in [src/core/errors.ts](src/core/errors.ts).

## 🤝 Interoperability

| Our side | Other side | Status |
|---|---|---|
| Issuer | Our receiver | ✅ Verified, in every CI run, on Node and in workerd |
| Issuer | Keycloak 26.8.0 (`identity-assertion-jwt`, experimental) | ✅ Verified; ES256, RS256 and EdDSA. Keycloak ignores `scope` and `resource` |
| Issuer | node-oauth2-server ([PR #462](https://github.com/node-oauth/node-oauth2-server/pull/462), unreleased) | ✅ Verified; ES256 and RS256 (no EdDSA there) |
| **Okta Cross App Access** | Receiver on Workers + D1 | ✅ **Verified live**, RS256, with Okta's `act` carried into the access token |
| Issuer / receiver | Authelia | ⏳ Not possible yet: no release ships ID-JAG |
| Receiver | Keycloak as issuer | ⏳ Not possible: Keycloak doesn't issue ID-JAGs |

Each row's date, version, commands and the ways the other side differs are in [docs/interop.md](docs/interop.md). Nothing there is claimed from reading docs alone.

**Sign with ES256 or RS256** unless every receiver you target accepts EdDSA: Better Auth's `jwt()` defaults to EdDSA, and node-oauth2-server, among others, refuses it.

## ☁️ Example: two Workers

[examples/workers](examples/workers/README.md) is the whole flow on Cloudflare Workers with D1: an **enterprise IdP** (`oauthProvider()` + `jwt()` + `idJagIssuer()`), an **MCP server** (`mcp()` + `jwt()` + `idJagGrant()`) with one tool, `whoami`, and `client.mjs`, which plays the agent through every step and then shows a replay being refused. It also covers the two Workers limits you'll meet (a Worker can't fetch another on the same account by URL, or itself), and how to point Okta Cross App Access at the MCP server.

## 🧩 Runtimes and databases

The whole suite runs on Node.js (`node:sqlite`) and in workerd with D1. CI runs it on Node 24 with Better Auth 1.7.5 and the latest 1.7.x, and on Node 22 with 1.7.5. The receiver's single-use check relies on a UNIQUE constraint, so use a database adapter that enforces one (SQLite, D1, PostgreSQL, MySQL; not Better Auth's memory adapter in production).

## 🧭 Not yet

- **npm release** (0.1.0), with provenance and an SBOM; then the guide.
- **A later draft:** -04 expires on 2026-11-22. When -05 appears, [src/core/urns.ts](src/core/urns.ts) and this README will say which draft is implemented.
- `authorization_details` (RFC 9396) and `cnf` (sender-constrained ID-JAGs) are refused, by name, until the draft settles them.
- No admin API for trusted issuers yet: configure them in code, through `@better-auth/sso`, or in the table directly.
- No pairwise subject identifiers.

## 🔒 Security

- [docs/security.md](docs/security.md) has the threat model, what your app must configure, and the known limitations.
- [DECISIONS.md](DECISIONS.md) records every security-relevant decision, with its tests and mutation proofs.
- Each security check is mutation-tested: `scripts/mutate.py` removes it, and CI fails if no test notices. It runs weekly on `main`.
- All GitHub Actions are pinned by SHA, with least-privilege tokens, and the history is scanned with gitleaks.

Please report vulnerabilities privately, as [SECURITY.md](SECURITY.md) describes, not in public issues. Versioning, the draft and Better Auth compatibility are in [docs/versioning.md](docs/versioning.md).

## 🧪 Development

```bash
pnpm test            # Node + workerd (D1)
pnpm test:node       # one runtime only
pnpm test:workerd
pnpm typecheck
pnpm lint            # Biome
pnpm build           # dist + type declarations
scripts/use-better-auth.sh latest-1.7   # run the suite against another Better Auth version
INTEROP_KEYCLOAK=1 pnpm vitest run test/interop/keycloak.test.ts   # needs Keycloak in Docker, see docs/interop.md
```

## Contributing

Contributions are welcome: bug reports, [interop reports](https://github.com/mmcintosh/better-auth-id-jag/issues/new?template=interop.yml) (especially "it works with X"), fixes and features. For anything significant, please open an issue first. See [CONTRIBUTING.md](CONTRIBUTING.md): security checks come with tests that fail without them, and are on the mutation lists.

## License

MIT © Mark McIntosh

## Related

- [better-auth-saml-idp](https://github.com/mmcintosh/better-auth-saml-idp): your Better Auth server as a SAML 2.0 identity provider.
- [better-auth-scim-provisioning](https://github.com/mmcintosh/better-auth-scim-provisioning): provision users to the apps they sign in to, over SCIM 2.0, Google Workspace and webhooks.
