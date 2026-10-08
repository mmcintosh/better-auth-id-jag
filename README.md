# better-auth-id-jag

Let AI agents reach your users' tools **with the enterprise's say-so, not a fresh consent screen per app**. This package adds **Identity Assertion JWT Authorization Grants** (ID-JAG: Okta's *Cross App Access*, MCP's *Enterprise-Managed Authorization*) to [Better Auth](https://www.better-auth.com), on both sides of the exchange: **issue them** from your identity provider, and **accept them** at your MCP server's authorization server. Runs on **Cloudflare Workers** and **Node.js 22+**.

[![npm](https://img.shields.io/npm/v/better-auth-id-jag)](https://www.npmjs.com/package/better-auth-id-jag)
[![CI](https://github.com/mmcintosh/better-auth-id-jag/actions/workflows/ci.yml/badge.svg)](https://github.com/mmcintosh/better-auth-id-jag/actions/workflows/ci.yml)
[![Better Auth](https://img.shields.io/badge/better--auth-%E2%89%A51.7.5%20%3C1.8-black)](https://www.better-auth.com)
[![Runs on](https://img.shields.io/badge/runs%20on-Workers%20%7C%20Node%2022%2B-f38020)](#-runtimes-and-databases)
[![ID-JAG](https://img.shields.io/badge/ID--JAG-draft--04-informational)](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/mmcintosh/better-auth-id-jag/badge)](https://scorecard.dev/viewer/?uri=github.com/mmcintosh/better-auth-id-jag)
[![CodeQL](https://github.com/mmcintosh/better-auth-id-jag/actions/workflows/codeql.yml/badge.svg)](https://github.com/mmcintosh/better-auth-id-jag/actions/workflows/codeql.yml)
[![Socket](https://socket.dev/api/badge/npm/package/better-auth-id-jag)](https://socket.dev/npm/package/better-auth-id-jag)

```
person ─sign in─▶ IdP ─ID token─▶ agent ─token exchange─▶ IdP ─ID-JAG─▶ agent ─jwt-bearer─▶ MCP AS ─access token─▶ agent ─▶ /mcp
                  └──────────── idJagIssuer() ────────────┘                    └────── idJagGrant() ──────┘
```

> [!WARNING]
> **Experimental: this implements a draft, not a finished standard.** ID-JAG is an IETF Internet-Draft, [draft-ietf-oauth-identity-assertion-authz-grant-04](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/04/), still being worked on in the OAuth working group, and MCP's Enterprise-Managed Authorization builds on it. Its claims, URNs and rules can still change, and while they do, a 0.x minor release follows them, even when that breaks your setup. 1.0 waits until the draft settles. The **issuer** (`idJagIssuer()`) is newer than the receiver, and experimental in its own right. Review it for your own threat model before you rely on it in production.

> **Unofficial community plugin.** This project isn't affiliated with or endorsed by Better Auth. Status: **0.x, before 1.0**. It implements [draft-ietf-oauth-identity-assertion-authz-grant-04](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/04/) (exported as `SUPPORTED_DRAFT`). [What is and isn't implemented](#-conformance). Verified live against **Okta Cross App Access** and Okta's **xaa.dev** testers (OIDC and SAML), against **Keycloak 26.8** and node-oauth2-server in an interop suite that runs weekly in CI with Docker, and end to end with **better-auth-saml-idp 1.2.0** for SAML ([what exactly](#-interoperability)). Every design decision and its evidence is in [DECISIONS.md](DECISIONS.md); every change is in the [CHANGELOG](CHANGELOG.md).

If it's useful to you, a ⭐ on [GitHub](https://github.com/mmcintosh/better-auth-id-jag) helps others find it.

## ✨ Features

- 🔁 **Both roles in one package**: `idJagIssuer()` turns a Better Auth IdP (on `@better-auth/oauth-provider`) into an ID-JAG issuer over RFC 8693 token exchange; `idJagGrant()` lets an MCP server's authorization server (on `mcp()` or `oauthProvider()`) redeem them over the RFC 7523 jwt-bearer grant. Use either alone with any other implementation of the draft.
- 🚦 **Policy you control**: a code hook (`authorize`), a database registry of resource servers and policies with an admin API, or both, where **both must allow** and the narrower outcome wins: fewer scopes, shorter lifetime.
- 🎫 **Three kinds of subject token**: an ID token this IdP issued, a refresh token it issued (the draft's MAY, which Okta's conformance tooling and long-running agents use), or, experimentally, a SAML assertion from [better-auth-saml-idp](https://github.com/mmcintosh/better-auth-saml-idp), directly or through a refresh token as the draft's §4.5 and MCP describe.
- 🛑 **Blocks**: stop a user, a client, an audience or any combination from getting ID-JAGs, now or until a date, through the API; or block from a `jti` seen in the audit log.
- 🔐 **Strict at the receiver**: `typ` must be `oauth-id-jag+jwt`; RS256, ES256 and EdDSA (`EdDSA` or `Ed25519`) only, no `HS*`, no `none`; `aud` compared exactly with the issuer identifier; the ID-JAG's `client_id` must be the authenticated client; lifetime capped at 900 s; **single use** enforced by a database unique key.
- 🤐 **Refusals that don't leak**: the caller can't tell an unknown user from a denied policy from an untrusted issuer. Only defects in what they sent themselves (a missing claim, a malformed JWT) are named; the real reason goes to the audit log.
- 🏛️ **Trusted issuers from three places**: in code, from the OIDC providers you already have in `@better-auth/sso` (opt-in), or from a table, each with optional client allow-lists and `tenant` pinning.
- 👤 **Subject resolution you can reason about**: users your IdP provisioned over SCIM (when you link the issuer to a SCIM connection), else linked accounts, then (only if you allow it) email fallback for listed domains, then (only if you allow it) JIT provisioning from a verified email, with organization membership. A `resolveSubject` hook runs before all of it.
- 👥 **SCIM-provisioned users**: with `@better-auth/scim` at your app, ID-JAGs resolve to the users the IdP provisioned, and deprovisioning at the IdP stops the agent there too.
- 🤖 **Agent delegation**: an `act` claim (RFC 8693, as Okta sends to name the AI agent) is accepted and carried into the access token.
- 📈 **Audit trail**: `onIssued`, `onRefreshIssued`, `onAccepted`, `onRefused` and `onAdminChanged` events, and an optional audit table with retention, including the provider's own client-authentication refusals.
- 🧪 **Tested as if it matters**: the suite runs on Node and in workerd with D1; property-based tests; and a weekly mutation run that fails CI when a security check can be removed without a test noticing.
- ☁️ **Runs where your app runs**: a Better Auth plugin, not a separate server. Only `fetch` and Web APIs; the receiver's single outbound request (JWKS and discovery) goes through a `fetch` you can replace, for example with a Workers service binding.

## 📚 Contents

[Install](#-install) · [Quick start](#-quick-start) · [Issuer](#-issuer-idjagissuer) · [Receiver](#-receiver-idjaggrant) · [Database tables](#-database-tables) · [Audit events](#-audit-events) · [Errors](#-errors) · [What ID-JAG controls](#-what-id-jag-controls-and-what-your-mcp-server-still-must) · [Conformance](#-conformance) · [Interoperability](#-interoperability) · [Example](#-example-two-workers) · [Runtimes and databases](#-runtimes-and-databases) · [Not yet](#-not-yet) · [Security](#-security) · [Development](#-development)

## 📦 Install

```sh
npm install better-auth-id-jag
```

Requires Better Auth `>=1.7.5 <1.8.0`, `@better-auth/core` and `@better-auth/oauth-provider` in the same range (peer dependencies), and Node.js 22 or later or Cloudflare Workers. Both sides need Better Auth's `jwt()` plugin. Optional peers, used only when you install them: `@better-auth/mcp`, `@better-auth/sso` and `@better-auth/scim` (same range) for the receiver, and `better-auth-saml-idp` `>=1.2.0` for SAML subject tokens.

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
    mcp({ loginPage: "/login", consentPage: "/consent", resource: "https://mcp.example.com/mcp", scopes: ["read"] }),
    idJagGrant({
      trustedIssuers: [
        { issuer: "https://idp.example.com/api/auth", jwksUri: "https://idp.example.com/api/auth/jwks" },
      ],
    }),
  ],
});
```

> **With `exactOptionalPropertyTypes`:** Better Auth's own `oauthProvider()` and `mcp()` plugin types don't compile under that setting (upstream, not this package). Cast them where you list your plugins (`mcp({ … }) as unknown as BetterAuthPlugin`), as this repository's tests do.

Then create the tables with your usual migration (`npx auth migrate`, or `npx auth generate` for Drizzle and Prisma), and the agent can run the flow:

1. Get an ID token (or a refresh token) for the user from the IdP, as any OAuth client does.
2. **Token exchange** at the IdP's token endpoint: `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`, `requested_token_type=urn:ietf:params:oauth:token-type:id-jag`, `subject_token=<id token>`, `audience=<the MCP authorization server's issuer>`, and optionally `resource` and `scope`.
3. **jwt-bearer** at the MCP authorization server's token endpoint: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`, `assertion=<the ID-JAG>`, authenticating with the client id *that* server issued it.
4. Call `/mcp` with the access token.

> [!IMPORTANT]
> **The audience is the authorization server's issuer, exactly as its metadata publishes it**, path included: the `issuer` field of `/.well-known/oauth-authorization-server/api/auth`, for example `https://mcp.example.com/api/auth`. Not the MCP resource, not the bare origin, not with a trailing slash. The receiver compares it exactly. In Okta, that is the value for the resource app's **Resource Server** tab.

## 🏢 Issuer: `idJagIssuer()`

> **Experimental.** The issuer works and is tested, including against Keycloak and node-oauth2-server, but no production client has used it yet. Its options and admin API may change in a 0.x minor release. Better Auth may also add a general RFC 8693 token-exchange plugin (better-auth/better-auth#8023). Two extensions can't register the same grant type, so this plugin may then have to sit on top of that one. The handler is also exported as a plain function (`handleTokenExchange`) for that reason. The receiver isn't affected.

Adds the token-exchange grant to `@better-auth/oauth-provider`'s token endpoint, advertises `identity_chaining_requested_token_types_supported` in its metadata, and signs ID-JAGs with the `jwt()` plugin's keys.

### Options

| Option | Default | |
|---|---|---|
| `authorize` | | Code policy: `(input) => { decision: "allow", scopes, … } \| { decision: "deny", reason? }`. See [Policy](#policy). |
| `registry` | | Database policy: `{ enabled, canManage?, cacheSeconds? }` (`cacheSeconds`: 60 by default, 0 to 3600). See [Registry and admin API](#registry-and-admin-api). |
| `blocks` | | `{ canManage? }`: who may manage [blocks](#blocks) over the API. Blocks are enforced either way. |
| `maxIdTokenAgeSeconds` | `3600` | The oldest ID token (by `iat`) accepted as a subject token, even when it hasn't expired. 60 to 86400. An older one is refused as `subject_token_expired`; exchange the refresh token instead. |
| `allowPublicClients` | `false` | The draft: "SHOULD only be supported for confidential clients". Turning it on logs a warning at startup. |
| `signingAlgorithm` | the `jwt()` plugin's | `"RS256"`, `"ES256"` or `"EdDSA"`; must be the jwt plugin's `keyPairConfig.alg` or one of its `keyPairConfigs`. |
| `defaultLifetimeSeconds` | `300` | When no policy sets a lifetime. At most 900. |
| `allowLoopbackHttpAudiences` | `false` | Allow `http://` audiences on `localhost`, `127.0.0.1` and `[::1]`, for local development. Otherwise audiences are https. |
| `sweepIntervalSeconds` | `3600` | Seconds between opportunistic sweeps of expired rows, per isolate. `0` never sweeps. |
| `saml` | | Experimental: `{ subjectTokens?, refreshTokens? }`. See [SAML subject tokens](#saml-subject-tokens). |
| `events` | | `{ onIssued?, onRefreshIssued?, onAccepted?, onRefused?, onAdminChanged? }`. See [Audit events](#-audit-events). |
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

With `registry: { enabled: true, canManage }`, resource servers (`idJagResourceServer`) and policies (`idJagPolicy`) live in the database, and their admin API is mounted under `/id-jag/*` for users `canManage` returns exactly `true` for (a throw denies). Blocks have their own `blocks: { canManage }`, so they can be managed without the registry and by different people. The audit route (`/id-jag/audit`, with `auditLog`) is mounted with either and open to either. Every change emits `onAdminChanged` with the acting user.

```ts
import { createAuthClient } from "better-auth/client";
import { idJagIssuerClient } from "better-auth-id-jag/client";

const authClient = createAuthClient({ plugins: [idJagIssuerClient()] });

await authClient.idJag.resourceServers.create({ resourceServer: { audience, name, scopes } });
await authClient.idJag.policies.create({ policy: { resourceServerId, name, subjectKind, clientIds, scopes } });
await authClient.idJag.blocks.create({ block: { userId, clientId, audience, reason, expiresAt } });
await authClient.idJag.blocks.createFromJti({ jti, reason });
```

With both `authorize` and `registry`, both must allow. Without a `canManage` its routes aren't mounted, but the tables are still read: blocks are checked on every exchange whether or not `blocks.canManage` is set.

### Blocks

A block (`idJagBlock`) refuses new ID-JAGs for a user, optionally narrowed to a client and an audience, until `expiresAt` or until it is deleted. `createFromJti` builds one from an ID-JAG this issuer minted: from its `jti` row while that lasts (until a few minutes after the token expires), then from its `id-jag.issued` audit row, so blocking from a `jti` seen in the audit log needs `auditLog`. A block stops **issuance**: an ID-JAG already issued lives at most its lifetime (300 s by default), and an access token already issued by the receiver is the receiver's to revoke.

**What stops an exchange:** a ban, a block, an ID token older than `maxIdTokenAgeSeconds` (an hour by default), an ID token whose session has ended (only for clients whose ID tokens carry `sid`: those with `enable_end_session` or a back-channel logout URI), and revoking the refresh token at `/oauth2/revoke`. Signing out alone doesn't stop an ID token without `sid` (it works until the age cap), nor an `offline_access` refresh token (revoke it, or block the user).

### SAML subject tokens

> **Experimental.** This needs [better-auth-saml-idp](https://github.com/mmcintosh/better-auth-saml-idp) **≥ 1.2.0**, with token exchange turned on for the SP. It is unit-tested against a stub of that package's interface and verified end to end against the released 1.2.0 ([test/interop/saml-idp-e2e](test/interop/saml-idp-e2e/README.md)): both paths, replays, a tampered assertion and another client's attempt.

When people sign in to an agent through SAML, using your Better Auth server as the SAML IdP, the agent holds an Assertion. It can exchange that Assertion at your token endpoint (RFC 8693, `subject_token_type=urn:ietf:params:oauth:token-type:saml2`, the Assertion as base64url or padded base64). The SAML IdP does the verification:
- the Assertion carries its own signature;
- it was issued to the SP that is mapped to the authenticated client (`tokenExchange: { clientId }` on the SP);
- it is within its validity window;
- it hasn't been exchanged before (single use);
- the user and the session are still good.

The issuer then re-reads the user and applies bans and blocks.

```ts
betterAuth({
  plugins: [
    jwt(),
    oauthProvider({ /* … */ }),
    samlIdp({ /* … an SP with tokenExchange: { clientId } … */ }), // before idJagIssuer()
    idJagIssuer({
      authorize,
      saml: {
        subjectTokens: true,                     // (a) Assertion → ID-JAG
        refreshTokens: { scopes: ["openid", "offline_access", "profile", "email"] }, // (b) Assertion → refresh token
      },
    }),
  ],
});
```

- **(b) is what Okta and MCP's Enterprise-Managed Authorization use** (draft -04 §4.5). The client sends `requested_token_type=urn:ietf:params:oauth:token-type:refresh_token`, `scope=openid offline_access …` and no `audience` or `resource`. It gets back `{ issued_token_type: …:refresh_token, access_token: <the refresh token>, token_type: "N_A", scope, expires_in }`, then exchanges that refresh token for ID-JAGs as usual. Only confidential clients that list `refresh_token` in their grant types can do this. The scopes must include `openid` and `offline_access` and stay within your list, the client's and the provider's. Bans and (user), (user, client) and (client) blocks apply. The ID-JAG policy runs later, when the refresh token is exchanged. Each refresh token issued emits `onRefreshIssued`.

  **It is an ordinary refresh token from your provider**, the same as one from a sign-in, and that is what the draft and Okta specify. At `grant_type=refresh_token` it yields your IdP's own access tokens and ID tokens (for the scopes it was issued with), until it expires or is revoked. No consent row is created: the SP's `tokenExchange` mapping in better-auth-saml-idp is the authorization. So keep `refreshTokens.scopes` to what the agent needs. The example above, which is also the default, allows `profile` and `email`, so that refresh token can read the user's profile and email at `/oauth2/userinfo`. A block stops its exchange for ID-JAGs, not its use at `grant_type=refresh_token`; revoke it at `/oauth2/revoke` to stop both.
- **(a)** exchanges the Assertion directly for an ID-JAG, through the same policy as an ID token. `auth_time` is its AuthnInstant and `acr` its AuthnContextClassRef.
- **Either way, an Assertion works once.** Exchanging it again is refused, and so is presenting it from another client. Any `saml` option makes startup fail unless better-auth-saml-idp's exchange capability is on the context, which means **install `samlIdp()` before `idJagIssuer()`**. Assertions are capped at 64 KiB of XML.

## 🔑 Receiver: `idJagGrant()`

Adds the jwt-bearer grant to the host's token endpoint (`mcp()` or `oauthProvider()`) and advertises `authorization_grant_profiles_supported`. For each request it checks, in order:
1. the client authenticated, and is confidential;
2. the ID-JAG's format (`typ`, `alg`, `kid`, required claims, refused claims, lifetime) and its time claims, which are checks a caller can make for itself, so they come before anything that depends on whom we trust;
3. that the issuer is trusted, looked up from the unverified `iss` before any key is fetched;
4. that it isn't self-issued, then the signature against the issuer's JWKS, then `aud`, exactly;
5. that `client_id` is the authenticated client;
6. the scopes, which only narrow, decided before the subject so `no_scope` can't reveal whether a user exists;
7. the resource;
8. single use of `jti`;
9. the subject.

**Single use, deliberately.** Draft §4.4.3 lets a client re-present an unexpired ID-JAG for a new access token, and whether a resource authorization server should refuse that is an open question ([oauth-wg issue #130](https://github.com/oauth-wg/oauth-identity-assertion-authz-grant/issues/130)). This receiver accepts each ID-JAG **once**. Keycloak, node-oauth2-server and Authelia's library do the same. A client that needs another access token gets a fresh ID-JAG from the IdP, which keeps revocation at the IdP. An ID-JAG is burnt at step 8 even when step 9 then refuses it, so a captured token can't be used to probe for users. The access token it issues is audience-restricted to the resource.

### Options

| Option | Default | |
|---|---|---|
| `trustedIssuers` | `[]` | Issuers configured in code. See [Trusted issuers](#trusted-issuers). |
| `sso` | `false` | `true` or `{ providerIds?, emailFallback?, jitProvisioning?, allowedClientIds? }`: also trust `@better-auth/sso`'s OIDC providers. |
| `trustedIssuerTable` | `false` | Also read trusted issuers from the `idJagTrustedIssuer` table (adds the table). |
| `resolveSubject` | | `(input) => { action: "link", userId } \| { action: "continue" } \| { action: "reject" }`. Runs before the default resolution. |
| `scim` | | `{ acquireActiveSCIMUserLink }`, imported from `@better-auth/scim`: needed when a trusted issuer has `scim`. See [SCIM-provisioned users](#scim-provisioned-users). |
| `defaultResource` | | The resource when neither the ID-JAG nor the request names one. Must be a registered resource. |
| `requireResourceClaim` | `false` | Refuse an ID-JAG without a `resource` claim. |
| `allowEmptyScope` | `false` | Issue a token with no scope when the intersection is empty, instead of `invalid_scope`. |
| `allowPublicClients` | `false` | Logs a warning at startup when set. |
| `clockSkewSeconds` | `60` | Allowed skew on `iat`, `nbf` and `exp`, 0 to 300. |
| `maxLifetimeSeconds` | `900` | The longest `exp − iat` accepted. |
| `fetch` | the global `fetch` | The only fetch the receiver uses (JWKS and discovery). |
| `jwks` | | `{ timeoutMs: 5000, maxBytes: 65536, cacheTtlSeconds: 600, minRefetchIntervalSeconds: 60, maxStaleSeconds: 3600 }`. An unknown `kid` refetches, at most once per interval. While the issuer's JWKS can't be fetched, cached keys keep working for at most `maxStaleSeconds` past their TTL, then every request is refused until a fetch succeeds. |
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
2. With `scim` on the trust entry: the user that SCIM connection provisioned with `externalId` = `sub`, while active. If there's none, the grant is refused, and steps 3–5 don't run, unless `scim.required` is `false`. See [SCIM-provisioned users](#scim-provisioned-users).
3. A linked account: `providerId` = `accountProviderId` (default `id-jag:<issuer>`), `accountId` = the ID-JAG's `sub`.
4. Only if `emailFallback` lists the domain: a local user with that verified email, which is then linked.
5. Only if `jitProvisioning` is on: a new user, from the `email` claim, marked verified only with `trustEmailVerified`, and linked. With `organizationId` and the organization plugin, they become a member with `jitRole`.

Otherwise the grant is refused (`unknown_subject`). A banned user (the admin plugin) is refused too.

### SCIM-provisioned users

When the IdP provisions its users to your app over SCIM (Better Auth's [`@better-auth/scim`](https://www.better-auth.com/docs/plugins/scim) at your app, and, for a Better Auth IdP, [better-auth-scim-provisioning](https://github.com/mmcintosh/better-auth-scim-provisioning) there), the receiver can resolve ID-JAGs to those users. Deprovisioning at the IdP then stops the agent at your app too:

```ts
import { acquireActiveSCIMUserLink, scim } from "@better-auth/scim";

plugins: [
  scim({ connections: [{ id: "acme-idp", credentials: [{ type: "bearer", id: "acme", token: process.env.ACME_SCIM_TOKEN }] }] }),
  idJagGrant({
    scim: { acquireActiveSCIMUserLink },
    trustedIssuers: [{ issuer: "https://idp.acme.com/api/auth", jwksUri: "https://idp.acme.com/api/auth/jwks", scim: { connectionId: "acme-idp" } }],
  }),
],
```

- **The ID-JAG's `sub` is the SCIM `externalId`.** Our issuer's `sub` is the IdP's user id, which is better-auth-scim-provisioning's default `externalId`; a `mapUser` that changes `externalId` breaks the link. For Okta, its SCIM must send the Okta user id as `externalId`.
- **Only active users of that connection.** `acquireActiveSCIMUserLink` finds the user that this connection provisioned, while the SCIM user is active and the connection isn't decommissioned. It never falls back to the email, the userName or a deleted identity. A user deactivated, deleted or banned at the IdP (better-auth-scim-provisioning deactivates them) is refused, even with an ID-JAG issued before that. A banned local user is refused too.
- **Required by default.** With no active provisioned user, the grant is refused (`unknown_subject`), so a deprovisioned user can't come back through an older account link, the email fallback or JIT. `scim: { connectionId, required: false }` falls through to those steps instead, as a migration aid only: a deprovisioned user who is linked by `sub` is then still found. Users that `@better-auth/scim` creates have `emailVerified: false`, so the email fallback never matches them, and JIT refuses their email as taken. The email fallback and JIT also need the issuer to send `email` at all (our issuer: `claims: { email: true }` in the policy).
- **Needs a database with transactions.** The lookup runs in the adapter's transaction (it bumps the SCIM subject's revision, so a concurrent deprovisioning is detected; a conflict is retried once, then refused). `@better-auth/scim` refuses adapters without native transactions: it works on Postgres, MySQL and SQLite, and on Drizzle and Prisma with `transaction: true`, **not on Cloudflare D1**.
- **Provisioning is asynchronous, and the step fails closed.** A user whose SCIM create hasn't reached your app yet (just signed up, an email not yet verified, the SCIM target down and retrying) is refused, and a retry succeeds once it's delivered. Only users the IdP provisions to that target resolve: better-auth-scim-provisioning sends only users with a verified email by default (`requireVerifiedEmail`), and a target can be scoped to an organization or a list. Everyone else is refused, which is the point.
- **Your `resolveSubject` hook runs first.** A hook that returns `link` decides before the SCIM step, so it can bring back a user SCIM would refuse: that overrides `scim.required`.
- **Access tokens already issued** live until they expire, as with every cutoff: see [What ID-JAG controls](#-what-id-jag-controls-and-what-your-mcp-server-still-must). `@better-auth/scim` ends the user's sessions at your app when they're deprovisioned.
- **The `idJagTrustedIssuer` table** has the same settings as a `scimConnectionId` column and a `scimRequired` column (null means required). A row with `scimConnectionId` on a host that didn't pass `acquireActiveSCIMUserLink` is refused, not resolved some other way.
- The `id-jag.accepted` event says how each user was found (`resolvedBy`: `"scim"`, `"account"`, `"email"`, `"jit"` or `"hook"`).

### SAML NameID subjects (`sub_id`)

When your users sign in through SAML (`@better-auth/sso`), the IdP can put the SAML NameID it would send you in the ID-JAG's `sub_id` (draft §3.2, format `saml-nameid`). A static trust entry with `samlSubjects` then resolves users by that NameID instead of `sub`. The account key becomes `providerId` = the mapping's `accountProviderId` and `accountId` = the NameID. That is the same key `@better-auth/sso` stores for a SAML sign-in, so set `accountProviderId` to the sso SAML provider's `providerId`. This applies to steps 3–5 above. The hook still runs first. Mappings are only read from the trust entry that `iss` matched, so `sub_id.issuer` never makes an issuer trusted. A mapping matches when `issuer` is equal and `spNameQualifier` and `nameQualifier` are equal, with "not configured" meaning "must be absent". It also checks `nameIdFormats` if you list any. A malformed `sub_id`, a transient NameID, or one with no matching mapping is refused (`subject_rejected`), never resolved by `sub` instead. With `requireSubId: true`, an ID-JAG without a SAML `sub_id` is refused as well. Without `requireSubId`, such an ID-JAG falls back to `sub`. A trust entry without `samlSubjects` ignores `sub_id`. Each SAML namespace needs its own `accountProviderId`, so the same NameID from two IdP connections gives two users. JIT still needs an `email` claim, because Better Auth users have an email address. The `idJagTrustedIssuer` table has the same two settings, as a `samlSubjects` JSON column and a `requireSubId` column.

```ts
trustedIssuers: [{
  issuer: "https://acme.okta.com/oauth2/default",
  jwksUri: "https://acme.okta.com/oauth2/default/v1/keys",
  samlSubjects: [{
    issuer: "http://www.okta.com/exk123",                 // the SAML IdP entity ID (sub_id.issuer)
    spNameQualifier: "https://mcp.example.com/saml/sp",   // omit if the IdP sends none
    nameIdFormats: ["urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"],
    accountProviderId: "acme-saml",                       // the @better-auth/sso SAML providerId
  }],
  requireSubId: true,
}],
```

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

## 🛡️ What ID-JAG controls, and what your MCP server still must

ID-JAG is **coarse-grained, enterprise-controlled access**: may this agent act for this user at this app, and with which scopes. The rest of an agent's permissions is layered on top, and most of it is your MCP server's job.

| Layer | Who decides | With this package |
|---|---|---|
| Which agents may act for which users at which apps | The IdP: its connections, assignments and user status, checked at every exchange | Our issuer: your `authorize` policy, the registry and blocks. Okta: its resource connections (verified live, [docs/interop.md](docs/interop.md)) |
| Which scopes the agent gets | The IdP grants them; the receiver intersects the request's scopes with the ID-JAG's | The access token is audience-bound to the resource and carries only those scopes |
| Which tools a scope unlocks | **Your MCP server**: check the token's `scope` on every tool call (for example `read` for listing, `write` for changes) | This package never sees tool calls |
| Different rights for different users | The IdP's policies (per group); your app's roles | JIT can add new users to an organization with a role (`organizationId`, `jitRole`) |
| Which records | **Your app** | Rich Authorization Requests (`authorization_details`) are refused for now |
| Who is acting | The ID-JAG's `act` claim names the agent (Okta sends it) | Carried into the access token: log it, or allow agents less than people |

**How fast a cutoff takes effect.** When the IdP stops an agent (a connection removed, a user unassigned or deactivated), it stops issuing ID-JAGs at once. An ID-JAG already issued lives at most its lifetime (300 s by default, 900 s at most) and works once. But an **access token already issued lives until it expires**: the provider's `accessTokenExpiresIn`, **an hour by default**. No refresh token is issued, so the agent then needs a new ID-JAG. For agents, set a short `accessTokenExpiresIn` on `mcp()` or `oauthProvider()`, and `scopeExpirations` (for example `{ write: "5m" }`) for the sensitive scopes.

## ✅ Conformance

Against [draft-ietf-oauth-identity-assertion-authz-grant-04](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/04/) and MCP's [Enterprise-Managed Authorization](https://github.com/modelcontextprotocol/ext-auth/blob/main/specification/stable/enterprise-managed-authorization.mdx). ✅ implemented and tested · ⚠️ implemented, with a deliberate choice · ❌ not implemented (refused by name, never silently ignored).

**Issuer** (`idJagIssuer()`, experimental)

| | Draft | |
|---|---|---|
| ✅ | §4.3 Token exchange, `requested_token_type` id-jag | Any other requested type is refused (`invalid_request`), so a future generic token exchange isn't shadowed. |
| ✅ | §4.3.3 Subject token: an ID token | Only one this IdP issued, for the authenticated client (`aud`), unexpired and at most `maxIdTokenAgeSeconds` old. |
| ✅ | §4.3.3 Subject token: a refresh token (MAY) | Only one this IdP issued to the authenticated client, unrevoked; the exchange doesn't consume or rotate it. |
| ✅ | §4.3, §4.5 Subject token: a SAML 2.0 assertion | Experimental; with better-auth-saml-idp ≥ 1.2.0. Directly to an ID-JAG, or to a refresh token (§4.5, MCP's SAML path). |
| ✅ | §4.3 `audience`, `resource`, `scope` | One audience and at most one resource per request; scopes only narrow. |
| ❌ | §4.3 `actor_token` | Refused (`invalid_request`). |
| ✅ | §3.1 Claims: `iss`, `sub`, `aud`, `client_id`, `jti`, `exp`, `iat`, `resource`, `scope`, `auth_time`, `acr`, `amr`, `tenant` | `iss` is exactly the metadata's `issuer`; `client_id` is the client's id **at the resource** (policy-mapped). |
| ✅ | §3.1 `email` | Only when the policy opts in and the email is verified. |
| ❌ | §3.1 `aud_sub`, `sub_id` (minting), `act` (minting), `authorization_details` | Not minted. (`sub_id` minting is deferred until a resource server needs it.) |
| ✅ | §4.3.4 Response: `issued_token_type`, `token_type: N_A`, `expires_in`, `scope` | |
| ✅ | §7 Metadata `identity_chaining_requested_token_types_supported` | |
| ⚠️ | §9.1 Confidential clients only (SHOULD) | Default; `allowPublicClients` turns it off, with a startup warning. |
| ✅ | Short lifetimes (§3.1's examples use 5 minutes) | 300 s by default, 900 s at most. |
| ❌ | §9.2 Step-up (`insufficient_user_authentication`) | Not implemented; the `authorize` hook can deny on `acr`/`auth_time` instead. |
| ❌ | §9.8 DPoP / `cnf` sender-constrained ID-JAGs | Not minted. |

**Receiver** (`idJagGrant()`)

| | Draft | |
|---|---|---|
| ✅ | §4.4 jwt-bearer grant (RFC 7523) for `typ: oauth-id-jag+jwt` | Other assertions are refused; a future plain RFC 7523 grant isn't shadowed. |
| ✅ | §4.4.1 `typ`, signature, `iss` trusted, `aud` = our issuer exactly (a single-element array allowed), `client_id` = the authenticated client, `exp`/`iat`/`nbf` | In the order shown under [Receiver](#-receiver-idjaggrant); refusals that depend on trust are indistinguishable to the caller. |
| ⚠️ | §4.4.3 Re-presenting an ID-JAG | **Refused: single use** ([#130](https://github.com/oauth-wg/oauth-identity-assertion-authz-grant/issues/130)). Get a fresh ID-JAG from the IdP. |
| ✅ | §4.4.3 No refresh token | Never issued (`offline_access` is stripped), and no ID token. |
| ✅ | `resource`, `scope` | The resource must be one of ours (`invalid_target`); scopes intersect the ID-JAG's, the client's and the resource's. |
| ✅ | MCP: the access token is audience-restricted to the MCP server | `aud` = the resource. |
| ✅ | §3.1 `act` | Accepted (shape-checked, at most 4 nested actors) and carried into the access token. |
| ✅ | §3.2 `sub_id` (`saml-nameid`) | Resolves users by SAML NameID when the trust entry maps it; never a source of trust (§9.5). |
| ⚠️ | §3.1 `email` | Used only with `emailFallback` for listed domains (a verified local user) or JIT; never by default. |
| ✅ | §3.1 `tenant` | A trust entry can pin it. |
| ❌ | §3.1 `aud_tenant`, `aud_sub` | Ignored. |
| ❌ | §4.4.1 `authorization_details` (RFC 9396) | Refused (`unsupported_claim`): the draft says a receiver MUST process it. |
| ❌ | §9.8 DPoP / `cnf`, `jwt-dpop` grant | An ID-JAG with `cnf` is refused (`unsupported_claim`), as §9.8.1.2 requires without a DPoP proof. |
| ✅ | §9.3 Not self-issued | An ID-JAG whose `iss` is this server is refused. |
| ⚠️ | §9.1 Confidential clients only (SHOULD) | Default; a CIMD client counts as confidential only with `private_key_jwt`. |
| ✅ | §7 Metadata `authorization_grant_profiles_supported`, jwt-bearer in `grant_types_supported` | |

## 🤝 Interoperability

| Our side | Other side | Status |
|---|---|---|
| Issuer | Our receiver | ✅ Verified, in every CI run, on Node and in workerd |
| Issuer | Keycloak 26.8.0 (`identity-assertion-jwt`, experimental) | ✅ Verified; ES256, RS256 and EdDSA. Keycloak ignores `scope` and `resource` |
| Issuer | node-oauth2-server ([PR #462](https://github.com/node-oauth/node-oauth2-server/pull/462), unreleased) | ✅ Verified; ES256 and RS256 (no EdDSA there) |
| **Okta Cross App Access** | Receiver on Workers + D1 | ✅ **Verified live**, RS256, with Okta's `act` carried into the access token; refresh-token subjects; Okta's connection, assignment and deactivation controls; our replay and `client_id` checks |
| **xaa.dev** (Okta's playground), OIDC and SAML | Receiver on Workers + D1 | ✅ **Verified live** with its resource-app tester through to an MCP `tools/call`; SAML users resolved by NameID (`sub_id`) |
| better-auth-saml-idp 1.2.0 (SAML assertions) | Issuer → our receiver | ✅ Verified end to end: Assertion → refresh token → ID-JAG, and Assertion → ID-JAG |
| better-auth-scim-provisioning 1.0.0 → `@better-auth/scim` 1.7.6 | Issuer → our receiver | ✅ Verified in every CI run (Node): users provisioned by the IdP resolve by SCIM; banned or deleted at the IdP, refused at the receiver, even with an earlier ID-JAG |
| Issuer / receiver | Authelia | ⏳ Not possible yet: no release ships ID-JAG |
| Receiver | Keycloak as issuer | ⏳ Not possible: Keycloak doesn't issue ID-JAGs |

Each row's date, version, commands and the ways the other side differs are in [docs/interop.md](docs/interop.md). Nothing there is claimed from reading docs alone.

**Sign with ES256 or RS256** unless every receiver you target accepts EdDSA: Better Auth's `jwt()` defaults to EdDSA, and node-oauth2-server, among others, refuses it.

## ☁️ Example: two Workers

[examples/workers](examples/workers/README.md) is the whole flow on Cloudflare Workers with D1: an **enterprise IdP** (`oauthProvider()` + `jwt()` + `idJagIssuer()`), an **MCP server** (`mcp()` + `jwt()` + `idJagGrant()`) with one tool, `whoami`, and `client.mjs`, which plays the agent through every step and then shows a replay being refused. It also covers the two Workers limits you'll meet (a Worker can't fetch another on the same account by URL, or itself), and how to point Okta Cross App Access at the MCP server.

## 🧩 Runtimes and databases

The whole suite runs on Node.js (`node:sqlite`) and in workerd with D1, except the SCIM tests, which need a database with transactions (`@better-auth/scim` doesn't run on D1). CI runs it on Node 24 with Better Auth 1.7.5 and the latest 1.7.x, and on Node 22 with 1.7.5. CI also runs the database-sensitive behaviour on **PostgreSQL, MySQL, MongoDB, Drizzle (PostgreSQL and MySQL) and Prisma**: single use under concurrency, the sweeps, concurrent first use, and SCIM resolution (not MongoDB, which the matrix runs without transactions). The built package is checked as a strict TypeScript host would use it, under TypeScript 7 and 5.9, with publint and Are the Types Wrong. The receiver's single-use check relies on a UNIQUE constraint, so use a database adapter that enforces one (not Better Auth's memory adapter, which the plugin warns about at startup).

## 🧭 Not yet

- **A later draft:** -04 expires on 2026-11-22. When -05 appears, [src/core/urns.ts](src/core/urns.ts) and this README will say which draft is implemented.
- The rows marked ❌ in [Conformance](#-conformance). Each one is refused by name, not silently ignored.
- No admin API for trusted issuers yet: configure them in code, through `@better-auth/sso`, or in the table directly.
- SCIM-provisioned users on Cloudflare D1: `@better-auth/scim` needs a database with native transactions.

## 🔒 Security

- [docs/security.md](docs/security.md) has the threat model, what your app must configure, and the known limitations.
- [DECISIONS.md](DECISIONS.md) records every security-relevant decision, with its tests and mutation proofs.
- Each security check is mutation-tested: `scripts/mutate.py` removes it, and CI fails if no test notices. It runs weekly on `main`.
- All GitHub Actions are pinned by SHA, with least-privilege tokens, and the history is scanned with gitleaks. CodeQL and OpenSSF Scorecard run on every push, and every dependency install in CI goes through Socket Firewall.
- Releases are published from CI with npm provenance, each with a CycloneDX SBOM on its GitHub release.

Please report vulnerabilities privately, as [SECURITY.md](SECURITY.md) describes, not in public issues. Versioning, the draft and Better Auth compatibility are in [docs/versioning.md](docs/versioning.md).

## 🧪 Development

```bash
pnpm test            # Node + workerd (D1)
pnpm test:node       # one runtime only
pnpm test:workerd
pnpm typecheck
pnpm lint            # Biome
pnpm docs:check      # every relative link and #anchor in the Markdown docs
pnpm build           # dist + type declarations
pnpm pack:check      # the built package: strict host under TypeScript 7 and 5.9, publint, Are the Types Wrong
ADAPTER_DB=postgres ADAPTER_URL=postgres://… pnpm vitest run --project node test/adapters   # the adapter matrix
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
