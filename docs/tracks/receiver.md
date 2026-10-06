# Track A: the receiver (`idJagGrant`)

Phase 1, Track A. The receiver lets a Better Auth app that is an MCP server's authorization server
(`@better-auth/mcp`, or `@better-auth/oauth-provider`) accept ID-JAGs (draft -04) over the
`urn:ietf:params:oauth:grant-type:jwt-bearer` grant. It issues its own access token,
audience-restricted to the MCP resource.

## What is here

| File | What it does |
|---|---|
| `src/receiver/plugin.ts` | `idJagGrant(options)`: from `init`, registers the grant and the `authorization_grant_profiles_supported` metadata through `extendOAuthProvider`. Also declares the schema (`idJagJti`; `idJagAudit` with `auditLog`; `idJagTrustedIssuer` with `trustedIssuerTable`) and logs the startup warnings. `idJagGrantExtension(resolved)` is exported for hosts that build their own extension list. |
| `src/receiver/grant.ts` | `handleIdJagGrant(input, resolved)`: the grant handler as a plain function, steps 1–10 below. |
| `src/receiver/options.ts` | The options types, their zod schema (strict: unknown keys refused) and `resolveReceiverOptions()`, which validates the options and builds the state: JWKS cache, clock, sweep throttle. |
| `src/receiver/trust.ts` | `findTrustedIssuer`: static config, `@better-auth/sso` OIDC rows and the `idJagTrustedIssuer` table, combined. |
| `src/receiver/jwks.ts` | `JwksCache`: JWKS and discovery fetches under the S10 network rules, with a cache by kid and a refetch rate limit. |
| `src/receiver/resolve.ts` | `resolveSubject`: the host hook, then the linked account, then the email fallback, then JIT. |
| `src/receiver/schema.ts` | The `idJagTrustedIssuer` table. |
| `src/receiver/index.ts` | The public API (below). `src/index.ts` is not wired; that happens at merge. |

### Public API (`src/receiver/index.ts`)

- **Plugin:** `idJagGrant(options)`, `idJagGrantExtension(resolved)`, `RECEIVER_PLUGIN_ID`.
- **Handler, as a plain function:** `handleIdJagGrant(input, resolved)`, `resolveReceiverOptions(options)`.
- **Building blocks:** `findTrustedIssuer`, `resolveSubject`, `JwksCache`, `registeredResources`, `openIdConfigurationUrl`, `trustedIssuerSchema`, `TRUSTED_ISSUER_MODEL`, `STRIPPED_SCOPES`.
- **Types:** `IdJagGrantOptions`, `StaticTrustedIssuer`, `SsoTrustOptions`, `ResolveSubjectInput`, `SubjectResolution`, `TrustedIssuerView`, `TrustEntry`, `ResolvedReceiverOptions`, `FetchLike`, `JwksSettings`, `KeySource`, `IssuerKeys`, `ResolvedSubject`.

### Options

```ts
idJagGrant({
  trustedIssuers?: [{ issuer, jwksUri? | discoveryUri?, organizationId?, allowedClientIds?, tenant?,
                      accountProviderId?, emailFallback?: { domains }, jitProvisioning?: boolean | { trustEmailVerified? } }],
  sso?: boolean | { providerIds?, emailFallback?, jitProvisioning?, allowedClientIds? },   // default off
  trustedIssuerTable?: boolean,                                                           // default off
  resolveSubject?: (input) => { action: "link", userId } | { action: "continue" } | { action: "reject" },
  defaultResource?: string,
  allowPublicClients?: boolean,      // default false; warns at startup
  allowEmptyScope?: boolean,         // default false
  clockSkewSeconds?, maxLifetimeSeconds?,                 // validated by the core: [0, 300], [1, 900]
  fetch?: (url, init) => Promise<Response>,               // the only fetch the receiver uses
  jwks?: { timeoutMs = 5000, maxBytes = 65536, cacheTtlSeconds = 600, minRefetchIntervalSeconds = 60 },
  events?, auditLog?: { retentionDays },                  // core/audit.ts
  clock?: () => Date,                                     // for tests
})
```

## The plan's §3.4 steps, as built

The order is D-007's, as the Phase 1 brief corrected it.

| Step | Where | How |
|---|---|---|
| 1. Client | `grant.ts` | `provider.authenticateClient({ requireCredentials: !allowPublicClients })`. The provider throws its own `invalid_client` / `unauthorized_client`. Then our own check refuses a client whose method or registration is `none` (`public_client`). A discovered (CIMD) client counts only with `private_key_jwt`. `authenticated: true` is set only after this. |
| 2. Parse | `grant.ts` | `parseIdJag` (the core: typ, alg, kid, crit, required and unsupported claims, lifetime). Then `checkTimes` **before** the trust lookup, so `expired` / `not_yet_valid` can't confirm whether an issuer is trusted (S8). A plain RFC 7523 assertion fails here with the public `wrong_typ`. |
| 3. Trust | `trust.ts` | Looks up the **unverified** `iss` (and `tenant`) in the three sources. No match is `untrusted_issuer`, and so are two or more. Nothing is fetched for an untrusted issuer. |
| 4. Signature, `aud` | `grant.ts`, `jwks.ts`, core | `verifyIdJag(token, key, { issuer: trust.issuer, audience: getIssuer(ctx, opts) })`. `key` is a lazy resolver, so verifyIdJag's own order holds: `iss`, `self_issued`, then the signature, and only the signature fetches keys. The resolver also refuses an `alg` the issuer's JWKS doesn't publish, as `bad_signature`. `aud` is compared exactly. |
| 5. `client_id` | `grant.ts` | `claims.client_id === authenticated clientId`, exactly (D-004). Then the trust entry's `allowedClientIds`, if set. Both are `client_mismatch`. |
| 6. Scopes (moved before the subject, D-007) | `grant.ts` | Granted = ID-JAG `scope` ∩ the request's `scope` (if sent) ∩ the client's registered scopes ∩ the resource's scopes. The resource's scopes are its `allowedScopes`, or else the provider's advertised or configured scopes. `openid` and `offline_access` are always removed. Empty → `no_scope`. |
| 7. Resource | `grant.ts` | Picked from the claim, or else the request's `resource`, or else `defaultResource`, or else the only registered one. It must be in `opts.resources`; for `mcp()` that includes its `resource`. Otherwise `unknown_resource` (`invalid_target`). Plan §3.4 step 9. |
| 8. `jti` | core | `recordJti(adapter, { side: "accepted", ..., exp, clockSkewSeconds })`; `false` → `replay`. |
| 9. Subject | `resolve.ts` | Plan step 10: the hook, then the account (`providerId` = the entry's account provider id, `accountId` = `sub`), then the email fallback (opt-in, listed or verified domains), then JIT (opt-in). Banned users are refused. |
| 10. Issue | `grant.ts` | `provider.issueTokens({ client, user, scopes, resources: [resource], accessTokenClaims: { idjag: { iss, jti, tenant? } }, authTime, tokenResponse: {} })`. With no `offline_access` there is no refresh token, and with no `openid` no ID token. `id-jag.accepted` is emitted. |

Every refusal is an `IdJagRefusal`. It is emitted as `id-jag.refused` and thrown as `toApiError(...)`.
`sweepJtis` and `sweepAudit` run in the background at most once a minute per instance (`maybeSweep`).

## Decisions (each the agent's choice; for the maintainer to confirm)

- **D-A01: sso trust is opt-in** (`sso: true | {…}`; default off). `@better-auth/sso` providers exist for sign-in. Trusting every one of them for ID-JAGs by default would widen what they can do. Depending on the host's sso configuration, ordinary users may be able to register providers. The plan's G1 ("from any IdP registered in sso") is still one option away.
- **D-A02: our own discovery and JWKS fetch, not sso's `discoverOIDCConfig` / `fetchDiscoveryDocument`.** Those use Better Auth's global-fetch-based `betterFetch`, and S10 needs one injectable `fetch` with our caps.
  - Discovery: the document's `issuer` must equal the trusted issuer exactly. Its `jwks_uri` may be on another host, as OIDC allows, but must be https.
  - Without `jwksEndpoint` or `discoveryEndpoint`, an sso row (or table row) uses `<issuer>/.well-known/openid-configuration`.
- **D-A03: lazy key resolution.** The JWKS fetch happens inside the signature check, so nothing is fetched for a self-issued token, or for one refused at `iss`.
- **D-A04: ambiguous trust is refused.** The same `iss` (and tenant) in two entries means two sets of keys and account links; neither is picked. The cause is logged as a warning.
- **D-A05: account provider ids.**
  - An sso-trusted issuer links accounts under the sso `providerId` (what sso creates at sign-in).
  - A static entry uses `accountProviderId`, default `id-jag:<issuer>`.
  - A table row uses its `ssoProviderId`, or else that same default.
- **D-A06: resources.**
  - One resource per token.
  - A request may only pick among the resources the ID-JAG names.
  - An ID-JAG without `resource` is redeemable for one registered resource: the request's choice, `defaultResource`, or the only registered one. More than one candidate is refused rather than guessed.
  - The MCP extension expects the claim. Requiring it is open question 3.
  - `defaultResource` must be registered: checked at startup.
- **D-A07: no `issueRefreshToken` option.** `openid` and `offline_access` are always removed. The provider issues a refresh token only for `offline_access` (docs/phase-0.md finding 3), and an ID token only for `openid`. A regression test asserts neither appears, for a client allowed `refresh_token` and an ID-JAG that asks for both.
- **D-A08: two guards for public clients.**
  - `requireCredentials: !allowPublicClients` is what the brief asked for.
  - Our own check after it refuses method/registration `none` as `public_client`, so the refusal is ours and audited if the provider's behaviour changes.
  - The provider's own client-authentication errors (wrong secret, missing credentials, unauthorized grant) are passed through unchanged and **not audited**. The core has no reason code for them; see core change request 1.
- **D-A09: email fallback.**
  - Exact domain match, lowercase, no subdomains.
  - For sso rows it needs `domainVerified === true` (sso's `domainVerification` must be enabled); the row's `domain` may be a comma-separated list.
  - It never takes a user who already has an account at the same issuer under another `sub`.
  - It never re-links an orphaned account row.
- **D-A10: JIT.**
  - Needs an `email` claim.
  - Refused if a user with that email exists: only the email fallback may match existing users.
  - `emailVerified` is false unless `trustEmailVerified`.
  - Uses `internalAdapter.createUser(…, { method: "id-jag" })`, so `user.validateUserInfo` applies.
  - **No organization membership in Phase 1** (open question 4).
- **D-A11: JWKS cache.**
  - Per plugin instance, keyed by (issuer, jwksUri, discoveryUri), with kids looked up within an entry.
  - TTL 10 min. An unknown kid or an expired entry refetches only if the last *attempt*, failed ones included, is ≥ 60 s old; otherwise the cached keys answer, and an unknown kid fails as `bad_signature`.
  - Concurrent lookups share one in-flight fetch.
  - 64 KiB cap, checked from `content-length` and again while streaming. A 5 s deadline races the whole exchange and aborts the signal, so a fetch that ignores the signal still loses.
  - At most 100 keys; `use: "enc"` keys dropped. An empty set is `jwks_unavailable` (S1).
- **D-A12: the `idJagTrustedIssuer` table** is a third source, opt-in (`trustedIssuerTable: true`, which also adds the table to the schema).
  - Read-only in Phase 1. Rows are written by the host; there is **no admin API**.
  - List columns (`allowedClientIds`, `emailDomains`) are JSON strings.
  - An invalid row is ignored with a warning.
  - The plan's "unique per org" can't be declared in Better Auth's plugin schema format; only `issuer` is indexed.
- **D-A13: `tenant` pinning.** A static or table entry with `tenant` matches only ID-JAGs with that `tenant` claim. This is Okta's `iss` + `tenant` mapping for multi-tenant IdPs.
- **D-A14: the hook fails closed.** A throw, or anything that isn't `link` / `continue` / `reject`, is `subject_rejected`. `link` to a missing user is `unknown_subject`.
- **D-A15: provider errors after the `jti` is recorded.** One example: `issueTokens` throwing `invalid_target` because `enforcePerClientResources` (default true) finds the client unlinked from the resource. These burn the `jti` and are not audited. The client gets a new ID-JAG. `mcp()` links its resource to every new client, so this needs a misconfigured host.
- **D-A16: the access token carries `idjag: { iss, jti, tenant? }`** (plan §3.4 step 12), as a per-issuance JWT claim. It isn't visible at opaque-token introspection, which doesn't apply here: with a resource, the token is a JWT.
- **D-A17: a `clock` option** (for tests). It drives the time checks, the JWKS cache and the sweep throttle. Access-token times are the provider's.

## Evidence

Run on 2026-10-06, Better Auth 1.7.6 (D-002).

- **`pnpm typecheck` and `pnpm lint`:** clean.
- **`pnpm test`:** 26 files, 304 tests, all passing: 152 on Node (node:sqlite) and 152 in workerd (D1).
  - The receiver's own tests: 92 per runtime, in 8 files under `test/receiver/`.
  - The rest of the suite (core and the Phase 0 spike) is unchanged.
- **Exit criterion** (`test/receiver/exit.test.ts`, both runtimes):
  - A hand-minted ES256 ID-JAG from the test IdP yields an access token at the `mcp()` host.
  - `requireMcpAuth(auth, handler, { resource: MCP_RESOURCE })` accepts it and passes the claims (`sub` = the local user, `aud` = the resource, `iss` = our issuer, `scope: "read"`).
  - The same token with `{ resource: "http://localhost:3000/other-mcp" }` gets a 401 with a `Bearer` challenge, and so does a tampered token.
  - requireMcpAuth uses the global fetch for the AS JWKS, so the test routes that one URL to the host.
- **Every reason code** the receiver produces is asserted by its audit reason and by the exact response body: `missing_parameter`, `malformed_token`, `wrong_typ`, `disallowed_alg`, `missing_kid`, `missing_claim`, `unsupported_claim`, `invalid_claim`, `lifetime_too_long`, `expired`, `not_yet_valid`, `untrusted_issuer`, `self_issued`, `jwks_unavailable`, `bad_signature`, `wrong_audience`, `client_mismatch`, `no_scope`, `unknown_resource`, `replay`, `unknown_subject`, `subject_rejected`, `banned_user`, `public_client`.
  - `public_client` is reached through a fake provider: the real one refuses public clients first (D-A08).
  - The provider's `invalid_client` and `unauthorized_client` are asserted by body.
- **S8:** unknown subject, untrusted issuer, bad signature, replay, wrong audience and client mismatch give byte-identical bodies and statuses. An expired token says the same whether its issuer is trusted or not.
- **S3:** 10 concurrent redemptions of one ID-JAG across two auth instances on one database: exactly one 200, nine identical refusals, all `replay`.
- **S9:** fast-check, 300 runs each, on arbitrary JWKS bodies and statuses and on arbitrary discovery documents. The only outcomes are a key set or `jwks_unavailable`.

### Each guard broken once (`test/mutations/receiver.json`, `python3 scripts/mutate.py test/mutations/receiver.json`)

63 mutations over `src/receiver/**`, plus three in the core seen from the receiver's tests: S2 `typ`, S8 the public `unknown_subject`, and the core's parse. **Final run: 63 caught, 0 survived.**

The first run caught 56 and 7 survived. Each was then handled:

| Survivor (first run) | Why | Now |
|---|---|---|
| SAML sso rows trusted (presence check removed) | Equivalent: a missing `oidcConfig` also fails the schema parse | Replaced by a mutant that removes both guards: caught |
| `authenticated: true` before client authentication | Our own `public_client` is unreachable behind the provider | Unit test with a fake provider (method `none`, missing, or a CIMD client without `private_key_jwt`): caught |
| Resource-supported scopes ignored | Every test client had a scope list | A client with no registered scopes, on `oauthProvider()`: caught |
| Request may pick a resource outside the ID-JAG's | The other resource was unregistered as well | A host with two registered resources: caught |
| Time checks after the trust lookup | Only tested with a trusted issuer | An expired token from an untrusted issuer must say `expired`: caught |
| No size cap from `content-length` | The streamed cap caught the same body | A declared-huge, endless body must be refused without reading: caught |
| Hook `reject` ignored | Fell through to "no decision", the same reason | The refusal's detail is asserted: caught |

| S-item | Mutations (all caught) |
|---|---|
| S1 trust, no trust = deny, empty JWKS | 7 |
| S2 typ | 1 |
| S3 aud exact, client_id continuity, jti single use | 6 |
| S4 alg narrowing, refetch rate limit, rotation, cache, discovery issuer | 7 |
| S5 confidential only, startup warning, `authenticated` flag | 3 |
| S7 scope intersection, stripped scopes, resource set, audience restriction | 9 |
| S8 order (time before trust, scope before subject), generic wording | 3 |
| S10 https, redirects (3xx and opaque), size (declared and streamed), timeout, injected fetch | 8 |
| Subject resolution (plan step 10), trust options, options schema, sweeps, metadata | 19 |

S6 is the issuer's. S9 is covered by the property tests above. S11: the receiver holds no secrets of its own.

## Open questions for the maintainer

1. **sso trust opt-in** (D-A01): keep it opt-in, or default it on when sso is installed?
2. **Strict single use** (D-007's open item) stays. A client whose access token expired gets a new ID-JAG rather than re-presenting the old one.
3. **Require the `resource` claim?** The MCP extension says the access token must be audience-restricted to "the MCP Server identified by the `resource` claim". Today an ID-JAG without it is accepted for one registered resource (D-A06). A `requireResourceClaim` option, or making it the default, is a one-line change.
4. **JIT and organizations:** should JIT add the user to the trust entry's `organizationId` (with the organization plugin), as the plan says ("with the sso provider's `organizationProvisioning` role")? Not done in Phase 1.
5. **Access-token lifetime:** the provider's default (1 h). Should it be capped at the ID-JAG's `exp` or a receiver option? `issueTokens` has no per-issuance expiry, so a cap needs `scopeExpirations` or an upstream change.
6. **Unaudited client-authentication failures** (D-A08): fine as is, or wait for core change request 1?
7. **Admin API for `idJagTrustedIssuer`:** Phase 1 has none (D-A12). Is it wanted before 0.1 (plan G5), with the admin plugin's access control and `onAdminChanged` events?

## Core change requests

1. **A reason for provider client-authentication failures.** Then the receiver (and the issuer) could audit a wrong secret or a missing assertion. These would be `authenticated: false` refusals: handlers would see them, the table wouldn't store them.
   ```diff
   --- a/src/core/errors.ts
   +++ b/src/core/errors.ts
   @@ export const REASONS = {
      public_client: { error: "invalid_client", public: false },
   +  client_authentication_failed: { error: "invalid_client", public: false },
   +  unauthorized_client: { error: "unauthorized_client", public: false },
   ```
   The receiver would then catch the provider's `APIError` from `authenticateClient`, emit the refusal and rethrow the provider's error unchanged. That keeps the provider's `WWW-Authenticate` behaviour.
2. **`verifyIdJag` accepting an already-parsed token** (`verifyParsedIdJag(parsed, token, key, expected)`), to save the second `parseIdJag` and `checkTimes` the receiver now causes. Not needed for correctness; the double parse costs microseconds.
3. **Schema overlap at merge.** Both plugins declare `idJagJti` (and `idJagAudit`). A host with both installs the same model twice. Better Auth merges plugin schemas by model name and the fields are identical, so it should be harmless, but nothing has tested it yet. A Phase 2 host with both plugins should. If it isn't harmless, the core should export one "core tables" plugin both depend on.
