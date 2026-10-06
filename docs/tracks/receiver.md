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
| `src/receiver/resolve.ts` | `resolveSubject`: the host hook, then the subject's key (`subjectKey`: `sub`, or a mapped SAML NameID `sub_id`, D-A27–D-A31), then the linked account, then the email fallback, then JIT. |
| `src/receiver/membership.ts` | `addJitMembership`: a JIT-created user joins the trust entry's organization (Phase 2, D-A18–D-A20). |
| `src/receiver/schema.ts` | The `idJagTrustedIssuer` table. |
| `src/receiver/index.ts` | The public API (below). `src/index.ts` is not wired; that happens at merge. |

### Public API (`src/receiver/index.ts`)

- **Plugin:** `idJagGrant(options)`, `idJagGrantExtension(resolved)`, `RECEIVER_PLUGIN_ID`.
- **Handler, as a plain function:** `handleIdJagGrant(input, resolved)`, `resolveReceiverOptions(options)`.
- **Building blocks:** `findTrustedIssuer`, `resolveSubject`, `addJitMembership`, `DEFAULT_JIT_ROLE`, `JwksCache`, `registeredResources`, `openIdConfigurationUrl`, `trustedIssuerSchema`, `TRUSTED_ISSUER_MODEL`, `STRIPPED_SCOPES`.
- **Types:** `IdJagGrantOptions`, `StaticTrustedIssuer`, `SsoTrustOptions`, `ResolveSubjectInput`, `SubjectResolution`, `TrustedIssuerView`, `TrustEntry`, `ResolvedReceiverOptions`, `FetchLike`, `JwksSettings`, `KeySource`, `IssuerKeys`, `ResolvedSubject`, `MembershipOutcome`.

### Options

```ts
idJagGrant({
  trustedIssuers?: [{ issuer, jwksUri? | discoveryUri?, organizationId?, allowedClientIds?, tenant?,
                      accountProviderId?, emailFallback?: { domains }, jitProvisioning?: boolean | { trustEmailVerified? },
                      jitRole?,                 // needs organizationId; default "member"; checked against the organization plugin's roles (D-A26)
                      samlSubjects?: [{ issuer, spNameQualifier?, nameQualifier?, nameIdFormats?, accountProviderId }],
                      requireSubId? }],         // needs samlSubjects; default false (D-A27)
  sso?: boolean | { providerIds?, emailFallback?, jitProvisioning?, allowedClientIds? },   // default off
  trustedIssuerTable?: boolean,                                                           // default off
  resolveSubject?: (input) => { action: "link", userId } | { action: "continue" } | { action: "reject" },
  defaultResource?: string,
  allowPublicClients?: boolean,      // default false; warns at startup
  allowEmptyScope?: boolean,         // default false
  requireResourceClaim?: boolean,    // default false (D-A06, D-A21)
  clockSkewSeconds?, maxLifetimeSeconds?,                 // validated by the core: [0, 300], [1, 900]
  fetch?: (url, init) => Promise<Response>,               // the only fetch the receiver uses
  jwks?: { timeoutMs = 5000, maxBytes = 65536, cacheTtlSeconds = 600, minRefetchIntervalSeconds = 60,
           maxStaleSeconds = 3600 },                      // D-A25: integer >= 0
  events?, auditLog?: { retentionDays },                  // core/audit.ts
  clock?: () => Date,                                     // for tests
})
```

## The plan's §3.4 steps, as built

The order is D-007's, as the Phase 1 brief corrected it.

| Step | Where | How |
|---|---|---|
| 1. Client | `grant.ts` | `provider.authenticateClient({ requireCredentials: !allowPublicClients })`. The provider throws its own `invalid_client` / `unauthorized_client`. Then our own check refuses a client whose method or registration is `none` (`public_client`). A discovered (CIMD) client counts only with `private_key_jwt`. `authenticated: true` is set only after this. |
| 2. Parse | `grant.ts` | `parseIdJag` (the core: typ, alg, kid, crit, required and unsupported claims, lifetime). Then `checkTimes` **before** the trust lookup, so `expired` / `not_yet_valid` can't confirm whether an issuer is trusted (S8). A plain RFC 7523 assertion fails here with the public `wrong_typ`. With `requireResourceClaim`, a token without `resource` fails here too, with the public `missing_claim` (D-A21). |
| 3. Trust | `trust.ts` | Looks up the **unverified** `iss` (and `tenant`) in the three sources. No match is `untrusted_issuer`, and so are two or more. Nothing is fetched for an untrusted issuer. |
| 4. Signature, `aud` | `grant.ts`, `jwks.ts`, core | `verifyIdJag(token, key, { issuer: trust.issuer, audience: getIssuer(ctx, opts) })`. `key` is a lazy resolver, so verifyIdJag's own order holds: `iss`, `self_issued`, then the signature, and only the signature fetches keys. The resolver also refuses an `alg` the issuer's JWKS doesn't publish, as `bad_signature`. `aud` is compared exactly. |
| 5. `client_id` | `grant.ts` | `claims.client_id === authenticated clientId`, exactly (D-004). Then the trust entry's `allowedClientIds`, if set. Both are `client_mismatch`. |
| 6. Scopes (moved before the subject, D-007) | `grant.ts` | Granted = ID-JAG `scope` ∩ the request's `scope` (if sent) ∩ the client's registered scopes ∩ the resource's scopes. The resource's scopes are its `allowedScopes`, or else the provider's advertised or configured scopes. `openid` and `offline_access` are always removed. Empty → `no_scope`. |
| 7. Resource | `grant.ts` | Picked from the claim, or else the request's `resource`, or else `defaultResource`, or else the only registered one. It must be in `opts.resources`; for `mcp()` that includes its `resource`. Otherwise `unknown_resource` (`invalid_target`). Plan §3.4 step 9. |
| 8. `jti` | core | `recordJti(adapter, { side: "accepted", ..., exp, clockSkewSeconds })`; `false` → `replay`. |
| 9. Subject | `resolve.ts` | Plan step 10: the hook, then the subject's key (D-A28: `sub`, or for an entry with `samlSubjects` the mapped SAML NameID of `sub_id`), then the account (`providerId` = the entry's account provider id, `accountId` = `sub`; or the mapping's `accountProviderId` and the NameID), then the email fallback (opt-in, listed or verified domains), then JIT (opt-in). Banned users are refused. A JIT user joins the trust entry's organization (D-A18–D-A20). |
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
  - The MCP extension expects the claim. Phase 2: `requireResourceClaim` (default off, D-009 #4) refuses a token without it (D-A21).
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
  - It links only a local user whose `emailVerified` is true (D-A23).
- **D-A10: JIT.**
  - Needs an `email` claim.
  - Refused if a user with that email exists: only the email fallback may match existing users.
  - `emailVerified` is false unless `trustEmailVerified`.
  - Uses `internalAdapter.createUser(…, { method: "id-jag" })`, so `user.validateUserInfo` applies.
  - Phase 2: the user joins the trust entry's organization (D-A18–D-A20).
- **D-A11: JWKS cache.**
  - Per plugin instance, keyed by (issuer, jwksUri, discoveryUri), with kids looked up within an entry.
  - TTL 10 min. An unknown kid or an expired entry refetches only if the last *attempt*, failed ones included, is ≥ 60 s old; otherwise the cached keys answer, and an unknown kid fails as `bad_signature`.
  - Concurrent lookups share one in-flight fetch.
  - 64 KiB cap, checked from `content-length` and again while streaming. A 5 s deadline races the whole exchange and aborts the signal, so a fetch that ignores the signal still loses.
  - At most 100 keys; `use: "enc"` keys dropped. An empty set is `jwks_unavailable` (S1).
  - Cached keys outlive a failing JWKS by at most `maxStaleSeconds` past the TTL (D-A25).
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

### Phase 2 additions (D-009 #4 and #5)

- **D-A18: JIT adds organization membership** (the maintainer's D-009 #5).
  - When JIT creates a user for a trust entry with an `organizationId` (a static entry, an sso row's `organizationId`, or a table row's), the user becomes a member of that organization. Only when the organization plugin is installed.
  - The representation is the organization plugin's own, written as `@better-auth/sso` writes it: an `adapter.create` on `member` (`organizationId`, `userId`, `role`, `createdAt`). Like sso's, it goes past the organization plugin's endpoints, so its `organizationHooks` and `membershipLimit` don't run. A host whose `member` schema has extra required fields gets the failure path (D-A20).
  - **Role.** For an sso row it is sso's own `organizationProvisioning`: `disabled` means no membership, then `getRole` (called with the new user, the ID-JAG's claims as `userInfo`, no token, and the sso provider row with `oidcConfig` parsed), then `defaultRole`, then `"member"`. For a static entry, the new `jitRole` option. For a table row, a new nullable `jitRole` column. Both default to `"member"`. `jitRole` without `organizationId` is a configuration error.
  - **Idempotent:** an existing membership is left as it is (`already-member`).
  - **A pending, unexpired invitation** for the email decides instead, as in sso: no membership is added, so the invitation (which may carry another role) can still be accepted.
  - **The organization must exist.** If it doesn't, that's the failure path. sso doesn't check, and an insert would then depend on whether the adapter enforces foreign keys (D1 does, node:sqlite doesn't by default).
- **D-A19: an existing user is never added.** That covers a user found by the hook, by the linked account or by the email fallback. Membership is written only when JIT creates the user.
  - Existing memberships are the host's business. An agent's token request shouldn't change who belongs to an organization, and an administrator's removal of a member would otherwise be undone by the next ID-JAG.
  - This differs from sso's sign-in, which assigns a provider-bound organization at every login when the user isn't a member yet.
- **D-A20: a failed membership refuses the grant and removes the new user.**
  - The order is: create the user, add the membership, then link the account. If the membership fails (a missing organization, `getRole` throws or returns no role, the insert throws), the error is logged, the new user is deleted, and the grant is refused with `subject_rejected` (non-public, generic `invalid_grant`). The ID-JAG's `jti` is already recorded, so it is burnt, as for every refusal after step 8.
  - Why not keep the user and log? By D-A19, the next ID-JAG would find that user through the linked account and accept it without a membership: a half-provisioned user, silently accepted.
  - If the deletion fails too, it is logged, and the leftover user has **no linked account**. So a retry can't find it by `sub`, and JIT refuses its email (D-A10). It is never accepted, and an administrator can see it in the log.
  - Better Auth's adapters give no transaction that works on D1, so this is compensation rather than atomicity.
- **D-A21: `requireResourceClaim`** (default `false`, D-009 #4).
  - When `true`, an ID-JAG without `resource` is refused as the **public** `missing_claim` (`invalid_grant`, "The assertion is missing a required claim."; the audit detail is `resource`). This is checked in step 2, right after the time checks and before the trust lookup.
  - **Why public, and why there (S8):** the answer depends only on the token the caller sent and on this receiver's configuration, not on trust, keys, users or the jti table. So it is the same for a trusted and an untrusted issuer, nothing is fetched for it, and the jti isn't burnt (the client can fix the token). `unknown_resource` after the signature would hide the issue from a legitimate client behind the generic `invalid_target`, and teach an attacker nothing more either way.
  - The request's `resource` parameter and `defaultResource` never stand in for the claim when it is required.
- **D-A22: no organization plugin.**
  - **At startup:** a warning for static entries with JIT and an `organizationId`.
  - **At request time:** a warning each time JIT skips a membership for that reason. sso and table rows aren't known at startup.
  - In both cases the user is still created, without a membership. That's the brief's choice: the entry's organization can't be honoured, but the host chose JIT.

### After the independent review (D-A23–D-A26)

Four defects, each reproduced by the reviewer; each got a failing test first, which was seen to fail, then the fix.

- **D-A23: the email fallback took over unverified local accounts (security).**
  - **Defect.** Someone self-registers `victim@corp.example` with a password and never verifies it. The victim's ID-JAG (email fallback) was then linked to that account, and the attacker's password still signed in. `resolve.ts` never looked at the local user's `emailVerified`. Better Auth's own account linking requires it by default (`requireLocalEmailVerified`).
  - **Fix.** The email fallback links only a local user whose `emailVerified` is `true`. Otherwise it refuses with `unknown_subject` (non-public; detail `email fallback: the local user's email is not verified`). It does **not** fall through to JIT, and JIT still refuses an existing email (D-A10).
  - **Evidence.** `resolve.test.ts`, "an unverified local account is never taken over…": before the fix, `accepted`. After it: refused with the generic body, no account linked, no user created even with JIT on, the user's only account is still `credential`, and `signInEmail` with the password still works. "a verified local user is linked" covers the positive case. The tests whose fixtures made users without `emailVerified` and then expected the email fallback to link them now create verified users.
- **D-A24: two first-use grants at once locked the user out (availability).**
  - **Defect.** Reproduced on workerd/D1 with the email fallback: concurrent first-use requests all returned 200 and each wrote an `account` row for (accountProviderId, `sub`). Every later grant for that user was then an **empty HTTP 500**, unaudited, because Better Auth's `findAccountOwnerByKey` throws "Multiple accounts match". With JIT, the requests that lost the user's UNIQUE email insert were empty 500s. Node's synchronous SQLite hid this. The suite's only concurrency test covered the jti insert.
  - **Fix** (`resolve.ts`):
    - **Lookups tolerate duplicates.** Lookups by (providerId, accountId) are our own `findMany`. They are sorted deterministically (oldest `createdAt`, then lowest `id`) and never throw on duplicates. A missing or unparsable `createdAt` sorts last.
    - **Convergence after linking.** After linking (email fallback or JIT), the request re-reads the matching rows.
      - If there is more than one, the oldest wins.
      - Whoever sees exact duplicates of the winner's link (same user) deletes them. That covers the interleaving no barrier can force: a request that saw only its own row and returned, before an older row arrived.
      - A request whose own row lost deletes its account row. For JIT it also deletes the membership it added and the user it created. Then it continues with the winner's user.
      - A failed cleanup is logged, and the grant continues with the winner. Leftovers don't break lookups.
      - A warning is logged whenever duplicates are seen.
    - **No empty 500s.** `resolveSubject` now throws only `IdJagRefusal`. Anything else (a lost UNIQUE race, a database error) is logged (`subject resolution failed unexpectedly`) and refused as `subject_rejected` (non-public), so it is audited. This also covers an `APIError` thrown by a host's user-creation hook, which was passed through as the provider's own error before.
    - **Residual.** Two JIT requests that carry *different* emails for one `sub`, interleaved so that the loser has already returned before the winner's row appears, can leave two users. Lookups still pick one deterministically, and the leftover can be removed by hand. Same-email JIT can't produce this, because the email is UNIQUE.
  - **Evidence** (`test/receiver/concurrency.test.ts`, both runtimes, two auth instances on one database, 6 parallel requests with distinct valid ID-JAGs for one new subject):
    - **Each scenario runs twice:** as the requests come, and held at the same step by a barrier in Better Auth's `databaseHooks` (`barrier()` in `receiver-host.ts`). The barrier makes the race happen on Node too, and so in the mutation runner.
    - **Before the fix,** the held runs failed on Node and every run failed on workerd: 6 account rows then a 500 later (email); empty 500s (JIT); 6 users and accounts (JIT, different emails); a 500 with seeded duplicates.
    - **After the fix:**
      - email fallback: one row, a later grant 200;
      - JIT: no 500, one user, one account, one membership, a later grant 200; the held run's losers refused as `subject_rejected`;
      - JIT with different emails: all 200 for one user, the losers' users, memberships and accounts gone;
      - two seeded rows: the older `createdAt` wins, then the lower id on a tie; never an error;
      - two unit tests (a late duplicate of the same user removed by the winner; a losing JIT request deleting its own account and membership even when deleting the user cascades nothing);
      - an adapter that throws: `subject_rejected`, logged.
- **D-A25: stale IdP keys accepted indefinitely while the JWKS fetch failed.**
  - **Defect.** With the JWKS down, the first request each minute failed `jwks_unavailable`, and every other request verified against the old cached keys. That was still true 30 simulated days past the 10-minute TTL, so a key the IdP had withdrawn kept working while its JWKS was unreachable.
  - **Fix.** New option `jwks.maxStaleSeconds`, default 3600, validated as an integer ≥ 0. Once `now ≥ fetchedAt + cacheTtl + maxStale`, the cached keys are discarded. Every request is then `jwks_unavailable` until a fetch succeeds, still at most one fetch per `minRefetchIntervalSeconds`. Within the window, behaviour is as before: the request that triggers a failed refetch is refused, and the others use the cached keys.
  - **Evidence** (`jwks.test.ts`, injected clock):
    - **Unit, within the window:** the old keys still work while the JWKS is down, up to the last millisecond.
    - **Unit, past it:** refused, fetched or not, and still refused 30 days on. Recovery once the JWKS answers again.
    - **Unit, `maxStale 0`:** no stale use at all.
    - **Through the grant:** the default (an hour) and `maxStaleSeconds: 120`. Before the fix, the cache tests got `ok` past the window.
    - **Options:** negative, fractional and infinite values are refused; 0 is accepted.
- **D-A26: `jitRole` checked against the organization plugin's roles** (the review's Question 2, accepted).
  - **Startup.** With the organization plugin installed, a static entry's `jitRole` must name its roles. Those are the built-in `owner`, `admin` and `member`, plus the keys of its `roles` option, exactly as the plugin validates a member's role in `crud-members`. A comma-separated value (the plugin's multi-role form) is checked part by part. An unknown role is a startup error naming it, the issuer, and the known roles.
    - With `dynamicAccessControl.enabled`, an organization can define more roles, so the startup check is skipped and the role is checked at provisioning.
    - Without the organization plugin there is nothing to check (and no membership, D-A22).
  - **Provisioning.** sso rows (`defaultRole`, `getRole`) and table rows (`jitRole`) can only be checked when a user is provisioned. Static entries are checked there too, which is cheap. With dynamic access control, the organization's own `organizationRole` rows also count. An unknown role goes down the D-A20 failure path: the error is logged with the role named (the log line now includes the error message), the new user is removed, and the grant is refused with `subject_rejected`.
  - **Evidence** (`membership.test.ts`):
    - **Startup:** `superuser` fails with the role named; the three built-in roles and `admin,member` pass; no plugin, no check.
    - **Custom roles:** `auditor` (custom `roles`) is accepted and used; `auditr` fails.
    - **Provisioning:** a table row's `superuser`, and an sso `defaultRole` of `superuser` or a `getRole` returning `ghost`, are each refused with a log line, and the user is removed.
    - **Dynamic access control:** an organization's own role is refused until its `organizationRole` row exists, then used.
  - **New exports:** `BUILT_IN_ORGANIZATION_ROLES`, `organizationRoles`, `unknownRoles`, `OrganizationRoles`.

**Run on 2026-10-06, after these fixes:**
- **`pnpm typecheck` and `pnpm lint`:** clean.
- **`pnpm test`:** 642 passed, 28 skipped. That is 321 per runtime, Node and workerd.
- **The receiver's own tests:** 134 per runtime, in 10 files (111 before).
- **`python3 scripts/mutate.py test/mutations/receiver.json`:** 121 entries; 117 caught, 4 expected survivors, 0 problems, exit 0.
  - **Stale patterns updated (3):** "not called from JIT", "account linked before the membership" and "existing user found by email is added too". The code they target was rewritten.
  - **New entries (29):**
    - D-A23: 2;
    - D-A24: 15;
    - D-A25: 5;
    - D-A26: 7.
  - **The four expected survivors, each with its reason in the list:**
    - `emailVerified === false` instead of `!== true` is equivalent: the field is a required boolean.
    - Two defensive refusals in `converge` are equivalent: the wrapper refuses the same way.
    - A failed cleanup aborting the grant affects availability only, and nothing injects a failing delete.
  - **Two first-run survivors, now caught:** "the loser keeps its JIT membership" and "the loser keeps its account row". Deleting the user cascaded both on SQLite. The unit test with a non-cascading `deleteUser` now catches them.

`JwksSettings` (exported) has a new required `maxStaleMs`. `test/support/receiver-host.ts` gained `databaseHooks`, `organizationOptions` and `barrier()`.

### Phase 3: SAML NameID `sub_id` (task T8, D-A27–D-A31)

The design's receiver part (phase-3 design §2, rows R3-S1 to R3-S8), draft -04 §3.1, §3.2.1–§3.2.2, §4.4.1, §9.5 and §9.6. The core's `SAML_NAMEID_SUB_ID_FORMAT`, `samlNameIdSubIdSchema` and `parseSamlNameIdSubId()` are used as they are. Nothing in `src/core/**` changed.

- **D-A27: options and table columns.**
  - A static trust entry takes `samlSubjects?: [{ issuer, spNameQualifier?, nameQualifier?, nameIdFormats?, accountProviderId }]` and `requireSubId?: boolean` (default false).
  - The `idJagTrustedIssuer` table has two new nullable columns: `samlSubjects`, a JSON string in the same shape (like the table's other list columns), and `requireSubId`, a boolean where null means false. The table is still read-only (D-A12).
  - **Validation.** Both go through zod (`samlSubjectSchema`, strict). The SAML values are non-empty, at most 2048 characters, with no C0/C1 controls (the core refuses those in `sub_id`, so a configured value with them could never match). `nameIdFormats` is non-empty and can't contain the transient format. A list has between 1 and 100 entries. `requireSubId` needs `samlSubjects`.
  - **Checks across one entry's mappings** (`normaliseSamlSubjects`, run for static entries and for table rows):
    - A SAML namespace, meaning (issuer, spNameQualifier, nameQualifier) with absent and `null` counted as the same, can't be listed twice.
    - Two namespaces can't share an `accountProviderId`. Identical NameIDs from different IdP connections would otherwise become one user.
    - A mapping can't use the entry's own `sub` account provider id. NameIDs and `sub`s would then share one key space.
  - **Checks across static entries:** an `accountProviderId` names exactly one namespace. That is one SAML namespace, which several entries may share (two ID-JAG issuers relaying one SAML IdP), or one entry's `sub`s.
  - A static defect is a startup error that names the issuer and the problem. A table row with a defect is ignored with a warning, as for its other columns. Overlaps between sources (static, table, sso) aren't checked: they are only known at request time.
  - **Left out, as the design says:** `sso.samlSubjects` for sso-trusted issuers. It is a follow-up; sso trust entries ignore `sub_id` for now.
    - **[uncertain] in the design, resolved by reading sso 1.7.6:** an SAML `ssoProvider` row's `issuer` is the registrant's `body.issuer` (`z.string().url()`). It isn't checked against the IdP metadata's entity ID when the row is registered. At sign-in, sso uses `idp.entityMeta.getEntityID()`, so the two can differ. Inferring a mapping from the row's `issuer` would therefore be wrong. A follow-up could derive it with sso's exported `deriveSAMLIdentityProviderEntityID(samlConfig)`.
- **D-A28: the order, and what is compared** (`subjectKey` in `resolve.ts`, exported).
  - **Where:** after the host's `resolveSubject` hook, which sees the raw claims, `sub_id` included, and can still link, continue or reject. It comes before any account lookup.
    - Step 9 runs only after trust by `iss`, the signature, `aud`, `client_id`, scopes, the resource and `jti`. Only the mappings of the trust entry that matched are read, so `sub_id.issuer` never selects or establishes trust (§9.5).
  - **No `samlSubjects`:** `sub_id` is ignored and the key is (accountProviderId, `sub`), as before. A malformed `sub_id` isn't refused either (R3-S5).
  - **With `samlSubjects`, and a `sub_id` whose `format` is `saml-nameid`:**
    1. It is parsed with the core's strict schema. If that fails, the result is `subject_rejected` with the detail `sub_id malformed (...)`.
       - The core throws its public `invalid_claim`. It is re-thrown as the non-public `subject_rejected`, because draft §3.2.2 says `invalid_grant`. The public body would also tell a caller which issuers resolve by `sub_id`.
       - It is never a fallback to `sub`.
    2. A transient `nameid_format` is refused, whatever the mappings say, and before any mapping is matched.
    3. The mapping must match the `issuer` exactly, and `sp_name_qualifier` and `name_qualifier` null-safely: a value missing from the configuration must also be missing from the `sub_id`. There is no case folding and no trailing-slash normalisation. With no match: `subject_rejected` ("sub_id not authorized for this issuer").
    4. If the mapping lists `nameIdFormats`, `nameid_format` must be present and listed.
    5. The key is (mapping.accountProviderId, `nameid`).
  - **`sub_id` absent or of another format:** with `requireSubId`, `subject_rejected` ("sub_id required: …"). Without it, the `sub` key, as before.
    - A `sub_id` that isn't an object with a non-empty string `format` is already refused by the core's parse in step 2 (the public `invalid_claim`, before trust). That ordering is unchanged.
  - **What isn't part of the key:**
    - `sp_provided_id` isn't compared. The draft requires comparing the members "that are part of the set of identifier fields it uses", and we don't use it.
    - `nameid_format` is an allow-list, not part of the key, because sso doesn't store it on the account (`{ providerId, accountId: extract.nameID }`, confirmed in `@better-auth/sso` dist `index.mjs`, around lines 3001–3045).
- **D-A29: lookups and links use the key.**
  - **Linked account:** the same duplicate-tolerant lookup (D-A24) under the key. An owned account gives that user. An orphaned one is `unknown_subject`, never re-linked by email.
  - **Email fallback:** unchanged rules.
    - It needs the entry's `emailDomains`, and it keeps D-A23: only a local user whose `emailVerified` is `true`. Otherwise `unknown_subject`, not JIT.
    - A user who already has an account under the key's provider id (another NameID of the same SAML namespace) is refused.
    - It links (accountProviderId, nameid).
  - **JIT:** links with the mapping key, not `sub`. xaa.dev warns that `sub` may be an "opaque, Auth Server-local identifier that changes on server restart". A later ID-JAG with another `sub` and the same `sub_id` finds the same user.
  - **Known gap:** JIT still needs an `email` claim, because Better Auth users must have one. xaa.dev's persistent-NameID runs carry no `email`, so they get a clean `unknown_subject` (generic body, nothing created) unless an account is already linked or the host's hook resolves them. sso itself falls back to the NameID as the email at SAML sign-in. We don't, because a NameID isn't a verified address.
  - **Audit details (§9.6):** a NameID can be an email address or an enterprise id, so it never appears in a refusal detail. "Not authorized" and "format not allowed" record the log-safe members instead: `issuer`, `sp_name_qualifier`, `name_qualifier` and `nameid_format`. That is the "observe mode" the design asks for, for configuring xaa.dev from its first refused run. `unknown_subject` records `sub_id at <accountProviderId>`.
- **D-A30: one account provider id per namespace** (the R3-S7 rule, enforced at configuration time by D-A27). With two mappings and two `accountProviderId`s, the same NameID from two IdP connections gives two users (xaa.dev's test).
- **D-A31: concurrent first use converges under the new key too** (D-A24). `converge` now takes the key, (providerId, accountId), instead of the trust entry and `sub`. So the oldest-row-wins re-read, the cleanup of duplicates and of the loser's JIT user and membership, and the no-500 wrapper all apply to links under a mapping key unchanged.

**Evidence** (run on 2026-10-06; see "Phase 3 evidence" below).

| Item | Test (`test/receiver/sub-id.test.ts` unless noted; both runtimes) |
|---|---|
| R3-S1 | "a sub_id mapped only under another trust entry is refused…": entry A maps only Y and B maps X. A's ID-JAG with X's `sub_id`, while A's `sub` is linked, gives `subject_rejected` and the generic body; the detail has X's issuer and not the NameID. B's ID-JAG resolves the X-linked user. "an untrusted iss with a valid-looking sub_id": `untrusted_issuer`, with no fetch. |
| R3-S2 | `sp_name_qualifier` mismatched, absent when configured, or present when not configured; the issuer with a trailing slash or upper-cased: each refused, while the exact match is accepted. The same for `name_qualifier`, with an explicit `null` in the configuration. `nameIdFormats`: an unlisted or absent format is refused; no list accepts any non-transient format. |
| R3-S3 | An unknown member, an empty `nameid`, a control character in `nameid` or `issuer`, a missing `issuer`, a non-string member, an empty `nameid_format`: each `subject_rejected` with the generic body, while the `sub` is linked, so a fallback would have been accepted. |
| R3-S4 | `requireSubId`: absent, and `format: "email"`, are refused even with the `sub` linked; a mapped `sub_id` is accepted. Without it, both fall back to `sub`. Table rows: `requireSubId` is honoured. |
| R3-S5 | No mappings: a `sub_id` naming an existing SAML-linked account gives `unknown_subject`; a malformed `sub_id` with a linked `sub` is accepted. `subjectKey` returns the `sub` key. |
| R3-S6 | Transient: refused (exact detail) even with an account linked for that NameID and no format list, and before mapping (an unmapped issuer gets the transient detail). Listing it in `nameIdFormats` is a startup error (here and in `options.test.ts`). |
| R3-S7 | JIT links (accountProviderId, nameid), and nothing under `sub`. Another `sub` with the same `sub_id` gives the same user, with or without `email`. **xaa.dev's case:** the same NameID under two mappings with two `accountProviderId`s gives two users, each found again by its own link. An account stored as sso stores a SAML sign-in is found. Persistent NameID, no `email`, JIT: a clean `unknown_subject`, nothing linked (the known gap). A banned user is refused; an orphaned link isn't re-linked by email (unit level, and the lookup uses the mapping key). |
| R3-S8 | The email fallback under `sub_id`: an unverified self-registered account is refused (D-A23's detail), with nothing linked, no JIT, and its only account still `credential`. A verified user is linked under (accountProviderId, nameid) and not under `sub`. Another NameID with the same email is refused. |
| Hook | It runs first, sees `sub_id`, and its `link` wins over a `sub_id` that would be refused. |
| Table | The `samlSubjects` JSON and `requireSubId` are used; null columns behave as before. Rows with invalid JSON, an empty list, an unknown key, an empty issuer, a namespace listed twice, two namespaces under one provider id, a mapping under the row's own provider id, or `requireSubId` without mappings are ignored with a warning. |
| Options (`options.test.ts`) | 16 refusals (an empty list, an empty issuer, no `accountProviderId`, an unknown key, a control character, an empty qualifier, empty `nameIdFormats`, transient, a namespace listed twice, two namespaces under one provider id, the entry's own or default provider id, another entry's `sub` provider id, one provider id for two namespaces across entries, `requireSubId` without mappings, a non-boolean `requireSubId`). Accepted and normalised: a full mapping, and two entries sharing one namespace. |
| D-A31 (`concurrency.test.ts`) | Two instances on one database, 6 parallel requests with distinct ID-JAGs, **one `sub_id` and 6 different `sub`s**. Each scenario runs as the requests come and held by `barrier()`. The email fallback (held at the account insert): one row under the mapping key, none under any `sub`, a later grant with a new `sub` gets 200. JIT (held at the user insert): no 500, one user, one row, one membership, the held run's losers `subject_rejected`. JIT with 6 different emails, held at the account insert: all 200 for one user, and the losers' users and rows removed. |

**Phase 3 evidence, run on 2026-10-06:**
- **`pnpm typecheck` and `pnpm lint`:** clean.
- **`pnpm test`:** 768 passed and 28 skipped, which is 384 per runtime, on Node (node:sqlite) and workerd (D1).
  - The receiver's own tests: 184 per runtime, in 11 files (134 before). The new ones are `sub-id.test.ts` (28), `options.test.ts` (+17) and `concurrency.test.ts` (+5).
- **`python3 scripts/mutate.py test/mutations/receiver.json`:** 157 entries; 153 caught, 4 expected survivors (the same four as D-A23/D-A24), 0 problems, exit 0.
  - **Stale patterns updated (6),** because the code they target now uses the subject key: "email fallback takes a user linked to another subject", "account linked before the membership", "jitRole without organizationId accepted", and D-A24's "findAccountOwnerByKey", "email fallback: no convergence" and "JIT: no convergence".
  - **New entries (36):**
    - R3-S1: 2;
    - R3-S2: 6;
    - R3-S3: 2;
    - R3-S4: 5;
    - R3-S5: 1;
    - R3-S6: 2;
    - R3-S7: 6, including the hook order and the NameID kept out of two audit details;
    - R3-S8: 2;
    - options and table: 9;
    - D-A31: 1.
  - **The first run had two survivors,** "two SAML namespaces under one accountProviderId accepted" and "a mapping under the entry's own sub provider id accepted". For static entries they are equivalent, because the across-entries check refuses both configurations too. Table rows rely on the within-entry check alone. Two table-row tests were added, and both mutants are now caught.
  - **"D-A24 for D-A27: no convergence for links under the mapping key"** fails exactly the two barrier-held SAML runs: the email fallback held at the account insert, and JIT with different emails. Rerun by hand on Node, to see which tests fail. So the barrier really forces the race for the new key.
- **Still open:**
  - the exact `sub_id.issuer` and `sp_name_qualifier` values xaa.dev sends (design [uncertain]). The refusal detail records them for the observe-mode first run (T10);
  - `sso.samlSubjects` (follow-up);
  - JIT without `email` (known gap, D-A29).

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

### Phase 2 evidence (D-A18–D-A22), 2026-10-06

- **Tests:** `test/receiver/membership.test.ts` (15 per runtime), one `requireResourceClaim` test in `grant.test.ts`, and three option cases in `options.test.ts`. The receiver now has 111 tests per runtime, in 9 files.
  - **Membership tests:** the default and `jitRole` roles; the same subject again; no `organizationId`; existing users (by account and by email) not added; a pending invitation; an sso row with `defaultRole`, `getRole` (and its arguments), `disabled`, or no setting; a table row's `jitRole`; no organization plugin (startup and request-time warnings, user created); a missing organization (user removed, generic body, a retry refused too); `getRole` throwing or returning `""`; deletion failing too (account never linked); a missing organization on an adapter without foreign keys; idempotence.
  - **The `requireResourceClaim` test:** the public `missing_claim` body; the request's `resource` doesn't stand in for the claim; no JWKS fetch; the same answer for an untrusted issuer; the refused token's `jti` is still usable.
- **Each guard broken once:** 27 entries appended to `test/mutations/receiver.json` (91 in all). `python3 scripts/mutate.py test/mutations/receiver.json`: **91 caught, 0 expected survivors, 0 problems, exit 0.**
  - The first run had one survivor, "missing organization not detected". node:sqlite and D1 both enforce the `member → organization` reference, so the insert failed anyway. A unit test now hides the organization from an adapter that would accept the row, and the mutation is caught.
  - The 27 entries:
    - `requireResourceClaim`: removed; always on; not resolved; moved after the signature (S8); moved after the jti.
    - JIT membership:
      - never added, or not called;
      - `jitRole` ignored, not resolved (static), or not read (table);
      - sso: rows use `jitRole`; `disabled`, `getRole` or `defaultRole` ignored; `getRole`'s result not validated;
      - the plugin check removed; either warning removed;
      - the organization-existence, existing-member or invitation check removed;
      - a failure swallowed; the user not removed; the account linked first;
      - existing users added (by account, by email);
      - the `jitRole` ⇒ `organizationId` refinement removed.

## For the guide

- **The `jti` is recorded before the subject is resolved** (step 8 before step 9). An ID-JAG for an unknown subject, or one refused at subject resolution for any reason (D-A14, D-A20), is used up. This is deliberate: it stops anyone probing for users with a captured token, since each probe costs a fresh ID-JAG from the IdP. A legitimate client whose user has since been provisioned just asks the IdP for a new ID-JAG.
- **Okta's Resource Server tab takes the receiver's issuer string exactly as the authorization server metadata publishes it**, path included. Okta puts that string in every ID-JAG's `aud`, and the receiver compares `aud` to its own issuer exactly (step 4, S3). A trailing slash or a missing `/api/auth` refuses every token as `wrong_audience`.
  - To read it, fetch the RFC 8414 metadata, with the issuer's path appended after the well-known segment, and copy the `issuer` field:

    ```sh
    curl -s https://mcp.example.com/.well-known/oauth-authorization-server/api/auth | jq -r .issuer
    # https://mcp.example.com/api/auth
    ```
  - For Better Auth's default `basePath`, that is `https://<host>/api/auth`.
  - Check that `grant_types_supported` includes `urn:ietf:params:oauth:grant-type:jwt-bearer`, and that `authorization_grant_profiles_supported` includes `urn:ietf:params:oauth:grant-profile:id-jag`.

## Open questions for the maintainer

1. **sso trust opt-in** (D-A01): keep it opt-in, or default it on when sso is installed?
2. **Strict single use** (D-007's open item) stays. A client whose access token expired gets a new ID-JAG rather than re-presenting the old one.
3. **Require the `resource` claim?** *Decided (D-009 #4): a `requireResourceClaim` option, default off, revisited after Phase 2 (D-A21).* The MCP extension says the access token must be audience-restricted to "the MCP Server identified by the `resource` claim". Today an ID-JAG without it is accepted for one registered resource (D-A06). A `requireResourceClaim` option, or making it the default, is a one-line change.
4. **JIT and organizations:** *Decided (D-009 #5): yes (D-A18–D-A20).* should JIT add the user to the trust entry's `organizationId` (with the organization plugin), as the plan says ("with the sso provider's `organizationProvisioning` role")? Not done in Phase 1.
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
4. **(Phase 3, optional) `parseSamlNameIdSubId` without the public refusal.** It throws the public `invalid_claim`, which the receiver catches and re-throws as `subject_rejected` (D-A28). A non-throwing variant would make that explicit:
   ```diff
   --- a/src/core/jwt.ts
   +++ b/src/core/jwt.ts
   @@
   +/** As parseSamlNameIdSubId, without throwing: the issues' paths when malformed. */
   +export function safeParseSamlNameIdSubId(subId: unknown): { ok: true; value: SamlNameIdSubId | undefined } | { ok: false; issues: string } {
   +  if (subId === undefined || (typeof subId === "object" && subId !== null && (subId as { format?: unknown }).format !== "saml-nameid")) return { ok: true, value: undefined };
   +  const parsed = samlNameIdSubIdSchema.safeParse(subId);
   +  return parsed.success ? { ok: true, value: parsed.data } : { ok: false, issues: parsed.error.issues.map((i) => i.path.join(".") || i.code).join(",") };
   +}
   ```
   Not needed for correctness: the catch in `subjectKey` does the same.

## D-A32: email fallback respects the host's account-linking settings (2026-10-06)

The Phase 2 review's item 1, second half. Email fallback is implicit account linking, so it is refused (`unknown_subject`,
detail "email fallback: the host disabled implicit account linking") when the host sets
`account.accountLinking.enabled: false` or `account.accountLinking.disableImplicitLinking: true`. Better Auth's
`requireLocalEmailVerified` (deprecated; about to become unconditional) is already met unconditionally, which is
stricter (D-A23).
- **Caught while writing the test:** the first version read `options.accountLinking`, but Better Auth keeps it at
  `options.account.accountLinking`, so the check could never fire.
- **Also from the review:** item 6, a test that an expired invitation doesn't block JIT membership (the `expiresAt`
  condition had no test).
- **Evidence:** both mutations caught.
