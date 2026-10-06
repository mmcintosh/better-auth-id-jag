# Track B: the issuer (`idJagIssuer()`)

`src/issuer/`: a Better Auth plugin that makes an OIDC provider on `@better-auth/oauth-provider` + `jwt()` issue ID-JAGs
(draft-ietf-oauth-identity-assertion-authz-grant-04 §4.3) through the RFC 8693 token exchange, after a policy the host
defines in code, in a database registry, or both. Built on the shared core (`src/core`): `buildIdJag`, `newJti`, the URNs,
`IdJagRefusal`/`toApiError`, `recordJti` (side `issued`), `emit`, `sweepJtis`/`sweepAudit`. Nothing in `src/core` changed.

## Files

| File | What |
|---|---|
| `plugin.ts` | `idJagIssuer(options)`, `createIssuerState`, `checkIssuerHost` (startup checks) |
| `exchange.ts` | `handleTokenExchange(input, state)`: the grant handler, as a plain function too |
| `subject/id-token.ts` | `verifyOwnIdToken`: an ID token this IdP issued, verified with this host's own keys |
| `subject/refresh-token.ts` | `verifyOwnRefreshToken`: a refresh token this provider issued to the client, looked up by the provider's own hash, never changed (D-B14) |
| `blocks.ts` | blocks (D-B16): input schema, matching, `checkBlocks` (the policy step's first check), sweep |
| `policy.ts` | `decide`: blocks, then code hook + registry, deny by default, narrowing |
| `directory.ts` | registry lookups by audience, re-validated rows, per-isolate cache |
| `records.ts` | registry input schemas (zod), stored-row re-validation, lookup keys |
| `registry.ts` | the admin API (mounted only with `registry.canManage`): registry routes, blocks, audit |
| `schema.ts` | `idJagBlock` (always), `idJagResourceServer`, `idJagPolicy` (+ the core's `idJagJti`, `idJagAudit`) |
| `options.ts` | options, their types and their validation (zod, at startup) |
| `url.ts` | audience normalisation, resource URIs |
| `client.ts` | `idJagIssuerClient()`, the typed client plugin for the admin API |
| `index.ts` | the public API (to be re-exported from `src/index.ts` at merge) |

## Public API

```ts
idJagIssuer({
  authorize?: (input: AuthorizeInput) => AuthorizeResult | Promise<AuthorizeResult>,
  registry?: { enabled: boolean; canManage?: ({ user, session }) => boolean | Promise<boolean>; cacheSeconds?: number },
  allowPublicClients?: boolean,          // default false; true logs a startup warning (S5)
  signingAlgorithm?: "RS256" | "ES256" | "EdDSA", // default: the jwt plugin's keyPairConfig.alg
  defaultLifetimeSeconds?: number,       // default 300, max 900 (S7)
  allowLoopbackHttpAudiences?: boolean,  // http://localhost etc. for development; default false
  sweepIntervalSeconds?: number,         // opportunistic jti/audit sweeps per isolate; default 3600, 0 = never
  events?: { onIssued?, onRefused?, onAdminChanged? },   // the core's audit hooks
  auditLog?: { retentionDays: number },  // the core's audit table
})
// AuthorizeResult:
//   { decision: "allow", scopes, resource?, lifetimeSeconds?, clientIdAtResource?, claims?: { email?, tenant? } }
// | { decision: "deny", reason? }
```

Also exported: `handleTokenExchange`, `createIssuerState`, `checkIssuerHost`, `decide`, `verifyOwnIdToken`,
`verifyOwnRefreshToken`, `REFRESH_TOKEN_TOKEN_TYPE`, `checkBlocks`, `normalizeAudience`,
`issuerSchema`/`registrySchema`/`blockSchema`, the model names (`BLOCK_MODEL` = `idJagBlock`),
`ID_JAG_REGISTRY_ERROR_CODES`, and the types (`BlockConfig`, `BlockRecord`, `RefreshTokenSubject`).
`SubjectTokenClaims` (the `authorize` hook's `subjectToken`) gained `tokenType`: the id_token or refresh_token URN.

Client: `idJagIssuerClient()`:
- `authClient.idJag.resourceServers.create(…)`, `.policies.create(…)` (as before);
- `authClient.idJag.blocks({ query: { userId?, clientId?, audience? } })`, `.blocks.get({ query: { id } })`;
- `.blocks.create({ block: { userId?, clientId?, audience?, reason, expiresAt? } })`;
- `.blocks.createFromJti({ jti, fields?: ("userId" | "clientId" | "audience")[], reason, expiresAt? })`;
- `.blocks.delete({ id })`.

`.issued.revoke(…)` is gone (D-B21).

Admin API (all `sensitiveSessionMiddleware`; GET list/get, POST mutations; mounted with `registry.canManage`):
- registry, only when `registry.enabled`: `/id-jag/resource-servers[/get|/create|/update|/delete]`,
  `/id-jag/policies[/get|/create|/update|/delete]`;
- always: `/id-jag/blocks[/get|/create|/create-from-jti|/delete]`, `/id-jag/audit` (404 without `auditLog`).

Subject tokens: `subject_token_type` `urn:ietf:params:oauth:token-type:id_token` or
`urn:ietf:params:oauth:token-type:refresh_token`. Nothing new is advertised: draft -04 defines no metadata for
subject token types, only `identity_chaining_requested_token_types_supported`.

## How each plan §3.3 step is implemented

1. **Client.** `provider.authenticateClient({ requireCredentials: !allowPublicClients })`. A request that names a client
   but sends no credential becomes our `public_client` (401, `WWW-Authenticate: Basic`); every other provider refusal
   (wrong secret, unknown client, client not registered for the token-exchange grant → `unauthorized_client`) passes
   through as the provider shaped it. A second check refuses `token_endpoint_auth_method: none` clients unless
   `allowPublicClients`. Only after this does a refusal event say `authenticated: true` (and reach the audit table).
2. **Parameters.** Read from the raw form (`ctx.request.clone().text()`) so repeats are visible (the provider's body
   schema keeps one value; it merges only repeated `resource`), or from the parsed body for server-side calls.
   `requested_token_type` must be the ID-JAG URN (absent or anything else → `unsupported_requested_token_type`);
   `actor_token`/`actor_token_type` → `actor_token_unsupported`; `subject_token`, `subject_token_type`, `audience`
   required (`missing_parameter`); `subject_token_type` must be the id_token or refresh_token URN
(`unsupported_subject_token_type`);
   `audience` normalised (below), several audiences or our own issuer → `invalid_audience`; at most one `resource`
   (the provider already refused non-URIs with its own error); `scope` ≤ 4096 chars; any single-valued parameter
   repeated → `unsupported_parameter`.
3. **Subject token** (`subject/id-token.ts`). In order: shape; `typ` absent or `JWT` (an access token, ID-JAG or logout
   token is refused); `alg` asymmetric (no HS*, no `none`); `kid`; no `crit`; claims schema; `exp > now`, no grace
   (`expired`); `iat` at most 60 s ahead; `iss` = `jwt.issuer ?? baseURL` (S6, before any key is touched); the key by
   `kid` from this host's jwks table (or the jwt plugin's own `adapter.getJwks`), within the jwt plugin's grace period
   as its JWKS route publishes them; the key's alg must be the header's; `compactVerify`; `aud` contains the
   authenticated client (several audiences need `azp` = the client). Then the user by `sub` (`unknown_subject`), not
   banned (`banned_user`, ban expiry honoured). No outbound request at all (S10, tested with a `fetch` that throws).

   **Or a refresh token** (`subject/refresh-token.ts`, D-B14, D-B15). Decoded as the provider's refresh_token grant
   decodes it: `prefix.refreshToken` stripped (refused when configured and missing), `formatRefreshToken.decrypt`
   when configured, then `provider.hashToken(value, "refresh_token")` and an exact match on `oauthRefreshToken.token`.
   In order: length; found; `clientId` = the authenticated client; not `revoked` (rotation sets it too); no
   `confirmation` (sender-constrained); `openid` among its scopes; then `expiresAt > now` (`subject_token_expired`).
   Then the same user, ban and pairwise steps as for ID tokens. `auth_time` comes from the row's `authTime`. Nothing
   is written to the row.
4. **Policy** (`policy.ts`). First the blocks (D-B16): an active block matching (user, client, audience) refuses
   with `policy_denied`, detail `blocked: <id>`. Then the sources: `authorize` and/or the registry; none configured → `no_policy` (and a startup
   warning). Each configured source must allow. Registry: the enabled, valid resource servers for the audience that
   apply to the user (no organization, or one the user is a member of) → their enabled, valid policies matching the
   client and the subject (everyone / users / role / organization) → `no_policy` / `policy_denied`; two resource
   servers that both allow → `policy_denied` (ambiguous). Allowed scopes = ∪ matching policies' scopes ∩ the
   resource server's; across sources ∩; then ∩ the requested ones when any were requested (none requested → the
   allowed set). After an allow: empty result for a non-empty request → `no_scope`; a resource not in the resource
   server's list, or none when it `requireResource` → `unknown_resource`.
5. **Mint.** `buildIdJag` with `iss`, `sub` = user id, `aud` = normalised audience, `client_id` = client-id-at-resource
   (registry mapping or hook value, default the client's own id; two sources disagreeing → `policy_denied`), `jti` =
   `newJti()`, `iat`, `exp` = `iat` + lifetime (shortest of the sources', else `defaultLifetimeSeconds`, capped at 900),
   `resource`, `scope`, `auth_time`/`acr`/`amr` from the ID token, `email` only when every source opts in **and** the
   user's email is verified, `tenant` = the resource server's organization (or the hook's `claims.tenant`). Signed by
   `signJWT(ctx, { options: jwtOptions, header: { typ }, payload, signingAlgorithm? })`; `kid` set by `signJWT`.
6. **Respond.** `recordJti` (side `issued`, keyed on our issuer), `id-jag.issued`, opportunistic sweep, then exactly
   `{ issued_token_type, access_token, token_type: "N_A", scope?, expires_in }`. Returning this from the extension
   grant handler works unchanged: the provider returns the handler's object as the JSON body, and the token endpoint's
   `metadata.noStore` adds `Cache-Control: no-store` and `Pragma: no-cache` (measured over HTTP, `exchange.test.ts`).

Metadata: `identity_chaining_requested_token_types_supported: ["urn:ietf:params:oauth:token-type:id-jag"]` in both
discovery documents; `grant_types_supported` lists token-exchange automatically.

## Decisions (each the agent's choice, raised with the maintainer)

- **D-B01: ID tokens obtained the honest way in tests.** A signed-in user's cookie → `GET /oauth2/authorize` (PKCE,
  skip-consent client) → `authorization_code` at `/oauth2/token` with the client's secret. No hand-minted ID tokens
  except forgeries (refusal tests) and the `verifyOwnIdToken` unit tests, which supply "our" keys through the jwt
  plugin's `adapter.getJwks` so each defect can be the only one in a token signed by our key.
- **D-B02: pairwise clients are refused explicitly.** oauth-provider puts an HMAC of the user id in `sub` for a pairwise
  client; resolving it would mean hashing every user. v1 refuses (`invalid_subject_token`, detail "pairwise subject (not
  supported in v1)"). The ID-JAG's `sub` is always the user id; no subject-mapping option in v1.
- **D-B03: hosts we can't serve fail at startup.** No oauth-provider, `disableJwtPlugin` (HS256 ID tokens under each
  client's secret), no jwt plugin, jwt plugin with `jwt.sign`/`jwks.remoteUrl` (remote keys: verifying ID tokens would
  need a fetch, S10), a `signingAlgorithm` the jwt plugin has no key configuration for, or an ID-JAG algorithm outside
  RS256/ES256/EdDSA (S4). Options are validated with zod (strict: unknown keys, NaN, out-of-range numbers refused).
- **D-B04: both sources must allow.** With `authorize` and the registry, each must allow and the narrower outcome wins
  (scopes ∩, shortest lifetime, email only if both opt in, resource / client id / tenant must agree). The registry is
  evaluated first; the hook isn't called when it denies. Simplest rule that never widens.
- **D-B05: S8 ordering.** `no_policy`, `policy_denied`, `unknown_subject`, `banned_user`, `invalid_subject_token` share
  one body (`invalid_grant`, "The grant is invalid."). `no_scope` (`invalid_scope`) and `unknown_resource`
  (`invalid_target`) are only produced **after** a policy allowed: a caller could learn the allow anyway by asking for no
  scope or no resource, so the specific error codes leak nothing more.
- **D-B06: registry model.** `idJagResourceServer`: audience unique per organization via `lookupKey` = SHA-256 of
  (organizationId ?? "", audience), unique at field level and as the named index `id_jag_resource_server_lookup_key_unique`
  (MongoDB, saml-idp D-033); `resources`, `scopes`, `clientIdsAtResource` (JSON map: client id here → client id at the
  resource authorization server, D-004), `requireResource`. `idJagPolicy`: `subjectKind` + `subjectRef`, `clientIds`
  (required, explicit: no wildcard), `scopes` (must be the resource server's at write; intersected again at read),
  `lifetimeSeconds`, `includeEmail`. A resource server with policies can't be deleted (409); a policy's resource server
  can't change. Rows are re-validated on every read (schema, normalised audience, lookup key); invalid rows are listed
  with their issues and never used. Lookups are cached per isolate (`cacheSeconds`, default 60, hits and misses, 2000
  entries).
- **D-B07: the client-id mapping lives on the resource server** (per requesting client), the field D-004 asks for. The
  hook can return `clientIdAtResource` for code-only hosts.
- **D-B08: audience normalisation.** https only (loopback http behind an option), no fragment, no query, no userinfo, no
  whitespace or controls; scheme and host lower-cased and a default port dropped (URL syntax); the path kept exactly
  as sent, so `https://rs.example` and `https://rs.example/` stay different (a receiver compares exactly).
- **D-B09: one resource per request.** RFC 8707 allows several; the ID-JAG's `resource` is then an array that the
  receiver must map to one audience-restricted token. v1 takes one (`unsupported_parameter` for more).
- **D-B10: email.** Only when the policy opts in and `emailVerified` is true; an unverified address is silently left
  out (receivers may use `email` to link accounts).
- **D-B11: revoke (superseded by D-B16 and D-B21).** `/id-jag/issued/revoke` checked the jti was issued here and
  recorded an `id-jag.admin` "revoke" event, nothing more. The maintainer's D-009 #12 replaced it with blocks.
- **D-B12: requested_token_type absent = unsupported.** RFC 8693 lets the AS choose a default; we only serve id-jag
  and must not shadow a future generic token-exchange grant (plan Question 7).
- **D-B13: the plugin's endpoints are typed as mounted** (`ReturnType<typeof registryEndpoints>`) so the client plugin
  infers them, but are `{}` at runtime without `registry.canManage`.

### Phase 2 (the maintainer's D-009: refresh-token subjects, blocks)

- **D-B14: refresh tokens as subject tokens, in the provider's own representation.** The draft's MAY ("a Refresh
  Token previously issued by the IdP Authorization Server for that resource owner"), needed for the MCP extension's
  SAML path and for conformance tools that exchange one. Only a refresh token **this provider** issued **to the
  authenticated client** is accepted. It is looked up exactly as the provider's own refresh_token grant looks it up
  (prefix, `formatRefreshToken`, `provider.hashToken`), so `storeTokens: { hash }` hosts work unchanged. The row is
  only read: not rotated, consumed or extended. The client keeps using the token at the token endpoint, which is
  tested by refreshing with the same token after two exchanges.
  - **Why it's safe.** The token is a 32-character random secret the client already holds. Only its hash is stored,
    and we compare hashes exactly. Its client binding is checked against the authenticated client, the S6 rule for
    refresh tokens. A revoked or rotated token is refused, so the provider's revocation endpoint and its
    refresh-token-reuse handling both stop exchanges at once. The user is re-read and the ban checked, as for ID
    tokens. Nothing in the token can widen the grant: the ID-JAG's scopes come from the policy, not the token's.
  - **What's carried.** `sub` is the row's `userId`. `auth_time` is the row's `authTime`. There's no `acr` or `amr`,
    because the provider doesn't store them. `email` and `tenant` come from the current user and policy. The draft
    asks for "current subject attributes and policy", and that is what both subject token types already do.
  - **What's ignored.** The token's own scopes (`openid profile offline_access`, the IdP's scopes) aren't
    intersected with the ID-JAG's: they are about this IdP's APIs, not the resource's. Its RFC 8707 `resources` are
    ignored for the same reason.
  - **Pairwise clients are refused** for refresh tokens too. The ID-JAG's `sub` is the real user id, which the client
    can read, and that defeats pairwise.
  - **Sessions.** No session is required. The provider keeps `offline_access` refresh tokens after sign-out by
    design, and we follow it. Revoking the token, or banning the user, stops the exchange.
  - **The policy sees it.** `subjectToken.tokenType` is the URN that was exchanged. `subjectToken.raw` is
    `{ token_type, client_id, scope, iat, exp }`, never the token or its hash. Both policy sources and the narrowing
    apply identically: tested with the hook and with the registry, comparing both token types' responses and claims.
  - **Advertised:** nothing new. Draft -04 has no metadata for subject token types.
- **D-B15: refresh-token refusals.**
  - **One body for most refusals.** Unknown, another client's, revoked, rotated (even within the provider's
    `refreshTokenReuseInterval`), sender-constrained, without `openid`, a missing prefix or an undecodable format are
    all `invalid_subject_token` (not public). The audit detail names the step.
  - **Expiry is public, but checked late.** `subject_token_expired` comes after the client and revocation checks.
    So it only tells the client that its own, unrevoked token has expired, which the client could have recorded
    itself. Another client presenting the same expired token gets the generic refusal (tested). An ID token's expiry
    is public before the issuer check because it can be read from the token. A refresh token's can't, hence the
    later position.
  - **Sender-constrained tokens are refused.** A refresh token with a `confirmation` (e.g. DPoP `jkt`) is refused,
    because we can't check its proof of possession yet. Accepting it would strip the sender constraint.
  - **`openid` is required.** An ID-JAG is an identity assertion. The ID-token path implies `openid`, so a refresh
    token that was never granted it doesn't yield one.
- **D-B16: blocks (D-009 #12).** Table `idJagBlock`: `userId`, `clientId`, `audience`, each a value (matched
  exactly) or null for "any", at least one set, plus `reason`, `createdBy`, `createdAt` and an optional `expiresAt`.
  - **What it can cover.** (user), (user, client), (user, client, audience), (client), (client, audience) and
    (audience) are all expressible. "Block everything" isn't one: an empty block is refused at write.
  - **How it's checked.** The policy step checks blocks first, before any source, on every exchange and for both
    subject token types. It uses three indexed reads: the user's blocks, any-user blocks of this client, and any-user
    any-client blocks of this audience.
  - **The refusal.** A match is `policy_denied` with detail `blocked: <id>`, the same body as every other deny (S8).
  - **What a block stops.** **A block stops new ID-JAGs immediately, on every instance (no cache). ID-JAGs already
    issued remain valid at their receivers until they expire (default 5 minutes, at most 15), because there is no
    ID-JAG revocation protocol and receivers can't see the block.** To also cut the access tokens a receiver already
    issued from them, act at the receiver.
  - **Expiry and the audience.** An expired block no longer matches, and the opportunistic sweep deletes it. The
    audience is normalised at write, as the exchange normalises it.
- **D-B17: the block's refusal reason and audit target use what core has.** Until core gains them (core change
  requests 5 and 6 below):
  - the refusal is `policy_denied`, with the block in the detail;
  - the `id-jag.admin` event's `target` is `"block"`, cast onto the core's union (the core's type doesn't list it).
- **D-B18: where blocks live.** The `idJagBlock` table is always in the schema, like `idJagJti`: blocking is the
  enforcement half of revocation, and a host with only a code policy needs it too. The blocks and audit routes are
  mounted whenever `registry.canManage` is set, even with `registry.enabled: false` (then only they are mounted).
  They use the registry's access control: `sensitiveSessionMiddleware`, impersonation and bans refused, `canManage`
  exactly `true`, the origin check kept. Every create and delete is an `id-jag.admin` event with the actor.
- **D-B19: no existence checks at block creation.** Blocking a user id or client id that doesn't exist (yet) is
  harmless and useful (e.g. a client id metadata document URL before that client shows up), so neither is looked up.
- **D-B20: blocks fail closed.** Each of the three reads takes at most 1,000 rows. Reaching the limit refuses
  (`policy_denied`, "too many blocks to evaluate") rather than risking a missed block. Rows are compared again in
  memory, exactly, so a case-folding collation can't widen a block (tested with a folding adapter wrapper).
- **D-B21: no endpoint is called "revoke".** `/id-jag/issued/revoke` and `authClient.idJag.issued.revoke` are
  removed, not renamed: they never revoked anything. The useful part, starting from an ID-JAG you saw in the audit
  log, is `/id-jag/blocks/create-from-jti`. It blocks that jti's user, client and/or audience (`fields`, default all
  three), from the jti row this issuer recorded (404 when unknown or swept). A jti alone means nothing to a receiver.

## Evidence

### Phase 2 (refresh-token subjects, blocks), 2026-10-06

- **Tests.** `pnpm test`: 542 passed, 0 failed, 271 per runtime (Node with node:sqlite, workerd with D1). Issuer:
  116 per runtime (89 before). New are `refresh-token.test.ts` (14) and `blocks.test.ts` (12). `registry.test.ts`
  lost the revoke test and gained two: that `/issued/revoke` is gone, and a registry policy applied identically to a
  refresh-token subject. `client.test.ts` now also covers the blocks calls. `pnpm typecheck` and `pnpm lint` are
  clean.
- **Refresh tokens are real.** Every refresh token in the tests comes from authorization_code with `offline_access`,
  through `/oauth2/authorize`. Revocation goes through the provider's `/oauth2/revoke`. Non-rotation is proven three
  ways: the row is unchanged after two exchanges, the same token then refreshes at `/oauth2/token`, and after that
  rotation the old token is refused while the new one works.
- **Fixed on the way.** `cache: an entry expires after cacheSeconds` failed once under full-suite load. Its middle
  assertion assumed under 1 s between two exchanges, so it is now only checked when that held. The expiry assertion
  that the cache mutation needs is unchanged.
- **Each guard broken once.** `python3 scripts/mutate.py test/mutations/issuer.json` ran the whole list: **117
  mutations, 112 caught, 5 expected survivors (the five above, unchanged), 0 problems, exit 0.**
  - **Added:** 36 mutations to the 82 already there (79 from Phase 1, 3 from D-009). 17 are on refresh-token
    subjects (S6r, plus the two-edit S8r "expiry before the client check"), and 19 are on blocks (B, one of them a
    two-edit pair).
  - **Updated:** 3 stale patterns (`S6 expired accepted`, stale since D-009's `subject_token_expired`;
    `Req subject_token_type not checked`; `S10 outbound fetch`).
  - **Removed:** `API unknown jti revoked`, replaced by `B unknown jti blocked (create-from-jti)`.
  - **One new survivor, now caught.** On the first run of the new mutations, "pairwise guard skipped for refresh
    tokens" survived. A pairwise refresh-token test was added, and it is caught.

**Tests.** `pnpm test` (2026-10-06): 298 passed, 0 failed, both projects. Issuer: 89 per runtime (178 in total) in
`test/issuer/` (exchange 16, refusals 26, registry 27, id-token 6, startup 8, fuzz 3, client 1, rs256 1,
signing-algorithm 1). The other 60 per runtime are the core and Phase 0 tests, unchanged. `pnpm typecheck` and
`pnpm lint` are clean.

**Exit criterion (plan §5 Track B).** `exchange.test.ts` ("exit criterion…", ES256), `rs256.test.ts` (RS256) and
`registry.test.ts` (the first test, registry policy with a mapped client id). In each, a confidential client gets an ID
token through the real authorization-code flow and exchanges it. Then `verifyIdJag` from `src/core` verifies the
ID-JAG against the host's JWKS, fetched over the host's own `/jwks` route. The ID-JAG has `typ` `oauth-id-jag+jwt`, a
`kid`, the policy's narrowed scopes (`read` from `read write`; `write` from `write admin`) and the mapped `client_id`
(`agent-at-rs`, `rs-client`). Both runtimes pass. `signing-algorithm.test.ts`: the default is the jwt plugin's
algorithm (EdDSA), and `signingAlgorithm: "ES256"` gives ES256 ID-JAGs while the ID tokens stay EdDSA.

**Each guard broken once.** `test/mutations/issuer.json` has 79 mutations, run with
`python3 scripts/mutate.py test/mutations/issuer.json` (Node project, each with its relevant test files).

- **First run:** 69 caught, 10 survived.
- **Then:**
  - Tests were added for 5 of the survivors, which are now caught:
    - "cache never expires": a cacheSeconds 1 test;
    - "exact audience match dropped": a case-folding adapter wrapper;
    - "unknown_resource before the policy decides": an S8 test;
    - "own issuer as audience": the self check was unreachable with an http issuer until loopback http was allowed;
    - "policy moved to another resource server": the old test failed earlier for another reason.
  - Two guard pairs were each broken together with a multi-edit run, and both pairs are caught:
    - plain `sessionMiddleware` **and** the session's user trusted: caught by the cookie-cache demotion test;
    - the field-level unique flag **and** the named index removed: caught by the concurrent-create race test and the schema test.
- **Still surviving (5), each explained:**

| Mutation | Why it survives |
|---|---|
| S1 invalid policy row used (`!p.valid` dropped) | Equivalent: a policy row is invalid only when its config doesn't parse, so `!p.config` decides the same. |
| S5 public clients allowed (the second check dropped) | Defence in depth: `requireCredentials: true` refuses first. Both guards off is caught ("S5 both public-client guards off"). |
| S5 requireCredentials off | Defence in depth: the `token_endpoint_auth_method: none` check refuses next. Both off is caught. |
| API session user trusted, no re-read | `sensitiveSessionMiddleware` already gives the database's user. Both off is caught (above). |
| API lookupKey field-level unique dropped | The named table-level unique index still enforces it on SQL. Both off is caught (above). |

One is an equivalent mutant; the other four are halves of guard pairs, and each pair is caught when it is broken
together.

S-items covered by at least one caught mutation:
- S1: 14 caught.
- S2: typ (the ID-JAG's `typ` is the core's `buildIdJag`; our side refuses typ'd tokens as ID tokens).
- S4: the startup allow-list and `signingAlgorithm`; symmetric algorithms refused.
- S5: both guards together.
- S6: 14.
- S7: 13.
- S8: 2.
- S10: the injected `fetch`.
- S3 (jti record): "jti not recorded".
- S9 is the fuzz file. S11 doesn't apply (no secrets of our own).

### All mutations

| Mutation | First run | Final |
|---|---|---|
| S1 no policy source = allow | CAUGHT | CAUGHT |
| S1 policy ignores clientIds | CAUGHT | CAUGHT |
| S1 subject users matches everyone | CAUGHT | CAUGHT |
| S1 subject role matches everyone | CAUGHT | CAUGHT |
| S1 subject organization matches everyone | CAUGHT | CAUGHT |
| S1 organization resource server applies to non-members | CAUGHT | CAUGHT |
| S1 two allowing resource servers not ambiguous | CAUGHT | CAUGHT |
| S1 hook deny ignored | CAUGHT | CAUGHT |
| S1 hook throw allows | CAUGHT | CAUGHT |
| S1 malformed verdict allows | CAUGHT | CAUGHT |
| S1 disabled policy used | CAUGHT | CAUGHT |
| S1 disabled resource server used | CAUGHT | CAUGHT |
| S1 invalid resource server row used | CAUGHT | CAUGHT |
| S1 invalid policy row used | SURVIVED | SURVIVED (equivalent) |
| S1 cache never expires | SURVIVED | CAUGHT (test added) |
| S1 exact audience match dropped (collation) | SURVIVED | CAUGHT (test added) |
| S5 public clients allowed | SURVIVED | SURVIVED (pair caught together) |
| S5 requireCredentials off (defence in depth below it) | SURVIVED | SURVIVED (pair caught together) |
| S5 both public-client guards off | CAUGHT | CAUGHT |
| S6 iss not checked | CAUGHT | CAUGHT |
| S6 signature not verified | CAUGHT | CAUGHT |
| S6 aud not checked | CAUGHT | CAUGHT |
| S6 azp not checked | CAUGHT | CAUGHT |
| S6 expired accepted | CAUGHT | CAUGHT |
| S6 expiry with grace | CAUGHT | CAUGHT |
| S6 iat in the future accepted | CAUGHT | CAUGHT |
| S6 typ not checked | CAUGHT | CAUGHT |
| S6/S4 symmetric alg accepted | CAUGHT | CAUGHT |
| S6 key alg not matched | CAUGHT | CAUGHT |
| S6 expired keys past grace kept | CAUGHT | CAUGHT |
| S6 pairwise not refused | CAUGHT | CAUGHT |
| S6 banned user accepted | CAUGHT | CAUGHT |
| S6 ban expiry ignored | CAUGHT | CAUGHT |
| S7 requested scopes not narrowed | CAUGHT | CAUGHT |
| S7 sources not intersected | CAUGHT | CAUGHT |
| S7 policy scopes not limited to the resource server's | CAUGHT | CAUGHT |
| S7 unregistered resource accepted | CAUGHT | CAUGHT |
| S7 required resource not enforced | CAUGHT | CAUGHT |
| S7 hook may swap the requested resource | CAUGHT | CAUGHT |
| S7 lifetime not capped | CAUGHT | CAUGHT |
| S7 longest policy lifetime wins | CAUGHT | CAUGHT |
| S7 empty grant when scopes requested | CAUGHT | CAUGHT |
| S7 email without opt-in (hook) | CAUGHT | CAUGHT |
| S7 email without opt-in (registry) | CAUGHT | CAUGHT |
| S7 unverified email sent | CAUGHT | CAUGHT |
| S7 policy scopes beyond the resource server's accepted at write | CAUGHT | CAUGHT |
| D-004 client_id is always the IdP id | CAUGHT | CAUGHT |
| D-004 registry mapping ignored | CAUGHT | CAUGHT |
| S8 no_policy answered as no_scope | CAUGHT | CAUGHT |
| S8 unknown_resource before the policy decides | SURVIVED | CAUGHT (test added) |
| Req requested_token_type not checked | CAUGHT | CAUGHT |
| Req actor_token accepted | CAUGHT | CAUGHT |
| Req subject_token_type not checked | CAUGHT | CAUGHT |
| Req repeated parameters accepted | CAUGHT | CAUGHT |
| Req several resources accepted | CAUGHT | CAUGHT |
| Req own issuer as audience | SURVIVED | CAUGHT (test added) |
| Req http audiences | CAUGHT | CAUGHT |
| Req audience fragment | CAUGHT | CAUGHT |
| Req audience path rewritten | CAUGHT | CAUGHT |
| Rec jti not recorded | CAUGHT | CAUGHT |
| Audit authenticated never set | CAUGHT | CAUGHT |
| Audit refusal not emitted | CAUGHT | CAUGHT |
| S10 outbound fetch | CAUGHT | CAUGHT |
| Start disableJwtPlugin accepted | CAUGHT | CAUGHT |
| Start remote keys accepted | CAUGHT | CAUGHT |
| Start S4 alg outside the allow-list | CAUGHT | CAUGHT |
| Start signingAlgorithm ignored | CAUGHT | CAUGHT |
| Start public-client warning dropped | CAUGHT | CAUGHT |
| API impersonation allowed | CAUGHT | CAUGHT |
| API canManage truthy allows | CAUGHT | CAUGHT |
| API canManage throw allows | CAUGHT | CAUGHT |
| API banned admin allowed | CAUGHT | CAUGHT |
| API session user trusted, no re-read (sensitiveSessionMiddleware still on) | SURVIVED | SURVIVED (pair caught together) |
| API resource server with policies deleted | CAUGHT | CAUGHT |
| API policy moved to another resource server | SURVIVED | CAUGHT (test added) |
| API unknown jti revoked | CAUGHT | CAUGHT |
| API change not emitted | CAUGHT | CAUGHT |
| API lookupKey field-level unique dropped (named index remains) | SURVIVED | SURVIVED (pair caught together) |
| API stored lookupKey not re-validated | CAUGHT | CAUGHT |
| API sessions: plain sessionMiddleware and the session's user trusted (multi-edit) | — | CAUGHT |
| API lookupKey: field-level unique and the named index removed (multi-edit) | — | CAUGHT |

## Core change requests

1. **A reason for other client-authentication failures** (e.g. `client_authentication_failed`, `invalid_client`, not
   public). Today a wrong secret or an unknown client is the provider's own error and the issuer emits no refusal
   event for it, because no core reason fits (`public_client` would be wrong). Diff in `src/core/errors.ts`:
   ```diff
      public_client: { error: "invalid_client", public: false },
   +  client_authentication_failed: { error: "invalid_client", public: false },
   ```
   (and the pinned public-reason test is unchanged, since it isn't public). The issuer would then catch the provider's
   `invalid_client`/`unauthorized_client` APIErrors, emit, and rethrow them unchanged.
2. **A subject-token expiry reason.** The issuer reuses `expired`, whose public description says "The assertion has
   expired." — about the ID-JAG. Suggest
   ```diff
   +  subject_token_expired: { error: "invalid_grant", public: true, description: "The subject token has expired." },
   ```
   and the public-reason test updated to include it.
3. Optional: `repeated_parameter` (`invalid_request`, public, "A parameter appears more than once.") instead of
   reusing `unsupported_parameter` for repeats.

(1 and 2 were made in D-009.) Phase 2:

4. **The refresh-token URN** (D-B14). Defined in `src/issuer/subject/refresh-token.ts` until then. Diff in
   `src/core/urns.ts`:
   ```diff
    /** The subject token type v1 accepts at the issuer: an ID token this IdP issued. */
    export const ID_TOKEN_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:id_token";
   +/** The other subject token type the issuer accepts: a refresh token this provider issued to the client. */
   +export const REFRESH_TOKEN_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:refresh_token";
   ```
   Then `src/issuer/subject/refresh-token.ts` re-exports the core's constant instead of defining it.
5. **A `blocked` reason** (D-B16, D-B17). Not public, so it shares `invalid_grant`'s generic body with every other
   deny (S8). Diff in `src/core/errors.ts`:
   ```diff
      policy_denied: { error: "invalid_grant", public: false },
      no_policy: { error: "invalid_grant", public: false },
   +  blocked: { error: "invalid_grant", public: false },
   ```
   The pinned public-reason test is unchanged. Then `checkBlocks` refuses with `blocked` (detail: the block id), and
   the tests' `policy_denied` + `blocked: ` detail assertions become `blocked`.
6. **The admin event's target and action** (D-B17, D-B21). Diff in `src/core/audit.ts`:
   ```diff
   -  action: "create" | "update" | "delete" | "revoke";
   -  target: "resource-server" | "policy" | "trusted-issuer" | "jti";
   +  action: "create" | "update" | "delete";
   +  target: "resource-server" | "policy" | "trusted-issuer" | "block";
   ```
   Nothing emits `"revoke"` or `"jti"` any more (the receiver doesn't either: checked with grep). Then the
   `BLOCK_TARGET` cast in `src/issuer/registry.ts` goes. A host whose handler switches on `target` sees `"block"`
   today already.

## Open questions for the maintainer

- D-B04 (both sources must allow) vs "either allows": the safer one is implemented; the consumer's user-status gate fits
  it as a hook that denies.
- Pairwise subjects (D-B02): refuse (now), or support by mapping the pairwise `sub` through the client?
- Several resource servers allowing one audience (a host's and an organization's): refused as ambiguous now; prefer the
  organization's instead?
- Should `idJagPolicy.clientIds` allow a wildcard for CIMD clients (URL client ids not known in advance)?
- ~~Revoke (D-B11)~~: decided in D-009 #12, implemented as blocks (D-B16).

Phase 2:

- **D-B15, sender-constrained refresh tokens:** they are refused today. When DPoP lands (v2), should the exchange
  require the DPoP proof and carry `cnf` into the ID-JAG?
- **D-B15, `openid`:** a refresh token must have been granted `openid`. Is that too strict for the SAML path, where
  the refresh token comes from an assertion grant? Nothing in this repository issues one today, so it's untested.
- **D-B18, blocks API mounting:** the blocks API is under `registry.canManage` even with the registry off. Should it
  have its own option (e.g. `blocks: { canManage }`)?
- **D-B16, blocks and sessions:** should a block also revoke the user's refresh tokens for that client at the provider?
  Today it only stops ID-JAGs: the client can still refresh its access tokens here.
