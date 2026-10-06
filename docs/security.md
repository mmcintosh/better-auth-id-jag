# Security

What this package defends against, what it needs from your app to do so, and what it doesn't do. The evidence for each control (the tests and mutation checks that keep it in place) is in [DECISIONS.md](../DECISIONS.md). To report a vulnerability, see [SECURITY.md](../SECURITY.md).

An ID-JAG is a bearer credential: whoever holds one, and can authenticate as the client it names, gets an access token for the user it names. Both sides are built to keep that window small and the decision with the enterprise.

## Host configuration

Things the plugins can't enforce on their own. Each startup warning below is worth treating as an error outside development.

- **A database that enforces UNIQUE.** Single use of each ID-JAG is a unique key on `idJagJti`: the INSERT is the check. Better Auth's memory adapter doesn't enforce it, and the plugin warns at startup. Use SQLite, D1, PostgreSQL, MySQL or another adapter that does.
- **The issuer needs `jwt()`, with local keys.** ID tokens and ID-JAGs are signed with the jwt plugin's keys and verified with the keys in your database, with no outbound request. The plugin refuses to start with `oauthProvider({ disableJwtPlugin: true })` (HS256 under each client's secret) or with remote keys (`jwt.sign`, `jwks.remoteUrl`).
- **Sign with ES256 or RS256** unless every receiver you target accepts EdDSA (`jwt()`'s default). This is interop, not security, but a receiver that refuses your algorithm fails closed.
- **Configure a policy.** With neither `authorize` nor `registry`, every token exchange is refused (`no_policy`), and the plugin warns at startup.
- **Configure trusted issuers.** With none, every ID-JAG is refused, and the plugin warns at startup. With `sso: true` but no sso plugin, no sso provider is trusted (also a warning).
- **Restrict `canManage`.** The registry API (`registry.canManage`) decides who gets ID-JAGs for what, and the blocks API (`blocks.canManage`) who is cut off; either also reads the audit log. Each must return exactly `true`; give them to administrators only.
- **On Workers, give Better Auth `waitUntil`** (`advanced.backgroundTasks`). Without it, audit rows and event handlers are cut off when the response is sent.
- **Keep the audience exact.** Configure the receiver's issuer identifier, and enter it at the IdP (Okta's Resource Server tab, your registry, your policy), exactly as `/.well-known/oauth-authorization-server` publishes it, path included.

## What the package enforces

### Both sides

| Threat | Control |
|---|---|
| A misconfiguration silently switching a check off | Options are validated at startup; an unknown key or an out-of-range value stops the plugin, naming each problem. |
| Failing open | No policy, no trusted issuer, no matching resource server, an empty key set, a fetch error: each is a refusal, never "allow" (S1). |
| A token of another kind accepted as an ID-JAG | `typ` must be exactly `oauth-id-jag+jwt` (S2); the issuer also refuses a `typ`'d token offered as an ID token. |
| Algorithm confusion | RS256, ES256 and EdDSA only. No `HS*`, no `none` (S4). |
| Oversized or hostile input | Tokens longer than any real ID-JAG are refused before decoding (S9); JWKS and discovery bodies are capped in size and time, and fuzzed. |
| Long-lived credentials | ID-JAG lifetime: 300 s by default, never more than 900 s, at both ends (S7). |
| Probing users and policies | A refusal's description names the defect only when the caller sent it (a missing claim, a malformed token). Trust, keys, users, policy and blocks get the generic description for their code; the real reason goes to the audit log (S8). |
| Log injection and a growing audit table | Every caller-supplied string is made log-safe; refusals of a caller that never authenticated reach your handler but not the table. |

### Issuer (`idJagIssuer()`)

| Threat | Control |
|---|---|
| Exchanging someone else's token | The subject token must be an ID token or refresh token **this IdP** issued, **to the client presenting it** (S6), verified with local keys only (S10). |
| Public clients holding ID-JAGs | Confidential clients only, unless `allowPublicClients` (S5; a startup warning). |
| An agent reaching more than intended | Code policy, registry policy or both; with both, both must allow and the narrower result wins (scopes ∩, shortest lifetime). Audiences are https and normalised; ambiguous resource servers are refused, and there are no wildcard client ids. |
| A user who should have lost access | Banned users (the admin plugin) are refused. Blocks refuse new ID-JAGs by user, client and audience, at once. The user is re-read from the database at each exchange. |
| An old sign-in minting ID-JAGs for hours | An ID token names no session and the provider's live 10 hours, so an ID token older than `maxIdTokenAgeSeconds` (by `iat`; an hour by default) is refused even before it expires. An ID token that carries `sid` is refused once that session is gone. A refresh token stops working as a subject token once it is revoked or rotated. |
| Leaking an email the user didn't verify | `email` goes into the ID-JAG only when the policy opts in **and** the email is verified. |

### Receiver (`idJagGrant()`)

| Threat | Control |
|---|---|
| Forged ID-JAGs | Only trusted issuers, matched by exact `iss` (and `tenant`); signature checked against that issuer's JWKS. An ID-JAG naming this server as its issuer is refused (`self_issued`, draft §9.3). |
| An ID-JAG meant for another server | `aud` must equal this server's issuer identifier exactly: not the resource, the bare origin, or with a trailing slash. |
| A stolen ID-JAG redeemed by another client | The ID-JAG's `client_id` must be the client that authenticated; per-issuer `allowedClientIds` narrow it further. |
| Replay | Each `jti` is redeemed once per issuer, enforced by a unique key (S3), tested under concurrency. |
| SSRF and slow-loris through JWKS fetching | The only outbound requests are JWKS and discovery of configured issuers, https only, through the `fetch` you choose, with redirects refused, a timeout, a size cap, a cache and a minimum refetch interval (S10). |
| Taking over a local account | Subjects resolve through linked accounts. Email matching is off unless you list domains (or, with sso, the provider's domain is verified); JIT is off unless you turn it on, and trusts `email_verified` only when you say so. JIT that can't add the organization membership deletes the new user and refuses. |
| Claims the receiver can't honour | `authorization_details` and `cnf` are refused by name rather than ignored. |
| Scope escalation | The token gets the request's scopes ∩ the ID-JAG's; an empty intersection is `invalid_scope` unless `allowEmptyScope`. The token is audience-restricted to the resource. |

## Known limitations

- **What stops the issuer, and what doesn't.** A new exchange is refused after a ban, a block, once the ID token is older than `maxIdTokenAgeSeconds` (an hour by default), once the session an ID token's `sid` names has ended, and once the refresh token is revoked (`/oauth2/revoke`) or rotated. **Signing out is not on that list** for an ID token without `sid` (oauth-provider puts `sid` in only for clients with `enable_end_session` or a back-channel logout URI): it keeps working until the age cap. An `offline_access` refresh token outlives sign-out by design; revoke it, or block the user.
- **An ID-JAG already issued lives out its lifetime.** Nothing above reaches an ID-JAG already issued: it stays valid at its receiver for at most its lifetime (300 s by default, 900 s at most), and access tokens the receiver issued from it (JWTs) live until they expire. There's no ID-JAG revocation protocol. Keep lifetimes short, and revoke at the receiver if you need to.
- **Blocking from a `jti` needs the audit log after a few minutes.** The issued `jti` row is swept a few minutes after the token expires; after that, `createFromJti` finds the ID-JAG only in the audit table (`auditLog`, for its retention), and otherwise answers 404 saying so.
- **A refused grant can burn its `jti`.** The single-use INSERT comes before the subject, resource-binding and token steps, so a refusal after it (an unknown subject, a JIT failure, a provider error from a misconfigured host) uses the ID-JAG up, and the client asks the IdP for a new one. Refusals that depend only on the token and this server's configuration (such as a missing required `resource`) come earlier and don't burn it.
- **JIT is compensation, not a transaction.** Better Auth's adapters give no transaction that works on D1. If removing a half-provisioned user also fails, it's logged, and the leftover user has no linked account, so it's never accepted.
- **Other implementations differ.** Keycloak ignores the ID-JAG's `scope` and `resource`; node-oauth2-server doesn't read `resource`. A policy that narrows them at our issuer doesn't narrow those servers' tokens: see [interop](interop.md).
- **The draft is a draft.** It may still change claims and rules, and its security considerations may grow. See [versioning](versioning.md#the-draft).
- **Not in this version:** pairwise subject identifiers, sender-constrained ID-JAGs (`cnf`), Rich Authorization Requests, and an admin API for trusted issuers.
