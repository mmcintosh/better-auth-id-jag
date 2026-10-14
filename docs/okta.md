# The receiver behind Okta Cross App Access

This guide puts `idJagGrant()` (the receiver) behind **Okta Cross App Access** (XAA): Okta signs the ID-JAG, an AI
agent presents it at your Better Auth server, and your MCP server gets an access token for the user. Every step
and value here comes from the live runs against an Okta org recorded in
[docs/interop.md](interop.md#okta-cross-app-access--our-receiver) (2026-10-06, Okta 2026.09.1, our receiver on
Cloudflare Workers with D1), or from the code and its tests. Console labels are Okta's as of 2026.09; Okta may move
them.

```
person ─sign in─▶ Okta ─ID token─▶ agent ─token exchange─▶ Okta ─ID-JAG─▶ agent ─jwt-bearer─▶ your AS ─access token─▶ agent ─▶ your /mcp
```

## 1. What you need

- **An Okta org with Cross App Access.** The live runs used an Okta Integrator Free Plan org. Cross App Access is
  switched on per resource app; there is no org-wide toggle.
- **A resource app**: an OIDC web app in Okta that stands for your MCP server.
- **An AI agent**: registered in Okta under **Directory > AI agents**, with Okta-generated client credentials (a
  client secret). Its app needs the **Authorization Code**, **Refresh Token** and **Token Exchange** grants.
- **Your server**: Better Auth with `mcp()` (or `oauthProvider()`), `jwt()` and `idJagGrant()`, reachable over https.

## 2. Your receiver

```ts
idJagGrant({
  trustedIssuers: [
    {
      issuer: "https://acme.okta.com",                 // your org, exactly: not /oauth2/default
      jwksUri: "https://acme.okta.com/oauth2/v1/keys",  // the org's keys
      allowedClientIds: ["<the agent's client id here>"], // optional: only this client may present Okta's ID-JAGs
      jitProvisioning: { trustEmailVerified: true },    // one way to find users, as the live run did: see below
    },
  ],
});
```

- **The issuer is the org itself**, `https://<org>.okta.com`, not a custom authorization server such as
  `/oauth2/default`: Okta signs Cross App Access ID-JAGs with its org authorization server. The trust lookup
  compares `iss` exactly.
- **Keys:** `jwksUri` = `https://<org>.okta.com/oauth2/v1/keys`. If you use `discoveryUri` instead, point it at the
  org's `/.well-known/openid-configuration`. The org's `/.well-known/oauth-authorization-server` has no `jwks_uri`
  (checked 2026-10-14), so discovery through it fails (`jwks_unavailable`).
- **The agent is a client of your server too.** Register it at your server as a confidential client for the
  jwt-bearer grant, and note the client id your server gives it: Okta puts that id in the ID-JAG's `client_id`,
  and the receiver checks it against the client that authenticates (D-004). The example's `/setup` does this
  (`examples/workers/mcp-server/src/index.ts`).

### Finding the user

Okta's ID-JAG names the user by `sub` (the Okta user id) and sends their `email`. The receiver tries these in order
([README, "Who the subject is"](../README.md#who-the-subject-is)); the first that applies decides:

| Step | Set | What it does | Watch out |
|---|---|---|---|
| 1. `resolveSubject` | your hook | Link, reject, or continue | Runs first, on every ID-JAG |
| 2. SCIM | `scim: { connectionId }` on the trust entry, `scim` on the receiver | The user that SCIM connection provisioned with `externalId` = `sub`, while active. Deprovisioning at the IdP then stops the user at your server too | **Required by default**: with no provisioned user the grant is refused, and steps 3–5 don't run (`scim.required: false` falls through). Okta's SCIM must send the Okta user id as `externalId`. Needs `@better-auth/scim` and a database with transactions: **not D1** ([README](../README.md#scim-provisioned-users)). Tested with better-auth-scim-provisioning, not run live with Okta |
| 3. A linked account | nothing | The user linked to `id-jag:https://<org>.okta.com` + Okta `sub` | Someone, or step 4 or 5, has to create the link |
| 4. Email fallback | `emailFallback: { domains: ["acme.com"] }` | A local user with that email, only if their email is verified, then linked | Refused if that user is already linked to another subject of this issuer, or if your Better Auth config turns account linking (or implicit linking) off |
| 5. Just in time | `jitProvisioning: true` or `{ trustEmailVerified: true }` | A new user from `email`, then linked. The live run used this: the first ID-JAG created the user, later ones found it by the link | `trustEmailVerified` marks the new email verified on Okta's word (no `email_verified` claim is read), so email fallback and Better Auth's own account linking will then trust it. JIT refuses an email that already belongs to a local user. A deactivated Okta user's local account stays; only new ID-JAGs stop |

Otherwise the grant is refused (`unknown_subject`). To require MFA, see
[How the person signed in](security.md#how-the-person-signed-in): decide in `resolveSubject`, because the access token
doesn't carry `acr`, `amr` or `auth_time`. The claims recorded from Okta's ID-JAG in the live run include neither `acr` nor
`amr` ([docs/interop.md](interop.md#okta-cross-app-access--our-receiver)), so check what your org sends before you
require them: a rule that requires MFA refuses every ID-JAG without it.

## 3. In the Okta Admin Console

| Where | Field | Value |
|---|---|---|
| Resource app → **Machine Assignments** → **Resource server access** | **Cross-app access (XAA)** | On |
| Same | **Issuer URL** | Your server's issuer **exactly as its metadata publishes it**, path included: the `issuer` of `https://<your server>/.well-known/oauth-authorization-server/api/auth`, for example `https://mcp.example.com/api/auth`. No trailing slash. The receiver compares `aud` with it exactly. |
| AI agent's app | Grants | Authorization Code, Refresh Token, Token Exchange |
| AI agent → its **resource connection** (Application > App configured for AI Agent access) | Resource app | The resource app above |
| Same | **Resource indicator** | Your MCP resource, for example `https://mcp.example.com/mcp` |
| Same | **Client id** | The agent's client id **at your server** (section 2), not its Okta client id |
| Same | Scopes | The scopes the agent may get, for example `read` |
| Resource app → Assignments | Users or groups | Who may use it through the agent (unassigning a user here made Okta refuse their exchanges in the live run) |

Things the live runs ran into:
- **The connection's client id can come up filled in with the issuer URL.** Our receiver then refuses every ID-JAG
  (`client_mismatch`). The client id can't be edited: deactivate the connection, remove it, and add it again.
- **Turning cross-app access off and on again** asks for the issuer URL again and drops the connection's resource
  indicator; set it again.
- **For refresh tokens as subject tokens**, the agent's app needs the Refresh Token grant; a persistent refresh token
  (not rotated on each use) is simpler for testing.
- **Group assignments can't be removed for one user**: **Convert assignments** to individual ones first.

## 4. What Okta's ID-JAG carries, and what the receiver does with it

| Header / claim | Value | The receiver |
|---|---|---|
| `typ`, `alg`, `kid` | `oauth-id-jag+jwt`, `RS256`, a key from the org's `/oauth2/v1/keys` | Checks `typ`, allows RS256, verifies the signature |
| `iss` | `https://<org>.okta.com` | Must equal a trust entry's `issuer` |
| `aud` | The issuer URL entered on the resource app | Must equal your issuer exactly |
| `client_id` | The client id entered in the resource connection | Must be the client that authenticates |
| `sub`, `sub_profile`, `email` | The Okta user id, `user`, the user's email | Find the user by `sub` and `email` (section 2) |
| `resource`, `scope` | As on the connection | The access token is for that resource, with the scopes in all of: the ID-JAG, the request, the client's and the resource's (`openid` and `offline_access` dropped) |
| `act` | `{ "sub": "<the agent's Okta client id>", "sub_profile": "ai_agent web_app" }` | Accepted and **carried into the access token** (D-010) |
| `exp − iat`, `jti` | 300 s, `IDAAG.…` | At most 900 s; each `jti` once |

Because `act` reaches the access token, your MCP server can tell an agent from a person or an app and allow it
less: the example's MCP server lets a token with `act` only read
([examples/workers, "Layered permissions"](../examples/workers/README.md#layered-permissions)).

## 5. Cutoffs: who stops what, and how fast

From the lifecycle checks against the live org ([docs/interop.md](interop.md#the-lifecycle-checks-2026-10-06-second-session-d-023)):

| What happens | Who refuses | Answer |
|---|---|---|
| Cross-app access turned off on the resource app | Okta, at the exchange | `invalid_target` |
| An audience with no resource connection | Okta | `invalid_target` |
| A scope the connection doesn't allow | Okta | `invalid_scope` |
| The user unassigned | Okta | `access_denied` ("User is not assigned to the client application.") |
| The user deactivated | Okta | `invalid_request` ("'subject_token' is invalid.") |
| The same ID-JAG twice | Your receiver | `invalid_grant` (audit: `replay`) |
| An ID-JAG whose `client_id` isn't the authenticating client | Your receiver | `invalid_grant` (audit: `client_mismatch`) |

Okta stops issuing ID-JAGs at once. An ID-JAG already issued lives 300 s and works once. **An access token already
issued lives until it expires**: `accessTokenExpiresIn` on `mcp()` or `oauthProvider()`, an hour by default. Set it
short for agents, and shorter for sensitive scopes with `scopeExpirations` (the example: 300 s, and 120 s for
`write`). See [README, "What ID-JAG controls"](../README.md#-what-id-jag-controls-and-what-your-mcp-server-still-must).

## 6. Troubleshooting

What the agent sees depends on the check. Problems it could see for itself (a malformed ID-JAG, a wrong `typ` or
`alg`, a lifetime over 900 s, an expired token, an unsupported claim) come back as `invalid_grant` with a specific
`error_description`. Everything that depends on whom your server trusts (the issuer, the signature, the audience,
the client, the subject, a replay) comes back as `invalid_grant` with one generic description, so a caller can't probe
your configuration. Client authentication is oauth-provider's own (`invalid_client`, `unauthorized_client`). The
real reason is always in the receiver's audit trail: `events.onRefused` (`e.reason`), or the `idJagAudit` table with
`auditLog: { retentionDays }`.

The checks run in a fixed order ([README, "Receiver"](../README.md#-receiver-idjaggrant)): client, format and times,
issuer, signature, `aud`, `client_id`, scopes, resource, single use, then the subject. So you see one problem at a
time, and fixing it can reveal the next. An ID-JAG is spent at the single-use step, before the subject is resolved:
after an `unknown_subject`, the agent needs a new ID-JAG.

| Reason | Likely cause with Okta | Fix |
|---|---|---|
| `client_authentication_failed`, `client_not_allowed_grant`, `public_client` | The agent's credentials at your server are wrong, its client lacks the jwt-bearer grant, or it's a public client | Register it at your server as a confidential client with `urn:ietf:params:oauth:grant-type:jwt-bearer` (section 2) |
| `expired`, `not_yet_valid` | Clock skew between Okta and your server beyond `clockSkewSeconds` (60), or an ID-JAG kept past its 300 s | Sync clocks; exchange shortly before redeeming |
| `untrusted_issuer` | The trust entry names `/oauth2/default` or another issuer | `issuer: "https://<org>.okta.com"`, exactly |
| `jwks_unavailable` | `discoveryUri` points at the org's `oauth-authorization-server` document (no `jwks_uri`), or the keys can't be fetched | `jwksUri: "https://<org>.okta.com/oauth2/v1/keys"`, or the org's `openid-configuration` |
| `bad_signature` | The keys come from somewhere else than the org's, for example a half-updated entry with the org issuer but `/oauth2/default/v1/keys` (Okta's `kid` isn't there) | The org's `/oauth2/v1/keys` |
| `wrong_audience` | The resource app's Issuer URL isn't your issuer exactly (a trailing slash, no `/api/auth`, the MCP URL) | Copy `issuer` from your `/.well-known/oauth-authorization-server/api/auth` |
| `client_mismatch` | The connection's client id isn't the client authenticating at your server (for example the issuer URL filled in), or that client isn't in the trust entry's `allowedClientIds` | Re-create the connection with the agent's client id at your server; check `allowedClientIds` |
| `no_scope` | No scope is in all of: the ID-JAG (the connection's scopes), the request, the client's registered scopes and your resource's | Align the connection's scopes with your client's and your resource's |
| `unknown_resource` | The connection's resource indicator isn't a resource your server registered | Use your MCP resource URL exactly |
| `replay` | The agent presented the same ID-JAG twice | Get a new ID-JAG for each access token |
| `unknown_subject` | No step in "Finding the user" found or created the user: no link, no `emailFallback` domain, no JIT, SCIM required with no provisioned user, or JIT found the email taken | Section 2, "Finding the user" |
| `subject_rejected` | Your `resolveSubject` rejected it, for example an MFA rule and an ID-JAG without `amr`/`acr` | Check what your rule requires against what Okta sends |
| `unsupported_claim` | The ID-JAG carries `authorization_details` or `cnf` | Not supported yet. (`act` is supported: Okta always sends it for an AI agent.) |

Okta's own refusals happen at the token exchange, before your server sees anything: `invalid_target`,
`invalid_scope`, `access_denied`, `invalid_request` (section 5).

## Try it

The example Workers ([examples/workers](../examples/workers/README.md#okta-cross-app-access)) were run against an
Okta org this way: set `OKTA_ISSUER` and `OKTA_JWKS_URI` on the MCP server, and `node examples/workers/okta-agent.mjs`
plays the agent (`--subject=refresh`, `--negative`).
