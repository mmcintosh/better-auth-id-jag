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
      jitProvisioning: { trustEmailVerified: true },    // or another way to find users: see below
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

Okta's ID-JAG names the user by `sub` (the Okta user id) and sends their `email`. The receiver finds the local user in
this order ([README, "Who the subject is"](../README.md#who-the-subject-is)); pick the steps you want:

| Way | Set | Good for | Watch out |
|---|---|---|---|
| A linked account | nothing (the default step) | Users who already have a link (`id-jag:https://<org>.okta.com` + Okta `sub`) | Someone has to create the links |
| Email fallback | `emailFallback: { domains: ["acme.com"] }` | Existing local users with a verified email at a domain you own | Only for domains you control |
| Just in time | `jitProvisioning: { trustEmailVerified: true }` | New users: created from `email` and linked to `sub`. The live run used this: the first ID-JAG created the user, later ones found it by the link | A deactivated Okta user's local account stays; only new ID-JAGs stop |
| SCIM | `scim: { connectionId }` on the trust entry, `scim` on the receiver | Deprovisioning that also stops the user at your server | Needs `@better-auth/scim` and a database with transactions ([README](../README.md#scim-provisioned-users)) |

JIT refuses an email that already belongs to another local user (`unknown_subject`), so it can't take over an
account. To require MFA, see [How the person signed in](security.md#how-the-person-signed-in): decide in
`resolveSubject`, because the access token doesn't carry `acr`, `amr` or `auth_time`.

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
| Resource app → Assignments | Users or groups | Who may use it through the agent |

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
| `sub`, `email` | The Okta user id, the user's email | Find the user (section 2) |
| `resource`, `scope` | As on the connection | The access token is for that resource, with those scopes ∩ the request's |
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

The agent only ever sees a generic `invalid_grant` (or `invalid_client`, `invalid_scope`, `invalid_target`): the
receiver doesn't tell a caller why it distrusts an issuer or a user. The real reason is in the receiver's audit
trail: `events.onRefused` (`e.reason`), or the `idJagAudit` table with `auditLog: { retentionDays }`.

| Reason | Likely cause with Okta | Fix |
|---|---|---|
| `untrusted_issuer` | The trust entry names `/oauth2/default` or another issuer | `issuer: "https://<org>.okta.com"`, exactly |
| `jwks_unavailable` | `discoveryUri` points at the org's `oauth-authorization-server` document (no `jwks_uri`), or the keys can't be fetched | `jwksUri: "https://<org>.okta.com/oauth2/v1/keys"`, or the org's `openid-configuration` |
| `wrong_audience` | The resource app's Issuer URL isn't your issuer exactly (a trailing slash, no `/api/auth`, the MCP URL) | Copy `issuer` from your `/.well-known/oauth-authorization-server/api/auth` |
| `client_mismatch` | The connection's client id isn't the client authenticating at your server, for example the issuer URL filled in | Re-create the connection with the agent's client id at your server |
| `unknown_subject` | No linked account, no `emailFallback` domain, no JIT; or JIT found the email taken by another user | Section 2, "Finding the user" |
| `unknown_resource` | The connection's resource indicator isn't a resource your server registered | Use your MCP resource URL exactly |
| `no_scope` | No scope is in all of: the ID-JAG (the connection's scopes), the request, the client's registered scopes and your resource's | Align the connection's scopes with your client's and your resource's |
| `replay` | The agent presented the same ID-JAG twice | Get a new ID-JAG for each access token |
| `unsupported_claim` | The ID-JAG carries `authorization_details` or `cnf` | Not supported yet. (`act` is supported: Okta always sends it for an AI agent.) |

Okta's own refusals happen at the token exchange, before your server sees anything: `invalid_target`,
`invalid_scope`, `access_denied` (section 5).

## Try it

The example Workers ([examples/workers](../examples/workers/README.md#okta-cross-app-access)) were run against an
Okta org this way: set `OKTA_ISSUER` and `OKTA_JWKS_URI` on the MCP server, and `node examples/workers/okta-agent.mjs`
plays the agent (`--subject=refresh`, `--negative`).
