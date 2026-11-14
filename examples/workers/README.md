# Enterprise-Managed Authorization on two Workers

Two Better Auth apps on Cloudflare Workers with D1, and a script that plays the MCP client:

- **`enterprise-idp/`**: the enterprise identity provider. `oauthProvider()` + `jwt()` (ES256) + `idJagIssuer()`.
  People sign in here. The agent exchanges their ID token for an ID-JAG, after the policy has approved it.
- **`mcp-server/`**: an MCP server and its authorization server. `mcp()` + `jwt()` + `idJagGrant()`. It trusts the IdP
  (and optionally Okta), turns an ID-JAG into an access token for its `/mcp`, and serves four tools (`whoami`,
  `list_notes`, `add_note`, `delete_note`).
- **`tester/`**: a separate, public "test your IdP" receiver: anyone building an ID-JAG issuer registers it (GitHub
  or GitLab sign-in, 24 hours, confirmed by an ID-JAG signed with the issuer's key), redeems ID-JAGs, and reads a
  rule-by-rule report next to the receiver's decision. Locked down: isolated sandbox users, rate limits, daily budgets,
  a blocklist, kill switches, and personal data kept a day at most. See
  [docs/test-your-idp.md](../../docs/test-your-idp.md).
- **`client.mjs`**: the five steps of the flow, printing every token it gets, then a replay to show single use. It runs
  as an AI agent or, with `--client=app`, as an ordinary app.

```
person ─sign in─▶ IdP ─ID token─▶ client ─token exchange─▶ IdP ─ID-JAG─▶ client ─jwt-bearer─▶ MCP AS ─access token─▶ client ─▶ /mcp
```

## What the example shows

- **The client's id differs between the two servers.** The MCP server registers the agent and issues it its own client
  id. The IdP records that id in the agent's metadata (`clientIdAtResource`) and puts it in the ID-JAG's `client_id`.
  Okta's resource-app guides describe the same model.
- **The IdP's policy is a code hook.** Allow the `read` scope for the MCP server's authorization server, deny
  everything else. A real IdP would use the registry and its admin API instead.
- **The IdP tells agents from apps.** `--setup` registers two clients: an AI agent and an ordinary app acting for the
  user. The IdP's policy names the agent as the actor in the ID-JAG (`act`, from the client's metadata `agent: true`),
  as Okta does for AI agents, and not the app. The MCP server carries `act` into the access token and keeps agents
  read-only (D-037).
- **The MCP server lists MCP's Enterprise-Managed Authorization extension** in its `initialize` reply
  (`capabilities.extensions`). The extension's own discovery is the authorization server's metadata
  (`authorization_grant_profiles_supported`), which the receiver advertises; the `initialize` entry is for clients that
  look there too (MCPJam does).
- **The MCP server provisions users on first use (JIT)** from the ID-JAG's verified `email`. The IdP's policy opts
  into sending it.
- **Audit events reach the D1 table** because `advanced.backgroundTasks` hands Better Auth's background work to the
  request's `ctx.waitUntil` (`background.ts`). Without that, Workers cut the work off when the response is sent, and the
  audit log stays empty.

## Two Workers limits, and what the example does about them

- **Fetching another Worker on the same account:** a Worker can't reach another one by its URL. The MCP server reaches
  the IdP's JWKS through a **service binding** (`IDP`), passed to `idJagGrant({ fetch })`. Okta's JWKS goes over the
  internet as usual.
- **Fetching itself:** a Worker can't fetch its own `workers.dev` URL; the request never completes.
  `requireMcpAuth` fetches the server's own JWKS by URL, so `/mcp` makes the same check in-process instead, with jose
  and the server's keys. A resource server deployed apart from its authorization server uses `requireMcpAuth` as is.
  `test/receiver/exit.test.ts` runs it against these tokens.

## Deploy

```sh
pnpm build                                   # the schema script reads the built package
node examples/workers/schema.mts idp > examples/workers/enterprise-idp/migrations/0001_init.sql
node examples/workers/schema.mts mcp > examples/workers/mcp-server/migrations/0001_init.sql
```

For each Worker:
1. Create its D1 database (`wrangler d1 create`).
2. Copy `wrangler.jsonc` to `wrangler.deploy.jsonc` (git-ignored), and fill in the database id and the other Worker's
   URL.
3. Apply the migrations, deploy, and set the secrets `BETTER_AUTH_SECRET` and `SETUP_KEY`. Use the same `SETUP_KEY` for
   both.

Deploy the IdP first, because the MCP server's service binding needs it to exist.

```sh
SETUP_KEY_FILE=<file> node examples/workers/client.mjs https://<idp> https://<mcp> --setup   # once
node examples/workers/client.mjs https://<idp> https://<mcp>                                 # any time after
```

The IdP registers every client for `client_secret_post` and lists only that method in its metadata (the top of
`enterprise-idp/src/index.ts` says why: [Claude Code](#claude-code)). A state file from before that change holds
`client_secret_basic` clients: run `--setup` once more.

## Okta Cross App Access

For your own server, [docs/okta.md](../../docs/okta.md) is the whole guide. For these Workers:

Set `OKTA_ISSUER` and `OKTA_JWKS_URI` on the MCP server. In Okta, the resource app's **Issuer URL** (Machine Assignments, Resource server access) takes the
MCP server's issuer **exactly as its metadata publishes it**, path included: the `issuer` field of
`https://<mcp>/.well-known/oauth-authorization-server/api/auth`, for example `https://<mcp>/api/auth`. The receiver
compares `aud` with it exactly. The AI agent's client id and secret are issued by the MCP server (`/setup`) and entered
in Okta.

`node examples/workers/okta-agent.mjs` plays the agent: `--subject=refresh` exchanges Okta's refresh token instead of
the ID token, `--negative` adds the replay, scope and audience refusals, and `--refresh-file=<path>` with `--reuse`
replays a saved refresh token (after unassigning or deactivating the user in Okta). See the header of the script.

### A client that sends its secret in the body

`/setup` registers `client_secret_basic` clients (what `client.mjs` and `okta-agent.mjs` use). VS Code and xaa.dev's
tester send the secret in the request body, and Better Auth holds a client to the method it was registered with, so
register theirs with `client_secret_post`:

```sh
curl -X POST https://<mcp>/setup -H "x-setup-key: $(cat <file>)" -H 'content-type: application/json' \
  -d '{"email":"operator@example.com","password":"example-password-1234","name":"VS Code","tokenEndpointAuthMethod":"client_secret_post"}'
```

The reply is the client id and secret. The client may ask for both scopes, `read write`: VS Code asks for every scope
the server advertises.

### VS Code

VS Code 1.123+ (preview) does this flow itself, with Okta as the IdP: verified with VS Code 1.141.0
([docs/interop.md](../../docs/interop.md#vs-code-with-okta--our-receiver)). Set up Okta for these Workers as above, then:

1. Register a `client_secret_post` client at the MCP server (above) and enter its id in Okta's resource connection,
   allowing `read write`.
2. On the agent's Okta app, add the sign-in redirect URI `http://127.0.0.1:33418/` (desktop VS Code's loopback
   redirect, trailing slash included).
3. In VS Code's user settings, `mcp.enterpriseManagedAuth.idp`: Okta's issuer and the agent's Okta client. In
   `mcp.json`, the server `https://<mcp>/mcp` with `"oauth": { "enterpriseManaged": true, "clientId": "<from step 1>" }`.
   VS Code asks for the client secret once.

## Claude Code

Claude Code's Cross App Access (`CLAUDE_CODE_ENABLE_XAA=1`) works against these Workers with **this IdP** as the IdP:
it asks the IdP for no scope, and this IdP's policy grants the user's scopes anyway (`read`, plus `write` for the users
in `WRITERS`): draft -06 doesn't say what an omitted `scope` gets, and RFC 6749 section 3.3 lets an authorization
server apply a pre-defined default. With Okta it can't: Okta grants no scope when
none is asked for, and the receiver refuses an ID-JAG without one
([docs/interop.md](../../docs/interop.md)).

1. Register Claude Code's client at the MCP server (`/setup`, as above; Basic is fine there), then at the IdP with
   Claude Code's loopback redirect:

   ```sh
   curl -X POST https://<idp>/setup -H "x-setup-key: $(cat <file>)" -H 'content-type: application/json' \
     -d '{"email":"agent-user@example.com","password":"example-password-1234","clientIdAtResource":"<the MCP client id>","agent":true,"redirectUris":["http://localhost:8765/callback"]}'
   ```

2. `claude mcp xaa setup --issuer https://<idp>/api/auth --client-id <the IdP client id> --client-secret --callback-port 8765`
   (the secret from `MCP_XAA_IDP_CLIENT_SECRET`), then `claude mcp xaa login`: the IdP's sign-in page (`/login`) opens
   in the browser.
3. `claude mcp add --transport http --xaa --client-id <the MCP client id> --client-secret <name> https://<mcp>/mcp`
   (the secret from `MCP_CLIENT_SECRET`).

Why `client_secret_post` here: Claude Code 2.1.319 signs in with HTTP Basic when the IdP's metadata lists it, but
always sends the secret in the body when it asks for the ID-JAG. Better Auth holds a client to one registered method, so
a Basic client fails the second step. Listing only `client_secret_post` makes Claude Code use it for both.

## Running locally

`wrangler dev` runs both Workers (each with its own `--persist-to`, because the two configs share a placeholder
database id), and `/setup` works on `http://localhost`. The whole flow doesn't: the receiver takes only `https`
issuers and JWKS URLs, so an ID-JAG from a local IdP is refused. Deploy, or put both behind https.

## Layered permissions

The demo shows the layers ID-JAG leaves to you (README, "What ID-JAG controls"):

| Layer | Where | In the demo |
|---|---|---|
| Who may have which scope | The IdP's policy | `read` for everyone; `write` only for the emails in the IdP's `WRITERS` (here `agent-user@example.com`). `reader-user@example.com`'s agent asks for `read write` and gets `read` |
| Which tool a scope unlocks | The MCP server | `whoami` and `list_notes` need `read`; `add_note` and `delete_note` need `write`. Without it: **403** with `WWW-Authenticate: … error="insufficient_scope", scope="write"` |
| What an agent may do compared with an app | The IdP names it, the MCP server decides | The IdP puts `act` in an AI agent's ID-JAGs (Okta does too), not in an app's. An agent may write **within guardrails**: each tool says whether an agent may use it on its own (`add_note`) or needs a person's approval (`delete_note`; this demo has no approval step, so it refuses). The refusal is an MCP **tool error** (200, `isError`, `structuredContent: { status: "approval_required", retryable: false }`), not a 403: the token has the scope, so a client mustn't be told to sign in again for it. Every write is logged with the person, the agent (`act.sub`) and the ID-JAG's `jti` |
| How long access outlives a cutoff | The MCP server's token lifetimes | `accessTokenExpiresIn: 300`, `scopeExpirations: { write: "2m" }` |

```sh
node examples/workers/client.mjs <idp> <mcp> --client=app                 # app for agent-user: read write, add_note and delete_note 200, token 120 s
node examples/workers/client.mjs <idp> <mcp>                              # AI agent for agent-user: read write, add_note 200, delete_note a tool error (needs approval)
node examples/workers/client.mjs <idp> <mcp> --as=reader                  # AI agent for reader-user: read only, add_note and delete_note 403 insufficient_scope
node examples/workers/client.mjs <idp> <mcp> --client=app --as=reader     # app for reader-user: the same
node examples/workers/client.mjs <idp> <mcp> --as=reader --cutoff         # polls until the token stops working
```

A state file from before the AI agent and app were split needs `--setup` once more (it registers the two clients).
Each run checks its results and prints what failed: an agent's token must carry `act` and an app's must not, so a
run against an IdP that doesn't tell them apart fails instead of passing.

Measured on the deployed demo (2026-10-08): the write token stopped working 125 s after it was issued, the read
token 305 s after (polled every 10 s). An IdP decision (a block, a deprovisioning) stops new ID-JAGs at once; an
agent keeps what it already has for at most those lifetimes, instead of Better Auth's default hour.

## xaa.dev's resource-app tester

Set `XAA_ISSUER` to `https://idp.xaa.dev` and `CORS_ORIGINS` to `https://xaa.dev` on the MCP server: the tester calls
the token endpoint and `/mcp` from the browser. It authenticates with `client_secret_post`, so register its client
with that method ("A client that sends its secret in the body", above). In the tester, choose **Use My Own Auth Server** and
enter the MCP server's issuer, its token endpoint, and that client. The SAML variant sends the user as a SAML NameID
in `sub_id`; the MCP server maps xaa.dev's SAML issuer (`samlSubjects`, in `mcp-server/src/auth.ts`). Results:
[docs/interop.md](../../docs/interop.md#xaadev--our-receiver).

## The public tester

The IdP can also be tested against the public tester at https://idjag-tester.infowall.net. The tester is a second
receiver: it redeems an ID-JAG and reports every rule it passed or failed
([docs/test-your-idp.md](../../docs/test-your-idp.md)). The token exchange's `audience` tells the IdP which receiver an
ID-JAG is for:

```
person ─sign in─▶ IdP ─ID token─▶ client ─token exchange─▶ IdP ─┬─ audience: the MCP server ─▶ ID-JAG ─jwt-bearer─▶ MCP AS ─access token─▶ client ─▶ /mcp
                                                                │    only to clients registered for the MCP server; read, or read write for WRITERS
                                                                │
                                                                └─ audience: the tester ─────▶ ID-JAG ─jwt-bearer─▶ tester ─▶ a report, rule by rule
                                                                     only to clients registered "for": "tester"; read only
```

Each receiver knows the client by its own client id, and the IdP puts that id in the ID-JAG's `client_id`. A client
for the tester is therefore registered twice, in this order:

1. Register the IdP's issuer at the tester. The tester gives a client id there.
2. Register a client at the IdP with `"for": "tester"` and that client id:

```sh
curl -X POST https://<idp>/setup -H "x-setup-key: $(cat <file>)" -H 'content-type: application/json' \
  -d '{"email":"agent-user@example.com","password":"example-password-1234","clientIdAtResource":"<the tester client id>","agent":true,"for":"tester"}'
```

Its redirect URI is then the tester's `/flow/callback`, so the tester's "Run the whole flow" can sign in with it
and redeem the ID-JAG it gets; the curl's answer has the client id and secret to enter there. This IdP's clients
authenticate with `client_secret_post`, so choose that in the tester's form. If you tick the tester's refresh token
option, the sign-in asks for consent too (`prompt=consent`), on this IdP's `/consent` page: press Allow.

`TESTER_AS_ISSUER` and `TESTER_RESOURCE` turn this on. `wrangler.jsonc` sets them to the public tester; without them,
the IdP issues ID-JAGs for the MCP server only. A client registered for one receiver gets nothing from the other
(`policy` in `enterprise-idp/src/auth.ts`, tested in `test/examples/enterprise-idp-policy.test.ts`).
