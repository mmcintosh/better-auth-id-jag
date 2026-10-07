# Enterprise-Managed Authorization on two Workers

Two Better Auth apps on Cloudflare Workers with D1, and a script that plays the MCP client:

- **`enterprise-idp/`**: the enterprise identity provider. `oauthProvider()` + `jwt()` (ES256) + `idJagIssuer()`.
  People sign in here. The agent exchanges their ID token for an ID-JAG, after the policy has approved it.
- **`mcp-server/`**: an MCP server and its authorization server. `mcp()` + `jwt()` + `idJagGrant()`. It trusts the IdP
  (and optionally Okta), turns an ID-JAG into an access token for its `/mcp`, and serves one tool, `whoami`.
- **`client.mjs`**: the five steps of the flow, printing every token it gets, then a replay to show single use.

```
person ─sign in─▶ IdP ─ID token─▶ client ─token exchange─▶ IdP ─ID-JAG─▶ client ─jwt-bearer─▶ MCP AS ─access token─▶ client ─▶ /mcp
```

## What the example shows

- **The client's id differs between the two servers.** The MCP server registers the agent and issues it its own client
  id. The IdP records that id in the agent's metadata (`clientIdAtResource`) and puts it in the ID-JAG's `client_id`.
  Okta's resource-app guides describe the same model.
- **The IdP's policy is a code hook.** Allow the `read` scope for the MCP server's authorization server, deny
  everything else. A real IdP would use the registry and its admin API instead.
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

## Okta Cross App Access

Set `OKTA_ISSUER` and `OKTA_JWKS_URI` on the MCP server. In Okta, the resource app's **Resource Server** tab takes the
MCP server's issuer **exactly as its metadata publishes it**, path included: the `issuer` field of
`https://<mcp>/.well-known/oauth-authorization-server/api/auth`, for example `https://<mcp>/api/auth`. The receiver
compares `aud` with it exactly. The AI agent's client id and secret are issued by the MCP server (`/setup`) and entered
in Okta.

`node examples/workers/okta-agent.mjs` plays the agent: `--subject=refresh` exchanges Okta's refresh token instead of
the ID token, `--negative` adds the replay, scope and audience refusals, and `--refresh-file=<path>` with `--reuse`
replays a saved refresh token (after unassigning or deactivating the user in Okta). See the header of the script.

## xaa.dev's resource-app tester

Set `XAA_ISSUER` to `https://idp.xaa.dev` and `CORS_ORIGINS` to `https://xaa.dev` on the MCP server: the tester calls
the token endpoint and `/mcp` from the browser. It authenticates with `client_secret_post`, so register its client
with that method (`/setup` registers `client_secret_basic`). In the tester, choose **Use My Own Auth Server** and
enter the MCP server's issuer, its token endpoint, and that client. The SAML variant sends the user as a SAML NameID
in `sub_id`; the MCP server maps xaa.dev's SAML issuer (`samlSubjects`, in `mcp-server/src/auth.ts`). Results:
[docs/interop.md](../../docs/interop.md#xaadev--our-receiver).
