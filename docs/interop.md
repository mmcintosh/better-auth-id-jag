# Interoperability

This page lists which other ID-JAG implementations our issuer (`idJagIssuer()`) and our receiver
(`idJagGrant()`) have been run against, and what happened. Each row is one of three things:

- **verified**: a test ran the whole flow against that implementation, with the date and version;
- **differs, because …**: the flow works, but the other side behaves differently in a way you should know;
- **not possible, because …**: there's nothing to test against yet, with the reason and links.

Nothing here is claimed from reading docs alone. Where a row says "verified", the test is in
`test/interop/`, and the commands to run it are below.

## The matrix

| Our side | Other side | Status |
|---|---|---|
| Our issuer | Our receiver (`mcp()` host) | **Verified** 2026-10-06, this repository at `better-auth` 1.7.6, on Node 24.12 and in workerd. Runs in every CI build. |
| Our issuer | Keycloak receiver | **Verified** 2026-10-06, Keycloak 26.8.0 (`quay.io/keycloak/keycloak:26.8.0@sha256:b0f60d489d51c5d113390bdf5461d4c06e6051be026c05549f2e1e10ec352bcc`), feature `identity-assertion-jwt`. ES256, RS256 and EdDSA all accepted. **Differs:** Keycloak ignores the ID-JAG's `scope` and `resource` (see below). |
| Our issuer | Authelia receiver | **Not possible yet**, because no Authelia release or nightly includes ID-JAG support (see below). |
| Authelia issuer | Our receiver | **Not possible yet**, for the same reason. |
| Our issuer | node-oauth2-server receiver | **Verified** 2026-10-06 against the unreleased pull request [node-oauth/node-oauth2-server#462](https://github.com/node-oauth/node-oauth2-server/pull/462) at commit `0b7844f83f552d3acf50e13aca27f03c214fd825`. ES256 and RS256 accepted. **Differs:** EdDSA is refused (see below). |
| Microsoft Entra ID (issuer) | Our receiver | **Not possible yet**, because Entra doesn't issue ID-JAGs: its [release notes](https://learn.microsoft.com/en-us/entra/fundamentals/whats-new) don't mention them (checked 2026-10-10). `scripts/entra-watch.mjs` checks them weekly and fails at the first mention. Entra's on-behalf-of flow also uses the jwt-bearer grant but isn't ID-JAG: our receiver refuses its tokens (`typ`). |
| Our receiver | Keycloak issuer | **Not possible**, because Keycloak doesn't issue ID-JAGs. Its guide lists the issuer side as "Not Yet Implemented". |
| SAML IdP: better-auth-saml-idp (assertion exchange) → our issuer → our receiver | (both SAML paths) | **Verified** 2026-10-06 against **better-auth-saml-idp 1.2.0 from npm** (and before that its `feat/assertion-exchange` at `2d54cb4`), with this repository's main: every check passes (`test/interop/saml-idp-e2e`). |
| better-auth-scim-provisioning 1.2.0 (IdP) → `@better-auth/scim` 1.7.6 + our receiver | (SCIM-provisioned users) | **Verified** 2026-10-10 in every CI run on Node (`test/interop/scim-provisioning.test.ts`): a user the IdP provisioned resolves by SCIM (`resolvedBy: "scim"`); banned or deleted at the IdP, the receiver refuses even an ID-JAG issued before. Also on Postgres, MySQL, Drizzle and Prisma (the adapter matrix). Not on D1: `@better-auth/scim` needs native transactions. |
| Okta Cross App Access (issuer) | Our receiver (`mcp()` host on Workers) | **Verified live** 2026-10-06, an Okta Integrator Free Plan org (Okta 2026.09.1), our receiver deployed on Cloudflare Workers with D1. RS256 ID-JAG accepted; Okta's `act` claim (the AI agent) carried into the access token. **Found:** our receiver refused `act` until D-010 (see below). A second session the same day ran the lifecycle checks: a returning user, the refresh-token subject, replay, scope and audience refusals, the connection disabled, the user unassigned and deactivated (D-023, below). |
| xaa.dev playground IdP (Okta's), OIDC | Our receiver (`mcp()` host on Workers) | **Verified live** 2026-10-06 with xaa.dev's resource-app tester, "Use My Own Auth Server": ID token → ID-JAG at xaa.dev → our access token → MCP `tools/call` 200. **Differs:** the tester calls our token endpoint and MCP server from the browser (CORS) and authenticates with `client_secret_post` (see below). |
| xaa.dev playground IdP, SAML | Our receiver | **Verified live** 2026-10-06: SAML SSO → assertion → refresh token → ID-JAG with a SAML `sub_id` → our access token, the user resolved by NameID through `samlSubjects` → MCP `tools/call` 200 (see below). |
| MCPJam's Cross App Access debugger (`@mcpjam/sdk` 9.3.0), OIDC and SAML | Our receiver (`mcp()` host over HTTP) | **Verified** 2026-10-14, weekly in the Interop workflow: MCPJam's ID-JAG → our access token → MCP `initialize`, and each of MCPJam's ten attacks refused with the matching reason, for an ID token and for a SAML `sub_id` (see below). |
| identity-provider.net ("ZipIdP", a stub IdP on xaa.rocks) | Our receiver | **Verified live** 2026-10-14, weekly in the Interop workflow: ID token and refresh token → ZipIdP's ID-JAG (RS256) → our access token; replay, another client id and an ML-DSA-signed ID-JAG refused (see below). |
| PingFederate 13.1.3 (issuer) | Our receiver | **Verified live** 2026-10-14, PingFederate in Docker (`pingidentity/pingfederate:13.1.3-latest`, a DevOps evaluation license), refresh-token subject: ID-JAG → our access token; replay refused. **Differs:** Ping names its signing key by `x5t` only, never `kid` (accepted since D-042); `client_id` and a 5-minute lifetime need two settings on the connection (see below). |
| Oracle OCI IAM identity domain (issuer) | Our receiver | **Refused, by design** (checked live 2026-10-14, a Free-type identity domain, Oracle's ID-JAG from 2026-10-09): Oracle's ID-JAG has **no `aud`**, which the draft requires, so our receiver refuses it (`missing_claim`). **Found:** Oracle's signing key lists `key_ops` `["wrapKey", "encrypt", "verify"]`, which WebCrypto won't import for RS256; our receiver returned a 500 until D-041 (see below). |

## Our issuer → our receiver

`test/interop/self.test.ts`, 5 tests, on both test runtimes. There are two separate Better Auth instances in one
process:

- **The IdP**, at `https://idp.example`: `oauthProvider()`, `jwt()` (ES256) and `idJagIssuer()`, with a code-hook policy.
- **The MCP server's authorization server**, at `https://mcp.example`: `mcp()`, `cimd()`, `jwt()` and `idJagGrant()`.
  It trusts the IdP through a static trusted issuer.

They talk only through `Request`s:

1. A user signs in at the IdP. The agent gets an ID token through `/oauth2/authorize` (PKCE) and the
   `authorization_code` grant.
2. The agent does a token exchange at the IdP, with `audience` = `https://mcp.example/api/auth` (the MCP
   authorization server's issuer) and `resource` = `https://mcp.example/mcp`.
3. The agent sends the jwt-bearer grant to the MCP authorization server. It authenticates with the client id
   *that server* issued it. The IdP's policy maps the agent's IdP client id to that id (`clientIdAtResource`).
4. The MCP authorization server fetches the IdP's `/jwks` through the receiver's `fetch` option, which is routed
   to the IdP's handler. That is the only outbound request.
5. `requireMcpAuth` accepts the access token for `https://mcp.example/mcp` and refuses it for another resource.

The tests also check what should be refused:

- the same ID-JAG redeemed twice (`replay`);
- an ID-JAG whose `client_id` is the agent's IdP client id (`client_mismatch`);
- `aud` set to the MCP resource, the bare origin, or the issuer with a trailing slash (`wrong_audience`);
- an ID-JAG signed by another instance at the same issuer URL (`bad_signature`);
- an audience the IdP's policy doesn't know (`policy_denied`).

One more test covers JIT provisioning: a verified email, sent because the policy opted in, creates and links a
local user.

**Databases.** On Node, each host has its own in-memory SQLite. In workerd, a test file gets a single D1. Two hosts
sharing it would share the `user`, `jwks` and `oauthClient` tables, so the MCP server would sign with the IdP's key.
So in workerd the IdP runs on Better Auth's memory adapter, and the MCP host keeps the D1, because the receiver's
single-use check needs a database that enforces UNIQUE.

## Our issuer → Keycloak

`test/interop/keycloak.test.ts`, 9 tests, Node only. It is skipped unless `INTEROP_KEYCLOAK=1`.

Our IdP is served over real HTTP on `127.0.0.1` (Node's `http` module, `test/support/interop-http.ts`), so Keycloak
can fetch its JWKS. The test sets everything up through Keycloak's admin REST API, in a fresh realm per test:

- **The identity provider:** type `jwt-authorization-grant`, alias `better-auth`, with `config.issuer` = our issuer,
  `config.jwksUrl` = our `/api/auth/jwks`, `useJwksUrl`, `jwtAuthorizationGrantEnabled` and
  `jwtAuthorizationGrantMaxAllowedAssertionExpiration=300`. One test uses the guide's `oidc` broker type instead.
- **A confidential client** `agent-kc`, with the attributes `oauth2.jwt.authorization.grant.enabled=true` and
  `oauth2.jwt.authorization.grant.idp=better-auth`.
- **A user** with a federated identity link: `identityProvider=better-auth`, `userId` = our `sub`, which is our
  user id.

### Run it

```sh
docker run -d --name keycloak --network host \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:26.8.0@sha256:b0f60d489d51c5d113390bdf5461d4c06e6051be026c05549f2e1e10ec352bcc \
  start-dev --http-port=18080 --features=identity-assertion-jwt
until curl -sf http://localhost:18080/realms/master >/dev/null; do sleep 2; done
INTEROP_KEYCLOAK=1 pnpm vitest run --project node test/interop/keycloak.test.ts
docker rm -f keycloak
```

`INTEROP_KEYCLOAK_URL` overrides `http://localhost:18080`. The container uses host networking because Keycloak has to
reach our IdP on loopback. Keycloak allows an `http` JWKS URL on loopback and private addresses under the default
`sslRequired=external`.

### Result (2026-10-06, Keycloak 26.8.0, Node 24.12.0, Docker 29.1.3)

All 9 passed. What Keycloak did:

| Case | Keycloak's answer |
|---|---|
| ID-JAG for a pre-linked subject (ES256) | 200, a Keycloak access token. `iss` = the realm, `sub` = the Keycloak user, `azp` = `agent-kc`, `aud` = `account`, `expires_in` 300, no refresh token. Keycloak fetched `GET /api/auth/jwks` from our IdP. |
| `aud` = the realm's token endpoint instead of its issuer | 200 |
| Identity provider configured as an `oidc` broker | 200 |
| RS256, EdDSA | 200 each |
| The same ID-JAG again | 400 `{"error":"invalid_grant","error_description":"Token reuse detected"}` |
| Subject not linked | 400 `{"error":"invalid_grant","error_description":"User not found"}` |
| `client_id` = the agent's id at the IdP | 400 `{"error":"invalid_grant","error_description":"client id in assertion : agent-at-the-idp and client id in request header/body : agent-kc"}` |
| `aud` = the realm issuer with a trailing slash | 400 `{"error":"invalid_grant","error_description":"Invalid token audience"}` |
| ID-JAG with `scope=read`, `resource=https://mcp.example/mcp`, plus `resource` on the request | 200, `scope` = `profile email`, `aud` = `account` |

### Where Keycloak differs

- **Keycloak ignores `scope` and `resource`.** Its token carries the client's default scopes, whatever the ID-JAG
  allowed. Its token endpoint reads only `assertion` and `scope` for this grant. A policy that narrows scopes at our
  issuer doesn't narrow Keycloak's token, so configure the Keycloak client's scopes to match.
- **`aud` has two accepted values:** the realm issuer, or the token endpoint. Our receiver accepts only its issuer
  identifier. Keycloak refuses an `aud` array with more than one value; our issuer always sends a single string.
- **Keycloak checks lifetime from `iat`.** It refuses an assertion older than
  `jwtAuthorizationGrantMaxAllowedAssertionExpiration` seconds (default 300), whatever `exp` says. Our issuer's
  default lifetime is 300 seconds. A policy that sets a longer one (up to 900) gets ID-JAGs that Keycloak refuses
  after 300.
- **Clock skew defaults to 0 on the OIDC broker type.** The setting is `allowedClockSkew`.
- **The subject must be pre-linked.** There is no JIT and no email matching for this grant. The user also needs no
  pending required actions, and either no consent requirement or consent already given.
- **`typ` must be exactly `oauth-id-jag+jwt`** for Keycloak's ID-JAG validator to run. Any other `typ` falls back to
  plain RFC 7523 validation, which doesn't check `client_id`. Our issuer always sends the exact value.
- **Error descriptions name the failing check** (as in the table above). Our receiver doesn't, by design (S8).
- **Our issuer's audiences are https only.** `allowLoopbackHttpAudiences: true` is what lets it mint for
  `http://localhost:18080/realms/…`. The test sets it.
- **Keycloak's guide is written against draft -01.** We implement -04. The claims Keycloak checks (`iss`, `sub`,
  `aud`, `client_id`, `jti`, `exp`, `iat`) are the same in both.

Keycloak's rules above are from its source at the 26.8.0 tag:
`services/src/main/java/org/keycloak/protocol/oidc/grants/JWTAuthorizationGrantType.java`,
`services/…/oidc/grants/IDJWTAuthorizationGrantValidator.java`,
`services/…/authentication/authenticators/client/AbstractBaseJWTValidator.java` and
`services/…/broker/jwtauthorizationgrant/JWTAuthorizationGrantConfig.java`. The feature is `IDENTITY_ASSERTION_JWT`
(experimental) in `common/src/main/java/org/keycloak/common/Profile.java`, first released in 26.7.0. Guide:
<https://www.keycloak.org/securing-apps/identity-assertion-jwt-authorization-grant>.

## Okta Cross App Access → our receiver

Live, by hand, against the example MCP server (`examples/workers/mcp-server`) deployed on Workers, with
`examples/workers/okta-agent.mjs` playing the AI agent:

1. The user signed in at Okta (authorization code + PKCE) to the agent's Okta app: an ID token.
2. The agent exchanged it at Okta's token endpoint (RFC 8693, `requested_token_type` id-jag,
   `audience` = our receiver's issuer, `resource` = our `/mcp`, `scope=read`). Okta checked the agent's
   resource connection and returned `issued_token_type` id-jag, `token_type` `N_A`, `expires_in` 300.
3. The agent redeemed the ID-JAG at our receiver with the client id and secret **our receiver issued**
   (Okta's model, D-004): an access token for `/mcp`.
4. The agent called the MCP server's tool with it: 200.

What Okta's ID-JAG carries:

| Header / claim | Value |
|---|---|
| `typ`, `alg`, `kid` | `oauth-id-jag+jwt`, `RS256`, a key from the org's `/oauth2/v1/keys` |
| `iss` | the Okta org itself (`https://<org>.okta.com`), not a custom authorization server |
| `aud` | exactly the issuer URL entered on the resource app's XAA settings (our `…/api/auth`) |
| `client_id` | the agent's client id **at our receiver**, as entered in Okta's resource connection |
| `sub`, `sub_profile` | the Okta user id, `user` |
| `resource`, `scope` | as configured on the connection (`…/mcp`, `read`) |
| `email` | the user's email |
| `act` | `{ "sub": "<the agent's Okta client id>", "sub_profile": "ai_agent web_app" }` |
| `exp - iat` | 300 s; `jti` prefixed `IDAAG.` |

**Found:** the first attempt was refused by our receiver with `unsupported_claim`: after the core review
(D-007) the core refused any ID-JAG with `act`, and Okta always sends it for an AI agent. `act` records who
acts for the user (RFC 8693 delegation) and widens nothing, so it is now accepted, shape-checked (an object
with `sub`, at most 4 nested actors) and carried into the access token (D-010). `authorization_details`
stays refused. Without the live test the receiver would have refused every Okta ID-JAG.

### The lifecycle checks (2026-10-06, second session, D-023)

The same org and deployment, `okta-agent.mjs` with `--subject=refresh`, `--negative` and `--refresh-file`/`--reuse`:

| Check | Result |
|---|---|
| A returning user | The same local user, through the linked Okta account; no user or link created |
| Okta's **refresh token** as the subject token | Accepted by Okta; our receiver's result as for an ID token |
| The same ID-JAG redeemed twice | Our receiver refused the second (`invalid_grant`; audit `replay`) |
| `scope=read admin` | **Okta** refused: `invalid_scope` ("scopes are not allowed for this request: [admin]") |
| An audience with no connection | **Okta** refused: `invalid_target` |
| Cross-app access disabled on the resource app | **Okta** refused the exchange of both an ID token and a refresh token: `invalid_target` |
| The connection re-created with the issuer URL in the client-id field | Okta minted an ID-JAG whose `client_id` was that URL; **our receiver** refused it (`client_mismatch`: not the client that authenticated) |
| The user unassigned from the resource app (with a saved refresh token) | **Okta** refused: `access_denied`, "User is not assigned to the client application."; reassigned, the same refresh token worked again |
| A new user, first use | Provisioned just in time from the verified `email` and linked |
| That user deactivated (with a saved refresh token) | **Okta** refused: `invalid_request`, "'subject_token' is invalid." |

So the enterprise controls work as the specification intends: Okta enforces the connection, its scopes,
assignment and the user's status at every exchange, and our receiver enforces the ID-JAG's audience, client and
single use. Deactivating a user doesn't remove the local user our receiver provisioned (with SCIM provisioning and `scim`
on the trust entry it does stop them: see the better-auth-scim-provisioning row), and
an access token already issued lives until it expires.

Setting it up in Okta, step by step, with the values for your own server: [docs/okta.md](okta.md).

## xaa.dev → our receiver

[xaa.dev](https://xaa.dev) is Okta's Cross App Access playground. Its **resource-app tester** (Resource App →
Register it with xaa.dev's IdP → **Use My Own Auth Server**) has the playground IdP (`https://idp.xaa.dev`, RS256,
JWKS at `/jwks`) issue ID-JAGs to our receiver, redeems them at our token endpoint, and calls our MCP server.
Live, 2026-10-06, against `examples/workers/mcp-server` with `XAA_ISSUER` and `CORS_ORIGINS` set:

| Variant | Flow | Result |
|---|---|---|
| OIDC | Sign-in → refresh token → ID-JAG → jwt-bearer at our receiver → MCP `initialize`, `notifications/initialized`, `tools/call` | ✅ 200 at every step; the user provisioned just in time; a returning user found by its link |
| SAML | SAML SSO → assertion exchanged for a refresh token (draft §4.5) → ID-JAG → jwt-bearer → MCP | ✅ 200 at every step, the user resolved by the SAML NameID in `sub_id` |

What the tester needs from a receiver, and what it found:

- **The browser calls the receiver.** The token endpoint and the MCP endpoint need CORS for `https://xaa.dev`
  (the example's opt-in `CORS_ORIGINS`). Without it the tester reports "Failed to fetch".
- **`client_secret_post`.** It sends the receiver-issued client id and secret in the body, so register that
  client with `token_endpoint_auth_method: client_secret_post`. Otherwise our receiver refuses
  (`invalid_client`, "client registered for client_secret_basic cannot use client_secret_post").
- **Real MCP.** Its last step is MCP's Streamable HTTP (`initialize` with capabilities, then the initialized
  notification, then `tools/call`).
- **The audience.** The ID-JAG's `aud` is the auth-server URL entered in the tester, `client_id` the target client
  id, `resource` the resource identifier. The tester asks its own IdP for `resource=…/mcp/` with a trailing
  slash, but the ID-JAG carries `…/mcp` as registered.
- **An email that's already ours.** The first OIDC run asserted an email already linked to the Okta user. Our
  receiver refused it (`unknown_subject`, "JIT: email belongs to an existing user"), because the xaa.dev trust
  entry has no email fallback. That's the account-takeover protection working against a real third-party IdP.
  A user new to our receiver was provisioned.
- **SAML subjects.** The SAML variant's ID-JAG has `sub` = the email and
  `sub_id = { format: "saml-nameid", issuer: "https://idp.xaa.dev/saml", nameid: <email>, nameid_format:
  "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" }`. Without a mapping, our receiver resolved it by
  `sub`, a new identity, and refused the colliding email as above. With `samlSubjects: [{ issuer:
  "https://idp.xaa.dev/saml", nameIdFormats: [emailAddress], accountProviderId: "xaa-saml" }]` on the trust entry,
  and that NameID linked to the existing user, the ID-JAG resolved to that user **through `sub_id` alone** (its
  `sub` is linked to nothing).
- The tester offers no conformance export; the evidence is its step results and our audit log.

## Authelia: not possible yet

Authelia's OAuth library merged ID-JAG support for both roles, draft -04:
[authelia/oauth2-provider#815](https://github.com/authelia/oauth2-provider/pull/815), merged 2026-10-01 as
`59208d3d3eaeefae2ca04b156a4f275385ec70ca`. But:

- **No library release contains it.** The latest tag, `v0.3.3` (`db7e7df6`, 2026-09-19), predates the merge.
- **Authelia itself pins `v0.3.3`.** That is its `go.mod` on `master` as of 2026-10-05, with no `replace` for the
  library. The latest release is v4.39.28 (2026-09-17), and the `master` image is built on the same library version.
- **Nothing in Authelia wires the grant up.** There is no configuration key, and no pull request or issue mentions
  ID-JAG. The nearest pull request is token exchange, [authelia/authelia#13122](https://github.com/authelia/authelia/pull/13122).
  It is open, and its docs list jwt-bearer as "planned".

Building Authelia from source against the library's `master` wouldn't help, since the server has no configuration to
turn the handlers on. We'll test both directions when an Authelia release or nightly ships it.

## Our issuer → node-oauth2-server

`test/interop/node-oauth2-server.test.ts`, 5 tests, Node only. It is skipped unless `INTEROP_NODE_OAUTH2=1` and
`INTEROP_NODE_OAUTH2_DIR` are set.

The grant is [node-oauth/node-oauth2-server#462](https://github.com/node-oauth/node-oauth2-server/pull/462).
It is open and unreleased: npm's latest `@node-oauth/oauth2-server` is 5.3.0, which doesn't have it, and the
maintainer would rather merge generic RFC 7523 support (#453) first. So it isn't a dependency of this package. The
test loads it from a directory you install it into, at the PR's head commit:

```sh
mkdir -p /tmp/noas && cd /tmp/noas && echo '{"name":"noas-interop","private":true}' > package.json
npm install --ignore-scripts --no-audit --no-fund \
  https://codeload.github.com/manmohan-shaw-okta/node-oauth2-server/tar.gz/0b7844f83f552d3acf50e13aca27f03c214fd825
cd -   # back to this repository
INTEROP_NODE_OAUTH2=1 INTEROP_NODE_OAUTH2_DIR=/tmp/noas pnpm vitest run --project node test/interop/node-oauth2-server.test.ts
```

node-oauth2-server doesn't fetch JWKS. The host's model resolves the key (`getRequestingIssuerKey(iss, kid)`), and
the test's model reads our IdP's `/jwks` in process. Its issuer identifier (`tokenEndpointUri`) is
`https://as.node-oauth2.example`.

### Result (2026-10-06, PR #462 at `0b7844f8`, Node 24.12.0)

All 5 passed:

| Case | node-oauth2-server's answer |
|---|---|
| ES256 and RS256 ID-JAGs for a known subject | Token issued with the ID-JAG's scope, no refresh token |
| The same ID-JAG again | `invalid_grant` "Invalid grant: `assertion` is invalid" |
| EdDSA ID-JAG | `invalid_grant` (the same text) |
| `scope=read` on the request, ID-JAG `read write` | Token with `read` |
| `scope=read write` on the request, ID-JAG `read` | `invalid_scope` "Invalid scope: requested scope exceeds the scope granted by the assertion" |
| `client_id` = the agent's id at the IdP; an unknown subject | `invalid_grant` (the same text) |

### Where node-oauth2-server differs

- **No EdDSA.** Its verifier knows RS256, PS256 and ES256 only. Better Auth's `jwt()` plugin defaults to EdDSA, so
  an issuer left on the default doesn't interoperate. Sign ID-JAGs with ES256 or RS256: set the `jwt()`
  `keyPairConfig`, or the issuer's `signingAlgorithm` with a matching `keyPairConfigs` entry.
- **A request `scope` wider than the ID-JAG's is an error** (`invalid_scope`). Our receiver narrows it silently, to
  the intersection.
- **It doesn't read `resource`.**
- **It has no maximum lifetime check** (ours: 900 s).
- **Every assertion failure gives the same `invalid_grant` text**, as ours does (S8).
- **`aud` must equal `tokenEndpointUri` exactly.** The option's name notwithstanding, its comment says that value is
  the issuer identifier.
- **The PR targets draft -03.** Its claim checks are the ones -04 requires.

## MCPJam → our receiver

`test/interop/mcpjam.test.ts`, 24 tests, Node only. It is skipped unless `INTEROP_MCPJAM=1` and
`INTEROP_MCPJAM_DIR` are set.

[MCPJam](https://github.com/MCPJam/inspector)'s Cross App Access debugger plays the enterprise IdP (it mints and
signs the ID-JAG) and the AI agent (it redeems the ID-JAG at our receiver and calls the MCP server with the access
token). It isn't a dependency of this package. The test loads its engine, `@mcpjam/sdk` (the `mcpjam xaa run` CLI
is a wrapper over it), from a directory you install it into:

```sh
mkdir -p /tmp/mcpjam && cd /tmp/mcpjam && echo '{"name":"mcpjam-interop","private":true}' > package.json
npm install --ignore-scripts --no-audit --no-fund @mcpjam/sdk@9.3.0
cd -   # back to this repository
DO_NOT_TRACK=1 INTEROP_MCPJAM=1 INTEROP_MCPJAM_DIR=/tmp/mcpjam pnpm vitest run --project node test/interop/mcpjam.test.ts
```

Everything runs on one machine. Our receiver and a minimal MCP endpoint are served over HTTP on 127.0.0.1, and so
are MCPJam's issuer metadata and JWKS: MCPJam checks that its issuer publishes its signing key before it sends
anything. Our receiver only takes an https `jwksUri`, so the trust entry names one and the receiver's `fetch`
answers it with the same key. MCPJam sends usage telemetry unless `DO_NOT_TRACK=1`; the test sets it.

### Result (2026-10-14, `@mcpjam/sdk` 9.3.0, Node 24.12.0)

All 24 passed. The whole flow (protected-resource and authorization-server discovery, the ID-JAG, our access
token, an MCP `initialize` with it) for an OIDC ID token and for a SAML assertion, whose ID-JAG carries a
`saml-nameid` `sub_id` that our receiver resolves through `samlSubjects`. MCPJam also records that our authorization
server advertises the jwt-bearer grant and the ID-JAG profile. Each of its attacks, with our receiver's reason:

| MCPJam's attack | Refused as |
|---|---|
| `bad_signature` | `bad_signature` |
| `wrong_audience` | `wrong_audience` |
| `expired` | `lifetime_too_long`: its expired ID-JAG also lives 3600 s, and the lifetime cap (900 s) comes first. The `exp` check has its own tests. |
| `missing_claims` | `missing_claim` |
| `invalid_type_header` | `wrong_typ` |
| `wrong_issuer` | `untrusted_issuer` |
| `resource_mismatch` | `unknown_resource` |
| `client_id_mismatch` | `client_mismatch` |
| `unknown_kid` | `bad_signature` (no key in the issuer's JWKS) |
| `scope_denial` | `no_scope` |
| `unknown_sub` | Policy, not an attack: with `jitProvisioning`, a new user (with SAML, under its own NameID, not linked to the known user); without it, `unknown_subject`. |

MCPJam reports "unknown" for the MCP Enterprise-Managed Authorization extension because the test's MCP endpoint
doesn't advertise it. That's the MCP server's part, not the receiver's.

## identity-provider.net → our receiver

`test/interop/zipidp.test.ts`, 4 tests, Node only, live on the internet. It is skipped unless `INTEROP_ZIPIDP=1`:

```sh
INTEROP_ZIPIDP=1 pnpm vitest run --project node test/interop/zipidp.test.ts
```

[identity-provider.net](https://identity-provider.net) ("ZipIdP") is a stub IdP for testing Cross App Access, one
of the [xaa.rocks](https://xaa.rocks) tools. Anyone can make a sandbox (no account: a cookie), and sign-in is
simulated (any username, any 6-digit code). The test makes a sandbox, registers our receiver's authorization server
(its issuer as the audience), the MCP resource and an agent client with a connection to our receiver, signs a user
in, and exchanges the ID token, then the refresh token, for ID-JAGs. Our receiver runs in-process and fetches only
ZipIdP's real JWKS. The test deletes every record it made (a sandbox itself can't be deleted).

### Result (2026-10-14)

All 4 passed. ZipIdP's ID-JAG: `typ` `oauth-id-jag+jwt`, RS256 with a key from `/jwks`, `iss`
`https://identity-provider.net`, `aud` our issuer, `client_id` the agent's id at our receiver, an opaque `sub`,
`email`, `auth_time`, `resource`, `scope`, `jti`, 300 s. No `act`.

| Check | Result |
|---|---|
| ID token → ID-JAG → our access token | Accepted; the user provisioned just in time and linked by `sub` |
| The same ID-JAG again | Refused: `replay` |
| Refresh token as the subject token | Accepted; the same local user |
| The connection re-pointed at another client id | Refused: `client_mismatch` |
| ZipIdP set to sign ID-JAGs with ML-DSA-65 | Refused: `disallowed_alg`, a normal refusal, not an error |

ZipIdP's JWKS mixes its RS256 key with ML-DSA keys (`kty: "AKP"`); that doesn't affect picking the RS256 key.
It puts a `sub_id` in the ID-JAG only for users who signed in through an upstream IdP, so SAML subjects aren't
tested here (MCPJam and xaa.dev cover them).

## PingFederate → our receiver

Run live on 2026-10-14 (issue #24) against PingFederate 13.1.3 in Docker on a developer machine, with a Ping DevOps
evaluation license. Configured through the admin API: a token-exchange processor policy over the OAuth Refresh Token
Token Processor, an **OAuth Token Exchange SP connection** for our receiver with `idJagEnabled`, and a client allowed
the password, refresh-token and token-exchange grants. The subject was a refresh token (PingFederate also takes an ID
token, through the JWT Token Processor 2.0).

| Header / claim | Out of the box | Setting that changes it |
|---|---|---|
| `typ`, `alg` | `oauth-id-jag+jwt`, RS256 | |
| `kid` | **none**: the key is named by `x5t` (its certificate's SHA-1 thumbprint) | none; the receiver matches `x5t` (D-042) |
| signing key | the SP connection's own key pair, **not in `/pf/JWKS`** | publish that key pair as the static RSA key (OAuth/OpenID Connect keys, static keys on, "publish x5c"), so `/pf/JWKS` carries it with `x5t` |
| `iss` | the engine's base URL | |
| `aud` | the connection's Partner's Entity ID (our receiver's issuer), or the request's `audience` | |
| `client_id` | **none** | an extended attribute `client_id` on the connection, fulfilled with the agent's client id **at our receiver** (Okta's model, D-004) |
| `sub` | the refresh token's user (here the user name) | |
| `scope`, `resource` | the request's; the connection is chosen by `resource`, and an unknown one is `invalid_target` | |
| lifetime | **30 minutes** (`exp` − `iat` = 1800), with `nbf` = `iat` − 300 | the connection's "minutes after" (5) |

**Result:** with those settings, the ID-JAG is accepted: our access token, the user found by the account linked under
PingFederate's subject, and the same ID-JAG again refused (`replay`). Before D-042 our receiver refused every
PingFederate ID-JAG (`missing_kid`); out of the box it also lacks `client_id` (`missing_claim`) and lives longer than our
300-second cap (`lifetime_too_long`).

A trust entry for it: `{ issuer: "<the engine's base URL>", jwksUri: "<engine>/pf/JWKS" }`.

## Oracle OCI IAM → our receiver

Checked live on 2026-10-14 (issue #24) with a Free-type OCI IAM identity domain, a week after Oracle added ID-JAG
issuance. Set up with the OCI CLI: a confidential app (the agent), a test user, and an outbound Identity Propagation
Trust with `idJagEnabled`, naming the agent and the permitted scopes and resources. The subject was an ID token from an
authorization-code sign-in (Oracle refuses `openid` with the password grant).

| Header / claim | Value |
|---|---|
| `typ`, `alg`, `kid` | `oauth-id-jag+jwt`, `RS256`, `SIGNING_KEY` (also `x5t`, `x5t#S256`) |
| `iss` | `https://identity.oraclecloud.com/`, **the same for every Oracle tenant**; the domain's own URL is only in the ID token's `tenant_iss` |
| `aud` | **none** |
| `client_id` | the agent's client id **at Oracle** |
| `sub` | the user's user name (here an email address) |
| `resource`, `scope` | the request's ∩ the trust's (one resource is a string) |
| lifetime | 300 s; `iat`, `exp`, `jti` present |

Oracle requires `resource` (`audience` alone is refused: "resource is required for ID-JAG") and refuses a resource the
trust doesn't list. Its AS metadata lists `urn:ietf:params:oauth:token-type:id-jag` in
`identity_chaining_requested_token_types_supported`, but `grant_types_supported` doesn't list token exchange.

**Our receiver refuses it:** `missing_claim` (`aud`). The draft requires `aud` (the resource authorization server's
issuer); it is what keeps an ID-JAG for one app from being redeemed at another, so the receiver doesn't relax it.

**Found, and fixed (D-041):** Oracle's JWKS publishes its RSA key with `key_ops` `["wrapKey", "encrypt", "verify"]`.
WebCrypto refuses to import an RSASSA key for any usage but `verify`, so jose (and any WebCrypto verifier) throws; the
signature itself is valid once `key_ops` is ignored. Our receiver now keeps a key whose `key_ops` includes `verify`
and imports it for `verify` only. The error had also been a 500: a `DOMException`'s numeric `code` reached the log
sanitiser. Now any key WebCrypto won't import is `jwks_unavailable`.

If Oracle adds `aud`, a trust entry would be `{ issuer: "https://identity.oraclecloud.com/", jwksUri:
"https://idcs-<id>.identity.oraclecloud.com/admin/v1/SigningCert/jwk" }` (the domain's "Access signing certificate"
setting on), with `allowedClientIds`, since every Oracle tenant shares that `iss` and only the keys tell them apart.

## CI

`.github/workflows/interop.yml` runs the Keycloak, node-oauth2-server, MCPJam and identity-provider.net jobs by hand
and every Monday:

- the Keycloak image is pinned by digest, node-oauth2-server by commit, and `@mcpjam/sdk` by version;
- the identity-provider.net job is live: it fails if that service is down or has changed;
- actions are pinned by SHA, as in `ci.yml`;
- the only permission is `contents: read`.

`self.test.ts` needs neither and runs in `ci.yml` with the rest of the suite.
