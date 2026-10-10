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
| Our receiver | Keycloak issuer | **Not possible**, because Keycloak doesn't issue ID-JAGs. Its guide lists the issuer side as "Not Yet Implemented". |
| SAML IdP: better-auth-saml-idp (assertion exchange) → our issuer → our receiver | (both SAML paths) | **Verified** 2026-10-06 against **better-auth-saml-idp 1.2.0 from npm** (and before that its `feat/assertion-exchange` at `2d54cb4`), with this repository's main: every check passes (`test/interop/saml-idp-e2e`). |
| better-auth-scim-provisioning 1.2.0 (IdP) → `@better-auth/scim` 1.7.6 + our receiver | (SCIM-provisioned users) | **Verified** 2026-10-10 in every CI run on Node (`test/interop/scim-provisioning.test.ts`): a user the IdP provisioned resolves by SCIM (`resolvedBy: "scim"`); banned or deleted at the IdP, the receiver refuses even an ID-JAG issued before. Also on Postgres, MySQL, Drizzle and Prisma (the adapter matrix). Not on D1: `@better-auth/scim` needs native transactions. |
| Okta Cross App Access (issuer) | Our receiver (`mcp()` host on Workers) | **Verified live** 2026-10-06, an Okta Integrator Free Plan org (Okta 2026.09.1), our receiver deployed on Cloudflare Workers with D1. RS256 ID-JAG accepted; Okta's `act` claim (the AI agent) carried into the access token. **Found:** our receiver refused `act` until D-010 (see below). A second session the same day ran the lifecycle checks: a returning user, the refresh-token subject, replay, scope and audience refusals, the connection disabled, the user unassigned and deactivated (D-023, below). |
| xaa.dev playground IdP (Okta's), OIDC | Our receiver (`mcp()` host on Workers) | **Verified live** 2026-10-06 with xaa.dev's resource-app tester, "Use My Own Auth Server": ID token → ID-JAG at xaa.dev → our access token → MCP `tools/call` 200. **Differs:** the tester calls our token endpoint and MCP server from the browser (CORS) and authenticates with `client_secret_post` (see below). |
| xaa.dev playground IdP, SAML | Our receiver | **Verified live** 2026-10-06: SAML SSO → assertion → refresh token → ID-JAG with a SAML `sub_id` → our access token, the user resolved by NameID through `samlSubjects` → MCP `tools/call` 200 (see below). |

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
| The user unassigned (with a saved refresh token) | **Okta** refused: `access_denied`, "User is not assigned to the client application."; reassigned, the same refresh token worked again |
| A new user, first use | Provisioned just in time from the verified `email` and linked |
| That user deactivated (with a saved refresh token) | **Okta** refused: `invalid_request`, "'subject_token' is invalid." |

So the enterprise controls work as the specification intends: Okta enforces the connection, its scopes,
assignment and the user's status at every exchange, and our receiver enforces the ID-JAG's audience, client and
single use. Deactivating a user doesn't remove the local user our receiver provisioned (with SCIM provisioning and `scim`
on the trust entry it does stop them: see the better-auth-scim-provisioning row), and
an access token already issued lives until it expires.

Setting it up in Okta (Admin Console, 2026.09):
- The **resource app** is an OIDC web app. On its **Machine Assignments** tab, **Resource server access**,
  enable **Cross-app access (XAA)** and set its **Issuer URL** to the receiver's `issuer`, exactly as the
  receiver's `/.well-known/oauth-authorization-server/...` publishes it (path included). There is no org-wide
  feature toggle.
- The **AI agent** is registered under **Directory > AI agents** (manually), with Okta-generated client
  credentials (a client secret); its app needs the Authorization Code, Refresh Token and Token Exchange grants.
- Its **resource connection** (Application > App configured for AI Agent access) takes the resource app, the
  **resource indicator** (our `/mcp`), the **agent's client id registered at our receiver**, and the scopes.
- Subject mapping: the receiver provisioned the user just in time from the verified `email` claim; Okta's `sub`
  is then linked, so later ID-JAGs find the same user.
- The agent's app needs the **Refresh Token** grant for refresh tokens as subject tokens; a persistent refresh
  token (not rotated on each use) is simpler for testing.
- Turning cross-app access off and on again on the resource app asks for the issuer URL again and drops the
  resource connection's resource indicator. The connection's **client id can't be edited**: deactivate the
  connection, remove it, and add it again. Check the client id field: it may come up filled with the issuer URL,
  which our receiver then refuses as `client_mismatch`.
- Assignments made through a group can't be removed for one user: **Convert assignments** to individual ones first.

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

## CI

`.github/workflows/interop.yml` runs the Keycloak and node-oauth2-server jobs by hand and every Monday:

- the Keycloak image is pinned by digest, and node-oauth2-server by commit;
- actions are pinned by SHA, as in `ci.yml`;
- the only permission is `contents: read`.

`self.test.ts` needs neither and runs in `ci.yml` with the rest of the suite.
