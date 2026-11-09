# Changelog

## [Unreleased]

### Fixed

- **create-from-jti refuses an audit row whose values were cut** (D-069): an audience over 300 characters made a block
  that matched nothing, and the call reported success.
- **The issuer's authorize hook must return scope tokens, and a grant over 4096 characters is refused** (D-069),
  instead of a scope split in two or an empty server error.
- **The registry directory refuses past its bounds** (D-069): over 100 resource servers for an audience, or 1000
  policies for a resource server, is refused rather than decided on part of them.

## [0.7.0] - 2026-11-09

The rule-by-rule ID-JAG checker is public: checkIdJag and checkIssuerMetadata.

### Added

- **The rule-by-rule ID-JAG checker is public:** `checkIdJag` and `checkIssuerMetadata`, with their types
  (`RuleResult`, `RuleLevel`, `RuleOutcome`, `IdJagCheckInput`, `IdJagReport`, `MetadataCheckInput`). Every rule an
  ID-JAG (or an IdP's metadata and keys) is held to, each with pass, fail, warn, info or skip, its level and its
  source in draft -06 or an RFC, all at once rather than the receiver's first refusal. Pure: no network, no clock of
  its own. The public tester (`examples/workers/tester`) reports with it.

## [0.6.1] - 2026-11-09

A security fix: the issuer refuses an ID-JAG request that carries a DPoP proof, instead of answering it with an unbound ID-JAG.

### Security

- **The issuer refuses an ID-JAG request that carries a DPoP proof** (D-066): `invalid_request`, "DPoP-bound ID-JAGs
  are not supported.", audit reason `dpop_unsupported`. Draft -06 section 9.11.1.1 says the IdP MUST validate the proof and bind the ID-JAG to it; the issuer
  doesn't mint bound ID-JAGs, and it used to ignore the header and return an unbound one. A patch release, as
  docs/versioning.md allows for a security fix the draft requires. A SAML assertion exchanged for a refresh token is
  unchanged: oauth-provider checks a DPoP proof there itself. The new reason widens the exported `ReasonCode` type: a
  TypeScript `switch` over every reason that ends in `never` needs a `dpop_unsupported` case. New reasons normally wait
  for a minor release (docs/versioning.md); this one ships in a patch under the exception for security fixes the draft
  requires.
- **The receiver's handling of a DPoP proof is now pinned by a test** (oauth-provider's, after the single-use and
  subject steps): an invalid proof is `invalid_dpop_proof` and spends the ID-JAG; a valid one binds the access token.

### Documentation

- A fresh-eyes review of the README and docs against draft -06: the MCP Enterprise-Managed Authorization link (moved),
  a SAML `sub_id` refusal named with its real code (`sub_id_rejected`), the jwt-bearer and token-exchange rows that
  claimed other grants aren't shadowed, `act` minting marked ⚠️ (outside the draft's rules), `aud_tenant` described as
  single-tenant only, the quick start signing with RS256, the receiver's step order, Okta troubleshooting rows
  (`foreign_resource`, `subject_unavailable`, a missing `scope`), and smaller corrections.
- **The live Okta Cross App Access and xaa.dev checks re-run against the published 0.6.0** (#23):
  `docs/interop.md`. Okta: ID token and refresh token as the subject, replay refused, Okta's own refusals unchanged;
  xaa.dev: OIDC and SAML, 200 at every step.
- **Real MCP clients in `docs/interop.md`:** Claude Code 2.1.319 with Okta (refused, correctly: it asks for no scope,
  so Okta's ID-JAG has none) and with the example IdP (verified with tool calls); VS Code 1.145.0 with Okta re-run with
  tool calls. What a server needs to know about each, including that a refusal for any reason other than a missing scope
  belongs in an MCP tool error, not a 403 `insufficient_scope`, which made both clients sign in again.

### Example

- **A public "test your IdP" receiver** (`examples/workers/tester`, `docs/test-your-idp.md`): someone building an
  ID-JAG issuer signs in with GitHub or GitLab, registers their issuer for 24 hours, redeems ID-JAGs at this package's
  receiver, and reads every rule each one passed or failed, with the draft -06 section, beside the receiver's own
  decision. A registration is pending until an ID-JAG signed with the issuer's own key confirms it, so nobody can hold
  an issuer they don't run. Locked down: one registration per account, each issuer's subjects in their own sandbox,
  rate limits and daily budgets, a blocklist, a stored and a deploy-level kill switch, admin keys that can close but
  not reopen. Privacy: no email, picture, provider token or IP address is stored; what is personal lasts a day at most
  or until "delete my data now"; an abuse record of fingerprints (keyed hashes) lasts 7 days. Not deployed yet.
- **The tester is plug and play:** paste an ID-JAG into "Check an ID-JAG" and the tester redeems it with the
  registration's own client (its secret kept encrypted while the registration lasts); every value to configure has a
  copy button, and all of them come as one JSON template; the client-authentication choice moved under "Advanced".
  Each check on the results page shows its own decision (a redeemed ID-JAG no longer shows its later replay's
  refusal), and HEAD is answered like GET.

## [0.6.0] - 2026-11-04

### Breaking

What to change when you upgrade from 0.5.x:

- **Better Auth 1.7.16 or later** (`>=1.7.16 <1.8.0`, was `>=1.7.10`), for `better-auth` and every
  `@better-auth/*` peer (D-064): 1.7.16 fixed twelve security advisories. On an older 1.7.x, upgrade Better Auth and
  its plugins together first; npm warns about the peer range until you do. The details are under Changed.
- **A client that switches on the OAuth `error` code** sees draft -06's codes (D-059, D-063): `access_denied` for "a
  new token won't help", `invalid_request` at the issuer for a bad subject token, `invalid_target` for an unknown
  audience or resource, HTTP 500 `server_error` when the issuer's own code fails. The details are under Changed.
- **An issuer `authorize` hook** that denies an audience or resource it doesn't serve should now return
  `{ decision: "unknown_audience" }` or `{ decision: "unknown_resource" }` (draft -06 requires `invalid_target`); a
  plain deny still works, as `access_denied`. `AuthorizeResult` gained these two members, so an exhaustive `switch`
  over `decision` in your own code needs the new cases.
- **A request with `authorization_details`** is refused at the issuer (`invalid_request`); it used to be ignored.
- **A receiver ID-JAG whose resource claim names a resource you don't serve** is refused, even beside one you do
  (D-060).

### Security

- **Receiver: the email fallback could link a look-alike address** (D-064). On a database whose collation ignores
  accents (MySQL's and MariaDB's defaults), Better Auth before 1.7.16 answered a lookup for `josé@corp.com`
  with the user `jose@corp.com`
  ([GHSA-2f9c-7xj7-gh55](https://github.com/better-auth/better-auth/security/advisories/GHSA-2f9c-7xj7-gh55)), and
  the email fallback linked the ID-JAG's subject to that user: an ID-JAG for `josé@` was accepted as the verified
  local `jose@`, from then on. It needs a trusted issuer that asserts the look-alike address, in a domain listed for
  the fallback. Now the receiver checks the stored address itself (Unicode-normalized, case ignored) and refuses a
  different one (`unknown_subject`), whatever Better Auth does, and Better Auth 1.7.16 is required. **On 0.5.x,
  upgrading Better Auth to 1.7.16 or later closes it** (0.5.x accepts it). Hosts without the email fallback, or whose
  database tells accents apart (PostgreSQL, SQLite, D1 and MongoDB by default), are not affected.

### Changed

- **Requires Better Auth 1.7.16 or later** (D-064). Better Auth 1.7.16 (2026-11-03) fixed twelve advisories that
  1.7.10 to 1.7.15 have, among them
  [GHSA-4wq4-2ppv-q3hg](https://github.com/better-auth/better-auth/security/advisories/GHSA-4wq4-2ppv-q3hg)
  (critical; the Expo authorization proxy),
  [GHSA-q747-mqgr-4gh7](https://github.com/better-auth/better-auth/security/advisories/GHSA-q747-mqgr-4gh7) (high;
  the phone number plugin) and
  [GHSA-9p5w-h4pr-fcrc](https://github.com/better-auth/better-auth/security/advisories/GHSA-9p5w-h4pr-fcrc) (high;
  the Electron plugin). One of them reaches this package (see Security). No schema change.
- **Implements ID-JAG draft -06** (D-062): `SUPPORTED_DRAFT` is
  `draft-ietf-oauth-identity-assertion-authz-grant-06`, was -04. No claim, token type URN, grant type or metadata name
  changed, so an -04 ID-JAG is a valid -06 one. What changed is below: error codes, the `resource` claim, client
  authentication wording, a new optional metadata field. The README's conformance table cites -06's sections (several
  moved: step-up §9.2 → §9.3, self-issued §9.3 → §9.4, subject trust §9.5 → §9.8, DPoP §9.8 → §9.11, refresh token
  §4.4.3 → §4.4.4) and has rows for -06's new requirements. Single use of each ID-JAG is now ✅: -06 §4.4.4 allows a
  receiver to accept each ID-JAG once by tracking `jti`.
- **README**: plain headings (anchors lost their emoji prefix, so `#-conformance` is now `#conformance`), and the
  feature list says what the error codes tell a caller.
- **Error codes follow ID-JAG draft -06** (D-059). Draft -05/-06 profile which OAuth error code each refusal uses, so a
  client knows whether a new token will help. A client that switches on `error` needs updating; audit reason codes
  are unchanged except where noted.
  - Issuer: a subject token that fails validation (`invalid_subject_token`, `subject_token_expired`) is
    `invalid_request`, was `invalid_grant`. More than one `audience` is `invalid_request` (new reason
    `repeated_audience`), was `invalid_target`. An audience with no resource server in the registry is
    `invalid_target` (new reason `unknown_audience`, was `no_policy`/`invalid_grant`). A policy deny, a block, a
    banned or deleted user and "no policy" are `access_denied`, were `invalid_grant`. A pairwise client is
    `access_denied` (new reason `pairwise_client`, was `invalid_subject_token`). A SAML Assertion already exchanged
    or not yet valid is `invalid_request` (new reasons `subject_token_replay`, `subject_token_not_yet_valid`, were
    `replay`, `not_yet_valid`).
  - Receiver: `unknown_subject`, `subject_rejected` and `banned_user` are `access_denied`, were `invalid_grant`.
    A failure a retry may fix (a concurrent first use, a database error, a `resolveSubject` that throws) has its own
    reason, `subject_unavailable`, and stays `invalid_grant`. A malformed `sub_id` is `invalid_claim`
    (`invalid_grant`, with its description), was `subject_rejected`.
  - Trust failures at the receiver (issuer, signature, `aud`, `client_id`, replay) are still one generic
    `invalid_grant`.
- **Receiver: every resource in the ID-JAG's `resource` claim must be one of ours** (D-060, draft -06 §4.4.1). An
  ID-JAG naming a resource this server doesn't govern, even beside one it does, is refused (`foreign_resource`,
  `invalid_grant`), whichever resource the request picks. It used to be accepted when the request picked ours, and
  refused as `unknown_resource` (`invalid_target`) otherwise. Identifiers are compared exactly.
- **Codes the pre-release review corrected** (D-063). Receiver: a SAML `sub_id` the trust entry can't use (absent
  under `requireSubId`, another format, transient, not mapped) stays `invalid_grant`, as draft -06 §3.2.2 requires
  (new reason `sub_id_rejected`, split from `subject_rejected`, which is now `access_denied`). A
  JIT user whose organization membership can't be added is `subject_unavailable` (`invalid_grant`), was
  `subject_rejected`. Issuer: an `authorize` hook that throws is HTTP 500 `server_error` (new reason
  `internal_error`), was `policy_denied`; so is a SAML verifier that crashes. A SAML Assertion whose user is banned or
  gone (`ACCOUNT_INACTIVE`) is `banned_user` (`access_denied`), as for an ID token, was `invalid_subject_token`.
- **`allowPublicClients`'s startup warning** (both sides) now says the option is outside draft -06 (§4.3.3 at the
  issuer, §4.4 at the receiver), which makes client authentication a MUST. The option, its default (off) and its
  behaviour are unchanged (D-061).

### Added

- **Issuer: `id_jag_signing_alg_values_supported` in the metadata** (draft -06 §7.1, D-061), as `["RS256"]`, when the
  issuer signs ID-JAGs with RS256. Omitted otherwise: if present the list MUST include RS256. Exported as
  `ISSUER_SIGNING_ALG_METADATA_FIELD`. The signing default doesn't change (the `jwt()` plugin's key); set
  `signingAlgorithm: "RS256"` for a receiver that accepts only RS256.
- **Issuer: `authorize` can answer `{ decision: "unknown_audience" }`** (D-059): the caller gets `invalid_target`,
  as draft -06 §4.3.3 requires for an audience the IdP has no trust relationship with. A plain deny is
  `access_denied`.
- **Issuer: `authorize` can answer `{ decision: "unknown_resource" }`** (D-063): `invalid_target`, for a `resource`
  the audience doesn't govern (draft -06 §4.3.3). Type `AuthorizeUnknownResource`.
- **Issuer: `authorization_details` is refused by name** (D-063, `authorization_details_unsupported`,
  `invalid_request`): draft -06 §4.3.3 says the IdP MUST process it, and ignoring it issued the policy's scopes to a
  client that asked for less.
- **Receiver: a startup warning when trust entries for different issuers share an `accountProviderId`** (D-063): a
  `sub` from any of them links to the same local user. Allowed, for an IdP that changed its issuer URL.
- **Docs.** The conformance table marks as ⚠️ what is a deliberate limit: one resource per issuer request, refresh
  tokens not rotated (§9.2), `tenant` enforced only when pinned, `aud_tenant`/`aud_sub` ignored; `act` minting is ✅
  (it was listed as not minted). `docs/security.md`: pin `tenant` for a multi-tenant IdP with email fallback or JIT;
  one `accountProviderId` per issuer. The README quick start answers `unknown_audience`.

## [0.5.4] - 2026-11-01

### Security

- **Receiver: two tenants of one issuer could resolve to the same user** (D-057). Subjects are looked up by
  (`accountProviderId`, `sub`), and the default `accountProviderId` is `id-jag:<issuer>` whatever the tenant. With
  two trust entries for one multi-tenant issuer pinned to different tenants (or one pinned and one not), and no
  `accountProviderId` of their own, an ID-JAG from tenant B whose `sub` equals a tenant A user's was accepted as that
  user. A multi-tenant IdP's `sub` is unique only within its tenant. Now such static entries are a startup error,
  and such `idJagTrustedIssuer` rows are refused (`untrusted_issuer`, with a warning) until each tenant has its own
  `ssoProviderId`. Only hosts with several tenant entries for one issuer are affected; a single entry per issuer
  behaves as before.

## [0.5.3] - 2026-10-30

### Fixed

- **Issuer: a subject token's `acr` or `amr` the ID-JAG can't carry is refused, never a 500** (D-056). An ID token
  whose `acr` or an `amr` entry has a control character, or a SAML Assertion whose class is empty or has one, passed
  the subject-token check and then failed the ID-JAG's own claim check: HTTP 500, no ID-JAG issued. Now it's
  `invalid_subject_token`. The ID-token case needs Better Auth 1.8's `authenticationContext` (1.7 always says
  `acr: "0"`); the SAML case needs a SAML IdP configured with such a class.

### Documentation

- **How the person signed in, on Better Auth 1.8** (D-056): with oauth-provider's `authenticationContext`, an
  ID-JAG from an ID token carries exactly the `acr`/`amr` your resolver returned, so it can claim MFA. A refresh-token
  subject still carries neither. `docs/security.md` and the README's policy section.

## [0.5.2] - 2026-10-27

### Changed

- **Requires `zod` 4.6.6 or later** (`^4.6.6`, was `^4.6.5`, D-053).
  [GHSA-mrhx-c7xc-m3w5](https://github.com/advisories/GHSA-mrhx-c7xc-m3w5) (high) covers zod 4.6.5 and earlier:
  a large array can exhaust memory while zod collects its validation issues. This package caps the size of outside
  input before zod parses it, so it isn't exposed itself, but the old range let a host install the affected zod.
  A host whose lockfile still has zod 4.6.5 gets a second copy until it runs `pnpm update zod` (or the npm or yarn
  equivalent); Better Auth accepts 4.6.6 and later.

## [0.5.1] - 2026-10-23

### Changed

- **`zod` and `jose` are ranges now** (`^4.6.5` and `^6.2.12`, were exact `4.6.7` and `6.2.12`), so a host whose
  tree has an older zod or jose within those ranges shares one copy instead of installing a second (D-050).

## [0.5.0] - 2026-10-20

### Changed

- **Requires Better Auth 1.7.10 or later** (`>=1.7.10 <1.8.0`, was `>=1.7.5`), for `better-auth` and every
  `@better-auth/*` peer (D-044). Better Auth 1.7.7 fixed account-takeover advisories that 1.7.5 and 1.7.6 have:
  [GHSA-965c-763c-88jm](https://github.com/better-auth/better-auth/security/advisories/GHSA-965c-763c-88jm)
  (critical; the Magic Link plugin with social or Generic OAuth sign-in) and
  [GHSA-r4xp-prcw-77qf](https://github.com/better-auth/better-auth/security/advisories/GHSA-r4xp-prcw-77qf)
  (high; the OAuth Proxy plugin). This package uses neither plugin, but the old floor let a host install an affected
  Better Auth next to it. **On an older 1.7.x, upgrade Better Auth and its plugins together first**; npm warns about
  the peer range until you do. No code or schema change in this package.

### Fixed

- **Issuer: a malformed `resource` is a 400, never a 500** (D-045). A `resource` longer than 2048 characters or
  with a control character passed Better Auth's own check (1.7.x) and reached the ID-JAG builder, whose claim check
  threw: HTTP 500 (no ID-JAG was issued). On Better Auth 1.8 an empty `resource=` did the same. The issuer now checks
  `resource` itself (an absolute URI without a fragment, at most 2048 characters) and refuses anything else with
  `invalid_target` and the new public reason `invalid_resource`.

### Added

- **Issuer: another token exchange beside ours** (D-046). Better Auth 1.8's `oauthTokenExchange()` registers the same
  token-exchange grant as `idJagIssuer()`, and oauth-provider allows one handler per grant type, so listing both
  stops startup. New option `idJagIssuer({ otherTokenExchange })`: requests this plugin doesn't serve (a
  `requested_token_type` other than an ID-JAG, or a refresh token with SAML path (b)) go to that handler instead of
  being refused. New export `tokenExchangeFrom(plugin)` takes the handler out of a plugin like
  `oauthTokenExchange()`, and refuses one with parts it would lose. Listing both plugins now fails with a message
  saying this. Nothing changes without the option. Tested against `oauthTokenExchange()` on Better Auth
  1.8.0-beta.1 (the CI's 1.8 row); this release's peer range is still 1.7.
- **Issuer: step-up** (draft -04 §9.2, D-043). The `authorize` hook can deny with
  `stepUp: { maxAge?, acrValues?, description?, uri? }`. The client then gets `insufficient_user_authentication`
  with `max_age`, `acr_values`, `error_description` and `error_uri` (RFC 9470's parameters), not the generic
  `invalid_grant`, so it can send the person back to sign in again, for example to a "confirm it's you" page. Off
  unless the hook asks; a deny without it is unchanged. Audited as the new reason `step_up_required`. A malformed
  `stepUp` is a malformed verdict (`policy_denied`).

## [0.4.0] - 2026-10-18

### Added

- **Issuer: `act` for agents** (D-036). The `authorize` hook can return `claims: { act: true }` (or
  `{ act: { sub_profile } }`) to name the requesting client as the actor in the ID-JAG, RFC 8693 `act` with `sub` =
  its client id at the IdP, as Okta does for AI agents. Off unless the hook asks; the actor is always the requesting
  client, never one the policy names. Receivers that require `act` (some do) now accept our ID-JAGs, and ours
  carries it into the access token. `sub_profile` is space-separated names of letters, digits, punctuation and
  symbols (D-040); anything else (blank, padded or doubled spaces, invisible, combining or blank-rendering characters)
  is a malformed verdict (`policy_denied`). On 0.3.0 a hook returning `claims: { act: … }` got no error and no `act`
  (the claim was dropped silently, and the agent's ID-JAGs looked like an app's): upgrade before relying on it.
- **Receiver: ID-JAGs that name their key by certificate thumbprint** (D-042). A header without `kid` is accepted
  when it carries `x5t` or `x5t#S256`; the key is the issuer's with that thumbprint (published, or worked out from its
  `x5c`). PingFederate never sends `kid`, so every PingFederate ID-JAG was refused (`missing_kid`); verified live with
  13.1.3 (docs/interop.md). `IdJagHeader.kid` is now optional.
- **Audit: `act`** (D-040). `id-jag.issued` and `id-jag.accepted` events (and audit rows' `details`) carry the
  ID-JAG's `act` as `{ sub, sub_profile? }`: the current actor only, log-safe. New exported type `ActSummary`.

### Fixed

- **Receiver: JWKS keys with `key_ops`, and no 500 on a key WebCrypto refuses** (D-041). A key published for
  `["wrapKey", "encrypt", "verify"]` (Oracle OCI IAM's) failed every ID-JAG it signed, as a 500: WebCrypto won't import
  an RSA or EC signing key for those usages, and the error's numeric `code` crashed the log sanitiser. A key whose
  `key_ops` includes `verify` is now used for verify only; one without `verify` is skipped; any key WebCrypto still
  refuses is `jwks_unavailable`.

- **Audit: strings are cut in code points, and lone surrogates repaired** (D-040). An event string over the cap
  (300; a refusal's detail, a long client id) could end in half a surrogate pair; a lone surrogate sent as a JSON
  escape reached handlers and the audit table as is. Both are now valid UTF-16, cut whole, a lone surrogate as U+FFFD.

- **Issuer: no assumption about Better Auth's default signing algorithm** (#19). The startup check took an unset
  `keyPairConfig.alg` to mean EdDSA, so `signingAlgorithm: "RS256"` would be refused on a Better Auth whose default is
  RS256 (better-auth#9935); and verifying the host's own ID tokens assumed EdDSA for a stored key without `alg`. Now
  an unset `keyPairConfig.alg` means Better Auth's own default, read from Better Auth (its `DEFAULT_JWT_ALGORITHM`
  where exported, else 1.7's EdDSA); each ID-JAG's actual algorithm is also checked when it is signed (not
  RS256/ES256/EdDSA: none is issued, a 500 with the algorithm in the server log); and a stored key's
  algorithm comes from the key (its `alg`, else the configured one when it fits the key type, else the key type).
- **README: the Okta trust-entry examples named `/oauth2/default`** (#21). Cross App Access ID-JAGs come from the
  org authorization server (`iss` `https://<org>.okta.com`, keys at `/oauth2/v1/keys`), so the examples refused every
  Okta ID-JAG (`untrusted_issuer`). Also: the org's `/.well-known/oauth-authorization-server` has no `jwks_uri`, so
  `discoveryUri` must be its `/.well-known/openid-configuration`.

### Example

- **The example MCP server lists the Enterprise-Managed Authorization extension** in its `initialize` reply
  (`capabilities.extensions["io.modelcontextprotocol/enterprise-managed-authorization"]`); MCPJam now reports it as
  advertised. The receiver already met the extension's discovery rule (its metadata's ID-JAG grant profile).
- **The example IdP tells AI agents from apps** (D-037): `--setup` registers both, the IdP names the agent in
  `act` (from client metadata `agent: true`), and the demo MCP server keeps agents read-only. `client.mjs
  --client=app` runs as the app. Re-run `--setup` once.
- **The example MCP server works with VS Code** (#25): `/setup` takes `"tokenEndpointAuthMethod":
  "client_secret_post"` (VS Code and xaa.dev's tester send the secret in the body), its clients carry no redirect URI
  (they only redeem ID-JAGs), and `GET /mcp` answers 405 instead of 200 (no server-to-client stream; VS Code polled
  it). The example IdP's `/setup` now also works on `http://localhost`. README: VS Code setup, running locally.

### Documentation

- **`docs/okta.md`: the receiver behind Okta Cross App Access** (#22): the trust entry (the org issuer, its keys),
  finding users, the Okta console values, what Okta's ID-JAG carries, cutoffs, and what each refusal means, from
  the live runs and the code. The console steps moved there from `docs/interop.md`.
- **The receiver's access token doesn't carry `auth_time` either** (#26), only `acr`/`amr` were named: README and
  `docs/security.md`. A test pins that none of the three reaches the access token or its introspection, so an
  upstream change that lets `auth_time` through (better-auth#11267) is noticed (the grant passes no `acr`/`amr`); `authTime` at `grant.ts` stays, with a comment that it has no effect yet.
- **How the person signed in** (`docs/security.md`, README; D-033): an ID-JAG's `auth_time`, `acr` and `amr` are
  copied from the subject token, never derived. From an ID token that is always `acr: "0"` and no `amr` (oauth-provider
  fixes them); only a SAML Assertion's class can claim MFA, so the SAML IdP must state only what the session did. A
  rule that requires MFA treats a missing value as not proven: at the receiver, in `resolveSubject`. Tests pin each
  of these.

### Interoperability

- **Two more ID-JAG implementations against the receiver**, in the weekly Interop workflow (`docs/interop.md`;
  D-035): MCPJam's Cross App Access debugger (`@mcpjam/sdk` 9.3.0), the whole flow to an MCP `initialize` and each of
  its ten attacks refused with the matching reason, for an ID token and for a SAML `sub_id`
  (`test/interop/mcpjam.test.ts`); and identity-provider.net, live, an independent issuer: ID token and refresh token
  subjects accepted, replay, another client id and an ML-DSA-signed ID-JAG refused (`test/interop/zipidp.test.ts`).
  Tests only; no runtime change.
- **A real MCP client: VS Code 1.141.0 with Okta** (#25), live, through to `initialize` and `tools/list` on the
  example MCP server (`docs/interop.md`): what a server must allow for it (`client_secret_post`, every advertised
  scope, the loopback redirect URI at the IdP).

## [0.3.0] - 2026-10-10

A smaller, explicit public API (breaking: internals no longer exported), the SCIM option types, and the layered-permissions example.

### Breaking

- **The public API is now an explicit list** (`src/index.ts`, `docs/versioning.md`; D-031): 52 runtime exports
  instead of 106. Removed, as internals nothing documented uses: `emit`, `auditRow`, `sweepAudit`, `refuse`,
  `logSafe`, `toApiError`, `providerErrorCode`, `providerRefusalReason`, `publicDescription`, `IdJagRefusal`, `jtiKey`,
  `recordJti`, `hasJti`, `jtiExpiresAt`, `sweepJtis`, `warnIfReplayUnsafe`, `JTI_RETENTION_MARGIN_SECONDS`,
  `checkTimes`, `newJti`, `isIdJagTyp`, `idJagClaimsSchema`, `lifetimeOption`, `skewOption`, `MAX_TOKEN_LENGTH`,
  `MAX_ACT_DEPTH`, `UNSUPPORTED_CLAIMS`, `parseSamlNameIdSubId`, `samlNameIdSubIdSchema`, `TRANSIENT_NAMEID_FORMAT`,
  `decide`, `checkBlocks`, `checkBlocksWithoutAudience`, `RegistryDirectory`, `normalizeAudience`,
  `verifyOwnIdToken`, `verifyOwnRefreshToken`, `verifyOwnSamlAssertion`, `decodeSaml2SubjectToken`,
  `MAX_SAML2_TOKEN_LENGTH`, `getSamlIdpExchange`, `assertionExchangeErrorCode`, `ASSERTION_EXCHANGE_ERROR_CODES`,
  `SAML_IDP_EXCHANGE_KEY`, `resolveSubject` (the function; the option is unchanged), `subjectKey`,
  `findTrustedIssuer`, `openIdConfigurationUrl`, `registeredResources`, `STRIPPED_SCOPES`, `addJitMembership`,
  `organizationRoles`, `unknownRoles`, `BUILT_IN_ORGANIZATION_ROLES`, `JwksCache`, and the internal types that went
  with them. If you used one of these, open an issue: adding an export back is not a breaking change.

### Added

- The SCIM option types `ScimTrustInput` and `AcquireActiveScimUserLink` are exported (they were missing in 0.2).

## [0.2.1] - 2026-10-08

Fixes the SCIM step from 0.2.0: parallel redemptions for one user are no longer refused.

- **Fix (SCIM, new in 0.2.0): parallel redemptions for one user were refused.** `acquireActiveSCIMUserLink` bumps the
  SCIM subject's revision on every lookup, so concurrent lookups of the same user conflict with each other, not only
  with a lifecycle change; on Postgres, 8 parallel redemptions for one active user got 3 tokens and 5
  `invalid_grant`. A conflict is now retried with exponential backoff and full jitter for up to 5 seconds (at most 40
  attempts), then refused, as before, and concurrent redemptions for the same user in one process share a single
  lookup (D-030). Found by the better-auth-scim-provisioning maintainer on Cloudflare with Postgres through
  Hyperdrive (D-029).
- Docs: on Cloudflare, create the auth database's Hyperdrive config with caching disabled.

## [0.2.0] - 2026-10-08

SCIM-provisioned users at the receiver: deprovisioning at the IdP stops the agent at your app too.

- Receiver: **SCIM-provisioned users** (D-027). A trusted issuer with `scim: { connectionId, required? }` resolves the
  ID-JAG's `sub` as the SCIM `externalId` through `@better-auth/scim`'s `acquireActiveSCIMUserLink` (passed in as
  `idJagGrant({ scim: { acquireActiveSCIMUserLink } })`): only an active provisioned user is found, and by default a
  subject with none is refused, so deprovisioning at the IdP stops the agent here too. The `idJagTrustedIssuer`
  table gains `scimConnectionId` and `scimRequired`. Needs a database with transactions (not D1). The
  `id-jag.accepted` event gains `resolvedBy`.
- **Migration, only with `trustedIssuerTable: true`:** the `idJagTrustedIssuer` table has two new nullable columns
  (`scimConnectionId`, `scimRequired`). Run `npx auth migrate` (or `npx auth generate` for Drizzle and Prisma).

## [0.1.0] - 2026-10-08

The first release: Identity Assertion JWT Authorization Grants for Better Auth, an issuer (experimental) and a receiver, draft -04.

- `idJagIssuer()`: issue ID-JAGs from a Better Auth IdP (RFC 8693 token exchange, ID-token subject tokens, policy hook
  and registry with an admin API, `better-auth-id-jag/client`).
- `idJagGrant()`: accept ID-JAGs at an MCP server's authorization server (RFC 7523 jwt-bearer, trusted issuers from
  config, `@better-auth/sso` or a table, audience-restricted access tokens).
- The shared core: ID-JAG parse/verify/build, errors, jti replay table, audit events. Draft -04.
- Issuer: refresh tokens this provider issued are accepted as subject tokens; **blocks** (a user, a client, an
  audience, or any combination, optionally until a date) stop new ID-JAGs and replace "revoke", which never revoked
  anything; `iss` is always the issuer the metadata publishes. The issuer is **experimental**.
- Receiver: `act` (who acts for the user, as Okta sends for an AI agent) is accepted and carried into the access
  token; an ID-JAG with `cnf` (key-bound) or `authorization_details` is refused until those are supported. Just-in-time
  provisioning adds the user to the trust entry's organization. New option `requireResourceClaim`. Single use stays,
  deliberately (oauth-wg issue #130).
- Both: the OAuth provider's own client-authentication refusals reach the audit events; a startup warning on database
  adapters that don't enforce unique keys.
- Issuer, experimental: **SAML assertions** from better-auth-saml-idp ≥ 1.2.0 as subject tokens, directly to an
  ID-JAG, or to a refresh token first (draft -04 §4.5, MCP's SAML path; `saml: { subjectTokens, refreshTokens }`,
  `scope_required`, the `id-jag.refresh-issued` event). `maxIdTokenAgeSeconds` (an hour by default) and the `sid`
  session check stop old sign-ins; `blocks: { canManage }`; blocking from a `jti` falls back to the audit log.
- Receiver: users resolved by SAML NameID (`sub_id`, `samlSubjects`, `requireSubId`); the email fallback needs a
  verified local email and respects `account.accountLinking`; concurrent first use converges on one user and link
  instead of a 500; `jwks.maxStaleSeconds`; `jitRole`.
- Both: options accept `undefined` for every optional field (strict TypeScript hosts); one `events` object can serve
  both plugins. Tested on Postgres, MySQL, MongoDB, Drizzle and Prisma.
- Receiver: while an issuer's key set can't be fetched, its cached keys answer every request for up to
  `jwks.maxStaleSeconds` past their TTL, including the one whose refetch failed (logged as a warning). Core:
  `AUDIT_EVENT_TYPES`, every audit event type.
- Verified live against Okta Cross App Access (including the refresh-token subject and Okta's connection, assignment
  and deactivation controls) and Okta's xaa.dev testers (OIDC and SAML), and against Keycloak 26.8.0 and
  node-oauth2-server in the interop suite.
- Published from CI with npm provenance and a CycloneDX SBOM; every install in CI runs through Socket Firewall.

