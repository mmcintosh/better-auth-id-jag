# Test your IdP

A public receiver for people building an **ID-JAG issuer** (an IdP that implements
[draft-ietf-oauth-identity-assertion-authz-grant-06](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/06/)).
Register your issuer, redeem an ID-JAG, and see every rule it passed or failed, each with the draft section it comes
from, next to what a real receiver decided. The receiver is this package's `idJagGrant()`, unchanged; the code is
[`examples/workers/tester`](../examples/workers/tester).

It is a testing aid: the rules as this package reads draft -06, with the code to show for each. It is not a
conformance or certification test, and its results are visible only to the account that registered.

**It runs at <https://idjag-tester.infowall.net>.**

## What it checks

Other tools cover other parts:
- [xaa.dev](https://xaa.dev) and [xaa.rocks](https://xaa.rocks) test clients and resource apps against their IdPs.
- [motd.xaa.rocks](https://motd.xaa.rocks) accepts any issuer's ID-JAG but doesn't say what's wrong with one.
- [id-jag-validate](https://github.com/peteretelej/id-jag-validate) checks a token you paste, offline, rule by rule.

This one is a live receiver for your IdP. It answers two questions:
- Does a real receiver redeem your ID-JAG?
- If not, which rules does it break? You see all of them, not only the first.

| Where | Rules |
|---|---|
| Your metadata, at registration | Found at RFC 8414's location (or OpenID Connect Discovery's); `issuer` exactly the one you entered; `jwks_uri` https; `identity_chaining_requested_token_types_supported` lists the ID-JAG type; `id_jag_signing_alg_values_supported`, if present, includes RS256 (draft section 7.1) |
| Your JWKS, at registration | Keys present; no private or symmetric key material; at least one RSA, EC or OKP key; each with a `kid` |
| Each ID-JAG | `typ` `oauth-id-jag+jwt` (any case, `application/` optional); an accepted `alg` (RS256, ES256, EdDSA; never `none` or HS*); the key named by `kid` (or `x5t`); no `crit`; the signature, with your published keys, chosen as the receiver chooses them; `iss`, `sub`, `aud` (this receiver's issuer, a string or a one-element array), `client_id` (the client that authenticated), `jti`, `exp` and `iat` in whole seconds, the lifetime; `resource`, if present, names this receiver's MCP server; `scope` present and includes `read`; no `cnf` or `authorization_details` (not supported here); the optional claims' shapes (`act`, `sub_id`, `tenant`, `auth_time`, `acr`, `amr`); `email` or `aud_sub` (RECOMMENDED); and the receiver's own parser, as a last check |
| The redemption | The receiver's own decision: accepted, or refused with its reason (for example `replay`, `foreign_resource`, `no_scope`) |

Each result is **pass**, **fail**, **warn** (allowed, but not what the draft recommends), or **info**. Rules marked
POLICY are this receiver's own choices, which the draft allows, for example that an ID-JAG without `scope` grants
nothing (section 4.3.3: the IdP includes "the granted values, if any").

### The rules

Every rule below is in the package's checker, [`src/core/check.ts`](../src/core/check.ts) (`checkIdJag` and
`checkIssuerMetadata`; `jwks.fetch` is in the tester's [`index.ts`](../examples/workers/tester/src/index.ts)),
written from the text of draft -06 and the RFCs it relies on. The level is the source's own word (MUST, SHOULD,
RECOMMENDED, OPTIONAL), or POLICY for this receiver's choice. A rule whose level differs by case (a claim that is
present but malformed, say) lists both.

**At registration: your metadata and keys.** A failed rule marked *blocks* stops the registration.

| Rule | Level | Source | What it checks |
|---|---|---|---|
| `metadata.location` | SHOULD | draft -06 section 7.1; RFC 8414 section 3 | Your metadata is at RFC 8414's location (OpenID Connect Discovery's is accepted as a fallback, with a warning) |
| `metadata.issuer` | MUST | RFC 8414 section 3.3 | The metadata's `issuer` is exactly the issuer you entered (blocks) |
| `metadata.jwks_uri` | POLICY | draft -06 section 7.1 | `jwks_uri` is an https URL (blocks) |
| `metadata.token_types` | SHOULD | draft -06 section 7.1 | `identity_chaining_requested_token_types_supported` lists the ID-JAG token type |
| `metadata.signing_algs` | MUST, if present | draft -06 section 7.1 | `id_jag_signing_alg_values_supported`, if present, includes RS256 |
| `jwks.fetch` | MUST | draft -06 section 4.4.1; RFC 7521 section 5.2 | Your JWKS can be fetched: a receiver verifies the ID-JAG's signature with these keys (blocks) |
| `jwks.keys` | MUST | RFC 7517 section 5 | It is a JSON object with a non-empty `keys` array (blocks) |
| `jwks.no_private` | MUST | RFC 7517 section 9.2 | No private or symmetric key material is published (blocks) |
| `jwks.usable` | MUST | draft -06 section 3 | At least one RSA, EC or OKP key (blocks) |
| `jwks.kid` | OPTIONAL | RFC 7517 section 4.5 | Every key has a `kid` |

**For each ID-JAG.**

| Rule | Level | Source | What it checks |
|---|---|---|---|
| `jwt.structure` | MUST | RFC 7519 section 7.2 | A compact JWT with a JSON header and claims; nothing else is checked without it |
| `header.typ` | MUST | draft -06 sections 4.4.1, 3.1; RFC 7515 section 4.1.9 | `typ` is `oauth-id-jag+jwt` (any case, `application/` optional) |
| `header.alg` | POLICY | draft -06 sections 3, 4.4.1 | An algorithm this receiver accepts: RS256, ES256, EdDSA (never `none` or HS*); notes that RS256 is the one every IdP and receiver must implement |
| `header.kid` | POLICY; MUST for a thumbprint's form | RFC 7515 sections 4.1.4, 4.1.7, 4.1.8 | The header names the key: a `kid`, or else an `x5t` / `x5t#S256` of the right form |
| `header.crit` | MUST | RFC 7515 section 4.1.11 | No `crit` (this receiver understands no critical parameters) |
| `signature` | MUST | draft -06 section 4.4.1; RFC 7521 section 5.2 | The signature verifies with a key from your JWKS, chosen as the receiver chooses it (signing keys only, by `kid`, else by thumbprint) |
| `claim.iss` | MUST | draft -06 sections 3.1, 4.4.1 | `iss` is exactly your registered issuer |
| `claim.sub` | MUST | draft -06 section 3.1 | `sub` is a non-empty string |
| `claim.aud` | MUST | draft -06 section 4.4.1 | `aud` is this receiver's issuer identifier: a string, or an array of exactly one |
| `claim.client_id` | MUST | draft -06 sections 3.1, 4.4.1 | `client_id` is present and is the client that authenticated |
| `claim.jti` | MUST | draft -06 section 3.1 | `jti` is present (each ID-JAG works once here) |
| `claim.exp` | MUST; POLICY for whole seconds | draft -06 section 3.1; RFC 7519 sections 2, 4.1.4 | `exp` is a NumericDate in whole seconds, not passed (60 s of clock skew) |
| `claim.iat` | MUST; POLICY for whole seconds | draft -06 section 3.1; RFC 7519 sections 2, 4.1.6 | `iat` is a NumericDate in whole seconds, not in the future |
| `claim.lifetime` | POLICY | draft -06 section 4.3.4 | `exp` minus `iat` is more than 0 and at most 900 s (the draft's example is 300) |
| `claim.nbf` | OPTIONAL | RFC 7519 section 4.1.5 | `nbf`, if present, has passed |
| `claim.resource` | OPTIONAL; MUST if present | draft -06 sections 3.1, 4.4.1 | If present: a string or a non-empty array of unique strings, each a resource this receiver governs |
| `claim.scope` | POLICY; MUST for its form | draft -06 sections 3.1, 4.3.3, 4.4.1; RFC 6749 section 3.3 | `scope` is one space-separated string and includes something this receiver grants (`read`); absent means nothing was granted |
| `claim.authorization_details` | POLICY | draft -06 section 4.4.1 | Not present: this receiver refuses Rich Authorization Requests for now |
| `claim.tenant` | OPTIONAL | draft -06 sections 3.1, 6.1 | `tenant`, if present, is a string (the tester registers single-tenant issuers) |
| `claim.act` | OPTIONAL | draft -06 section 9.10; RFC 8693 section 4.1 | `act`, if present, is an object with a `sub` |
| `claim.sub_id` | OPTIONAL | draft -06 section 3.2; RFC 9493 | `sub_id`, if present, is an object with a `format` (the tester resolves users by `sub` only) |
| `claim.cnf` | POLICY | draft -06 section 9.11.1.2 | Not present: this receiver doesn't take sender-constrained ID-JAGs |
| `claim.email_or_aud_sub` | RECOMMENDED | draft -06 section 3.1 | `email` or `aud_sub` is present, so a receiver can find or create the user |
| `claim.auth_time`, `claim.acr`, `claim.amr` | OPTIONAL | draft -06 section 3.1; OpenID Connect Core | If present: a NumericDate, a string, an array of strings |
| `receiver.parse` | MUST | this receiver | The receiver's own parser (`parseIdJag`, `src/core/jwt.ts`) accepts the header and claims, so the report can't say "every rule passed" on a token the receiver refuses for its shape |

Next to the rules, each report shows the receiver's own decision: the published `idJagGrant()` (`src/receiver/grant.ts`),
which redeemed or refused the ID-JAG, with its reason.

### What it doesn't check

Only what a receiver can see: the ID-JAG and your metadata and keys. Draft -06 also has rules for how your IdP
**issues** ID-JAGs (section 4.3.3): authenticating the requesting client, validating the subject token, the
`audience` and `resource` it accepts, its error codes. The tester never sees that exchange, so it can't check any of
it. Nor does the list above claim to cover every MUST in the draft.

## How to use it

1. **Sign in with GitHub or GitLab** (gitlab.com). The account must be at least 30 days old.
2. **Register your issuer.** Enter your issuer identifier exactly as your ID-JAGs' `iss`. The tester reads your
   metadata and JWKS and shows the results. You get a client here, valid until your sign-in ends (24 hours after you
   signed in). The registration starts **pending**.
3. **Have your IdP mint an ID-JAG** with the values the registration page shows, each with a copy button (or all at
   once, as JSON): `aud` this receiver's issuer (`<tester>/api/auth`), `client_id` the client id you got here (not
   your IdP's own), `scope` `read`, and optionally `resource` `<tester>/mcp`, with the header `typ`
   `oauth-id-jag+jwt`.
4. **Paste it into "Check an ID-JAG"** and press Check. The tester redeems it with your client here, through the same
   token endpoint anyone would use, and adds the report to your results page.

   The first ID-JAG signed with a key from your issuer's published JWKS, with your issuer as `iss` and this client as
   `client_id`, **confirms** the registration: proof that you run the issuer. It is then redeemed as usual. Until
   then, others may register the same issuer too, and the first to confirm holds it while the registration lasts.
   So nobody can hold an issuer they don't run, unless the issuer signs ID-JAGs for anyone who asks (an open
   playground IdP); then anyone can confirm it.
5. **Read the report** at `<tester>/results`: every rule, and the receiver's own decision.

**From your own code instead:** the registration page also shows the client secret, once, and how to redeem with it:

```sh
curl <tester>/api/auth/oauth2/token -u <client_id>:<client_secret> \
  -d grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer \
  -d assertion=<your ID-JAG>
```

Then you can call the MCP server at `<tester>/mcp` with the access token: `whoami` shows what the receiver made of
your ID-JAG, `checks` the latest reports. If your code sends the secret in the request body rather than HTTP Basic,
choose `client_secret_post` under "Advanced" when you register.

Your users never sign in here. Each subject your ID-JAGs name becomes a sandbox user of your registration only. No
email from your ID-JAGs is stored.

## Limits

- **Registrations:**
  - one active at a time per account, two a day;
  - three a day from one address;
  - three a day across everyone.
- **One confirmed registration per issuer at a time** (see step 4).
- **Redemptions:**
  - 10 a minute per registration from one address, and 50 a day per registration;
  - 300 a day across everyone, after which redemptions stop until 00:00 UTC.

  Only requests your client authenticated count, so nobody else can use up your allowance.
- **Requests:** 30 a minute from one address, to any page.
- **The tester closes itself** after a run of server errors, until an operator reopens it. An operator watches it
  and can close it, end a registration, or block an account or network that abuses it.

## Privacy

The tester keeps what it needs to show you your results and to keep it open without being abused, in three layers.

**About you, for 24 hours at most:**
- your public login and when your account was created (for the 30-day rule);
- your provider's account id;
- your sign-in, which lasts 24 hours. A registration ends when your sign-in does, and everything about you is deleted
  within minutes after both have ended.

**Never stored:**
- your email (a made-up address that receives no mail stands in);
- your picture;
- your provider's tokens;
- your IP address;
- your browser's user agent.

GitHub is asked only for `read:user`, GitLab for `read_user`.

**About your IdP, while the registration lasts:**
- its metadata report, its keys, and the client here, including the client secret, encrypted (AES-GCM, under a key
  derived from the deployment's own secret) so that "Check an ID-JAG" can redeem with it
  (`examples/workers/tester/src/seal.ts`);
- the sandbox users;
- each redemption's report and the receiver's logs of it.

**An abuse record, for 7 days, that isn't about you as a person.** It holds fingerprints (keyed hashes) of the
account, the address and its network: the same account always gives the same fingerprint, but a fingerprint can't
be turned back into the account or the address. With them it keeps:
- the account's age as a range;
- the IdP's host name;
- the counts of redemptions and refusals;
- how the registration ended.

The record also holds the account's and network's fingerprints under the blocklist's key (below), so that someone
caught abusing the tester can be blocked during those 7 days, even after their registration and their own data are
gone.

The weekly fingerprint key is deleted two weeks after it was made; the blocklist key, once nothing is blocked and
no abuse record uses it. Until then the fingerprints count as pseudonymous data: whoever holds the key could check
whether a given account made one. They are kept to enforce the daily limits and to spot abuse. Once a key is
deleted, and the restore history below has dropped it too (30 days), nobody, the operator included, can tell whose
its fingerprints were.

**A blocklist, for 30 days, only for accounts and networks caught abusing the tester.** It holds fingerprints under
the blocklist key.

**Delete my data now:** a button on your results page, which works even while the tester is closed. It ends your
registration and deletes everything about you and your IdP at once, your sign-in included. Only the abuse record
remains, for the rest of its 7 days: it holds no login, email or address, and the limits and the blocklist must
still work.

**Cloudflare** (its pages as read on 2026-11-07):
- **Request logs.** Cloudflare's [Workers pricing page](https://developers.cloudflare.com/workers/platform/pricing/)
  gives Workers Logs a retention of "7 Days" on the Workers Paid plan. The tester writes only its own log lines
  there: registration ids, IdP host names, and when it closes or ends a registration; never logins or addresses
  (`console.log` calls in `examples/workers/tester/src/index.ts`). Cloudflare's automatic per-request logs are
  turned off (`"invocation_logs": false` in its `wrangler.jsonc`).
- **Database restore history.** Cloudflare's [D1 Time Travel page](https://developers.cloudflare.com/d1/reference/time-travel/)
  says: "You do not need to enable Time Travel. It is always on." and "You can restore a database back to a point
  in time up to 30 days in the past (Workers Paid plan) or 7 days (Workers Free plan)." The page offers no way to
  turn it off or shorten it. So anything deleted from the tester's database can still be restored from that history
  for up to 30 days, by the operator only. The tester never stores an email, a provider token or an address, so that
  history holds nothing more about you than this page lists.

Nothing is shared or used for anything else. The site shows your results only to you. The services involved see
what they always see: GitHub or GitLab, your sign-in; Cloudflare, your request and its bot check (Turnstile).

Test data only: use test users, never real ones. There is no uptime promise.

## Running your own

The tester is an example Worker: [`examples/workers/tester`](../examples/workers/tester). It needs:
- a D1 database;
- a GitHub OAuth app (scope `read:user`) and, optionally, a GitLab one (scope `read_user`);
- a Turnstile widget;
- the three rate-limit bindings in its `wrangler.jsonc`;
- these secrets: `BETTER_AUTH_SECRET`, `GITHUB_CLIENT_SECRET`, `GITLAB_CLIENT_SECRET` (with GitLab),
  `TURNSTILE_SECRET_KEY`, and `ADMIN_STATS_KEY`, `ADMIN_CLOSE_KEY`, `ADMIN_OPEN_KEY`.

Each admin key must be at least 32 characters:
- **`ADMIN_STATS_KEY`** reads `/admin/stats`: counts, registration states and the abuse record (fingerprints, no
  personal data).
- **`ADMIN_CLOSE_KEY`** can close the tester (`POST /admin/close`), end one registration (`POST /admin/revoke`), or
  block a registration's account and/or network for 30 days and end it (`POST /admin/block`, by registration id,
  for 7 days after the registration was made). It can never reopen anything.
- **`ADMIN_OPEN_KEY`** reopens it (`POST /admin/open`).

Setting `TESTER_ENABLED` to anything but `true`, or `POST /admin/close`, closes everything except the home page,
`/admin`, signing out and "Delete my data now". Set `PUBLIC_ORIGIN` to the tester's address so that no other host name (such as its workers.dev one) is
served. Host the tester on its own domain, not a subdomain of a site with sign-ins of its own: its pages show what
testers' IdPs send, and browsers treat subdomains of one domain as the same site for cookies.
