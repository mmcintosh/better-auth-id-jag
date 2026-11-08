# Test your IdP

A public receiver for people building an **ID-JAG issuer** (an IdP that implements
[draft-ietf-oauth-identity-assertion-authz-grant-06](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/06/)).
Register your issuer, redeem an ID-JAG, and see every rule it passed or failed, each with the draft section it comes
from, next to what a real receiver decided. The receiver is this package's `idJagGrant()`, unchanged; the code is
[`examples/workers/tester`](../examples/workers/tester).

It is a testing aid: the rules as this package reads draft -06, with the code to show for each. It is not a
conformance or certification test, and its results are visible only to the account that registered.

> **Status:** built, not yet deployed. This page gives its address once it is.

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

## How to use it

1. **Sign in with GitHub or GitLab** (gitlab.com). The account must be at least 30 days old.
2. **Register your issuer.** Enter your issuer identifier exactly as your ID-JAGs' `iss`, and how your client will
   authenticate (`client_secret_basic` or `client_secret_post`). The tester reads your metadata and JWKS and shows the
   results. You get a client id and a secret, shown once, valid for 24 hours. The registration starts **pending**.
3. **Mint an ID-JAG** with the values the registration page shows: `aud` this receiver's issuer (`<tester>/api/auth`),
   `client_id` the client id you got here (not your IdP's own), `scope` `read`, and optionally `resource`
   `<tester>/mcp`.
4. **Redeem it:**

   ```sh
   curl <tester>/api/auth/oauth2/token -u <client_id>:<client_secret> \
     -d grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer \
     -d assertion=<your ID-JAG>
   ```

   The first ID-JAG signed with a key from your issuer's published JWKS, with your issuer as `iss` and this client as
   `client_id`, **confirms** the registration: proof that you run the issuer. It is then redeemed as usual. Until
   then, others may register the same issuer too, and the first to confirm holds it for the registration's 24 hours.
   So nobody can hold an issuer they don't run.
5. **Read the report** at `<tester>/results`. Optionally call the MCP server at `<tester>/mcp` with the access token:
   `whoami` shows what the receiver made of your ID-JAG, `checks` the latest reports.

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
- your sign-in, which lasts a day.

**Never stored:**
- your email (a made-up address that receives no mail stands in);
- your picture;
- your provider's tokens;
- your IP address.

GitHub is asked only for `read:user`, GitLab for `read_user`.

**About your IdP, for the registration's 24 hours:**
- its metadata report, its keys, and the client here;
- the sandbox users;
- each redemption's report and the receiver's logs of it.

**An abuse record, for 7 days, that isn't about you as a person.** It holds fingerprints (keyed hashes) of the
account, the address and its network: the same account always gives the same fingerprint, but a fingerprint can't
be turned back into the account or the address. With them it keeps:
- the account's age as a range;
- the IdP's host name;
- the counts of redemptions and refusals;
- how the registration ended.

The fingerprint key changes every week and is deleted a week later. Until then the fingerprints count as
pseudonymous data: whoever holds the key could check whether a given account made one. They are kept to enforce the
daily limits and to spot abuse. Once the key is deleted, and the restore history below has dropped it too (30 days),
nobody, the operator included, can tell whose a fingerprint was.

**A blocklist, for 30 days, only for accounts and networks caught abusing the tester.** It holds fingerprints under
its own key, which is deleted when nothing is blocked.

**Delete my data now:** a button on your results page. It ends your registration and deletes everything about you
and your IdP at once, your sign-in included. Only the abuse record remains, for the rest of its 7 days: it holds no
login, email or address, and the limits must still count.

**Cloudflare:**
- Its request logs (Workers Logs, kept 7 days) record registration ids and IdP host names, never logins or addresses.
- Its database keeps a restore history (D1 Time Travel) that can't be turned off: anything deleted can still be
  restored from it for 30 days, by the operator only. Because no email, token or address is ever stored, that
  history holds little more than the above.

Nothing is shared or used for anything else. The site shows your results only to you.

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
  block a registration's account and/or network for 30 days and end it (`POST /admin/block`, while the registration
  exists). It can never reopen anything.
- **`ADMIN_OPEN_KEY`** reopens it (`POST /admin/open`).

Setting `TESTER_ENABLED` to anything but `true`, or `POST /admin/close`, closes everything except the home page and
`/admin`. Set `PUBLIC_ORIGIN` to the tester's address so that no other host name (such as its workers.dev one) is
served. Host the tester on its own domain, not a subdomain of a site with sign-ins of its own: its pages show what
testers' IdPs send, and browsers treat subdomains of one domain as the same site for cookies.
