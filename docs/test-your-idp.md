# Test your IdP

A public receiver for people building an **ID-JAG issuer** (an IdP that implements
[draft-ietf-oauth-identity-assertion-authz-grant-06](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/06/)).
Register your issuer, redeem an ID-JAG, and see every rule it passed or failed, each with the draft section it comes
from, next to what a real receiver decided. The receiver is this package's `idJagGrant()`, unchanged; the code is
[`examples/workers/tester`](../examples/workers/tester).

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
| Each ID-JAG | `typ` `oauth-id-jag+jwt`; an accepted `alg` (RS256, ES256, EdDSA; never `none` or HS*); the signature, with your published keys; `iss`, `sub`, `aud` (this receiver's issuer, a string or a one-element array), `client_id` (the client that authenticated), `jti`, `exp`, `iat`, the lifetime; `resource`, if present, names this receiver's MCP server; `scope` present and includes `read`; the optional claims' shapes (`act`, `sub_id`, `tenant`, `auth_time`, `acr`, `amr`); `email` or `aud_sub` (RECOMMENDED) |
| The redemption | The receiver's own decision: accepted, or refused with its reason (for example `replay`, `foreign_resource`, `no_scope`) |

Each result is **pass**, **fail**, **warn** (allowed, but not what the draft recommends), or **info**. Rules marked
POLICY are this receiver's own choices, which the draft allows, for example that an ID-JAG without `scope` grants
nothing (section 4.3.3: the IdP includes "the granted values, if any").

## How to use it

1. **Sign in with GitHub.** The account must be at least 30 days old.
2. **Register your issuer.** Enter your issuer identifier exactly as your ID-JAGs' `iss`, and how your client will
   authenticate (`client_secret_basic` or `client_secret_post`). The tester reads your metadata and JWKS and shows the
   results. You get a client id and a secret, shown once, valid for 24 hours.
3. **Mint an ID-JAG** with the values the registration page shows: `aud` this receiver's issuer (`<tester>/api/auth`),
   `client_id` the client id you got here (not your IdP's own), `scope` `read`, and optionally `resource`
   `<tester>/mcp`.
4. **Redeem it:**

   ```sh
   curl <tester>/api/auth/oauth2/token -u <client_id>:<client_secret> \
     -d grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer \
     -d assertion=<your ID-JAG>
   ```

5. **Read the report** at `<tester>/results`. Optionally call the MCP server at `<tester>/mcp` with the access token:
   `whoami` shows what the receiver made of your ID-JAG, `checks` the latest reports.

Your users never sign in here. Each subject your ID-JAGs name becomes a sandbox user of your registration only. No
email from your ID-JAGs is stored.

## Limits

- **Registrations:**
  - one active at a time per GitHub account, two a day;
  - three a day from one address;
  - three a day across everyone.
- **One registration per issuer at a time.** If someone else has registered your issuer, wait for it to expire, at
  most 24 hours.
- **Redemptions:**
  - 10 a minute and 50 a day per registration;
  - 30 requests a minute from one address.
- **The tester closes itself** if it sees far more use than testing needs, or a run of server errors. An operator
  watches it and can close it, or end one registration, at any time.

## What is kept, and for how long

**For a registration:**
- your issuer, its metadata report and its JWKS;
- the client;
- the sandbox users;
- each redemption's report and the receiver's audit rows.

All of it is deleted within minutes after the registration ends. A short record of the registration itself (GitHub
login, issuer, address, times) is kept a week, for the daily limits, then deleted.

**Your GitHub account** (login, email, the sign-in token) stays while you have registrations, and is deleted about a week after your last one ends.

Test data only: use test users, never real ones. There is no uptime promise.

## Running your own

The tester is an example Worker: [`examples/workers/tester`](../examples/workers/tester). It needs:
- a D1 database;
- a GitHub OAuth app;
- a Turnstile widget;
- the three rate-limit bindings in its `wrangler.jsonc`;
- these secrets: `BETTER_AUTH_SECRET`, `GITHUB_CLIENT_SECRET`, `TURNSTILE_SECRET_KEY`, and `ADMIN_STATS_KEY`, `ADMIN_CLOSE_KEY`, `ADMIN_OPEN_KEY`.

Each admin key must be at least 32 characters:
- **`ADMIN_STATS_KEY`** reads `/admin/stats`.
- **`ADMIN_CLOSE_KEY`** can close the tester (`POST /admin/close`) or end one registration (`POST /admin/revoke`), and never reopen it.
- **`ADMIN_OPEN_KEY`** reopens it (`POST /admin/open`).

Setting `TESTER_ENABLED` to anything but `true` closes everything except `/admin`.
