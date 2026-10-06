# Versioning

This package follows [Semantic Versioning](https://semver.org). **Before 1.0**, a minor release (0.x.0) may break things, and every break is at the top of its [CHANGELOG](../CHANGELOG.md) entry with what to change; a patch release (0.x.y) never does. From 1.0: a **major** release for a change that could break your app or the other side of the exchange, a **minor** release for anything new, and a **patch** release for fixes.

## The draft

ID-JAG is an IETF draft: [draft-ietf-oauth-identity-assertion-authz-grant](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/). Each release implements one draft, named in `SUPPORTED_DRAFT` ([src/core/urns.ts](../src/core/urns.ts)), the README and the release notes. Today that's **-04**.

A new draft can rename a claim, a token type URN or a metadata field. When one does:

- the release that adopts it says so at the top of its notes, with what changes on the wire;
- where the change is in what the *other* side sends or accepts, the receiver accepts both forms for at least one minor release where that's safe, so an IdP and an MCP server don't have to upgrade on the same day; the issuer moves to the new form only when the main receivers (Okta, Keycloak) have;
- before 1.0, that release is a minor one; from 1.0, a change that drops an old form is a major one.

A security fix the draft requires is the exception: it ships in a patch release, even if it refuses something an earlier release accepted.

## What counts as the public API

A change to any of these that could break an app using them as documented counts as breaking:

- **The plugins and their options**: `idJagIssuer()`, `idJagGrant()` and `idJagIssuerClient()` (`better-auth-id-jag/client`); every option's name, what it accepts and its default. Unknown options are refused at startup, so a new option never changes what an existing configuration means.
- **What's on the wire**: the ID-JAG the issuer signs (its `typ`, its claims and their meaning), the token-exchange and jwt-bearer requests each side accepts, the metadata fields each side advertises, the claims the receiver adds to the access token (`idjag`, `act`), and the OAuth `error` codes in responses.
- **What's refused**: a check that refuses something today keeps refusing it. Loosening one (accepting something new) can come in a minor release, only by an opt-in option unless it's a draft requirement.
- **The admin API**: the `/id-jag/*` routes' paths, their parameters, what they return, and who may call them (`canManage`).
- **Audit events**: the four event types, their fields, and the reason codes in `REASONS` ([src/core/errors.ts](../src/core/errors.ts)). New fields and new reason codes can come in a minor release, so handlers should ignore what they don't know and give an unknown reason a `default` branch.
- **The database schema**: the tables (`idJagJti`, `idJagBlock`, and with their options `idJagTrustedIssuer`, `idJagResourceServer`, `idJagPolicy`, `idJagAudit`) and their columns. A new or changed column needs a migration, so from 1.0 it comes only in a major release, announced at the top of its notes with the migration; a table that exists only with a new option can come in a minor release, since turning the option on is when you migrate. The rows are internal: read them through the admin API and the events.
- **The exports** of `better-auth-id-jag`, with their types. The lower-level ones (`handleTokenExchange`, `handleIdJagGrant`, `checkIssuerHost`, `createIssuerState`, the schema builders) are public too, for hosts that compose the grants themselves.

## What doesn't

- Log messages, and the text of `error_description` (its *code* is the API; the generic descriptions stay generic on purpose).
- The examples in `examples/`, which follow the next release.
- Behaviour that contradicts the documentation is a bug, and fixing it can come in any release.

## Better Auth versions

The peer range covers the Better Auth versions this release is tested with: `>=1.7.5 <1.8.0` for `better-auth`, `@better-auth/core` and `@better-auth/oauth-provider`, so far. CI runs the suite on 1.7.5 and the latest 1.7.x. A new Better Auth minor (1.8) gets a release of this package that widens the range once it's tested, usually a minor one. Until then, npm will warn about the peer range.

## Node.js and runtimes

Node.js 22 and later, and Cloudflare Workers, as tested in CI. Dropping a Node.js version that's still maintained comes only in a major release (from 1.0).
