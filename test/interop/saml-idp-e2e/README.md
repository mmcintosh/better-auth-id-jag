# Cross-repository end to end: better-auth-saml-idp → idJagIssuer → idJagGrant

A real SAML sign-in at better-auth-saml-idp, with assertion exchange on (`tokenExchange` on the SP), is followed by
our issuer's two SAML paths and our receiver:
- **Path (b):** the Assertion → a refresh token (draft -04 §4.5) → an ID-JAG → an access token.
- **Path (a):** the Assertion → an ID-JAG directly → an access token.

It also checks the attacks that cross the two repositories:
- a replay, refused on each path;
- a tampered assertion, refused, and it doesn't burn the real one;
- another client presenting the agent's assertion with the agent's `client_id` forged in the body, refused on both paths, and it doesn't consume it either.

It runs as its own project, so both packages share **one** Better Auth (pnpm overrides). The sibling develops on
1.7.5, this repository on 1.7.6.

```sh
pnpm build                                  # this repository's dist
cd test/interop/saml-idp-e2e
openssl req -x509 -newkey rsa:2048 -nodes -keyout idp.key -out idp.crt -days 2 -subj "/CN=e2e-saml-idp"
pnpm install --ignore-scripts
node e2e.mjs
```

It installs better-auth-saml-idp **1.2.0 from npm**, the first release with assertion exchange. To test an
unreleased branch instead, point the dependency at `file:../../../../better-auth-saml-idp`.
