# Phase 2: features from the Phase 1 review, interop, and Okta live (2026-10-06)

**Verdict: done, and Okta Cross App Access works live against our receiver.**
- **Interop:** our issuer works with our receiver (in every CI run), with Keycloak 26.8.0 and with node-oauth2-server.
  Authelia can't be tested yet, because no release ships ID-JAG.
- **The five Phase 1 review findings** have all landed.
- **The examples:** two example Workers run the whole flow over HTTP on Cloudflare.
- **Found live:** the receiver refused Okta's `act` claim. It's fixed (D-010), and the live run then passed.

## The Phase 1 review's findings

| # | Finding | Landed |
|---|---|---|
| 1 | The provider's own client-authentication refusals weren't audited | D-009. `client_authentication_failed`, `client_not_allowed_grant` and `provider_refused` events on both sides; response unchanged. The new tests found `instanceof APIError` missing some provider errors, so detection now uses `isAPIError`. |
| 2 | Refresh-token subject tokens, moved from Phase 3 | D-B14 to D-B15, D-011. |
| 3 | Mutation lists re-run on main, and run weekly | `.github/workflows/mutations.yml`. `scripts/mutate.py` now supports guard pairs and known survivors, and fails on a new survivor or a stale pattern. The first re-run on main found one stale core entry. |
| 4 | "Revoke" that didn't revoke | Replaced by blocks: D-B16 to D-B21, D-011. |
| 5 | JIT outside the organization | D-A18 to D-A22. |

The thirteen Phase 1 questions were decided as the review recommended (D-009). Smaller items also landed:
- `requireResourceClaim`;
- a startup warning on adapters without UNIQUE;
- the guide notes on the burnt jti and on the exact issuer string Okta needs;
- the track worktrees removed.

## Okta Cross App Access, live

Details and the Okta-side setup are in `docs/interop.md`. Okta's ID-JAG was RS256, with:
- `aud` = our issuer, exactly;
- `client_id` = the id **our receiver** issued the agent (D-004 was right);
- `resource`, `scope` and `email`;
- `act`, naming the AI agent.

The first run was refused by **our** receiver, because the core refused `act` (D-007). That would have refused every
Okta ID-JAG. With the fix, the second run passed end to end: Okta sign-in → Okta token exchange → our jwt-bearer
grant (JIT provisioning from the verified email) → `whoami` on `/mcp`, 200. The access token carries Okta's `act`.

Three things about Okta that the setup notes had wrong or didn't say:
- **No org-wide switch:** Cross App Access isn't an org-wide "Features" toggle. It's enabled per resource app
  (Machine Assignments → Resource server access).
- **The issuer:** the ID-JAG's issuer is the org (`https://<org>.okta.com`), not the `-admin` host.
- **The agent's credentials:** in Okta, the agent's resource connection takes the agent's client id at the
  receiver.

## Interop matrix (`docs/interop.md`)

| Our side | Other side | Result |
|---|---|---|
| issuer | our receiver | verified, in every CI run, Node and workerd |
| issuer | Keycloak 26.8.0 | verified (ES256, RS256, EdDSA). Keycloak ignores `scope` and `resource`, accepts the assertion for only **300 s after `iat`** whatever `exp` says, and requires a pre-linked subject. |
| issuer | node-oauth2-server PR #462 | verified (ES256, RS256). **No EdDSA.** A wider request scope is an error there, where ours narrows. |
| receiver | **Okta Cross App Access** | **verified live** |
| either | Authelia | not possible yet: library merged, no release |
| receiver | Keycloak as issuer | not possible: Keycloak doesn't issue ID-JAGs |

Consequences for us:
- **Algorithm:** issuers should sign RS256 or ES256, not the jwt plugin's EdDSA default. Already the recommendation
  (D-004).
- **Lifetime:** keep the ID-JAG lifetime at the 300 s default for Keycloak.

## Examples on Workers (`examples/workers/`)

- **The two Workers:** an enterprise IdP (oauthProvider + jwt ES256 + idJagIssuer) and an MCP server (mcp + jwt +
  idJagGrant), each on D1.
- **The client:** `client.mjs` runs the five steps plus a replay; the replay is refused. Four consecutive runs passed
  on the deployed Workers, and again after every merge.
- **For Okta:** `okta-agent.mjs` plays the AI agent.

Three Workers facts for the guide:
1. **Audit events are lost** unless `advanced.backgroundTasks` hands the work to `ctx.waitUntil`. Our audit table
   stayed empty until this was wired.
2. **A Worker can't fetch another Worker on the same account by URL.** The receiver's injectable `fetch` reaches
   the IdP's JWKS through a service binding instead.
3. **A Worker can't fetch its own `workers.dev` URL,** so `requireMcpAuth`, which fetches its own JWKS, can't run
   in a resource server deployed together with its authorization server. The example makes the same check
   in-process.

Two unexplained moments, recorded honestly:
- **One `invalid_grant` at the MCP server** before audit events were wired; its reason was lost, and it hasn't
  happened since.
- **Intermittent stalls of Node's `fetch` from this machine** to workers.dev, which `curl` didn't show. Unread
  response bodies were part of it: the client now reads every body.

## Evidence

- **Tests:** 598 passing after D-012 (299 per runtime: Node with node:sqlite, workerd with D1), plus 28 interop tests skipped
  unless Docker is set up. Typecheck and lint are clean, the build succeeds, and the examples typecheck against the
  built package.
- **Mutations:** 254, recorded below. Every guard is caught when broken, except 5 survivors that are known and
  explained.
- **Live:** Okta (above); the example Workers (above).

### Mutation run on merged main

`python3 scripts/mutate.py test/mutations/core.json test/mutations/receiver.json test/mutations/issuer.json` on
merged main at `e84868f` (2026-10-06): **254 mutations, 249 caught, 5 expected survivors, 0 problems, exit 0**.
- **The 5 survivors** are the issuer's known ones from Phase 1: one equivalent mutant, and four halves of guard pairs,
  each pair caught when broken together (`test/mutations/issuer.json`, `expect: "survive"` with the reason).
- **The three D-012 mutations** were added afterwards and run on their own: all caught.
- **The weekly CI job** (`mutations.yml`) runs the whole list from now on.

## Questions for the maintainer

Receiver (`docs/tracks/receiver.md`):
1. When an existing user is resolved, should the receiver ever add organization membership, as sso does at every
   sign-in? Today it does not (D-A19).
2. Should `jitRole` be checked against the organization plugin's roles? Custom roles exist.
3. The membership write skips the organization plugin's hooks and `membershipLimit`, as sso's does. Acceptable?
4. JIT doesn't add a membership while an invitation for the email is pending, as sso does. Keep that?

Issuer (`docs/tracks/issuer.md`):

5. Once DPoP lands, should sender-constrained refresh tokens be accepted, with `cnf` carried into the ID-JAG?
6. Is requiring `openid` on a refresh-token subject too strict for the future SAML-derived path?
7. Should blocks get their own option rather than `registry.canManage`?
8. Should a block also revoke the user's refresh tokens for that client at the provider?

Operations:

9. **Rotate the Okta agent's client secret.** It was pasted into the chat during setup.
10. Keep the two example Workers and the Okta configuration up after Phase 2, as the live demo, or delete them?

## Next: more Okta evidence (agreed with the maintainer, 2026-10-06)

In this order, after the Phase 2 checkpoint:
1. **One scripted session, about 30 minutes; the maintainer clicks in Okta where needed:**
   - **Revocation at the IdP:** unassign the user, or remove the agent's resource connection. Okta must refuse the
     next exchange; re-enable it, and access returns.
   - **A returning user:** found through the linked Okta account, not JIT.
   - **The refresh-token path:** Okta's refresh token exchanged for an ID-JAG.
   - **Negative checks with real Okta tokens:** a replay, a scope outside the connection, a wrong audience, each with
     its reason in our audit table.
2. **Organization membership:** an Okta trust entry with an organization; a first-time Okta user lands in it with
   the right role.
3. **Deprovisioning:** a test user deactivated in Okta loses access at the next exchange.
4. **Okta's xaa.dev resource-app conformance tester**, in two runs. Its test IdP is `https://idp.xaa.dev`, with
   keys at `/jwks`. It presents the ID-JAG at our token endpoint with a client registered here for it, then calls
   our API.
   - **a. The OIDC variant:** all steps green, with the exported conformance log kept in `docs/interop.md`.
   - **b. The SAML variant** (`/developer/test-resource-app`): the ID-JAG adds `sub_id` in the `saml-nameid`
     format. Draft -04 keeps `sub` required, and lets the receiver MAY resolve users by `sub_id`. The receiver
     accepts `sub_id` but doesn't resolve by it yet. This run either passes through email/JIT, or defines the
     `sub_id` resolution to add (a natural start for Phase 3).
5. **A real MCP client through Okta** (Claude or VS Code against our MCP server). The outcome is recorded either
   way: "works", or the gap and why.

## After Phase 3: the SCIM lifecycle (agreed with the maintainer, 2026-10-06)

Provision → ID-JAG → deprovision, across the sibling packages:
- **Provision:** `better-auth-scim-provisioning` on the IdP pushes users to the MCP server, which has inbound SCIM
  (`@better-auth/scim`), so ID-JAGs find them without JIT. That covers the SAML users with no email that JIT can't
  create.
- **ID-JAG:** the receiver links the provisioned user to the ID-JAG's `sub` through the SCIM `externalId`. Agreed
  with the SCIM session, 2026-10-06:
  - **The values line up.** Our issuer's `sub` is always the IdP's `user.id` (pairwise refused), which is
    better-auth-scim-provisioning's default `externalId`. Overriding it with `mapUser` breaks the link, which goes in
    the docs. Okta's `sub` is the Okta user id, so Okta's own SCIM must set `externalId` to that.
  - **The link is configured, not inferred.** A trusted issuer gets `scim?: { connectionId }` (per tenant for a
    multi-tenant entry). Resolution calls `@better-auth/scim`'s `acquireActiveSCIMUserLink({ connectionId,
    externalId: sub })` before the account-by-`sub` step, and that only finds active links.
  - **The link is required by default.** When `scim` is configured, a missing link is refused, so JIT can't re-create
    a deprovisioned user.
- **Deprovision:** a deactivated user's next ID-JAG is refused at the MCP server, a second line behind the IdP's blocks
  and revocation.

The deliverables are an end-to-end test across the three packages and a documented integration. Not a core feature.

## Known loose ends

- **Workers types:** `src/receiver/jwks.ts` doesn't typecheck against `@cloudflare/workers-types` (the DOM
  `Response.type` / `TextDecoder` option types). It's harmless for consumers, who get `dist/`. Tidy it, so
  workers-types hosts can typecheck our source.
- **Tooling:** TypeScript 7 plus `typescript-5`, and `pack:check` (publint, Are the Types Wrong, a strict-host
  types check), as in the siblings. Dependabot's TypeScript 7 PR is still open.
- **Adapter matrix:** Postgres, MySQL, MongoDB, Drizzle and Prisma for the new tables. This matters most for the
  jti unique index on MongoDB (D-007).
- **CodeQL, Scorecard, dependency review and OSV:** waiting for the repository to go public.
