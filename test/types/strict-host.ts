// A host app compiled with exactOptionalPropertyTypes against the built declarations (dist/):
// `pnpm pack:check` runs it under TypeScript 7 and 5.9. Both plugins must fit BetterAuthPlugin, pass
// inline in `plugins` as apps write them, and accept `undefined` for optional options from a host's
// own optional values. The client plugin must work with createAuthClient.
import { type BetterAuthPlugin, betterAuth } from "better-auth";
import { createAuthClient } from "better-auth/client";
import { jwt } from "better-auth/plugins";
import { type IdJagGrantOptions, type IdJagIssuerOptions, idJagGrant, idJagIssuer, verifyIdJag } from "better-auth-id-jag";
import { idJagIssuerClient } from "better-auth-id-jag/client";

declare const maybeLifetime: number | undefined;
declare const maybeSkew: number | undefined;
declare const maybeOrg: string | undefined;

const issuerOptions: IdJagIssuerOptions = {
  authorize: ({ audience }) => (audience === "https://mcp.example/api/auth" ? { decision: "allow", scopes: ["read"], lifetimeSeconds: maybeLifetime } : { decision: "deny" }),
  defaultLifetimeSeconds: maybeLifetime,
  signingAlgorithm: "ES256",
  auditLog: { retentionDays: 30 },
};
const grantOptions: IdJagGrantOptions = {
  trustedIssuers: [{ issuer: "https://idp.example/api/auth", jwksUri: "https://idp.example/api/auth/jwks", organizationId: maybeOrg, jitProvisioning: { trustEmailVerified: true } }],
  clockSkewSeconds: maybeSkew,
  jwks: { maxStaleSeconds: 3600 },
};

// Each is a BetterAuthPlugin…
export const issuerPlugin: BetterAuthPlugin = idJagIssuer(issuerOptions);
export const grantPlugin: BetterAuthPlugin = idJagGrant(grantOptions);
// …and passes inline, as apps write it.
export const auth = betterAuth({ plugins: [jwt(), idJagIssuer(issuerOptions), idJagGrant(grantOptions)] });

// The core verifier, for hosts that check an ID-JAG themselves.
export const verify = (token: string, keys: Parameters<typeof verifyIdJag>[1]) => verifyIdJag(token, keys, { issuer: "https://idp.example/api/auth", audience: "https://mcp.example/api/auth" });

// The client plugin.
export const client = createAuthClient({ plugins: [idJagIssuerClient()] });
