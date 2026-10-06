// Hosts the issuer can't serve safely fail at startup, with a clear error; options are validated.
import { betterAuth, type BetterAuthPlugin } from "better-auth";
import { jwt } from "better-auth/plugins";
import { oauthProvider } from "@better-auth/oauth-provider";
import { describe, expect, it } from "vitest";
import { type IdJagIssuerOptions, idJagIssuer, resolveIssuerOptions } from "../../src/issuer";
import { BASE, SECRET } from "../support/issuer-host";

const provider = (o: Record<string, unknown> = {}) => oauthProvider({ loginPage: "/login", consentPage: "/consent", ...o }) as unknown as BetterAuthPlugin;
const issuer = (o: IdJagIssuerOptions = { authorize: () => ({ decision: "deny" }) }) => idJagIssuer(o) as unknown as BetterAuthPlugin;

async function boot(plugins: BetterAuthPlugin[]) {
  const auth = betterAuth({ baseURL: BASE, secret: SECRET, telemetry: { enabled: false }, plugins });
  return auth.$context.then(
    () => "ok",
    (e: Error) => e.message,
  );
}

describe("startup checks", () => {
  it("boots on oauthProvider() + jwt()", async () => {
    expect(await boot([jwt(), provider(), issuer()])).toBe("ok");
  });

  it("refuses a host without oauthProvider()", async () => {
    expect(await boot([jwt(), issuer()])).toMatch(/requires the oauth-provider plugin/);
  });

  it("refuses disableJwtPlugin (HS256 ID tokens under the client secret)", async () => {
    expect(await boot([provider({ disableJwtPlugin: true, storeClientSecret: "encrypted" }), issuer()])).toMatch(/disableJwtPlugin/);
  });

  it("refuses a host without the jwt plugin", async () => {
    // oauthProvider() itself may complain first; either way, startup fails.
    expect(await boot([provider(), issuer()])).not.toBe("ok");
  });

  it("refuses remote signing (jwt.sign / jwks.remoteUrl): no local keys to verify ID tokens with", async () => {
    const remote = jwt({ jwks: { remoteUrl: "https://keys.example/jwks", keyPairConfig: { alg: "ES256" } }, jwt: { sign: async () => "x" } });
    expect(await boot([remote, provider(), issuer()])).toMatch(/remote keys/);
  });

  it("refuses a signingAlgorithm the jwt plugin has no key configuration for", async () => {
    expect(await boot([jwt({ jwks: { keyPairConfig: { alg: "ES256" } } }), provider(), issuer({ signingAlgorithm: "RS256" })])).toMatch(/signingAlgorithm RS256/);
  });

  it("refuses to sign ID-JAGs with an algorithm receivers refuse (S4)", async () => {
    expect(await boot([jwt({ jwks: { keyPairConfig: { alg: "PS256" } } }), provider(), issuer()])).toMatch(/PS256/);
  });

  it("validates options: unknown keys, out-of-range numbers, wrong types", () => {
    for (const bad of [
      { nope: true },
      { defaultLifetimeSeconds: 901 },
      { defaultLifetimeSeconds: Number.NaN },
      { defaultLifetimeSeconds: 0 },
      { signingAlgorithm: "HS256" },
      { authorize: "allow" },
      { registry: { enabled: true, cacheSeconds: -1 } },
      { registry: { enabled: "yes" } },
      { auditLog: { retentionDays: 0 } },
      { sweepIntervalSeconds: Number.POSITIVE_INFINITY },
      { maxIdTokenAgeSeconds: 59 },
      { maxIdTokenAgeSeconds: 86_401 },
      { maxIdTokenAgeSeconds: 600.5 },
      { maxIdTokenAgeSeconds: Number.NaN },
      { maxIdTokenAgeSeconds: "3600" },
      { blocks: { canManage: true } },
      { blocks: { enabled: true } },
    ]) {
      expect(() => resolveIssuerOptions(bad as never), JSON.stringify(bad)).toThrow(/idJagIssuer: invalid options/);
    }
    expect(resolveIssuerOptions({})).toMatchObject({ defaultLifetimeSeconds: 300, allowPublicClients: false, registryEnabled: false, cacheSeconds: 60, maxIdTokenAgeSeconds: 3600 });
    expect(resolveIssuerOptions({ maxIdTokenAgeSeconds: 60 }).maxIdTokenAgeSeconds).toBe(60);
    expect(resolveIssuerOptions({ maxIdTokenAgeSeconds: 86_400 }).maxIdTokenAgeSeconds).toBe(86_400);
  });
});
