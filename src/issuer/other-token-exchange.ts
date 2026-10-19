// D-046: another token-exchange grant beside ours. oauth-provider registers one handler per grant type and throws
// at startup when two extensions claim the same one, so Better Auth 1.8's oauthTokenExchange() (access token →
// access token) can't be listed next to idJagIssuer(). Our issuer keeps the grant and forwards every request it
// doesn't serve to `otherTokenExchange`; tokenExchangeFrom() takes that handler out of a plugin like
// oauthTokenExchange(), through the public extendOAuthProvider, so the host lists our plugin only.
import type { OAuthExtensionGrantHandler, OAuthProviderExtension } from "@better-auth/oauth-provider";
import { TOKEN_EXCHANGE_GRANT } from "../core";

/** A token-exchange grant handler, as an oauth-provider extension registers it. */
export type TokenExchangeHandler = OAuthExtensionGrantHandler;

/** Better Auth 1.8's oauthTokenExchange() plugin id. */
export const BETTER_AUTH_TOKEN_EXCHANGE_PLUGIN_ID = "oauth-token-exchange";

/**
 * The token-exchange handler a plugin registers (such as `oauthTokenExchange()` from `@better-auth/oauth-provider`
 * 1.8), for `idJagIssuer({ otherTokenExchange })`. The plugin's `init` runs once, now, against a stand-in that
 * captures what it passes to `extendOAuthProvider`; the host doesn't list the plugin itself. Throws when the plugin
 * does anything that would be lost that way: anything besides `id` and `init` (endpoints, schema, hooks, …), an
 * `init` that returns something or is async, or an extension with more than the token-exchange grant.
 */
export function tokenExchangeFrom(plugin: { id: string; init?: unknown }): TokenExchangeHandler {
  const name = typeof plugin?.id === "string" ? plugin.id : "the plugin";
  const fail = (why: string): never => {
    throw new Error(`tokenExchangeFrom(${name}): ${why}; it can't be captured whole, so list it as its own plugin (without idJagIssuer) instead`);
  };
  const extra = Object.keys(plugin ?? {}).filter((k) => k !== "id" && k !== "init" && (plugin as Record<string, unknown>)[k] !== undefined);
  if (extra.length > 0) fail(`it also has ${extra.join(", ")}`);
  if (typeof plugin.init !== "function") fail("it has no init");
  // extendOAuthProvider reads and replaces provider.options.extensions on what ctx.getPlugin("oauth-provider") returns.
  const provider: { options: { extensions?: OAuthProviderExtension[] } } = { options: {} };
  const standIn = { getPlugin: (id: string) => (id === "oauth-provider" ? provider : null) };
  let returned: unknown;
  try {
    returned = (plugin.init as (ctx: unknown) => unknown)(standIn);
  } catch (e) {
    fail(`its init needs more than extendOAuthProvider (${e instanceof Error ? e.message : String(e)})`);
  }
  if (returned !== undefined) fail(typeof (returned as { then?: unknown })?.then === "function" ? "its init is async" : "its init returns options or context");
  const captured = provider.options.extensions ?? [];
  if (captured.length !== 1) fail(`it registered ${captured.length} extensions, not one`);
  const extension = captured[0] as OAuthProviderExtension;
  const other = Object.keys(extension).filter((k) => k !== "grants" && (extension as Record<string, unknown>)[k] !== undefined);
  if (other.length > 0) fail(`its extension also has ${other.join(", ")}`);
  const grants = Object.keys(extension.grants ?? {});
  const handler = extension.grants?.[TOKEN_EXCHANGE_GRANT];
  if (grants.length !== 1 || typeof handler !== "function") fail(`its extension registers ${grants.join(", ") || "no grant"}, not only ${TOKEN_EXCHANGE_GRANT}`);
  return handler as TokenExchangeHandler;
}

/** At startup: both plugins listed would make oauth-provider throw "registered more than once"; say what to do instead. */
export function refuseBothTokenExchanges(plugins: readonly { id?: unknown }[] | undefined): void {
  if (!plugins?.some((p) => p?.id === BETTER_AUTH_TOKEN_EXCHANGE_PLUGIN_ID)) return;
  throw new Error(
    "idJagIssuer: oauthTokenExchange() is listed too, and both register the token-exchange grant (oauth-provider allows one handler per grant type). Remove oauthTokenExchange() from plugins and pass idJagIssuer({ otherTokenExchange: tokenExchangeFrom(oauthTokenExchange()) }): ID-JAG requests stay here, the rest go to it.",
  );
}
