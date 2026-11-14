// How the tester's client sends its secret to the tester's IdP, in a run of the whole flow: from the run form's
// choice and what the IdP publishes. In its own module: the Worker's entry module (index.ts) may export only its
// handler.

export const AUTH_METHODS = ["client_secret_basic", "client_secret_post"] as const;
export type AuthMethod = (typeof AUTH_METHODS)[number];
const AUTH_HOW: Record<AuthMethod, string> = { client_secret_basic: "client_secret_basic (HTTP Basic)", client_secret_post: "client_secret_post (in the form body)" };

/**
 * How the tester's client sends its secret, from the run form's choice and the IdP's published
 * token_endpoint_auth_methods_supported (RFC 8414 section 2: absent means client_secret_basic). Automatic takes Basic
 * when the IdP lists it (RFC 6749 section 2.3.1 requires IdPs to support it), else the form body. A choice the IdP
 * doesn't list is refused: the token endpoint would refuse it after the person signed in.
 */
export function clientAuthMethod(chosen: AuthMethod | "auto", published: unknown): { ok: true; method: AuthMethod; note: string } | { ok: false; why: string } {
  const listed = Array.isArray(published) ? published.filter((v): v is string => typeof v === "string") : null;
  const supported = listed ?? ["client_secret_basic"];
  const shown = listed ? listed.slice(0, 8).map((v) => v.slice(0, 64)).join(", ") || "nothing" : "client_secret_basic only (it doesn't list token_endpoint_auth_methods_supported, RFC 8414 section 2)";
  if (chosen === "auto") {
    const method = AUTH_METHODS.find((a) => supported.includes(a));
    if (!method) return { ok: false, why: `Your IdP's metadata lists ${shown} as token_endpoint_auth_methods_supported; the tester's client can send its secret only with client_secret_basic or client_secret_post.` };
    return { ok: true, method, note: `The tester's client sends its secret with ${AUTH_HOW[method]}, as your IdP's metadata lists.` };
  }
  if (!supported.includes(chosen)) return { ok: false, why: `Your IdP's metadata says its token endpoint accepts ${shown}, not ${chosen}. Choose Automatic, or the method your IdP's client is set up for.` };
  return { ok: true, method: chosen, note: `The tester's client sends its secret with ${AUTH_HOW[chosen]}, as you chose.` };
}

