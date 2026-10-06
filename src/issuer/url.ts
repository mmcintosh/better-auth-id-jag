// Audience and resource identifiers. The audience is the resource authorization server's issuer
// identifier (RFC 8414), which a receiver compares by exact string: so we normalise only what URL
// syntax makes equivalent beyond doubt (scheme and host case, a default port) and never add or
// remove a path, not even a trailing slash ("no trailing-slash games", plan §3.4 step 5).

// biome-ignore lint/suspicious/noControlCharactersInRegex: refusing them is the point.
const CONTROL = /[\u0000- \u007f-\u009f]/;
const LOOPBACK = new Set(["localhost", "127.0.0.1", "[::1]"]);

/** The normalised audience, or a reason it isn't one. */
export function normalizeAudience(value: string, o: { allowLoopbackHttp?: boolean } = {}): { ok: true; audience: string } | { ok: false; why: string } {
  if (value.length === 0 || value.length > 2048) return { ok: false, why: "length" };
  if (CONTROL.test(value)) return { ok: false, why: "control or space characters" };
  if (value.includes("#")) return { ok: false, why: "fragment" };
  if (value.includes("?")) return { ok: false, why: "query" };
  let u: URL;
  try {
    u = new URL(value);
  } catch {
    return { ok: false, why: "not an absolute URL" };
  }
  const loopbackHttp = o.allowLoopbackHttp === true && u.protocol === "http:" && LOOPBACK.has(u.hostname);
  if (u.protocol !== "https:" && !loopbackHttp) return { ok: false, why: "not https" };
  if (u.username || u.password) return { ok: false, why: "userinfo" };
  if (!u.hostname) return { ok: false, why: "no host" };
  // The path as sent (URL would turn "" into "/"), percent-encoding as URL serialises it.
  const afterScheme = value.slice(value.indexOf("//") + 2);
  const hasPath = afterScheme.includes("/");
  return { ok: true, audience: `${u.protocol}//${u.host}${hasPath ? u.pathname : ""}` };
}

/** An RFC 8707 resource: an absolute URI without a fragment (the provider checks this too). */
export function isResourceUri(value: string): boolean {
  if (value.length === 0 || value.length > 2048 || CONTROL.test(value) || value.includes("#")) return false;
  return URL.canParse(value);
}
