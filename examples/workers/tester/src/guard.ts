// The only outbound requests the tester makes are to the addresses a registered issuer names: its metadata and its
// JWKS, and in a run of the whole flow the token endpoint its metadata names, which may be on another host. A
// registration is proven (confirmed) only by an ID-JAG signed with the issuer's key, so until then these may be
// someone else's. A run's code exchange goes before anything is proven, with the client id and secret typed for the
// run and whatever code comes back (one a run); the token exchange waits for an ID token that verifies with the
// issuer's keys, and the refusal probes for a confirmed registration (index.ts, D-075). This keeps all of them to
// public https hosts, small answers, a short timeout, and no redirects, so the tester can't be pointed at private
// places or made to download much. (Workers can't reach private networks anyway; this is the rest.)

const MAX_URL_LENGTH = 512;
/** Names that never resolve on the public internet, or that we'd rather not call. */
const BLOCKED_SUFFIXES = ["localhost", "local", "internal", "invalid", "test", "example", "lan", "home", "corp", "intranet", "onion", "arpa", "home.arpa"];

export type UrlCheck = { ok: true; url: URL } | { ok: false; why: string };

/** A URL the tester may fetch: https, default port, a DNS name with a public suffix, no credentials or fragment. */
export function checkPublicHttpsUrl(raw: string): UrlCheck {
  if (typeof raw !== "string" || raw.length === 0 || raw.length > MAX_URL_LENGTH) return { ok: false, why: `must be a URL of at most ${MAX_URL_LENGTH} characters` };
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return { ok: false, why: "is not a URL" };
  }
  if (url.protocol !== "https:") return { ok: false, why: "must use https" };
  if (url.username || url.password) return { ok: false, why: "must not contain a user name or password" };
  if (url.hash) return { ok: false, why: "must not contain a fragment (#)" };
  if (url.port !== "" && url.port !== "443") return { ok: false, why: "must use the default https port" };
  const host = url.hostname.toLowerCase();
  // "localhost." and "metadata.internal." are the same names as without the dot: refuse the form outright.
  if (host.endsWith(".")) return { ok: false, why: "must not end with a dot" };
  if (host.startsWith("[") || host.includes(":")) return { ok: false, why: "must use a DNS name, not an IP address" };
  if (/^[0-9.]+$/.test(host) || /^0x/i.test(host)) return { ok: false, why: "must use a DNS name, not an IP address" };
  if (!host.includes(".")) return { ok: false, why: "must use a fully qualified DNS name" };
  const last = host.split(".").pop() ?? "";
  if (/^[0-9]+$/.test(last)) return { ok: false, why: "must use a DNS name, not an IP address" };
  if (BLOCKED_SUFFIXES.some((s) => host === s || host.endsWith(`.${s}`))) return { ok: false, why: "must be a public DNS name" };
  return { ok: true, url };
}

export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

/** For the receiver's `fetch` option: refuses any URL the guard refuses, and never follows a redirect. */
export function guardedFetch(fetchImpl: FetchLike): FetchLike {
  return async (input, init) => {
    const check = checkPublicHttpsUrl(String(input));
    if (!check.ok) throw new Error(`refused to fetch: the URL ${check.why}`);
    const response = await fetchImpl(check.url.href, { ...init, redirect: "manual" });
    if (response.status >= 300 && response.status < 400) throw new Error("refused to follow a redirect");
    return response;
  };
}

export type JsonFetch = { ok: true; json: unknown } | { ok: false; why: string };

/** GETs a JSON document through the guard: at most `maxBytes`, within `timeoutMs`, no redirects. Never throws. */
export async function fetchJsonCapped(fetchImpl: FetchLike, raw: string, { maxBytes = 65_536, timeoutMs = 3_000 } = {}): Promise<JsonFetch> {
  const check = checkPublicHttpsUrl(raw);
  if (!check.ok) return { ok: false, why: `the URL ${check.why}` };
  const signal = AbortSignal.timeout(timeoutMs);
  try {
    const response = await fetchImpl(check.url.href, { method: "GET", redirect: "manual", signal, headers: { accept: "application/json" } });
    if (response.status >= 300 && response.status < 400) return { ok: false, why: `answered ${response.status} (a redirect, which the tester doesn't follow)` };
    if (!response.ok) return { ok: false, why: `answered HTTP ${response.status}` };
    const text = await readCapped(response, maxBytes);
    if (text === null) return { ok: false, why: `is larger than ${maxBytes} bytes` };
    if (text === undefined) return { ok: false, why: "sent no body" };
    try {
      return { ok: true, json: JSON.parse(text) };
    } catch {
      return { ok: false, why: "is not JSON" };
    }
  } catch {
    return { ok: false, why: signal.aborted ? `didn't answer within ${timeoutMs} ms` : "couldn't be fetched" };
  }
}

/** A response's body as text, read up to `maxBytes`: null when it is larger, undefined when there is none. */
async function readCapped(response: Response, maxBytes: number): Promise<string | null | undefined> {
  if (Number(response.headers.get("content-length") ?? "0") > maxBytes) return null;
  const reader = response.body?.getReader();
  if (!reader) return undefined;
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > maxBytes) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const c of chunks) {
    bytes.set(c, offset);
    offset += c.byteLength;
  }
  return new TextDecoder().decode(bytes);
}

/** A token endpoint's answer: its status, the two headers the rules read, and its body as JSON (undefined if it isn't). */
export type FormPost = { ok: true; status: number; contentType: string | null; cacheControl: string | null; json: unknown } | { ok: false; why: string };

/**
 * POSTs a form to a token endpoint through the guard: at most `maxBytes` back, within `timeoutMs`, no redirects. Any
 * status is an answer (an OAuth error is one); only a refused URL, a redirect, a timeout or a body too large isn't.
 * Never throws.
 */
export async function postFormCapped(fetchImpl: FetchLike, raw: string, form: URLSearchParams, headers: Record<string, string>, { maxBytes = 65_536, timeoutMs = 5_000 } = {}): Promise<FormPost> {
  const check = checkPublicHttpsUrl(raw);
  if (!check.ok) return { ok: false, why: `the URL ${check.why}` };
  const signal = AbortSignal.timeout(timeoutMs);
  try {
    const response = await fetchImpl(check.url.href, { method: "POST", redirect: "manual", signal, headers: { ...headers, accept: "application/json", "content-type": "application/x-www-form-urlencoded" }, body: form.toString() });
    if (response.status >= 300 && response.status < 400) return { ok: false, why: `answered ${response.status} (a redirect, which the tester doesn't follow)` };
    const text = await readCapped(response, maxBytes);
    if (text === null) return { ok: false, why: `answered with more than ${maxBytes} bytes` };
    let json: unknown;
    try {
      json = text === undefined ? undefined : JSON.parse(text);
    } catch {
      json = undefined;
    }
    return { ok: true, status: response.status, contentType: response.headers.get("content-type"), cacheControl: response.headers.get("cache-control"), json };
  } catch {
    return { ok: false, why: signal.aborted ? `didn't answer within ${timeoutMs} ms` : "couldn't be reached" };
  }
}

/** RFC 8414 section 3.1: the well-known segment goes between the host and the issuer's path. */
export function oauthMetadataUrl(issuer: URL): string {
  const path = issuer.pathname === "/" ? "" : issuer.pathname.replace(/\/$/, "");
  return `${issuer.origin}/.well-known/oauth-authorization-server${path}`;
}

/** OpenID Connect Discovery 1.0 section 4: appended to the issuer. */
export function openIdConfigurationUrl(issuer: URL): string {
  return `${issuer.href.replace(/\/$/, "")}/.well-known/openid-configuration`;
}
