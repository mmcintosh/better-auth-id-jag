// The only outbound requests the tester makes are to a tester's own issuer: its metadata and its JWKS. This keeps
// them to public https hosts, small answers, a short timeout, and no redirects, so the tester can't be pointed at
// arbitrary places or made to download much. (Workers can't reach private networks anyway; this is the rest.)

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
    const declared = Number(response.headers.get("content-length") ?? "0");
    if (declared > maxBytes) return { ok: false, why: `is larger than ${maxBytes} bytes` };
    const reader = response.body?.getReader();
    if (!reader) return { ok: false, why: "sent no body" };
    const chunks: Uint8Array[] = [];
    let size = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maxBytes) {
        await reader.cancel();
        return { ok: false, why: `is larger than ${maxBytes} bytes` };
      }
      chunks.push(value);
    }
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const c of chunks) {
      bytes.set(c, offset);
      offset += c.byteLength;
    }
    try {
      return { ok: true, json: JSON.parse(new TextDecoder().decode(bytes)) };
    } catch {
      return { ok: false, why: "is not JSON" };
    }
  } catch {
    return { ok: false, why: signal.aborted ? `didn't answer within ${timeoutMs} ms` : "couldn't be fetched" };
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
