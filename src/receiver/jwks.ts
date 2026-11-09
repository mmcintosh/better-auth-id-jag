// A trusted issuer's keys (S4, S10). The receiver's only outbound requests are made here, to the
// JWKS or discovery URL of an issuer it already trusts, through one injectable `fetch`:
// - https only, no credentials in the URL;
// - `redirect: "manual"`, and any redirect (a 3xx, or workerd's opaque redirect) is a failure:
//   workerd refuses `redirect: "error"` (docs/phase-0.md finding 1);
// - a response size cap and a timeout covering the whole exchange;
// - keys cached per issuer by `kid`; an unknown `kid` causes at most one refetch per interval per
//   issuer, so a caller can't make us hammer an issuer's JWKS; a failed fetch counts too;
// - while the JWKS is unreachable, cached keys keep working for at most `maxStaleMs` past the TTL
//   (D-A25); after that they are discarded, so a key the IdP withdrew can't live on indefinitely.
// Every problem is `jwks_unavailable`; an empty key set is a problem, not "trust nothing" (S1).
import { createLocalJWKSet, type JSONWebKeySet, type JWK } from "jose";
import { z } from "zod";
import { ALLOWED_ALGORITHMS, type IdJagAlgorithm, IdJagRefusal, refuse } from "../core";

export type FetchLike = (input: string, init: RequestInit) => Promise<Response>;

export interface JwksSettings {
  timeoutMs: number;
  maxBytes: number;
  cacheTtlMs: number;
  minRefetchMs: number;
  /** How long past the TTL cached keys may still be used while refetches fail. */
  maxStaleMs: number;
}

/**
 * How an ID-JAG names its key: by `kid`, or (PingFederate's, which sends no kid; D-042) by the SHA-1 or SHA-256
 * thumbprint of the key's certificate. A `kid`, when there is one, is used alone.
 */
export interface KeyRef {
  kid?: string | undefined;
  x5t?: string | undefined;
  "x5t#S256"?: string | undefined;
}

/** Where an issuer's keys come from. */
export interface KeySource {
  issuer: string;
  jwksUri?: string | undefined;
  discoveryUri?: string | undefined;
}

export interface IssuerKeys {
  /** The jose key resolver over the issuer's JWKS. */
  key: ReturnType<typeof createLocalJWKSet>;
  /** The algorithms the JWKS publishes, when every key names one; otherwise undefined (all allowed). */
  algorithms: IdJagAlgorithm[] | undefined;
}

interface Entry {
  keys: JWK[] | null;
  fetchedAt: number;
  lastAttemptAt: number;
  inflight: Promise<void> | null;
}

const MAX_KEYS = 100;
const jwksSchema = z.looseObject({ keys: z.array(z.looseObject({ kty: z.string().min(1), kid: z.string().optional(), alg: z.string().optional(), use: z.string().optional() })).max(MAX_KEYS) });
const discoverySchema = z.looseObject({ issuer: z.string().min(1), jwks_uri: z.string().min(1) });

function assertHttps(url: string, what: string): URL {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    refuse("jwks_unavailable", `${what}: not a URL`);
  }
  if (u.protocol !== "https:") refuse("jwks_unavailable", `${what}: not https`);
  if (u.username || u.password) refuse("jwks_unavailable", `${what}: credentials in URL`);
  return u;
}

export class JwksCache {
  private readonly entries = new Map<string, Entry>();

  constructor(
    private readonly fetchImpl: FetchLike,
    private readonly settings: JwksSettings,
    private readonly now: () => number,
  ) {}

  /**
   * The keys to verify an ID-JAG from this issuer naming `ref` (a kid, or a KeyRef); fetches (or refetches) as the rules allow.
   * Named by thumbprint, only the keys with that thumbprint are offered (a key not found: no keys, a bad signature).
   * A failed refetch doesn't refuse the request while the cached keys are within `maxStale` past their
   * TTL: they answer, and `onStaleRefetchError` hears about the failure (the operator should know).
   */
  async keysFor(source: KeySource, ref: string | KeyRef, onStaleRefetchError?: (e: unknown) => void): Promise<IssuerKeys> {
    const named = typeof ref === "string" ? { kid: ref } : ref;
    const cacheKey = JSON.stringify([source.issuer, source.jwksUri ?? "", source.discoveryUri ?? ""]);
    let entry = this.entries.get(cacheKey);
    if (!entry) {
      entry = { keys: null, fetchedAt: 0, lastAttemptAt: Number.NEGATIVE_INFINITY, inflight: null };
      this.entries.set(cacheKey, entry);
    }
    const now = this.now();
    const fresh = entry.keys !== null && now - entry.fetchedAt < this.settings.cacheTtlMs;
    const known = entry.keys?.some((k) => matches(k, named)) ?? false;
    if (!(fresh && known)) {
      if (entry.inflight !== null) await entry.inflight;
      else if (now - entry.lastAttemptAt >= this.settings.minRefetchMs)
        await this.refresh(entry, source).catch((e: unknown) => {
          if (!this.usable(entry)) throw e;
          onStaleRefetchError?.(e);
        });
      // else: refetched too recently; use what we have (an unknown kid then fails as a bad signature).
    }
    // Too stale to use (the refetches failed): discard the keys until a fetch succeeds.
    if (entry.keys !== null && !this.usable(entry)) entry.keys = null;
    if (!entry.keys) refuse("jwks_unavailable", "no keys (a recent fetch failed)");
    if (named.kid !== undefined) return toIssuerKeys(entry.keys);
    // No kid: only the keys whose certificate the header names; jose then picks among them by alg and key type.
    const selected = entry.keys.filter((k) => matches(k, named));
    if (selected.length === 0) refuse("bad_signature", "no key with this certificate thumbprint");
    return toIssuerKeys(selected, entry.keys);
  }

  /** Cached keys no more than `maxStale` past their TTL. */
  private usable(entry: Entry): boolean {
    return entry.keys !== null && this.now() - entry.fetchedAt < this.settings.cacheTtlMs + this.settings.maxStaleMs;
  }

  private refresh(entry: Entry, source: KeySource): Promise<void> {
    entry.lastAttemptAt = this.now();
    const run = (async () => {
      try {
        const keys = await this.load(source);
        entry.keys = keys;
        entry.fetchedAt = this.now();
      } finally {
        entry.inflight = null;
      }
    })();
    entry.inflight = run.catch(() => {});
    return run;
  }

  private async load(source: KeySource): Promise<JWK[]> {
    let jwksUri = source.jwksUri;
    if (!jwksUri) {
      if (!source.discoveryUri) refuse("jwks_unavailable", "no jwksUri or discoveryUri");
      const doc = discoverySchema.safeParse(await this.getJson(source.discoveryUri, "discovery"));
      if (!doc.success) refuse("jwks_unavailable", "discovery document invalid");
      // RFC 8414 §3.3 / OIDC Discovery §4.3: the document's issuer must be the issuer, exactly.
      if (doc.data.issuer !== source.issuer) refuse("jwks_unavailable", "discovery issuer mismatch");
      jwksUri = doc.data.jwks_uri;
    }
    const doc = jwksSchema.safeParse(await this.getJson(jwksUri, "jwks"));
    if (!doc.success) refuse("jwks_unavailable", "JWKS document invalid");
    const keys = (await Promise.all(doc.data.keys.filter((k) => (k.use === undefined || k.use === "sig") && verifies(k.key_ops)).map(verifyOnly).map(withThumbprints))) as JWK[];
    if (keys.length === 0) refuse("jwks_unavailable", "JWKS has no signing keys");
    // jose validates each key when it is used; a JWKS it can't load at all is unavailable.
    try {
      createLocalJWKSet({ keys } as JSONWebKeySet);
    } catch {
      refuse("jwks_unavailable", "JWKS not loadable");
    }
    return keys;
  }

  /** GET a JSON document under the network rules. */
  private async getJson(url: string, what: string): Promise<unknown> {
    assertHttps(url, what);
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const deadline = new Promise<never>((_, reject) => {
      timer = setTimeout(() => {
        controller.abort();
        reject(new Error("timeout"));
      }, this.settings.timeoutMs);
    });
    try {
      return await Promise.race([this.exchange(url, what, controller.signal), deadline]);
    } catch (error) {
      if (error instanceof IdJagRefusal) throw error;
      refuse("jwks_unavailable", `${what}: ${error instanceof Error ? error.message : "fetch failed"}`);
    } finally {
      clearTimeout(timer);
    }
  }

  private async exchange(url: string, what: string, signal: AbortSignal): Promise<unknown> {
    const res = await this.fetchImpl(url, { method: "GET", redirect: "manual", signal, headers: { accept: "application/json" } });
    // Node shows the 3xx; workerd and browsers an opaque redirect with status 0.
    if (res.type === "opaqueredirect" || (res.status >= 300 && res.status < 400)) refuse("jwks_unavailable", `${what}: redirect refused`);
    if (res.status !== 200) refuse("jwks_unavailable", `${what}: HTTP ${res.status}`);
    const declared = Number(res.headers.get("content-length") ?? "NaN");
    if (Number.isFinite(declared) && declared > this.settings.maxBytes) refuse("jwks_unavailable", `${what}: too large`);
    const text = await readCapped(res, this.settings.maxBytes, what);
    try {
      return JSON.parse(text) as unknown;
    } catch {
      refuse("jwks_unavailable", `${what}: not JSON`);
    }
  }
}

async function readCapped(res: Response, max: number, what: string): Promise<string> {
  if (!res.body) refuse("jwks_unavailable", `${what}: empty body`);
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > max) {
      await reader.cancel().catch(() => {});
      refuse("jwks_unavailable", `${what}: too large`);
    }
    chunks.push(value);
  }
  const all = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    all.set(c, offset);
    offset += c.byteLength;
  }
  return new TextDecoder("utf-8", { fatal: false }).decode(all);
}

/** RFC 7517 §4.3: a key without `key_ops` may be used for anything; one with it, only for what it lists. */
function verifies(ops: unknown): boolean {
  return ops === undefined || (Array.isArray(ops) && ops.includes("verify"));
}

/**
 * The key as jose imports it: `key_ops` reduced to `["verify"]`, the only use made of it here. WebCrypto refuses to
 * import an RSA or EC signing key whose usages include anything else, so a key published for
 * `["wrapKey", "encrypt", "verify"]` (Oracle's) would fail every ID-JAG signed with it.
 */
function verifyOnly<K extends Record<string, unknown>>(k: K): K {
  return k.key_ops === undefined ? k : { ...k, key_ops: ["verify"] };
}

/** Whether the key is the one `ref` names: by kid when there is one, else by either certificate thumbprint. */
function matches(k: JWK, ref: KeyRef): boolean {
  if (ref.kid !== undefined) return k.kid === ref.kid;
  const own = k as JWK & { "x5t#S256"?: unknown };
  return (ref["x5t#S256"] !== undefined && own["x5t#S256"] === ref["x5t#S256"]) || (ref.x5t !== undefined && own.x5t === ref.x5t);
}

/**
 * The key with its certificate thumbprints (RFC 7517 §4.8, §4.9) worked out from `x5c` when the JWKS doesn't publish
 * them, so an ID-JAG naming its key by thumbprint finds it. Published values are kept as they are: a wrong one only
 * means the key isn't found, since the signature is still checked with the key itself.
 */
async function withThumbprints<K extends Record<string, unknown>>(k: K): Promise<K> {
  const cert = Array.isArray(k.x5c) && typeof k.x5c[0] === "string" ? k.x5c[0] : undefined;
  if (cert === undefined || (typeof k.x5t === "string" && typeof k["x5t#S256"] === "string")) return k;
  let der: Uint8Array<ArrayBuffer>;
  try {
    der = Uint8Array.from(atob(cert), (c) => c.charCodeAt(0));
  } catch {
    return k; // not base64: no thumbprints, the key is still usable by kid
  }
  const digest = async (alg: "SHA-1" | "SHA-256") => base64url(new Uint8Array(await crypto.subtle.digest(alg, der)));
  return { ...k, ...(typeof k.x5t === "string" ? {} : { x5t: await digest("SHA-1") }), ...(typeof k["x5t#S256"] === "string" ? {} : { "x5t#S256": await digest("SHA-256") }) };
}

function base64url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** The resolver over `keys`; the published algorithms from `all` (every key of the issuer, by default). */
function toIssuerKeys(keys: JWK[], all: JWK[] = keys): IssuerKeys {
  const named = all.map((k) => k.alg);
  const algorithms = named.every((a): a is string => typeof a === "string") ? ALLOWED_ALGORITHMS.filter((a) => named.includes(a)) : undefined;
  return { key: createLocalJWKSet({ keys } as JSONWebKeySet), algorithms };
}
