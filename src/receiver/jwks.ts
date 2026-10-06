// A trusted issuer's keys (S4, S10). The receiver's only outbound requests are made here, to the
// JWKS or discovery URL of an issuer it already trusts, through one injectable `fetch`:
// - https only, no credentials in the URL;
// - `redirect: "manual"`, and any redirect (a 3xx, or workerd's opaque redirect) is a failure:
//   workerd refuses `redirect: "error"` (docs/phase-0.md finding 1);
// - a response size cap and a timeout covering the whole exchange;
// - keys cached per issuer by `kid`; an unknown `kid` causes at most one refetch per interval per
//   issuer, so a caller can't make us hammer an issuer's JWKS; a failed fetch counts too.
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

  /** The keys to verify an ID-JAG with `kid` from this issuer; fetches (or refetches) as the rules allow. */
  async keysFor(source: KeySource, kid: string): Promise<IssuerKeys> {
    const cacheKey = JSON.stringify([source.issuer, source.jwksUri ?? "", source.discoveryUri ?? ""]);
    let entry = this.entries.get(cacheKey);
    if (!entry) {
      entry = { keys: null, fetchedAt: 0, lastAttemptAt: Number.NEGATIVE_INFINITY, inflight: null };
      this.entries.set(cacheKey, entry);
    }
    const now = this.now();
    const fresh = entry.keys !== null && now - entry.fetchedAt < this.settings.cacheTtlMs;
    const hasKid = entry.keys?.some((k) => k.kid === kid) ?? false;
    if (!(fresh && hasKid)) {
      if (entry.inflight !== null) await entry.inflight;
      else if (now - entry.lastAttemptAt >= this.settings.minRefetchMs) await this.refresh(entry, source);
      // else: refetched too recently; use what we have (an unknown kid then fails as a bad signature).
    }
    if (!entry.keys) refuse("jwks_unavailable", "no keys (a recent fetch failed)");
    return toIssuerKeys(entry.keys);
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
    const keys = doc.data.keys.filter((k) => k.use === undefined || k.use === "sig") as JWK[];
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

function toIssuerKeys(keys: JWK[]): IssuerKeys {
  const named = keys.map((k) => k.alg);
  const algorithms = named.every((a): a is string => typeof a === "string") ? ALLOWED_ALGORITHMS.filter((a) => named.includes(a)) : undefined;
  return { key: createLocalJWKSet({ keys } as JSONWebKeySet), algorithms };
}
