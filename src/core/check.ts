// Every rule an ID-JAG is held to, each with its outcome and the draft -06 section (or RFC) it comes from. The
// receiver stops at the first refusal; this runs them all, so an IdP builder sees everything wrong at once. A report,
// never a gate: the public tester (examples/workers/tester) still sends the ID-JAG to the real receiver, whose
// decision is what counts. The rules are listed with their sources in docs/test-your-idp.md.
//
// Pure: no network, no clock of its own. The caller passes the issuer's JWKS and the time.
import { compactVerify, importJWK, type JSONWebKeySet, type JWK } from "jose";
import { parseIdJag } from "./jwt";
import { ALLOWED_ALGORITHMS, DEFAULT_CLOCK_SKEW_SECONDS, ID_JAG_TOKEN_TYPE, ID_JAG_TYP, ISSUER_METADATA_FIELD, ISSUER_SIGNING_ALG_METADATA_FIELD, MAX_LIFETIME_SECONDS } from "./urns";

/** MUST and friends from the draft; POLICY is this receiver's own choice, which the draft allows. */
export type RuleLevel = "MUST" | "SHOULD" | "RECOMMENDED" | "OPTIONAL" | "POLICY";
/** fail: the receiver refuses, or must. warn: allowed, but not what the draft recommends. info: worth knowing. */
export type RuleOutcome = "pass" | "fail" | "warn" | "info" | "skip";

export interface RuleResult {
  id: string;
  level: RuleLevel;
  /** Where the rule comes from, for example "draft -06 section 4.4.1". */
  cite: string;
  outcome: RuleOutcome;
  message: string;
}

export interface IdJagCheckInput {
  /** The registered issuer: `iss` must equal it exactly. */
  issuer: string;
  /** This receiver's issuer identifier: `aud` must be it. */
  audience: string;
  /** The protected resource this receiver governs. */
  resource: string;
  /** The scopes this receiver can grant. */
  grantableScopes: readonly string[];
  /** The client that authenticated the request, when known. */
  clientId: string | undefined;
  /** The issuer's JWKS, or null when it couldn't be fetched (the signature rule is then skipped). */
  jwks: JSONWebKeySet | null;
  /** Unix seconds. */
  now: number;
}

export interface IdJagReport {
  header: Record<string, unknown> | null;
  claims: Record<string, unknown> | null;
  results: RuleResult[];
}

const D = (section: string) => `draft -06 section ${section}`;
const MAX_TOKEN_CHARS = 16_384;

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const isNonEmptyString = (v: unknown): v is string => typeof v === "string" && v.length > 0;
const isNumericDate = (v: unknown): v is number => typeof v === "number" && Number.isFinite(v);
/**
 * A value as the report shows it: short, and never more than one line. Never throws: a value nested too deeply for
 * JSON.stringify (and for String, which recurses through arrays the same way) is shown as a placeholder.
 */
export const show = (v: unknown): string => {
  let s: string;
  try {
    s = typeof v === "string" ? JSON.stringify(v) : (JSON.stringify(v) ?? String(v));
  } catch {
    s = "(a value too deeply nested to show)";
  }
  return s.length > 120 ? `${s.slice(0, 117)}...` : s;
};

function decodePart(part: string): Record<string, unknown> | null {
  try {
    const bin = atob(part.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(part.length / 4) * 4, "="));
    const json: unknown = JSON.parse(new TextDecoder().decode(Uint8Array.from(bin, (c) => c.charCodeAt(0))));
    return isObject(json) ? json : null;
  } catch {
    return null;
  }
}

/** Checks one ID-JAG. Never throws. */
export async function checkIdJag(token: string, input: IdJagCheckInput): Promise<IdJagReport> {
  const results: RuleResult[] = [];
  const add = (id: string, level: RuleLevel, cite: string, outcome: RuleOutcome, message: string) => results.push({ id, level, cite, outcome, message });

  // Structure: a compact JWS with JSON header and claims (RFC 7519 section 7.2). Nothing else can be checked without it.
  const parts = typeof token === "string" && token.length <= MAX_TOKEN_CHARS ? token.split(".") : [];
  const header = parts.length === 3 ? decodePart(parts[0] as string) : null;
  const claims = parts.length === 3 ? decodePart(parts[1] as string) : null;
  if (!header || !claims) {
    add("jwt.structure", "MUST", "RFC 7519 section 7.2", "fail", parts.length === 3 ? "The header or the claims are not a JSON object." : `Not a compact JWT (three dot-separated parts, at most ${MAX_TOKEN_CHARS} characters).`);
    return { header, claims, results };
  }
  add("jwt.structure", "MUST", "RFC 7519 section 7.2", "pass", "A compact JWT with a JSON header and claims.");

  // Header.
  // typ is a media type (RFC 7515 section 4.1.9): any letter case, "application/" optional. The receiver accepts both forms.
  const typ = typeof header.typ === "string" ? header.typ.toLowerCase() : undefined;
  const typOk = typ === ID_JAG_TYP || typ === `application/${ID_JAG_TYP}`;
  add("header.typ", "MUST", `${D("4.4.1, 3.1")}; RFC 7515 section 4.1.9`, typOk ? "pass" : "fail", typOk ? (header.typ === ID_JAG_TYP ? `typ is ${ID_JAG_TYP}.` : `typ ${show(header.typ)} is accepted (a media type: any case, application/ optional); ${ID_JAG_TYP} is the usual form.`) : `typ must be ${ID_JAG_TYP}; it is ${show(header.typ)}.`);
  const alg = header.alg;
  const algAllowed = typeof alg === "string" && (ALLOWED_ALGORITHMS as readonly string[]).includes(alg);
  add("header.alg", "POLICY", D("3, 4.4.1"), algAllowed ? "pass" : "fail", algAllowed ? `alg ${alg}, which this receiver accepts (${ALLOWED_ALGORITHMS.join(", ")}).` : `alg ${show(alg)} is not accepted here (${ALLOWED_ALGORITHMS.join(", ")}); never none or HS*.`);
  if (algAllowed && alg !== "RS256") add("header.alg.rs256", "MUST", D("3"), "info", "RS256 is mandatory to implement for IdPs and receivers; this ID-JAG uses another algorithm, which receivers SHOULD (ES256) or may accept.");
  // The receiver needs the key named: a kid, or else a certificate thumbprint (PingFederate sends x5t, never a kid).
  const thumbprintOk = (name: "x5t" | "x5t#S256") => header[name] === undefined || (typeof header[name] === "string" && (name === "x5t" ? /^[A-Za-z0-9_-]{27}$/ : /^[A-Za-z0-9_-]{43}$/).test(header[name] as string));
  const hasThumbprint = header.x5t !== undefined || header["x5t#S256"] !== undefined;
  if (!thumbprintOk("x5t") || !thumbprintOk("x5t#S256")) add("header.kid", "MUST", "RFC 7515 sections 4.1.7, 4.1.8", "fail", "x5t or x5t#S256 is present but isn't a base64url SHA-1 or SHA-256 thumbprint.");
  else if (header.kid !== undefined && !isNonEmptyString(header.kid)) add("header.kid", "POLICY", "RFC 7515 section 4.1.4", "fail", "kid must be a non-empty string.");
  else if (isNonEmptyString(header.kid)) add("header.kid", "POLICY", "RFC 7515 section 4.1.4", "pass", "kid names the signing key.");
  else if (hasThumbprint) add("header.kid", "POLICY", "RFC 7515 sections 4.1.7, 4.1.8", "warn", "No kid; the key is named by certificate thumbprint, which this receiver accepts. Some receivers look only at kid.");
  else add("header.kid", "POLICY", "RFC 7515 section 4.1.4", "fail", "Neither kid nor x5t: this receiver refuses an ID-JAG that doesn't name its key (missing_kid). Name the key, so key rotation works.");
  if (header.crit !== undefined) add("header.crit", "MUST", "RFC 7515 section 4.1.11", "fail", "crit lists header parameters a receiver must understand; this receiver understands none, so it refuses.");

  // Signature, with the issuer's published keys.
  if (!input.jwks) add("signature", "MUST", `${D("4.4.1")}; RFC 7521 section 5.2`, "skip", "Your JWKS couldn't be fetched, so the signature wasn't checked.");
  else if (!algAllowed) add("signature", "MUST", `${D("4.4.1")}; RFC 7521 section 5.2`, "fail", "Not checked: the algorithm isn't accepted.");
  else {
    const candidates = await signingKeys(input.jwks, header);
    let verified = false;
    for (const k of candidates) {
      try {
        await compactVerify(token, await importJWK(k, alg as string), { algorithms: [alg as string] });
        verified = true;
        break;
      } catch {
        // the next candidate
      }
    }
    add("signature", "MUST", `${D("4.4.1")}; RFC 7521 section 5.2`, verified ? "pass" : "fail", verified ? "The signature verifies with a key from your JWKS." : candidates.length === 0 ? "No signing key in your JWKS matches the header's kid (or x5t). Publish the key, or name it correctly." : "The signature doesn't verify with the matching key.");
  }

  // Claims (section 3.1), and the receiver's processing rules (section 4.4.1).
  add("claim.iss", "MUST", D("3.1, 4.4.1"), claims.iss === input.issuer ? "pass" : "fail", claims.iss === input.issuer ? "iss is your registered issuer." : `iss must be exactly your registered issuer ${show(input.issuer)}; it is ${show(claims.iss)}.`);
  add("claim.sub", "MUST", D("3.1"), isNonEmptyString(claims.sub) ? "pass" : "fail", isNonEmptyString(claims.sub) ? "sub is present." : "sub is REQUIRED: a non-empty string.");

  const aud = claims.aud;
  const audOk = aud === input.audience || (Array.isArray(aud) && aud.length === 1 && aud[0] === input.audience);
  add("claim.aud", "MUST", D("4.4.1"), audOk ? "pass" : "fail", audOk ? "aud is this receiver's issuer identifier." : Array.isArray(aud) && aud.length > 1 ? `aud as an array must have exactly one element, ${show(input.audience)}; it has ${aud.length}.` : `aud must be this receiver's issuer identifier ${show(input.audience)} (the authorization server, not the resource); it is ${show(aud)}.`);

  if (!isNonEmptyString(claims.client_id)) add("claim.client_id", "MUST", D("3.1"), "fail", "client_id is REQUIRED: the client's id at this receiver.");
  else if (input.clientId === undefined) add("claim.client_id", "MUST", D("4.4.1"), "skip", "client_id is present; the request's client wasn't known, so it wasn't compared.");
  else add("claim.client_id", "MUST", D("4.4.1"), claims.client_id === input.clientId ? "pass" : "fail", claims.client_id === input.clientId ? "client_id is the client that authenticated." : `client_id must be the client that authenticated (${show(input.clientId)}); it is ${show(claims.client_id)}. Use the client id the receiver gave you, not your IdP's own.`);

  add("claim.jti", "MUST", D("3.1"), isNonEmptyString(claims.jti) ? "pass" : "fail", isNonEmptyString(claims.jti) ? "jti is present (each ID-JAG works once here)." : "jti is REQUIRED: a unique id for this ID-JAG.");

  const skew = DEFAULT_CLOCK_SKEW_SECONDS;
  if (!isNumericDate(claims.exp)) add("claim.exp", "MUST", `${D("3.1")}; RFC 7519 section 4.1.4`, "fail", "exp is REQUIRED: a NumericDate (seconds).");
  else if (!Number.isInteger(claims.exp)) add("claim.exp", "POLICY", "RFC 7519 section 2", "fail", "exp has a fraction: this receiver requires whole seconds.");
  else add("claim.exp", "MUST", `${D("3.1")}; RFC 7519 section 4.1.4`, claims.exp > input.now - skew ? "pass" : "fail", claims.exp > input.now - skew ? `Not expired (${Math.round(claims.exp - input.now)} s left).` : `Expired ${Math.round(input.now - claims.exp)} s ago.`);
  if (!isNumericDate(claims.iat)) add("claim.iat", "MUST", `${D("3.1")}; RFC 7519 section 4.1.6`, "fail", "iat is REQUIRED: a NumericDate (seconds).");
  else if (!Number.isInteger(claims.iat)) add("claim.iat", "POLICY", "RFC 7519 section 2", "fail", "iat has a fraction: this receiver requires whole seconds.");
  else add("claim.iat", "MUST", `${D("3.1")}; RFC 7519 section 4.1.6`, claims.iat <= input.now + skew ? "pass" : "fail", claims.iat <= input.now + skew ? "iat is not in the future." : `iat is ${Math.round(claims.iat - input.now)} s in the future: check your clock.`);
  if (isNumericDate(claims.exp) && isNumericDate(claims.iat)) {
    const life = claims.exp - claims.iat;
    add("claim.lifetime", "POLICY", D("4.3.4"), life > 0 && life <= MAX_LIFETIME_SECONDS ? "pass" : "fail", life > 0 && life <= MAX_LIFETIME_SECONDS ? `Lifetime ${life} s (this receiver allows at most ${MAX_LIFETIME_SECONDS}; the draft's example is 300).` : `Lifetime ${life} s: this receiver allows more than 0 and at most ${MAX_LIFETIME_SECONDS} s. ID-JAGs are meant to be short-lived.`);
  }
  if (claims.nbf !== undefined) add("claim.nbf", "OPTIONAL", "RFC 7519 section 4.1.5", isNumericDate(claims.nbf) && claims.nbf <= input.now + skew ? "pass" : "fail", isNumericDate(claims.nbf) && claims.nbf <= input.now + skew ? "nbf has passed." : "nbf must be a NumericDate that has passed.");

  // resource: optional; if present, every identifier must be one this receiver governs.
  const resource = claims.resource;
  if (resource === undefined) add("claim.resource", "OPTIONAL", D("3.1, 4.4.1"), "info", `No resource: this receiver then uses its default resource, ${show(input.resource)} (allowed: MAY select a default).`);
  else {
    const list = typeof resource === "string" ? [resource] : Array.isArray(resource) ? resource : null;
    if (!list || list.length === 0 || list.some((r) => typeof r !== "string") || new Set(list).size !== list.length) add("claim.resource", "MUST", D("3.1"), "fail", "resource must be a string, or a non-empty JSON array of unique strings.");
    else {
      const foreign = list.filter((r) => r !== input.resource);
      add("claim.resource", "MUST", D("4.4.1"), foreign.length === 0 ? "pass" : "fail", foreign.length === 0 ? "resource names this receiver's MCP server." : `Every resource must be one this receiver governs (${show(input.resource)}); not: ${foreign.map(show).join(", ")}.`);
    }
  }

  // scope: optional in the claim, but an ID-JAG without it grants nothing (section 4.3.3: "the granted values, if any").
  const scope = claims.scope;
  if (scope === undefined) add("claim.scope", "POLICY", D("4.3.3, 4.4.1"), "fail", `No scope: the IdP includes the scopes it granted, so none were granted, and this receiver refuses (no_scope). Ask your IdP for ${input.grantableScopes.join(" ")}.`);
  else if (typeof scope !== "string") add("claim.scope", "MUST", `${D("3.1")}; RFC 6749 section 3.3`, "fail", "scope must be one string of space-separated scopes, not an array.");
  else {
    const granted = scope.split(" ").filter((s) => input.grantableScopes.includes(s));
    add("claim.scope", "POLICY", `${D("4.4.1")}; RFC 6749 section 3.3`, granted.length > 0 ? "pass" : "fail", granted.length > 0 ? `scope ${show(scope)}; this receiver grants ${granted.join(" ")}.` : `scope ${show(scope)} includes nothing this receiver grants (${input.grantableScopes.join(" ")}).`);
  }

  if (claims.authorization_details !== undefined) add("claim.authorization_details", "POLICY", D("4.4.1"), "fail", "authorization_details (Rich Authorization Requests): this receiver refuses them for now.");
  if (claims.tenant !== undefined) add("claim.tenant", "OPTIONAL", D("3.1, 6.1"), typeof claims.tenant === "string" ? "info" : "fail", typeof claims.tenant === "string" ? "tenant is present: your issuer is multi-tenant." : "tenant must be a JSON string.");
  if (claims.act !== undefined) add("claim.act", "OPTIONAL", `${D("9.10")}; RFC 8693 section 4.1`, isObject(claims.act) && isNonEmptyString(claims.act.sub) ? "info" : "fail", isObject(claims.act) && isNonEmptyString(claims.act.sub) ? `act names an actor (${show(claims.act.sub)}): the receiver carries it into the access token.` : "act must be an object with a sub.");
  if (claims.sub_id !== undefined) add("claim.sub_id", "OPTIONAL", `${D("3.2")}; RFC 9493`, isObject(claims.sub_id) && isNonEmptyString(claims.sub_id.format) ? "info" : "fail", isObject(claims.sub_id) && isNonEmptyString(claims.sub_id.format) ? `sub_id (format ${show(claims.sub_id.format)}): subject lookup depends on the receiver's configuration (by sub, or by sub_id where it maps a SAML NameID).` : "sub_id must be an object with a format (RFC 9493).");
  if (claims.cnf !== undefined) add("claim.cnf", "POLICY", D("9.11.1.2"), "fail", "cnf (a sender-constrained ID-JAG): this receiver doesn't support proof of possession at redemption, so it refuses.");
  if (claims.email === undefined && claims.aud_sub === undefined) add("claim.email_or_aud_sub", "RECOMMENDED", D("3.1"), "warn", "Neither email nor aud_sub: RECOMMENDED, so a receiver can find or create the user.");
  else add("claim.email_or_aud_sub", "RECOMMENDED", D("3.1"), "pass", "email or aud_sub is present.");
  if (claims.auth_time !== undefined && !isNumericDate(claims.auth_time)) add("claim.auth_time", "OPTIONAL", `${D("3.1")}; OpenID Connect Core`, "fail", "auth_time must be a NumericDate.");
  if (claims.acr !== undefined && typeof claims.acr !== "string") add("claim.acr", "OPTIONAL", `${D("3.1")}; OpenID Connect Core`, "fail", "acr must be a string.");
  if (claims.amr !== undefined && !(Array.isArray(claims.amr) && claims.amr.every((a) => typeof a === "string"))) add("claim.amr", "OPTIONAL", `${D("3.1")}; OpenID Connect Core`, "fail", "amr must be an array of strings.");

  // The receiver's own parser, as a last check: whatever it refuses on shape, the report says so even if no rule
  // above caught it.
  try {
    parseIdJag(token);
    add("receiver.parse", "MUST", "this receiver", "pass", "The receiver's parser accepts the header and claims.");
  } catch (e) {
    const reason = (e as { reason?: unknown }).reason;
    add("receiver.parse", "MUST", "this receiver", "fail", `The receiver's parser refuses it: ${typeof reason === "string" ? reason : "malformed"}.`);
  }

  return { header, claims, results };
}

/**
 * The keys the receiver would try, as it chooses them: signing keys only (no "use": "enc", key_ops allowing verify),
 * by kid when the header names one, else by certificate thumbprint.
 */
async function signingKeys(jwks: JSONWebKeySet, header: Record<string, unknown>): Promise<JWK[]> {
  const keys = (Array.isArray(jwks.keys) ? jwks.keys : []).filter((k) => isObject(k) && (k.use === undefined || k.use === "sig") && (k.key_ops === undefined || (Array.isArray(k.key_ops) && k.key_ops.includes("verify")))).map((k) => (k.key_ops === undefined ? k : { ...k, key_ops: ["verify"] })) as JWK[];
  if (isNonEmptyString(header.kid)) return keys.filter((k) => k.kid === header.kid);
  const out: JWK[] = [];
  for (const k of keys) {
    const cert = Array.isArray(k.x5c) && typeof k.x5c[0] === "string" ? k.x5c[0] : undefined;
    // A certificate that isn't base64 gives no thumbprints (as the receiver's own key selection, src/receiver/jwks.ts),
    // so one bad entry, even on an unrelated key, can't stop the report.
    let der: Uint8Array<ArrayBuffer> | undefined;
    try {
      der = cert ? Uint8Array.from(atob(cert), (c) => c.charCodeAt(0)) : undefined;
    } catch {
      der = undefined;
    }
    const b64url = (b: ArrayBuffer) => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const x5t = (k as { x5t?: string }).x5t ?? (der ? b64url(await crypto.subtle.digest("SHA-1", der)) : undefined);
    const x5tS256 = (k as { "x5t#S256"?: string })["x5t#S256"] ?? (der ? b64url(await crypto.subtle.digest("SHA-256", der)) : undefined);
    if ((header["x5t#S256"] !== undefined && x5tS256 === header["x5t#S256"]) || (header.x5t !== undefined && x5t === header.x5t)) out.push(k);
  }
  return out;
}

/** What a registration found at the issuer: its metadata document and its JWKS. */
export interface MetadataCheckInput {
  issuer: string;
  /** Which well-known location answered: RFC 8414's, or OpenID Connect Discovery's (the fallback). */
  source: "oauth-authorization-server" | "openid-configuration";
  /** The metadata document as fetched: anything that isn't a JSON object fails metadata.issuer (and blocks). */
  metadata: unknown;
  jwks: unknown;
}

/** Checks the issuer's metadata and keys at registration. `blocking` lists the rules that stop a registration. */
export function checkIssuerMetadata(input: MetadataCheckInput): { results: RuleResult[]; blocking: string[] } {
  const results: RuleResult[] = [];
  const add = (id: string, level: RuleLevel, cite: string, outcome: RuleOutcome, message: string) => results.push({ id, level, cite, outcome, message });
  // Metadata as fetched can be any JSON (null, an array, a string): read as an empty document, so every rule still
  // reports, and metadata.issuer says why it fails.
  const metadataIsObject = isObject(input.metadata);
  const m: Record<string, unknown> = isObject(input.metadata) ? input.metadata : {};

  add("metadata.location", "SHOULD", `${D("7.1")}; RFC 8414 section 3`, input.source === "oauth-authorization-server" ? "pass" : "warn", input.source === "oauth-authorization-server" ? "Found at RFC 8414's location." : "Found only at OpenID Connect Discovery's location: allowed as a fallback (MAY), but RFC 8414's is what receivers SHOULD use.");
  add("metadata.issuer", "MUST", "RFC 8414 section 3.3", m.issuer === input.issuer ? "pass" : "fail", m.issuer === input.issuer ? "The metadata's issuer is exactly the issuer you entered." : metadataIsObject ? `The metadata's issuer must be exactly ${show(input.issuer)}; it is ${show(m.issuer)}.` : `The metadata must be a JSON object with an issuer of exactly ${show(input.issuer)}; it is ${show(input.metadata)}.`);
  const jwksUri = m.jwks_uri;
  add("metadata.jwks_uri", "POLICY", D("7.1"), typeof jwksUri === "string" && jwksUri.startsWith("https://") ? "pass" : "fail", typeof jwksUri === "string" && jwksUri.startsWith("https://") ? "jwks_uri is an https URL." : `jwks_uri must be an https URL; it is ${show(jwksUri)}.`);
  const chaining = m[ISSUER_METADATA_FIELD];
  add("metadata.token_types", "SHOULD", D("7.1"), Array.isArray(chaining) && chaining.includes(ID_JAG_TOKEN_TYPE) ? "pass" : "warn", Array.isArray(chaining) && chaining.includes(ID_JAG_TOKEN_TYPE) ? `${ISSUER_METADATA_FIELD} lists ${ID_JAG_TOKEN_TYPE}.` : `${ISSUER_METADATA_FIELD} SHOULD list ${ID_JAG_TOKEN_TYPE}, so clients can tell you issue ID-JAGs.`);
  const algs = m[ISSUER_SIGNING_ALG_METADATA_FIELD];
  if (algs === undefined) add("metadata.signing_algs", "OPTIONAL", D("7.1"), "info", `${ISSUER_SIGNING_ALG_METADATA_FIELD} is absent (optional).`);
  else add("metadata.signing_algs", "MUST", D("7.1"), Array.isArray(algs) && algs.includes("RS256") ? "pass" : "fail", Array.isArray(algs) && algs.includes("RS256") ? `${ISSUER_SIGNING_ALG_METADATA_FIELD} includes RS256.` : `${ISSUER_SIGNING_ALG_METADATA_FIELD}, if present, MUST include RS256.`);

  const keys = isObject(input.jwks) && Array.isArray(input.jwks.keys) ? (input.jwks.keys as unknown[]) : null;
  add("jwks.keys", "MUST", "RFC 7517 section 5", keys && keys.length > 0 ? "pass" : "fail", keys && keys.length > 0 ? `Your JWKS has ${keys.length} key(s).` : "Your JWKS must be a JSON object with a non-empty keys array.");
  const privateMembers = ["d", "p", "q", "dp", "dq", "qi", "k", "oth"];
  const leaking = (keys ?? []).filter((k) => isObject(k) && privateMembers.some((p) => p in k));
  add("jwks.no_private", "MUST", "RFC 7517 section 9.2", leaking.length === 0 ? "pass" : "fail", leaking.length === 0 ? "No private or symmetric key material is published." : `Your JWKS publishes private or symmetric key material in ${leaking.length} key(s). Remove it and rotate those keys now.`);
  const usable = (keys ?? []).filter((k) => isObject(k) && (k.kty === "RSA" || k.kty === "EC" || k.kty === "OKP"));
  add("jwks.usable", "MUST", D("3"), usable.length > 0 ? "pass" : "fail", usable.length > 0 ? "At least one RSA, EC or OKP key." : "No RSA, EC or OKP key: nothing could verify an ID-JAG.");
  const noKid = usable.filter((k) => isObject(k) && !isNonEmptyString(k.kid));
  if (usable.length > 0) add("jwks.kid", "OPTIONAL", "RFC 7517 section 4.5", noKid.length === 0 ? "pass" : "warn", noKid.length === 0 ? "Every key has a kid." : `${noKid.length} key(s) have no kid: receivers then have to try each key.`);

  const blocking = results.filter((r) => r.outcome === "fail" && ["metadata.issuer", "metadata.jwks_uri", "jwks.keys", "jwks.no_private", "jwks.usable"].includes(r.id)).map((r) => r.id);
  return { results, blocking };
}

/** The IdP's answer to a token exchange for an ID-JAG, as the client received it (draft -06 section 4.3.4). */
export interface ExchangeCheckInput {
  /** The HTTP status. */
  status: number;
  /** The answer's Content-Type header, or null when it has none. */
  contentType: string | null;
  /** The answer's Cache-Control header, or null when it has none. */
  cacheControl: string | null;
  /** The body, parsed as JSON; undefined when it isn't JSON. */
  body: unknown;
  /** The scope the client sent, or undefined when it sent none. */
  requestedScope: string | undefined;
  /** The resource values the client sent, as sent (empty when it sent none). */
  requestedResources: readonly string[];
}

export interface ExchangeReport {
  results: RuleResult[];
  /** The ID-JAG (the answer's access_token), for checkIdJag; null when the answer has none. */
  idJag: string | null;
  /** The IdP's OAuth error, when it refused (RFC 6749 section 5.2). */
  error: { code: string; description: string | null } | null;
}

const scopeSet = (s: string) => new Set(s.split(" ").filter(Boolean));
const sameScopes = (a: string, b: string) => {
  const x = scopeSet(a);
  const y = scopeSet(b);
  return x.size === y.size && [...x].every((s) => y.has(s));
};
/** How far expires_in may be from the ID-JAG's exp - iat before the report says so (the two are measured apart). */
const EXPIRES_IN_TOLERANCE_SECONDS = 5;

/**
 * Checks an IdP's answer to a token exchange for an ID-JAG: the answer's own rules. The ID-JAG in it is checked with
 * checkIdJag. Pure; never throws.
 */
export function checkExchange(input: ExchangeCheckInput): ExchangeReport {
  const results: RuleResult[] = [];
  const add = (id: string, level: RuleLevel, cite: string, outcome: RuleOutcome, message: string) => results.push({ id, level, cite, outcome, message });
  const body = isObject(input.body) ? input.body : null;
  const statusCite = `${D("4.3.4")}; RFC 8693 section 2.2.1`;

  if (input.status !== 200) {
    const code = body && isNonEmptyString(body.error) ? body.error : null;
    const description = body && typeof body.error_description === "string" ? body.error_description : null;
    add("exchange.status", "MUST", statusCite, "fail", code ? `The IdP refused the exchange (HTTP ${input.status}, error ${show(code)}${description === null ? "" : `, ${show(description)}`}), so there is no answer to check. If it should allow this client this audience and resource, look at its policy.` : `The IdP answered HTTP ${input.status} without an OAuth error response (RFC 6749 section 5.2), so there is no answer to check.`);
    return { results, idJag: null, error: code ? { code, description } : null };
  }
  if (!body) {
    add("exchange.status", "MUST", statusCite, "fail", "HTTP 200, but the body isn't a JSON object.");
    return { results, idJag: null, error: null };
  }
  const json = /^application\/json\s*(;|$)/i.test(input.contentType ?? "");
  add("exchange.status", "MUST", `${statusCite}; RFC 6749 section 5.1`, json ? "pass" : "fail", json ? "HTTP 200 with a JSON object." : `HTTP 200 with a JSON object, but Content-Type is ${show(input.contentType)}: it must be application/json.`);

  add("exchange.issued_token_type", "MUST", D("4.3.4"), body.issued_token_type === ID_JAG_TOKEN_TYPE ? "pass" : "fail", body.issued_token_type === ID_JAG_TOKEN_TYPE ? `issued_token_type is ${ID_JAG_TOKEN_TYPE}.` : `issued_token_type is REQUIRED: ${ID_JAG_TOKEN_TYPE}; it is ${show(body.issued_token_type)}.`);
  // token_type is case-insensitive (RFC 6749 section 5.1).
  const nA = typeof body.token_type === "string" && body.token_type.toLowerCase() === "n_a";
  add("exchange.token_type", "MUST", `${D("4.3.4")}; RFC 8693 section 2.2.1`, nA ? "pass" : "fail", nA ? "token_type is N_A (an ID-JAG isn't an access token)." : `token_type is REQUIRED: N_A, because an ID-JAG isn't an access token; it is ${show(body.token_type)}.`);

  const idJag = isNonEmptyString(body.access_token) ? body.access_token : null;
  add("exchange.access_token", "MUST", D("4.3.4"), idJag ? "pass" : "fail", idJag ? "access_token holds the ID-JAG (its own rules are below)." : "access_token is REQUIRED: the ID-JAG, as a string.");

  // The ID-JAG's claims, read without checking them (checkIdJag does), to compare with the answer.
  const parts = idJag && idJag.length <= MAX_TOKEN_CHARS ? idJag.split(".") : [];
  const claims = parts.length === 3 ? decodePart(parts[1] as string) : null;
  const unreadable = "Not compared: the ID-JAG's claims couldn't be read.";

  // scope: OPTIONAL when the granted scope is the requested one, REQUIRED otherwise; it describes the same grant as the
  // ID-JAG's scope claim, which carries the granted values (section 4.3.3).
  const scopeCite = `${D("4.3.4")}; RFC 6749 section 5.1`;
  const issued = claims && typeof claims.scope === "string" ? claims.scope : undefined;
  if (body.scope !== undefined && typeof body.scope !== "string") add("exchange.scope", "MUST", scopeCite, "fail", "scope must be one string of space-separated scopes.");
  else if (!claims) add("exchange.scope", "MUST", scopeCite, "skip", unreadable);
  else if (typeof body.scope === "string") {
    if (issued === undefined) add("exchange.scope", "MUST", `${D("4.3.3")}; ${scopeCite}`, "fail", `The answer grants scope ${show(body.scope)}, but the ID-JAG has no scope claim: the IdP includes the granted values in it.`);
    else add("exchange.scope", "MUST", scopeCite, sameScopes(body.scope, issued) ? "pass" : "fail", sameScopes(body.scope, issued) ? `scope ${show(body.scope)}, the same as the ID-JAG's.` : `The answer's scope ${show(body.scope)} isn't the ID-JAG's scope ${show(issued)}: both name the scopes granted.`);
  } else {
    const same = sameScopes(input.requestedScope ?? "", issued ?? "");
    add("exchange.scope", "MUST", scopeCite, same ? "pass" : "fail", same ? "No scope in the answer, and the ID-JAG's scope is the one requested (scope is then OPTIONAL)." : `scope is REQUIRED in the answer when the granted scope differs from the requested one: requested ${show(input.requestedScope ?? "")}, granted ${show(issued ?? "")}.`);
  }

  const expiresIn = body.expires_in;
  if (expiresIn === undefined) add("exchange.expires_in", "RECOMMENDED", D("4.3.4"), "warn", "No expires_in: RECOMMENDED, the ID-JAG's lifetime in seconds.");
  else if (typeof expiresIn !== "number" || !Number.isInteger(expiresIn) || expiresIn <= 0) add("exchange.expires_in", "RECOMMENDED", `${D("4.3.4")}; RFC 6749 section 5.1`, "fail", `expires_in must be a positive whole number of seconds; it is ${show(expiresIn)}.`);
  else if (!claims || !isNumericDate(claims.exp) || !isNumericDate(claims.iat)) add("exchange.expires_in", "RECOMMENDED", D("4.3.4"), "pass", `expires_in ${expiresIn} s (not compared: the ID-JAG's exp or iat couldn't be read).`);
  else {
    const life = claims.exp - claims.iat;
    const close = Math.abs(expiresIn - life) <= EXPIRES_IN_TOLERANCE_SECONDS;
    add("exchange.expires_in", "RECOMMENDED", D("4.3.4"), close ? "pass" : "warn", close ? `expires_in ${expiresIn} s, the ID-JAG's lifetime.` : `expires_in ${expiresIn} s, but the ID-JAG's lifetime (exp - iat) is ${life} s.`);
  }

  add("exchange.refresh_token", "SHOULD", `${D("4.3.4")}; RFC 8693 section 2.2.1`, body.refresh_token === undefined ? "pass" : "warn", body.refresh_token === undefined ? "No refresh_token." : "The answer has a refresh_token: SHOULD NOT be used with an ID-JAG.");

  const noStore = (input.cacheControl ?? "").split(",").some((d) => d.trim().toLowerCase() === "no-store");
  add("exchange.no_store", "MUST", `${D("4.3.4")}; RFC 6749 section 5.1`, noStore ? "pass" : "fail", noStore ? "Cache-Control: no-store." : `An answer with a token MUST have Cache-Control: no-store; it has ${show(input.cacheControl)}.`);

  // resource: each requested resource the IdP grants appears in the claim exactly as sent; granting none is refused
  // (invalid_target), so an answer to a request with resource grants at least one.
  const echoCite = D("4.3.3");
  if (input.requestedResources.length === 0) add("exchange.resource_echo", "OPTIONAL", echoCite, "info", "No resource was requested: the IdP MAY choose a default one.");
  else if (!claims) add("exchange.resource_echo", "MUST", echoCite, "skip", unreadable);
  else {
    const r = claims.resource;
    const list = typeof r === "string" ? [r] : Array.isArray(r) ? r : null;
    const notSent = (list ?? []).filter((x) => typeof x !== "string" || !input.requestedResources.includes(x));
    if (!list || list.length === 0) add("exchange.resource_echo", "MUST", echoCite, "fail", `resource was requested (${input.requestedResources.map(show).join(", ")}) and the exchange succeeded, but the ID-JAG has no resource claim: the IdP includes each granted resource in it.`);
    else add("exchange.resource_echo", "MUST", echoCite, notSent.length === 0 ? "pass" : "fail", notSent.length === 0 ? "Each resource in the ID-JAG is one the client sent, exactly as sent." : `Each granted resource must appear exactly as the client sent it (${input.requestedResources.map(show).join(", ")}); not as sent: ${notSent.map(show).join(", ")}.`);
  }

  return { results, idJag, error: null };
}
