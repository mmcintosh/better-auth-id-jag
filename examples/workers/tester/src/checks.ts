// Every rule an ID-JAG is held to, each with its outcome and the draft -06 section it comes from. The receiver
// stops at the first refusal; this runs them all, so an IdP builder sees everything wrong at once. It is a report,
// never a gate: the tester still sends the request to the real receiver, whose decision is what counts.
//
// Pure: no network, no clock of its own. The caller passes the issuer's JWKS and the time.
import { compactVerify, createLocalJWKSet, decodeProtectedHeader, type JSONWebKeySet } from "jose";
import { ALLOWED_ALGORITHMS, DEFAULT_CLOCK_SKEW_SECONDS, ID_JAG_TOKEN_TYPE, ID_JAG_TYP, ISSUER_METADATA_FIELD, ISSUER_SIGNING_ALG_METADATA_FIELD, MAX_LIFETIME_SECONDS } from "better-auth-id-jag";

/** MUST and friends from the draft; POLICY is this receiver's own choice, which the draft allows. */
export type Level = "MUST" | "SHOULD" | "RECOMMENDED" | "OPTIONAL" | "POLICY";
/** fail: the receiver refuses, or must. warn: allowed, but not what the draft recommends. info: worth knowing. */
export type Outcome = "pass" | "fail" | "warn" | "info" | "skip";

export interface RuleResult {
  id: string;
  level: Level;
  /** Where the rule comes from, for example "draft -06 section 4.4.1". */
  cite: string;
  outcome: Outcome;
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
/** A value as the report shows it: short, and never more than one line. */
export const show = (v: unknown): string => {
  let s: string;
  try {
    s = typeof v === "string" ? JSON.stringify(v) : (JSON.stringify(v) ?? String(v));
  } catch {
    s = String(v);
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
  const add = (id: string, level: Level, cite: string, outcome: Outcome, message: string) => results.push({ id, level, cite, outcome, message });

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
  add("header.typ", "MUST", D("4.4.1, 3.1"), header.typ === ID_JAG_TYP ? "pass" : "fail", header.typ === ID_JAG_TYP ? `typ is ${ID_JAG_TYP}.` : `typ must be ${ID_JAG_TYP}; it is ${show(header.typ)}.`);
  const alg = header.alg;
  const algAllowed = typeof alg === "string" && (ALLOWED_ALGORITHMS as readonly string[]).includes(alg);
  add("header.alg", "POLICY", D("3, 4.4.1"), algAllowed ? "pass" : "fail", algAllowed ? `alg ${alg}, which this receiver accepts (${ALLOWED_ALGORITHMS.join(", ")}).` : `alg ${show(alg)} is not accepted here (${ALLOWED_ALGORITHMS.join(", ")}); never none or HS*.`);
  if (algAllowed && alg !== "RS256") add("header.alg.rs256", "MUST", D("3"), "info", "RS256 is mandatory to implement for IdPs and receivers; this ID-JAG uses another algorithm, which receivers SHOULD (ES256) or may accept.");
  add("header.kid", "OPTIONAL", "RFC 7515 section 4.1.4", isNonEmptyString(header.kid) ? "pass" : "warn", isNonEmptyString(header.kid) ? "kid names the signing key." : "No kid: a receiver has to try every key in your JWKS. Name the key, so key rotation works.");

  // Signature, with the issuer's published keys.
  if (!input.jwks) add("signature", "MUST", D("4.4.1") + "; RFC 7521 section 5.2", "skip", "Your JWKS couldn't be fetched, so the signature wasn't checked.");
  else if (!algAllowed) add("signature", "MUST", D("4.4.1") + "; RFC 7521 section 5.2", "fail", "Not checked: the algorithm isn't accepted.");
  else {
    try {
      decodeProtectedHeader(token);
      await compactVerify(token, createLocalJWKSet(input.jwks), { algorithms: [...ALLOWED_ALGORITHMS] });
      add("signature", "MUST", D("4.4.1") + "; RFC 7521 section 5.2", "pass", "The signature verifies with a key from your JWKS.");
    } catch (e) {
      const code = (e as { code?: string }).code;
      const why = code === "ERR_JWKS_NO_MATCHING_KEY" ? "no key in your JWKS matches (kid, alg and key type)" : code === "ERR_JWKS_MULTIPLE_MATCHING_KEYS" ? "several keys match and none verifies" : "it doesn't verify with the matching key";
      add("signature", "MUST", D("4.4.1") + "; RFC 7521 section 5.2", "fail", `The signature fails: ${why}.`);
    }
  }

  // Claims (section 3.1), and the receiver's processing rules (section 4.4.1).
  add("claim.iss", "MUST", D("3.1, 4.4.1"), claims.iss === input.issuer ? "pass" : "fail", claims.iss === input.issuer ? "iss is your registered issuer." : `iss must be exactly your registered issuer ${show(input.issuer)}; it is ${show(claims.iss)}.`);
  add("claim.sub", "MUST", D("3.1"), isNonEmptyString(claims.sub) ? "pass" : "fail", isNonEmptyString(claims.sub) ? "sub is present." : "sub is REQUIRED: a non-empty string.");

  const aud = claims.aud;
  const audOk = aud === input.audience || (Array.isArray(aud) && aud.length === 1 && aud[0] === input.audience);
  add("claim.aud", "MUST", D("4.4.1"), audOk ? "pass" : "fail", audOk ? "aud is this receiver's issuer identifier." : Array.isArray(aud) && aud.length > 1 ? `aud as an array must have exactly one element, ${show(input.audience)}; it has ${aud.length}.` : `aud must be this receiver's issuer identifier ${show(input.audience)} (the authorization server, not the resource); it is ${show(aud)}.`);

  if (!isNonEmptyString(claims.client_id)) add("claim.client_id", "MUST", D("3.1"), "fail", "client_id is REQUIRED: the client's id at this receiver.");
  else if (input.clientId === undefined) add("claim.client_id", "MUST", D("4.4.1"), "skip", "client_id is present; the request's client wasn't known, so it wasn't compared.");
  else add("claim.client_id", "MUST", D("4.4.1"), claims.client_id === input.clientId ? "pass" : "fail", claims.client_id === input.clientId ? "client_id is the client that authenticated." : `client_id must be the client that authenticated (${show(input.clientId)}); it is ${show(claims.client_id)}. Use the client id this tester gave you, not your IdP's own.`);

  add("claim.jti", "MUST", D("3.1"), isNonEmptyString(claims.jti) ? "pass" : "fail", isNonEmptyString(claims.jti) ? "jti is present (each ID-JAG works once here)." : "jti is REQUIRED: a unique id for this ID-JAG.");

  const skew = DEFAULT_CLOCK_SKEW_SECONDS;
  if (!isNumericDate(claims.exp)) add("claim.exp", "MUST", D("3.1") + "; RFC 7519 section 4.1.4", "fail", "exp is REQUIRED: a NumericDate (seconds).");
  else add("claim.exp", "MUST", D("3.1") + "; RFC 7519 section 4.1.4", claims.exp > input.now - skew ? "pass" : "fail", claims.exp > input.now - skew ? `Not expired (${Math.round(claims.exp - input.now)} s left).` : `Expired ${Math.round(input.now - claims.exp)} s ago.`);
  if (!isNumericDate(claims.iat)) add("claim.iat", "MUST", D("3.1") + "; RFC 7519 section 4.1.6", "fail", "iat is REQUIRED: a NumericDate (seconds).");
  else add("claim.iat", "MUST", D("3.1") + "; RFC 7519 section 4.1.6", claims.iat <= input.now + skew ? "pass" : "fail", claims.iat <= input.now + skew ? "iat is not in the future." : `iat is ${Math.round(claims.iat - input.now)} s in the future: check your clock.`);
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
  else if (typeof scope !== "string") add("claim.scope", "MUST", D("3.1") + "; RFC 6749 section 3.3", "fail", "scope must be one string of space-separated scopes, not an array.");
  else {
    const granted = scope.split(" ").filter((s) => input.grantableScopes.includes(s));
    add("claim.scope", "POLICY", D("4.4.1") + "; RFC 6749 section 3.3", granted.length > 0 ? "pass" : "fail", granted.length > 0 ? `scope ${show(scope)}; this receiver grants ${granted.join(" ")}.` : `scope ${show(scope)} includes nothing this receiver grants (${input.grantableScopes.join(" ")}).`);
  }

  if (claims.authorization_details !== undefined) add("claim.authorization_details", "POLICY", D("4.4.1"), "fail", "authorization_details (Rich Authorization Requests): this receiver refuses them for now.");
  if (claims.tenant !== undefined) add("claim.tenant", "OPTIONAL", D("3.1, 6.1"), typeof claims.tenant === "string" ? "info" : "fail", typeof claims.tenant === "string" ? "tenant is present: your issuer is multi-tenant. This tester registers single-tenant issuers." : "tenant must be a JSON string.");
  if (claims.act !== undefined) add("claim.act", "OPTIONAL", D("9.10") + "; RFC 8693 section 4.1", isObject(claims.act) && isNonEmptyString(claims.act.sub) ? "info" : "fail", isObject(claims.act) && isNonEmptyString(claims.act.sub) ? `act names an actor (${show(claims.act.sub)}): the receiver carries it into the access token.` : "act must be an object with a sub.");
  if (claims.sub_id !== undefined) add("claim.sub_id", "OPTIONAL", D("3.2") + "; RFC 9493", isObject(claims.sub_id) && isNonEmptyString(claims.sub_id.format) ? "info" : "fail", isObject(claims.sub_id) && isNonEmptyString(claims.sub_id.format) ? `sub_id (format ${show(claims.sub_id.format)}): this tester resolves users by sub only.` : "sub_id must be an object with a format (RFC 9493).");
  if (claims.cnf !== undefined) add("claim.cnf", "OPTIONAL", D("9.11"), "info", "cnf: the ID-JAG is sender-constrained, so the redemption needs proof of possession (DPoP).");
  if (claims.email === undefined && claims.aud_sub === undefined) add("claim.email_or_aud_sub", "RECOMMENDED", D("3.1"), "warn", "Neither email nor aud_sub: RECOMMENDED, so a receiver can find or create the user. (This tester doesn't need them.)");
  else add("claim.email_or_aud_sub", "RECOMMENDED", D("3.1"), "pass", "email or aud_sub is present.");
  if (claims.auth_time !== undefined && !isNumericDate(claims.auth_time)) add("claim.auth_time", "OPTIONAL", D("3.1") + "; OpenID Connect Core", "fail", "auth_time must be a NumericDate.");
  if (claims.acr !== undefined && typeof claims.acr !== "string") add("claim.acr", "OPTIONAL", D("3.1") + "; OpenID Connect Core", "fail", "acr must be a string.");
  if (claims.amr !== undefined && !(Array.isArray(claims.amr) && claims.amr.every((a) => typeof a === "string"))) add("claim.amr", "OPTIONAL", D("3.1") + "; OpenID Connect Core", "fail", "amr must be an array of strings.");

  return { header, claims, results };
}

/** What a registration found at the issuer: its metadata document and its JWKS. */
export interface MetadataCheckInput {
  issuer: string;
  /** Which well-known location answered: RFC 8414's, or OpenID Connect Discovery's (the fallback). */
  source: "oauth-authorization-server" | "openid-configuration";
  metadata: Record<string, unknown>;
  jwks: unknown;
}

/** Checks the issuer's metadata and keys at registration. `blocking` lists the rules that stop a registration. */
export function checkIssuerMetadata(input: MetadataCheckInput): { results: RuleResult[]; blocking: string[] } {
  const results: RuleResult[] = [];
  const add = (id: string, level: Level, cite: string, outcome: Outcome, message: string) => results.push({ id, level, cite, outcome, message });
  const m = input.metadata;

  add("metadata.location", "SHOULD", D("7.1") + "; RFC 8414 section 3", input.source === "oauth-authorization-server" ? "pass" : "warn", input.source === "oauth-authorization-server" ? "Found at RFC 8414's location." : "Found only at OpenID Connect Discovery's location: allowed as a fallback (MAY), but RFC 8414's is what receivers SHOULD use.");
  add("metadata.issuer", "MUST", "RFC 8414 section 3.3", m.issuer === input.issuer ? "pass" : "fail", m.issuer === input.issuer ? "The metadata's issuer is exactly the issuer you entered." : `The metadata's issuer must be exactly ${show(input.issuer)}; it is ${show(m.issuer)}.`);
  const jwksUri = m.jwks_uri;
  add("metadata.jwks_uri", "SHOULD", D("7.1"), typeof jwksUri === "string" && jwksUri.startsWith("https://") ? "pass" : "fail", typeof jwksUri === "string" && jwksUri.startsWith("https://") ? "jwks_uri is an https URL." : `jwks_uri must be an https URL; it is ${show(jwksUri)}.`);
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
