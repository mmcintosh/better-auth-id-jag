// Subject token: a SAML 2.0 Assertion **this IdP** issued (better-auth-saml-idp), as RFC 8693 §3's
// `urn:ietf:params:oauth:token-type:saml2` (draft -04 §4.3.1 for an ID-JAG, §4.5 for a refresh
// token). D-B26, D-B27.
//
// We only decode. Everything about the Assertion itself (XML hardening, our signature on the
// Assertion, the issuer and its key, the shape, the validity window, the SP → client mapping, the
// single-use record, the principal) is the SAML IdP's `verifyIssuedAssertion`, which only it can
// do: it holds the keys, the SP directory and the record written at issuance. We pass it the
// **authenticated** client's id, never one the caller named.
//
// Its refusals map onto ours (S8: one generic body for all but the time window, which the caller
// can read from its own Assertion):
//   ALREADY_EXCHANGED → replay; EXPIRED → subject_token_expired; NOT_YET_VALID → not_yet_valid;
//   MALFORMED, NOT_OURS, BAD_SIGNATURE, NOT_EXCHANGEABLE, WRONG_CLIENT, ACCOUNT_INACTIVE, an
//   unknown code, any other throw, and a malformed result → invalid_subject_token (detail: why).
import type { GenericEndpointContext } from "better-auth";
import { z } from "zod";
import { refuse } from "../../core";
import { assertionExchangeErrorCode, getSamlIdpExchange, MAX_ASSERTION_BYTES, type VerifiedAssertion } from "../saml-exchange";

/**
 * The longest `subject_token` accepted for saml2, in characters: padded base64 of the SAML IdP's
 * MAX_ASSERTION_BYTES (65536 bytes → 87384 characters). Assertions with attributes outgrow the
 * 16 KiB JWT cap. The decoded XML is also held to MAX_ASSERTION_BYTES.
 */
export const MAX_SAML2_TOKEN_LENGTH = Math.ceil(MAX_ASSERTION_BYTES / 3) * 4;

const bad = (detail: string): never => refuse("invalid_subject_token", `saml2: ${detail}`);

const URL_SAFE = /^[A-Za-z0-9_-]+={0,2}$/;
const STANDARD = /^[A-Za-z0-9+/]+={0,2}$/;
const utf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/**
 * The Assertion's XML from a `subject_token`: base64url (RFC 8693 §3; padding optional, correct
 * when present) or padded standard base64 (the draft's example), never a mix of the two alphabets;
 * * no whitespace; canonical (no stray bits); at most MAX_SAML2_TOKEN_LENGTH characters and
 * MAX_ASSERTION_BYTES bytes; strict UTF-8.
 * Throws IdJagRefusal (`invalid_subject_token`).
 */
export function decodeSaml2SubjectToken(token: string): string {
  if (token.length === 0) bad("empty");
  if (token.length > MAX_SAML2_TOKEN_LENGTH) bad(`longer than ${MAX_SAML2_TOKEN_LENGTH} characters`);
  const urlSafe = URL_SAFE.test(token);
  if (!urlSafe && !STANDARD.test(token)) bad("not base64url or base64");
  // Trailing padding, without a regex (CodeQL js/polynomial-redos; the checks above allow at most two).
  let end = token.length;
  while (end > 0 && token[end - 1] === "=") end--;
  const body = token.slice(0, end);
  const padded = body.length !== token.length;
  if (padded && token.length % 4 !== 0) bad("wrong padding");
  if (body.length % 4 === 1) bad("truncated");
  // Standard base64 (it has + or /) must be padded; base64url may omit it.
  if (!urlSafe && !padded && body.length % 4 !== 0) bad("base64 without padding");
  const standard = body.replace(/-/g, "+").replace(/_/g, "/");
  let binary: string;
  try {
    binary = atob(standard.padEnd(Math.ceil(standard.length / 4) * 4, "="));
  } catch {
    return bad("not base64url or base64");
  }
  // Canonical: re-encoding gives back exactly what was sent (no stray bits in the last character).
  if (btoa(binary).replace(/=+$/, "") !== standard) bad("not canonical");
  if (binary.length > MAX_ASSERTION_BYTES) bad(`longer than ${MAX_ASSERTION_BYTES} bytes`);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  try {
    return utf8.decode(bytes);
  } catch {
    return bad("not UTF-8");
  }
}

const nonEmpty = z.string().min(1);
/** What we rely on from the verifier's result; anything else it adds is ignored. */
const verifiedSchema = z.object({
  assertionId: nonEmpty,
  issuer: nonEmpty,
  tenantId: z.string().nullable(),
  serviceProvider: z.object({ id: nonEmpty, entityId: nonEmpty }),
  userId: nonEmpty,
  sessionId: z.string().optional(),
  nameId: z.string(),
  nameIdFormat: nonEmpty,
  authnInstant: z.date(),
  authnContextClassRef: z.string().optional(),
  notOnOrAfter: z.date(),
});

export interface SamlAssertionExpectations {
  /** The authenticated client: the Assertion's SP must be mapped to it (the SAML IdP checks). */
  clientId: string;
  now: Date;
}

/**
 * Verifies (and consumes: single use) a SAML Assertion this IdP issued to the SP mapped to
 * `clientId`, through better-auth-saml-idp. Throws IdJagRefusal: `invalid_subject_token`, `replay`,
 * `subject_token_expired` or `not_yet_valid`.
 */
export async function verifyOwnSamlAssertion(ctx: GenericEndpointContext, token: string, expected: SamlAssertionExpectations): Promise<VerifiedAssertion> {
  const xml = decodeSaml2SubjectToken(token);
  const exchange = getSamlIdpExchange(ctx);
  // Checked at startup (checkIssuerHost); a host that removed it since is misconfigured, not refused.
  if (!exchange) throw new Error("id-jag: SAML subject tokens need better-auth-saml-idp's exchange capability (ctx.context.samlIdpExchange, version 1)");
  let result: unknown;
  try {
    result = await exchange.verifyIssuedAssertion(ctx, xml, { clientId: expected.clientId, now: expected.now });
  } catch (e) {
    const code = assertionExchangeErrorCode(e);
    const message = e instanceof Error && e.message && e.message !== code ? `: ${e.message}` : "";
    switch (code) {
      case "ALREADY_EXCHANGED":
        return refuse("replay", `saml2: ALREADY_EXCHANGED${message}`);
      case "EXPIRED":
        return refuse("subject_token_expired", `saml2: EXPIRED${message}`);
      case "NOT_YET_VALID":
        return refuse("not_yet_valid", `saml2: NOT_YET_VALID${message}`);
      case undefined:
        // Not one of its refusals: fail closed, and tell the operator.
        ctx.context.logger.error("[id-jag] better-auth-saml-idp's verifyIssuedAssertion threw", e);
        return bad("the verifier failed");
      default:
        return bad(`${code}${message}`);
    }
  }
  const parsed = verifiedSchema.safeParse(result);
  if (!parsed.success) {
    ctx.context.logger.error("[id-jag] better-auth-saml-idp's verifyIssuedAssertion returned a malformed result", parsed.error.issues);
    return bad("the verifier returned a malformed result");
  }
  return parsed.data as VerifiedAssertion;
}
