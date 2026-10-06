// The capability better-auth-saml-idp (>= 1.2.0) publishes on Better Auth's context so this issuer
// can exchange the SAML assertions it issued (draft -04 §4.3.1, §4.5; D-016). Mirrored here, not
// imported: better-auth-saml-idp is an optional peer, with no runtime import (Workers bundles, and
// no second copy of that module), so the capability is found by duck typing.
//
// The interface is frozen with the SAML IdP's side (version 1). `nameIdFor` (sub_id minting) is
// deferred (D-016 #6) and not used here; a version-1 object may or may not carry it.
import type { GenericEndpointContext } from "better-auth";

/** What `verifyIssuedAssertion` returns: an assertion this IdP issued, to the SP mapped to `clientId`, now consumed. */
export interface VerifiedAssertion {
  /** The Assertion's `ID`. */
  assertionId: string;
  /** The Assertion's `Issuer`: the root identity's or a tenant's entity ID. */
  issuer: string;
  tenantId: string | null;
  /** The SP the Assertion was issued to (its `Audience`). */
  serviceProvider: { id: string; entityId: string };
  /** The Better Auth user the Assertion was issued for. */
  userId: string;
  /** The Better Auth session the SSO response was issued in, when there was one. */
  sessionId?: string;
  nameId: string;
  nameIdFormat: string;
  authnInstant: Date;
  authnContextClassRef?: string;
  notOnOrAfter: Date;
}

/** Why `verifyIssuedAssertion` refused. */
export type AssertionExchangeErrorCode = "MALFORMED" | "NOT_OURS" | "BAD_SIGNATURE" | "NOT_YET_VALID" | "EXPIRED" | "NOT_EXCHANGEABLE" | "WRONG_CLIENT" | "ALREADY_EXCHANGED" | "ACCOUNT_INACTIVE";

export const ASSERTION_EXCHANGE_ERROR_CODES = ["MALFORMED", "NOT_OURS", "BAD_SIGNATURE", "NOT_YET_VALID", "EXPIRED", "NOT_EXCHANGEABLE", "WRONG_CLIENT", "ALREADY_EXCHANGED", "ACCOUNT_INACTIVE"] as const satisfies readonly AssertionExchangeErrorCode[];

/** The shape of better-auth-saml-idp's `AssertionExchangeError` (an Error with a `code`). */
export interface AssertionExchangeErrorLike extends Error {
  readonly code: AssertionExchangeErrorCode;
}

/** The capability, version 1. */
export interface SamlIdpExchange {
  version: 1;
  /**
   * Verifies an Assertion this IdP issued (signature, issuer, shape, validity window), that its
   * SP is mapped to `clientId`, consumes its record (single use), and re-checks the user. Throws
   * an AssertionExchangeError otherwise.
   */
  verifyIssuedAssertion(ctx: GenericEndpointContext, assertionXml: string, expected: { clientId: string; now?: Date }): Promise<VerifiedAssertion>;
}

/** The key under which better-auth-saml-idp puts the capability on Better Auth's context. */
export const SAML_IDP_EXCHANGE_KEY = "samlIdpExchange";

/** The capability on this context, or undefined. Duck-typed: version 1 and a verifyIssuedAssertion function. */
export function getSamlIdpExchange(ctx: { context: unknown }): SamlIdpExchange | undefined {
  const context = ctx.context as Record<string, unknown> | null | undefined;
  const x = context?.[SAML_IDP_EXCHANGE_KEY] as Partial<SamlIdpExchange> | null | undefined;
  if (!x || typeof x !== "object" || x.version !== 1 || typeof x.verifyIssuedAssertion !== "function") return undefined;
  return x as SamlIdpExchange;
}

/**
 * The code of an AssertionExchangeError, or undefined. Duck-typed by `name` and `code`, never
 * `instanceof`: the thrower may be another copy of better-auth-saml-idp's module.
 */
export function assertionExchangeErrorCode(e: unknown): AssertionExchangeErrorCode | undefined {
  const x = e as { name?: unknown; code?: unknown } | null | undefined;
  if (!x || typeof x !== "object" || x.name !== "AssertionExchangeError") return undefined;
  const code = x.code;
  return typeof code === "string" && (ASSERTION_EXCHANGE_ERROR_CODES as readonly string[]).includes(code) ? (code as AssertionExchangeErrorCode) : undefined;
}

/** better-auth-saml-idp's cap on the Assertion's XML, in bytes (its MAX_ASSERTION_BYTES). */
export const MAX_ASSERTION_BYTES = 65_536;
