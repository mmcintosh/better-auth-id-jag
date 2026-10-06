// Every refusal, on both sides, goes through `refuse()`: an RFC 6749 §5.2 / RFC 8693 §2.2.2 error
// thrown as Better Auth's APIError, so the token endpoint answers with the standard JSON body (a
// plain Error from a grant handler becomes an empty 500: docs/phase-0.md, Phase 1 probe).
//
// S8: the caller must not be able to tell "unknown user" from "policy denied" from "untrusted
// issuer". So each reason has a public description that is either specific (the request itself
// was malformed: nothing to learn about our users or policies) or the generic one for its error
// code. The reason code itself goes to the audit event, never to the caller.
import { APIError } from "better-auth/api";

export type OAuthErrorCode = "invalid_request" | "invalid_client" | "invalid_grant" | "unauthorized_client" | "invalid_scope" | "invalid_target";

/** What the caller sees when the reason isn't safe to name. */
const GENERIC: Record<OAuthErrorCode, string> = {
  invalid_request: "The request is invalid.",
  invalid_client: "Client authentication failed.",
  invalid_grant: "The grant is invalid.",
  unauthorized_client: "The client is not authorized for this grant.",
  invalid_scope: "The requested scope is invalid.",
  invalid_target: "The requested resource or audience is invalid.",
};

/**
 * Every reason code, its error code, and whether its description may name it. `public: true`
 * only where the caller learns nothing it didn't send: a missing parameter, a malformed token.
 */
export const REASONS = {
  // Shared: the request.
  missing_parameter: { error: "invalid_request", public: true, description: "A required parameter is missing." },
  unsupported_parameter: { error: "invalid_request", public: true, description: "A parameter is not supported." },
  public_client: { error: "invalid_client", public: false },
  // Shared: the ID-JAG itself (parse step: the caller sent it, so naming the defect is safe).
  malformed_token: { error: "invalid_grant", public: true, description: "The assertion is not a well-formed JWT." },
  wrong_typ: { error: "invalid_grant", public: true, description: "The assertion is not an ID-JAG (typ)." },
  disallowed_alg: { error: "invalid_grant", public: true, description: "The assertion's signature algorithm is not accepted." },
  missing_kid: { error: "invalid_grant", public: true, description: "The assertion has no kid." },
  missing_claim: { error: "invalid_grant", public: true, description: "The assertion is missing a required claim." },
  unsupported_claim: { error: "invalid_grant", public: true, description: "The assertion carries a claim this server does not support (authorization_details, act)." },
  invalid_claim: { error: "invalid_grant", public: true, description: "The assertion has an invalid claim." },
  lifetime_too_long: { error: "invalid_grant", public: true, description: "The assertion's lifetime is too long." },
  expired: { error: "invalid_grant", public: true, description: "The assertion has expired." },
  not_yet_valid: { error: "invalid_grant", public: true, description: "The assertion is not yet valid." },
  // Receiver: trust and binding. Not public (S8).
  untrusted_issuer: { error: "invalid_grant", public: false },
  self_issued: { error: "invalid_grant", public: false },
  jwks_unavailable: { error: "invalid_grant", public: false },
  bad_signature: { error: "invalid_grant", public: false },
  wrong_audience: { error: "invalid_grant", public: false },
  client_mismatch: { error: "invalid_grant", public: false },
  replay: { error: "invalid_grant", public: false },
  unknown_resource: { error: "invalid_target", public: false },
  unknown_subject: { error: "invalid_grant", public: false },
  subject_rejected: { error: "invalid_grant", public: false },
  banned_user: { error: "invalid_grant", public: false },
  no_scope: { error: "invalid_scope", public: false },
  // Issuer: the exchange.
  unsupported_requested_token_type: { error: "invalid_request", public: true, description: "Unsupported requested_token_type." },
  unsupported_subject_token_type: { error: "invalid_request", public: true, description: "Unsupported subject_token_type." },
  actor_token_unsupported: { error: "invalid_request", public: true, description: "actor_token is not supported." },
  invalid_audience: { error: "invalid_target", public: true, description: "audience must be an absolute https URL." },
  invalid_subject_token: { error: "invalid_grant", public: false },
  policy_denied: { error: "invalid_grant", public: false },
  no_policy: { error: "invalid_grant", public: false },
} as const satisfies Record<string, { error: OAuthErrorCode; public: boolean; description?: string }>;

export type ReasonCode = keyof typeof REASONS;

/** Strips control, line-separator, bidi and invisible formatting characters and caps the length. */
export function logSafe(s: string, max = 300): string {
  // biome-ignore lint/suspicious/noControlCharactersInRegex: removing them is the point.
  const clean = s.replace(/[\u0000-\u001f\u007f-\u009f\u061c\u200b-\u200f\u2028\u2029\u202a-\u202e\u2060-\u2069\ufeff]/g, "");
  return clean.length > max ? `${clean.slice(0, max)}…` : clean;
}

/** A refusal before it is thrown: what the audit event records. */
export class IdJagRefusal extends Error {
  readonly error: OAuthErrorCode;
  /** For the audit log only: never sent to the caller. Log-safe and capped (it may quote the caller). */
  readonly detail: string | undefined;
  constructor(
    readonly reason: ReasonCode,
    detail?: string,
  ) {
    const safe = detail === undefined ? undefined : logSafe(detail);
    super(`${reason}${safe ? `: ${safe}` : ""}`);
    this.name = "IdJagRefusal";
    this.error = REASONS[reason].error;
    this.detail = safe;
  }
}

/** The description the caller sees for a reason. */
export function publicDescription(reason: ReasonCode): string {
  const r: { error: OAuthErrorCode; public: boolean; description?: string } = REASONS[reason];
  return r.public && r.description ? r.description : GENERIC[r.error];
}

/** The APIError the token endpoint turns into `{ error, error_description }`. */
export function toApiError(refusal: IdJagRefusal): APIError {
  const body = { error: refusal.error, error_description: publicDescription(refusal.reason) };
  // 401 with a challenge for client authentication (RFC 6749 §5.2), 400 for the rest.
  if (refusal.error === "invalid_client") return new APIError("UNAUTHORIZED", body, { "WWW-Authenticate": 'Basic realm="token"' });
  return new APIError("BAD_REQUEST", body);
}

/** Throw a refusal (inside core: callers catch it, audit it, and turn it into an APIError). */
export function refuse(reason: ReasonCode, detail?: string): never {
  throw new IdJagRefusal(reason, detail);
}
