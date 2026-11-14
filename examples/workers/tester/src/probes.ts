// The refusal probes of "Run the whole flow" (opt-in): token exchanges with one thing wrong, which the tester's IdP
// must, or should, refuse (draft -06 section 4.3.3). Each is graded on the refusal, and on the error code: where the
// draft names the code for that case, another code fails; where it only profiles one (section 4.3.4.3: "Any OAuth
// error code MAY be returned"), another code is a warn. An answer that isn't about the request (429, or a 5xx from
// the IdP or a gateway in front of it) isn't graded. Pure: the requests are built and graded here, sent by index.ts,
// only after the run's ID-JAG was issued and redeemed and only for a confirmed registration (D-076).
import { ID_JAG_TOKEN_TYPE, ID_TOKEN_TOKEN_TYPE, type RuleLevel, type RuleResult, SAML2_TOKEN_TYPE, TOKEN_EXCHANGE_GRANT } from "better-auth-id-jag";

const D = (section: string) => `draft -06 section ${section}`;

/** What a probe needs from the run: the good exchange's request, and the tokens it can send in the wrong place. */
export interface ProbeContext {
  /** The tester's own issuer identifier (the good request's audience). */
  audience: string;
  /** The tester's /mcp (the good request's resource). */
  resource: string;
  scope: string;
  idToken: string;
  /** The access token from the sign-in's code exchange, if the IdP gave one. */
  accessToken: string | undefined;
  /** The ID-JAG from the good exchange, if the IdP issued one. */
  idJag: string | null;
  /** An issuer identifier no IdP has a trust relationship with. */
  untrustedAudience: string;
  /** A resource outside the tester. */
  foreignResource: string;
}

export interface Probe {
  id: string;
  level: RuleLevel;
  cite: string;
  /** What is wrong with the request, for the report. */
  wrong: string;
  /** The error code the draft names or profiles for it. */
  expected: string;
  /** The draft names this code for this case (another code fails), rather than only profiling it (a warn). */
  codeRequired: boolean;
  /** Sent without the client's authentication. */
  anonymous?: boolean;
  /** How accepting it is graded: fail (the draft says MUST), or warn (it says SHOULD). */
  accepted: "fail" | "warn";
  /** The request's form, or why the run has nothing to send for it (the probe is then skipped). */
  form(c: ProbeContext): URLSearchParams | { skip: string };
}

const base = (c: ProbeContext, o: Record<string, string> = {}) =>
  new URLSearchParams({ grant_type: TOKEN_EXCHANGE_GRANT, requested_token_type: ID_JAG_TOKEN_TYPE, audience: c.audience, resource: c.resource, scope: c.scope, subject_token: c.idToken, subject_token_type: ID_TOKEN_TOKEN_TYPE, ...o });

export const PROBES: readonly Probe[] = [
  { id: "probe.no_client_auth", level: "MUST", cite: D("4.3.3"), wrong: "no client authentication", expected: "invalid_client", codeRequired: true, anonymous: true, accepted: "fail", form: (c) => base(c) },
  {
    id: "probe.two_audiences",
    level: "MUST",
    cite: D("4.3.3"),
    wrong: "two audience values",
    expected: "invalid_request",
    codeRequired: true,
    accepted: "fail",
    form: (c) => {
      const f = base(c);
      f.append("audience", c.untrustedAudience);
      return f;
    },
  },
  { id: "probe.unknown_audience", level: "MUST", cite: D("4.3.3"), wrong: "an audience your IdP has no trust relationship with", expected: "invalid_target", codeRequired: true, accepted: "fail", form: (c) => base(c, { audience: c.untrustedAudience }) },
  // A resource outside the audience: SHOULD be refused, with invalid_target (an IdP that doesn't know which resources
  // the audience governs may grant it, so accepting it is a warn). The request names this one resource only, so a
  // refusal grants none of them, and then the code MUST be invalid_target: another code fails.
  { id: "probe.resource_not_governed", level: "SHOULD", cite: D("4.3.3"), wrong: "a resource the tester doesn't govern", expected: "invalid_target", codeRequired: true, accepted: "warn", form: (c) => base(c, { resource: c.foreignResource }) },
  {
    id: "probe.access_token_as_id_token",
    level: "MUST",
    cite: `${D("4.3.3")}, 4.3.4.3`,
    wrong: "the sign-in's access token as the subject token, said to be an ID token",
    expected: "invalid_request",
    codeRequired: false,
    accepted: "fail",
    // An IdP whose access token is its ID token would get the correct request, and rightly accept it.
    form: (c) => (!c.accessToken ? { skip: "the sign-in gave no access token" } : c.accessToken === c.idToken ? { skip: "the sign-in's access token is its ID token, so this would be the correct request" } : base(c, { subject_token: c.accessToken })),
  },
  { id: "probe.id_jag_as_id_token", level: "MUST", cite: `${D("4.3.3")}, 4.3.4.3`, wrong: "the ID-JAG your IdP just issued as the subject token, said to be an ID token", expected: "invalid_request", codeRequired: false, accepted: "fail", form: (c) => (c.idJag ? base(c, { subject_token: c.idJag }) : { skip: "your IdP issued no ID-JAG" }) },
  { id: "probe.wrong_subject_type", level: "MUST", cite: `${D("4.3.3")}, 4.3.4.3`, wrong: "the ID token, said to be a SAML 2.0 assertion", expected: "invalid_request", codeRequired: false, accepted: "fail", form: (c) => base(c, { subject_token_type: SAML2_TOKEN_TYPE }) },
];

/** The IdP's answer to a probe, or why it couldn't be sent or read. */
export type ProbeAnswer = { ok: true; status: number; json: unknown } | { ok: false; why: string };

/** A probe not sent, and why. */
export const skipProbe = (probe: Probe, why: string): RuleResult => ({ id: probe.id, level: probe.level, cite: probe.cite, outcome: "skip", message: `Not sent: ${why}.` });

/** Grades one probe's answer. Never throws. */
export function gradeProbe(probe: Probe, answer: ProbeAnswer): RuleResult {
  const r = (outcome: RuleResult["outcome"], message: string): RuleResult => ({ id: probe.id, level: probe.level, cite: probe.cite, outcome, message });
  if (!answer.ok) return r("skip", `Not graded: your IdP's token endpoint ${answer.why}.`);
  // Rate limited, or a server error (the IdP's, or a gateway's): not an answer to what was wrong with the request.
  if (answer.status === 429 || answer.status >= 500) return r("skip", `Not graded: your IdP's token endpoint answered HTTP ${answer.status}${answer.status === 429 ? " (too many requests)" : " (a server error)"}, which says nothing about ${probe.wrong}.`);
  const body = typeof answer.json === "object" && answer.json !== null ? (answer.json as { error?: unknown; access_token?: unknown }) : {};
  const error = typeof body.error === "string" ? body.error.slice(0, 64) : null;
  const ok = answer.status >= 200 && answer.status < 300;
  // A 2xx is an acceptance unless it is an OAuth error without a token: then it is a refusal sent with the wrong
  // status (RFC 6749 section 5.2: HTTP 400, or 401 for invalid_client), graded on its code, at best a warn.
  if (ok && (error === null || typeof body.access_token === "string")) return r(probe.accepted, `Your IdP accepted a token exchange with ${probe.wrong} (HTTP ${answer.status}): it ${probe.accepted === "fail" ? "must" : "should"} refuse it, with ${probe.expected}.`);
  const wrongStatus = ok ? ` with HTTP ${answer.status}, where an error answer is HTTP 400 (401 for invalid_client, RFC 6749 section 5.2)` : "";
  if (error === probe.expected) return ok ? r("warn", `Refused with ${probe.expected}, but${wrongStatus} (${probe.wrong}).`) : r("pass", `Refused with ${probe.expected}, as the draft says (${probe.wrong}).`);
  const got = error ? `error ${JSON.stringify(error)}${wrongStatus}` : `HTTP ${answer.status} without an OAuth error`;
  return probe.codeRequired ? r("fail", `Refused, but with ${got}: the draft names ${probe.expected} for ${probe.wrong}.`) : r("warn", `Refused, with ${got}; the draft profiles ${probe.expected} for ${probe.wrong} (any OAuth error code MAY be returned, section 4.3.4.3).`);
}
