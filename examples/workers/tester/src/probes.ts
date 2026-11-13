// The refusal probes of "Run the whole flow" (opt-in): token exchanges with one thing wrong, which the tester's IdP
// must refuse (draft -06 section 4.3.3). Each is graded on the refusal, and on the error code: where the draft names
// the code for that case, another code fails; where it only profiles one (section 4.3.4.3: "Any OAuth error code MAY
// be returned"), another code is a warn. Pure: the requests are built and graded here, sent by index.ts.
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
  /** The request's form, or null when the run has nothing to send (the probe is then skipped). */
  form(c: ProbeContext): URLSearchParams | null;
}

const base = (c: ProbeContext, o: Record<string, string> = {}) =>
  new URLSearchParams({ grant_type: TOKEN_EXCHANGE_GRANT, requested_token_type: ID_JAG_TOKEN_TYPE, audience: c.audience, resource: c.resource, scope: c.scope, subject_token: c.idToken, subject_token_type: ID_TOKEN_TOKEN_TYPE, ...o });

export const PROBES: readonly Probe[] = [
  { id: "probe.no_client_auth", level: "MUST", cite: D("4.3.3"), wrong: "no client authentication", expected: "invalid_client", codeRequired: true, anonymous: true, form: (c) => base(c) },
  {
    id: "probe.two_audiences",
    level: "MUST",
    cite: D("4.3.3"),
    wrong: "two audience values",
    expected: "invalid_request",
    codeRequired: true,
    form: (c) => {
      const f = base(c);
      f.append("audience", c.untrustedAudience);
      return f;
    },
  },
  { id: "probe.unknown_audience", level: "MUST", cite: D("4.3.3"), wrong: "an audience your IdP has no trust relationship with", expected: "invalid_target", codeRequired: true, form: (c) => base(c, { audience: c.untrustedAudience }) },
  // Only a resource outside the audience: the IdP grants none of them, and then MUST answer invalid_target.
  { id: "probe.resource_not_governed", level: "MUST", cite: D("4.3.3"), wrong: "only a resource the tester doesn't govern", expected: "invalid_target", codeRequired: true, form: (c) => base(c, { resource: c.foreignResource }) },
  { id: "probe.access_token_as_id_token", level: "MUST", cite: `${D("4.3.3")}, 4.3.4.3`, wrong: "the sign-in's access token as the subject token, said to be an ID token", expected: "invalid_request", codeRequired: false, form: (c) => (c.accessToken ? base(c, { subject_token: c.accessToken }) : null) },
  { id: "probe.id_jag_as_id_token", level: "MUST", cite: `${D("4.3.3")}, 4.3.4.3`, wrong: "the ID-JAG your IdP just issued as the subject token, said to be an ID token", expected: "invalid_request", codeRequired: false, form: (c) => (c.idJag ? base(c, { subject_token: c.idJag }) : null) },
  { id: "probe.wrong_subject_type", level: "MUST", cite: `${D("4.3.3")}, 4.3.4.3`, wrong: "the ID token, said to be a SAML 2.0 assertion", expected: "invalid_request", codeRequired: false, form: (c) => base(c, { subject_token_type: SAML2_TOKEN_TYPE }) },
];

/** The IdP's answer to a probe, or why it couldn't be sent or read. */
export type ProbeAnswer = { ok: true; status: number; json: unknown } | { ok: false; why: string };

/** Grades one probe's answer. Never throws. */
export function gradeProbe(probe: Probe, answer: ProbeAnswer | null): RuleResult {
  const r = (outcome: RuleResult["outcome"], message: string): RuleResult => ({ id: probe.id, level: probe.level, cite: probe.cite, outcome, message });
  if (answer === null) return r("skip", `Not sent: the run had nothing to send for it (${probe.wrong}).`);
  if (!answer.ok) return r("skip", `Not graded: your IdP's token endpoint ${answer.why}.`);
  const error = typeof answer.json === "object" && answer.json !== null && typeof (answer.json as { error?: unknown }).error === "string" ? (answer.json as { error: string }).error.slice(0, 64) : null;
  if (answer.status >= 200 && answer.status < 300) return r("fail", `Your IdP accepted a token exchange with ${probe.wrong} (HTTP ${answer.status}): it must refuse it.`);
  if (error === probe.expected) return r("pass", `Refused with ${probe.expected}, as it must be (${probe.wrong}).`);
  const got = error ? `error ${JSON.stringify(error)}` : `HTTP ${answer.status} without an OAuth error`;
  return probe.codeRequired ? r("fail", `Refused, but with ${got}: the draft names ${probe.expected} for ${probe.wrong}.`) : r("warn", `Refused, with ${got}; the draft profiles ${probe.expected} for ${probe.wrong} (any OAuth error code MAY be returned, section 4.3.4.3).`);
}
