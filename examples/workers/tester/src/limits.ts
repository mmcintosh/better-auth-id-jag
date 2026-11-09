// The tester's limits and the version stamp on every report. In their own module: the Worker's entry module (index.ts)
// may export only its handler, since the runtime treats every named export there as an entry point.
import { SUPPORTED_DRAFT } from "better-auth-id-jag";
import pkg from "../../../../package.json";

/** Every limit in one place. The rate-limit bindings (wrangler.jsonc) add per-minute limits on top. */
export const LIMITS = {
  registrationHours: 24,
  registrationsPerDay: 3,
  registrationsPerAccountPerDay: 2,
  registrationsPerIpPerDay: 3,
  accountMinAgeDays: 30,
  redemptionsPerRegistrationPerDay: 50,
  /** Past this, across everyone, redemptions stop until 00:00 UTC: far more than real testing needs. */
  redemptionsPerDay: 300,
  /** This many 5xx answers in 10 minutes closes the tester until the operator reopens it. */
  serverErrorsPer10Min: 10,
  maxBodyBytes: 20_000,
};

/** What every report was checked against: a later draft or release may judge the same ID-JAG differently. */
export const CHECKED_AGAINST = `${SUPPORTED_DRAFT}; better-auth-id-jag ${pkg.version}`;
