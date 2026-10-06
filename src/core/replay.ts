// One `jti` record per ID-JAG, shared by both sides: the issuer records what it minted (audit, and
// revocation within the token's lifetime), the receiver what it accepted (single use, S3).
//
// The same design as better-auth-saml-idp's seen-request key (its D-011, D-033): the unique key is a
// hash of (side, iss, jti), the INSERT is the check, and a unique-key violation is a replay. A read
// after a failed insert only classifies the failure, so no adapter's error codes are parsed. The
// uniqueness is declared at field level (SQL migrators) and as a named table-level index (Better
// Auth 1.7's MongoDB adapter creates only those).
import type { BetterAuthPluginDBSchema, DBAdapter } from "better-auth";
import { JTI_RETENTION_MARGIN_SECONDS } from "./urns";

export const JTI_MODEL = "idJagJti";

export type JtiSide = "issued" | "accepted";

export function jtiSchema() {
  return {
    [JTI_MODEL]: {
      fields: {
        key: { type: "string", required: true, unique: true, input: false },
        side: { type: "string", required: true, input: false },
        jti: { type: "string", required: true, input: false },
        iss: { type: "string", required: true, input: false },
        aud: { type: "string", required: true, input: false },
        sub: { type: "string", required: true, input: false },
        clientId: { type: "string", required: true, input: false },
        expiresAt: { type: "date", required: true, input: false, index: true },
        createdAt: { type: "date", required: true, input: false },
      },
      indexes: [{ fields: ["key"], unique: true, name: "id_jag_jti_key_unique" }],
    },
  } satisfies BetterAuthPluginDBSchema;
}

/** The adapter surface used here (Better Auth's `ctx.context.adapter`). */
export type JtiAdapter = Pick<DBAdapter, "create" | "findOne" | "deleteMany">;

export interface JtiRecord {
  side: JtiSide;
  jti: string;
  iss: string;
  aud: string;
  sub: string;
  clientId: string;
  /** The token's `exp` claim (seconds). The row's expiry is computed from it, not passed in. */
  exp: number;
  /** The skew the token was accepted with. */
  clockSkewSeconds: number;
}

/**
 * When a row may be swept: after every instance, even one whose clock runs ahead, has stopped
 * accepting the token. `exp + skew + margin`.
 */
export function jtiExpiresAt(exp: number, clockSkewSeconds: number): Date {
  return new Date((exp + clockSkewSeconds + JTI_RETENTION_MARGIN_SECONDS) * 1000);
}

async function sha256b64url(input: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input)));
  let s = "";
  for (const b of digest) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** The unique key: a hash of the JSON array, so no (iss, jti) pair can collide with another. */
export function jtiKey(side: JtiSide, iss: string, jti: string): Promise<string> {
  return sha256b64url(JSON.stringify(["id-jag", side, iss, jti]));
}

/**
 * Records a jti. Returns true the first time, false if (side, iss, jti) was already recorded.
 * Requires a database that enforces UNIQUE: every real one does, with the migrations Better Auth
 * generates; Better Auth's memory adapter does not, and a MongoDB without the named index built
 * would not either. Then replays are accepted silently (documented in SECURITY.md and the guide).
 */
export async function recordJti(adapter: JtiAdapter, r: JtiRecord, now = new Date()): Promise<boolean> {
  const key = await jtiKey(r.side, r.iss, r.jti);
  const { exp, clockSkewSeconds, ...fields } = r;
  try {
    await adapter.create({ model: JTI_MODEL, data: { key, ...fields, expiresAt: jtiExpiresAt(exp, clockSkewSeconds), createdAt: now } });
    return true;
  } catch (error) {
    if (await adapter.findOne({ model: JTI_MODEL, where: [{ field: "key", value: key }] })) return false;
    throw error;
  }
}

/** Whether a jti was recorded (the issuer's audit and revocation views). */
export async function hasJti(adapter: JtiAdapter, side: JtiSide, iss: string, jti: string): Promise<boolean> {
  return !!(await adapter.findOne({ model: JTI_MODEL, where: [{ field: "key", value: await jtiKey(side, iss, jti) }] }));
}

/** Deletes rows whose token can no longer be accepted anywhere. */
export async function sweepJtis(adapter: JtiAdapter, now = new Date()): Promise<void> {
  await adapter.deleteMany({ model: JTI_MODEL, where: [{ field: "expiresAt", value: now, operator: "lt" }] });
}

/**
 * Adapters known not to enforce UNIQUE: on them, single use (S3) silently fails. Better Auth's
 * memory adapter is the one that ships; a MongoDB without its indexes built is the other case, and
 * can't be detected without a write, so it's documented instead (D-007, D-009).
 */
const NO_UNIQUE_ADAPTERS = new Set(["memory"]);

/** Logs a warning at startup when the host's adapter can't enforce the jti table's unique key. */
export function warnIfReplayUnsafe(ctx: { adapter: { id: string }; logger: { warn(message: string): void } }, plugin: string): void {
  if (NO_UNIQUE_ADAPTERS.has(ctx.adapter.id))
    ctx.logger.warn(`[id-jag] ${plugin}: the "${ctx.adapter.id}" adapter doesn't enforce unique keys, so ID-JAG single use (replay protection) does not hold. Use a real database outside development.`);
}
