// One `jti` record per ID-JAG, shared by both sides: the issuer records what it minted (audit, and
// revocation within the token's lifetime), the receiver what it accepted (single use, S3).
//
// The same design as better-auth-saml-idp's seen-request key (its D-011, D-033): the row id is a
// hash of (side, iss, jti), the INSERT is the check, and a unique-key violation is a replay. A read
// after a failed insert only classifies the failure, so no adapter's error codes are parsed. The
// uniqueness is declared at field level (SQL migrators) and as a named table-level index (Better
// Auth 1.7's MongoDB adapter creates only those).
import type { BetterAuthPluginDBSchema, DBAdapter } from "better-auth";

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
  /** The token's `exp` plus the clock skew: the row must outlive every moment the token is accepted. */
  expiresAt: Date;
}

async function sha256b64url(input: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input)));
  let s = "";
  for (const b of digest) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** The unique key: NUL-separated, so no (iss, jti) pair can collide with another. */
export function jtiKey(side: JtiSide, iss: string, jti: string): Promise<string> {
  return sha256b64url(`id-jag:${side}\u0000${iss}\u0000${jti}`);
}

/**
 * Records a jti. Returns true the first time, false if (side, iss, jti) was already recorded.
 * Requires a database that enforces UNIQUE (every real one; not Better Auth's memory adapter).
 */
export async function recordJti(adapter: JtiAdapter, r: JtiRecord, now = new Date()): Promise<boolean> {
  const key = await jtiKey(r.side, r.iss, r.jti);
  try {
    await adapter.create({ model: JTI_MODEL, data: { key, ...r, createdAt: now } });
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
