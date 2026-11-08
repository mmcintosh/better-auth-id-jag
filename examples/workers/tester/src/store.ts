// The tester's own tables (migrations/0002_tester.sql), read and written with plain D1 statements. Better Auth's
// tables (users, clients, the receiver's trust rows and audit) are touched here only to purge what a registration or
// a tester left behind. Times are Unix milliseconds.
//
// Three layers (docs/test-your-idp.md, "Privacy"):
// - personal: the tester's user row (login, provider account id, account age), session, registrations and their
//   reports. Gone within minutes of the registration ending and the day-long sign-in ending, or at once on request;
// - the abuse record (testerAbuse): fingerprints only, 7 days, unlinkable once its week's key is deleted;
// - the blocklist (testerBlock): fingerprints of accounts and networks caught abusing the tester, 30 days.
import { BLOCK_KEY_ID, TESTER_EMAIL_DOMAIN, WEEK_MS } from "./privacy";

export interface Registration {
  id: string;
  userId: string;
  issuer: string;
  jwksUri: string;
  jwks: string;
  jwksFetchedAt: number;
  clientId: string;
  trustRowId: string;
  authMethod: string;
  metadataReport: string;
  blockAccountFp: string;
  blockNetFp: string;
  createdAt: number;
  expiresAt: number;
  confirmedAt: number | null;
  revokedAt: number | null;
  revokedReason: string | null;
}

export interface AbuseRow {
  id: string;
  at: number;
  keyId: string;
  provider: string;
  accountFp: string;
  ipFp: string;
  netFp: string;
  accountAge: string;
  issuerHost: string;
}

export interface CheckRow {
  id: string;
  registrationId: string;
  at: number;
  jti: string | null;
  httpStatus: number;
  error: string | null;
  results: string;
  checkedAgainst: string;
}

export const DAY_MS = 86_400_000;
/** The start of the current UTC day: daily limits reset then. */
export const utcDayStart = (now: number) => now - (now % DAY_MS);

const ACTIVE = "revokedAt is null and expiresAt > ?";
const iso = (ms: number) => new Date(ms).toISOString();

export async function isClosed(db: D1Database): Promise<{ closed: boolean; reason: string | null }> {
  const row = await db.prepare(`select closed, reason from testerState where id = 'main'`).first<{ closed: number; reason: string | null }>();
  return { closed: row?.closed === 1, reason: row?.reason ?? null };
}

export async function setClosed(db: D1Database, closed: boolean, reason: string, by: string, now: number): Promise<void> {
  await db
    .prepare(`insert into testerState (id, closed, reason, changedAt, changedBy) values ('main', ?, ?, ?, ?) on conflict (id) do update set closed = excluded.closed, reason = excluded.reason, changedAt = excluded.changedAt, changedBy = excluded.changedBy`)
    .bind(closed ? 1 : 0, reason.slice(0, 300), now, by.slice(0, 100))
    .run();
}

export const activeByClient = (db: D1Database, clientId: string, now: number) => db.prepare(`select * from testerRegistration where clientId = ? and ${ACTIVE}`).bind(clientId, now).first<Registration>();
export const activeByUser = (db: D1Database, userId: string, now: number) => db.prepare(`select * from testerRegistration where userId = ? and ${ACTIVE}`).bind(userId, now).first<Registration>();
export const byId = (db: D1Database, id: string) => db.prepare(`select * from testerRegistration where id = ?`).bind(id).first<Registration>();
/** The issuer's confirmed registration while it lasts: only that one holds the issuer. Pending ones don't. */
export const confirmedByIssuer = (db: D1Database, issuer: string, now: number) => db.prepare(`select id from testerRegistration where issuer = ? and confirmedAt is not null and ${ACTIVE}`).bind(issuer, now).first<{ id: string }>();

/** A user's registrations whose data still exists, newest first. */
export async function byUser(db: D1Database, userId: string): Promise<Registration[]> {
  return (await db.prepare(`select * from testerRegistration where userId = ? order by createdAt desc limit 5`).bind(userId).all<Registration>()).results;
}

/** Is this account or network on the blocklist? */
export async function isBlocked(db: D1Database, fps: string[], now: number): Promise<boolean> {
  return !!(await db.prepare(`select fp from testerBlock where fp in (${fps.map(() => "?").join(", ")}) and expiresAt > ?`).bind(...fps, now).first());
}

/**
 * Reserves a pending registration and its abuse record in one transaction whose first statement checks every limit
 * at once, so requests at the same moment can't get past them: no active registration for the user, no confirmed one
 * for the issuer, and the day's counts overall, per account fingerprint and per address fingerprint. The abuse row
 * is written only if the registration was.
 */
export async function reserve(db: D1Database, r: Registration, a: AbuseRow, l: { day: number; perDay: number; perAccount: number; perIp: number }): Promise<boolean> {
  const [reg] = await db.batch([
    db
      .prepare(
        `insert into testerRegistration (id, userId, issuer, jwksUri, jwks, jwksFetchedAt, clientId, trustRowId, authMethod, metadataReport, blockAccountFp, blockNetFp, createdAt, expiresAt)
         select ?, ?, ?, ?, ?, ?, '', '', ?, ?, ?, ?, ?, ?
         where not exists (select 1 from testerRegistration where userId = ? and ${ACTIVE})
           and not exists (select 1 from testerRegistration where issuer = ? and confirmedAt is not null and ${ACTIVE})
           and (select count(*) from testerAbuse where at >= ?) < ?
           and (select count(*) from testerAbuse where at >= ? and accountFp = ?) < ?
           and (select count(*) from testerAbuse where at >= ? and ipFp = ?) < ?`,
      )
      .bind(r.id, r.userId, r.issuer, r.jwksUri, r.jwks, r.jwksFetchedAt, r.authMethod, r.metadataReport, r.blockAccountFp, r.blockNetFp, r.createdAt, r.expiresAt, r.userId, r.createdAt, r.issuer, r.createdAt, l.day, l.perDay, l.day, a.accountFp, l.perAccount, l.day, a.ipFp, l.perIp),
    db
      .prepare(`insert into testerAbuse (id, at, keyId, provider, accountFp, ipFp, netFp, accountAge, issuerHost) select ?, ?, ?, ?, ?, ?, ?, ?, ? where exists (select 1 from testerRegistration where id = ?)`)
      .bind(a.id, a.at, a.keyId, a.provider, a.accountFp, a.ipFp, a.netFp, a.accountAge, a.issuerHost, r.id),
  ]);
  return (reg?.meta.changes ?? 0) === 1;
}

/** The client is made: from now on it can redeem (a pending registration still has no trust row). */
export async function setClient(db: D1Database, id: string, clientId: string): Promise<void> {
  await db.prepare(`update testerRegistration set clientId = ? where id = ?`).bind(clientId, id).run();
}

/**
 * Confirms a pending registration, unless another registration of the issuer was confirmed first (then nothing
 * changes and false comes back). The caller then creates the trust row and calls setTrustRow.
 */
export async function confirm(db: D1Database, id: string, now: number): Promise<boolean> {
  const r = await db
    .prepare(`update testerRegistration set confirmedAt = ? where id = ? and confirmedAt is null and ${ACTIVE} and not exists (select 1 from testerRegistration r2 where r2.issuer = testerRegistration.issuer and r2.id <> testerRegistration.id and r2.confirmedAt is not null and r2.revokedAt is null and r2.expiresAt > ?)`)
    .bind(now, id, now, now)
    .run();
  if ((r.meta.changes ?? 0) !== 1) return false;
  await db.prepare(`update testerAbuse set confirmed = 1 where id = ?`).bind(id).run();
  return true;
}

export async function setTrustRow(db: D1Database, id: string, trustRowId: string): Promise<void> {
  await db.prepare(`update testerRegistration set trustRowId = ? where id = ?`).bind(trustRowId, id).run();
}

export async function unconfirm(db: D1Database, id: string): Promise<void> {
  await db.batch([db.prepare(`update testerRegistration set confirmedAt = null where id = ?`).bind(id), db.prepare(`update testerAbuse set confirmed = 0 where id = ?`).bind(id)]);
}

/** A registration that failed half-way: everything it made is removed (its abuse record stays: it still counts). */
export async function abandon(db: D1Database, id: string, clientId: string | undefined): Promise<void> {
  await db.batch([...(clientId ? [db.prepare(`delete from "oauthClient" where clientId = ?`).bind(clientId)] : []), db.prepare(`delete from testerRegistration where id = ?`).bind(id)]);
}

export async function updateJwks(db: D1Database, id: string, jwks: string, now: number): Promise<void> {
  await db.prepare(`update testerRegistration set jwks = ?, jwksFetchedAt = ? where id = ?`).bind(jwks, now, id).run();
}

/**
 * Ends a registration at once: its client is refused by the token endpoint and its access tokens by /mcp from now
 * on, and its trust row is disabled. The purge removes everything within minutes.
 */
export async function revoke(db: D1Database, id: string, reason: string, now: number): Promise<boolean> {
  const [r] = await db.batch([
    db.prepare(`update testerRegistration set revokedAt = ?, revokedReason = ? where id = ? and revokedAt is null`).bind(now, reason.slice(0, 300), id),
    db.prepare(`update "idJagTrustedIssuer" set enabled = 0 where id = (select trustRowId from testerRegistration where id = ?)`).bind(id),
  ]);
  return (r?.meta.changes ?? 0) > 0;
}

/** Blocks the registration's account and/or network for 30 days (blocklist-key fingerprints), and ends it. */
export async function block(db: D1Database, reg: Registration, kinds: ("account" | "network")[], reason: string, now: number): Promise<void> {
  await db.batch(
    kinds.map((kind) =>
      db.prepare(`insert into testerBlock (fp, kind, reason, createdAt, expiresAt) values (?, ?, ?, ?, ?) on conflict (fp) do update set reason = excluded.reason, expiresAt = excluded.expiresAt`).bind(kind === "account" ? reg.blockAccountFp : reg.blockNetFp, kind, reason.slice(0, 300), now, now + 30 * DAY_MS),
    ),
  );
  await revoke(db, reg.id, `blocked: ${reason}`, now);
}

export async function countChecks(db: D1Database, since: number, registrationId?: string): Promise<number> {
  const q = registrationId === undefined ? db.prepare(`select count(*) as n from testerCheck where at >= ?`).bind(since) : db.prepare(`select count(*) as n from testerCheck where at >= ? and registrationId = ?`).bind(since, registrationId);
  return (await q.first<{ n: number }>())?.n ?? 0;
}

export async function countServerErrors(db: D1Database, since: number): Promise<number> {
  return (await db.prepare(`select count(*) as n from testerCheck where at >= ? and httpStatus >= 500`).bind(since).first<{ n: number }>())?.n ?? 0;
}

export async function insertCheck(db: D1Database, c: CheckRow): Promise<void> {
  await db.prepare(`insert into testerCheck (id, registrationId, at, jti, httpStatus, error, results, checkedAgainst) values (?, ?, ?, ?, ?, ?, ?, ?)`).bind(c.id, c.registrationId, c.at, c.jti, c.httpStatus, c.error, c.results, c.checkedAgainst).run();
}

export async function recentChecks(db: D1Database, registrationId: string, limit = 50): Promise<CheckRow[]> {
  return (await db.prepare(`select * from testerCheck where registrationId = ? order by at desc limit ?`).bind(registrationId, limit).all<CheckRow>()).results;
}

/** The receiver's own decision for each ID-JAG, from its audit table (written in the background, so it may lag). */
export async function receiverDecisions(db: D1Database, clientId: string): Promise<Map<string, { type: string; reason: string | null }>> {
  const rows = (await db.prepare(`select jti, type, reason from idJagAudit where clientId = ? and jti is not null order by at desc limit 200`).bind(clientId).all<{ jti: string; type: string; reason: string | null }>()).results;
  const out = new Map<string, { type: string; reason: string | null }>();
  for (const r of rows) if (!out.has(r.jti)) out.set(r.jti, { type: r.type, reason: r.reason });
  return out;
}

// Counters for events that are deliberately not stored row by row (a refused flood must not become a flood of
// writes): counted in memory, written at most once a minute per isolate.
const pending = new Map<string, number>();
let lastFlush = 0;
export function bump(name: string): void {
  pending.set(name, (pending.get(name) ?? 0) + 1);
}
export async function flushCounters(db: D1Database, now: number): Promise<void> {
  if (pending.size === 0 || now - lastFlush < 60_000) return;
  lastFlush = now;
  const hour = iso(now - (now % 3_600_000)).slice(0, 13);
  const entries = [...pending.entries()];
  pending.clear();
  await db.batch(entries.map(([name, n]) => db.prepare(`insert into testerCounter (bucket, name, count) values (?, ?, ?) on conflict (bucket, name) do update set count = count + excluded.count`).bind(hour, name, n)));
}

/** Read-only numbers for the watcher (GET /admin/stats). Fingerprints and counts, no personal data. */
export async function stats(db: D1Database, now: number) {
  const day = utcDayStart(now);
  const [state, active, abuse, blocks, checks, byStatus, counters, reasons] = await Promise.all([
    isClosed(db),
    db.prepare(`select r.id, a.issuerHost, r.createdAt, r.expiresAt, r.confirmedAt, r.revokedAt, (select count(*) from testerCheck c where c.registrationId = r.id) as redemptions from testerRegistration r left join testerAbuse a on a.id = r.id order by r.createdAt desc limit 50`).all(),
    db.prepare(`select id, at, provider, substr(accountFp, 1, 12) as account, substr(ipFp, 1, 12) as address, substr(netFp, 1, 12) as network, accountAge, issuerHost, confirmed, redemptions, refusals, ended from testerAbuse order by at desc limit 200`).all(),
    db.prepare(`select kind, count(*) as n from testerBlock where expiresAt > ? group by kind`).bind(now).all(),
    countChecks(db, day),
    db.prepare(`select httpStatus, count(*) as n from testerCheck where at >= ? group by httpStatus`).bind(day).all(),
    db.prepare(`select bucket, name, count from testerCounter where bucket >= ? order by bucket desc`).bind(iso(now - DAY_MS).slice(0, 13)).all(),
    db.prepare(`select reason, count(*) as n from idJagAudit where type = 'id-jag.refused' and at >= ? group by reason`).bind(iso(day)).all(),
  ]);
  return { now: iso(now), state, registrations: active.results, abuseRecord: abuse.results, blocked: blocks.results, checksToday: checks, checksTodayByStatus: byStatus.results, counters: counters.results, receiverRefusalsToday: reasons.results };
}

/** Deletes everything one registration made, after writing its counts into its abuse record. */
async function purgeRegistration(db: D1Database, r: Pick<Registration, "id" | "clientId" | "trustRowId" | "revokedReason">): Promise<void> {
  const sandbox = `%@${r.id}.sandbox.invalid`;
  await db.batch([
    db.prepare(`update testerAbuse set redemptions = (select count(*) from testerCheck where registrationId = ?), refusals = (select count(*) from testerCheck where registrationId = ? and httpStatus <> 200), ended = ? where id = ?`).bind(r.id, r.id, r.revokedReason ? r.revokedReason.slice(0, 100) : "expired", r.id),
    db.prepare(`delete from "idJagTrustedIssuer" where id = ?`).bind(r.trustRowId),
    db.prepare(`delete from "oauthClient" where clientId = ?`).bind(r.clientId),
    db.prepare(`delete from "session" where userId in (select id from "user" where email like ?)`).bind(sandbox),
    db.prepare(`delete from "account" where userId in (select id from "user" where email like ?)`).bind(sandbox),
    db.prepare(`delete from "user" where email like ?`).bind(sandbox),
    db.prepare(`delete from "idJagAudit" where clientId = ?`).bind(r.clientId),
    db.prepare(`delete from "idJagJti" where clientId = ?`).bind(r.clientId),
    db.prepare(`delete from testerCheck where registrationId = ?`).bind(r.id),
    db.prepare(`delete from testerRegistration where id = ?`).bind(r.id),
  ]);
}

/**
 * The purge (every 5 minutes, and for one issuer before it is registered or confirmed again): ended registrations
 * and all they made; testers whose sign-in and registrations have both ended; expired sign-in state; abuse records
 * older than 7 days; fingerprint keys nothing uses; expired blocks; old counters. Idempotent.
 */
export async function purge(db: D1Database, now: number, issuer?: string): Promise<number> {
  const ended = (
    issuer === undefined
      ? await db.prepare(`select id, clientId, trustRowId, revokedReason from testerRegistration where revokedAt is not null or expiresAt <= ? limit 20`).bind(now).all<Registration>()
      : await db.prepare(`select id, clientId, trustRowId, revokedReason from testerRegistration where issuer = ? and (revokedAt is not null or expiresAt <= ?)`).bind(issuer, now).all<Registration>()
  ).results;
  for (const r of ended) await purgeRegistration(db, r);
  if (issuer !== undefined) return ended.length;

  const testers = `select u.id from "user" u where u.email like '%@${TESTER_EMAIL_DOMAIN}' and not exists (select 1 from testerRegistration r where r.userId = u.id) and not exists (select 1 from "session" s where s.userId = u.id and s.expiresAt > ?)`;
  await db.batch([
    // Testers: once their day-long sign-in and every registration have ended, nothing about them is kept.
    db.prepare(`delete from "account" where userId in (${testers})`).bind(iso(now)),
    db.prepare(`delete from "session" where userId in (${testers})`).bind(iso(now)),
    db.prepare(`delete from "user" where id in (${testers})`).bind(iso(now)),
    db.prepare(`delete from "verification" where expiresAt < ?`).bind(iso(now)),
    db.prepare(`delete from testerAbuse where at < ?`).bind(now - WEEK_MS),
    db.prepare(`delete from testerKey where id <> ? and createdAt < ?`).bind(BLOCK_KEY_ID, now - 2 * WEEK_MS),
    db.prepare(`delete from testerBlock where expiresAt <= ?`).bind(now),
    // The blocklist key goes when nothing is blocked and no registration holds a fingerprint made with it.
    db.prepare(`delete from testerKey where id = ? and not exists (select 1 from testerBlock) and not exists (select 1 from testerRegistration)`).bind(BLOCK_KEY_ID),
    db.prepare(`delete from testerCounter where bucket < ?`).bind(iso(now - WEEK_MS).slice(0, 13)),
  ]);
  return ended.length;
}

/**
 * "Delete my data now": ends the tester's registrations and deletes everything they made, then the tester's own
 * records. The abuse record stays its 7 days: it holds fingerprints, not the tester, and limits must still count.
 */
export async function deleteTester(db: D1Database, userId: string, now: number): Promise<void> {
  const regs = (await db.prepare(`select * from testerRegistration where userId = ?`).bind(userId).all<Registration>()).results;
  for (const r of regs) {
    await revoke(db, r.id, "deleted by the tester", now);
    await purgeRegistration(db, { ...r, revokedReason: "deleted by the tester" });
  }
  await db.batch([
    db.prepare(`delete from "oauthClient" where userId = ?`).bind(userId),
    db.prepare(`delete from "session" where userId = ?`).bind(userId),
    db.prepare(`delete from "account" where userId = ?`).bind(userId),
    db.prepare(`delete from "user" where id = ?`).bind(userId),
  ]);
}
