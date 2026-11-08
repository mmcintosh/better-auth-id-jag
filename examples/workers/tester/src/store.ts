// The tester's own tables (migrations/0002_tester.sql), read and written with plain D1 statements. Better Auth's
// tables (users, clients, the receiver's trust rows and audit) are touched here only to purge what a registration
// left behind. Times are Unix milliseconds.

export interface Registration {
  id: string;
  userId: string;
  githubLogin: string;
  issuer: string;
  jwksUri: string;
  jwks: string;
  jwksFetchedAt: number;
  clientId: string;
  trustRowId: string;
  authMethod: string;
  metadataReport: string;
  ip: string | null;
  createdAt: number;
  expiresAt: number;
  revokedAt: number | null;
  revokedReason: string | null;
  purgedAt: number | null;
}

export interface CheckRow {
  id: string;
  registrationId: string;
  at: number;
  jti: string | null;
  httpStatus: number;
  error: string | null;
  results: string;
}

export const DAY_MS = 86_400_000;
/** The start of the current UTC day: daily limits reset then. */
export const utcDayStart = (now: number) => now - (now % DAY_MS);

const ACTIVE = "revokedAt is null and purgedAt is null and expiresAt > ?";

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
export const activeByIssuer = (db: D1Database, issuer: string, now: number) => db.prepare(`select * from testerRegistration where issuer = ? and ${ACTIVE}`).bind(issuer, now).first<Registration>();
export const activeByUser = (db: D1Database, userId: string, now: number) => db.prepare(`select * from testerRegistration where userId = ? and ${ACTIVE}`).bind(userId, now).first<Registration>();

/** A user's registrations whose data still exists (active, or expired and not yet purged), newest first. */
export async function unpurgedByUser(db: D1Database, userId: string): Promise<Registration[]> {
  return (await db.prepare(`select * from testerRegistration where userId = ? and purgedAt is null order by createdAt desc limit 5`).bind(userId).all<Registration>()).results;
}

export async function countRegistrations(db: D1Database, since: number, by?: { ip?: string; userId?: string }): Promise<number> {
  const where = by?.ip !== undefined ? " and ip = ?" : by?.userId !== undefined ? " and userId = ?" : "";
  const binds: unknown[] = [since, ...(by?.ip !== undefined ? [by.ip] : by?.userId !== undefined ? [by.userId] : [])];
  return (await db.prepare(`select count(*) as n from testerRegistration where createdAt >= ?${where}`).bind(...binds).first<{ n: number }>())?.n ?? 0;
}

export async function insertRegistration(db: D1Database, r: Registration): Promise<void> {
  await db
    .prepare(`insert into testerRegistration (id, userId, githubLogin, issuer, jwksUri, jwks, jwksFetchedAt, clientId, trustRowId, authMethod, metadataReport, ip, createdAt, expiresAt) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .bind(r.id, r.userId, r.githubLogin, r.issuer, r.jwksUri, r.jwks, r.jwksFetchedAt, r.clientId, r.trustRowId, r.authMethod, r.metadataReport, r.ip, r.createdAt, r.expiresAt)
    .run();
}

export async function updateJwks(db: D1Database, id: string, jwks: string, now: number): Promise<void> {
  await db.prepare(`update testerRegistration set jwks = ?, jwksFetchedAt = ? where id = ?`).bind(jwks, now, id).run();
}

/** Ends a registration at once (the watcher's or Mark's decision). Its client and trust row stop working now; the purge removes them. */
export async function revoke(db: D1Database, id: string, reason: string, now: number): Promise<boolean> {
  const r = await db.prepare(`update testerRegistration set revokedAt = ?, revokedReason = ? where id = ? and revokedAt is null`).bind(now, reason.slice(0, 300), id).run();
  return (r.meta.changes ?? 0) > 0;
}

export async function countChecks(db: D1Database, since: number, registrationId?: string): Promise<number> {
  const q = registrationId === undefined ? db.prepare(`select count(*) as n from testerCheck where at >= ?`).bind(since) : db.prepare(`select count(*) as n from testerCheck where at >= ? and registrationId = ?`).bind(since, registrationId);
  return (await q.first<{ n: number }>())?.n ?? 0;
}

export async function countServerErrors(db: D1Database, since: number): Promise<number> {
  return (await db.prepare(`select count(*) as n from testerCheck where at >= ? and httpStatus >= 500`).bind(since).first<{ n: number }>())?.n ?? 0;
}

export async function insertCheck(db: D1Database, c: CheckRow): Promise<void> {
  await db.prepare(`insert into testerCheck (id, registrationId, at, jti, httpStatus, error, results) values (?, ?, ?, ?, ?, ?, ?)`).bind(c.id, c.registrationId, c.at, c.jti, c.httpStatus, c.error, c.results).run();
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
  const hour = new Date(now - (now % 3_600_000)).toISOString().slice(0, 13);
  const entries = [...pending.entries()];
  pending.clear();
  await db.batch(entries.map(([name, n]) => db.prepare(`insert into testerCounter (bucket, name, count) values (?, ?, ?) on conflict (bucket, name) do update set count = count + excluded.count`).bind(hour, name, n)));
}

/** Read-only numbers for the watcher (GET /admin/stats). No secrets, no claims. */
export async function stats(db: D1Database, now: number) {
  const day = utcDayStart(now);
  const [state, regs, checks, byStatus, counters, reasons] = await Promise.all([
    isClosed(db),
    db.prepare(`select id, githubLogin, issuer, ip, createdAt, expiresAt, revokedAt, revokedReason, purgedAt from testerRegistration where createdAt >= ? order by createdAt desc limit 50`).bind(now - 3 * DAY_MS).all(),
    countChecks(db, day),
    db.prepare(`select httpStatus, count(*) as n from testerCheck where at >= ? group by httpStatus`).bind(day).all(),
    db.prepare(`select bucket, name, count from testerCounter where bucket >= ? order by bucket desc`).bind(new Date(now - DAY_MS).toISOString().slice(0, 13)).all(),
    db.prepare(`select reason, count(*) as n from idJagAudit where type = 'id-jag.refused' and at >= ? group by reason`).bind(new Date(day).toISOString()).all(),
  ]);
  return { now: new Date(now).toISOString(), state, registrations: regs.results, checksToday: checks, checksTodayByStatus: byStatus.results, counters: counters.results, receiverRefusalsToday: reasons.results };
}

/**
 * Deletes what ended registrations left behind: the client (its tokens and resources cascade), the trust row, the
 * sandbox users, the receiver's audit and replay rows, and the check reports. Then old bookkeeping. Idempotent.
 */
export async function purge(db: D1Database, now: number): Promise<number> {
  const ended = (await db.prepare(`select id, clientId, trustRowId from testerRegistration where purgedAt is null and (revokedAt is not null or expiresAt <= ?) limit 20`).bind(now).all<Pick<Registration, "id" | "clientId" | "trustRowId">>()).results;
  for (const r of ended) {
    const sandbox = `%@${r.id}.sandbox.invalid`;
    await db.batch([
      db.prepare(`delete from "idJagTrustedIssuer" where id = ?`).bind(r.trustRowId),
      db.prepare(`delete from "oauthClient" where clientId = ?`).bind(r.clientId),
      db.prepare(`delete from "session" where userId in (select id from "user" where email like ?)`).bind(sandbox),
      db.prepare(`delete from "account" where userId in (select id from "user" where email like ?)`).bind(sandbox),
      db.prepare(`delete from "user" where email like ?`).bind(sandbox),
      db.prepare(`delete from "idJagAudit" where clientId = ?`).bind(r.clientId),
      db.prepare(`delete from "idJagJti" where clientId = ?`).bind(r.clientId),
      db.prepare(`delete from testerCheck where registrationId = ?`).bind(r.id),
      db.prepare(`update testerRegistration set purgedAt = ?, jwks = '{}', metadataReport = '[]' where id = ?`).bind(now, r.id),
    ]);
  }
  // Bookkeeping kept a week (for the daily limits and the watcher), then gone; so are testers who stopped coming.
  const weekAgo = now - 7 * DAY_MS;
  await db.batch([
    db.prepare(`delete from testerRegistration where purgedAt is not null and purgedAt < ?`).bind(weekAgo),
    db.prepare(`delete from testerCounter where bucket < ?`).bind(new Date(weekAgo).toISOString().slice(0, 13)),
    db.prepare(`delete from "session" where userId in (select u.id from "user" u where u.email not like '%.sandbox.invalid' and u.createdAt < ? and not exists (select 1 from testerRegistration r where r.userId = u.id))`).bind(new Date(weekAgo).toISOString()),
    db.prepare(`delete from "account" where userId in (select u.id from "user" u where u.email not like '%.sandbox.invalid' and u.createdAt < ? and not exists (select 1 from testerRegistration r where r.userId = u.id))`).bind(new Date(weekAgo).toISOString()),
    db.prepare(`delete from "user" where email not like '%.sandbox.invalid' and createdAt < ? and not exists (select 1 from testerRegistration r where r.userId = "user".id)`).bind(new Date(weekAgo).toISOString()),
  ]);
  return ended.length;
}
