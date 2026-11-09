// Fingerprints instead of identities. The abuse record keeps a keyed hash of a tester's account and address, not the
// account or address: the same account always gives the same fingerprint, but a fingerprint can't be turned back
// into it. The key changes every week and is deleted once nothing uses it, after which even we can't tell whose a
// fingerprint was. The blocklist has its own key, kept only while something is blocked.

export const WEEK_MS = 7 * 86_400_000;
/** Where testers' made-up email addresses live: a reserved name that never receives mail. */
export const TESTER_EMAIL_DOMAIN = "testers.invalid";
/** The key id for a time: weeks counted from the Unix epoch, so a week never splits a UTC day. */
export const weekKeyId = (now: number) => `w${Math.floor(now / WEEK_MS)}`;
export const BLOCK_KEY_ID = "block";

const random = () => btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))));

/** The part of D1 this module uses (so its pure helpers typecheck without the Workers types). */
interface Db {
  prepare(query: string): { bind(...values: unknown[]): { run(): Promise<unknown>; first<T>(): Promise<T | null> } };
}

/** The key with this id, made the first time it is needed. Two isolates racing both read the one that was stored. */
export async function fingerprintKey(db: Db, id: string, now: number): Promise<string> {
  await db.prepare(`insert into testerKey (id, key, createdAt) values (?, ?, ?) on conflict (id) do nothing`).bind(id, random(), now).run();
  const row = await db.prepare(`select key from testerKey where id = ?`).bind(id).first<{ key: string }>();
  if (!row) throw new Error("fingerprint key missing");
  return row.key;
}

/** HMAC-SHA-256 of the value under the key: 128 bits, hex. */
export async function fingerprint(key: string, value: string): Promise<string> {
  const k = await crypto.subtle.importKey("raw", Uint8Array.from(atob(key), (c) => c.charCodeAt(0)), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", k, new TextEncoder().encode(value)));
  return [...mac.slice(0, 16)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** The address's neighbourhood: its /24 for IPv4, its /48 for IPv6, so moving to the next address doesn't hide anyone. */
export function network(ip: string): string {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return `${ip.split(".").slice(0, 3).join(".")}.0/24`;
  if (ip.includes(":")) {
    const [head = "", tail = ""] = ip.toLowerCase().split("::");
    const left = head ? head.split(":") : [];
    const right = tail ? tail.split(":") : [];
    const groups = ip.includes("::") ? [...left, ...Array(Math.max(0, 8 - left.length - right.length)).fill("0"), ...right] : left;
    return `${groups.slice(0, 3).map((g) => g.replace(/^0+(?=.)/, "")).join(":")}::/48`;
  }
  return ip;
}

/** An account's age as a range: enough to tell a throwaway from an established account, nothing more. */
export function ageBucket(createdAt: number, now: number): string {
  const days = (now - createdAt) / 86_400_000;
  return days < 30 ? "under 30 days" : days < 365 ? "30 days to 1 year" : days < 5 * 365 ? "1 to 5 years" : "over 5 years";
}
