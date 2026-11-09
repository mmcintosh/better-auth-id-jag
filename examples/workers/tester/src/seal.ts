// The registration's client secret, kept encrypted while the registration lasts, so the tester can redeem the ID-JAGs
// a tester pastes into "Check an ID-JAG" with their own client. AES-GCM under a key derived (HKDF) from the
// deployment's BETTER_AUTH_SECRET; the row, and the secret with it, is deleted when the registration ends.

const encoder = new TextEncoder();
const b64 = (b: ArrayBuffer | Uint8Array) => btoa(String.fromCharCode(...new Uint8Array(b)));
const unb64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

async function key(secret: string): Promise<CryptoKey> {
  const base = await crypto.subtle.importKey("raw", encoder.encode(secret), "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info: encoder.encode("idjag-tester client secret") }, base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

/** "iv.ciphertext", both base64. */
export async function seal(secret: string, plaintext: string): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, await key(secret), encoder.encode(plaintext));
  return `${b64(iv)}.${b64(ct)}`;
}

/** The plaintext, or null when it can't be opened (another deployment's secret, or tampered with). */
export async function open(secret: string, sealed: string): Promise<string | null> {
  const [iv, ct] = sealed.split(".");
  if (!iv || !ct) return null;
  try {
    return new TextDecoder().decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(iv) }, await key(secret), unb64(ct)));
  } catch {
    return null;
  }
}
