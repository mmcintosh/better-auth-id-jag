// The tester's fingerprints (examples/workers/tester/src/privacy.ts): the same input under one key always matches,
// another key never does; networks group neighbouring addresses; ages are ranges.
import { describe, expect, it } from "vitest";
import { ageBucket, fingerprint, network, WEEK_MS, weekKeyId } from "../../examples/workers/tester/src/privacy";

const key = (b: number) => btoa(String.fromCharCode(...new Uint8Array(32).fill(b)));

describe("tester: fingerprints", () => {
  it("are stable under one key, differ under another, and don't contain the input", async () => {
    const a = await fingerprint(key(1), "github:42");
    expect(await fingerprint(key(1), "github:42")).toBe(a);
    expect(await fingerprint(key(2), "github:42")).not.toBe(a);
    expect(await fingerprint(key(1), "github:43")).not.toBe(a);
    expect(a).toMatch(/^[0-9a-f]{32}$/);
  });

  it("networks: an IPv4 /24 and an IPv6 /48, however the address is written", () => {
    expect(network("198.51.100.7")).toBe("198.51.100.0/24");
    expect(network("198.51.100.200")).toBe("198.51.100.0/24");
    expect(network("2001:db8:abcd:12::1")).toBe("2001:db8:abcd::/48");
    expect(network("2001:0db8:abcd:0012:0000:0000:0000:0001")).toBe("2001:db8:abcd::/48");
    expect(network("2001:db8::1")).toBe("2001:db8:0::/48");
  });

  it("ages are ranges, and a week's key id never splits a UTC day", () => {
    const now = Date.UTC(2026, 10, 7);
    expect(ageBucket(now - 10 * 86_400_000, now)).toBe("under 30 days");
    expect(ageBucket(now - 100 * 86_400_000, now)).toBe("30 days to 1 year");
    expect(ageBucket(now - 1000 * 86_400_000, now)).toBe("1 to 5 years");
    expect(ageBucket(now - 3000 * 86_400_000, now)).toBe("over 5 years");
    expect(WEEK_MS % 86_400_000).toBe(0);
    // Weeks are whole UTC days from the epoch, so the last millisecond of a day has that day's key.
    expect(weekKeyId(now + 86_400_000 - 1)).toBe(weekKeyId(now));
    expect(weekKeyId(now)).not.toBe(weekKeyId(now + WEEK_MS));
  });
});
