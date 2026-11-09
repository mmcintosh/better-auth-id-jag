// A Worker may not make random values (or fetch, or set timers) while its modules load: Cloudflare refuses to deploy
// it ("Disallowed operation called within global scope"). The test runtime doesn't enforce that, so this does, for
// the tester's own modules: loading them with crypto's random functions throwing must not throw.
import { afterEach, describe, expect, it, vi } from "vitest";

describe("tester: nothing random while the modules load", () => {
  afterEach(() => vi.restoreAllMocks());

  it("loads the Worker's modules without calling crypto's random functions", async () => {
    vi.resetModules();
    const calls: string[] = [];
    vi.spyOn(crypto, "randomUUID").mockImplementation(() => {
      calls.push("randomUUID");
      throw new Error("randomUUID at load time");
    });
    vi.spyOn(crypto, "getRandomValues").mockImplementation(() => {
      calls.push("getRandomValues");
      throw new Error("getRandomValues at load time");
    });
    for (const m of ["index", "auth", "guard", "pages", "privacy", "store", "logo", "app", "seal", "limits"]) await import(`../../examples/workers/tester/src/${m}.ts`);
    expect(calls).toEqual([]);
  });

  it("the Worker's entry module exports only its handler (the runtime treats any other export as an entry point)", async () => {
    vi.resetModules();
    expect(Object.keys(await import("../../examples/workers/tester/src/index"))).toEqual(["default"]);
  });
});
