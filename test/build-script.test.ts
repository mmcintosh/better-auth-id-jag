// scripts/build.mjs turns its own file URL into a path with fileURLToPath: URL.pathname leaves a space as %20, so the
// build failed in a checkout such as "~/My Projects/" (D-070). CI builds from a path without one, so this holds it.
import { describe, expect, it } from "vitest";
import build from "../scripts/build.mjs?raw";

describe("scripts/build.mjs", () => {
  it("takes its root with fileURLToPath, never from URL.pathname", () => {
    expect(build).toMatch(/const root = fileURLToPath\(new URL\("\.\.", import\.meta\.url\)\);/);
    expect(build).not.toMatch(/import\.meta\.url\)\.pathname/);
  });
});
