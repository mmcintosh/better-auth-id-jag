// docs/test-your-idp.md lists every rule the tester reports, and only those: the rule ids in its tables and in the
// code (the checker in src/core/check.ts, and jwks.fetch in the tester's index.ts) must be the same set, so the
// published list can't drift.
import { describe, expect, it } from "vitest";

const workerd = navigator.userAgent === "Cloudflare-Workers";

describe.skipIf(workerd)("tester: the documented rules are the rules in the code", () => {
  it("every rule id in the code is in the doc's tables, and every id there is in the code", async () => {
    const { readFileSync } = await import("node:fs");
    const read = (p: string) => readFileSync(new URL(`../../${p}`, import.meta.url), "utf8");
    const code = read("src/core/check.ts") + read("examples/workers/tester/src/index.ts");
    const inCode = new Set([...code.matchAll(/(?:add\(|id: )"((?:jwt|header|signature|claim|receiver|metadata|jwks)[a-z_.]*)"/g)].map((m) => m[1] as string));
    const doc = read("docs/test-your-idp.md");
    const tables = doc.slice(doc.indexOf("### The rules"), doc.indexOf("### What it doesn't check"));
    const inDoc = new Set([...tables.matchAll(/^\| `([a-z_.]+)`(?:, `([a-z_.]+)`)?(?:, `([a-z_.]+)`)?/gm)].flatMap((m) => [m[1], m[2], m[3]].filter((x): x is string => !!x)));
    expect(inCode.size).toBeGreaterThan(30);
    expect([...inCode].filter((id) => !inDoc.has(id)), "in the code, missing from the doc").toEqual([]);
    expect([...inDoc].filter((id) => !inCode.has(id)), "in the doc, not in the code").toEqual([]);
  });
});
