// Build the published package: ESM bundled per entry (dependencies external), plus .d.ts from tsc.
import { execFileSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { build } from "esbuild";

const root = new URL("..", import.meta.url).pathname;
rmSync(`${root}dist`, { recursive: true, force: true });
await build({
  absWorkingDir: root,
  entryPoints: ["src/index.ts", "src/client.ts"],
  outdir: "dist",
  bundle: true,
  format: "esm",
  platform: "neutral",
  target: "es2022",
  packages: "external",
  sourcemap: true,
  logLevel: "warning",
});
execFileSync("npx", ["tsc", "-p", "tsconfig.build.json"], { cwd: root, stdio: "inherit" });

// Sources use extensionless relative imports (moduleResolution "Bundler"). Consumers on
// "NodeNext" need explicit extensions in declaration files (both `from "./x"` and the inline
// `import("./x")` tsc emits), so add them.
for (const file of readdirSync(`${root}dist`, { recursive: true, encoding: "utf8" }).filter((f) => f.endsWith(".d.ts"))) {
  const path = `${root}dist/${file}`;
  const dir = dirname(path);
  const src = readFileSync(path, "utf8");
  // A directory import ("./core") becomes "./core/index.js", a file import ("./jwt") "./jwt.js".
  const out = src.replace(/(from\s+|import\()(["'])(\.{1,2}\/[^"']+)\2/g, (m, pre, q, spec) =>
    /\.(js|mjs|cjs|json)$/.test(spec) ? m : `${pre}${q}${spec}${existsSync(join(dir, spec, "index.d.ts")) ? "/index" : ""}.js${q}`,
  );
  if (out !== src) writeFileSync(path, out);
}
