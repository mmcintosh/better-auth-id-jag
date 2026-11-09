declare namespace Cloudflare {
  interface Env {
    DB: D1Database;
  }
}

// Vite's ?raw imports (the tester's migrations, in test/examples/tester-worker.test.ts; scripts/build.mjs, in
// test/build-script.test.ts).
declare module "*.mjs?raw" {
  const text: string;
  export default text;
}
declare module "*.sql?raw" {
  const text: string;
  export default text;
}
