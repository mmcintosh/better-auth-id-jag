declare namespace Cloudflare {
  interface Env {
    DB: D1Database;
  }
}

// Vite's ?raw imports (the tester's migrations, in test/examples/tester-worker.test.ts).
declare module "*.sql?raw" {
  const text: string;
  export default text;
}
