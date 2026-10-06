// Serve a Better Auth handler over real HTTP (Node's http module; no extra dependency), so a
// container can fetch our issuer's JWKS. Node only: import it dynamically from gated tests.
import { createServer, type IncomingMessage, type Server } from "node:http";
import type { AddressInfo } from "node:net";

export interface Served {
  port: number;
  /** Every request the server saw: method and path. */
  seen: string[];
  close(): Promise<void>;
}

/** Listen on 127.0.0.1 (port 0 = any free one) and route every request to `handler()` once it is set. */
export async function listen(port = 0): Promise<Served & { use(handler: (r: Request) => Promise<Response>): void }> {
  let handler: ((r: Request) => Promise<Response>) | undefined;
  const seen: string[] = [];
  const server: Server = createServer(async (req, res) => {
    seen.push(`${req.method} ${req.url}`);
    try {
      if (!handler) throw new Error("no handler yet");
      const response = await handler(await toRequest(req, port === 0 ? (server.address() as AddressInfo).port : port));
      res.statusCode = response.status;
      response.headers.forEach((v, k) => {
        if (k !== "set-cookie") res.setHeader(k, v);
      });
      const cookies = response.headers.getSetCookie();
      if (cookies.length) res.setHeader("set-cookie", cookies);
      res.end(Buffer.from(await response.arrayBuffer()));
    } catch (e) {
      res.statusCode = 500;
      res.end(String(e));
    }
  });
  await new Promise<void>((resolve) => server.listen(port, "127.0.0.1", resolve));
  const actual = (server.address() as AddressInfo).port;
  return {
    port: actual,
    seen,
    use(h) {
      handler = h;
    },
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

async function toRequest(req: IncomingMessage, port: number): Promise<Request> {
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  const headers = new Headers();
  for (const [k, v] of Object.entries(req.headers)) if (v !== undefined) headers.set(k, Array.isArray(v) ? v.join(", ") : v);
  const method = req.method ?? "GET";
  return new Request(`http://localhost:${port}${req.url ?? "/"}`, { method, headers, ...(method === "GET" || method === "HEAD" ? {} : { body: Buffer.concat(chunks) }) });
}
