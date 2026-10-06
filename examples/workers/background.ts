// Better Auth runs audit events and other background work through `advanced.backgroundTasks`.
// On Workers that work must be handed to the request's ctx.waitUntil, or it is cut off when the
// response is sent (the audit log stays empty). The auth instance is cached per isolate, so the
// current request's waitUntil travels in an AsyncLocalStorage.
import { AsyncLocalStorage } from "node:async_hooks";

const current = new AsyncLocalStorage<ExecutionContext>();

/** For betterAuth({ advanced: { backgroundTasks } }). */
export const backgroundTasks = {
  handler: (promise: Promise<unknown>) => {
    const ctx = current.getStore();
    if (ctx) ctx.waitUntil(promise);
    else void promise;
  },
};

/** Runs a request's handling with its ExecutionContext available to backgroundTasks. */
export const withExecutionContext = <T>(ctx: ExecutionContext, fn: () => T): T => current.run(ctx, fn);
