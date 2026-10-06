// Registry lookups at exchange time: the enabled, valid resource servers for an audience, each with
// its enabled, valid policies. Cached per isolate (hits and misses, capped), so unknown audiences
// don't each cost a read; other isolates see a change within `cacheSeconds` (D-027's design).
import type { GenericEndpointContext } from "better-auth";
import { POLICY_MODEL, RESOURCE_SERVER_MODEL } from "./schema";
import { type PolicyConfig, type PolicyRecord, readPolicy, readResourceServer, type ResourceServerConfig, type ResourceServerRecord } from "./records";

const MAX_CACHED = 2000;
const MAX_PER_AUDIENCE = 100;
const MAX_POLICIES = 1000;

export type UsableResourceServer = ResourceServerRecord & { config: ResourceServerConfig };
export type UsablePolicy = PolicyRecord & { config: PolicyConfig };
export interface AudienceEntry {
  resourceServer: UsableResourceServer;
  policies: UsablePolicy[];
}

export class RegistryDirectory {
  private readonly cache = new Map<string, { at: number; entries: AudienceEntry[] }>();
  constructor(private readonly o: { cacheSeconds: number; allowLoopbackHttp: boolean }) {}

  invalidate(): void {
    this.cache.clear();
  }

  async lookup(ctx: GenericEndpointContext, audience: string): Promise<AudienceEntry[]> {
    const now = Date.now();
    const hit = this.cache.get(audience);
    if (hit && now - hit.at < this.o.cacheSeconds * 1000) return hit.entries;
    const entries = await this.load(ctx, audience);
    if (this.o.cacheSeconds > 0) {
      if (this.cache.size >= MAX_CACHED) this.cache.clear();
      this.cache.set(audience, { at: now, entries });
    }
    return entries;
  }

  private async load(ctx: GenericEndpointContext, audience: string): Promise<AudienceEntry[]> {
    const adapter = ctx.context.adapter;
    const rows = await adapter.findMany<Record<string, unknown>>({ model: RESOURCE_SERVER_MODEL, where: [{ field: "audience", value: audience }], limit: MAX_PER_AUDIENCE });
    const entries: AudienceEntry[] = [];
    // Exact match, whatever the collation (a case-insensitive one would widen the lookup).
    for (const row of rows.filter((r) => r.audience === audience)) {
      const rs = await readResourceServer(row, { allowLoopbackHttp: this.o.allowLoopbackHttp });
      if (!rs.valid || !rs.config) {
        ctx.context.logger.warn(`[id-jag] resource server ${rs.id} no longer validates; not used: ${rs.issues.join("; ")}`);
        continue;
      }
      if (!rs.enabled) continue;
      const policyRows = await adapter.findMany<Record<string, unknown>>({ model: POLICY_MODEL, where: [{ field: "resourceServerId", value: rs.id }], limit: MAX_POLICIES });
      const policies: UsablePolicy[] = [];
      for (const pr of policyRows) {
        const p = readPolicy(pr);
        if (!p.valid || !p.config) {
          ctx.context.logger.warn(`[id-jag] policy ${p.id} no longer validates; not used: ${p.issues.join("; ")}`);
          continue;
        }
        if (p.enabled && p.config.resourceServerId === rs.id) policies.push(p as UsablePolicy);
      }
      entries.push({ resourceServer: rs as UsableResourceServer, policies });
    }
    return entries;
  }
}
