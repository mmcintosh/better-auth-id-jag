// Plan §3.3 step 4: who may have an ID-JAG for which audience, with which scopes. Deny by default
// (S1): no source configured, no resource server for the audience, or no matching policy is a
// refusal, never "allow all". Each configured source must allow (code hook and registry), and the
// narrower outcome wins: scopes intersect, the shortest lifetime wins, email only if every source
// opts in. Scopes only narrow (S7): never wider than requested ∩ allowed. Before any source, an
// administrator's block (blocks.ts) refuses outright.
//
// S8 ordering: the refusals that would tell the caller something about our policies (no policy,
// policy denied) are all `invalid_grant` with one generic body, like unknown or banned users. The
// two specific refusals (`no_scope`, `unknown_resource`) come only **after** a policy allowed: by
// then the caller could have learnt the allow anyway (by asking for no scope or no resource).
import type { GenericEndpointContext, User } from "better-auth";
import { z } from "zod";
import { MAX_LIFETIME_SECONDS, refuse } from "../core";
import { checkBlocks } from "./blocks";
import type { AudienceEntry, RegistryDirectory } from "./directory";
import type { AuthorizeInput, AuthorizeResult, PolicyClient, ResolvedIssuerOptions, SubjectTokenClaims } from "./options";
import { isResourceUri } from "./url";

export interface PolicyRequest {
  ctx: GenericEndpointContext;
  user: User & Record<string, unknown>;
  client: PolicyClient;
  audience: string;
  resource?: string | undefined;
  requestedScopes: string[];
  subjectToken: SubjectTokenClaims;
}

/** What to mint. */
export interface Grant {
  scopes: string[];
  resource?: string | undefined;
  lifetimeSeconds: number;
  clientIdAtResource: string;
  includeEmail: boolean;
  tenant?: string | undefined;
  /** Which sources allowed (for the audit detail). */
  sources: ("registry" | "authorize")[];
}

/** One source's allow, before combining. */
interface Allow {
  scopes: string[];
  resource?: string | undefined;
  /** Only resources from this set (the registry's resource server), when set. */
  allowedResources?: string[] | undefined;
  requireResource?: boolean | undefined;
  lifetimeSeconds?: number | undefined;
  clientIdAtResource?: string | undefined;
  email: boolean;
  tenant?: string | undefined;
}

const verdictSchema = z.discriminatedUnion("decision", [
  z.object({
    decision: z.literal("allow"),
    scopes: z.array(z.string().min(1).max(256)).max(1000),
    resource: z.string().refine(isResourceUri).optional(),
    lifetimeSeconds: z.number().int().min(1).optional(),
    clientIdAtResource: z.string().min(1).max(512).optional(),
    claims: z.object({ email: z.boolean().optional(), tenant: z.string().min(1).max(512).optional() }).optional(),
  }),
  z.object({ decision: z.literal("deny"), reason: z.string().optional() }),
]);

const truthy = (v: unknown) => v === true || v === 1 || v === "1" || v === "true";

/** The user's organizations, from the organization plugin's `member` table when it is installed. */
async function membershipsOf(ctx: GenericEndpointContext, userId: string): Promise<Set<string>> {
  if (!ctx.context.hasPlugin("organization")) return new Set();
  const rows = await ctx.context.adapter.findMany<{ organizationId?: unknown; userId?: unknown }>({ model: "member", where: [{ field: "userId", value: userId }], limit: 1000 });
  return new Set(rows.filter((r) => r.userId === userId && typeof r.organizationId === "string").map((r) => r.organizationId as string));
}

/** The admin plugin's role field: a comma-separated list. */
const rolesOf = (user: Record<string, unknown>) =>
  new Set(
    String(user.role ?? "")
      .split(",")
      .map((r) => r.trim())
      .filter(Boolean),
  );

async function fromRegistry(directory: RegistryDirectory, r: PolicyRequest): Promise<Allow> {
  const entries = await directory.lookup(r.ctx, r.audience);
  if (entries.length === 0) refuse("no_policy", "no resource server for this audience");
  const orgs = entries.some((e) => e.resourceServer.config.organizationId !== undefined || e.policies.some((p) => p.config.subjectKind === "organization")) ? await membershipsOf(r.ctx, r.user.id) : new Set<string>();
  const roles = rolesOf(r.user);
  // A resource server of an organization applies only to that organization's members.
  const applicable = entries.filter((e) => e.resourceServer.config.organizationId === undefined || orgs.has(e.resourceServer.config.organizationId));
  if (applicable.length === 0) refuse("no_policy", "no resource server for this audience applies to this user");
  const matches = (e: AudienceEntry) =>
    e.policies.filter((p) => {
      const c = p.config;
      if (!c.clientIds.includes(r.client.clientId)) return false;
      switch (c.subjectKind) {
        case "everyone":
          return true;
        case "users":
          return c.subjectRef.includes(r.user.id);
        case "role":
          return c.subjectRef.some((x) => roles.has(x));
        case "organization":
          return c.subjectRef.some((x) => orgs.has(x));
      }
      return false;
    });
  const allowing = applicable.map((e) => ({ e, policies: matches(e) })).filter((x) => x.policies.length > 0);
  if (allowing.length === 0) refuse("policy_denied", "no policy for this user and client");
  // Two resource servers (e.g. the host's and an organization's) for one audience, both allowing:
  // which one's scopes and client id to use is ambiguous, so neither is used.
  if (allowing.length > 1) refuse("policy_denied", `ambiguous: ${allowing.length} resource servers for this audience allow it`);
  const { e, policies } = allowing[0] as (typeof allowing)[number];
  const rsScopes = new Set(e.resourceServer.config.scopes);
  const scopes = [...new Set(policies.flatMap((p) => p.config.scopes.filter((s) => rsScopes.has(s))))];
  const lifetimes = policies.map((p) => p.config.lifetimeSeconds).filter((x): x is number => x !== undefined);
  return {
    scopes,
    allowedResources: e.resourceServer.config.resources,
    requireResource: e.resourceServer.config.requireResource,
    ...(lifetimes.length ? { lifetimeSeconds: Math.min(...lifetimes) } : {}),
    ...(e.resourceServer.config.clientIdsAtResource[r.client.clientId] !== undefined ? { clientIdAtResource: e.resourceServer.config.clientIdsAtResource[r.client.clientId] } : {}),
    email: policies.some((p) => p.config.includeEmail),
    ...(e.resourceServer.config.organizationId !== undefined ? { tenant: e.resourceServer.config.organizationId } : {}),
  };
}

async function fromHook(hook: (input: AuthorizeInput) => unknown, r: PolicyRequest): Promise<Allow> {
  let verdict: unknown;
  try {
    verdict = await hook({ ctx: r.ctx, user: r.user, client: r.client, audience: r.audience, resource: r.resource, requestedScopes: [...r.requestedScopes], subjectToken: r.subjectToken });
  } catch (e) {
    r.ctx.context.logger.error("[id-jag] authorize threw; denied", e);
    return refuse("policy_denied", "authorize threw");
  }
  const parsed = verdictSchema.safeParse(verdict);
  if (!parsed.success) return refuse("policy_denied", "authorize returned a malformed verdict");
  const v = parsed.data as AuthorizeResult;
  if (v.decision !== "allow") return refuse("policy_denied", `authorize: ${v.reason ?? "denied"}`);
  return {
    scopes: [...new Set(v.scopes)],
    ...(v.resource !== undefined ? { resource: v.resource } : {}),
    ...(v.lifetimeSeconds !== undefined ? { lifetimeSeconds: v.lifetimeSeconds } : {}),
    ...(v.clientIdAtResource !== undefined ? { clientIdAtResource: v.clientIdAtResource } : {}),
    email: truthy(v.claims?.email),
    ...(v.claims?.tenant !== undefined ? { tenant: v.claims.tenant } : {}),
  };
}

/** Agree, or refuse: two sources that name different values for one claim can't both be honoured. */
function agree(name: string, values: (string | undefined)[]): string | undefined {
  const set = new Set(values.filter((v): v is string => v !== undefined));
  if (set.size > 1) refuse("policy_denied", `sources disagree on ${name}`);
  return [...set][0];
}

/** Runs every configured source and combines their allows; throws IdJagRefusal on any deny. */
export async function decide(options: ResolvedIssuerOptions, directory: RegistryDirectory | undefined, r: PolicyRequest): Promise<Grant> {
  const allows: Allow[] = [];
  const sources: Grant["sources"] = [];
  // An administrator's block (D-B16) wins over every source; same body as any other deny (S8).
  await checkBlocks(r.ctx, { userId: r.user.id, clientId: r.client.clientId, audience: r.audience });
  if (!directory && !options.authorize) refuse("no_policy", "no policy source configured");
  if (directory) {
    allows.push(await fromRegistry(directory, r));
    sources.push("registry");
  }
  if (options.authorize) {
    allows.push(await fromHook(options.authorize, r));
    sources.push("authorize");
  }

  // Resource: the one the client asked for, or (when it asked for none) one a source named.
  if (r.resource !== undefined && allows.some((a) => a.resource !== undefined && a.resource !== r.resource)) refuse("policy_denied", "a source named another resource");
  const resource = r.resource ?? agree("resource", allows.map((a) => a.resource));
  const clientIdAtResource = agree("the client id at the resource", allows.map((a) => a.clientIdAtResource)) ?? r.client.clientId;
  const tenant = agree("tenant", allows.map((a) => a.tenant));

  // Scopes: every source's ∩, then ∩ the requested ones when any were requested.
  let allowed = allows[0]?.scopes ?? [];
  for (const a of allows.slice(1)) allowed = allowed.filter((s) => a.scopes.includes(s));
  const scopes = r.requestedScopes.length > 0 ? r.requestedScopes.filter((s) => allowed.includes(s)) : allowed;
  if (r.requestedScopes.length > 0 && scopes.length === 0) refuse("no_scope", `requested ${r.requestedScopes.join(" ")}`);

  // After an allow (see the top of this file): the resource must be registered.
  for (const a of allows) {
    if (a.allowedResources === undefined) continue;
    if (resource === undefined && a.requireResource) refuse("unknown_resource", "this resource server requires a resource");
    if (resource !== undefined && !a.allowedResources.includes(resource)) refuse("unknown_resource", resource);
  }

  const lifetimes = allows.map((a) => a.lifetimeSeconds).filter((x): x is number => x !== undefined);
  const lifetimeSeconds = Math.min(lifetimes.length ? Math.min(...lifetimes) : options.defaultLifetimeSeconds, MAX_LIFETIME_SECONDS);
  return {
    scopes,
    ...(resource !== undefined ? { resource } : {}),
    lifetimeSeconds,
    clientIdAtResource,
    includeEmail: allows.length > 0 && allows.every((a) => a.email),
    ...(tenant !== undefined ? { tenant } : {}),
    sources,
  };
}
