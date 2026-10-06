// JIT provisioning's organization membership (D-009 #5, D-A18): a user created by JIT for a trust
// entry that names an organization becomes a member of it, in the organization plugin's own
// representation (a `member` row: organizationId, userId, role, createdAt), written the way
// `@better-auth/sso` writes it (`adapter.create` on `member`, after checking for an existing
// membership and for a pending invitation). Only at creation: an existing user's memberships are
// the host's business (D-A19).
//
// The role: for an sso-trusted issuer, sso's own `organizationProvisioning` (`disabled`, `getRole`,
// `defaultRole`, else "member"); for a static entry or a table row, its `jitRole` (default "member").
//
// Outcomes: a membership is added, or there is nothing to do (no organization on the entry, no
// organization plugin, sso provisioning disabled, already a member, an invitation pending). Anything
// else (the organization doesn't exist, `getRole` throws or returns no role, the role isn't one the
// organization plugin knows, the insert fails) throws: the caller removes the new user and refuses
// the grant (D-A20, D-A26).
import type { GenericEndpointContext, User } from "better-auth";
import { z } from "zod";
import type { IdJagClaims } from "../core";
import type { TrustEntry } from "./options";

export const DEFAULT_JIT_ROLE = "member";

/** The organization plugin's built-in roles (its `defaultRoles`); its `roles` option adds to them. */
export const BUILT_IN_ORGANIZATION_ROLES = ["owner", "admin", "member"] as const;

const organizationOptionsSchema = z.looseObject({
  roles: z.record(z.string(), z.unknown()).optional().nullable(),
  dynamicAccessControl: z.looseObject({ enabled: z.boolean().optional() }).optional().nullable(),
});

/** The roles the organization plugin knows statically, and whether organizations may define more (dynamic access control). */
export interface OrganizationRoles {
  known: Set<string>;
  dynamic: boolean;
}

/** Read from the organization plugin as it validates a member's role (crud-members: defaultRoles plus `roles`). */
export function organizationRoles(plugin: { options?: unknown } | null | undefined): OrganizationRoles {
  const parsed = organizationOptionsSchema.safeParse(plugin?.options ?? {});
  const options = parsed.success ? parsed.data : {};
  return { known: new Set<string>([...BUILT_IN_ORGANIZATION_ROLES, ...Object.keys(options.roles ?? {})]), dynamic: options.dynamicAccessControl?.enabled === true };
}

/** The parts of a role (the organization plugin stores several as "a,b") that aren't statically known. */
export function unknownRoles(memberRole: string, roles: OrganizationRoles): string[] {
  return memberRole.split(",").map((r) => r.trim()).filter((r) => !roles.known.has(r));
}

/** Throws unless every part of the role is the organization plugin's, or (dynamic access control) the organization's own. */
async function assertKnownRole(ctx: GenericEndpointContext, organizationId: string, memberRole: string): Promise<void> {
  const roles = organizationRoles(ctx.context.getPlugin("organization") as { options?: unknown } | null);
  let unknown = unknownRoles(memberRole, roles);
  if (unknown.length > 0 && roles.dynamic) {
    const defined = await ctx.context.adapter.findMany<{ role: string }>({
      model: "organizationRole",
      where: [
        { field: "organizationId", value: organizationId },
        { field: "role", value: unknown, operator: "in" },
      ],
    });
    unknown = unknown.filter((r) => !defined.some((d) => d.role === r));
  }
  if (unknown.length > 0) throw new Error(`role ${unknown.map((r) => JSON.stringify(r)).join(", ")} is not a role of the organization plugin${roles.dynamic ? ` or of organization ${organizationId}` : ""}`);
}

export type MembershipOutcome = "added" | "no-organization" | "no-organization-plugin" | "provisioning-disabled" | "already-member" | "invitation-pending";

const role = z.string().min(1).max(256);

const ssoProvisioningSchema = z.looseObject({
  organizationProvisioning: z
    .looseObject({
      disabled: z.boolean().optional(),
      defaultRole: role.optional(),
      getRole: z.custom<(data: Record<string, unknown>) => unknown>((v) => typeof v === "function").optional(),
    })
    .optional()
    .nullable(),
});

/** The role sso would give this user; null when sso's organization provisioning is disabled. */
async function ssoRole(ctx: GenericEndpointContext, trust: TrustEntry, user: User, claims: IdJagClaims): Promise<string | null> {
  const plugin = ctx.context.getPlugin("sso") as { options?: unknown } | null;
  const parsed = ssoProvisioningSchema.safeParse(plugin?.options ?? {});
  const provisioning = parsed.success ? parsed.data.organizationProvisioning : undefined;
  if (provisioning?.disabled === true) return null;
  if (provisioning?.getRole) {
    const row = await ctx.context.adapter.findOne<Record<string, unknown>>({ model: "ssoProvider", where: [{ field: "providerId", value: trust.id }] });
    let provider: Record<string, unknown> | null = row;
    if (row && typeof row.oidcConfig === "string") {
      try {
        provider = { ...row, oidcConfig: JSON.parse(row.oidcConfig) as unknown };
      } catch {
        provider = row;
      }
    }
    // As sso calls it at sign-in; the ID-JAG's claims stand in for the userinfo, and there is no token.
    const chosen = role.safeParse(await provisioning.getRole({ user, userInfo: { ...claims }, token: undefined, provider }));
    if (!chosen.success) throw new Error("sso organizationProvisioning.getRole returned no role");
    return chosen.data;
  }
  return provisioning?.defaultRole ?? DEFAULT_JIT_ROLE;
}

/** Adds a just-provisioned user to the trust entry's organization. Throws when it should and can't. */
export async function addJitMembership(ctx: GenericEndpointContext, trust: TrustEntry, user: User, claims: IdJagClaims, now: Date): Promise<MembershipOutcome> {
  const organizationId = trust.organizationId;
  if (organizationId === undefined) return "no-organization";
  if (!ctx.context.hasPlugin("organization")) {
    ctx.context.logger.warn(`[id-jag] JIT: trust entry ${trust.source}:${trust.id} names an organization, but the organization plugin is not installed; no membership added.`);
    return "no-organization-plugin";
  }
  const memberRole = trust.source === "sso" ? await ssoRole(ctx, trust, user, claims) : (trust.jitRole ?? DEFAULT_JIT_ROLE);
  if (memberRole === null) return "provisioning-disabled";
  // Static entries are checked at startup too; sso and table rows can only be checked here (D-A26).
  await assertKnownRole(ctx, organizationId, memberRole);
  const { adapter } = ctx.context;
  const organization = await adapter.findOne<Record<string, unknown>>({ model: "organization", where: [{ field: "id", value: organizationId }] });
  if (!organization) throw new Error(`organization ${organizationId} does not exist`);
  const existing = await adapter.findOne<Record<string, unknown>>({
    model: "member",
    where: [
      { field: "organizationId", value: organizationId },
      { field: "userId", value: user.id },
    ],
  });
  if (existing) return "already-member";
  // A pending invitation decides the role (as sso: it doesn't preempt an invitation).
  const invitation = await adapter.findOne<Record<string, unknown>>({
    model: "invitation",
    where: [
      { field: "organizationId", value: organizationId },
      { field: "email", value: user.email.toLowerCase() },
      { field: "status", value: "pending" },
      { field: "expiresAt", value: now, operator: "gt" },
    ],
  });
  if (invitation) return "invitation-pending";
  await adapter.create({ model: "member", data: { organizationId, userId: user.id, role: memberRole, createdAt: now } });
  return "added";
}
