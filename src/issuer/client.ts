// Client plugin for the issuer's admin API. Routes are typed from the server plugin, e.g.
//   authClient.idJag.resourceServers.create({ resourceServer: { audience, name, scopes } })
//   authClient.idJag.policies.create({ policy: { resourceServerId, name, subjectKind, clientIds, scopes } })
//   authClient.idJag.blocks.create({ block: { userId, clientId?, audience?, reason, expiresAt? } })
//   authClient.idJag.blocks.createFromJti({ jti, fields?, reason })
//   authClient.idJag.blocks() / .blocks.get({ query: { id } }) / .blocks.delete({ id })
import type { BetterAuthClientPlugin } from "better-auth/client";
import type { idJagIssuer } from "./plugin";

export const idJagIssuerClient = () =>
  ({
    id: "id-jag-issuer",
    $InferServerPlugin: {} as ReturnType<typeof idJagIssuer>,
  }) satisfies BetterAuthClientPlugin;
