// Keycloak's admin REST API, just enough to set up an ID-JAG receiver realm: a realm, a trusted
// identity provider for our issuer, a confidential client allowed the JWT authorization grant, and
// a user pre-linked to our issuer's subject (Keycloak's federated identity link).
// Keycloak's guide: https://www.keycloak.org/securing-apps/identity-assertion-jwt-authorization-grant

export interface KeycloakRealm {
  base: string;
  realm: string;
  /** The realm's issuer identifier: the ID-JAG's `aud`. */
  issuer: string;
  tokenEndpoint: string;
  admin: (path: string, init?: RequestInit) => Promise<Response>;
}

async function adminToken(base: string, user: string, password: string): Promise<string> {
  const res = await fetch(`${base}/realms/master/protocol/openid-connect/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "password", client_id: "admin-cli", username: user, password }),
  });
  if (res.status !== 200) throw new Error(`keycloak admin token: ${res.status} ${await res.text()}`);
  return ((await res.json()) as { access_token: string }).access_token;
}

async function ok(res: Response, what: string) {
  if (res.status >= 300) throw new Error(`keycloak ${what}: ${res.status} ${await res.text()}`);
  return res;
}

/** A fresh realm. */
export async function createRealm(base: string, o: { user?: string; password?: string } = {}): Promise<KeycloakRealm> {
  const token = await adminToken(base, o.user ?? "admin", o.password ?? "admin");
  const admin = (path: string, init: RequestInit = {}) =>
    fetch(`${base}/admin/realms${path}`, { ...init, headers: { authorization: `Bearer ${token}`, "content-type": "application/json", ...(init.headers as Record<string, string> | undefined) } });
  const realm = `idjag-${crypto.randomUUID().slice(0, 8)}`;
  await ok(await admin("", { method: "POST", body: JSON.stringify({ realm, enabled: true }) }), "create realm");
  const issuer = `${base}/realms/${realm}`;
  return { base, realm, issuer, tokenEndpoint: `${issuer}/protocol/openid-connect/token`, admin: (p, i) => admin(`/${realm}${p}`, i) };
}

/** Trust our issuer: an identity provider of the standalone `jwt-authorization-grant` type, or an OIDC broker. */
export async function addIdentityProvider(kc: KeycloakRealm, o: { alias: string; issuer: string; jwksUrl: string; providerId?: "jwt-authorization-grant" | "oidc"; config?: Record<string, string> }) {
  const providerId = o.providerId ?? "jwt-authorization-grant";
  const config: Record<string, string> = {
    issuer: o.issuer,
    jwksUrl: o.jwksUrl,
    useJwksUrl: "true",
    validateSignature: "true",
    jwtAuthorizationGrantEnabled: "true",
    jwtAuthorizationGrantAssertionReuseAllowed: "false",
    jwtAuthorizationGrantMaxAllowedAssertionExpiration: "300",
    ...(providerId === "oidc" ? { authorizationUrl: `${o.issuer}/oauth2/authorize`, tokenUrl: `${o.issuer}/oauth2/token`, clientId: "unused", clientSecret: "unused", clientAuthMethod: "client_secret_basic" } : {}),
    ...o.config,
  };
  await ok(await kc.admin("/identity-provider/instances", { method: "POST", body: JSON.stringify({ alias: o.alias, providerId, enabled: true, config }) }), "create identity provider");
}

/** A confidential client allowed the JWT authorization grant from the given identity provider(s). */
export async function addClient(kc: KeycloakRealm, o: { clientId: string; secret: string; idps: string[] }) {
  await ok(
    await kc.admin("/clients", {
      method: "POST",
      body: JSON.stringify({
        clientId: o.clientId,
        protocol: "openid-connect",
        publicClient: false,
        clientAuthenticatorType: "client-secret",
        secret: o.secret,
        standardFlowEnabled: false,
        directAccessGrantsEnabled: false,
        serviceAccountsEnabled: false,
        consentRequired: false,
        attributes: { "oauth2.jwt.authorization.grant.enabled": "true", "oauth2.jwt.authorization.grant.idp": o.idps.join("##") },
      }),
    }),
    "create client",
  );
}

/** A user, linked to `sub` at the identity provider `alias`. Returns the Keycloak user id. */
export async function addLinkedUser(kc: KeycloakRealm, o: { username: string; email: string; alias: string; sub: string }) {
  const res = await ok(await kc.admin("/users", { method: "POST", body: JSON.stringify({ username: o.username, email: o.email, emailVerified: true, enabled: true, firstName: "Ada", lastName: "Lovelace", requiredActions: [] }) }), "create user");
  const id = (res.headers.get("location") ?? "").split("/").pop() ?? "";
  await ok(await kc.admin(`/users/${id}/federated-identity/${o.alias}`, { method: "POST", body: JSON.stringify({ identityProvider: o.alias, userId: o.sub, userName: o.username }) }), "link user");
  return id;
}

/** The JWT authorization grant at Keycloak's token endpoint. */
export async function redeemAtKeycloak(kc: KeycloakRealm, client: { clientId: string; secret: string }, assertion: string, extra: Record<string, string> = {}) {
  const res = await fetch(kc.tokenEndpoint, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", authorization: `Basic ${btoa(`${encodeURIComponent(client.clientId)}:${encodeURIComponent(client.secret)}`)}` },
    body: new URLSearchParams({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion, ...extra }),
  });
  const text = await res.text();
  let body: Record<string, unknown> = {};
  try {
    body = JSON.parse(text) as Record<string, unknown>;
  } catch {}
  return { status: res.status, body, text };
}
