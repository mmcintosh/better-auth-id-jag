-- One row per run of the whole flow, from /flow/start until /flow/callback takes it (at most 10 minutes): what the
-- callback needs. The IdP client's secret and the PKCE verifier are sealed (src/seal.ts). Deleted when the callback
-- takes it, when it expires (the purge), or with its registration. probes: 1 when the tester asked for the refusal
-- probes (src/probes.ts).
create table "testerFlow" ("stateHash" text not null primary key, "registrationId" text not null, "userId" text not null, "tokenEndpoint" text not null, "idpClientId" text not null, "idpSecretEnc" text not null, "authMethod" text not null, "scope" text not null, "verifierEnc" text not null, "nonce" text not null, "probes" integer not null default 0, "createdAt" integer not null, "expiresAt" integer not null);
create index "testerFlow_registrationId_idx" on "testerFlow" ("registrationId");
create index "testerFlow_userId_idx" on "testerFlow" ("userId");
create index "testerFlow_expiresAt_idx" on "testerFlow" ("expiresAt");
