-- The tester's own tables (src/store.ts). Times are Unix milliseconds.

-- One row per registration: a tester's issuer, the client it got here, and when it ends.
create table "testerRegistration" ("id" text not null primary key, "userId" text not null, "githubLogin" text not null, "issuer" text not null, "jwksUri" text not null, "jwks" text not null, "jwksFetchedAt" integer not null, "clientId" text not null, "trustRowId" text not null, "authMethod" text not null, "metadataReport" text not null, "ip" text, "createdAt" integer not null, "expiresAt" integer not null, "revokedAt" integer, "revokedReason" text, "purgedAt" integer);
create index "testerRegistration_clientId_idx" on "testerRegistration" ("clientId");
create index "testerRegistration_issuer_idx" on "testerRegistration" ("issuer");
create index "testerRegistration_userId_idx" on "testerRegistration" ("userId");
create index "testerRegistration_createdAt_idx" on "testerRegistration" ("createdAt");

-- One row per redemption: the rule-by-rule report and the HTTP answer.
-- checkedAgainst: the draft and package version the rules came from, so a later draft doesn't make old results look wrong.
create table "testerCheck" ("id" text not null primary key, "registrationId" text not null, "at" integer not null, "jti" text, "httpStatus" integer not null, "error" text, "results" text not null, "checkedAgainst" text not null);
create index "testerCheck_registrationId_at_idx" on "testerCheck" ("registrationId", "at");
create index "testerCheck_at_idx" on "testerCheck" ("at");

-- The stored kill switch (one row, id 'main').
create table "testerState" ("id" text not null primary key, "closed" integer not null, "reason" text, "changedAt" integer not null, "changedBy" text);

-- Hourly counts of what isn't stored row by row (rate-limited requests, failed bot checks, ...).
create table "testerCounter" ("bucket" text not null, "name" text not null, "count" integer not null, primary key ("bucket", "name"));
