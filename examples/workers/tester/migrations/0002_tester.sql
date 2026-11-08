-- The tester's own tables (src/store.ts). Times are Unix milliseconds.

-- One row per registration, deleted (with everything it made) within minutes of the registration ending. Pending
-- until its first ID-JAG signed with the issuer's own key (confirmedAt); only a confirmed one has a trust row.
-- blockAccountFp and blockNetFp: the tester's account and address network under the blocklist key, so the watcher
-- can block them while the registration lasts; never kept after it.
create table "testerRegistration" ("id" text not null primary key, "userId" text not null, "issuer" text not null, "jwksUri" text not null, "jwks" text not null, "jwksFetchedAt" integer not null, "clientId" text not null, "trustRowId" text not null, "authMethod" text not null, "metadataReport" text not null, "blockAccountFp" text not null, "blockNetFp" text not null, "createdAt" integer not null, "expiresAt" integer not null, "confirmedAt" integer, "revokedAt" integer, "revokedReason" text);
create index "testerRegistration_clientId_idx" on "testerRegistration" ("clientId");
create index "testerRegistration_issuer_idx" on "testerRegistration" ("issuer");
create index "testerRegistration_userId_idx" on "testerRegistration" ("userId");

-- One row per redemption: the rule-by-rule report and the HTTP answer. Deleted with its registration.
-- checkedAgainst: the draft and package version the rules came from, so a later draft doesn't make old results look wrong.
create table "testerCheck" ("id" text not null primary key, "registrationId" text not null, "at" integer not null, "jti" text, "httpStatus" integer not null, "error" text, "results" text not null, "checkedAgainst" text not null);
create index "testerCheck_registrationId_at_idx" on "testerCheck" ("registrationId", "at");
create index "testerCheck_at_idx" on "testerCheck" ("at");

-- The abuse record, kept 7 days: fingerprints (keyed hashes) of the account, address and network, never the account
-- or address; the key's id (keyId) is deleted a week after its week ends, and with it any way to link a row to anyone.
create table "testerAbuse" ("id" text not null primary key, "at" integer not null, "keyId" text not null, "provider" text not null, "accountFp" text not null, "ipFp" text not null, "netFp" text not null, "accountAge" text not null, "issuerHost" text not null, "confirmed" integer not null default 0, "redemptions" integer not null default 0, "refusals" integer not null default 0, "ended" text);
create index "testerAbuse_at_idx" on "testerAbuse" ("at");

-- Fingerprint keys: one per week ("w<n>"), and the blocklist's ("block"), kept only while something is blocked.
create table "testerKey" ("id" text not null primary key, "key" text not null, "createdAt" integer not null);

-- Accounts and networks the watcher or Mark blocked, as blocklist-key fingerprints, for 30 days.
create table "testerBlock" ("fp" text not null primary key, "kind" text not null, "reason" text not null, "createdAt" integer not null, "expiresAt" integer not null);

-- The stored kill switch (one row, id 'main').
create table "testerState" ("id" text not null primary key, "closed" integer not null, "reason" text, "changedAt" integer not null, "changedBy" text);

-- Hourly counts of what isn't stored row by row (rate-limited requests, failed bot checks, ...). No personal data.
create table "testerCounter" ("bucket" text not null, "name" text not null, "count" integer not null, primary key ("bucket", "name"));
