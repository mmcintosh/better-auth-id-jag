-- The columns @better-auth/oauth-provider 1.8 adds, and its one new index, for a database made on 1.7
-- (from examples/workers/schema.mts run on 1.7.25 and on 1.8.0-beta.10, compared). All can be empty, so existing
-- rows are kept; 1.7 ignores them. Without them, 1.8 refuses to start: "Database schema mismatch".
alter table "oauthClient" add column "sectorIdentifier" text;
alter table "oauthClient" add column "expiresAt" date;
alter table "oauthClient" add column "frontchannelLogoutUri" text;
alter table "oauthClient" add column "frontchannelLogoutSessionRequired" integer;
alter table "oauthClient" add column "requirePushedAuthorizationRequests" integer;
alter table "oauthRefreshToken" add column "grantId" text;
alter table "oauthRefreshToken" add column "acr" text;
alter table "oauthRefreshToken" add column "amr" text;
alter table "oauthAccessToken" add column "grantId" text;
alter table "oauthAccessToken" add column "act" text;
alter table "oauthAccessToken" add column "accessTokenClaims" text;
create index "oauthAccessToken_grantId_idx" on "oauthAccessToken" ("grantId");
