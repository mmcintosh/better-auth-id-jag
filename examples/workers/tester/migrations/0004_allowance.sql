-- Daily redemption allowances, taken atomically before a redemption (once the client's secret is checked) and given
-- back if it doesn't count. Kept apart from the reports, so deleting reports (the purge, "delete my data") gives no
-- allowance back. Seeded from the reports already written, so deploying this doesn't reset the day's usage.
create table "testerAllowance" ("key" text not null primary key, "day" integer not null, "used" integer not null);
insert into "testerAllowance" ("key", "day", "used") select 'registration:' || "registrationId" || ':' || ("at" - "at" % 86400000), "at" - "at" % 86400000, count(*) from "testerCheck" group by "registrationId", "at" - "at" % 86400000;
insert into "testerAllowance" ("key", "day", "used") select 'everyone:' || ("at" - "at" % 86400000), "at" - "at" % 86400000, count(*) from "testerCheck" group by "at" - "at" % 86400000;
-- When the report's JWKS was last asked for, successful or not (jwksFetchedAt stays the last success): one fetch a
-- minute per registration, claimed by one request at a time.
alter table "testerRegistration" add column "jwksAttemptAt" integer not null default 0;
