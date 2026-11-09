-- Daily redemption allowances, taken atomically before a redemption and given back if the receiver didn't authenticate
-- the client. Kept apart from the reports, so deleting reports (the purge, "delete my data") gives no allowance back.
create table "testerAllowance" ("key" text not null primary key, "day" integer not null, "used" integer not null);
