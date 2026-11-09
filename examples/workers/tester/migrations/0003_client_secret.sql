-- The registration's client secret, encrypted (src/seal.ts), so "Check an ID-JAG" can redeem with it. Deleted with the
-- registration's row.
alter table "testerRegistration" add column "clientSecretEnc" text;
