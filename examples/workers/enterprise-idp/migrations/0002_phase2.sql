create table "idJagBlock" ("id" text not null primary key, "userId" text, "clientId" text, "audience" text, "reason" text not null, "createdBy" text not null, "createdAt" date not null, "expiresAt" date);

create index "idJagBlock_userId_idx" on "idJagBlock" ("userId");

create index "idJagBlock_clientId_idx" on "idJagBlock" ("clientId");

create index "idJagBlock_audience_idx" on "idJagBlock" ("audience");

create index "idJagBlock_expiresAt_idx" on "idJagBlock" ("expiresAt");
