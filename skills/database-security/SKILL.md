---
id: database-security
version: "1.0.0"
title: "Database Security"
description: "Prevent SQL injection, ORM misuse, credential leaks; enforce least-privilege DB users and safe migrations"
category: prevention
severity: critical
applies_to:
  - "when generating SQL or raw query strings"
  - "when generating ORM model code or queries"
  - "when generating database migration files"
  - "when wiring connection strings or pooling"
languages: ["sql", "python", "javascript", "typescript", "go", "ruby", "java", "kotlin", "csharp"]
token_budget:
  minimal: 1000
  compact: 1200
  full: 2500
rules_path: "rules/"
related_skills: ["secret-detection", "api-security", "logging-security"]
last_updated: "2026-06-20"
sources:
  - "OWASP SQL Injection Prevention Cheat Sheet"
  - "OWASP Database Security Cheat Sheet"
  - "CWE-89: Improper Neutralization of Special Elements in an SQL Command"
  - "CIS PostgreSQL / MySQL Benchmarks"
---

# Database Security

## Rules (for AI agents)

### ALWAYS
- Use parameterized queries / prepared statements for any SQL that touches
  user-controlled values. Pass values as parameters, never via string
  concatenation or formatting (`%s`, `+`, template literals).
- Use the ORM's safe query API. In SQLAlchemy: `session.execute(text(":id"),
  {"id": user_id})`. In Django: ORM methods, `Model.objects.filter(...)`. In
  Sequelize / Prisma / SQLAlchemy core: `.where({ ... })` builders. In Go:
  `db.QueryContext(ctx, "select ... where id = $1", id)`.
- Validate that identifier columns / table names — which can't be parameterized —
  come from a hard-coded allowlist, not from user input.
- Use a dedicated database user per application with the minimum grants needed.
  Web apps that only read shouldn't have `INSERT`/`UPDATE`/`DELETE`. Migration
  jobs run as a separate `DDL`-capable user.
- Enable Row-Level Security (Postgres `CREATE POLICY` / Supabase RLS / Azure SQL
  RLS) for multi-tenant tables and set the tenant context per session.
- Pull DB credentials from a secret manager or env var injected at start —
  never from a committed `database.yml` / `.env`. Rotate on schedule.
- Use TLS to the database (`sslmode=require` for Postgres, `requireSSL=true`
  for MySQL, encrypted connection for MSSQL). Pin the CA where the driver
  supports it.
- Connection pooling has a max size that fits within the DB's `max_connections`,
  with healthy back-pressure on the application.

### NEVER
- Concatenate user input into SQL: `"SELECT * FROM users WHERE name='" + name
  + "'"`. Even if you "escape" it yourself — drivers escape correctly only
  when binding through the parameter API.
- Use ORM raw query methods (`.raw()`, `.objects.raw()`, `.query(text(...))`)
  with f-string interpolation of user input.
- Run application workloads as the database superuser / `root` / `postgres` /
  `sa`. Create a service user.
- Disable TLS to the database (`sslmode=disable`, `useSSL=false`).
- Store secrets, PII, or large blobs in JSON columns without encryption-at-rest
  and a key rotation plan.
- Run destructive migrations (DROP TABLE, DROP COLUMN, ALTER COLUMN type changes
  on populated tables) inline with deploys without an expand–contract plan and
  a backup verified to be restorable.
- Bind an internet-exposed database listener with no allowlist; databases stay
  in a private network and are reached via a bastion / VPN / private link.
- Log entire SQL statements with bound values at INFO level — bound values are
  almost always sensitive.

### KNOWN FALSE POSITIVES
- Reporting tools that run analyst-authored ad-hoc SQL legitimately interpolate
  identifiers; they should run against a read-only replica with a separate user
  whose grants prevent damage.
- Some ORMs (Django, SQLAlchemy 1.x) use `%s` placeholders as *parameter
  markers*, not Python format-string placeholders — that's safe.
- Health-check queries (`SELECT 1`) are intentionally trivial.

## Context (for humans)

SQL injection has been #1 or #2 on every OWASP Top 10 for fifteen years and it
hasn't budged because the failure mode is *easy by default*: any language with
string concatenation lets you produce a query. AI assistants happily generate
"works in dev" code that interpolates user input — particularly for sorting
columns, dynamic filters, and pagination.

This skill pairs naturally with `api-security` (which guards the route) and
`secret-detection` (which guards the connection string).


### Verify & lock (triaging a finding)

A scanner/review hit (raw query string-building, an ORM `.raw()`/`text()` with
interpolation, a superuser connection string) is a *candidate*, not a confirmed
bug. Confirm it, fix it, then lock it so it can't come back.

1. **Confirm it's real (probe the suspect input).** Send injection payloads
   through the exact field that reaches the sink — a quote-breaker like
   `' OR '1'='1` or `'; DROP--` for auth/filter params, and a time-based
   `' OR pg_sleep(5)--` (Postgres) / `' OR SLEEP(5)--` (MySQL) / `'+sleep(5)+'`
   (NoSQL `$where`) when output is hidden. A real hit = auth bypass, extra/all
   rows returned, a SQL error echoed, or a ~5s delay. False positive = input is
   already bound via a parameter marker (Django/SQLAlchemy `%s` placeholders are
   safe), or the interpolated token is an allowlisted identifier, not a value.
   Also confirm privilege findings: connect as the app user and try a
   `DELETE`/`DROP`/DDL it shouldn't have — a real hit succeeds.
2. **Fix, then lock with a regression test** (unit *or* integration — dev's
   call): assert the injection payload yields a *secure* outcome — zero rows /
   auth denied / no delay / a parameterized query object, not a built string —
   while a benign value (a real username, a normal id) still returns its correct
   single row. For least-privilege, assert the app user is denied the
   destructive grant. Commit it to CI so the guard can't be silently dropped in
   a later refactor.

## References

- `rules/sql_injection_sinks.json`
- `rules/orm_safe_patterns.json`
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html).
- [CWE-89](https://cwe.mitre.org/data/definitions/89.html) — SQL Injection.
- [PostgreSQL Row-Level Security](https://www.postgresql.org/docs/current/ddl-rowsecurity.html).
