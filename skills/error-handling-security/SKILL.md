---
id: error-handling-security
version: "1.0.0"
title: "Error-Handling Security"
description: "No stack traces / SQL / paths / framework versions in client responses; generic errors out, structured errors in logs"
category: prevention
severity: medium
applies_to:
  - "when generating HTTP / GraphQL / RPC error handlers"
  - "when generating exception / panic / rescue blocks"
  - "when wiring framework default error pages"
languages: ["*"]
token_budget:
  minimal: 1000
  compact: 900
  full: 1900
rules_path: "rules/"
related_skills: ["api-security", "logging-security"]
last_updated: "2026-06-20"
sources:
  - "OWASP Error Handling Cheat Sheet"
  - "CWE-209 — Generation of Error Message Containing Sensitive Information"
  - "CWE-754 — Improper Check for Unusual or Exceptional Conditions"
---

# Error-Handling Security

## Rules (for AI agents)

### ALWAYS
- Catch exceptions at the boundary (HTTP handler, RPC method, message
  consumer). Log them with full context server-side; return a sanitized
  error externally.
- External error responses include: a stable error code, a short
  human-readable message, and a correlation / request ID. They never
  include: stack trace, SQL fragment, file path, internal hostname,
  framework version banner.
- Log errors at the appropriate level: `ERROR` / `WARN` for actionable
  failures; `INFO` for expected business outcomes; `DEBUG` for diagnostic
  detail (and only when explicitly enabled).
- Return uniform error responses across the API surface — same shape, same
  set of codes — so attackers can't infer behavior from error variation
  (e.g., login: same message and timing for "wrong username" vs "wrong
  password").
- Disable framework default error pages in production
  (`app.debug = False` / `Rails.env.production?` / `Environment=Production`
  / `DEBUG=False`). Replace with a 5xx page that returns only the
  correlation ID.
- Use a centralized error-rendering helper so the sanitization rules are
  in one place, not duplicated.

### NEVER
- Render `traceback.format_exc()`, `e.toString()`, `printStackTrace()`,
  `panic`, or framework debug pages to the client in production.
- Echo SQL queries / parameters in error messages — `IntegrityError:
  duplicate key value violates unique constraint "users_email_key"` tells
  an attacker the table and column name.
- Leak presence-of-record information: `User not found` vs
  `Invalid password` lets an attacker enumerate accounts. Use a single
  message for both.
- Leak filesystem paths (`/var/www/app/src/handlers.py`) or version banners
  (`X-Powered-By: Express/4.17.1`).
- Treat `try / except: pass` as error handling; either the exception is
  expected (log + continue) or it isn't (let it propagate).
- Use 4xx error responses to validate input shape — bots iterate over
  parameters and use the response body to learn the schema. Return a
  uniform 400 plus a correlation ID for malformed input.
- Send full error details (including PII) to third-party error tracking
  services without a scrubber. Redact `password`, `Authorization`,
  `Cookie`, `Set-Cookie`, `token`, `secret`, common PII patterns.

### KNOWN FALSE POSITIVES
- Developer-facing error pages on `localhost` / `*.local` are fine.
- A handful of API endpoints (debug, admin, internal RPC) may legitimately
  return more detail; they must require authenticated, authorized
  callers and never be reachable from the internet.
- Health checks and CI smoke tests intentionally expose details when
  invoked from inside the cluster.

## Context (for humans)

CWE-209 is small text but big impact: it's how attackers go from "this
service exists" to "this service runs Spring 5.2 on Tomcat 9 with a
PostgreSQL table called `users` and a column called `email_normalized`".
Every extra detail in the error message reduces the cost of the next
attack.

This skill is intentionally narrow and pairs with `logging-security` (the
*log* side of the same operation) and `api-security` (the response shape).


### Verify & lock (triaging a finding)

A scanner/review hit is a *candidate*, not a confirmed bug. Confirm it, fix it,
then lock it so it can't come back.

1. **Confirm it's real (force an error and read the response).** Hit the
   suspect endpoint with input that throws — malformed JSON/types, a `'` to
   trip the DB layer, an oversized/missing field, or a route that 500s — and
   inspect the raw HTTP body *and* status. Real if the response leaks a stack
   trace, SQL fragment (`...unique constraint "users_email_key"`), filesystem
   path, internal hostname, framework debug page, or a version banner
   (`X-Powered-By`); also real if errors *differ* (`User not found` vs
   `Invalid password`, or differing status/timing) and let you enumerate. False
   positive if you get a generic sanitized message + stable code + correlation
   ID, identical across cases.
2. **Fix, then lock with a regression test** (unit *or* integration — dev's
   call): assert the forced error returns a generic body with the correct
   status (e.g. uniform 400/500) and a correlation ID, and that the body
   contains NO stack trace, SQL text, path, or version string; assert
   account-enumeration probes return the *same* message/status. Add a positive
   check that the full detail still lands in the server-side log/error tracker
   (redacted). Commit it to CI so the sanitizer can't be silently dropped in a
   later refactor.

## References

- `rules/error_response_template.json`
- `rules/redaction_patterns.json`
- [OWASP Error Handling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html).
- [CWE-209](https://cwe.mitre.org/data/definitions/209.html).
