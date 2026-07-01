---
id: logging-security
version: "1.0.0"
title: "Logging Security"
description: "Prevent secret/PII leaks in logs, log-injection attacks, missing audit trails, weak retention"
category: prevention
severity: high
applies_to:
  - "when generating logger calls or structured-logging schemas"
  - "when wiring log shippers, sinks, retention, and access controls"
  - "when reviewing requirements for audit logging"
languages: ["*"]
token_budget:
  minimal: 1000
  compact: 1100
  full: 2400
rules_path: "rules/"
related_skills: ["secret-detection", "error-handling-security", "compliance-awareness"]
last_updated: "2026-06-20"
sources:
  - "OWASP Logging Cheat Sheet"
  - "CWE-532 — Insertion of Sensitive Information into Log File"
  - "CWE-117 — Improper Output Neutralization for Logs"
  - "NIST SP 800-92 (Guide to Computer Security Log Management)"
---

# Logging Security

## Rules (for AI agents)

### ALWAYS
- Log in a **structured format** (JSON or logfmt) with stable field names.
  Include `timestamp`, `service`, `version`, `level`, `trace_id`,
  `span_id`, `user_id` (when authenticated), `request_id`, `event`.
- Run every log message through a **redactor** before it reaches the log
  sink: passwords, tokens, API keys, cookies, full URLs containing
  `?token=`, common PII patterns (SSN-like, credit-card-like, email
  optionally).
- Sanitize newlines / control characters from any user-controlled string
  before logging it (CWE-117): replace `\n`, `\r`, `\t` so an attacker
  can't inject fake log lines.
- Log security-relevant events as **immutable audit records**: login
  success/failure, MFA challenges, password change, role change, access
  grant/revoke, data export, admin action. Audit records get longer
  retention and stricter access.
- Set retention per data category, not globally: short for debug,
  long for audit, no PII after consent expires.
- Ship logs to a centralized, append-only store (Cloud Logging, CloudWatch,
  Elastic, Loki) with read access restricted to engineering / SecOps.
- Alert on missing logs from a service (silent failure) and on log volume
  anomalies (10x spike or 10x drop).

### NEVER
- Log full request / response bodies at INFO. Bodies regularly contain
  passwords, tokens, PII, and uploaded files.
- Log `Authorization` headers, `Cookie` / `Set-Cookie` headers, query-string
  tokens, or any field named `password`, `secret`, `token`, `key`,
  `private`, or `credential` — even after "obfuscation" like `***`.
- Log entire bound SQL statements with their parameter values; log the
  statement template + parameter *names* + a hashed value identifier
  instead.
- Allow unprivileged users to read raw logs containing other users' data.
- Use plain `print()` / `console.log` / `fmt.Println` in production
  services; use the configured logger so redaction and structure are
  applied uniformly.
- Disable logging of failed authentication attempts to "reduce noise" —
  brute-force detection depends on those records.
- Log to a single file on local disk in production; logs there are lost
  when the pod / container / VM dies.

### KNOWN FALSE POSITIVES
- Health-check or load-balancer probe logs can legitimately be downsampled
  / suppressed at the load balancer to save volume.
- A `request_id` value that happens to look like a token is not a token —
  redactors that match patterns can over-redact; whitelist known-safe
  prefixes (your `req_` correlation IDs, for example).
- Anonymous public-API access logs without auth headers are not a privacy
  issue per se; client IPs may still be PII under GDPR.

## Context (for humans)

Logs are the most common place secrets end up in plain text — request
dumps, exception traces, debug prints, third-party SDK telemetry. OWASP's
Logging Cheat Sheet covers the operational rules; NIST SP 800-92 covers
the retention / centralization / audit-trail side. The audit-trail
requirements show up under SOC 2 CC7.2, PCI-DSS 10, HIPAA §164.312(b),
and ISO 27001 A.12.4.

This skill is the partner to `secret-detection` (which scans source) and
`error-handling-security` (which sanitizes the external response). Logs
sit between the two and bleed both directions.


### Verify & lock (triaging a finding)

A scanner/review hit is a *candidate*, not a confirmed bug. Confirm it, fix it,
then lock it so it can't come back.

1. **Confirm it's real (exercise the path, then read the emitted log).** Drive the
   code path with marked sensitive input — a known password, bearer token, API key,
   SSN-like / full-PAN / email value — then grep the *actual* sink output (file,
   stdout, shipper) for it. For log injection (CWE-117), send input carrying `\n`,
   `\r`, CRLF, or ANSI escapes and check whether it forges a second log line or
   spoofs fields. Also check the unhappy path: trigger an exception and inspect the
   error/stack log, and confirm security events (login fail, password/role change,
   data export) actually land. Real if the secret/PII appears verbatim, the forged
   line lands, or the audit record is missing; FP if already redacted (`***`/hash),
   the newline is escaped to one line, or it's a whitelisted safe ID (e.g. `req_`).
2. **Fix, then lock with a regression test** (unit *or* integration — dev's call):
   capture logger output in the test and assert the sensitive field is absent/redacted,
   that CRLF-laced input collapses to a single escaped line, and that the expected
   audit event is emitted — while a benign message still logs normally. Commit it so
   the redactor, sanitizer, and audit call can't be silently dropped.

## References

- `rules/redaction_patterns.json`
- `rules/audit_event_schema.json`
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html).
- [CWE-532](https://cwe.mitre.org/data/definitions/532.html).
- [CWE-117](https://cwe.mitre.org/data/definitions/117.html).
- [NIST SP 800-92](https://csrc.nist.gov/publications/detail/sp/800-92/final).
