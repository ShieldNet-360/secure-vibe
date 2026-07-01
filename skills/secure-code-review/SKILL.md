---
id: secure-code-review
version: "1.1.0"
title: "Secure Code Review"
description: "Apply OWASP Top 10 and CWE Top 25 patterns during code generation and review"
category: prevention
severity: high
applies_to:
  - "when generating new code"
  - "when reviewing pull requests"
  - "when refactoring security-sensitive paths (auth, input handling, file I/O)"
  - "when adding new HTTP handlers or endpoints"
languages: ["*"]
token_budget:
  minimal: 700
  compact: 900
  full: 2400
rules_path: "checklists/"
related_skills: ["api-security", "secret-detection", "container-security"]
last_updated: "2026-06-20"
sources:
  - "OWASP Top 10 2021"
  - "CWE Top 25 2023"
  - "SEI CERT Coding Standards"
external_tools:
  - name: semgrep
    purpose: "multi-language SAST (OWASP/CWE rulesets)"
    command: "semgrep --config auto"
---

# Secure Code Review

## Rules (for AI agents)

### ALWAYS
- Use parameterized queries / prepared statements for all database access. Never build
  SQL by string concatenation, even for "trusted" inputs.
- Validate input at the trust boundary — type, length, allowed characters, allowed
  range — and reject before processing.
- Encode output for the rendering context (HTML escape for HTML, URL encode for query
  params, JSON encode for JSON output).
- Use the language's built-in cryptography library, never custom-rolled crypto. Prefer
  AES-GCM for symmetric encryption, Ed25519 / RSA-PSS for signatures, Argon2id /
  bcrypt for password hashing.
- Use `crypto/rand` (Go), `secrets` module (Python), `crypto.randomBytes` (Node.js), or
  the platform CSPRNG for any random value involved in security (tokens, IDs,
  session keys).
- Set explicit security headers on HTTP responses: `Content-Security-Policy`,
  `Strict-Transport-Security`, `X-Content-Type-Options: nosniff`, `Referrer-Policy`.
- Use the principle of least privilege for file paths, database users, IAM policies,
  and process privileges.

### NEVER
- Build SQL/NoSQL queries by string concatenation with user input.
- Pass user input directly to `exec`, `system`, `eval`, `Function()`, `child_process`,
  `subprocess.run(shell=True)`, or any other command-execution path.
- Trust client-side validation. Always re-validate server-side.
- Use `MD5` or `SHA1` for any new security-sensitive purpose (passwords, signatures,
  HMAC). Use SHA-256 / SHA-3 / BLAKE2 / Argon2id instead.
- Use ECB mode for any encryption, ever. Prefer GCM, CCM, or ChaCha20-Poly1305.
- Use `==` for password comparison — use a constant-time comparison
  (`hmac.compare_digest`, `crypto.timingSafeEqual`, `subtle.ConstantTimeCompare`).
- Allow user input to determine file paths without canonicalization and allowlist
  checks (defends against `../../../etc/passwd` style path traversal).
- Disable TLS certificate verification in production code — `verify=False`,
  `InsecureSkipVerify: true`, `rejectUnauthorized: false`.

### KNOWN FALSE POSITIVES
- Internal admin tools intentionally executing shell commands against trusted, fixed
  arguments are acceptable when documented and code-reviewed.
- Cryptographic test vectors using `MD5` / `SHA1` for compatibility with documented
  protocols (e.g. legacy interop tests) are acceptable.
- Constant-time comparison is overkill for non-secret comparisons (string equality in
  logs, tag matching).

## Context (for humans)

Most modern web vulnerabilities boil down to the same handful of root causes: failure
to validate input, failure to use the right cryptographic primitive, failure to apply
least privilege, failure to use the framework's built-in defenses. This skill is the
AI's checklist for not falling into those traps.


### Verify & lock (triaging a finding)

A review produces a *list of candidates*, not confirmed bugs — OWASP/CWE pattern
matches and SAST hits flag *where to look*, not *what is true*. For each finding, run
the same loop before you act, so you fix real issues and lock them against regression.

1. **Confirm it's real (probe per class).** Reproduce the finding with a concrete probe
   matched to its class, and hand off to the domain skill that owns the exact probe:
   DAST/runtime for injection, XSS, auth, SSRF, deserialization; config/behavioral
   checks for container, IaC, IAM, secrets. Check it against the skill's KNOWN FALSE
   POSITIVES first (e.g. documented admin shell-outs, legacy MD5 test vectors) — those
   are pre-cleared. Real only if reproduced; otherwise mark it a false positive with a
   one-line rationale so the same pattern isn't re-raised next review.
2. **Fix, then lock with a regression test** (unit *or* integration — dev's call). For
   every confirmed finding add a test that feeds the attack input and asserts the secure
   outcome (rejected/escaped/denied), plus a benign case that still passes; wire it into
   CI. A finding without a regression test will come back. Commit it so the class can't recur.

Rules: this is the cross-cutting triage discipline that *orchestrates* the domain skills —
it routes each finding to the right class-specific probe rather than re-deriving it here.
Stay framework-agnostic; the proof is the probe and the test, not the pattern match.

## References

- `checklists/owasp_top10.yaml`
- `checklists/injection_patterns.yaml`
- [OWASP Top 10 2021](https://owasp.org/Top10/).
- [CWE Top 25 2023](https://cwe.mitre.org/top25/archive/2023/2023_top25_list.html).
