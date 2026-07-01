---
id: compliance-awareness
version: "1.0.0"
title: "Compliance Awareness"
description: "Map generated code against OWASP, CWE, and SANS Top 25 controls for traceability"
category: compliance
severity: medium
applies_to:
  - "when generating code in regulated environments"
  - "when writing audit-relevant comments or documentation"
  - "when refactoring code that crosses compliance boundaries (PII, PHI, PCI scope)"
languages: ["*"]
token_budget:
  minimal: 400
  compact: 700
  full: 2000
rules_path: "frameworks/"
related_skills: ["secure-code-review", "api-security"]
last_updated: "2026-06-20"
sources:
  - "OWASP Top 10 2021"
  - "CWE Top 25 2023"
  - "PCI DSS v4.0"
  - "HIPAA Security Rule"
  - "SOC 2 Trust Services Criteria"
---

# Compliance Awareness

## Rules (for AI agents)

### ALWAYS
- Tag functions that handle PII / PHI / PCI data with a comment indicating the
  classification (e.g. `// classification: PII`).
- Log audit events for security-relevant actions (login, permission change, data
  export, admin operations) — log who, what, when, NOT the sensitive payload.
- Identify the CWE / OWASP category for security-relevant code in comments when the
  team's convention is to include traceability (`// addresses CWE-79 — XSS`).
- For PCI scope, segregate card-data-handling code into clearly-named modules so
  scope boundaries are visible.
- For HIPAA workloads, prefer encryption at rest AND in transit, with documented key
  management.

### NEVER
- Include PII / PHI / PCI in log messages, error messages, or telemetry events.
- Store payment card numbers, CVVs, or full magnetic stripe data outside of a PCI
  DSS-compliant tokenization service.
- Mix PII-handling code into general utility modules without explicit classification.
- Generate code that processes EU residents' personal data without considering GDPR
  obligations (right to erasure, data minimization, lawful basis).
- Suggest workarounds that bypass compliance controls "for development" — these
  workarounds always leak into production.

### KNOWN FALSE POSITIVES
- Logs of *types* of data accessed ("user accessed claim record") are usually fine;
  the rule is against logging the *contents* of sensitive fields.
- Test fixtures using clearly fake data (`555-0100` phone numbers,
  `4111-1111-1111-1111` PAN, `John Doe`) are not PII.
- Audit log retention is intentionally long (often years) and should not be filtered
  by general data-retention sweeps.

## Context (for humans)

Compliance frameworks (PCI DSS, HIPAA, SOC 2, ISO 27001, GDPR) prescribe controls but
don't tell developers what code to write. This skill bridges the gap by attaching
control-relevant guidance to AI generation steps, so the resulting code is
audit-friendly by default.


### Verify & lock (triaging a finding)

A compliance gap flagged in review is a *candidate*, not a confirmed gap. Confirm the
control is actually missing, remediate, then lock it so the control can't silently
regress between audits.

1. **Confirm the gap is real (map to the control + check for evidence).** Tie the
   finding to a specific clause — SOC 2 CC-series, PCI DSS requirement, HIPAA Security
   Rule safeguard, GDPR article — then check whether the technical evidence for that
   control actually exists: encryption-at-rest flag enabled, audit logging on for the
   security-relevant action, MFA enforced on the access path, PII/PHI classification
   tags present, the data-retention/erasure job scheduled and running. Real gap if the
   evidence is absent; false positive if a compensating control (tokenization service,
   network segmentation, an existing managed-encryption layer) already satisfies the
   clause.
2. **Remediate, then lock with an automated control test** (unit *or* integration —
   dev's call). Write a CI check that asserts the control's technical evidence as
   compliance-as-code: the config flag is set, the audit-log entry is emitted for the
   sensitive action, the classification comment/tag is present on the data-handling
   module, the retention policy exists. Add a passing baseline and commit it, so the
   control is verified continuously rather than rediscovered at the next audit.

## References

- `frameworks/owasp_mapping.yaml`
- `frameworks/cwe_mapping.yaml`
- [OWASP Top 10 2021](https://owasp.org/Top10/).
- [CWE Top 25 2023](https://cwe.mitre.org/top25/archive/2023/2023_top25_list.html).
- [PCI DSS v4.0](https://www.pcisecuritystandards.org/document_library/).
