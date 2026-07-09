---
id: security-regression-tests
version: "1.0.0"
title: "Security Regression Tests"
description: "Lock every confirmed security fix with a deterministic regression test so CI re-verifies it on every build (no live probing)"
category: prevention
severity: medium
applies_to:
  - "when a security finding has been confirmed and fixed"
  - "when generating or changing security-sensitive code (authz, input handling, secrets)"
  - "when wiring a security gate into CI/CD"
languages: ["*"]
token_budget:
  minimal: 600
  compact: 950
  full: 1800
related_skills: ["dynamic-verification", "secure-code-review", "api-security"]
last_updated: "2026-07-08"
sources:
  - "OWASP Web Security Testing Guide (WSTG)"
  - "Google Testing Blog — regression testing"
---

# Security Regression Tests

## Rules (for AI agents)

### ALWAYS
- For every **confirmed and fixed** security finding, add a regression test that
  pins the secure behaviour, and commit it. The test is the durable, CI-side
  verification — it re-checks the fix on every build, unlike a one-off live probe.
- Structure each test as **attack + control**: the attack input now yields the
  secure outcome (`403`/`404`, rejected, escaped, not evaluated, no exec), AND a
  legitimate input still succeeds. Both assertions matter — the attack half guards
  the vulnerability; the control half catches an over-correction that breaks the
  feature.
- Map the test to the finding's class:
  - IDOR/BOLA → authenticate as A, request B's resource id → `403`/`404`.
  - Broken auth → forged / expired / `none`-alg token → `401`.
  - Mass assignment → POST an extra privileged field → it is ignored, never persisted.
  - SQLi / XSS / SSTI → the payload is parameterized / escaped / not evaluated.
  - Secret → the secret is absent from the built artifact and loaded from the env.
- Prefer the **smallest tier that proves it**: a unit test on the handler/guard
  covers most authz/validation; use an integration test only when the bug lives at
  a boundary (routing, middleware order, ORM).
- Name and place the test so a reviewer sees it guards a security fix
  (`test_idor_orders_cross_tenant_403`) and reference the finding.

### NEVER
- Close a confirmed finding without a regression test — "fixed by inspection" rots;
  the next refactor silently reintroduces it.
- Assert only the happy path — without the attack assertion the test does not guard
  the bug at all.
- Put a **live-target probe inside CI** as the verification. CI must be
  deterministic and offline; the regression test replaces the probe. Live probing
  stays an in-session, agent-driven activity ([[dynamic-verification]]).
- Hardcode a real secret/token into a fixture to exercise a secret check — use an
  obviously-fake sentinel.

### KNOWN FALSE POSITIVES
- A **refuted** candidate (not a real bug) needs no regression test — do not add
  tests for non-issues.
- Config / infra findings (a Dockerfile `USER`, a workflow permission, a bad
  dependency) are locked by the **scanner gate** in CI (`secure-vibe audit
  --fail-on`), not a unit test — there, the gate *is* the regression check.

## Context (for humans)

Verification splits by *where* it runs. In an interactive session an agent can
confirm a finding **live** against a running target ([[dynamic-verification]]).
CI has no agent and must never send attack traffic — so the CI-side verification is
a **regression test**: when you fix a finding you also write a deterministic test
that replays the attack input and asserts the secure outcome, plus a control that
the feature still works. That test runs on every build, turning a one-time
confirmation into a permanent guard.

This is how "VERIFY" shows up in a pipeline: not a probe, but a committed test that
your normal suite and the `secure-vibe audit` gate enforce. A confirmed bug that
ships without one is a bug waiting to come back.

## References

- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/).
- Related skills: `dynamic-verification`, `secure-code-review`, `api-security`.
