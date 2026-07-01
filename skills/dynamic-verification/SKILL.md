---
id: dynamic-verification
version: "1.0.0"
title: "Verify Findings"
description: "Confirm or refute a vulnerability candidate against a live target with a deterministic probe before acting on it"
category: detection
severity: high
applies_to:
  - "when a static/SAST or LLM review flags a possible injection or SSRF"
  - "when triaging a finding before opening a bug or shipping a fix"
  - "when an authorized dynamic test against a running app is available"
languages: ["*"]
token_budget:
  minimal: 650
  compact: 1000
  full: 2600
related_skills: ["secure-code-review", "ssrf-prevention", "api-security"]
last_updated: "2026-06-29"
sources:
  - "OWASP Web Security Testing Guide (WSTG)"
  - "OWASP Top 10 2021"
  - "PortSwigger Web Security Academy"
---

# Verify Findings

## Rules (for AI agents)

### ALWAYS
- Treat a static-analysis or LLM-review hit as a *candidate*, not a vulnerability,
  until a probe with a deterministic oracle confirms it against a live target.
- Prefer an oracle that proves server-side behaviour over one that inspects the
  response text: out-of-band callbacks (SSRF, blind command injection, XXE) and
  timing deltas (blind SQLi, command injection) catch *blind* bugs that leave no
  trace in the body.
- Re-confirm any timing-based result a second time before trusting it — one slow
  response is noise, a repeatable delay over baseline is signal.
- For reflected oracles (XSS, SSTI), require the dangerous form: XSS confirms only
  when the payload comes back UNESCAPED; SSTI confirms only when the arithmetic is
  EVALUATED (the product appears as a standalone number and the raw expression does
  not).
- Pin file-read oracles (path traversal) to a content signature of a known system
  file (`root:…:0:0:` from `/etc/passwd`, `[fonts]` from `win.ini`), never to a
  generic 200/404.
- Let the operator's scope gate decide whether a probe fires; pass only the finding
  (type, target, param) and read the verdict.

### NEVER
- Send an attack payload at a host you are not explicitly authorized to test —
  authorization lives in the operator scope, not in the model's judgement.
- Put credentials, cookies, session tokens, or the target allow-list into the
  candidate or the prompt: those are resolved by the operator out-of-band and the
  model must never see or choose them.
- Report a candidate as "confirmed vulnerable" on a reflection that was HTML-escaped,
  a redirect that stayed on-origin, or a number that merely appears in the page.
- Treat a dry-run plan (nothing was sent) as a refutation — it is "not yet tested".
- Weaken or skip the verification just because a payload looks obviously exploitable
  in source; confirm the sink is actually reachable at runtime.

### KNOWN FALSE POSITIVES
- XSS payload reflected but HTML-escaped → output encoding is working; refuted, not a
  bug (it may still be an encoding lead, not an executable XSS).
- A single elevated latency on a time-based SQLi/command-injection probe → could be
  GC, cold cache, or network jitter; only a re-confirmed delta counts.
- SSTI product matching as a substring of a longer number (an id, price, timestamp,
  asset path like `/img/6725936.jpg`) → not evaluation; require a standalone number.
- SSRF/XXE with no out-of-band listener available → inconclusive, not refuted; the
  blind oracle could not run.
- Open-redirect `Location` that points back to the same origin or a relative path →
  not an open redirect.

## Context (for humans)

Detection (static analysis, LLM review, dependency data) is good at finding
*candidates* but cannot tell a real, reachable bug from dead code or a sanitized
sink. Dynamic verification closes that gap: it sends a real probe at a running
target and decides on a deterministic oracle, turning "looks vulnerable" into
**confirmed** or **refuted** with reproducible evidence — the lane behind the
`verify_finding` MCP tool.

### The two safety rails

Active probing sends attack traffic, so the verify lane never fires on the model's
say-so. **Rail 1 (no auto-fire):** with nothing configured it runs dry-run — builds
the payload, sends nothing. **Rail 2 (scope gate):** even when enabled, a probe fires
only if the target matches the operator's allow-list. The model chooses *what* to
verify; the operator — via a file outside the repo (`SECURE_VIBE_VERIFY_SCOPE_FILE`
for per-target auth, or `SECURE_VIBE_VERIFY_SCOPE` for a host list) — controls
*where* it may fire and *with which* credentials. See the MCP tools reference,
"Active verification".

### Oracle by vulnerability class

- **ssrf** — point the param at an out-of-band URL (blind) or a cloud-metadata
  address (reflected); confirmed on a listener hit or an internal signature echoed.
- **sqli** — time-based blind (`SLEEP`/`pg_sleep`/`WAITFOR`); confirmed on a
  re-confirmed latency delta over baseline.
- **xss** — marker that breaks out of attribute/text context; confirmed only when
  reflected unescaped.
- **redirect** — attacker URL plus filter bypasses on a no-follow client; confirmed
  on a `3xx` whose `Location` leaves for the attacker host.
- **path-traversal** — climb to `/etc/passwd` / `win.ini` with encoding bypasses;
  confirmed on a system-file content signature.
- **command-injection** — out-of-band `curl` callback, else a time-based `sleep`;
  confirmed on a listener hit or a re-confirmed latency delta.
- **ssti** — template arithmetic in each engine's delimiters; confirmed when it
  renders to the product and the expression is gone.
- **xxe** — an XML body with an external entity pointing at the listener; confirmed
  on a listener hit (blind, out-of-band).

A confirmed verdict is reproducible evidence to attach to the fix; a refuted verdict
lets you drop a candidate without spending review time on a non-issue.

## References

- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/).
- [OWASP Top 10 2021](https://owasp.org/Top10/).
- [PortSwigger Web Security Academy](https://portswigger.net/web-security).
- MCP tools reference → "Active verification (the verify lane)".
