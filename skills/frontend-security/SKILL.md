---
id: frontend-security
version: "1.0.0"
title: "Frontend Security"
description: "Browser-side hardening: XSS, CSP, CORS, SRI, DOM clobbering, iframe sandboxing, Trusted Types"
category: prevention
severity: high
applies_to:
  - "when generating HTML / JSX / Vue / Svelte templates"
  - "when wiring up response headers in a web app"
  - "when adding third-party script tags or CDN resources"
languages: ["html", "javascript", "typescript", "tsx", "jsx", "vue", "svelte"]
token_budget:
  minimal: 1000
  compact: 1200
  full: 2800
rules_path: "rules/"
related_skills: ["cors-security", "auth-security", "logging-security"]
last_updated: "2026-06-20"
sources:
  - "OWASP XSS Prevention Cheat Sheet"
  - "OWASP Content Security Policy Cheat Sheet"
  - "CWE-79: Improper Neutralization of Input During Web Page Generation"
  - "MDN Trusted Types"
---

# Frontend Security

## Rules (for AI agents)

### ALWAYS
- Treat all user/URL/storage data as untrusted. Render via framework
  escaping (`{}` in JSX/Vue/Svelte, `{{ }}` in templating). For raw HTML use a
  vetted sanitizer (DOMPurify) with a strict allowlist.
- Send a strict `Content-Security-Policy` header. Minimum production baseline:
  `default-src 'self'; script-src 'self' 'nonce-<random>'; object-src 'none';
  base-uri 'self'; frame-ancestors 'none'; form-action 'self';
  upgrade-insecure-requests`. Use nonces or hashes — never `'unsafe-inline'` for
  `script-src`.
- Set `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`,
  `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer-when-downgrade`
  or stricter, and `Permissions-Policy` to drop unused features.
- Add `integrity="sha384-..." crossorigin="anonymous"` to every `<script>` and
  `<link rel="stylesheet">` loaded from a CDN.
- Add `sandbox="allow-scripts allow-same-origin"` (only the attributes you need)
  to every `<iframe>`. Default to no allow flags.
- Use cookies with `Secure; HttpOnly; SameSite=Lax` (or `Strict` for sensitive
  flows). `__Host-` prefix when there's no subdomain sharing.
- Enable Trusted Types where browser support allows
  (`Content-Security-Policy: require-trusted-types-for 'script'`) so DOM-sink
  assignments (`innerHTML`, `setAttribute('src', ...)` for scripts) must be
  routed through a typed policy.

### NEVER
- Use `dangerouslySetInnerHTML`, `v-html`, `{@html ...}`, `innerHTML =`, or
  `document.write` with untrusted input.
- Use `eval`, `new Function`, `setTimeout(string)`, `setInterval(string)`, or
  `Function('return x')`.
- Inject user input into `href`, `src`, `formaction`, `action`, or any URL-bearing
  attribute without scheme validation (block `javascript:`, `data:`, `vbscript:`).
- Use `target="_blank"` without `rel="noopener noreferrer"` — leaks
  `window.opener`.
- Trust DOM nodes by id alone. DOM clobbering: an attacker-controlled
  `<input name="config">` shadows `window.config`.
- Use `postMessage` without checking `event.origin` against an allowlist.
- Store JWTs, refresh tokens, or PII in `localStorage` / `sessionStorage` —
  any XSS exfiltrates them. Prefer HttpOnly cookies.
- Read or write `document.cookie` from JavaScript for auth cookies — they
  should be HttpOnly anyway.

### KNOWN FALSE POSITIVES
- Internal admin tools deliberately rendering Markdown / rich text from trusted
  authors may use `dangerouslySetInnerHTML` after a sanitizer pass; document the
  sanitizer call inline.
- Browser extensions sometimes need `'unsafe-eval'` in the extension CSP;
  user-facing web app CSP should still forbid it.
- WebSocket connections to non-same-origin endpoints are fine when the server
  performs origin validation.

## Context (for humans)

The OWASP XSS Prevention Cheat Sheet is still the authoritative reference for the
escaping rules; CSP is the defense-in-depth layer that turns one missed escape
into a logged report rather than a stolen session. Trusted Types is the newer
browser-enforced pattern that pushes the "did this go through a sanitizer?"
question from runtime audit to type system.

AI-generated frontends commonly reach for `innerHTML` and `dangerouslySetInnerHTML`
because they're shorter; this skill is the counterweight.


### Verify & lock (triaging a finding)

A scanner/review hit is a *candidate*, not a confirmed bug. Confirm it, fix it,
then lock it so it can't come back.

1. **Confirm it's real (probe the suspect sink).** Drive the value into the sink the
   finding names and check whether it actually *executes*. For XSS (reflected/stored/DOM,
   `dangerouslySetInnerHTML`/`v-html`/`innerHTML`/`document.write`), load the page in a
   headless browser, feed a live payload (`<img src=x onerror=...>`, `"><script>...`,
   or `javascript:` in an `href`/`src`), and confirm a callback fires (alert/DOM
   mutation/network beacon). Execution = real; output that comes back HTML-escaped or
   stripped by the sanitizer = FP. For a missing/weak header (CSP with `'unsafe-inline'`,
   absent `frame-ancestors`/SRI/iframe `sandbox`, `target="_blank"` without `rel`), fetch
   the live response and assert the header/attribute is genuinely absent or permissive —
   not set by a proxy/CDN one layer up.
2. **Fix, then lock with a regression test** (unit *or* integration — dev's call):
   render or submit the payload and assert it appears escaped in the DOM with no script
   execution, while a benign value still renders normally; for header findings, assert the
   response carries the strict directive (no `'unsafe-inline'`, `frame-ancestors 'none'`,
   `integrity=`/`sandbox=` present). Unit level asserts escaped output; integration/
   headless-browser level asserts the payload never executes. Commit it to CI so the guard
   can't be silently dropped in a later refactor.

## References

- `rules/csp_defaults.json`
- `rules/xss_sinks.json`
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html).
- [OWASP CSP Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html).
- [CWE-79](https://cwe.mitre.org/data/definitions/79.html) — Cross-site scripting.
- [Trusted Types (MDN)](https://developer.mozilla.org/en-US/docs/Web/API/Trusted_Types_API).
