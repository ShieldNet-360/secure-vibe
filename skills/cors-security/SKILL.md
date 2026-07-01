---
id: cors-security
version: "1.0.0"
title: "CORS Security"
description: "Strict CORS configuration: no wildcard with credentials, allowlist-based origins, sensible preflight cache, minimal exposed headers"
category: prevention
severity: high
applies_to:
  - "when generating CORS middleware or framework config"
  - "when wiring API Gateway / Cloud Front / Nginx CORS headers"
  - "when reviewing a cross-origin browser-facing endpoint"
languages: ["*"]
token_budget:
  minimal: 1000
  compact: 1000
  full: 2000
rules_path: "rules/"
related_skills: ["frontend-security", "api-security"]
last_updated: "2026-06-20"
sources:
  - "OWASP HTML5 Security Cheat Sheet — CORS"
  - "CWE-942 — Permissive Cross-domain Policy with Untrusted Domains"
  - "Fetch Living Standard (CORS)"
---

# CORS Security

## Rules (for AI agents)

### ALWAYS
- Use an **allowlist** of origins, not `*`. Reflect the incoming `Origin`
  header only when it matches a known entry from configuration (or matches
  a precompiled regex of operator-controlled hostnames).
- If responses include credentials (cookies, `Authorization`), set
  `Access-Control-Allow-Credentials: true` **and** ensure
  `Access-Control-Allow-Origin` is a single specific origin string —
  never `*`.
- Include `Vary: Origin` on responses whose body depends on the request
  `Origin`, so caches don't serve one origin's response to another.
- Restrict preflight `Access-Control-Allow-Methods` to the actual methods
  the endpoint accepts; restrict `Access-Control-Allow-Headers` to the
  actual headers consumed.
- Set `Access-Control-Max-Age` to a sensible value (≤ 86400 in production)
  to amortize preflight latency without locking in a bad allowlist.
- Maintain the allowlist in code (or in a config file checked into
  source), not derived from a database — so attackers can't add their
  origin by inserting a row.

### NEVER
- Set `Access-Control-Allow-Origin: *` together with
  `Access-Control-Allow-Credentials: true`. The Fetch spec forbids it for
  a reason — browsers will refuse the response, but the bigger problem is
  that an upstream proxy / cache may already have leaked it.
- Reflect the `Origin` header without an allowlist check (`Access-Control-
  Allow-Origin: <Origin>` for every incoming origin). That's the same as
  `*` for credentials but with worse caching behavior.
- Allow `null` as an Origin. `null` is what Chrome sends from sandboxed
  iframes, `data:` URIs, and `file://` — none of which should have
  credentialed access to your API.
- Allow arbitrary subdomains with a regex like `.*\.example\.com$` without
  considering subdomain takeover. Pin specific subdomains; treat
  `*.example.com` as a deliberate decision tied to subdomain ownership
  controls.
- Expose internal headers via `Access-Control-Expose-Headers`. Limit to
  the minimal set the frontend genuinely needs.
- Use CORS as authorization. CORS is a *browser* policy; it does not stop
  server-to-server, curl, or non-browser clients. Authenticate the
  request properly.

### KNOWN FALSE POSITIVES
- Truly public, unauthenticated APIs (e.g., open data, marketing CDN
  endpoints) can legitimately use `Access-Control-Allow-Origin: *`
  *without* credentials.
- Internal admin tools restricted to a private network can use a single
  fixed origin; the wildcard concern doesn't apply because there are no
  cross-origin callers.
- A handful of integrations (Stripe.js, Plaid, Auth0) expect specific CORS
  headers — read each provider's CORS section before relaxing the
  baseline.

## Context (for humans)

CORS is widely misunderstood as a security control. It isn't — it's a
*relaxation* of the same-origin policy. The security control is
authentication. CORS misconfiguration matters because, when combined with
cookies or `Authorization` headers, it gives untrusted origins the ability
to make credentialed cross-origin requests and read the response.

This skill is short by design — the matrix of bad combinations is finite
and the rules are blunt.


### Verify & lock (triaging a finding)

A scanner/review hit is a *candidate*, not a confirmed bug. Confirm it, fix it,
then lock it so it can't come back.

1. **Confirm it's real (probe the suspect input).** Replay a request to the endpoint
   with a forged `Origin` header the allowlist should reject — `Origin: https://evil.example`,
   then separately `Origin: null` — and send credentials (cookie or `Authorization`).
   A real hit: the response echoes `Access-Control-Allow-Origin: https://evil.example`
   (or `null`, or `*`) **together with** `Access-Control-Allow-Credentials: true`, meaning
   the attacker's page can read the credentialed response. A false positive: the server
   omits the ACAO header, returns a fixed trusted origin regardless of input, or sends
   `*` with **no** credentials on a genuinely public endpoint — also watch for `*.example.com`
   regexes that match attacker-controlled subdomains, and missing `Vary: Origin` on cached responses.
2. **Fix, then lock with a regression test** (unit *or* integration — dev's call): assert that
   requests with `Origin: https://evil.example` and `Origin: null` yield no reflected ACAO (never
   `*` paired with `Allow-Credentials: true`), while a known-good origin from the allowlist is
   reflected as a single specific value with `Vary: Origin` present. Commit it to CI so the guard
   can't be silently dropped in a later refactor.

## References

- `rules/cors_safe_config.json`
- [OWASP CORS Origin Header Scrutiny](https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny).
- [CWE-942](https://cwe.mitre.org/data/definitions/942.html).
- [Fetch — CORS protocol](https://fetch.spec.whatwg.org/#http-cors-protocol).
