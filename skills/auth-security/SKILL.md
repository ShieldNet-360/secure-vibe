---
id: auth-security
version: "1.0.0"
title: "Authentication & Authorization Security"
description: "JWT, OAuth 2.0 / OIDC, session management, CSRF, password hashing, and MFA enforcement"
category: prevention
severity: critical
applies_to:
  - "when generating login / signup / password-reset flows"
  - "when generating JWT issuance or verification"
  - "when generating OAuth 2.0 / OIDC client or server code"
  - "when wiring session cookies, CSRF tokens, MFA"
languages: ["*"]
token_budget:
  minimal: 1000
  compact: 1300
  full: 2700
rules_path: "rules/"
related_skills: ["api-security", "crypto-misuse", "secret-detection"]
last_updated: "2026-06-20"
sources:
  - "OWASP Authentication Cheat Sheet"
  - "OWASP Session Management Cheat Sheet"
  - "RFC 6749 — OAuth 2.0"
  - "RFC 7519 — JSON Web Token"
  - "RFC 9700 — OAuth 2.0 Security BCP"
  - "NIST SP 800-63B (Authenticator Assurance)"
---

# Authentication & Authorization Security

## Rules (for AI agents)

### ALWAYS
- For JWT verification, pin the expected algorithm (`RS256`, `EdDSA`, or `ES256`)
  and verify `iss`, `aud`, `exp`, `nbf`, and `iat`. Reject `alg=none` and any
  unexpected algorithm.
- For OAuth 2.0 public clients (SPA / mobile / CLI), use the **authorization
  code flow with PKCE** (S256). Never the implicit flow. Never the resource
  owner password credentials grant.
- Cookies for sessions: `Secure; HttpOnly; SameSite=Lax` (or `Strict` for
  sensitive flows). Use the `__Host-` prefix when there's no subdomain sharing.
- Rotate the session identifier on login and on privilege change. Bind the
  session to the user agent only as a soft signal — never as the sole check.
- Hash passwords with argon2id (m=64 MiB, t=3, p=1) and a per-user random salt.
  Bcrypt cost ≥ 12 or scrypt N≥2^17 are acceptable alternatives for legacy
  systems. PBKDF2-SHA256 requires ≥ 600,000 iterations (OWASP 2023 minimum).
- Enforce password length ≥ 12 characters with no composition rules; allow
  Unicode; check candidate passwords against a known-breached list
  (HIBP / pwned-passwords k-anonymity API).
- Implement account lockout *or* rate limiting for password attempts (NIST
  SP 800-63B §5.2.2: at most 100 failures over 30 days).
- Implement CSRF protection for state-changing requests reachable from a
  browser session: synchronizer token, double-submit cookie, or
  `SameSite=Strict` for high-risk endpoints.
- Require MFA / step-up for administrative operations, password changes,
  MFA-device changes, billing changes.
- For OIDC, validate the `nonce` you sent against the `nonce` in the ID token;
  validate the `at_hash` / `c_hash` when present.

### NEVER
- Use `Math.random()` (or any non-CSPRNG) to generate session IDs, reset
  tokens, MFA recovery codes, or API keys.
- Accept JWT `alg=none`; or accept HS256 from a client when the issuer signs
  with RS256 (classic algorithm-confusion attack).
- Compare passwords or token hashes with `==` / `strcmp`; use a constant-time
  comparator.
- Store passwords reversibly (encrypted instead of hashed). Storage must be
  one-way.
- Leak which of username/password was wrong. Return a generic
  "invalid credentials" message.
- Put access tokens, refresh tokens, or session IDs in URL query strings —
  they leak to logs, Referer headers, and browser history.
- Use `localStorage` / `sessionStorage` to hold long-lived refresh tokens.
  Use HttpOnly cookies.
- Trust client-supplied roles / claims at the API layer — re-derive the
  authenticated subject and look up server-side authorization on each request.
- Issue long-lived (>1 hour) access tokens; rely on refresh tokens with
  rotation.
- Use the implicit flow or the password grant.

### KNOWN FALSE POSITIVES
- Service-to-service tokens with long TTLs are sometimes acceptable when stored
  in a secret manager and bound to a specific workload identity.
- Local-development "magic link" auth without password hashing for ephemeral
  dev users is fine if it's gated behind an env flag and disabled in prod.
- Tokens in URL query are tolerable in *one* place — the OAuth authorization
  code return — because the value is short-lived and one-time-use.

## Context (for humans)

Authentication failures show up consistently in OWASP Top 10 (A07:2021 —
Identification and Authentication Failures). The common modes are: weak
password storage, predictable tokens, missing MFA, JWT misconfiguration, and
session fixation. RFC 9700 (OAuth 2.0 Security BCP) and NIST SP 800-63B are
the authoritative references for the recipe.

AI assistants tend to ship "works in dev" auth: HS256 JWTs with hard-coded
secrets, `bcrypt.hash` with default cost 10, no PKCE, tokens in localStorage.
This skill catches each of those.


### Verify & lock (triaging a finding)

A scanner/review hit is a *candidate*, not a confirmed bug. Confirm it, fix it,
then lock it so it can't come back.

1. **Confirm it's real (probe the suspect input).** Replay the protected request with the credential weakened, not just absent. For broken authz, hit another user's object / an admin route as a low-privilege (or unauthenticated) caller and re-derive the subject server-side — a `200` with real data where you expected `401`/`403` confirms it. For JWT, resend the token with `alg` flipped to `none`/`HS256` (signed with the public key), `exp` in the past, or a swapped `iss`/`aud`; acceptance = real hit. For sessions, capture the pre-login session ID, authenticate, and check it didn't rotate (fixation); for reset/MFA, request many tokens and test for predictability (non-CSPRNG), reuse, or no expiry. A false positive looks like the same probe returning `401`/`403`, a rejected token, or a rotated identifier.
2. **Fix, then lock with a regression test** (unit *or* integration — dev's call): assert the attack input yields the secure outcome — cross-user/role-escalation request → `403`; `alg=none`/expired/wrong-aud token → rejected; pre-auth session ID → changed after login; reset/MFA tokens → CSPRNG, single-use, time-boxed; wrong password → generic error with no user/pass distinction. Pair each with a benign case that must still pass (legitimate owner → `200`, valid token verified, correct login succeeds) so the guard isn't just blanket-denying. Commit it to CI so the guard can't be silently dropped in a later refactor.

## References

- `rules/jwt_safe_config.json`
- `rules/oauth_flows.json`
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html).
- [RFC 9700 — OAuth 2.0 Security BCP](https://datatracker.ietf.org/doc/html/rfc9700).
- [NIST SP 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html).
