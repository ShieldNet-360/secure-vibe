---
id: api-security
version: "1.1.0"
title: "API Security"
description: "Apply OWASP API Top 10 patterns to authentication, authorization, and input validation"
category: prevention
severity: high
applies_to:
  - "when generating HTTP handlers"
  - "when generating GraphQL resolvers"
  - "when generating gRPC service methods"
  - "when reviewing API endpoint changes"
languages: ["*"]
token_budget:
  minimal: 750
  compact: 1100
  full: 2700
rules_path: "checklists/"
related_skills: ["secure-code-review", "secret-detection", "ssrf-prevention"]
last_updated: "2026-06-20"
sources:
  - "OWASP API Security Top 10 2023"
  - "OWASP Authentication Cheat Sheet"
  - "OAuth 2.0 Security Best Current Practice (RFC 9700)"
---

# API Security

## Rules (for AI agents)

### ALWAYS
- Require authentication on every non-public endpoint. Default to authenticated; opt
  out for genuinely public routes by explicit annotation.
- Apply authorization at the object level — confirm the authenticated subject actually
  has access to the requested resource ID, not just that they're logged in (defeats
  the OWASP API1 BOLA / IDOR class).
- Validate all request inputs against an explicit schema (JSON Schema, Pydantic,
  Zod, validator/v10 struct tags). Reject early; never propagate untrusted input
  deeper.
- Enforce rate limits at the route level for authentication endpoints, password reset,
  and any expensive operation.
- Use short-lived access tokens (≤ 1 hour) with refresh tokens, not long-lived bearer
  tokens.
- Return generic error messages externally (`invalid credentials`) and log specifics
  internally — avoid leaking which of username/password was wrong.
- Include `Cache-Control: no-store` on responses containing personal or sensitive
  data.

### NEVER
- Use sequential integer IDs in URLs for resources accessible across tenants. Use
  UUIDs or unguessable opaque IDs.
- Trust `Authorization` headers without verifying the signature and expiration.
- Accept `none` algorithm JWTs. Pin the expected algorithm at verification time.
- Mass-assign request bodies directly to ORM models (`User(**request.json)`) — this
  enables privilege escalation when the model has admin fields the user shouldn't
  control.
- Disable CSRF protection on state-changing endpoints used by browsers.
- Return stack traces or framework error pages to the client in production.
- Use `HTTP GET` for any state-changing operation — GET should be safe and
  idempotent.
- Rely on **network position** (IP allowlist, VPN, private subnet, "internal
  only", a WAF/edge rule) as the *only* control on a sensitive endpoint.
  Reachability is not authentication: the moment there's an SSRF, a compromised
  internal host, a tenant on the network, or a boundary change, an
  unauthenticated "internal" endpoint (`permission_classes = [AllowAny]`,
  no `RequireAuth`) is wide open. Enforce auth/authz at the service itself,
  behind any network control.
- Place security controls (auth, field-stripping, CSRF, rate-limit, input
  validation) only at a gateway / BFF / proxy while the backend service is
  **also directly reachable**. An attacker calls the service directly and
  bypasses every proxy-layer control — controls must live at the service that
  owns the data. (A common variant: the gateway checks that a JWT is *present*
  but the service never checks the caller's *role*.)

### KNOWN FALSE POSITIVES
- Public marketing-site endpoints serving anonymous traffic legitimately have no auth
  and no rate limits beyond the load balancer.
- Sequential IDs in paths are fine for genuinely public, non-tenant-scoped resources
  (e.g. blog post slugs, public product catalog items).
- Health-check endpoints (`/healthz`, `/ready`) intentionally bypass auth.
- A network control (mTLS service mesh, NetworkPolicy, private ingress) is fine
  as **defense-in-depth** — the anti-pattern is only when it's the *sole* control
  and the service itself authenticates nothing.
- Mutual-TLS / SPIFFE workload identity between services **is** authentication
  (a cryptographic caller identity), not mere network position — mTLS-authenticated
  service-to-service calls are fine even on a private network.

## Context (for humans)

The OWASP API Top 10 differs from the web Top 10 mostly because APIs have weaker
defaults: they often skip CSRF, they expose object IDs directly, and they tend to
trust developer-provided client-side state. This skill codifies the most common
high-impact mistakes.

A recurring architectural failure is **trusting the perimeter instead of the
service**: a BFF/gateway enforces auth, strips fields, and checks CSRF, while the
core service is also directly reachable and authenticates nothing because it's
"internal". Anyone who can reach the core service — via SSRF, a foothold inside
the allowlisted network, or simply a public DNS name that resolves to the same
backend — bypasses every perimeter control. Network position is a mitigation, not
an authentication boundary; the owning service must enforce auth/authz itself.


### Verify & lock (triaging a finding)

A scanner/review hit is a *candidate*, not a confirmed bug. Confirm it, fix it,
then lock it so it can't come back.

1. **Confirm it's real (probe the suspect input).** Replay the endpoint as an
   attacker would. *BOLA/IDOR:* authenticate as user A, request user B's resource ID
   (`GET /orders/{B_id}`) — a real hit returns B's data or `200`; a false positive
   returns `403/404`. *Broken auth:* call the endpoint with no token, an expired
   token, and a `none`/wrong-alg JWT — acceptance is a real hit. *Mass assignment:*
   POST/PATCH with an extra privileged field (`{"role":"admin","is_verified":true}`)
   and re-read the object — if the field stuck, it's real. *Rate-limit:* fire N rapid
   auth/reset requests; absence of `429` after the threshold confirms it. *Perimeter
   trust:* hit the backend service directly (bypassing the gateway) — a `200` without
   auth confirms the control lives only at the proxy.
2. **Fix, then lock with a regression test** (unit *or* integration — dev's call):
   assert the attack input now yields the secure outcome (cross-tenant ID → `403/404`;
   forged/expired/`none`-alg token → `401`; unknown privileged field → ignored or
   rejected, never persisted; over-threshold burst → `429`; direct-to-service call →
   auth enforced), AND that a legitimate request (owner reading own resource, valid
   token, allowed fields) still succeeds. Commit it to CI so the guard can't be
   silently dropped in a later refactor.

## References

- `checklists/auth_patterns.yaml`
- `checklists/input_validation.yaml`
- [OWASP API Security Top 10 2023](https://owasp.org/API-Security/editions/2023/en/0x00-introduction/).
- [RFC 9700 — OAuth 2.0 Security BCP](https://datatracker.ietf.org/doc/html/rfc9700).
