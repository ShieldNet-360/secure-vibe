---
id: graphql-security
version: "1.0.0"
title: "GraphQL Security"
description: "Defend GraphQL APIs: depth/complexity limits, introspection in production, batching/aliasing abuse, field-level authorization, persisted queries"
category: prevention
severity: high
applies_to:
  - "when generating GraphQL schemas, resolvers, or server config"
  - "when wiring authentication/authorization to a GraphQL endpoint"
  - "when adding a public GraphQL API gateway"
  - "when reviewing /graphql endpoint exposure"
languages: ["javascript", "typescript", "python", "go", "java", "kotlin", "csharp", "ruby"]
token_budget:
  minimal: 1200
  compact: 1500
  full: 2200
rules_path: "rules/"
related_skills: ["api-security", "auth-security", "logging-security"]
last_updated: "2026-06-20"
sources:
  - "OWASP GraphQL Cheat Sheet"
  - "CWE-400: Uncontrolled Resource Consumption"
  - "Apollo GraphQL Production Checklist"
  - "graphql-armor (Escape technologies)"
---

# GraphQL Security

## Rules (for AI agents)

### ALWAYS
- Enforce a maximum **query depth** (typical: 7–10) and **query
  complexity** (cost) at the server. A 5-level nested query against a
  many-to-many relationship can return billions of nodes; without a
  cost limit, one client crashes the database.
- Disable **introspection** in production. Introspection makes
  reconnaissance trivial; legitimate clients have the schema baked in
  via codegen or a `.graphql` artifact.
- Use **persisted queries** (allowlisted operation hashes) for any
  high-traffic / public API. Anonymous arbitrary GraphQL is the GraphQL
  equivalent of `eval(req.body)`.
- Apply **field-level authorization** in resolvers, not just at the
  endpoint. GraphQL aggregates many fields into one HTTP response — a
  single missing `@auth` on a sensitive field leaks data across the
  whole query.
- Limit the number of **aliases** per request (typical: 15) and the
  number of **operations per batch** (typical: 5). Apollo / Relay both
  allow batched queries — without limits this is an N-pages-of-the-API
  amplification primitive.
- Reject **circular fragment** definitions early (most servers do, but
  custom executors don't). A self-referencing fragment causes
  exponential parse-time cost.
- Return generic errors to clients (`INTERNAL_SERVER_ERROR`,
  `UNAUTHORIZED`) and route stack traces / SQL snippets to server logs
  only. Default Apollo errors leak schema and query internals.
- Set a request size limit (typical: 100 KiB) and a request timeout
  (typical: 10 s) on the HTTP layer in front of the GraphQL server.
  A 1 MiB GraphQL query has no legitimate use.

### NEVER
- Expose `/graphql` introspection on a production endpoint. The
  GraphQL playground (GraphiQL, Apollo Sandbox) must also be disabled
  in production builds.
- Trust the depth / complexity of a query because "our clients only
  send well-formed queries." Any attacker can hand-craft a request to
  `/graphql`.
- Allow `@skip(if: ...)` / `@include(if: ...)` directives to gate
  authorization checks. Directives run after authorization in most
  executors, but custom directive ordering has produced authz bypasses.
- Implement N+1 patterns in resolvers (one DB query per parent record).
  Use a DataLoader or join-based fetch. N+1 is both a performance bug
  and a DoS amplifier.
- Allow file uploads via GraphQL multipart (`apollo-upload-server`,
  `graphql-upload`) without size limits, MIME validation, and
  out-of-band virus scan. The 2020 CVE-2020-7754 (`graphql-upload`)
  showed how a malformed multipart can crash the server.
- Cache GraphQL responses by URL alone. POST `/graphql` always uses the
  same URL; cache must key on operation hash + variables + auth claims
  to avoid cross-tenant leaks.
- Expose mutations that take untrusted JSON `input:` objects without
  schema validation. GraphQL types are mandatory at the schema layer,
  but `JSON` / `Scalar` types bypass them entirely.

### KNOWN FALSE POSITIVES
- Internal admin GraphQL endpoints behind an authenticated VPN may
  legitimately leave introspection on for developer ergonomics.
- Static-allowlisted persisted queries make depth / complexity checks
  redundant on those operations — keep the checks for any operation
  that isn't in the allowlist (i.e. operations through a `disabled` flag).
- Public, read-only data APIs may use very high cost limits with
  caching aggressively configured at the CDN layer; the trade-off is
  documented per endpoint.

## Context (for humans)

GraphQL gives clients a query language. That language is Turing-complete
in practice — depth, aliasing, fragments, and unions combine to form
near-arbitrary computation against the resolver graph. Treating
`/graphql` as a single endpoint with simple WAF / rate-limit controls is
inadequate.

The 2022-2024 era of GraphQL incidents (Hyatt, Slack research from
Apollo, several account-takeover-via-batching cases) all hinged on
either missing field-level authorization or missing cost analysis.
graphql-armor (Escape) and Apollo's built-in validation rules now
provide off-the-shelf middleware for most of these — use them.


### Verify & lock (triaging a finding)

A scanner/review hit is a *candidate*, not a confirmed bug. Confirm it, fix it,
then lock it so it can't come back.

1. **Confirm it's real (probe the suspect input).** POST directly to `/graphql`
   (bypass your client — attackers do). For *introspection*: send `{ __schema {
   types { name } } }`; a real hit returns the full type list (and GraphiQL/Sandbox
   loads) — an FP returns a generic error or 400. For *DoS*: send a deeply-nested
   recursive query (e.g. `user { friends { friends { friends { … } } } }` past your
   depth limit) or one with 50+ aliases / a batch of many operations; real if it
   hangs, spikes DB load, or amplifies — FP if rejected with a depth/complexity/alias
   error. For *authz*: request a sensitive field as a low-priv user; real if it
   returns data instead of `UNAUTHORIZED`.
2. **Fix, then lock with a regression test** (unit *or* integration — dev's call):
   assert introspection is OFF in the prod config (`{ __schema }` → error, not schema);
   assert a query exceeding the depth/complexity/alias limit is *rejected* before
   execution; assert a sensitive field returns `UNAUTHORIZED` for an unauthorized
   caller. Include a benign case that must still pass — a normal shallow query under
   the limits returns data, and an authorized caller reads the field. Commit it to CI
   so the guard can't be silently dropped in a later refactor.

## References

- `rules/graphql_safe_config.json`
- [OWASP GraphQL Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html).
- [CWE-400](https://cwe.mitre.org/data/definitions/400.html).
- [Apollo Production Checklist](https://www.apollographql.com/docs/apollo-server/security/production-checklist/).
- [graphql-armor](https://escape.tech/graphql-armor/).
