# `evals/fixtures/auth-patterns`

Code samples that contain authentication / authorization anti-patterns.
The eval harness either:

1. Feeds the file to an agent under test and grades whether the
   agent's review identifies the same issues as the source skill, or
2. Runs the static rules from the relevant skill (`jwt-handling`,
   `oauth-flows`, `session-management`) over the file and compares the
   findings to `expected.json`.

Layout: one source file per anti-pattern + an `expected.json`. Each
fixture cites the source rule in `expected.json` so reviewers can
verify the anti-pattern is real.

Seed fixtures (linked to actual skill rules):

| File | Anti-pattern | Source skill |
| --- | --- | --- |
| `jwt-none-alg.py` | accepts JWT with `alg: none` | `skills/auth-security/rules/jwt_safe_config.json` |
| `oauth-implicit-flow.js` | uses removed Implicit Flow for SPAs | `skills/auth-security/rules/oauth_flows.json` |
| `weak-session-cookie.py` | session cookie without `HttpOnly` / `Secure` / `SameSite` | `skills/auth-security/SKILL.md` (session hardening section) |
