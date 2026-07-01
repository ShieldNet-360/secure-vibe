---
id: secret-detection
version: "1.8.1"
title: "Secret Detection"
description: "Detect and prevent hardcoded secrets, API keys, tokens, and credentials in code"
category: prevention
severity: critical
applies_to:
  - "before every commit"
  - "when reviewing code that handles credentials"
  - "when writing configuration files"
  - "when creating .env or config templates"
languages: ["*"]
token_budget:
  minimal: 800
  compact: 1300
  full: 2600
rules_path: "checklists/"
tests_path: "tests/"
related_skills: ["dependency-audit", "supply-chain-security"]
last_updated: "2026-06-21"
sources:
  - "OWASP Secrets Management Cheat Sheet"
  - "CWE-798: Use of Hard-coded Credentials"
  - "CWE-259: Use of Hard-coded Password"
  - "NIST SP 800-57 Part 1 Rev. 5: Key Management"
external_tools:
  - name: gitleaks
    purpose: "secrets, whole-repo + git history"
    command: "gitleaks dir | gitleaks git"
---

# Secret Detection

## Rules (for AI agents)

### ALWAYS
- Check all string literals longer than 20 characters near keywords: `api_key`, `secret`,
  `token`, `password`, `credential`, `auth`, `bearer`, `private_key`, `access_key`,
  `client_secret`, `refresh_token`.
- Flag any string matching known secret patterns. The bundled pattern set covers AWS
  (`AKIA...`), GitHub classic (`ghp_`, `gho_`) **and fine-grained** (`github_pat_`)
  PATs, OpenAI (`sk-`), **Anthropic (`sk-ant-api03-`)**, Slack (`xox[baprs]-`),
  Stripe (`sk_live_`), Google (`AIza...`), **Azure AD client secrets**, **Databricks
  (`dapi`)**, **Datadog 32-hex with hotword**, **Twilio (`SK`)**, **SendGrid
  (`SG.`)**, **npm (`npm_`)**, **PyPI upload (`pypi-AgEI`)**, **Heroku UUID with
  hotword**, **DigitalOcean (`dop_v1_`)**, **HashiCorp Vault (`hvs.`)**, **Supabase
  (`sbp_`)**, **Linear (`lin_api_`)**, JWT, and PEM private keys.
- Verify `.gitignore` includes: `*.pem`, `*.key`, `.env`, `.env.*`, `*credentials*`,
  `*secret*`, `id_rsa*`, `*.ppk`.
- Prefer environment variable usage (`os.environ`, `process.env`, `os.Getenv`) over
  hardcoded values for any credential, connection string, or API endpoint that has an
  attached secret.
- Suggest a secret manager (1Password, AWS Secrets Manager, HashiCorp Vault, Doppler)
  when credentials must be shared across machines or services.

### NEVER
- Commit files matching: `*.pem`, `*.key`, `*.p12`, `*.pfx`, `.env`, `.env.local`,
  `*credentials*`, `id_rsa`, `id_dsa`, `id_ecdsa`, `id_ed25519`.
- Hardcode API keys, tokens, passwords, or connection strings in source code.
- Include real secrets in test fixtures — use documented placeholders such as
  `AKIAIOSFODNN7EXAMPLE`, `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`, or
  `xoxb-EXAMPLE-EXAMPLE`.
- Log or print secret values, even in debug mode.
- Echo secrets to terminals in CI logs (mask via `::add-mask::` in GitHub Actions).
- Embed signing keys in container images, even base images.

### KNOWN FALSE POSITIVES
- AWS documentation example: `AKIAIOSFODNN7EXAMPLE` and the matching secret access key
  `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`.
- Strings containing: "example", "test", "placeholder", "dummy", "sample", "changeme",
  "your-key-here", "REPLACE_ME", "TODO", "FIXME", "XXX".
- Hash literals in CSS/SCSS (e.g., `#ff0000`, `#deadbeef`).
- Base64-encoded non-secret content in tests (lorem ipsum encoded, image fixtures).
- Git commit SHAs in changelogs and release notes.
- JWT tokens in the OAuth RFC documentation examples (`eyJ...` strings appearing in
  comments).

## Context (for humans)

Hardcoded secrets remain one of the most common causes of breaches. GitHub's annual
"State of the Octoverse" reports consistently rank secret leakage in the top three
disclosed vulnerability categories, and the average cost of a leaked credential
(remediation + rotation + impact) is measured in tens of thousands of dollars per
incident even before customer data is involved.

AI coding assistants accelerate this risk because the path of least resistance is to
inline a working credential and "fix it later." This skill is the counterweight: it
trains the AI to refuse the path of least resistance.

The detection strategy in `checklists/secret_detection.yaml` mirrors the layered
pipeline, now with **83 distinct patterns** grouped as: developer platforms (28
— GitHub, Anthropic, OpenAI, Supabase, Vercel), collaboration & comms (13 —
Slack, Discord, Dropbox, Twilio, Teams), cloud platforms (12 — AWS, Azure AD,
GCP, DigitalOcean, Heroku), enterprise SaaS (11 — Salesforce, Atlassian,
Shopify, Workday, NetSuite), data platforms (9 — Databricks, Datadog, Vault,
MongoDB Atlas, Grafana), generic & cryptographic (4 — JWT, PEM keys), payments
(3 — Stripe), and email (3 — SendGrid, Mailgun, Mailchimp). Each pattern carries
severity, hotwords, a proximity window, and an entropy floor, documented in
[secure-edge ARCHITECTURE.md](https://github.com/shieldnet-360/secure-edge/blob/main/ARCHITECTURE.md)
— Aho-Corasick prefix scan, regex validation, hotword proximity, entropy
thresholds, and exclusion rules. Counts are derived from the
`type: secret_pattern` entries; keep them in sync when adding patterns.

PR-B1 unified the three legacy JSON sidecars
(`rules/dlp_patterns.json`, `rules/dlp_exclusions.json`,
`rules/dlp_patterns.locales.json`) into a single
`checklists/secret_detection.yaml` matching the convention used by every other
skill. The AI-drafted locale hotword sidecar was dropped in the same PR.

Lane 1 (this PR) imported 9 high-confidence patterns from
[mazen160/secrets-patterns-db](https://github.com/mazen160/secrets-patterns-db) —
AWS AppSync (`da2-`), AWS MWS (`amzn.mws.`), GitHub App Installation (`ghs_`),
GitHub Refresh (`ghr_`), Stripe Public Live (`pk_live_`), Mailgun (`key-`),
Mailchimp (32-hex + `-usN`), Dropbox short-lived (`sl.`), and Discord bot.
Each carries its upstream URL in the `references:` field as evidence.


### Verify & lock (triaging a finding)

A scanner/review hit is a *candidate*, not a confirmed bug. Confirm it, fix it,
then lock it so it can't come back.

1. **Confirm it's real (live secret vs. placeholder).** Most hits are dummies:
   documented examples (`AKIAIOSFODNN7EXAMPLE`), strings with `example`/`test`/
   `placeholder`/`changeme`/`XXX`, CSS hex (`#deadbeef`), commit SHAs, or RFC JWT
   samples. A real secret matches the provider's prefix/format AND clears the entropy
   floor. To confirm it's *live* (not already rotated), do a READ-ONLY check where the
   provider offers one — token-introspection or a whoami/`GET /user`-style call (e.g.
   GitHub `GET /user`, AWS `sts get-caller-identity`). NEVER make a write/destructive
   call. Real if the provider says the credential is valid; FP if it's a fixture or
   the provider rejects it. Genuine FPs go in the `exclusions:` block of
   `secret_detection.yaml` so the pattern stops re-flagging them.
2. **Fix (ROTATE first — git history retains it), then lock.** Removing the line or
   `git rm` does NOT remediate: the secret lives in history and is already compromised.
   Rotate/revoke the credential at the provider first, move the new value to an env var
   or secret manager, then purge history if warranted. Lock it: add a pre-commit hook
   plus a CI secret-scan gate (`SecureVibe gate` / gitleaks over dir + git history)
   that fails the build on that pattern, and mask values in CI logs
   (`::add-mask::`). Assert a clean file passes and a planted fake secret is caught,
   then commit the gate so it can't be reintroduced.

## References

- `checklists/secret_detection.yaml` — unified secret-detection rules: regex patterns
  (Aho-Corasick prefixes, hotwords, entropy thresholds) plus the
  `exclusions:` block for false-positive suppressions.
- `tests/corpus.json` — test fixtures for validation.
- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [CWE-798](https://cwe.mitre.org/data/definitions/798.html) — Use of Hard-coded
  Credentials.
- [CWE-259](https://cwe.mitre.org/data/definitions/259.html) — Use of Hard-coded
  Password.
