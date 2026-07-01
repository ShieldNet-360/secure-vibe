---
id: cicd-security
version: "1.1.0"
title: "CI/CD Pipeline Security"
description: "Harden GitHub Actions, GitLab CI, and similar pipelines against supply-chain attacks, secret exfiltration, and pwn-request style abuses"
category: prevention
severity: critical
applies_to:
  - "when authoring or reviewing CI/CD workflow files"
  - "when adding a third-party action / image / script to a pipeline"
  - "when wiring cloud or registry credentials into CI"
  - "when triaging a suspected pipeline compromise"
languages: ["yaml", "shell", "*"]
token_budget:
  minimal: 1200
  compact: 1500
  full: 2200
rules_path: "checklists/"
related_skills: ["supply-chain-security", "secret-detection", "container-security"]
last_updated: "2026-06-21"
sources:
  - "OpenSSF Scorecard — Pinned-Dependencies / Token-Permissions"
  - "SLSA v1.0 Build Track"
  - "GitHub Security Lab — Preventing pwn requests"
  - "StepSecurity — tj-actions/changed-files attack analysis"
  - "CWE-1395: Dependency on Vulnerable Third-Party Component"
external_tools:
  - name: actionlint
    purpose: "GitHub Actions workflow lint (syntax, expressions, shellcheck on run: steps)"
    command: "actionlint"
---

# CI/CD Pipeline Security

## Rules (for AI agents)

### ALWAYS
- Pin every third-party GitHub Action by **commit SHA** (full 40-char),
  not by tag — tags can be re-pushed. Same applies to GitLab CI `include:`
  references and reusable workflows. Renovate / Dependabot can keep the
  SHA pins fresh.
  <!-- pattern: { id: gha-pin-actions-by-sha, severity: high, check: deterministic } -->
- Declare `permissions:` at the workflow or job level and default to
  `contents: read` only. Grant additional scopes (`id-token: write`,
  `packages: write`, etc.) job-by-job, never workflow-wide.
  <!-- pattern: { id: gha-default-permissions-read, severity: high, check: deterministic } -->
- Use **OIDC** (`id-token: write` + cloud provider trust policy) for
  short-lived cloud credentials. Never store long-lived AWS / GCP / Azure
  keys as GitHub Secrets.
  <!-- pattern: { id: gha-oidc-cloud-credentials, severity: high, check: deterministic } -->
- Treat `pull_request_target`, `workflow_run`, and any `pull_request` job
  that uses `actions/checkout` with `ref: ${{ github.event.pull_request.head.ref }}`
  as **trusted-context-on-untrusted-code**. Either don't run them, or run
  with no secrets and no write tokens.
  <!-- pattern: { id: gha-pr-target-no-untrusted-checkout, severity: critical, check: deterministic } -->
- Echo every untrusted expression (`${{ github.event.* }}`) through an
  environment variable first; never interpolate it directly into `run:`
  body — that's the canonical GitHub Actions script-injection sink.
  <!-- pattern: { id: gha-no-untrusted-script-injection, severity: critical, check: deterministic } -->
- Sign release artifacts (Sigstore / cosign) and publish SLSA provenance
  attestations. Verify provenance in any consumer pipeline that pulls the
  artifact.
- Set `runs-on` to a hardened runner image and pin the runner version.
  Audit-mode StepSecurity Harden-Runner (or equivalent egress firewall)
  for any workflow handling secrets is recommended.
  <!-- pattern: { id: gha-harden-runner, severity: medium, check: llm } -->
- Treat `npm install`, `pip install`, `go install`, `cargo install`, and
  `docker pull` invoked in CI as untrusted code execution. Run with
  `--ignore-scripts` (npm/yarn), pinned lockfiles, registry allowlists,
  and per-job least-privilege tokens.

### NEVER
- Pin a third-party action by floating tag (`@v1`, `@main`, `@latest`).
  The tj-actions/changed-files March 2025 incident exfiltrated secrets
  from 23,000+ repositories specifically because consumers used floating
  tags.
- `curl | bash` (or `wget -O- | sh`) any installer script in CI.
  The 2021 Codecov bash-uploader compromise exfiltrated env vars to an
  attacker for ~10 weeks because thousands of pipelines ran
  `bash <(curl https://codecov.io/bash)`. Always download, checksum,
  then execute.
  <!-- pattern: { id: gha-no-curl-pipe-bash, severity: critical, check: deterministic } -->
- Echo secrets to logs, even on failure. Use `::add-mask::` for any
  computed-at-runtime secret, and double-check with the GitHub
  workflow-log search.
- Allow workflows to run on forked PRs with `pull_request_target` if any
  job touches a write-scoped token or secret. The combination is the
  canonical "pwn request" pattern documented by GitHub Security Lab.
- Cache mutable state (e.g. `~/.npm`, `~/.cargo`, `~/.gradle`) keyed only
  on `os`. A cache hit cross-job is a cross-tenant attack surface — key
  on a lockfile hash and scope to the workflow ref.
  <!-- pattern: { id: gha-cache-key-scope, severity: medium, check: deterministic } -->
- Trust artifact downloads from arbitrary workflow runs without verifying
  the source workflow + commit SHA. Build-cache poisoning works through
  unscoped artifact reuse.
  <!-- pattern: { id: gha-artifact-verify-source, severity: medium, check: deterministic } -->
- Store secrets in repository variables (`vars.*`) — they are plaintext
  to anyone with read access. Only `secrets.*` are gated by the secret
  scanning + scope rules.

### KNOWN FALSE POSITIVES
- First-party actions in the same organization that you mirror or fork
  in-house may legitimately be pinned by tag if the org enforces signed
  tags + branch-protection on the action repo.
- Public-data pipelines that handle no secrets and produce no signed
  artifact (e.g. nightly link-checkers) don't need OIDC or SLSA
  provenance, and may use floating tags without practical impact.
- `pull_request_target` is legitimate for label / triage bots that only
  call the GitHub API with the minimal scopes needed, do not check out
  PR code, and don't expose secrets in env.

## Context (for humans)

CI/CD is now the most lucrative single supply-chain target. A pipeline
runs trusted code against trusted credentials and trusted registries —
compromising it once gives access to every downstream consumer of every
artifact it produces. The 2021 Codecov compromise, 2021 SolarWinds
incident, 2024 Ultralytics PyPI release-pipeline poisoning, and the
2025 tj-actions/changed-files mass exfiltration all hinged on
unauthenticated changes to CI-consumed scripts or actions.

Most of the defenses are mechanical: pin by SHA, minimize permissions,
use OIDC, sign artifacts, verify provenance. The hard part is enforcing
them across an organization. OpenSSF Scorecard automates checks for the
mechanical defenses and integrates with branch protection.

This skill emphasizes the design-pattern weaknesses (pwn requests,
script injection, curl-pipe-bash, floating tags, untrusted artifact
download) because they are the patterns AI-generated workflow YAML
reinvents most often.


### Verify & lock (triaging a finding)

A scanner/review hit is a *candidate*, not a confirmed bug. Confirm it, fix it,
then lock it so it can't come back.

1. **Confirm it's real (inspect config + reproduce behavior).** This is config-
   and run-level, not a browser. For an *unpinned action*, `git ls-remote` the
   referenced repo and confirm `@v1`/`@main` resolves to a mutable, re-pushable
   tag (a 40-char SHA is already locked → FP). For a *pwn-request*
   (`pull_request_target`/`workflow_run` + checkout of PR head with a write token
   or secret), open a test PR from a throwaway fork and confirm attacker code
   actually runs in the trusted context. For *script injection*, trace whether a
   `${{ github.event.* }}` value reaches a `run:` body unquoted and echo a marker
   to prove it executes. For *default-write perms*, inspect the run's
   `GITHUB_TOKEN` permissions (no top-level `permissions:` → `write-all`). For
   *curl|bash* / *OIDC*, confirm the installer is piped unverified, or that a
   long-lived cloud key sits in Secrets where OIDC should be. Real if
   reproducible; FP if already SHA-pinned, read-scoped, or no-secrets context.
2. **Fix, then lock with a regression test** (CI policy gate, dev's call): add an
   actionlint + SecureVibe step (or OpenSSF Scorecard / Renovate SHA-pin) to the
   pipeline that fails on a floating tag, a missing top-level `permissions: read`,
   a `curl | bash`, or a pwn-request checkout — plus one benign workflow that
   passes the gate. Commit it so the guard can't be silently dropped.

## References

- `checklists/gitlab_ci_hardening.yaml`
- [OpenSSF Scorecard](https://github.com/ossf/scorecard).
- [SLSA v1.0 Build Track](https://slsa.dev/spec/v1.0/levels).
- [GitHub Security Lab — Preventing pwn requests](https://securitylab.github.com/research/github-actions-preventing-pwn-requests/).
- [StepSecurity — tj-actions/changed-files attack analysis](https://www.stepsecurity.io/blog/tj-actions-changed-files-attack-analysis).
- [CWE-1395](https://cwe.mitre.org/data/definitions/1395.html).
