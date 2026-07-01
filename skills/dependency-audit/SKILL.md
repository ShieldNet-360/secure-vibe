---
id: dependency-audit
version: "1.0.0"
title: "Dependency Audit"
description: "Audit project dependencies for known vulnerabilities, malicious packages, and supply chain risks"
category: supply-chain
severity: high
applies_to:
  - "when adding a new dependency"
  - "when upgrading dependencies"
  - "when reviewing package manifests (package.json, requirements.txt, go.mod, Cargo.toml)"
  - "before merging a PR that modifies dependency files"
languages: ["*"]
token_budget:
  minimal: 400
  compact: 750
  full: 1900
rules_path: "rules/"
related_skills: ["secret-detection", "supply-chain-security"]
last_updated: "2026-06-20"
sources:
  - "OWASP Top 10 2021 — A06: Vulnerable and Outdated Components"
  - "CWE-1104: Use of Unmaintained Third Party Components"
  - "CISA Software Bill of Materials guidance"
---

# Dependency Audit

## Rules (for AI agents)

### ALWAYS
- Pin dependencies to exact versions in lockfiles (`package-lock.json`, `yarn.lock`,
  `Pipfile.lock`, `poetry.lock`, `go.sum`, `Cargo.lock`).
- Cross-check every new dependency name against the bundled malicious-package list in
  `vulnerabilities/supply-chain/malicious-packages/`.
- Prefer well-established packages with high download counts, multiple maintainers, and
  recent activity over newer alternatives that solve the same problem.
- Run the package manager's audit command (`npm audit`, `pip-audit`, `cargo audit`,
  `govulncheck`) and review reported issues before merging.
- Verify the package's repository URL on the package page actually exists and matches
  the linked GitHub / GitLab / Codeberg project.

### NEVER
- Add a dependency without pinning its version.
- Install packages with `--unsafe-perm` or equivalent flags that bypass install
  sandboxing.
- Add a dependency whose name appears in the bundled malicious-package list.
- Add a brand-new package (published within the last 30 days) without a clear,
  documented reason — typosquats are usually freshly published.
- Use the `latest` tag in a production lockfile or container image FROM line.
- Commit unused dependencies — they expand the attack surface for free.

### KNOWN FALSE POSITIVES
- Internal monorepo packages (`@yourco/*`) flagged as "unknown" — these are valid when
  the namespace is owned by your organization.
- New patch versions of stable packages (e.g. `react@18.2.5` after `18.2.4`) flagged as
  "recently published" — patch updates are usually fine.
- Package names that legitimately overlap with malicious entries from years ago that
  have been re-registered by the original maintainer.

## Context (for humans)

Supply chain attacks have grown faster than any other attack category since 2019.
Compromise of a popular package (event-stream, ua-parser-js, colors, faker, xz-utils)
or publication of a typosquat (axois vs axios, urllib3 vs urlib3) reliably nets the
attacker thousands of downstream victims within hours.

AI coding tools are particularly vulnerable because the model has no visibility into
when a package was last compromised. The model recommends what it learned during
training; if a maintainer was compromised after the training cutoff, the AI happily
recommends a backdoored version.

This skill compensates by injecting the live malicious-package database into the AI's
working context and requiring the AI to consult it before adding any dependency.


### Verify & lock (triaging a finding)

A scanner/review hit is a *candidate*, not a confirmed bug. Confirm it, fix it,
then lock it so it can't come back.

1. **Confirm it's real (inspect).** Resolve the *installed* version from the lockfile
   (`package-lock.json`, `poetry.lock`, `go.sum`, `Cargo.lock`) — not the manifest range —
   and check it actually falls inside the advisory's vulnerable range; an SCA hit is a false
   positive if the resolved version is already patched. Then check reachability: is the
   vulnerable package/function on a runtime path, or is it a transitive *dev-only* dep
   (test/build tooling) that never ships? For a malicious-package/typosquat hit, confirm the
   name, registry, and repo URL against the bundled malicious-package list and the real
   project — re-registered legacy names and owned `@yourco/*` namespaces are known FPs.
   Real if a runtime (or shipped) path resolves to a version in the vulnerable range, or the
   name matches a live malicious entry.
2. **Fix, then lock with a regression test** (unit *or* integration — dev's call): upgrade to
   the patched version and pin it exactly in the lockfile; then add a CI `audit`/gate step
   (`npm audit`, `pip-audit`, `govulncheck`, `cargo audit`) that fails on that advisory id at
   the chosen severity floor, or a lockfile assertion that the resolved version is `>=` the
   patched one. Keep a clean baseline that passes so a future downgrade or transitive pull-in
   re-trips it. Commit it so the guard can't be silently dropped.

## References

- `rules/known_malicious.json` — symlink or copy of the relevant
  `vulnerabilities/supply-chain/malicious-packages/*.json` files.
- [OWASP Top 10 A06](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/).
- [npm Advisories](https://github.com/advisories?query=type%3Aunreviewed+ecosystem%3Anpm).
- [PyPI Advisory Database](https://github.com/pypa/advisory-database).
