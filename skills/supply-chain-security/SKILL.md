---
id: supply-chain-security
version: "1.1.0"
title: "Supply Chain Security"
description: "Defend against typosquats, dependency confusion, and malicious package contributions"
category: supply-chain
severity: critical
applies_to:
  - "when AI is asked to add a dependency"
  - "when reviewing PRs that modify package manifests"
  - "when setting up a new project that uses internal namespaces"
  - "before publishing a package to a public registry"
languages: ["*"]
token_budget:
  minimal: 750
  compact: 1100
  full: 2500
rules_path: "rules/"
tests_path: "tests/"
related_skills: ["dependency-audit", "secret-detection", "container-security"]
last_updated: "2026-06-21"
sources:
  - "Alex Birsan, Dependency Confusion (2021)"
  - "OpenSSF Best Practices for OSS Developers"
  - "SLSA Supply-chain Levels for Software Artifacts v1.0"
---

# Supply Chain Security

## Rules (for AI agents)

### ALWAYS
- Compute Levenshtein distance against the top-1000 list for the relevant ecosystem
  whenever proposing a new dependency. Flag any candidate with distance ≤ 2 from a
  popular package (`axois` vs `axios`, `urlib3` vs `urllib3`, `colours` vs `colors`,
  `python-dateutil` vs `dateutil` vs `dateutils`).
- Verify that internal-namespace packages (`@yourco/*`, `com.yourco.*`) are pulled from
  the internal registry, not the public one. Configure `.npmrc` /
  `pip.conf` / `settings.gradle` with the internal scope explicitly.
- Pin the registry URL in lockfiles to prevent registry redirection attacks.
- Check that any newly added package has a verified maintainer (`npm` provenance,
  `sigstore` signature, or GPG-signed git tag) when published in the last 90 days.
- Treat install scripts (`postinstall`, `preinstall`, `setup.py` arbitrary code,
  `build.rs`) as high-risk surface and flag them in the PR description for human
  review.
- Secure your application's **own update / release channel**, not just
  third-party deps. Require authentication **and** a release-manager role on the
  endpoint that publishes a release, and have the client **verify a signature
  (or pinned checksum) over the downloaded artifact before executing it**. The
  publish-then-clients-auto-download path is a supply chain too: poison one
  release and every client runs it.

### NEVER
- Add a public package whose name matches an internal namespace pattern.
- Trust a package whose repository URL on the registry page does not match its actual
  source repo.
- Recommend a freshly-published package with low download counts for a security-critical
  use case (auth, crypto, HTTP, DB drivers).
- Disable the package manager's integrity check (`--no-package-lock`, `--ignore-scripts
  = false` when defending against it, `npm config set audit false` in production).
- Auto-merge dependency-bump PRs without a reviewer when the bump crosses a major
  version.
- Suggest installing tools via `curl | sh` patterns from untrusted sources.
- Let any authenticated user — or, worse, an unauthenticated request — publish
  or overwrite a release artifact that other users' clients auto-download, or
  have the client execute an update without verifying a signature / pinned
  checksum. Either one is a one-poison-many-RCE supply-chain break.

### KNOWN FALSE POSITIVES
- Legitimate orgs forking and republishing maintained packages with a `-fork` or
  `-community` suffix; verify the fork's repo URL before flagging.
- Beta / alpha releases of well-known packages (e.g. `next@canary`) appear "newly
  published" but are part of a known release cadence.
- Internal namespace packages (`@yourco/internal-tools`) intentionally not on the
  public registry — these are fine when the `.npmrc` is configured correctly.
- Auto-update frameworks that verify a signature by default (Sparkle,
  electron-updater with a pinned public key, Omaha) are the *correct* pattern —
  flagging "the app auto-updates" is an FP; the control is signature / checksum
  verification, not the absence of auto-update.
- A staging / dev update feed without signing is acceptable when it's gated
  behind an env flag or internal network and never serves production clients.

## Context (for humans)

The dependency-confusion attack class works because most package managers default to
preferring the highest-version package across all configured registries. If an
attacker publishes `@yourco/internal-tool@99.9.9` to npmjs.com, every `npm install` in
your team's project pulls the attacker's code instead of the legitimate internal one.

Typosquats are equally devastating but exploit human attention instead of registry
defaults. AI tools are especially prone because they generate plausible-looking
package names without checking which ones actually exist.

The same trust model applies to the software you ship: an app's auto-update
channel is a supply chain in miniature. If the publish endpoint lacks auth/role
gating, or the client runs the downloaded artifact without verifying a signature
or checksum, an attacker who can write one release achieves code execution on
every client at once — the desktop-app equivalent of dependency confusion.


### Verify & lock (triaging a finding)

A scanner/review hit is a *candidate*, not a confirmed bug. Confirm it, fix it,
then lock it so it can't come back.

1. **Confirm it's real (inspect).** Resolve, don't guess. For a **known-CVE dep**,
   read the *resolved lockfile* (not the manifest range) and confirm the installed
   version falls in the vulnerable range — patched-in-lockfile is an FP. For a
   **typosquat**, diff the name against the intended package (Levenshtein ≤ 2:
   `axois`/`axios`) and inspect its install scripts (`postinstall`, `setup.py`,
   `build.rs`) in a sandbox before running anything. For **dependency confusion**,
   confirm the internal-namespace package (`@yourco/*`) actually resolved from the
   public registry, not your internal one. Check the registry's repo URL matches the
   real source. FP if it's a legit `-fork`, a known canary/beta, or a correctly
   scoped internal package.
2. **Fix, then lock with a regression test** (unit *or* integration — dev's call):
   pin the exact version *and* registry URL in the lockfile, then add a CI gate that
   fails the build if the bad package/version reappears — a deny-list/allow-list, a
   scoped `.npmrc`/`pip.conf` install check, or a `SecureVibe gate` step — and assert
   a clean lockfile still passes. For your own release channel, gate publish on auth +
   release-manager role and verify a signature/pinned checksum before clients execute.
   Commit it so the guard can't be silently dropped.

## References

- `rules/typosquat_patterns.json`
- `rules/dependency_confusion.json`
- [Alex Birsan's original dependency confusion writeup](https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610).
- [SLSA](https://slsa.dev/).
