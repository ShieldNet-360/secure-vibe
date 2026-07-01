# Security Policy

**SecureVibe** is itself a piece of security tooling. Its data and binary
distribution are signed, reproducibly built, and meant to be safe to embed in
commercial products under the [MIT license](./LICENSE).

This document describes how to report a security issue privately and what to
expect from the maintainers in response.

## Supported versions

| Component | Versions supported with security fixes |
|-----------|---------------------------------------|
| CLI (`secure-vibe`, `secure-vibe mcp`) | Latest tagged release on `main` |
| Skill manifests + rules | Latest tagged release on `main` |
| Manifest signing key (`secure-code-release-2026`) | Active; rotation policy described in [SIGNING.md](./SIGNING.md) |

We do not maintain security backports for older tags. Please upgrade to the
latest release.

## Reporting a vulnerability

Please **do not** open a public GitHub issue, PR, or discussion for a
security issue. Instead, report it privately by one of the following
channels:

- **GitHub private advisory:** https://github.com/shieldnet-360/secure-vibe/security/advisories/new
- **Email:** `security@shieldnet360.com` (PGP key on request)

Include, where possible:

- A short description of the issue.
- Reproduction steps or a proof-of-concept.
- Which component is affected (CLI, signing pipeline, a particular rule
  file, a vulnerability database entry, etc.).
- Any suggested mitigation or fix.

## What to expect

- **Acknowledgement** within 3 business days.
- **Triage and severity assessment** within 7 business days, using the
  [CVSS 3.1](https://www.first.org/cvss/) scoring system.
- **Coordinated disclosure timeline** agreed with the reporter (default:
  90 days from acknowledgement, shorter if the issue is being actively
  exploited).
- **Credit** in the release notes for the advisory, unless you prefer to
  remain anonymous.

## Scope

In scope:

- Code execution, signature bypass, or supply-chain risk in the CLI or
  MCP server (`cmd/secure-vibe/`, `cmd/secure-vibe/`).
- Tampering with the manifest verification or update protocol that lets a
  malicious update be applied.
- Vulnerabilities in our release pipeline that allow unauthorized
  publishing of a signed manifest.
- Stored false-positive or false-negative patterns whose impact is
  *increasing* exposure to a real-world attack (e.g. a regex that
  whitelists an actively exploited token).

Out of scope:

- Reporting that a vulnerability database entry is missing — please file
  a normal PR to add it (see [CONTRIBUTING.md](./CONTRIBUTING.md)).
- Issues only reproducible on an unsupported version, fork, or
  out-of-tree modification.
- Generic / informational findings without a credible attack path.

## Public advisories

Published security advisories are listed at:

- https://github.com/shieldnet-360/secure-vibe/security/advisories

## Hall of fame

Researchers and contributors who responsibly disclose security issues are
credited in the relevant release notes and advisory pages. Thank you in
advance for helping keep SecureVibe trustworthy.
