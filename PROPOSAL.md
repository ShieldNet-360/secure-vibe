# SecureVibe — Design Document

This document describes the design and scope of **SecureVibe**, a security
knowledge framework for AI-assisted coding maintained by
[ShieldNet360](https://www.shieldnet360.com) and released under the
[MIT license](./LICENSE). The Go module path is `github.com/shieldnet-360/secure-vibe`
and the CLI binary is `secure-vibe`.

## Problem Statement

AI coding assistants (Claude Code, Cursor, GitHub Copilot, Codex, Windsurf, Cline, Devin,
Antigravity) are used by millions of developers daily. The dominant interaction pattern is
"vibe coding" — rapidly prototyping features by describing intent and accepting whatever the
AI produces. This pattern has two structural security weaknesses:

- **AI tools have no built-in security knowledge beyond their training data.** The training
  data is months or years stale by the time a model ships. A package that was compromised
  yesterday is happily imported by the model today, because the model's training corpus
  predates the compromise.
- **Security review is an afterthought.** AI-generated code routinely lands in production
  without anyone checking for hardcoded secrets, vulnerable dependencies, typosquat imports,
  injection patterns, or insecure infrastructure-as-code.

Meanwhile, supply chain attacks have increased dramatically since 2019 (Sonatype's annual
State of the Software Supply Chain reports document multi-hundred-percent year-over-year
growth in malicious package counts). Existing security tools (SAST, SCA, secret scanners)
run *after* code is written, when the developer has already moved on. By that point the
bad code is in the diff, the typosquat is in `package.json`, the API key is in `.env.example`.

There is no standardized, open-source mechanism for injecting **up-to-date security rules
into AI coding workflows themselves** — at the point of generation, before the code is
committed. CTOs and tech leads have no governance framework for AI-assisted development
security. They cannot answer the question: *"What security rules is the AI applying when
my team is vibe-coding?"*

Every existing answer to this question is one of three flavors:

1. **Proprietary** — closed-source enterprise products that lock customers into a vendor.
2. **Expensive** — per-developer SaaS pricing that prices out smaller teams.
3. **Infrastructure-heavy** — requires servers, agents, and IT involvement before any
   developer benefits.

SecureVibe exists to solve this gap with an MIT-licensed, file-based,
offline-capable library that any developer can drop into their IDE in under five
minutes.

## Solution

A structured, open-source library of security skills that:

1. **Embeds directly** into AI coding tools via their native configuration mechanisms
   (`CLAUDE.md`, `.cursorrules`, `.github/copilot-instructions.md`, `AGENTS.md`,
   `.windsurfrules`, `devin.md`, `.clinerules`).
2. **Ships offline-first** with bundled rules — no server dependency required. The library
   is useful from the first `git clone` with zero network calls.
3. **Updates incrementally** via signed manifests — new vulnerabilities, rules, and
   patterns are distributed without re-downloading the entire library.
4. **Minimizes token usage** — tiered compilation (`minimal` / `compact` / `full`) so
   skills don't waste the AI tool's context window.
5. **Covers the full security stack** — secrets, dependencies, code patterns,
   infrastructure, compliance, supply chain.
6. **Provides a CLI** for validation, update management, and IDE file generation.
7. **Supports scheduled background updates** on Windows, macOS, and Linux using each
   platform's native scheduling mechanism (Task Scheduler, `launchd`, `systemd` timers).

## `SKILL.md` Format Specification

Every skill in the library is a directory under `skills/` containing a `SKILL.md` manifest
and any number of associated rule, checklist, or test files. The `SKILL.md` is the
canonical entry point: it has YAML frontmatter describing the skill and a markdown body
containing the actual rules in three token-budget tiers.

```yaml
---
id: secret-detection
version: "1.2.0"
title: "Secret Detection"
description: "Detect and prevent hardcoded secrets, API keys, tokens, and credentials in code"
category: prevention               # prevention | detection | compliance | supply-chain | hardening
severity: critical                 # critical | high | medium | low
applies_to:                        # when this skill should activate
  - "before every commit"
  - "when reviewing code that handles credentials"
  - "when writing configuration files"
  - "when creating .env or config templates"
languages: ["*"]                   # or specific: ["python", "javascript", "go", "rust"]
token_budget:
  minimal: 180                     # tokens for minimal variant
  compact: 650                     # tokens for compact variant
  full: 1800                       # tokens for full variant
rules_path: "rules/"               # relative path to machine-readable rules
tests_path: "tests/"               # relative path to test corpus
related_skills: ["dependency-audit", "supply-chain-security"]
last_updated: "2026-05-12"
sources:
  - "OWASP Secrets Management Cheat Sheet"
  - "CWE-798: Use of Hard-coded Credentials"
---

# Secret Detection

## Rules (for AI agents)

### ALWAYS
- Check all string literals longer than 20 characters near keywords: `api_key`, `secret`,
  `token`, `password`, `credential`, `auth`, `bearer`, `private_key`.
- Flag any string matching known secret patterns: `AKIA[0-9A-Z]{16}`,
  `ghp_[A-Za-z0-9_]{36}`, `sk-[A-Za-z0-9]{48}`, `-----BEGIN.*PRIVATE KEY-----`.
- Verify `.gitignore` includes: `*.pem`, `*.key`, `.env`, `.env.*`, `*credentials*`,
  `*secret*`.
- Check for environment variable usage instead of hardcoded values.

### NEVER
- Commit files matching: `*.pem`, `*.key`, `*.p12`, `*.pfx`, `.env`, `.env.local`,
  `*credentials*`.
- Hardcode API keys, tokens, passwords, or connection strings in source code.
- Include real secrets in test fixtures (use `AKIAIOSFODNN7EXAMPLE`-style placeholders).
- Log or print secret values, even in debug mode.

### KNOWN FALSE POSITIVES
- AWS documentation example: `AKIAIOSFODNN7EXAMPLE`.
- Strings containing: "example", "test", "placeholder", "dummy", "sample", "changeme",
  "your-key-here".
- Hash literals in CSS/SCSS (e.g., `#ff0000`).
- Base64-encoded non-secret content in tests.

## References
- `checklists/secret_detection.yaml` — unified machine-readable patterns
  (Aho-Corasick prefixes, hotwords, entropy thresholds) and the
  `exclusions:` block for community-maintained false-positive suppressions.
```

The frontmatter schema is enforced by `secure-vibe dev validate` and by CI on every PR.

## Design Principles

1. **Skills-Centric.** Every capability is a self-contained skill with a human-readable
   `SKILL.md` and machine-readable rules. Skills compose; they do not couple.
2. **Offline-First.** The library works fully offline with bundled content. Remote
   updates are optional. (This mirrors the secure-edge philosophy: a security tool that
   requires a server is itself a supply-chain risk.)
3. **Token-Efficient.** Tiered compilation minimizes context window consumption. Skills
   are loaded on demand, not monolithically. Each `SKILL.md` declares pre-counted token
   budgets for `minimal`, `compact`, and `full` variants.
4. **Privacy-Preserving.** The CLI and SDK never phone home, never collect telemetry,
   never track usage. Following the "Process, Don't Persist" design from secure-edge:
   the tool stores configuration locally, but no event logs, no usage metrics, no
   identifiers.
5. **Signed and Verifiable.** All remote rule bundles are signed with Ed25519. Users
   can verify rules came from the official source, preventing supply-chain attacks on
   the security tooling itself. This signing model is borrowed directly from the TRDS
   (Tenant Rule Distribution Service) compilation worker in sn360-security-platform.
6. **Community-Updatable.** Vulnerability data, detection rules, and false-positive
   exclusions are all structured for PR-based contribution. The schema is JSON / YAML
   for human-friendliness and machine-validation.
7. **Cross-Platform.** The CLI is a single Go binary for Windows / macOS / Linux.
   Scheduled updates use native OS mechanisms (`launchd`, `systemd`, Task Scheduler) —
   no daemons, no helper processes.

## Target Audience

- **Tech Leads** — enforce security practices across AI-assisted dev teams by checking
  the relevant `SKILL.md` into the project root. The skill becomes the AI's contract.
- **CTOs / CISOs** — governance framework for AI coding tool adoption. Compliance
  evidence that security checks exist in the AI workflow, with timestamps proving when
  rules were last refreshed.
- **Individual Developers** — better security habits embedded into their AI assistant.
  One `cp` command and the assistant stops suggesting hardcoded API keys.
- **Security Engineers** — contribute detection rules, vulnerability data, and
  false-positive fixes that benefit the entire community. The Sigma rule extracted from
  internal incident response work becomes a shared asset.
- **Open Source Maintainers** — protect projects from supply-chain contributions by AI
  tools that introduce vulnerabilities. AI-generated PRs are flagged by the same
  patterns the maintainer's own AI assistant respects.

## IDE Integration Matrix

| Tool | Config file | Location | Mechanism | Token budget | Auto-reload |
|------|-------------|----------|-----------|--------------|-------------|
| Claude Code | `CLAUDE.md` | project root | read on session start | compact (2000) | on new session |
| Cursor | `.cursorrules` | project root | read on session start | compact (2000) | on new session |
| GitHub Copilot | `copilot-instructions.md` | `.github/` | read on session start | compact (2000) | on new session |
| Codex / OpenAI | `AGENTS.md` | project root | read on task start | compact (2000) | on new task |
| Windsurf | `.windsurfrules` | project root | read on session start | compact (2000) | on new session |
| Devin | `devin.md` | project root | read on session start | full (5000) | on new session |
| Cline / OpenCode | `.clinerules` | project root | read on session start | compact (2000) | on new session |
| MCP Server | n/a | any | on-demand tool calls | minimal per call | real-time |

The MCP integration serves skills on demand via Model Context Protocol tool calls,
which means the AI tool spends tokens *only* when it actively decides to consult a
skill. This is the most token-efficient delivery model.

## Incremental Update Architecture

The library is distributed as a Git repo (offline-first) and as signed release artifacts
(for incremental updates). The CLI walks the same protocol either way.

- A root `manifest.json` lists every distributable file with its SHA-256 checksum, a
  monotonically-increasing version, a `released_at` timestamp, and an Ed25519 signature
  over the entire manifest.
- `secure-vibe update` fetches the latest manifest, compares checksums against the
  local copy, and downloads **only the files that changed**. For large files
  (vulnerability databases, dictionaries), the CLI prefers delta patches when present.
- Update sources are configurable: GitHub Releases (default), self-hosted CDN, or an
  air-gapped tarball manually copied onto the device. The CLI does not care; the
  signature verification step is identical in all three modes.
- Signature verification: the Ed25519 public key is embedded in the CLI binary at build
  time. Manifests from untrusted sources are rejected before any rule file is written.
  This prevents a malicious mirror from injecting a backdoored skill.
- This format mirrors the secure-edge rule distribution mechanism (`manifest.json` +
  checksums + delta updates), with signing added.

## Vulnerability Database Scope

The vulnerability database is opinionated about what it covers and what it does not.

### In scope (curated, supply-chain-focused)

- **Known malicious packages** for npm, PyPI, crates.io, Go modules, RubyGems, Maven Central, NuGet, GitHub Actions, and Docker Hub.
  Curated from npm advisories, PyPI advisories, Snyk / Socket.dev / Phylum reports, and
  high-confidence public incident write-ups.
- **Typosquat database.** Levenshtein distance precomputed against the top-1000 packages
  per ecosystem, so the AI can flag `axios` vs `axois` instantly.
- **Dependency confusion patterns.** Internal namespace patterns to watch for
  (`@yourco/`, `com.yourco.`) so AI-generated code doesn't pull a public package that
  shadows an internal one.
- **CVE-to-code-pattern mappings.** CVEs that manifest as code patterns, not just
  version ranges (e.g. unsafe Log4j substitution syntax, Spring4Shell template
  injection). These are the CVEs that SCA tools miss because they only check versions.

### Out of scope (defer to existing databases)

- **Comprehensive CVE database** — defer to NVD, OSV, GitHub Advisory Database.
- **Comprehensive SCA version scanning** — defer to Snyk, Dependabot, Renovate.
- **Binary vulnerability scanning** — defer to Trivy / Grype.
- **Container image vulnerability scanning** — defer to Trivy / Grype.

SecureVibe is intentionally narrow: it covers the **supply-chain attack surface
that AI coding tools introduce** and nothing else. Trying to be a general CVE
database would be a strategic mistake.

## Token Budget Strategy

The three-tier system is the single most important design choice in the library. It is
the answer to "how do we make security rules useful inside a finite context window?"

- **Minimal (< 500 tokens)** — only ALWAYS / NEVER bullet rules. No examples, no
  rationale, no false-positive lists. Intended for expensive API-based tools (Claude
  Sonnet API, GPT-4-Turbo API) where every 1k tokens has measurable cost, and for small
  context windows where space is at a premium.
- **Compact (< 2000 tokens)** — full rules with known false positives and external
  references. Default for most IDE integrations. Best balance of guidance versus cost.
- **Full (< 5000 tokens)** — rules + examples + rationale + related CWEs. For tools
  running local models (which have effectively-free tokens), for tools like Devin that
  benefit from deeper context, and for security training scenarios where the rationale
  is the point.

Each skill's `SKILL.md` contains all three tiers, clearly delineated. The `dist/`
compiler extracts the appropriate tier when generating IDE-specific files. The compiler
verifies the resulting file is within budget and fails the build if it isn't.

## Scope Boundaries — What This Does NOT Deliver

- **Runtime application security** (WAF, RASP). SecureVibe is a *development-time*
  tool. Runtime defense is a different category entirely.
- **SAST / DAST scanning.** Complementary, not replacement. SecureVibe shifts
  guidance *into* the AI generation step; SAST runs *after*. Both should run.
- **Real-time CVE monitoring / alerting.** That is an ops tool. SecureVibe
  distributes structured knowledge; it does not page humans at 3am.
- **Proprietary rule content.** Everything is MIT-licensed. If a rule is too sensitive
  to publish, it does not belong here.
- **AI model fine-tuning or training data.** Skills are *prompts*, not training corpora.
  We do not modify the AI; we modify what the AI reads.
- **Code generation or auto-fix.** Detection + guidance only, never patches. The library
  tells the AI "this is wrong"; it does not attempt to write the fix on behalf of the
  AI. Auto-fix is a slippery slope into shipping AI-generated code that bypasses human
  review for security-critical changes.
