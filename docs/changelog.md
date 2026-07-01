---
hide:
  - toc
---

# Changelog

Release history for SecureVibe. Every version is an Ed25519-signed release
(see [Signing](https://github.com/shieldnet-360/secure-vibe/blob/main/SIGNING.md)); full
notes on [GitHub Releases](https://github.com/shieldnet-360/secure-vibe/releases).

## v0.9.0 — 2026-06-21 · Initial public release (ShieldNet360)

First public, open-source release of SecureVibe under [ShieldNet360](https://www.shieldnet360.com).
A deliberate pre-1.0 cut: the product is feature-complete across the
**PREVENT → DETECT → ENFORCE → LEARN** lifecycle and ships with reproducible,
CI-gated benchmarks; the remaining supply-chain trust automation (CodeQL,
OpenSSF Scorecard, SLSA provenance, SBOM, reproducible-build verification) is
tracked on the [roadmap](concepts/roadmap.md) for v1.0.

**Capabilities at launch**

- **PREVENT** — 29 signed `SKILL.md` knowledge docs injected into AI coding
  assistants (Claude Code, Cursor, Copilot, Codex, Windsurf, Cline, Devin) via
  MCP, so secure code is written at generation time.
- **DETECT** — 4 deterministic scanners (secrets, dependencies, Dockerfile,
  GitHub Actions) over a 2,022-entry, web-cited malicious-package canon across
  10 ecosystems, plus OSV and 27 Sigma rules.
- **ENFORCE** — `gate` blocks insecure diffs in CI (severity floor, SARIF →
  GitHub Code Scanning); reusable GitHub Action and pre-commit hook.
- **LEARN** — `secure-vibe contribute`: a signed local overlay flywheel
  (you → team → org) with peer-to-peer submit / verify / import.
- **Trust** — Ed25519-signed releases and data manifests; manifest-checksum,
  dist-drift, and scanner-eval-drift CI gates; offline-first, keyless.
- **Docs** — Material site with an in-browser WebAssembly
  [Playground](playground.md), per-role guides, a Threat-Intelligence browser,
  compliance-coverage matrices, and reproducible benchmark methodology.
- **Eval** — a 110-fixture, judged prevention-lift harness; the first
  trustworthy measured prevention-lift (**+7.4 points** with the skill in
  context, **+10.0 points** with the scanner tool, false-positives flat — see
  [Benchmarks](concepts/benchmarks.md)).

Installs: `curl | sh`, Homebrew tap, `go install`, and npx.
