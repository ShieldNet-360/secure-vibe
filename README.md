# SecureVibe

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![npm](https://img.shields.io/npm/v/@shieldnet360/secure-vibe?color=cb3837&logo=npm)](https://www.npmjs.com/package/@shieldnet360/secure-vibe)
[![Skills](https://img.shields.io/badge/skills-30-blue)](./skills)
[![Platforms](https://img.shields.io/badge/platforms-win%20%7C%20mac%20%7C%20linux-green)](#platform-support)

**Prevention-first security for AI-written code.** SecureVibe feeds your AI coding
assistant signed `SKILL.md` security knowledge *at the point of code generation*,
then backs it with deterministic scanners and a CI gate. One static Go binary —
`secure-vibe` — is **both** the CLI/gate **and** the MCP server. Offline, keyless,
no telemetry, Ed25519-signed releases.

Maintained by **[ShieldNet360](https://www.shieldnet360.com)** · MIT — free to fork, embed, and ship commercially.

## Install

npm bundles the library data (skills + vuln DB), so it works on macOS, Linux, and Windows out of the box:

```bash
npx -y @shieldnet360/secure-vibe <command>   # run on demand: scan · gate · check · init · mcp · status
npm install -g @shieldnet360/secure-vibe      # …or install globally for a persistent `secure-vibe`
```

<details><summary>Build from source (Go)</summary>

`go install github.com/shieldnet-360/secure-vibe/cmd/secure-vibe@latest` builds only the
binary (no bundled data). Point it at a library checkout via `--path` / `$SECURE_VIBE_LIBRARY_PATH`.
</details>

## Quick start

```bash
# 1 · embed security skills into your assistant (writes CLAUDE.md / .cursorrules / …)
secure-vibe init --tool claude        # claude · cursor · copilot · codex · windsurf · cline · devin

# 2 · scan code — auto-detects secrets / bad deps / Dockerfile / GitHub Actions per file
secure-vibe scan .

# 3 · gate a build (CI / pre-commit) — non-zero exit on findings, SARIF for Code Scanning
secure-vibe gate . --severity-floor high --format sarif

# 4 · vet one package before adding it
secure-vibe check event-stream@3.3.6 -e npm

# 5 · the MCP server (17 tools over stdio) — this is the command clients spawn:
secure-vibe mcp                                    # or: npx -y @shieldnet360/secure-vibe mcp
#    register it with Claude Code in one line:
claude mcp add SecureVibe -- npx -y @shieldnet360/secure-vibe mcp
#    Cursor · Windsurf · VS Code · Cline · Zed → docs/reference/mcp-clients.md
```

## See it catch something

```console
$ secure-vibe check event-stream@3.3.6 -e npm
=== check event-stream@3.3.6 (npm) ===
Malicious entries:  1
  ! MALICIOUS  [critical]  event-stream — Maintainer account compromised; malicious
    flatmap-stream dependency added to steal cryptocurrency wallets

$ secure-vibe gate Dockerfile --severity-floor high   # FROM ubuntu:latest / USER root
Verdict:        FAIL
Findings: 3   (critical: 1, high: 2)
$ echo $?
1
```

## What you get

The lifecycle is **PREVENT → DETECT → ENFORCE → VERIFY → LEARN**:

- **PREVENT** — 30 signed skills across 8 assistants, consulted as code is written.
- **DETECT** — one auto-detecting `scan`: secrets, dependencies (curated malicious / typosquat DB + CVE / OSV across 10 ecosystems), Dockerfile, and GitHub Actions.
- **ENFORCE** — `gate` blocks insecure diffs; `--format json|sarif`, `--report-dir` for an HTML + PDF report.
- **VERIFY** — dynamic `verify_finding` confirms a candidate against a *live* target (ssrf · sqli · xss · redirect · path-traversal · command-injection · ssti · xxe); gated, dry-run by default.
- **LEARN** — `secure-vibe contribute add -p <pkg> -e npm` writes a signed `.secure-vibe/overlay.json`; commit it (team) or point `$SECURE_VIBE_OVERLAY` at a shared file (org).

> **Narrow by design.** Detection is four deterministic scanners, not a general SAST. It catches known patterns and known-bad packages with near-zero false positives; it does not claim to find every vulnerability.

## Commands

| Command | What it does |
|---|---|
| `init --tool <ide>` | Write the assistant config (`CLAUDE.md`, `.cursorrules`, …) that embeds the skills |
| `scan <path>` | Auto-detect + report findings (secrets / deps / Dockerfile / Actions) |
| `gate <path>` | Same detection, **non-zero exit** above a severity floor — the CI entry point |
| `check <pkg>[@ver] -e <eco>` | Look up one package: malicious / typosquat / CVE / OSV |
| `mcp` | Run the MCP server (17 tools); `mcp connect` registers it with Claude Code |
| `contribute` | The LEARN loop — block a bad package locally, share via git / overlay |
| `update` | Pull signed skills + vuln data (`--self` updates the binary) · `status` reports freshness |

Full reference: [docs/reference/cli.md](./docs/reference/cli.md) · `secure-vibe --help`.

## Docs

- [ARCHITECTURE.md](./ARCHITECTURE.md) — design, compiler, update protocol, repo layout.
- [docs/](./docs/) — guides (developer · devops · security · evaluator), install, air-gapped, team rollout.
- [docs/reference/mcp-clients.md](./docs/reference/mcp-clients.md) — connect the MCP server to any agent (Claude Code · Cursor · Windsurf · VS Code · Cline · Zed) · [docs/reference/mcp-tools.md](./docs/reference/mcp-tools.md) — the 17 MCP tools · [skills/](./skills) — the 30-skill catalogue.
- [SIGNING.md](./SIGNING.md) — Ed25519 release signing · [CONTRIBUTING.md](./CONTRIBUTING.md) · [SECURITY.md](./SECURITY.md).

## Platform support

| OS | Arch | Install | Auto-update |
|----|------|---------|-------------|
| macOS | amd64, arm64 | npm / npx (or `go install`) | launchd |
| Linux | amd64, arm64 | npm / npx (or `go install`) | systemd user timer |
| Windows | amd64 | npm / npx (or `go install`) | Task Scheduler |

## License

[MIT](./LICENSE) — Copyright (c) 2024-2026 **ShieldNet360**. Free to fork, embed, and ship commercially; please preserve the notice and attribution.
