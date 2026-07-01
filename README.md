# SecureVibe

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![Skills](https://img.shields.io/badge/skills-30-blue)](./skills)
[![Platforms](https://img.shields.io/badge/platforms-win%20%7C%20mac%20%7C%20linux-green)](#platform-support)

**Prevention-first security for AI-written code.** SecureVibe ships current
security knowledge *at the point of code generation* — signed `SKILL.md`
knowledge fed to your AI coding assistant, backed by deterministic scanners and
a CI gate. One static Go binary — `secure-vibe` — is **both** the CLI/gate **and**
the MCP server. Offline, keyless, no telemetry, Ed25519-signed.

Maintained by **[ShieldNet360](https://www.shieldnet360.com)** · MIT — free to fork, embed, and ship commercially.

## Install

npm bundles the library data (skills + vuln DB), so it works on macOS, Linux, and Windows out of the box:

```bash
npx -y @shieldnet360/secure-vibe <command>   # run on demand: status · gate · scan-secrets · init · mcp …
npm install -g @shieldnet360/secure-vibe      # …or install globally for a persistent `secure-vibe`
```

<details><summary>Build from source (Go)</summary>

`go install github.com/shieldnet-360/secure-vibe/cmd/secure-vibe@latest` builds only the
binary (no bundled data). Point it at a library checkout via `--path` / `$SECURE_VIBE_LIBRARY_PATH`.
</details>

## Quick start

**1 · Embed skills in your assistant** — writes the config your tool reads at generation time:

```bash
npx -y @shieldnet360/secure-vibe init --tool claude   # claude · cursor · copilot · codex · windsurf · cline · devin
```

**2 · Run the MCP server** (16 tools over stdio) — wire it into Claude Code:

```bash
claude mcp add SecureVibe -- npx -y @shieldnet360/secure-vibe mcp
```

**3 · Gate in CI / pre-commit** — non-zero exit on findings at or above the floor, with SARIF for Code Scanning:

```bash
secure-vibe gate . --severity-floor high --format sarif
```

## What you get

- **PREVENT** — 30 signed skills across 8 assistants, consulted as code is written.
- **DETECT** — 4 deterministic scanners: secrets, dependencies (curated malicious/typosquat DB across 10 ecosystems), Dockerfile, GitHub Actions.
- **ENFORCE** — `secure-vibe gate` blocks insecure diffs; `--format json|sarif`, `--report-dir` for HTML/PDF.
- **VERIFY** — dynamic `verify_finding` confirms a candidate against a *live* target (ssrf · sqli · xss · redirect · path-traversal · command-injection · ssti · xxe); gated, dry-run by default.
- **LEARN** — `secure-vibe contribute add -p <pkg> -e npm` writes a signed `.secure-vibe/overlay.json`; commit it (team) or point `$SECURE_VIBE_OVERLAY` at a shared file (org).

## Docs

- [ARCHITECTURE.md](./ARCHITECTURE.md) — design, compiler, update protocol, repo layout.
- [docs/](./docs/) — guides (developer · devops · security · evaluator), install, air-gapped, team rollout.
- [docs/reference/mcp-tools.md](./docs/reference/mcp-tools.md) — full MCP tool reference · [skills/](./skills) — the 30-skill catalogue.
- [SIGNING.md](./SIGNING.md) — Ed25519 release signing · [CONTRIBUTING.md](./CONTRIBUTING.md) · [SECURITY.md](./SECURITY.md).

## Platform support

| OS | Arch | Install | Auto-update |
|----|------|---------|-------------|
| macOS | amd64, arm64 | npm / npx (or `go install`) | launchd |
| Linux | amd64, arm64 | npm / npx (or `go install`) | systemd user timer |
| Windows | amd64 | npm / npx (or `go install`) | Task Scheduler |

## License

[MIT](./LICENSE) — Copyright (c) 2024-2026 **ShieldNet360**. Free to fork, embed, and ship commercially; please preserve the notice and attribution.
