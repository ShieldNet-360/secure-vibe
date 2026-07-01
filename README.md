# SecureVibe

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![Skills](https://img.shields.io/badge/skills-30-blue)](#skill-catalogue)
[![CVE patterns](https://img.shields.io/badge/CVE%20patterns-58-orange)](./vulnerabilities/cve/code-relevant/cve_patterns.json)
[![Secret patterns](https://img.shields.io/badge/Secret%20patterns-74-red)](./skills/secret-detection/checklists/secret_detection.yaml)
[![Platforms](https://img.shields.io/badge/platforms-win%20%7C%20mac%20%7C%20linux-green)](#platform-support)

**SecureVibe** ships current security knowledge *at the point of code generation* —
a machine-readable library of security skills plus supply-chain vulnerability
intelligence that embeds directly into AI coding assistants (Claude Code, Cursor,
GitHub Copilot, Codex, Windsurf, Cline / OpenCode, Antigravity, Devin). It runs
fully offline, ships bundled rules, and supports incremental **Ed25519-signed**
updates. Everything is one static Go binary — `secure-vibe` — that is **both** the
CLI scanners/gate **and** the MCP server.

Maintained by **[ShieldNet360](https://www.shieldnet360.com)** · [MIT](./LICENSE) —
free to fork, embed, and ship commercially.

---

## Contents

- [Why](#why) · [What's inside](#whats-inside)
- [Install](#install) · [Embed in your IDE](#embed-skills-in-your-ide) · [Keep data current](#keep-data-current)
- [Token tiers](#token-tiers) · [CLI & MCP tools](#cli--mcp-tools) · [Skill catalogue](#skill-catalogue)
- [Profiles](#enterprise-profiles) · [Compliance](#compliance-evidence) · [Private repos](#private-repositories) · [SDKs](#sdks)
- [Build & test](#build--test) · [Signing](#signing) · [Platform support](#platform-support) · [Docs](#documentation) · [Contributing](#contributing)

---

## Why

- **AI assistants don't ship with current security knowledge.** Training data is
  stale — a package compromised yesterday is happily imported today.
- **Security review is an afterthought** in "vibe coding": hardcoded secrets,
  vulnerable dependencies, typosquats, and unsafe deserialization land in prod.
- **No standard way to inject security context** — every team hand-writes a
  `CLAUDE.md` / `.cursorrules` that holds only style rules.

SecureVibe closes the loop before the diff ever touches your repo, and is
MIT-licensed, offline, and keyless.

## What's inside

| Area | Path | Description |
|------|------|-------------|
| **Skills** | [`skills/`](./skills) | 30 self-contained `SKILL.md` manifests — rules, patterns, and checklists the AI consults at generation time. |
| **Vulnerability database** | [`vulnerabilities/`](./vulnerabilities) | Curated supply-chain corpus (malicious packages, typosquats, CVE patterns, dependency-confusion) plus an offline, delta-updatable OSV cache. |
| **Detection rules** | [`rules/`](./rules) | Sigma rules for AWS/GCP/Azure, K8s, Linux/macOS/Windows, and SaaS — complementing the prevention-time skills. |
| **Compliance maps** | [`compliance/`](./compliance) | OWASP / CWE / SANS mappings + SOC 2 / HIPAA / PCI-DSS / FedRAMP coverage maps. |
| **Pre-compiled IDE files** | [`dist/`](./dist) | Ready-to-drop-in `CLAUDE.md`, `.cursorrules`, `copilot-instructions.md`, `AGENTS.md`, and more. |
| **CLI + MCP binary** | [`cmd/secure-vibe/`](./cmd/secure-vibe) | One static Go binary: scanners, CI gate, IDE config, maintainer (`dev`) commands, and the `secure-vibe mcp` server. |

## Install

**npm — one command, all platforms (macOS · Linux · Windows).** The package bundles
the library data (skills + vuln DB), so it works out of the box.

```bash
# run on demand — nothing installed
npx -y @shieldnet360/secure-vibe <command>     # status · gate · scan-secrets · init · mcp · …

# …or install globally for a persistent `secure-vibe`
npm install -g @shieldnet360/secure-vibe
```

<details>
<summary>Build from source (Go)</summary>

`go install github.com/shieldnet-360/secure-vibe/cmd/secure-vibe@latest` builds only the
binary — it does **not** bundle the data. Point it at a library checkout via `--path` /
`$SECURE_VIBE_LIBRARY_PATH`, or clone the repo and `secure-vibe update --path ./lib`.
</details>

### Run the MCP server

Any MCP client speaks to `secure-vibe mcp` over stdio. Register it in Claude Code with one command:

```bash
# npm — no install, no JSON editing (recommended)
claude mcp add SecureVibe -- npx -y @shieldnet360/secure-vibe mcp

# or, if you built the binary from source (go install), let it wire itself in:
secure-vibe connect-mcp        # runs: claude mcp add -s local secure-vibe -- secure-vibe mcp --path <root>
```

Or configure any MCP client by hand:

```jsonc
{
  "mcpServers": {
    "SecureVibe": { "command": "npx", "args": ["-y", "@shieldnet360/secure-vibe", "mcp"] }
  }
}
```

## Embed skills in your IDE

Drop the pre-compiled file for your tool from [`dist/`](./dist) into your project
root, or generate a project-specific one with `secure-vibe init`:

| Tool | File | Source in `dist/` |
|------|------|-------------------|
| Claude Code | `CLAUDE.md` | `dist/CLAUDE.md` |
| Cursor | `.cursorrules` | `dist/.cursorrules` |
| GitHub Copilot | `.github/copilot-instructions.md` | `dist/copilot-instructions.md` |
| Codex / OpenAI | `AGENTS.md` | `dist/AGENTS.md` |
| Windsurf | `.windsurfrules` | `dist/.windsurfrules` |
| Devin | `devin.md` | `dist/devin.md` |
| Cline / OpenCode | `.clinerules` | `dist/.clinerules` |
| Any markdown-aware tool | `SECURITY-SKILLS.md` | `dist/SECURITY-SKILLS.md` |

```bash
# Copy once:
cp secure-vibe/dist/CLAUDE.md /your-project/CLAUDE.md
# …or symlink for auto-updates, or generate the file with `init` (all 30 skills by default):
npx -y @shieldnet360/secure-vibe init --tool claude   # no clone needed — npm bundles the skills
#   add --skills a,b,c to narrow · --budget <tier> for depth
#   installed the binary instead? run `secure-vibe init …` from a checkout, or set
#   $SECURE_VIBE_LIBRARY_PATH (or --library <checkout>) so it can find the skills data.
```

For Claude Code's native skill bundles, copy `dist/claude-skills/.claude/skills/`
into your project's `.claude/skills/`.

## Keep data current

Vulnerability data changes weekly; the CLI pulls incremental, signature-verified
updates.

```bash
secure-vibe update                       # pull latest signed skills + vuln data
secure-vibe update --regenerate          # …and rebuild the dist/ IDE files
secure-vibe status --fail-if-stale       # CI gate: exit 1 when data is >30 days old
secure-vibe dev scheduler install --interval 6h   # background auto-update (launchd / systemd / Task Scheduler)
```

The repo ships a *small* offline OSV sample. For full coverage, populate the
user cache once (then weekly): `secure-vibe dev fetch-vulns --from-release`
(single signed download) or `secure-vibe dev fetch-vulns` (direct from osv.dev).
Scheduled updates send anonymous `GET`s only — no device, host, IP, or user data.

## Token tiers

Skills load on demand, and every `SKILL.md` declares a pre-counted `token_budget`;
`dist/` files are compiled to a tier and the build fails if a variant exceeds it.

| Tier | Tokens | Contents | For |
|------|--------|----------|-----|
| `minimal` | < 500 | ALWAYS / NEVER rules only | Expensive API tools, tiny budgets |
| `compact` | < 2000 | Full rules + false positives + refs (default) | Most IDE integrations |
| `full` | < 5000 | Rules + examples + rationale + CWEs | Local large-context models, Devin |

Pick with `secure-vibe init --budget <tier>` (default `compact`).

## CLI & MCP tools

One binary, two surfaces: **16 MCP tools** (`tools/list`) and the same scanners as
top-level subcommands, sharing one Go library so a CLI finding is byte-identical to
the MCP response. Full reference: [docs/reference/mcp-tools.md](./docs/reference/mcp-tools.md).

- **Supply chain** — `check_dependency`, `check_typosquat`, `lookup_vulnerability`, `scan_dependencies`
- **Secrets** — `scan_secrets`, `check_secret_pattern`
- **Config files** — `scan_dockerfile`, `scan_github_actions`
- **Gate** — `gate` (CI-friendly pass/fail with `exit_code`)
- **Knowledge** — `get_skill`, `search_skills`, `explain_finding`, `map_compliance_control`, `get_sigma_rule`, `version_status`
- **Verify (dynamic)** — `verify_finding`: confirm a candidate against a *live* target (ssrf · sqli · xss · redirect · path-traversal · command-injection · ssti · xxe). Gated — dry-run unless an operator scope is configured.

```bash
secure-vibe scan-dependencies .             # walk the repo, audit every lockfile
secure-vibe scan-secrets ./src              # recursive secret scan
secure-vibe gate . --severity-floor high    # CI gate — non-zero exit on high+ findings
```

Add `--format json` / `--format sarif` for CI ingestion, or `--report-dir ./reports`
for a styled HTML + PDF report. The gate is also packaged as a
[pre-commit](https://pre-commit.com) hook and a GitHub Action — see
[CONTRIBUTING.md](./CONTRIBUTING.md).

### LEARN loop

Block a bad package the curated DB doesn't know yet — locally, no round trip:

```bash
secure-vibe contribute add -p evil-pkg -e npm --reason "exfiltrates AWS creds in a postinstall script"
secure-vibe gate package.json --severity-floor high   # now fails on evil-pkg
```

`contribute add` writes `.secure-vibe/overlay.json` in your project (the rule
never leaves your machine). Commit it to share with your team; point
`SECURE_VIBE_OVERLAY` at a shared file for org-wide enforcement. Upstream a
signed candidate via `contribute keygen` / `submit` / `verify` —
see [docs/contribute.md](./docs/contribute.md).

## Skill catalogue

All 30 skills are language-agnostic unless otherwise noted.

| Skill | Category | Severity | Languages |
|-------|----------|----------|-----------|
| `secret-detection` | prevention | critical | * |
| `dependency-audit` | supply-chain | high | * |
| `secure-code-review` | prevention | high | * |
| `supply-chain-security` | supply-chain | critical | * |
| `api-security` | prevention | high | * |
| `compliance-awareness` | compliance | medium | * |
| `iac-security` | hardening | high | hcl, yaml, json |
| `container-security` | hardening | high | dockerfile, yaml |
| `electron-security` | hardening | critical | javascript, typescript |
| `frontend-security` | prevention | high | javascript, typescript, html |
| `database-security` | prevention | high | sql, javascript, typescript, python, java, go |
| `crypto-misuse` | prevention | high | * |
| `auth-security` | prevention | critical | * |
| `iam-best-practices` | hardening | high | * |
| `serverless-security` | hardening | high | python, javascript, typescript, java, yaml |
| `mobile-security` | hardening | high | java, kotlin, swift, objective-c |
| `ml-security` | prevention | high | python, jupyter |
| `llm-app-security` | prevention | critical | python, javascript, typescript, go, * |
| `protocol-security` | hardening | high | * |
| `error-handling-security` | prevention | medium | * |
| `logging-security` | prevention | high | * |
| `cors-security` | hardening | medium | javascript, typescript, python, go, java |
| `cicd-security` | prevention | critical | yaml, shell, * |
| `ssrf-prevention` | prevention | critical | * |
| `deserialization-security` | prevention | critical | java, python, csharp, php, ruby, javascript, typescript |
| `graphql-security` | prevention | high | javascript, typescript, python, go, java, kotlin, csharp, ruby |
| `file-upload-security` | prevention | high | * |
| `websocket-security` | prevention | high | javascript, typescript, python, go, java, csharp, ruby, elixir |
| `saas-security` | prevention | critical | * |
| `dynamic-verification` | detection | high | * |

## Enterprise profiles

`secure-vibe init --profile <name>` selects a curated, compliance-aligned subset:

| Profile | Frameworks | Use case |
|---------|-----------|----------|
| `financial-services` | PCI-DSS v4.0, SOC 2 | Banks, fintech, payments |
| `healthcare` | HIPAA Security Rule | Hospitals, telehealth, claims |
| `government` | FedRAMP, NIST SP 800-53 Rev. 5 | Public-sector workloads |

Definitions live under [`profiles/`](./profiles).

## Compliance evidence

```bash
secure-vibe evidence --framework SOC2 --format markdown --out evidence.md
```

Maps installed skills to SOC 2 / HIPAA / PCI-DSS controls (YAML under
[`compliance/`](./compliance)) into a timestamped coverage report — a
developer-facing map, not a substitute for a real audit.

## Private repositories

For air-gapped / internal deployments, point the CLI at your own signed bundle:

```bash
secure-vibe configure \
  --source https://skills.internal.example.com \
  --bearer-token-env SECURE_VIBE_TOKEN \
  --trusted-key /etc/skills/orgkey.pem \
  --profile financial-services
```

This writes `.secure-vibe.yaml` next to the repo. The updater accepts multiple
trusted Ed25519 keys (`VerifyAny`) and authenticated HTTPS pulls. See
[docs/air-gapped-install.md](./docs/air-gapped-install.md).

## SDKs

Minimal Go, Python, and TypeScript SDKs live under [`sdk/`](./sdk):

```go
import skillslib "github.com/shieldnet-360/secure-vibe/sdk/go"
s, _ := skillslib.LoadSkill("skills/secret-detection/SKILL.md")
fmt.Println(skillslib.Extract(s, skillslib.TierCompact))
```

## Build & test

```bash
go build -o secure-vibe ./cmd/secure-vibe
go test ./...                          # CLI + MCP server + verify lane
secure-vibe dev validate                # SKILL.md frontmatter + token budgets
secure-vibe dev regenerate              # rebuild dist/ (CI fails if it drifts)
```

## Signing

Release manifests are signed with **Ed25519**; the public key is embedded in the
binary at build time. See [SIGNING.md](./SIGNING.md) for the YubiKey-backed
procedure and key policy.

## Platform support

| OS | Architectures | Install | Scheduled updates |
|----|---------------|---------|-------------------|
| macOS | `amd64`, `arm64` | `npm` / `npx` (or `go install` from source) | `launchd` |
| Linux | `amd64`, `arm64` | `npm` / `npx` (or `go install` from source) | `systemd` user timer |
| Windows | `amd64` | `npm` / `npx` (or `go install` from source) | Task Scheduler |

## Documentation

- [ARCHITECTURE.md](./ARCHITECTURE.md) — system design, compiler, update protocol, repo layout, scheduler.
- [PROPOSAL.md](./PROPOSAL.md) — problem statement, design principles, and the `SKILL.md` format spec.
- [SIGNING.md](./SIGNING.md) · [docs/](./docs/) (install, air-gapped, team rollout) · [docs/reference/mcp-tools.md](./docs/reference/mcp-tools.md) (full MCP tool reference).

## Contributing

PRs welcome — see [CONTRIBUTING.md](./CONTRIBUTING.md) and the AI-assisted-contribution
policy in [AGENTS.md](./AGENTS.md) (AI may assist, but predominantly AI-generated PRs
are not accepted). Add skills under `skills/` (use
[`skills/secret-detection/`](./skills/secret-detection) as the reference), vulnerability
entries with an external reference, or Sigma rules under `rules/`. Run
`secure-vibe dev validate` and `go test ./...` before submitting. Report security
issues privately via [SECURITY.md](./SECURITY.md).

## License and attribution

Released under the [MIT License](./LICENSE).

> Copyright (c) 2024-2026 **ShieldNet360** — https://www.shieldnet360.com

Free to fork, embed, and ship commercially; please preserve the MIT notice and
attribution in derivative works.
