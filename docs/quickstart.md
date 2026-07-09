# Quick Start

Get SecureVibe into a project in minutes. **One npm package is everything** — the
CLI scanner (`audit`), the MCP server, and the skill installer, all in a single
`secure-vibe` binary. The easiest path is npm; building from source is for contributors.

!!! note "Prerequisites"
    - **Node.js 18+** for the npm path (recommended), or **Go 1.22+** to build from source
    - **An AI coding assistant** (for the skills / MCP lanes): Claude Code, Cursor, Copilot, Codex, Windsurf, Cline, or Devin
    - **No network needed at runtime.** The npm package bundles the rule data and runs fully offline. Updates are optional.

## 1. Install

```bash
npm i -g @shieldnet360/secure-vibe
```

That puts one command on your PATH — `secure-vibe` — which is the CLI scanner
(`secure-vibe audit`), the MCP server (`secure-vibe mcp`), and the skill installer
(`secure-vibe init`). It bundles the rule data, so everything runs fully offline.

!!! tip "Sanity check"
    `secure-vibe check event-stream@3.3.6 -e npm` flags the famous 2018 npm supply-chain attack.

!!! note "Other channels"
    Run without installing: `npx -y @shieldnet360/secure-vibe <command>`. From source / contributors: `go install github.com/shieldnet-360/secure-vibe/cmd/secure-vibe@latest` (bare binary — point it at a data tree via `$SECURE_VIBE_LIBRARY_PATH`).

There are three ways to use it, and they compose: scan from the **CLI**, embed
**skills** so your assistant writes secure code, and expose the scanners to your
assistant over **MCP**.

## 2. Scan from the CLI

The everyday command. `audit` auto-detects the right scanner per file — secrets,
dependencies (lockfiles), Dockerfile, GitHub Actions — and reports findings.
Add `--fail-on` to make it **exit non-zero** for CI, and `check` vets a
single package.

```bash
secure-vibe audit .                                  # walk the repo, report everything
secure-vibe audit . --fail-on high --format sarif > results.sarif   # CI: fail on high+, emit SARIF
secure-vibe check left-pad@1.3.0 -e npm              # vet one package before adding it
```

`audit --fail-on` is the canonical "fail the build" entry point — wire it into a pre-commit
hook or a CI step. Add `--report-dir ./reports` for a self-contained HTML + PDF report.

## 3. Embed the skills into a project (prevention)

This is the **left-of-cursor** lane: install signed security skills so your AI
assistant writes secure code *at generation time*, before a scanner ever runs.

```bash
# in any project you want to make security-aware:
secure-vibe init --tool claude
```

That writes the assistant config (e.g. `.claude/skills/`, `CLAUDE.md`) — context-scoped, so
only the rule relevant to the files in play loads. The next time you open the
project, the assistant consults those rules. Other targets:
`--tool cursor | copilot | codex | windsurf | cline | devin | universal`.

!!! example "What prevention looks like"
    Ask the assistant to *"add a route that pings a host from a query parameter."*
    Without the skills it may shell out loosely; **with** them it cites the rule
    ("never pass user input to `exec` / `child_process`") and writes `execFile`
    with array args plus strict hostname validation. The skill shapes the diff.

## 4. Wire the MCP server

This gives the assistant on-demand access to the JSON-RPC tools — vulnerability
lookups, dependency scans, Dockerfile hardening, GitHub Actions audits, and the
`gate` — without spending tokens until a tool is actually called.

```bash
# For Claude Code — or run it yourself: `secure-vibe mcp connect`
claude mcp add SecureVibe -- npx -y @shieldnet360/secure-vibe mcp
```

Or hand-edit your client's MCP config:

```json
{
  "mcpServers": {
    "SecureVibe": {
      "command": "npx",
      "args": ["-y", "@shieldnet360/secure-vibe", "mcp"]
    }
  }
}
```

After restarting your client, ask *"scan this Dockerfile for hardening issues"* or
*"is `event-stream@3.3.6` known malicious?"* — it routes through the SecureVibe tools.

!!! tip "Other agents"
    Using **Cursor, Windsurf, VS Code, Cline, or Zed**? The server command is the
    same — only the config file and JSON key differ. See
    [Connect the MCP server to your agent](reference/mcp-clients.md).

!!! note "Drive a tool directly (no AI client)"
    The server speaks JSON-RPC 2.0 over stdio, so any script can call it:
    ```bash
    echo '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"lookup_vulnerability","arguments":{"package":"event-stream","ecosystem":"npm","version":"3.3.6"}}}' \
      | npx -y @shieldnet360/secure-vibe mcp
    # list every tool: {"jsonrpc":"2.0","id":1,"method":"tools/list"}
    ```

## 5. Keep it current

Vulnerability data and detection patterns change weekly. Two refresh paths, decoupled:

```bash
secure-vibe update                          # pull signed skill + vuln data (--self updates the binary)
secure-vibe dev fetch-vulns --from-release  # populate the user-local OSV cache (no repo write)
```

Check freshness at any time — an assistant is only as current as the data it's fed:

```bash
secure-vibe status                 # version, advisory count, data age, verdict
secure-vibe status --fail-if-stale # exit non-zero in CI when data is >30 days old
secure-vibe dev scheduler install --interval 6h   # unattended refresh (launchd / systemd / Task Scheduler)
```

## 5b. Block a bad package you discovered (LEARN loop)

Found a malicious or typosquatting package the curated database doesn't know yet?
Block it immediately — locally, no central round trip:

```bash
secure-vibe contribute add -p evil-pkg -e npm --reason "exfiltrates env in postinstall"
secure-vibe audit package.json --fail-on high   # now fails on evil-pkg
```

The rule is written to `.secure-vibe/overlay.json` and never leaves your machine.
Commit it to protect your team; run `contribute submit` (optionally `--key` to
sign) to share upstream. See [Contribute a Finding](contribute.md).

## 6. Generate a compliance coverage report

```bash
secure-vibe dev evidence --framework SOC2    --format markdown --out evidence-soc2.md
secure-vibe dev evidence --framework HIPAA   --format json
secure-vibe dev evidence --framework PCI-DSS --format markdown
```

Each report maps installed skills to framework controls with timestamps and source
citations — a developer-facing coverage map, not a substitute for a real audit.

## Next steps

- **Rolling out to a team** — see [admin-team-rollout](admin-team-rollout.md).
- **Air-gapped / regulated environments** — see [air-gapped-install](air-gapped-install.md).
- **Every command** — the [CLI reference](reference/cli.md); the [MCP tools](reference/mcp-tools.md).
- **Architecture** — read [ARCHITECTURE.md](https://github.com/shieldnet-360/secure-vibe/blob/main/ARCHITECTURE.md) for the full system design.
- **Signing model** — read [SIGNING.md](https://github.com/shieldnet-360/secure-vibe/blob/main/SIGNING.md) for key custody and rotation.
