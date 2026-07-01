# Quick Start

Get SecureVibe into a project in minutes. The easiest path is npm; building from source is for contributors.

!!! note "Prerequisites"
    - **Node.js 18+** for the npm path (recommended), or **Go 1.22+** to build from source
    - **An AI coding assistant**: Claude Code, Cursor, Copilot, Codex, Windsurf, Cline, or Devin
    - **No network needed at runtime.** The npm package bundles the rule data and runs fully offline. Updates are optional.

## 1. Install

Everything ships on npm — the package bundles the platform binary and the rule data, so there's no checkout and no Go toolchain.

```bash
npm i -g @shieldnet360/secure-code-mcp
```

That puts two commands on your PATH: `secure-code-mcp` (the MCP server) and `secure-code-check` (the CLI — the scanners plus the `gate`). Both read the bundled data, so they run fully offline.

!!! tip "Sanity check"
    `secure-code-check check-dependency --package event-stream --version 3.3.6 --ecosystem npm` flags the famous 2018 npm supply-chain attack.

!!! note "Other channels"
    Run without installing: `npx -p @shieldnet360/secure-code-mcp secure-code-check <cmd>`. From source / contributors: `go install github.com/shieldnet-360/secure-vibe/cmd/secure-vibe@latest` (bare binary — point it at a data tree via `$SECURE_VIBE_LIBRARY_PATH`).

## 2. Drop the skills into a project (fastest path)

```bash
# in any project you want to make security-aware:
npx @shieldnet360/secure-code-skill init --tool claude
```

That installs the native security skills (e.g. `.claude/skills/`) — context-scoped, so only the rule relevant to the files in play loads. The next time you open the project in Claude Code, those rules are available to the assistant.

Other targets: `--tool cursor | copilot | codex | windsurf | cline | universal`.

## 3. Wire the MCP server (most powerful path)

This gives the assistant on-demand access to the JSON-RPC tools — vulnerability lookups, dependency scans, Dockerfile hardening, GitHub Actions audits, and the `gate` — without spending tokens until the tools are actually called.

```bash
# For Claude Code (no install — npx fetches the package on first run):
claude mcp add secure-code -- npx -y @shieldnet360/secure-code-mcp
```

Or hand-edit your client's MCP config:

```json
{
  "mcpServers": {
    "secure-code": {
      "command": "npx",
      "args": ["-y", "@shieldnet360/secure-code-mcp"]
    }
  }
}
```

After restarting your client, ask the assistant something like *"scan this Dockerfile for hardening issues"* or *"is `event-stream@3.3.6` known malicious?"* — it'll route through the SecureVibe tools.

## 4. Try a single tool call directly

You don't need an AI client to use the MCP server. It speaks JSON-RPC 2.0 over stdio, so any script can drive it.

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"tools/call",
  "params":{"name":"lookup_vulnerability",
    "arguments":{"package":"event-stream","ecosystem":"npm","version":"3.3.6"}}}' \
  | npx -y @shieldnet360/secure-code-mcp
```

That returns the known compromise entry for the infamous 2018 supply-chain attack. Substitute any of the server's tools.

!!! note "List all available tools"
    ```bash
    echo '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | npx -y @shieldnet360/secure-code-mcp
    ```

## 5. Keep it current

Vulnerability data and detection patterns change weekly. Two refresh paths, decoupled:

```bash
# Refresh the committed library via signed manifest deltas (touches files in repo):
./secure-vibe update

# Populate the user-local OSV cache (~250 MB, ~80k npm advisories — no repo write):
./secure-vibe dev fetch-vulns --from-release
```

Check how stale the local data is at any time — an AI assistant is only as
current as the knowledge it is fed:

```bash
./secure-vibe status                 # version, advisory count, data age, verdict
./secure-vibe status --fail-if-stale # exit non-zero in CI when data is >30 days old
```

For unattended refresh, install the scheduler:

```bash
./secure-vibe dev scheduler install --interval 6h
```

That registers a `launchd` LaunchAgent (macOS), a `systemd` user timer (Linux), or a Task Scheduler task (Windows). No daemons, no privileged helpers.

## 5b. Block a bad package you discovered (LEARN loop)

Found a malicious or typosquatting package the curated database doesn't know
yet? Block it immediately — locally, no central round trip:

```bash
./secure-vibe contribute add -p evil-pkg -e npm --reason "exfiltrates env in postinstall"
./secure-vibe gate package.json --severity-floor high   # now fails on evil-pkg
```

The rule is written to `.secure-vibe/overlay.json` and never leaves your
machine. Commit that file to protect your whole team; run `contribute submit`
(optionally `--key` to sign) to share a candidate upstream. See
[Contribute a Finding](contribute.md).

## 6. Generate a compliance coverage report

```bash
./secure-vibe dev evidence --framework SOC2    --format markdown --out evidence-soc2.md
./secure-vibe dev evidence --framework HIPAA   --format json
./secure-vibe dev evidence --framework PCI-DSS --format markdown
```

Each report maps installed skills to framework controls with timestamps and source citations. The output is a developer-facing coverage map, not a substitute for a real audit.

## Next steps

- **Install on macOS / Linux / Windows** — see [install-macos](install-macos.md), [install-linux](install-linux.md), [install-windows](install-windows.md).
- **Rolling out to a team** — see [admin-team-rollout](admin-team-rollout.md).
- **Air-gapped / regulated environments** — see [air-gapped-install](air-gapped-install.md).
- **Architecture** — read [ARCHITECTURE.md](https://github.com/shieldnet-360/secure-vibe/blob/main/ARCHITECTURE.md) for the full system design.
- **Signing model** — read [SIGNING.md](https://github.com/shieldnet-360/secure-vibe/blob/main/SIGNING.md) for key custody and rotation.
