# Connect the MCP server to your agent

SecureVibe's MCP server exposes its scanners and skills to any
[Model Context Protocol](https://modelcontextprotocol.io) client — Claude Code,
Cursor, Windsurf, VS Code, Cline, Zed, and others. It always runs the same way:

```bash
npx -y @shieldnet360/secure-vibe mcp     # or, if installed globally: secure-vibe mcp
```

Every client just wraps that command in its own config. The **universal config**
(works for Claude Desktop, Cursor, Windsurf, Cline, and most others) is:

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

!!! tip "Restrict what the file tools can read"
    The file-reading tools (`scan_secrets`, `scan_dependencies`, `gate`, …) default
    to the current working directory. Widen the allow-list by appending
    `"--allowed-roots", "/path/to/project"` to `args`.

## Claude Code

One command — no JSON editing:

```bash
claude mcp add SecureVibe -- npx -y @shieldnet360/secure-vibe mcp
```

Or let SecureVibe wire itself in (uses the resolved library root):

```bash
secure-vibe mcp connect          # runs: claude mcp add -s local secure-vibe -- secure-vibe mcp --path <root>
secure-vibe mcp connect --print  # just print the command + an .mcp.json snippet, don't run
```

## Other agents

Drop the universal config into the client's MCP config file. Locations and the
JSON key differ slightly per client — verify against your client's current docs,
as these evolve:

| Client | Config file | Top-level key |
|---|---|---|
| **Claude Code** (project) | `.mcp.json` in the repo | `mcpServers` |
| **Claude Desktop** | `claude_desktop_config.json` | `mcpServers` |
| **Cursor** | `.cursor/mcp.json` (project) or `~/.cursor/mcp.json` (global) | `mcpServers` |
| **Windsurf** | `~/.codeium/windsurf/mcp_config.json` | `mcpServers` |
| **Cline** | *MCP Servers → Configure* (writes `cline_mcp_settings.json`) | `mcpServers` |
| **VS Code** (Copilot agent mode) | `.vscode/mcp.json` | `servers` |
| **Zed** | `settings.json` | `context_servers` |

**VS Code** uses `servers` instead of `mcpServers`:

```json
{ "servers": { "SecureVibe": { "command": "npx", "args": ["-y", "@shieldnet360/secure-vibe", "mcp"] } } }
```

After adding the server, restart (or reload) the client and ask it something like
*"scan this Dockerfile for hardening issues"* or *"is `event-stream@3.3.6` known
malicious?"* — the request routes through SecureVibe's tools.

## Verify it works — no AI client needed

The server speaks JSON-RPC 2.0 over stdio, so any script can drive it:

```bash
# list every tool
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | npx -y @shieldnet360/secure-vibe mcp

# call one tool
echo '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"lookup_vulnerability","arguments":{"package":"event-stream","ecosystem":"npm","version":"3.3.6"}}}' \
  | npx -y @shieldnet360/secure-vibe mcp
```

See the [MCP tool reference](mcp-tools.md) for all 17 tools and their arguments.
