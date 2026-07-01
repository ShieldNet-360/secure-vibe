# @shieldnet360/secure-vibe

**SecureVibe** in one command — secret detection, dependency / CVE scanning (offline
OSV cache), Dockerfile & GitHub Actions hardening, a CI `gate`, 30 security skills,
and a [Model Context Protocol](https://modelcontextprotocol.io) server. It's a single
Go binary (`secure-vibe`); this package ships it plus the library data, with the
prebuilt binary delivered as a per-platform optional dependency.

## As an MCP server

Reference it with `npx` in your MCP client config — no global install:

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

On first run npm fetches this package plus the one prebuilt binary matching your
OS/CPU. The file-reading tools (`scan_secrets`, `scan_dependencies`,
`scan_github_actions`, `scan_dockerfile`, `gate`) default to the current working
directory; widen the allow-list by appending `--allowed-roots /path/to/project` to
the `args`.

## As a CLI gate

The same binary is a scanner/gate for scripts, pre-commit hooks, and CI — no
JSON-RPC, just an exit code:

```bash
# pick the right scanner for a file (or a whole directory) and fail (exit 1)
# on any finding at or above the severity floor
npx -y @shieldnet360/secure-vibe gate Dockerfile --severity-floor high
npx -y @shieldnet360/secure-vibe scan-dependencies .
```

`gate` dispatches to the dependency / Dockerfile / GitHub Actions scanners by file
shape and falls back to a secret scan for anything else. The bundled data tree is
located automatically (no `--path` needed). Add `--format json|sarif` for CI.

## How it's packaged

A thin Node launcher over the Go binary. This package declares one optional
dependency per platform (`-darwin-arm64`, `-linux-x64`, …) gated by `os`/`cpu`, so
npm installs **only** the binary for your machine — no postinstall download, works
offline and under `npm ci --ignore-scripts`. The library data (skills, the OSV
cache, checklists) ships once inside this package and is handed to the binary via
`$SECURE_VIBE_LIBRARY_PATH`.

## Also available

- **Go (from source):** `go install github.com/shieldnet-360/secure-vibe/cmd/secure-vibe@latest`
  — builds only the binary; point it at library data via `--path` / `$SECURE_VIBE_LIBRARY_PATH`.

## License

MIT. See the [repository](https://github.com/shieldnet-360/secure-vibe).
