#!/usr/bin/env node
'use strict';

// Single launcher for the SecureVibe CLI + MCP server, distributed over npm.
//
// SecureVibe is ONE Go binary (`secure-vibe`) exposing every subcommand:
//   secure-vibe scan-secrets / gate / contribute / init / connect-mcp / ...
//   secure-vibe mcp            # the MCP server (JSON-RPC 2.0 over stdio)
//   secure-vibe dev <...>      # maintainer commands
//
// The binary ships per-platform in an optional dependency gated by the
// package's os/cpu fields, so npm installs ONLY the binary matching the host
// — no postinstall download, installs work offline and under
// `npm ci --ignore-scripts`.
//
// The library data tree (skills/, vulnerabilities/, ...) ships ONCE in this
// platform-agnostic package and is handed to the binary via the
// SECURE_VIBE_LIBRARY_PATH environment variable (the binary resolves its data root
// from that env when no --path is given — used by both the CLI subcommands and
// `secure-vibe mcp`). All argv and stdio are forwarded verbatim, and the
// child's exit status is propagated so `secure-vibe gate ...` works as a CI /
// pre-commit gate and `secure-vibe mcp` speaks JSON-RPC over stdio.

const path = require('node:path');
const { spawnSync } = require('node:child_process');

const platformKey = `${process.platform}-${process.arch}`;
const pkgName = `@shieldnet360/secure-vibe-${platformKey}`;
const binName = process.platform === 'win32' ? 'secure-vibe.exe' : 'secure-vibe';

let binDir;
try {
  // Resolve via package.json (always resolvable regardless of any exports
  // map) and derive the binary path from its directory.
  binDir = path.dirname(require.resolve(`${pkgName}/package.json`));
} catch {
  process.stderr.write(
    `secure-vibe: no prebuilt binary for ${platformKey}.\n` +
      `Expected the optional dependency ${pkgName} to be installed.\n` +
      `Supported platforms: darwin-x64, darwin-arm64, linux-x64, linux-arm64, win32-x64.\n` +
      `If your platform is supported, reinstall without --no-optional / --omit=optional.\n`
  );
  process.exit(1);
}

const binPath = path.join(binDir, 'bin', binName);
const dataDir = path.join(__dirname, '..', 'data');

const res = spawnSync(binPath, process.argv.slice(2), {
  stdio: 'inherit',
  env: { ...process.env, SECURE_VIBE_LIBRARY_PATH: process.env.SECURE_VIBE_LIBRARY_PATH || dataDir },
});

if (res.error) {
  process.stderr.write(`secure-vibe: failed to launch ${binPath}: ${res.error.message}\n`);
  process.exit(1);
}
// Propagate the child's exit status; if it was killed by a signal, exit 1.
process.exit(res.status === null ? 1 : res.status);
