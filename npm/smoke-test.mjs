#!/usr/bin/env node
// End-to-end smoke test for the npm packaging, host-platform only.
//
//   1. cross-build `secure-vibe` for the host
//   2. run build.mjs to assemble the main + host platform package
//   3. wire the platform package into the main package's node_modules
//      (what npm would do via the optionalDependency)
//   4. launch `bin/secure-vibe.js mcp` and assert the MCP `initialize`
//      handshake returns a serverInfo.name
//   5. run `bin/secure-vibe.js gate` on a bad Dockerfile and assert exit 1
//
// No network, no `npm install`, no registry — it exercises the launcher's
// binary resolution, the bundled data path, the JSON-RPC handshake, and the
// CLI gate.
//
// Usage: node npm/smoke-test.mjs

import { promises as fs } from 'node:fs';
import { spawn, spawnSync } from 'node:child_process';
import path from 'node:path';
import os from 'node:os';
import url from 'node:url';

const HERE = path.dirname(url.fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..');
const SCOPE = '@shieldnet360';
const MAIN = 'secure-vibe';

const NODE_TO_GO = {
  'darwin-x64': { go: 'darwin-amd64', exe: false },
  'darwin-arm64': { go: 'darwin-arm64', exe: false },
  'linux-x64': { go: 'linux-amd64', exe: false },
  'linux-arm64': { go: 'linux-arm64', exe: false },
  'win32-x64': { go: 'windows-amd64', exe: true },
};

function die(msg) {
  console.error(`smoke-test: FAIL — ${msg}`);
  process.exit(1);
}

function run(cmd, args, opts = {}) {
  const r = spawnSync(cmd, args, { stdio: 'inherit', ...opts });
  if (r.status !== 0) die(`\`${cmd} ${args.join(' ')}\` exited ${r.status}`);
}

async function stat(p) {
  try { await fs.access(p); return true; } catch { return false; }
}

async function main() {
  const key = `${process.platform}-${process.arch}`;
  const target = NODE_TO_GO[key];
  if (!target) die(`unsupported host ${key}`);

  const work = await fs.mkdtemp(path.join(os.tmpdir(), 'secure-vibe-smoke-'));
  const binDir = path.join(work, 'bin');
  const outDir = path.join(work, 'out');
  await fs.mkdir(binDir, { recursive: true });

  // 1. build host binary
  const binName = `secure-vibe-${target.go}${target.exe ? '.exe' : ''}`;
  console.log(`[1/5] building ${binName}`);
  run('go', ['build', '-trimpath', '-ldflags', '-s -w', '-o', path.join(binDir, binName), './cmd/secure-vibe'], {
    cwd: REPO,
    env: { ...process.env, CGO_ENABLED: '0' },
  });

  // 2. assemble packages
  console.log('[2/5] assembling npm packages');
  run('node', [path.join(HERE, 'build.mjs'), '--binaries', binDir, '--root', REPO, '--version', '0.0.0-smoke', '--out', outDir]);

  // 3. wire the platform package into the main package's node_modules
  console.log('[3/5] wiring optionalDependency into node_modules');
  const mainPkg = path.join(outDir, MAIN);
  const platPkg = path.join(outDir, `${MAIN}-${key}`);
  if (!(await stat(platPkg))) die(`platform package not assembled for ${key}`);
  const nm = path.join(mainPkg, 'node_modules', SCOPE, `${MAIN}-${key}`);
  await fs.mkdir(path.dirname(nm), { recursive: true });
  await fs.cp(platPkg, nm, { recursive: true });

  const launcher = path.join(mainPkg, 'bin', 'secure-vibe.js');

  // 4. `secure-vibe mcp` + initialize handshake
  console.log('[4/5] launching `secure-vibe mcp` and sending initialize');
  const req =
    JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'smoke', version: '0' } },
    }) + '\n';

  const resp = await new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [launcher, 'mcp'], { stdio: ['pipe', 'pipe', 'inherit'] });
    let buf = '';
    const timer = setTimeout(() => { child.kill(); reject(new Error('timed out waiting for initialize response')); }, 15000);
    child.stdout.on('data', (d) => {
      buf += d.toString();
      const nl = buf.indexOf('\n');
      if (nl !== -1) {
        clearTimeout(timer);
        child.kill();
        try { resolve(JSON.parse(buf.slice(0, nl))); } catch (e) { reject(e); }
      }
    });
    child.on('error', reject);
    child.stdin.write(req);
  });

  const name = resp?.result?.serverInfo?.name;
  if (!name) die(`initialize did not return a serverInfo.name: ${JSON.stringify(resp)}`);

  // 5. run the CLI gate via the same launcher; it must resolve the binary +
  //    the bundled data tree (via SECURE_VIBE_LIBRARY_PATH) and exit 1 on a
  //    deliberately bad Dockerfile.
  console.log('[5/5] running `secure-vibe gate` on a bad Dockerfile');
  const df = path.join(work, 'Dockerfile');
  await fs.writeFile(df, 'FROM node:latest\nUSER root\n');
  const gate = spawnSync(process.execPath, [launcher, 'gate', df, '--severity-floor', 'high'], { stdio: 'inherit' });
  if (gate.status !== 1) die(`expected \`gate\` to exit 1 on a bad Dockerfile, got ${gate.status}`);

  await fs.rm(work, { recursive: true, force: true });
  console.log(`smoke-test: PASS — ${SCOPE}/${MAIN} (${key}) MCP handshakes (serverInfo.name=${name}) and \`secure-vibe gate\` gates`);
}

main().catch((e) => die(e.message));
