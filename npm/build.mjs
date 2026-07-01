#!/usr/bin/env node
// Assemble the publishable npm package set from prebuilt `secure-vibe` binaries
// plus the library data tree. Produces, under --out:
//
//   secure-vibe/                     (platform-agnostic: launcher + data/)
//   secure-vibe-<node-platform-arch> (per platform: the `secure-vibe` binary)
//
// SecureVibe is ONE Go binary (`secure-vibe`) exposing every subcommand — the
// scanners, the `gate`, `init`, `mcp` (the MCP server), and `dev …`. The main
// package exposes a single bin, `secure-vibe`, that reads the bundled data/ via
// SECURE_VIBE_LIBRARY_PATH.
//
// Each platform package is gated by `os`/`cpu` so npm installs only the one
// matching the host. The main package lists them all as optionalDependencies
// pinned to the same version. Nothing is published here — see npm-publish CI.
//
// Usage:
//   node npm/build.mjs --binaries <dir> --root <repo-root> --version <x.y.z> --out <dir>
//
// --binaries  dir with secure-vibe-<goos>-<goarch>[.exe]
// --root      repo root to copy the data tree from (default: repo root of this script)
// --version   version stamped into every package.json (default: 0.0.0-dev)
// --out       output dir (default: npm/dist)

import { promises as fs } from 'node:fs';
import path from 'node:path';
import url from 'node:url';

const HERE = path.dirname(url.fileURLToPath(import.meta.url));
const REPO_DEFAULT = path.resolve(HERE, '..');

// node platform/arch  ->  go GOOS-GOARCH (binary suffix) + exe flag
const PLATFORMS = [
  { node: 'darwin-x64', go: 'darwin-amd64', os: 'darwin', cpu: 'x64', exe: false },
  { node: 'darwin-arm64', go: 'darwin-arm64', os: 'darwin', cpu: 'arm64', exe: false },
  { node: 'linux-x64', go: 'linux-amd64', os: 'linux', cpu: 'x64', exe: false },
  { node: 'linux-arm64', go: 'linux-arm64', os: 'linux', cpu: 'arm64', exe: false },
  { node: 'win32-x64', go: 'windows-amd64', os: 'win32', cpu: 'x64', exe: true },
];

// The data dirs/files `secure-vibe` reads at runtime (it requires <root>/skills
// to exist; the scanners also read vulnerabilities/, rules/, dictionaries/,
// compliance/, profiles/, and manifest.json). This mirrors the release data
// tarball minus dist/ (pointer output the binary regenerates on demand).
const DATA_ENTRIES = [
  'skills',
  'vulnerabilities',
  'dictionaries',
  'rules',
  'compliance',
  'profiles',
  'manifest.json',
];

const SCOPE = '@shieldnet360';
const MAIN = 'secure-vibe';

function parseArgs(argv) {
  const out = { binaries: null, root: REPO_DEFAULT, version: '0.0.0-dev', out: path.join(HERE, 'dist') };
  for (let i = 0; i < argv.length; i += 2) {
    const k = argv[i].replace(/^--/, '');
    const v = argv[i + 1];
    if (!(k in out)) throw new Error(`unknown flag: ${argv[i]}`);
    out[k] = v;
  }
  if (!out.binaries) throw new Error('--binaries <dir> is required');
  return out;
}

async function exists(p) {
  try { await fs.access(p); return true; } catch { return false; }
}

async function writeJson(p, obj) {
  await fs.writeFile(p, JSON.stringify(obj, null, 2) + '\n');
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const { binaries, root, version, out } = args;

  await fs.rm(out, { recursive: true, force: true });
  await fs.mkdir(out, { recursive: true });

  // ---- platform packages -------------------------------------------------
  const built = [];
  for (const p of PLATFORMS) {
    const srcBin = path.join(binaries, `secure-vibe-${p.go}${p.exe ? '.exe' : ''}`);
    if (!(await exists(srcBin))) {
      console.warn(`skip ${p.node}: ${path.basename(srcBin)} not found in --binaries`);
      continue;
    }
    const pkgDir = path.join(out, `${MAIN}-${p.node}`);
    await fs.mkdir(path.join(pkgDir, 'bin'), { recursive: true });
    const destBin = path.join(pkgDir, 'bin', p.exe ? 'secure-vibe.exe' : 'secure-vibe');
    await fs.copyFile(srcBin, destBin);
    await fs.chmod(destBin, 0o755);
    await writeJson(path.join(pkgDir, 'package.json'), {
      name: `${SCOPE}/${MAIN}-${p.node}`,
      version,
      description: `SecureVibe \`secure-vibe\` binary for ${p.node}.`,
      license: 'MIT',
      repository: { type: 'git', url: 'git+https://github.com/ShieldNet-360/secure-vibe.git' },
      os: [p.os],
      cpu: [p.cpu],
      files: ['bin/'],
    });
    built.push(p);
    console.log(`built ${SCOPE}/${MAIN}-${p.node} (${p.go})`);
  }
  if (built.length === 0) throw new Error('no platform binaries found; nothing to assemble');

  // ---- main (platform-agnostic) package ----------------------------------
  const mainSkel = path.join(HERE, MAIN);
  const mainOut = path.join(out, MAIN);
  await fs.mkdir(path.join(mainOut, 'bin'), { recursive: true });
  await fs.copyFile(path.join(mainSkel, 'bin', 'secure-vibe.js'), path.join(mainOut, 'bin', 'secure-vibe.js'));
  await fs.chmod(path.join(mainOut, 'bin', 'secure-vibe.js'), 0o755);
  await fs.copyFile(path.join(mainSkel, 'README.md'), path.join(mainOut, 'README.md'));

  // data tree
  const dataOut = path.join(mainOut, 'data');
  await fs.mkdir(dataOut, { recursive: true });
  for (const entry of DATA_ENTRIES) {
    const src = path.join(root, entry);
    if (!(await exists(src))) throw new Error(`data entry missing: ${entry} (looked in ${root})`);
    await fs.cp(src, path.join(dataOut, entry), { recursive: true });
  }

  // package.json: stamp version + pin optionalDependencies to ONLY the
  // platforms we actually built, at this version.
  const skelPkg = JSON.parse(await fs.readFile(path.join(mainSkel, 'package.json'), 'utf8'));
  skelPkg.version = version;
  skelPkg.optionalDependencies = {};
  for (const p of built) {
    skelPkg.optionalDependencies[`${SCOPE}/${MAIN}-${p.node}`] = version;
  }
  await writeJson(path.join(mainOut, 'package.json'), skelPkg);
  console.log(`assembled ${SCOPE}/${MAIN} @ ${version} (data: ${DATA_ENTRIES.join(', ')})`);
  console.log(`output: ${out}`);
}

main().catch((e) => {
  console.error(`build.mjs: ${e.message}`);
  process.exit(1);
});
