# npm packaging for `secure-vibe`

This directory packages the consolidated Go binary (`cmd/secure-vibe`) for
distribution over npm, so users can run it with `npx @shieldnet360/secure-vibe`
— the MCP server via `npx @shieldnet360/secure-vibe mcp`, the CLI gate via
`npx @shieldnet360/secure-vibe gate …`.

## Layout

```
npm/
  secure-vibe/             source skeleton of the MAIN (platform-agnostic) package
    bin/secure-vibe.js     the launcher (resolves the host binary, execs it, sets SECURE_VIBE_LIBRARY_PATH)
    package.json          version "0.0.0-dev" placeholder; optionalDependencies listed
    README.md             user-facing npm readme
  build.mjs               generator: binaries + data tree -> publishable package set
  smoke-test.mjs          host-only end-to-end test (build -> assemble -> handshake + gate)
  dist/                   (generated, git-ignored) the assembled packages
```

## Distribution model (esbuild-style platform packages)

`npx` runs a **thin launcher**, not the Go binary directly. The published set is
six packages:

- **`@shieldnet360/secure-vibe`** — platform-agnostic. Ships `bin/secure-vibe.js`
  plus the **library data tree** (`data/`: skills, the OSV cache, checklists),
  shipped once. Lists all five platform packages as `optionalDependencies`.
- **`@shieldnet360/secure-vibe-<os>-<arch>`** ×5 — each carries only the prebuilt
  `secure-vibe` binary, gated by `os`/`cpu`.

Because the binaries are `optionalDependencies` gated by `os`/`cpu`, npm installs
**only the one** matching the host. There is **no postinstall download** — installs
work offline and under `npm ci --ignore-scripts`, which matters for a security tool
(no arbitrary fetch-and-exec at install time).

`secure-vibe.js` resolves the host platform package via
`require.resolve('@shieldnet360/secure-vibe-<key>/package.json')`, then spawns its
`secure-vibe` binary with `SECURE_VIBE_LIBRARY_PATH=<this package>/data` and forwards
argv + stdio. The binary reads its data from disk (no `go:embed`), so the data
travels with it — hence the bundled `data/`.

### Why not a single self-contained binary (`go:embed`)?

Embedding would freeze the data at build time and bypass the `secure-vibe update`
model that refreshes the OSV cache independently of the binary. Shipping
data-as-files keeps that property and adds no Go changes.

## Build

```sh
# from release artifacts (CI) or locally cross-compiled binaries:
node npm/build.mjs --binaries <dir-of-secure-vibe-binaries> --root . --version <x.y.z> --out npm/dist
```

`--binaries` must contain `secure-vibe-<goos>-<goarch>[.exe]` (the names
`release.yml` produces). Missing platforms are skipped with a warning and dropped
from the main package's `optionalDependencies`, so a single-platform assembly is
valid for local testing.

## Test

```sh
node npm/smoke-test.mjs
```

Builds `secure-vibe` for the host, assembles the main + host platform package, wires
the platform package into the main package's `node_modules` (what npm would do via
the optionalDependency), then launches `bin/secure-vibe.js mcp` and asserts the MCP
`initialize` handshake returns a `serverInfo.name`, and runs `bin/secure-vibe.js gate`
on a bad Dockerfile and asserts a non-zero exit. No network, no registry.

## Publishing

Not done here — see [`.github/workflows/npm-publish.yml`](../.github/workflows/npm-publish.yml).
On a release (or `workflow_dispatch` with a tag) it cross-compiles the binaries,
runs `build.mjs` + `smoke-test.mjs` as a gate, and publishes the platform packages
first, then the main package, at the release version. Requires the `@shieldnet360`
npm scope and an `NPM_TOKEN` repo secret (publish no-ops if the secret is absent).
