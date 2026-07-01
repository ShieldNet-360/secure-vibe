# Secure-Code Skills — VS Code Extension

Drive the [`secure-vibe`](../../README.md) security tooling from inside VS Code.
The extension is a thin wrapper around the `secure-vibe` Go binary, so its
findings are **identical** to the CLI and the MCP server — there is no second
detection engine to drift.

## Features

- **Init Skills Config** — generate an IDE/agent rules file (`claude`, `cursor`,
  `copilot`, `codex`, `devin`, `cline`, `universal`) into the workspace.
- **Scan Current File / Workspace for Secrets** — Secret-detection credential, API key,
  token, and PEM detection.
- **Scan Dependencies** — parse lockfiles and check every resolved package
  against the malicious-package, typosquat, CVE-pattern, and OSV databases.
- **Scan Dockerfile** / **Scan GitHub Actions Workflow** — hardening passes.
- **Run Security Gate on Workspace** — the canonical "fail the build" check;
  walks the workspace and reports pass/fail against the severity floor.
- **Check a Single Dependency** — ad-hoc `package@version` lookup.

All findings are surfaced as native **diagnostics** in the Problems panel and in
a dedicated **Findings** view in the activity bar.

> SBOM generation is not included in this version.

## Zero-install by default

On the first scan, the extension automatically provisions everything it needs
into its own global storage — **no manual install required**:

1. **Binary** — downloads the `secure-vibe` build for your OS/arch from GitHub
   Releases and verifies it against the published `checksums-<os>-<arch>.txt`
   (SHA-256) before saving it.
2. **Rule data** — runs that binary's own `secure-vibe update`, which fetches
   the **signed** `secure-vibe-data.tar.gz` and verifies it with the
   embedded Ed25519 key, then writes the rule tree.

You can opt out via `skillsLibrary.autoDownload: false` and instead point the
extension at your own install:

- **Binary** — set `skillsLibrary.binaryPath` (or put `secure-vibe` on `PATH`).
- **Data** — set `skillsLibrary.libraryPath`, or export `SECURE_VIBE_LIBRARY_PATH`.

Explicit settings always take precedence over the managed copies.

## Getting started

1. **Install the extension** (from the Marketplace, or a local `.vsix` via
   *Extensions: Install from VSIX…*).
2. **Open your project folder** in VS Code.
3. **Run your first scan** — open the Command Palette (`Cmd/Ctrl+Shift+P`) and run
   **Skills: Scan Workspace for Secrets**. On the first run you'll see a
   *"Setting up Secure-Code Skills"* notification while the verified binary and
   signed rule data download — this happens once.
4. **Review findings** — results appear in the **Problems** panel and in the
   **Secure-Code Skills** view in the activity bar (the shield icon). Click any
   finding to jump to its location.
5. **Gate before you commit** — run **Skills: Run Security Gate on Workspace**
   (or click the `$(shield) Skills` status-bar item). It passes/fails against
   `skillsLibrary.severityFloor`.

### Typical workflows

- **Catch secrets as you work** — enable `skillsLibrary.scanSecretsOnSave` to
  scan each file on save.
- **Audit a lockfile** — right-click a lockfile (e.g. `package-lock.json`,
  `requirements.txt`, `go.sum`) in the Explorer and choose **Scan Dependencies**.
- **Harden a Dockerfile / workflow** — right-click a `Dockerfile`, or open a
  `.github/workflows/*.yml` and run the matching scan command.
- **Vet one package before adding it** — run **Skills: Check a Single
  Dependency**, enter the name, ecosystem, and optional version; the JSON result
  prints to the *Secure-Code Skills* output channel.
- **Onboard an AI agent** — run **Skills: Init Skills Config**, pick your tool
  (`claude`, `cursor`, `copilot`, `codex`, `devin`, `cline`, or `universal`), and
  the rules file is written into the workspace.

## Commands reference

| Command (palette) | What it does | Entry points |
|-------------------|--------------|--------------|
| Skills: Init Skills Config | Generate an agent/IDE rules file | Palette |
| Skills: Scan Current File for Secrets | Secret scan the active editor | Palette, editor right-click |
| Skills: Scan Workspace for Secrets | Secret scan the whole folder | Palette |
| Skills: Scan Dependencies | Lockfile → malicious/typosquat/CVE/OSV check | Palette, Explorer right-click |
| Skills: Scan Current Dockerfile | Dockerfile hardening pass | Palette, Explorer right-click |
| Skills: Scan Current GitHub Actions Workflow | Workflow hardening pass | Palette |
| Skills: Run Security Gate on Workspace | CI-style pass/fail check | Palette, status bar |
| Skills: Check a Single Dependency | Ad-hoc `package@version` lookup | Palette |
| Skills: Clear Findings | Clear diagnostics + the Findings view | Palette |

## Troubleshooting

- **"binary not found" / setup failed** — check the **Secure-Code Skills** output
  channel (*View → Output → Secure-Code Skills*) for the download URL and error.
  If you're offline or behind a proxy, set `skillsLibrary.autoDownload: false`
  and point `skillsLibrary.binaryPath` / `skillsLibrary.libraryPath` at a local
  install.
- **No findings where you expect them** — confirm the rule data resolved: an
  explicit `skillsLibrary.libraryPath`, `SECURE_VIBE_LIBRARY_PATH`, or the managed
  data dir must contain a `skills/` tree.
- **Pin or mirror downloads** — override `skillsLibrary.releaseBaseUrl` to a
  specific release tag's `download` URL or an internal mirror.

## Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `skillsLibrary.binaryPath` | `secure-vibe` | Path to the `secure-vibe` binary. |
| `skillsLibrary.libraryPath` | `""` | Path to the secure-vibe checkout (falls back to `SECURE_VIBE_LIBRARY_PATH`). |
| `skillsLibrary.vulnSource` | `local` | OSV lookup mode: `local` (offline), `external` (api.osv.dev), `hybrid`. |
| `skillsLibrary.severityFloor` | `high` | Lowest severity that fails the gate. |
| `skillsLibrary.defaultInitTool` | `devin` | Default target tool for Init. |
| `skillsLibrary.scanSecretsOnSave` | `false` | Scan a file for secrets on save. |
| `skillsLibrary.autoDownload` | `true` | Auto-download a verified binary + signed data on first run. |
| `skillsLibrary.releaseBaseUrl` | GitHub latest release | Base URL for binary + checksum downloads. |

## Commands

All commands are under the **Skills** category in the Command Palette
(`Cmd/Ctrl+Shift+P`). Dependency lockfiles and Dockerfiles also expose scans via
the Explorer right-click menu, and the current file exposes a secret scan via the
editor right-click menu.

## Develop / build

```bash
npm install
npm run compile      # type-check + emit dist/
# press F5 in VS Code to launch an Extension Development Host
```

To package a `.vsix`:

```bash
npx @vscode/vsce package
```
