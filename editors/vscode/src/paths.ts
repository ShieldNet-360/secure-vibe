import * as vscode from "vscode";
import * as fs from "fs";
import * as path from "path";

// Resolves the secure-vibe binary and library-data locations, bridging
// three sources in priority order: explicit user settings, the
// extension-managed (auto-downloaded) copies under global storage, and
// finally PATH / environment fallbacks.

let ctx: vscode.ExtensionContext | undefined;

export function init(context: vscode.ExtensionContext): void {
  ctx = context;
}

function config(): vscode.WorkspaceConfiguration {
  return vscode.workspace.getConfiguration("skillsLibrary");
}

function storageDir(): string {
  if (!ctx) {
    throw new Error("paths.init(context) was not called");
  }
  return ctx.globalStorageUri.fsPath;
}

export function managedBinDir(): string {
  return path.join(storageDir(), "bin");
}

export function managedDataDir(): string {
  return path.join(storageDir(), "data");
}

export function binaryName(): string {
  return process.platform === "win32" ? "secure-vibe.exe" : "secure-vibe";
}

export function managedBinaryPath(): string {
  return path.join(managedBinDir(), binaryName());
}

export function managedBinaryExists(): boolean {
  return fs.existsSync(managedBinaryPath());
}

export function managedDataExists(): boolean {
  // `update` writes the full tree; presence of skills/ is the cheap
  // signal that the data dir is populated.
  return fs.existsSync(path.join(managedDataDir(), "skills"));
}

// userBinaryPath returns the explicitly configured binary path, or
// undefined when the user left it at the default ("secure-vibe").
export function userBinaryPath(): string | undefined {
  const p = config().get<string>("binaryPath", "secure-vibe").trim();
  return p === "" || p === "secure-vibe" ? undefined : p;
}

// effectiveBinaryPath is what the CLI wrapper actually executes.
export function effectiveBinaryPath(): string {
  const explicit = userBinaryPath();
  if (explicit) {
    return explicit;
  }
  if (managedBinaryExists()) {
    return managedBinaryPath();
  }
  return "secure-vibe";
}

// userLibraryDir returns the configured library path or the
// SECURE_VIBE_LIBRARY_PATH env var, or undefined when neither is set.
export function userLibraryDir(): string | undefined {
  const configured = config().get<string>("libraryPath", "").trim();
  if (configured !== "") {
    return configured;
  }
  const env = process.env.SECURE_VIBE_LIBRARY_PATH?.trim();
  return env && env !== "" ? env : undefined;
}

// effectiveLibraryDir is the data root the scanners read from.
export function effectiveLibraryDir(): string | undefined {
  const explicit = userLibraryDir();
  if (explicit) {
    return explicit;
  }
  if (managedDataExists()) {
    return managedDataDir();
  }
  return undefined;
}

export function autoDownloadEnabled(): boolean {
  return config().get<boolean>("autoDownload", true);
}

export function releaseBaseUrl(): string {
  return config()
    .get<string>(
      "releaseBaseUrl",
      "https://github.com/shieldnet-360/secure-vibe/releases/latest/download"
    )
    .trim();
}

// goTarget maps the Node platform/arch onto the GOOS-GOARCH suffix the
// release assets are named with (see selfupdate.go / npm/build.mjs).
export function goTarget(): { goos: string; goarch: string } {
  const goos =
    process.platform === "win32"
      ? "windows"
      : process.platform === "darwin"
      ? "darwin"
      : "linux";
  const goarch = process.arch === "arm64" ? "arm64" : "amd64";
  return { goos, goarch };
}
