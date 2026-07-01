import { execFile } from "child_process";
import * as vscode from "vscode";
import * as paths from "./paths";
import {
  ScanSecretsResult,
  ScanDependenciesResult,
  ScanDockerfileResult,
  ScanGitHubActionsResult,
  PolicyCheckResult,
} from "./types";

// Generous cap: a workspace-wide gate or secret scan can emit a lot of
// JSON. 64 MiB keeps even large monorepos from tripping the default
// 1 MiB execFile buffer.
const MAX_BUFFER = 64 * 1024 * 1024;

export interface CliResult {
  stdout: string;
  stderr: string;
  code: number;
}

export class CliError extends Error {
  constructor(
    message: string,
    public readonly code: number,
    public readonly stderr: string
  ) {
    super(message);
    this.name = "CliError";
  }
}

function config(): vscode.WorkspaceConfiguration {
  return vscode.workspace.getConfiguration("skillsLibrary");
}

export function binaryPath(): string {
  return paths.effectiveBinaryPath();
}

export function vulnSource(): string {
  return config().get<string>("vulnSource", "local");
}

export function severityFloor(): string {
  return config().get<string>("severityFloor", "high");
}

// libraryArgs appends `--path <dataRoot>` resolved from settings, the
// SECURE_VIBE_LIBRARY_PATH env var, or the extension-managed data dir. When
// none resolve, the child process falls back to its own cwd/env
// resolution.
function libraryArgs(): string[] {
  const lib = paths.effectiveLibraryDir();
  return lib ? ["--path", lib] : [];
}

// run executes the secure-vibe binary with the given argument vector.
// It never uses a shell, so file paths and user-supplied package names
// cannot inject additional commands. A non-zero exit is surfaced as a
// CliError EXCEPT for the gate command, where exit 1 is a legitimate
// "findings present" signal the caller handles.
export function run(
  args: string[],
  cwd: string | undefined,
  allowNonZeroExit = false
): Promise<CliResult> {
  const bin = binaryPath();
  return new Promise((resolve, reject) => {
    execFile(
      bin,
      args,
      { cwd, maxBuffer: MAX_BUFFER, env: process.env },
      (err, stdout, stderr) => {
        const code =
          err && typeof (err as { code?: unknown }).code === "number"
            ? ((err as { code: number }).code)
            : err
            ? 1
            : 0;
        if (err && (err as NodeJS.ErrnoException).code === "ENOENT") {
          reject(
            new CliError(
              `secure-vibe binary not found at "${bin}". Set "skillsLibrary.binaryPath" in settings.`,
              -1,
              String(stderr)
            )
          );
          return;
        }
        if (err && !allowNonZeroExit) {
          reject(
            new CliError(
              `secure-vibe ${args[0]} failed (exit ${code}): ${String(stderr).trim()}`,
              code,
              String(stderr)
            )
          );
          return;
        }
        resolve({ stdout: String(stdout), stderr: String(stderr), code });
      }
    );
  });
}

function parseJSON<T>(stdout: string): T {
  return JSON.parse(stdout) as T;
}

// asArray normalizes the CLI's "single object for one file, array for a
// directory" output convention into a flat array.
function asArray<T>(parsed: T | T[]): T[] {
  return Array.isArray(parsed) ? parsed : [parsed];
}

export async function scanSecrets(target: string): Promise<ScanSecretsResult[]> {
  const res = await run(
    ["scan-secrets", target, "--format", "json", ...libraryArgs()],
    undefined
  );
  return asArray(parseJSON<ScanSecretsResult | ScanSecretsResult[]>(res.stdout));
}

export async function scanDependencies(
  target: string
): Promise<ScanDependenciesResult[]> {
  const res = await run(
    [
      "scan-dependencies",
      target,
      "--format",
      "json",
      "--vuln-source",
      vulnSource(),
      ...libraryArgs(),
    ],
    undefined
  );
  return asArray(
    parseJSON<ScanDependenciesResult | ScanDependenciesResult[]>(res.stdout)
  );
}

export async function scanDockerfile(
  target: string
): Promise<ScanDockerfileResult> {
  const res = await run(
    ["scan-dockerfile", target, "--format", "json", ...libraryArgs()],
    undefined
  );
  return parseJSON<ScanDockerfileResult>(res.stdout);
}

export async function scanGitHubActions(
  target: string
): Promise<ScanGitHubActionsResult> {
  const res = await run(
    ["scan-github-actions", target, "--format", "json", ...libraryArgs()],
    undefined
  );
  return parseJSON<ScanGitHubActionsResult>(res.stdout);
}

export async function gate(target: string): Promise<PolicyCheckResult[]> {
  // Exit 1 means "findings at or above the floor" — not an error.
  const res = await run(
    [
      "gate",
      target,
      "--format",
      "json",
      "--severity-floor",
      severityFloor(),
      ...libraryArgs(),
    ],
    undefined,
    true
  );
  const trimmed = res.stdout.trim();
  if (trimmed === "") {
    return [];
  }
  return asArray(parseJSON<PolicyCheckResult | PolicyCheckResult[]>(trimmed));
}

export async function init(
  tool: string,
  outDir: string,
  libraryDir: string
): Promise<string> {
  const res = await run(
    ["init", "--tool", tool, "--library", libraryDir, "--out", outDir, "--no-prompt"],
    outDir
  );
  return res.stdout.trim();
}

export async function checkDependency(
  pkg: string,
  ecosystem: string,
  version: string
): Promise<unknown> {
  const args = [
    "check-dependency",
    "--package",
    pkg,
    "--ecosystem",
    ecosystem,
    "--format",
    "json",
    "--vuln-source",
    vulnSource(),
    ...libraryArgs(),
  ];
  if (version.trim() !== "") {
    args.push("--version", version.trim());
  }
  const res = await run(args, undefined);
  return parseJSON<unknown>(res.stdout);
}
