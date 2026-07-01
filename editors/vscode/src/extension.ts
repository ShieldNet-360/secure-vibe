import * as vscode from "vscode";
import * as cli from "./cli";
import { CliError } from "./cli";
import * as diag from "./diagnostics";
import * as paths from "./paths";
import * as bootstrap from "./bootstrap";
import { FindingsProvider } from "./findingsTree";
import { NormalizedFinding } from "./types";

let collection: vscode.DiagnosticCollection;
let output: vscode.OutputChannel;
let status: vscode.StatusBarItem;
let findingsProvider: FindingsProvider;

const SOURCE = "SecureVibe";

export function activate(context: vscode.ExtensionContext): void {
  paths.init(context);
  collection = vscode.languages.createDiagnosticCollection("skillsLibrary");
  output = vscode.window.createOutputChannel("Secure-Code Skills");
  status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
  status.command = "skillsLibrary.gate";
  status.text = "$(shield) Skills";
  status.tooltip = "Run the SecureVibe gate on the workspace";
  status.show();

  findingsProvider = new FindingsProvider();

  context.subscriptions.push(
    collection,
    output,
    status,
    vscode.window.registerTreeDataProvider("skillsLibrary.findings", findingsProvider),
    vscode.commands.registerCommand("skillsLibrary.init", () => cmdInit()),
    vscode.commands.registerCommand("skillsLibrary.scanSecretsFile", () =>
      cmdScanSecretsFile()
    ),
    vscode.commands.registerCommand("skillsLibrary.scanSecretsWorkspace", () =>
      cmdScanSecretsWorkspace()
    ),
    vscode.commands.registerCommand("skillsLibrary.scanDependencies", (uri?: vscode.Uri) =>
      cmdScanDependencies(uri)
    ),
    vscode.commands.registerCommand("skillsLibrary.scanDockerfile", (uri?: vscode.Uri) =>
      cmdScanDockerfile(uri)
    ),
    vscode.commands.registerCommand("skillsLibrary.scanGitHubActions", (uri?: vscode.Uri) =>
      cmdScanGitHubActions(uri)
    ),
    vscode.commands.registerCommand("skillsLibrary.gate", () => cmdGate()),
    vscode.commands.registerCommand("skillsLibrary.checkDependency", () =>
      cmdCheckDependency()
    ),
    vscode.commands.registerCommand("skillsLibrary.clearDiagnostics", () => {
      collection.clear();
      findingsProvider.clear();
      setStatus("$(shield) Skills");
    }),
    vscode.workspace.onDidSaveTextDocument((doc) => onSave(doc))
  );
}

export function deactivate(): void {
  collection?.dispose();
  output?.dispose();
  status?.dispose();
}

// ---- command implementations ----

// ready returns true once a usable binary + data are available,
// auto-downloading them on first use when enabled.
async function ready(): Promise<boolean> {
  return bootstrap.ensureReady(output);
}

async function cmdInit(): Promise<void> {
  if (!(await ready())) {
    return;
  }
  const cfg = vscode.workspace.getConfiguration("skillsLibrary");
  const defaultTool = cfg.get<string>("defaultInitTool", "devin");
  const tool = await vscode.window.showQuickPick(
    ["claude", "cursor", "copilot", "codex", "devin", "cline", "universal"],
    { title: "Target tool for the skills config", placeHolder: defaultTool }
  );
  if (!tool) {
    return;
  }
  const root = workspaceRoot();
  if (!root) {
    vscode.window.showErrorMessage("Open a folder before running Init Skills Config.");
    return;
  }
  const libraryDir = paths.effectiveLibraryDir();
  if (!libraryDir) {
    promptMissingLibrary();
    return;
  }
  await withProgress(`Initializing ${tool} skills config`, async () => {
    try {
      const msg = await cli.init(tool, root, libraryDir);
      log(msg);
      vscode.window.showInformationMessage(`Skills config written for ${tool}.`);
    } catch (err) {
      reportError(err);
    }
  });
}

async function cmdScanSecretsFile(): Promise<void> {
  const file = activeFilePath();
  if (!file) {
    vscode.window.showWarningMessage("No active file to scan.");
    return;
  }
  await runScan("Scanning file for secrets", async () => {
    const results = await cli.scanSecrets(file);
    return diag.fromSecrets(results);
  });
}

async function cmdScanSecretsWorkspace(): Promise<void> {
  const root = workspaceRoot();
  if (!root) {
    return;
  }
  await runScan("Scanning workspace for secrets", async () => {
    const results = await cli.scanSecrets(root);
    return diag.fromSecrets(results);
  });
}

async function cmdScanDependencies(uri?: vscode.Uri): Promise<void> {
  const target = uri?.fsPath ?? workspaceRoot();
  if (!target) {
    return;
  }
  await runScan("Scanning dependencies", async () => {
    const results = await cli.scanDependencies(target);
    return diag.fromDependencies(results);
  });
}

async function cmdScanDockerfile(uri?: vscode.Uri): Promise<void> {
  const file = uri?.fsPath ?? activeFilePath();
  if (!file) {
    return;
  }
  await runScan("Scanning Dockerfile", async () => {
    const result = await cli.scanDockerfile(file);
    return diag.fromDockerfile(result);
  });
}

async function cmdScanGitHubActions(uri?: vscode.Uri): Promise<void> {
  const file = uri?.fsPath ?? activeFilePath();
  if (!file) {
    return;
  }
  await runScan("Scanning workflow", async () => {
    const result = await cli.scanGitHubActions(file);
    return diag.fromGitHubActions(result);
  });
}

async function cmdGate(): Promise<void> {
  const root = workspaceRoot();
  if (!root) {
    return;
  }
  if (!(await ready())) {
    return;
  }
  await withProgress("Running security gate", async () => {
    try {
      const results = await cli.gate(root);
      const findings = diag.fromGate(results);
      publish(findings);
      const failing = results.filter((r) => !r.pass).length;
      if (failing > 0) {
        setStatus(`$(shield) ${findings.length} finding(s)`, "errorForeground");
        vscode.window.showErrorMessage(
          `Gate FAILED: ${findings.length} finding(s) across ${failing} file(s) at or above '${cli.severityFloor()}'.`
        );
      } else {
        setStatus("$(shield) Gate passed");
        vscode.window.showInformationMessage("Gate passed: no findings at or above the floor.");
      }
    } catch (err) {
      reportError(err);
    }
  });
}

async function cmdCheckDependency(): Promise<void> {
  const pkg = await vscode.window.showInputBox({
    title: "Package name",
    placeHolder: "e.g. lodash",
  });
  if (!pkg) {
    return;
  }
  const ecosystem = await vscode.window.showQuickPick(
    ["npm", "pypi", "go", "cargo", "rubygems", "maven", "nuget"],
    { title: "Ecosystem" }
  );
  if (!ecosystem) {
    return;
  }
  const version =
    (await vscode.window.showInputBox({
      title: "Version (optional)",
      placeHolder: "leave blank to skip version-specific OSV matching",
    })) ?? "";
  if (!(await ready())) {
    return;
  }
  await withProgress(`Checking ${pkg}`, async () => {
    try {
      const result = await cli.checkDependency(pkg, ecosystem, version);
      log(`check-dependency ${pkg} (${ecosystem}):`);
      log(JSON.stringify(result, null, 2));
      output.show(true);
    } catch (err) {
      reportError(err);
    }
  });
}

// ---- helpers ----

function onSave(doc: vscode.TextDocument): void {
  const enabled = vscode.workspace
    .getConfiguration("skillsLibrary")
    .get<boolean>("scanSecretsOnSave", false);
  if (!enabled || doc.uri.scheme !== "file") {
    return;
  }
  void runScan("Scanning saved file for secrets", async () => {
    const results = await cli.scanSecrets(doc.uri.fsPath);
    return diag.fromSecrets(results);
  });
}

async function runScan(
  title: string,
  fn: () => Promise<NormalizedFinding[]>
): Promise<void> {
  if (!(await ready())) {
    return;
  }
  await withProgress(title, async () => {
    try {
      const findings = await fn();
      publish(findings);
      setStatus(
        findings.length > 0
          ? `$(shield) ${findings.length} finding(s)`
          : "$(shield) No findings",
        findings.length > 0 ? "editorWarning.foreground" : undefined
      );
      if (findings.length === 0) {
        vscode.window.showInformationMessage(`${title}: no findings.`);
      }
    } catch (err) {
      reportError(err);
    }
  });
}

function publish(findings: NormalizedFinding[]): void {
  collection.clear();
  diag.publish(collection, findings, SOURCE);
  findingsProvider.setFindings(findings);
  if (findings.length > 0) {
    vscode.commands.executeCommand("setContext", "skillsLibrary.hasFindings", true);
  }
}

function withProgress(title: string, fn: () => Promise<void>): Thenable<void> {
  return vscode.window.withProgress(
    { location: vscode.ProgressLocation.Notification, title, cancellable: false },
    fn
  );
}

function workspaceRoot(): string | undefined {
  return vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
}

function activeFilePath(): string | undefined {
  const doc = vscode.window.activeTextEditor?.document;
  return doc && doc.uri.scheme === "file" ? doc.uri.fsPath : undefined;
}

function promptMissingLibrary(): void {
  vscode.window
    .showErrorMessage(
      "No secure-vibe path configured. Set 'skillsLibrary.libraryPath' or the SECURE_VIBE_LIBRARY_PATH environment variable.",
      "Open Settings"
    )
    .then((choice) => {
      if (choice === "Open Settings") {
        vscode.commands.executeCommand(
          "workbench.action.openSettings",
          "skillsLibrary.libraryPath"
        );
      }
    });
}

function setStatus(text: string, colorId?: string): void {
  status.text = text;
  status.color = colorId ? new vscode.ThemeColor(colorId) : undefined;
}

function log(msg: string): void {
  output.appendLine(msg);
}

function reportError(err: unknown): void {
  if (err instanceof CliError) {
    log(`ERROR: ${err.message}`);
    if (err.stderr) {
      log(err.stderr);
    }
    vscode.window
      .showErrorMessage(err.message, "Show Output")
      .then((c) => c === "Show Output" && output.show(true));
    return;
  }
  const message = err instanceof Error ? err.message : String(err);
  log(`ERROR: ${message}`);
  vscode.window.showErrorMessage(`Secure-Code Skills: ${message}`);
}
