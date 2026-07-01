import * as vscode from "vscode";
import { NormalizedFinding } from "./types";
import { severityToVscode } from "./diagnostics";

// FindingNode is either a file group (children = its findings) or a
// leaf finding.
type FindingNode =
  | { kind: "file"; filePath: string; findings: NormalizedFinding[] }
  | { kind: "finding"; finding: NormalizedFinding };

export class FindingsProvider implements vscode.TreeDataProvider<FindingNode> {
  private readonly _onDidChange = new vscode.EventEmitter<void>();
  readonly onDidChangeTreeData = this._onDidChange.event;

  private findings: NormalizedFinding[] = [];

  setFindings(findings: NormalizedFinding[]): void {
    this.findings = findings;
    this._onDidChange.fire();
  }

  clear(): void {
    this.findings = [];
    this._onDidChange.fire();
  }

  getTreeItem(node: FindingNode): vscode.TreeItem {
    if (node.kind === "file") {
      const item = new vscode.TreeItem(
        vscode.Uri.file(node.filePath),
        vscode.TreeItemCollapsibleState.Expanded
      );
      item.description = `${node.findings.length} finding(s)`;
      item.resourceUri = vscode.Uri.file(node.filePath);
      item.iconPath = vscode.ThemeIcon.File;
      return item;
    }

    const f = node.finding;
    const item = new vscode.TreeItem(
      f.title,
      vscode.TreeItemCollapsibleState.None
    );
    item.description = `${f.severity}${f.ruleId ? " · " + f.ruleId : ""}`;
    item.tooltip = `${f.severity.toUpperCase()} — ${f.ruleId}\n${f.title}`;
    item.iconPath = iconForSeverity(f.severity);
    const line = f.line && f.line > 0 ? f.line - 1 : 0;
    item.command = {
      command: "vscode.open",
      title: "Open",
      arguments: [
        vscode.Uri.file(f.filePath),
        { selection: new vscode.Range(line, 0, line, 0) },
      ],
    };
    return item;
  }

  getChildren(node?: FindingNode): FindingNode[] {
    if (!node) {
      const byFile = new Map<string, NormalizedFinding[]>();
      for (const f of this.findings) {
        const list = byFile.get(f.filePath) ?? [];
        list.push(f);
        byFile.set(f.filePath, list);
      }
      return [...byFile.entries()].map(([filePath, findings]) => ({
        kind: "file",
        filePath,
        findings,
      }));
    }
    if (node.kind === "file") {
      return node.findings.map((finding) => ({ kind: "finding", finding }));
    }
    return [];
  }
}

function iconForSeverity(sev: string): vscode.ThemeIcon {
  switch (severityToVscode(sev)) {
    case vscode.DiagnosticSeverity.Error:
      return new vscode.ThemeIcon(
        "error",
        new vscode.ThemeColor("errorForeground")
      );
    case vscode.DiagnosticSeverity.Warning:
      return new vscode.ThemeIcon(
        "warning",
        new vscode.ThemeColor("editorWarning.foreground")
      );
    default:
      return new vscode.ThemeIcon("info");
  }
}
