import * as vscode from "vscode";
import * as fs from "fs";
import {
  NormalizedFinding,
  ScanSecretsResult,
  ScanDependenciesResult,
  ScanDockerfileResult,
  ScanGitHubActionsResult,
  PolicyCheckResult,
} from "./types";

// severityToVscode maps the library's severity bands onto VS Code's
// four diagnostic levels.
export function severityToVscode(sev: string): vscode.DiagnosticSeverity {
  switch (sev.toLowerCase().trim()) {
    case "critical":
    case "high":
      return vscode.DiagnosticSeverity.Error;
    case "medium":
      return vscode.DiagnosticSeverity.Warning;
    case "low":
      return vscode.DiagnosticSeverity.Information;
    default:
      return vscode.DiagnosticSeverity.Hint;
  }
}

// ---- Normalizers: each scanner result shape -> NormalizedFinding[] ----

export function fromSecrets(results: ScanSecretsResult[]): NormalizedFinding[] {
  const out: NormalizedFinding[] = [];
  for (const r of results) {
    if (!r.file_path) {
      continue;
    }
    for (const m of r.matches) {
      out.push({
        filePath: r.file_path,
        ruleId: `secret.${m.name}`,
        severity: m.severity,
        title: m.known_false_positive ? `${m.name} (likely false positive)` : m.name,
        start: m.start,
        end: m.end,
        knownFalsePositive: m.known_false_positive,
      });
    }
  }
  return out;
}

export function fromDependencies(
  results: ScanDependenciesResult[]
): NormalizedFinding[] {
  const out: NormalizedFinding[] = [];
  for (const r of results) {
    for (const f of r.findings) {
      out.push({
        filePath: r.file_path,
        ruleId: f.category,
        severity: f.severity,
        title: `${f.package}${f.version ? "@" + f.version : ""}: ${f.message}`,
        snippet: f.package,
      });
    }
  }
  return out;
}

export function fromDockerfile(r: ScanDockerfileResult): NormalizedFinding[] {
  return r.findings.map((f) => ({
    filePath: r.file_path,
    ruleId: f.rule_id,
    severity: f.severity,
    title: f.title,
    line: f.line,
    snippet: f.snippet,
  }));
}

export function fromGitHubActions(
  r: ScanGitHubActionsResult
): NormalizedFinding[] {
  return r.findings.map((f) => ({
    filePath: r.file_path,
    ruleId: f.rule_id,
    severity: f.severity,
    title: f.title,
    line: f.line,
    snippet: f.snippet,
  }));
}

export function fromGate(results: PolicyCheckResult[]): NormalizedFinding[] {
  const out: NormalizedFinding[] = [];
  for (const r of results) {
    for (const f of r.findings) {
      out.push({
        filePath: r.file_path,
        ruleId: f.rule_id,
        severity: f.severity,
        title: f.package
          ? `${f.package}${f.version ? "@" + f.version : ""}: ${f.title}`
          : f.title,
        line: f.line,
        snippet: f.snippet ?? f.package,
      });
    }
  }
  return out;
}

// rangeFor computes the best diagnostic range available for a finding:
// byte offsets (secrets) take precedence, then a 1-based line, then a
// search for the snippet text, then the first line as a fallback.
function rangeFor(finding: NormalizedFinding, text: string): vscode.Range {
  if (finding.start !== undefined && finding.end !== undefined) {
    const start = offsetToPosition(text, finding.start);
    const end = offsetToPosition(text, finding.end);
    return new vscode.Range(start, end);
  }
  if (finding.line && finding.line > 0) {
    const lineIdx = finding.line - 1;
    const lineText = text.split("\n")[lineIdx] ?? "";
    return new vscode.Range(lineIdx, 0, lineIdx, Math.max(lineText.length, 1));
  }
  if (finding.snippet) {
    const idx = text.indexOf(finding.snippet);
    if (idx >= 0) {
      return new vscode.Range(
        offsetToPosition(text, idx),
        offsetToPosition(text, idx + finding.snippet.length)
      );
    }
  }
  return new vscode.Range(0, 0, 0, 1);
}

// offsetToPosition converts a byte/character offset into a line/column
// Position by counting newlines. For ASCII (the common case for secrets
// and lockfile tokens) byte and UTF-16 offsets coincide.
function offsetToPosition(text: string, offset: number): vscode.Position {
  const clamped = Math.max(0, Math.min(offset, text.length));
  let line = 0;
  let col = 0;
  for (let i = 0; i < clamped; i++) {
    if (text[i] === "\n") {
      line++;
      col = 0;
    } else {
      col++;
    }
  }
  return new vscode.Position(line, col);
}

// publish writes the findings into the diagnostic collection, grouped
// by file. Returns the findings so a caller can also feed the tree view.
export function publish(
  collection: vscode.DiagnosticCollection,
  findings: NormalizedFinding[],
  source: string
): void {
  const byFile = new Map<string, NormalizedFinding[]>();
  for (const f of findings) {
    const list = byFile.get(f.filePath) ?? [];
    list.push(f);
    byFile.set(f.filePath, list);
  }
  for (const [filePath, fs2] of byFile) {
    let text = "";
    try {
      text = fs.readFileSync(filePath, "utf8");
    } catch {
      text = "";
    }
    const diags = fs2.map((f) => {
      const d = new vscode.Diagnostic(
        rangeFor(f, text),
        f.title,
        f.knownFalsePositive
          ? vscode.DiagnosticSeverity.Hint
          : severityToVscode(f.severity)
      );
      d.source = source;
      d.code = f.ruleId;
      return d;
    });
    collection.set(vscode.Uri.file(filePath), diags);
  }
}
