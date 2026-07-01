// TypeScript mirrors of the JSON payloads emitted by `secure-vibe
// ... --format json`. Field names match the Go `json:"..."` tags in
// internal/tools/library_scanners.go and library_extended.go so the
// wrapper can parse the CLI output directly.

export interface SecretMatch {
  name: string;
  severity: string;
  match: string;
  start: number;
  end: number;
  known_false_positive: boolean;
  score: number;
  entropy: number;
  hotword_hit: boolean;
}

export interface ScanSecretsResult {
  file_path?: string;
  file_size?: number;
  matches: SecretMatch[];
}

export interface DependencyFinding {
  package: string;
  version?: string;
  ecosystem: string;
  source?: string;
  severity: string;
  confidence?: string;
  category: string;
  message: string;
  cve?: string;
  attack_type?: string;
  references?: string[];
  extra?: Record<string, string>;
}

export interface ScanDependenciesResult {
  file_path: string;
  file_size: number;
  ecosystem?: string;
  dependencies_parsed: number;
  findings: DependencyFinding[];
}

export interface DockerfileFinding {
  rule_id: string;
  severity: string;
  confidence?: string;
  title: string;
  fix?: string;
  line?: number;
  snippet?: string;
}

export interface ScanDockerfileResult {
  file_path: string;
  file_size: number;
  findings: DockerfileFinding[];
}

export interface WorkflowFinding {
  rule_id: string;
  severity: string;
  confidence?: string;
  title: string;
  rationale?: string;
  fix?: string;
  line?: number;
  snippet?: string;
}

export interface ScanGitHubActionsResult {
  file_path: string;
  file_size: number;
  findings: WorkflowFinding[];
}

export interface PolicyCheckFinding {
  rule_id: string;
  severity: string;
  confidence?: string;
  title: string;
  line?: number;
  snippet?: string;
  package?: string;
  version?: string;
}

export interface PolicyCheckResult {
  file_path: string;
  file_size: number;
  scan: string;
  severity_floor: string;
  pass: boolean;
  exit_code: number;
  findings: PolicyCheckFinding[];
  counts: Record<string, number>;
}

// A normalized, source-agnostic finding the diagnostics and tree
// layers consume. Every scanner result is flattened into this shape.
export interface NormalizedFinding {
  filePath: string;
  ruleId: string;
  severity: string;
  title: string;
  // 1-based line when the scanner reports one; undefined otherwise.
  line?: number;
  // Byte offsets into the file, when the scanner reports them
  // (secret scanner only).
  start?: number;
  end?: number;
  snippet?: string;
  knownFalsePositive?: boolean;
}
