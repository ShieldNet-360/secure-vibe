// Package tools — project-scoped scanners introduced in v3 of the MCP
// server (Priority 3 of the SecureVibe rollout). The handlers in
// this file extend the dependency / secret coverage from "answer a
// single question about a single package or string" to "scan a
// project artifact (lockfile, workflow, Dockerfile) and return every
// applicable finding". The shared output shape is SARIF 2.1.0 so the
// MCP server can feed straight into a CI gate via `policy_check`.
//
// No new disk-access policy is introduced: every reader funnels
// through l.validateScanPath, so the same allowed-roots /
// sensitive-paths deny-list and absolute-path requirement that
// applies to scan_secrets also applies to the new scan_*.
package tools

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/shieldnet-360/secure-vibe/internal/skill"
	"github.com/shieldnet-360/secure-vibe/internal/tools/parsers"
)

// readScanFile is the shared on-disk read path for every new scanner.
// It enforces the same allowed-roots / sensitive-paths policy as
// ScanSecrets and the same 10 MiB cap, but returns errors prefixed
// with the supplied op name so a caller can tell which tool failed.
func (l *Library) readScanFile(op, filePath string) ([]byte, int64, error) {
	if err := l.validateScanPath(filePath); err != nil {
		// validateScanPath always prefixes "scan_secrets:" — rewrite
		// the prefix so the caller sees an error that matches the
		// tool they actually invoked.
		msg := strings.TrimPrefix(err.Error(), "scan_secrets:")
		return nil, 0, fmt.Errorf("%s:%s", op, msg)
	}
	st, err := os.Stat(filePath)
	if err != nil {
		return nil, 0, fmt.Errorf("%s: stat %s: %w", op, filePath, err)
	}
	if st.IsDir() {
		return nil, 0, fmt.Errorf("%s: %s is a directory", op, filePath)
	}
	if st.Size() > maxFileScanBytes {
		return nil, 0, fmt.Errorf("%s: %s is %d bytes; limit is %d", op, filePath, st.Size(), maxFileScanBytes)
	}
	f, err := os.Open(filePath)
	if err != nil {
		return nil, 0, fmt.Errorf("%s: open %s: %w", op, filePath, err)
	}
	defer f.Close()
	body, err := io.ReadAll(io.LimitReader(f, maxFileScanBytes+1))
	if err != nil {
		return nil, 0, fmt.Errorf("%s: read %s: %w", op, filePath, err)
	}
	if int64(len(body)) > maxFileScanBytes {
		return nil, 0, fmt.Errorf("%s: %s exceeded %d-byte limit during read", op, filePath, maxFileScanBytes)
	}
	return body, int64(len(body)), nil
}

// DependencyFinding is one row of the scan_dependencies output. It
// flattens the existing CheckDependencyResult shape down to "one
// finding per match" so that a SARIF run gets one Result per row.
//
// Confidence is a four-band qualitative signal describing how sure
// the scanner is that the finding applies to the resolved dependency.
// The bands are:
//
//   - "confirmed": curated, hand-reviewed evidence (e.g. an entry in
//     the curated malicious-packages DB with no upstream `source`),
//     or an OSV record whose version-range affected the resolved
//     version.
//   - "high":      structured database hit (OSSF malicious-packages
//     feed, curated typosquat DB, regex against
//     well-known anti-pattern in a workflow/Dockerfile)
//     where the match is unambiguous but not
//     individually reviewed.
//   - "medium":    pattern-only signal (substring CVE-name match,
//     runtime Levenshtein typosquat suggestion).
//   - "low":       weakest tier; reserved for fuzzy heuristics.
//
// An empty Confidence means the scanner did not classify the
// finding (older callers); consumers should treat the empty value
// as "high" for backwards compatibility.
type DependencyFinding struct {
	Package    string            `json:"package"`
	Version    string            `json:"version,omitempty"`
	Ecosystem  string            `json:"ecosystem"`
	Source     string            `json:"source,omitempty"`
	Severity   string            `json:"severity"`
	Confidence string            `json:"confidence,omitempty"`
	Category   string            `json:"category"`
	Message    string            `json:"message"`
	CVE        string            `json:"cve,omitempty"`
	AttackType string            `json:"attack_type,omitempty"`
	References []string          `json:"references,omitempty"`
	Extra      map[string]string `json:"extra,omitempty"`
}

// ScanDependenciesResult is what the scan_dependencies tool returns.
type ScanDependenciesResult struct {
	FilePath     string              `json:"file_path"`
	FileSize     int64               `json:"file_size"`
	Ecosystem    string              `json:"ecosystem,omitempty"`
	Dependencies int                 `json:"dependencies_parsed"`
	Findings     []DependencyFinding `json:"findings"`
}

// ScanDependencies parses the lockfile at filePath, walks every
// resolved (name, version, ecosystem) tuple, and checks each against
// the existing malicious-packages DB, typosquat DB, and CVE-pattern
// list. A clean lockfile returns Findings=[] (never nil) so SARIF
// output stays a valid 2.1.0 document.
func (l *Library) ScanDependencies(filePath string) (*ScanDependenciesResult, error) {
	const op = "scan_dependencies"
	body, size, err := l.readScanFile(op, filePath)
	if err != nil {
		return nil, err
	}
	deps, err := parsers.Parse(filePath, body)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	out := &ScanDependenciesResult{
		FilePath:     filePath,
		FileSize:     size,
		Dependencies: len(deps),
		Findings:     []DependencyFinding{},
	}
	if len(deps) > 0 {
		out.Ecosystem = deps[0].Ecosystem
	}
	for _, dep := range deps {
		inner, err := l.CheckDependency(dep.Name, dep.Version, dep.Ecosystem)
		if err != nil {
			// A single bad ecosystem shouldn't blow up the whole
			// scan; record it as a finding and continue.
			out.Findings = append(out.Findings, DependencyFinding{
				Package:   dep.Name,
				Version:   dep.Version,
				Ecosystem: dep.Ecosystem,
				Source:    dep.Source,
				Severity:  "info",
				Category:  "scan-error",
				Message:   err.Error(),
			})
			continue
		}
		for _, m := range inner.Malicious {
			sev := strings.ToLower(strings.TrimSpace(m.Severity))
			if sev == "" {
				sev = "high"
			}
			// Curated rows (no upstream `source`) have been hand-reviewed
			// against the upstream advisory and the affected version
			// list; treat those as "confirmed". Rows imported from the
			// OSSF malicious-packages feed are structured and reliable
			// but not individually triaged — emit "high" so a downstream
			// gate can choose to drop the floor by one notch if it
			// wants curated-only enforcement.
			conf := "confirmed"
			switch strings.TrimSpace(m.Source) {
			case "ossf-malicious-packages":
				conf = "high"
			case OverlaySource:
				// User-asserted via the local contribution overlay — a
				// real, enforced block, but not centrally reviewed canon.
				conf = "high"
			}
			out.Findings = append(out.Findings, DependencyFinding{
				Package:    dep.Name,
				Version:    dep.Version,
				Ecosystem:  dep.Ecosystem,
				Source:     dep.Source,
				Severity:   sev,
				Confidence: conf,
				Category:   "malicious-package",
				Message:    fmt.Sprintf("%s flagged as %s: %s", m.Name, m.Type, m.Description),
				CVE:        m.CVE,
				AttackType: m.AttackType,
				References: m.References,
			})
		}
		for _, t := range inner.Typosquats {
			// Typosquat rows come from the curated
			// typosquat-db/known_typosquats.json file. Every entry
			// names a known-good target and a known-bad squat that
			// has already been validated by a human reviewer, so the
			// match here is structural, not heuristic — "high".
			//
			// CheckTyposquat matches an entry from EITHER side (so the
			// interactive tool can answer "does X have known squats?"),
			// but for a lockfile scan only the squat side is a finding:
			// depending on the legitimate TARGET of someone else's
			// squat (lodash, when lodahs→lodash is in the DB) is not a
			// vulnerability in this dependency tree.
			if !strings.EqualFold(t.Typosquat, dep.Name) {
				continue
			}
			out.Findings = append(out.Findings, DependencyFinding{
				Package:    dep.Name,
				Version:    dep.Version,
				Ecosystem:  dep.Ecosystem,
				Source:     dep.Source,
				Severity:   "medium",
				Confidence: "high",
				Category:   "typosquat",
				Message:    fmt.Sprintf("%s squats %s (Levenshtein distance %d)", t.Typosquat, t.Target, t.LevenshteinDistance),
				Extra: map[string]string{
					"target":               t.Target,
					"typosquat":            t.Typosquat,
					"levenshtein_distance": fmt.Sprintf("%d", t.LevenshteinDistance),
				},
			})
		}
		for _, c := range inner.CVEs {
			sev := strings.ToLower(strings.TrimSpace(c.Severity))
			if sev == "" {
				sev = "medium"
			}
			// CVE-pattern matches are substring hits against the
			// curated CVE name/description; the underlying patterns
			// describe code shapes, not pinned versions, so a hit
			// against a package name is suggestive rather than
			// definitive. Emit "medium" so a strict gate can require
			// "high"+ for fail-the-build behaviour.
			out.Findings = append(out.Findings, DependencyFinding{
				Package:    dep.Name,
				Version:    dep.Version,
				Ecosystem:  dep.Ecosystem,
				Source:     dep.Source,
				Severity:   sev,
				Confidence: "medium",
				Category:   "cve-pattern",
				Message:    fmt.Sprintf("%s (%s): %s", c.CVE, c.Name, c.Description),
				CVE:        c.CVE,
				AttackType: c.AttackType,
				References: c.References,
			})
		}
		// OSV cache hits surface every advisory osv.dev knows for
		// this package, regardless of CVE alias. Severity is
		// translated from the OSV record's `severity[]` array (CVSS
		// v3.x base score) or its `database_specific.severity`
		// qualitative band (GHSA-style LOW/MODERATE/HIGH/CRITICAL),
		// with the higher-confidence database_specific signal taking
		// precedence. Records that have neither — typical of MAL-*
		// malicious-package and some RUSTSEC advisories — fall back
		// to "medium" so the finding still surfaces with a sensible
		// default instead of being dropped.
		for _, adv := range inner.OSVAdvisories {
			refs := []string{adv.Reference}
			severity := adv.Severity
			if severity == "" {
				severity = "medium"
			}
			// lookupOSV now consults each record's `affected[].ranges`
			// against the resolved version: an advisory that does not
			// cover the version is dropped before it reaches here, and
			// one that does is marked VersionConfirmed. So a confirmed
			// hit is "confirmed" (version intersects an affected range);
			// an unconfirmed hit — the version was absent, or the
			// ecosystem's range grammar was not evaluable, so the
			// advisory failed open on a name match — stays "high".
			conf := "high"
			if adv.VersionConfirmed {
				conf = "confirmed"
			}
			out.Findings = append(out.Findings, DependencyFinding{
				Package:    dep.Name,
				Version:    dep.Version,
				Ecosystem:  dep.Ecosystem,
				Source:     dep.Source,
				Severity:   severity,
				Confidence: conf,
				Category:   "osv-advisory",
				Message:    fmt.Sprintf("%s: %s", adv.ID, adv.Summary),
				References: refs,
				Extra: map[string]string{
					"osv_id":  adv.ID,
					"aliases": strings.Join(adv.Aliases, ","),
				},
			})
		}
	}
	return out, nil
}

// WorkflowFinding is one match against a hardening rule for a GitHub
// Actions workflow file.
//
// Confidence follows the same four-band scheme as DependencyFinding
// (see that type for the definition). The regex-only checklist hits
// emitted by ScanGitHubActions are "high" — the patterns target
// well-known anti-patterns (curl-pipe-sh, pull_request_target +
// checkout, missing top-level permissions). When the structured YAML
// parser becomes the primary path, those findings should be promoted
// to "confirmed".
type WorkflowFinding struct {
	RuleID     string `json:"rule_id"`
	Severity   string `json:"severity"`
	Confidence string `json:"confidence,omitempty"`
	Title      string `json:"title"`
	Rationale  string `json:"rationale,omitempty"`
	Fix        string `json:"fix,omitempty"`
	Line       int    `json:"line,omitempty"`
	Snippet    string `json:"snippet,omitempty"`
}

// ScanGitHubActionsResult is what scan_github_actions returns.
type ScanGitHubActionsResult struct {
	FilePath string            `json:"file_path"`
	FileSize int64             `json:"file_size"`
	Findings []WorkflowFinding `json:"findings"`
}

// gitHubActionsHardeningCheck mirrors one entry of
// skills/cicd-security/checklists/github_actions_hardening.yaml so the
// detection logic stays defined where the security review can keep
// editing it.
type gitHubActionsHardeningCheck struct {
	ID        string `yaml:"id"`
	Severity  string `yaml:"severity"`
	Title     string `yaml:"title"`
	Rationale string `yaml:"rationale"`
	Pattern   string `yaml:"pattern"`
	Require   string `yaml:"require"`
	Fix       string `yaml:"fix"`
}

// gitHubActionsChecks are the regex hardening rules whose detection is
// pure pattern-matching (no AST reasoning needed). Defined in Go — like
// dockerfileChecks — so the scanner contract lives in one place; their
// ids trace to the `<!-- pattern: { check: deterministic } -->` markers
// in cicd-security/SKILL.md. Rules that need structure (action pinning,
// pwn-request, expression injection) are handled by the AST pass with
// the same canonical ids and are intentionally NOT duplicated here.
var gitHubActionsChecks = []gitHubActionsHardeningCheck{
	{
		ID:        "gha-default-permissions-read",
		Severity:  "high",
		Title:     "Default `permissions:` to read-only at the workflow level",
		Rationale: "The default GitHub token has write access to many APIs. Setting workflow-level `permissions: { contents: read }` and granting job-level write selectively reduces blast radius.",
		Pattern:   `^on:[\s\S]+?\njobs:`,
		Require:   `permissions:\s*\n\s*contents:\s*read`,
		Fix:       "Add a top-level `permissions: { contents: read }` and grant write scopes per-job.",
	},
	{
		ID:        "gha-oidc-cloud-credentials",
		Severity:  "high",
		Title:     "Use OIDC for cloud credentials, not stored long-lived keys",
		Rationale: "Short-lived OIDC tokens cannot be replayed. Stored AWS/GCP/Azure keys in GitHub Secrets have been the source of major CI cloud-key exfiltration incidents.",
		Pattern:   `secrets\.(AWS_SECRET_ACCESS_KEY|GCP_SA_KEY|AZURE_CLIENT_SECRET)`,
		Fix:       "Add `permissions.id-token: write` and use the cloud's OIDC action with role-to-assume.",
	},
	{
		ID:        "gha-no-curl-pipe-bash",
		Severity:  "critical",
		Title:     "Never `curl | bash` in CI",
		Rationale: "Codecov bash-uploader 2021 (CVE-2021-32699) exfiltrated env vars for ~10 weeks via a remote-script substitution attack.",
		Pattern:   `(curl|wget)[^|\n]*\|\s*(ba)?sh`,
		Fix:       "Download, verify a known SHA-256, then execute. Prefer a vendor-supplied binary or container image.",
	},
	{
		// Regex, not AST: the regex reliably catches an untrusted
		// expression anywhere in a `run:` body (PR title, issue body,
		// head ref…); the structured AST check missed cases the regex
		// caught, so this is the canonical detector. `run:`-anchored, so
		// the scanner evaluates it per step chunk.
		ID:        "gha-no-untrusted-script-injection",
		Severity:  "critical",
		Title:     "Untrusted github.event expression interpolated into `run:`",
		Rationale: "`run: echo \"${{ github.event.pull_request.title }}\"` is a shell-injection sink. Route the value through an `env:` variable and reference it as $VAR.",
		Pattern:   `run:[\s\S]+?\$\{\{\s*github\.(event\.[a-z_.]+|head_ref\b)`,
		Fix:       "Bind the expression to env: NAME: ${{ ... }} and use \"$NAME\" inside the run body.",
	},
	{
		ID:        "gha-cache-key-scope",
		Severity:  "medium",
		Title:     "Cache keys must include a lockfile hash, not just `os`",
		Rationale: "Loose cache keys allow cross-tenant / cross-branch cache reuse — build-cache poisoning works through unscoped reuse.",
		Pattern:   `cache@[\s\S]+?key:\s*\$\{\{\s*runner\.os\s*\}\}`,
		Require:   `hashFiles\(`,
		Fix:       "Include `hashFiles('**/lockfile')` in the cache key.",
	},
	{
		ID:        "gha-artifact-verify-source",
		Severity:  "medium",
		Title:     "Verify provenance before downloading artifacts from other workflows",
		Rationale: "`actions/download-artifact` from arbitrary workflow runs can be tricked into pulling attacker-controlled artifacts.",
		Pattern:   `download-artifact@[\s\S]+?workflow:\s*[a-zA-Z0-9_-]+`,
		Fix:       "Pin both the source workflow file and commit SHA, and verify a SLSA provenance attestation before extraction.",
	},
}

// loadGitHubActionsChecks returns the in-Go regex hardening rules. Kept
// as a method returning (slice, error) to preserve the call site; the
// error is always nil now that the rules no longer come from disk.
func (l *Library) loadGitHubActionsChecks() ([]gitHubActionsHardeningCheck, error) {
	return gitHubActionsChecks, nil
}

// GitHubActionsRuleIDs returns the full set of rule ids the GHA scanner
// can emit: the in-Go regex checks (gitHubActionsChecks) plus the
// AST-only checks. Single source of truth for the trace test and the
// `coverage` command — mirrors DockerfileRuleIDs.
func GitHubActionsRuleIDs() map[string]bool {
	ids := map[string]bool{
		// Emitted by the AST pass, not gitHubActionsChecks.
		"gha-pin-actions-by-sha":              true,
		"gha-pr-target-no-untrusted-checkout": true,
	}
	for _, c := range gitHubActionsChecks {
		ids[c.ID] = true
	}
	return ids
}

// ScanGitHubActions runs every applicable hardening check from
// skills/cicd-security/checklists/github_actions_hardening.yaml
// against the file at filePath and returns the matches.
//
// The detection logic intentionally lives in YAML so the security
// review can update it without a Go release. Each check has a
// `pattern` (must match) and optionally a `require` (a second
// expression that, when set, MUST also match the body — used for
// "you have an `on:` block but no `permissions: contents: read`"
// style rules).
func (l *Library) ScanGitHubActions(filePath string) (*ScanGitHubActionsResult, error) {
	const op = "scan_github_actions"
	body, size, err := l.readScanFile(op, filePath)
	if err != nil {
		return nil, err
	}
	checks, err := l.loadGitHubActionsChecks()
	if err != nil {
		return nil, err
	}
	out := &ScanGitHubActionsResult{
		FilePath: filePath,
		FileSize: size,
		Findings: []WorkflowFinding{},
	}
	// Blank YAML comment text before the regex pass (offsets and line
	// numbers are preserved). Several checklist patterns use `[\s\S]+?`
	// to reach from an anchor (`run:`, `curl`) to a sink (`${{ … }}`,
	// `| sh`); without this, a workflow's own explanatory comment that
	// merely *mentions* the anchor becomes a false start point — the
	// match then either fires on the comment or spans newlines from it
	// down to the real sink and mis-locates the finding. Stripping the
	// comment text (to spaces) removes those false anchors while leaving
	// every executable line, and therefore every real finding, intact.
	text := blankYAMLComments(string(body))
	for _, c := range checks {
		if c.Pattern == "" {
			continue
		}
		pat, err := regexp.Compile("(?m)" + c.Pattern)
		if err != nil {
			continue
		}
		// "require" rules invert: the finding fires when the
		// surrounding section matches `pattern` but the body does
		// NOT contain `require`.
		if c.Require != "" {
			req, err := regexp.Compile("(?m)" + c.Require)
			if err != nil {
				continue
			}
			if pat.MatchString(text) && !req.MatchString(text) {
				out.Findings = append(out.Findings, WorkflowFinding{
					RuleID:     c.ID,
					Severity:   c.Severity,
					Confidence: "high",
					Title:      c.Title,
					Rationale:  collapseWS(c.Rationale),
					Fix:        collapseWS(c.Fix),
				})
			}
			continue
		}
		// A rule anchored on `run:` describes something inside a single
		// step's script. Evaluated file-wide, its `[\s\S]+?` body can
		// anchor on one step's `run:` and reach across the whole file to
		// a token in an unrelated later step — e.g. an innocent
		// `run: pip install` bridging to a much later step that safely
		// env-binds a github.event expression. Evaluate such rules per
		// step chunk so a match cannot span steps, while still catching a
		// genuine same-step injection even when an earlier innocent
		// `run:` precedes it.
		spans := [][]int{}
		if strings.HasPrefix(strings.TrimSpace(c.Pattern), "run:") {
			for _, chunk := range workflowStepChunks(text) {
				if loc := pat.FindStringIndex(text[chunk[0]:chunk[1]]); loc != nil {
					spans = append(spans, []int{chunk[0] + loc[0], chunk[0] + loc[1]})
				}
			}
		} else {
			spans = pat.FindAllStringIndex(text, -1)
		}
		for _, idx := range spans {
			line, snippet := lineInfo(text, idx[0])
			out.Findings = append(out.Findings, WorkflowFinding{
				RuleID:     c.ID,
				Severity:   c.Severity,
				Confidence: "high",
				Title:      c.Title,
				Rationale:  collapseWS(c.Rationale),
				Fix:        collapseWS(c.Fix),
				Line:       line,
				Snippet:    snippet,
			})
		}
	}

	// AST pass — structured YAML decode is the CANONICAL detector for
	// the three concepts below; the redundant regex versions were
	// removed (they double-fired, and the SHA-pin regex relied on a
	// negative lookahead Go's RE2 can't compile). These emit the clean
	// concept ids the SKILL.md markers reference:
	//
	//   * gha-pin-actions-by-sha: the regex pass cannot reliably tell
	//     a 40-char SHA pin from a version tag.
	//   * gha-pr-target-no-untrusted-checkout: pull_request_target +
	//     actions/checkout is the classic PWN-request pattern.
	//
	// (Expression-injection stays a regex check — the structured walk
	// missed cases the regex catches.)
	if wf, err := parsers.ParseWorkflow(body); err == nil && wf != nil {
		appendAstWorkflowFindings(wf, out)
	}
	return out, nil
}

// appendAstWorkflowFindings runs the structured checks on wf and
// appends each finding to out.Findings. The function is split out so
// the AST pass remains skippable on parse error (it's a strict
// addition to the regex pass, not a replacement).
func appendAstWorkflowFindings(wf *parsers.Workflow, out *ScanGitHubActionsResult) {
	prTarget := wf.IsPullRequestTarget()
	for jobName, job := range wf.Jobs {
		for _, step := range job.Steps {
			if step.Uses != "" && !parsers.IsPinnedAction(step.Uses) {
				out.Findings = append(out.Findings, WorkflowFinding{
					RuleID:     "gha-pin-actions-by-sha",
					Severity:   "high",
					Confidence: "confirmed",
					Title:      "Third-party action not pinned to a commit SHA",
					Rationale: fmt.Sprintf(
						"Job %s step uses %q. Pin to a 40-character commit SHA to defend"+
							" against tag-rewrite supply-chain attacks.",
						jobName, step.Uses,
					),
					Fix:     "Replace the @<tag> reference with @<40-char-sha>.",
					Line:    step.Line,
					Snippet: fmt.Sprintf("uses: %s", step.Uses),
				})
			}
			if prTarget && parsers.IsCheckoutAction(step.Uses) {
				out.Findings = append(out.Findings, WorkflowFinding{
					RuleID:     "gha-pr-target-no-untrusted-checkout",
					Severity:   "critical",
					Confidence: "confirmed",
					Title:      "pull_request_target combined with actions/checkout",
					Rationale: "pull_request_target runs with the base repo's secrets" +
						" while actions/checkout may fetch attacker-controlled PR head" +
						" code. The combination is the canonical PWN-request pattern.",
					Fix:     "Switch the trigger to pull_request, or pin checkout to the merge ref and never run attacker-supplied code.",
					Line:    step.Line,
					Snippet: fmt.Sprintf("uses: %s (job %q)", step.Uses, jobName),
				})
			}
			// Expression-injection is detected by the regex check
			// gha-no-untrusted-script-injection (in gitHubActionsChecks):
			// it catches untrusted ${{ github.event… }} in a run: body
			// more broadly than the structured walk did.
		}
	}
}

// truncateSnippet collapses runs of whitespace and clips the result
// to n runes so a joined-line Dockerfile snippet stays readable in
// scanner output.
func truncateSnippet(s string, n int) string {
	out := collapseWS(s)
	if len([]rune(out)) <= n {
		return out
	}
	r := []rune(out)
	return string(r[:n]) + "…"
}

// DockerfileFinding is one match against a Dockerfile hardening rule.
//
// Confidence follows the same four-band scheme as DependencyFinding.
// The regex-only checks emitted by ScanDockerfile are "high" — each
// pattern targets a specific Dockerfile token (FROM, USER, ENV/ARG,
// ADD, RUN curl|sh, apt-get install). When the multi-stage-aware AST
// parser becomes the primary path, AST-confirmed findings can be
// promoted to "confirmed".
type DockerfileFinding struct {
	RuleID     string `json:"rule_id"`
	Severity   string `json:"severity"`
	Confidence string `json:"confidence,omitempty"`
	Title      string `json:"title"`
	Fix        string `json:"fix,omitempty"`
	Line       int    `json:"line"`
	Snippet    string `json:"snippet"`
}

// ScanDockerfileResult is what scan_dockerfile returns.
type ScanDockerfileResult struct {
	FilePath string              `json:"file_path"`
	FileSize int64               `json:"file_size"`
	Findings []DockerfileFinding `json:"findings"`
}

// dockerfileCheck describes one inline rule used by ScanDockerfile.
// Defined as Go (not YAML) because the patterns reach into raw
// Dockerfile syntax that the checklist YAML deliberately keeps
// human-readable; mixing them would lose the explanatory value of
// the existing dockerfile_hardening.yaml. The IDs match the YAML
// where possible so consumers can join the two surfaces.
type dockerfileCheck struct {
	id       string
	severity string
	title    string
	fix      string
	// pattern matches an offending line. The check is line-oriented
	// so the regex sees one line at a time, simplifying both the
	// pattern and the reported line number.
	pattern *regexp.Regexp
}

var dockerfileChecks = []dockerfileCheck{
	{
		id:       "dkr-pinned-base-digest",
		severity: "high",
		title:    "FROM image is not pinned by tag or digest",
		fix:      "Pin the final FROM to `image:<tag>@sha256:<digest>` or at least an immutable tag.",
		// FROM image (with optional `AS stage`) where the image has
		// no tag and no digest. We also catch :latest explicitly.
		pattern: regexp.MustCompile(`(?im)^\s*FROM\s+(?:--platform=\S+\s+)?([A-Za-z0-9._/-]+)(?::latest\b)?(?:\s+AS\s+\S+)?\s*$`),
	},
	{
		id:       "dkr-explicit-latest-tag",
		severity: "high",
		title:    "FROM uses :latest tag",
		fix:      "Replace :latest with an explicit tag (and ideally pin to @sha256:<digest>).",
		pattern:  regexp.MustCompile(`(?im)^\s*FROM\s+\S+:latest\b`),
	},
	{
		id:       "dkr-non-root-user",
		severity: "critical",
		title:    "Final USER is root (explicit or implicit)",
		fix:      "Add `USER <non-root-uid>` near the end of the Dockerfile (uid >= 10000 satisfies K8s runAsNonRoot).",
		pattern:  regexp.MustCompile(`(?im)^\s*USER\s+(?:0|root)\b`),
	},
	{
		id:       "dkr-no-secrets-in-env",
		severity: "critical",
		title:    "ENV or ARG appears to embed a secret",
		fix:      "Use `RUN --mount=type=secret,id=<name>` or runtime injection — never bake credentials into image layers.",
		pattern:  regexp.MustCompile(`(?im)^\s*(?:ENV|ARG)\s+\S*(?:PASSWORD|SECRET|TOKEN|API[_-]?KEY|PRIVATE[_-]?KEY)\S*\s*=`),
	},
	{
		id:       "dkr-no-add-remote",
		severity: "medium",
		title:    "ADD fetches a remote URL",
		fix:      "Replace `ADD https://...` with `RUN curl --fail ...` plus a checksum verification step.",
		pattern:  regexp.MustCompile(`(?im)^\s*ADD\s+https?://`),
	},
	{
		id:       "dkr-no-curl-pipe-sh",
		severity: "critical",
		title:    "Build executes `curl | sh` / `wget -O- | sh`",
		fix:      "Download, verify a known SHA-256, then execute. Prefer a vendor-supplied binary or container image.",
		pattern:  regexp.MustCompile(`(?im)(?:curl|wget)\s+[^|]*\|\s*(?:ba)?sh\b`),
	},
	{
		id:       "dkr-apt-version-pin",
		severity: "medium",
		title:    "apt-get install without version pins",
		fix:      "Pin every package: `apt-get install -y --no-install-recommends pkg=1.2.3-4`.",
		// apt-get install line that is NOT a pin (no = inside the
		// package list).  Crude but covers the typical case.
		pattern: regexp.MustCompile(`(?im)apt-get\s+install\s+(?:-[A-Za-z]+\s+)*[A-Za-z0-9][A-Za-z0-9._+-]*(?:\s+[A-Za-z0-9][A-Za-z0-9._+-]*)*\s*$`),
	},
	{
		id:       "dkr-npm-install-not-ci",
		severity: "medium",
		title:    "Uses `npm install` instead of `npm ci` in a container build",
		fix:      "Use `npm ci` (or `pnpm/yarn install --frozen-lockfile`) for a reproducible, lockfile-faithful install.",
		// `npm/pnpm/yarn install` in a RUN. A `--frozen-lockfile` flag on
		// the line clears the finding (handled in ScanDockerfile); plain
		// `npm install` has no frozen equivalent (the fix is `npm ci`).
		pattern: regexp.MustCompile(`(?im)\b(?:npm|pnpm|yarn)\s+install\b`),
	},
}

// DockerfileRuleIDs returns the full set of rule ids the dockerfile
// scanner can emit: the inline regex checks (dockerfileChecks) plus the
// AST-only checks that live in ScanDockerfile but not in that slice.
// It is the single source of truth for "what the gate deterministically
// enforces" — consumed by the trace test and the `coverage` command.
func DockerfileRuleIDs() map[string]bool {
	ids := map[string]bool{
		// Emitted by the AST pass in ScanDockerfile, not dockerfileChecks.
		"dkr-missing-user-directive": true,
	}
	for _, c := range dockerfileChecks {
		ids[c.id] = true
	}
	return ids
}

// ScanDockerfile runs the inline dockerfileChecks against filePath
// and returns the findings. The rules are deliberately Go-side: they
// reference Dockerfile-specific tokens (FROM, USER, ADD, ENV, ARG,
// RUN) that the broader hardening YAML keeps human-readable.
//
// The scanner runs an AST pass first (via parsers.ParseDockerfile)
// to identify the final stage so multi-stage rules — USER and FROM
// pinning — only fire on the published image. The AST pass also
// resolves ARG-substituted FROM base images so `ARG B=node:latest`
// + `FROM $B` is still flagged. AST-confirmed findings carry
// confidence "confirmed"; the remaining regex checks (which fire
// per-line and can't reason about stages or ARG substitution)
// stay at "high".
func (l *Library) ScanDockerfile(filePath string) (*ScanDockerfileResult, error) {
	const op = "scan_dockerfile"
	body, size, err := l.readScanFile(op, filePath)
	if err != nil {
		return nil, err
	}
	out := &ScanDockerfileResult{
		FilePath: filePath,
		FileSize: size,
		Findings: []DockerfileFinding{},
	}

	ast := parsers.ParseDockerfile(body)
	finalIdx := -1
	if final := ast.FinalStage(); final != nil {
		finalIdx = final.Index
	}
	stageOf := buildDockerfileStageIndex(ast)

	// stageSensitive rules only fire on the final stage. The other
	// rules describe per-layer issues (secrets in env, ADD remote,
	// curl-pipe-sh, apt without pins) and remain per-line.
	stageSensitive := map[string]bool{
		"dkr-pinned-base-digest":  true,
		"dkr-explicit-latest-tag": true,
		"dkr-non-root-user":       true,
	}
	// flagged tracks which (line, rule) pairs we've already emitted
	// so the AST pass below does not double-emit a finding that
	// already fired via the regex pass.
	flagged := map[string]bool{}

	lines := strings.Split(string(body), "\n")
	for i, raw := range lines {
		// Strip trailing CR so the snippet is portable across LF /
		// CRLF input.
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		for _, c := range dockerfileChecks {
			if !c.pattern.MatchString(line) {
				continue
			}
			if stageSensitive[c.id] && finalIdx >= 0 {
				if stage := stageOf(i + 1); stage != finalIdx {
					continue
				}
			}
			// dkr-pinned-base-digest's intent is "no tag and no
			// digest". Skip the rule when the line already pins to
			// a digest or to an explicit non-latest tag.
			if c.id == "dkr-pinned-base-digest" {
				if strings.Contains(line, "@sha256:") {
					continue
				}
				// Has a colon for tag, other than :latest.
				if strings.Contains(line, ":") && !strings.Contains(strings.ToLower(line), ":latest") {
					// Tag is present and not :latest — accept.
					if !looksLikeUntaggedFROM(line) {
						continue
					}
				}
			}
			// `pnpm/yarn install --frozen-lockfile` is the correct,
			// reproducible form — don't flag it as npm-install-not-ci.
			if c.id == "dkr-npm-install-not-ci" && strings.Contains(line, "--frozen-lockfile") {
				continue
			}
			out.Findings = append(out.Findings, DockerfileFinding{
				RuleID:     c.id,
				Severity:   c.severity,
				Confidence: "high",
				Title:      c.title,
				Fix:        c.fix,
				Line:       i + 1,
				Snippet:    trimmed,
			})
			flagged[fmt.Sprintf("%d:%s", i+1, c.id)] = true
		}
	}

	// Joined-line pass: re-run the multi-line-sensitive rules
	// (curl-pipe-sh, apt-get-no-pin) against the AST's joined view
	// so a `curl … \ | sh \` split across backslash continuations
	// is still caught. Per-source-line findings from the regex pass
	// already populate `flagged`, so this pass only ADDS findings
	// the regex layer missed.
	joinedRules := map[string]int{
		"dkr-no-curl-pipe-sh": 0,
		"dkr-apt-version-pin": 0,
	}
	for _, ln := range ast.Lines {
		for _, c := range dockerfileChecks {
			if _, ok := joinedRules[c.id]; !ok {
				continue
			}
			if !c.pattern.MatchString(ln.Text) {
				continue
			}
			key := fmt.Sprintf("%d:%s", ln.StartLine, c.id)
			if flagged[key] {
				continue
			}
			// The joined view sometimes folds the offending RUN onto
			// a deeper line than the source's first hit; mark every
			// source line between StartLine and the next directive
			// as flagged to avoid double-reporting on the source-line
			// pass that runs first. In practice flagged[key] above
			// already covers that case, and we lean on the AST
			// confidence to signal "this came from the joined view".
			out.Findings = append(out.Findings, DockerfileFinding{
				RuleID:     c.id,
				Severity:   c.severity,
				Confidence: "confirmed",
				Title:      c.title,
				Fix:        c.fix,
				Line:       ln.StartLine,
				Snippet:    truncateSnippet(ln.Text, 240),
			})
			flagged[key] = true
		}
	}

	// AST-aware pass: catch findings the regex layer missed because
	// the base image is hidden behind an ARG reference, or because
	// the final stage inherits a root USER from its base image.
	if final := ast.FinalStage(); final != nil {
		resolved := strings.TrimSpace(final.ResolvedBase)
		if resolved == "" {
			resolved = final.BaseImage
		}
		lowered := strings.ToLower(resolved)
		hasLatest := strings.HasSuffix(lowered, ":latest") || strings.Contains(lowered, ":latest ")
		hasDigest := strings.Contains(resolved, "@sha256:")
		hasTag := strings.Contains(strings.Split(resolved, "@")[0], ":")
		snippet := strings.TrimSpace(lookupRawLine(lines, final.Line))
		key := func(rule string) string { return fmt.Sprintf("%d:%s", final.Line, rule) }
		if hasLatest && !flagged[key("dkr-explicit-latest-tag")] {
			out.Findings = append(out.Findings, DockerfileFinding{
				RuleID:     "dkr-explicit-latest-tag",
				Severity:   "high",
				Confidence: "confirmed",
				Title:      "FROM resolves to a :latest tag (ARG-substituted)",
				Fix:        "Replace :latest with an explicit tag (and ideally pin to @sha256:<digest>).",
				Line:       final.Line,
				Snippet:    snippet,
			})
			flagged[key("dkr-explicit-latest-tag")] = true
		}
		if !hasDigest && !hasTag && !flagged[key("dkr-pinned-base-digest")] {
			out.Findings = append(out.Findings, DockerfileFinding{
				RuleID:     "dkr-pinned-base-digest",
				Severity:   "high",
				Confidence: "confirmed",
				Title:      "FROM resolves to an untagged image (ARG-substituted)",
				Fix:        "Pin the final FROM to `image:<tag>@sha256:<digest>` or at least an immutable tag.",
				Line:       final.Line,
				Snippet:    snippet,
			})
			flagged[key("dkr-pinned-base-digest")] = true
		}
		// Final stage sets no USER at all → implicit root. The regex
		// rule dkr-non-root-user only catches an explicit `USER root`;
		// this AST check catches the (more common) total omission.
		if strings.TrimSpace(final.FinalUser) == "" && !flagged[key("dkr-missing-user-directive")] {
			out.Findings = append(out.Findings, DockerfileFinding{
				RuleID:     "dkr-missing-user-directive",
				Severity:   "critical",
				Confidence: "confirmed",
				Title:      "Final stage sets no USER — container runs as root by default",
				Fix:        "Add `USER <non-root-uid>` (uid >= 10000) near the end of the final stage.",
				Line:       final.Line,
				Snippet:    snippet,
			})
			flagged[key("dkr-missing-user-directive")] = true
		}
	}
	return out, nil
}

// buildDockerfileStageIndex returns a closure that maps a 1-based
// source line number to the AST stage index it belongs to. Lines
// that precede the first FROM return -1.
func buildDockerfileStageIndex(df *parsers.Dockerfile) func(int) int {
	if df == nil || len(df.Lines) == 0 {
		return func(int) int { return -1 }
	}
	return func(line int) int {
		stage := -1
		for _, l := range df.Lines {
			if l.StartLine > line {
				break
			}
			stage = l.Stage
		}
		return stage
	}
}

// lookupRawLine returns lines[idx-1] when idx is in range, or "".
// Used to surface the original source line as a finding snippet.
func lookupRawLine(lines []string, idx int) string {
	if idx <= 0 || idx > len(lines) {
		return ""
	}
	return strings.TrimRight(lines[idx-1], "\r")
}

// looksLikeUntaggedFROM returns true if a FROM line has no `:` after
// the image name. Used to disambiguate `FROM golang:1.22` (tagged,
// accept) from `FROM golang` (untagged, flag).
func looksLikeUntaggedFROM(line string) bool {
	fields := strings.Fields(strings.TrimSpace(line))
	for i, f := range fields {
		if i == 0 {
			continue
		}
		if strings.HasPrefix(f, "--platform=") {
			continue
		}
		// First non-flag token after FROM is the image.
		return !strings.Contains(f, ":") && !strings.Contains(f, "@sha256:")
	}
	return false
}

// ExplainFindingResult is what explain_finding returns.
type ExplainFindingResult struct {
	Query   string            `json:"query"`
	CWE     string            `json:"cwe,omitempty"`
	CVE     string            `json:"cve,omitempty"`
	Skills  []ExplainSkillHit `json:"skills"`
	Vulns   []ExplainVulnHit  `json:"vulns,omitempty"`
	Sources []string          `json:"sources,omitempty"`
}

// ExplainSkillHit is one skill that the query matched. The Excerpt
// is the always/never block extracted by the existing GetSkill
// machinery; the caller can pull the full body via get_skill if
// needed.
type ExplainSkillHit struct {
	SkillID  string `json:"skill_id"`
	Title    string `json:"title"`
	Category string `json:"category,omitempty"`
	Severity string `json:"severity,omitempty"`
	Excerpt  string `json:"excerpt,omitempty"`
	Why      string `json:"why,omitempty"`
}

// ExplainVulnHit is one CVE-pattern row that the query referenced
// directly.
type ExplainVulnHit struct {
	CVE         string   `json:"cve"`
	Name        string   `json:"name"`
	Severity    string   `json:"severity,omitempty"`
	Description string   `json:"description,omitempty"`
	References  []string `json:"references,omitempty"`
}

var (
	cweIDPattern = regexp.MustCompile(`(?i)\bCWE[-\s]?(\d{1,5})\b`)
	cveIDPattern = regexp.MustCompile(`(?i)\bCVE[-\s]?(\d{4})[-\s]?(\d{4,7})\b`)
)

// ExplainFinding takes a free-form query (a CWE ID, a CVE ID, or a
// short finding description) and returns the matching skills and
// vulnerability rows. Unlike search_skills, the search reaches into
// the skill body (ALWAYS/NEVER bullets), the `cwe:` frontmatter
// field, and the CVE-pattern database so a SAST/SCA finding can be
// mapped back to remediation guidance in one call.
func (l *Library) ExplainFinding(query string) (*ExplainFindingResult, error) {
	q := strings.TrimSpace(query)
	if q == "" {
		return nil, fmt.Errorf("explain_finding: query is required")
	}
	out := &ExplainFindingResult{Query: q, Skills: []ExplainSkillHit{}}
	// CWE / CVE normalisation.
	if m := cweIDPattern.FindStringSubmatch(q); m != nil {
		out.CWE = "CWE-" + m[1]
	}
	if m := cveIDPattern.FindStringSubmatch(q); m != nil {
		out.CVE = fmt.Sprintf("CVE-%s-%s", m[1], m[2])
	}
	skills, err := l.loadSkills()
	if err != nil {
		return nil, fmt.Errorf("explain_finding: %w", err)
	}
	needle := strings.ToLower(q)
	for _, s := range skills {
		body := skillBodyText(s)
		matched := false
		why := ""
		if out.CWE != "" {
			// Skills carry CWE refs in their body text (in the
			// References block or as inline citations), not in
			// frontmatter. A literal "CWE-NN" substring match is the
			// safest cross-skill lookup.
			if strings.Contains(strings.ToUpper(body), strings.ToUpper(out.CWE)) {
				matched = true
				why = "matches " + out.CWE + " in skill body"
			}
		}
		if !matched {
			hay := strings.ToLower(
				s.Frontmatter.ID + " " +
					s.Frontmatter.Title + " " +
					s.Frontmatter.Description + " " +
					strings.Join(s.Frontmatter.AppliesTo, " ") + " " +
					body,
			)
			if strings.Contains(hay, needle) {
				matched = true
				why = "substring match in skill body or metadata"
			}
		}
		if !matched {
			continue
		}
		out.Skills = append(out.Skills, ExplainSkillHit{
			SkillID:  s.Frontmatter.ID,
			Title:    s.Frontmatter.Title,
			Category: s.Frontmatter.Category,
			Severity: s.Frontmatter.Severity,
			Excerpt:  excerpt(body, 400),
			Why:      why,
		})
	}
	// CVE-pattern matches: walk the same vulnerability cache used by
	// CheckDependency. We surface a vuln row whenever the query
	// matches the CVE name, description, or — when normalised — the
	// CVE ID itself.
	if cve, err := l.loadCVEPatterns(); err == nil {
		for _, entry := range cve.Entries {
			hay := strings.ToLower(entry.CVE + " " + entry.Name + " " + entry.Description)
			match := false
			if out.CVE != "" && strings.EqualFold(entry.CVE, out.CVE) {
				match = true
			} else if strings.Contains(hay, needle) {
				match = true
			}
			if !match {
				continue
			}
			out.Vulns = append(out.Vulns, ExplainVulnHit{
				CVE:         entry.CVE,
				Name:        entry.Name,
				Severity:    entry.Severity,
				Description: entry.Description,
				References:  entry.References,
			})
		}
	}
	sort.SliceStable(out.Skills, func(i, j int) bool {
		return out.Skills[i].SkillID < out.Skills[j].SkillID
	})
	return out, nil
}

// PolicyCheckResult is what policy_check returns. It packages every
// applicable scan output plus a CI-friendly summary so a wrapper
// script can exit non-zero on any finding at or above the configured
// severity floor.
type PolicyCheckResult struct {
	FilePath      string               `json:"file_path"`
	FileSize      int64                `json:"file_size"`
	Scan          string               `json:"scan"`
	SeverityFloor string               `json:"severity_floor"`
	Pass          bool                 `json:"pass"`
	ExitCode      int                  `json:"exit_code"`
	Findings      []PolicyCheckFinding `json:"findings"`
	Counts        map[string]int       `json:"counts"`
}

// PolicyCheckFinding is the row shape every scanner is flattened to
// so policy_check can return a single homogeneous list to its
// caller. Confidence is threaded through from the underlying scanner
// finding so a CI consumer can drop low-confidence rows or escalate
// high-confidence ones without re-running the scanner.
type PolicyCheckFinding struct {
	RuleID     string `json:"rule_id"`
	Severity   string `json:"severity"`
	Confidence string `json:"confidence,omitempty"`
	Title      string `json:"title"`
	Line       int    `json:"line,omitempty"`
	Snippet    string `json:"snippet,omitempty"`
	Package    string `json:"package,omitempty"`
	Version    string `json:"version,omitempty"`
}

// PolicyCheck dispatches to the appropriate scanner for filePath and
// returns a pass/fail summary keyed by the severity floor. An empty
// severity floor defaults to "high".
//
// The dispatch table is:
//
//	package-lock.json / package.json / yarn.lock /
//	  pnpm-lock.yaml                               -> scan_dependencies
//	Pipfile.lock / poetry.lock / requirements*.txt -> scan_dependencies
//	go.sum / Cargo.lock                            -> scan_dependencies
//	pom.xml / *.gradle.lockfile                    -> scan_dependencies
//	packages.lock.json / *.csproj / *.fsproj /
//	  *.vbproj                                     -> scan_dependencies
//	Gemfile.lock                                   -> scan_dependencies
//	composer.lock / Package.resolved /
//	  pubspec.lock                                 -> scan_dependencies
//	*.yml / *.yaml under .github/workflows/        -> scan_github_actions
//	Dockerfile / *.dockerfile                      -> scan_dockerfile
//	anything else                                  -> scan_secrets
//
// Files that match no specialised scanner fall back to a secret scan
// (a credential can live in any file), so a gate run over a mixed set
// of changed files still catches leaked secrets instead of erroring on
// every unrecognised path. Curated false positives are skipped.
func (l *Library) PolicyCheck(filePath, severityFloor string) (*PolicyCheckResult, error) {
	if strings.TrimSpace(filePath) == "" {
		return nil, fmt.Errorf("gate: file_path is required")
	}
	floor := strings.ToLower(strings.TrimSpace(severityFloor))
	if floor == "" {
		floor = "high"
	}
	if !knownSeverity(floor) {
		return nil, fmt.Errorf("gate: unknown severity %q; want one of critical|high|medium|low|info", severityFloor)
	}
	scan, err := pickScan(filePath)
	if err != nil {
		return nil, err
	}
	out := &PolicyCheckResult{
		FilePath:      filePath,
		Scan:          scan,
		SeverityFloor: floor,
		Findings:      []PolicyCheckFinding{},
		Counts:        map[string]int{},
	}
	switch scan {
	case "scan_dependencies":
		res, err := l.ScanDependencies(filePath)
		if err != nil {
			return nil, err
		}
		out.FileSize = res.FileSize
		for _, f := range res.Findings {
			out.Findings = append(out.Findings, PolicyCheckFinding{
				RuleID:     "secure-vibe mcp." + f.Category,
				Severity:   f.Severity,
				Confidence: f.Confidence,
				Title:      f.Message,
				Package:    f.Package,
				Version:    f.Version,
			})
		}
	case "scan_github_actions":
		res, err := l.ScanGitHubActions(filePath)
		if err != nil {
			return nil, err
		}
		out.FileSize = res.FileSize
		for _, f := range res.Findings {
			out.Findings = append(out.Findings, PolicyCheckFinding{
				RuleID:     f.RuleID,
				Severity:   f.Severity,
				Confidence: f.Confidence,
				Title:      f.Title,
				Line:       f.Line,
				Snippet:    f.Snippet,
			})
		}
	case "scan_dockerfile":
		res, err := l.ScanDockerfile(filePath)
		if err != nil {
			return nil, err
		}
		out.FileSize = res.FileSize
		for _, f := range res.Findings {
			out.Findings = append(out.Findings, PolicyCheckFinding{
				RuleID:     f.RuleID,
				Severity:   f.Severity,
				Confidence: f.Confidence,
				Title:      f.Title,
				Line:       f.Line,
				Snippet:    f.Snippet,
			})
		}
	case "scan_secrets":
		res, err := l.ScanSecrets("", filePath)
		if err != nil {
			return nil, err
		}
		out.FileSize = res.FileSize
		for _, m := range res.Matches {
			// Curated false positives (the exclusions block in
			// secret_detection.yaml) must not fail a gate.
			if m.KnownFalsePositive {
				continue
			}
			out.Findings = append(out.Findings, PolicyCheckFinding{
				RuleID:   "secure-vibe.secret." + m.Name,
				Severity: m.Severity,
				Title:    m.Name,
			})
		}
	}
	// Aggregate counts and decide pass/fail.
	out.Pass = true
	for _, f := range out.Findings {
		sev := strings.ToLower(strings.TrimSpace(f.Severity))
		if sev == "" {
			sev = "info"
		}
		out.Counts[sev]++
		if severityRank(sev) >= severityRank(floor) {
			out.Pass = false
		}
	}
	if !out.Pass {
		out.ExitCode = 1
	}
	return out, nil
}

// pickScan returns the scan name that policy_check should dispatch to
// for the given file path, or an error if no scan applies.
// gateNoiseDirs are directory names skipped when a gate argument is a
// directory: version control, dependency installs, virtualenvs, and
// build output. Walking them would (at best) waste time and (at worst)
// scan thousands of vendored files for zero signal. ".git" is matched
// exactly so ".github" — which holds the workflows we DO want to gate —
// is still traversed.
var gateNoiseDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true,
	".venv": true, "venv": true, "__pycache__": true,
	"dist": true, "build": true, "target": true,
	".next": true, ".nuxt": true, ".idea": true, ".vscode": true,
	".terraform": true, ".gradle": true, ".mvn": true,
	// SecureVibe's own config dir: the contribution overlay holds
	// base64 Ed25519 signatures that would otherwise trip the secret
	// scanner's entropy check on a `gate <dir>` walk — a self-inflicted
	// finding on our own metadata. It is consumed as config, not scanned.
	".secure-vibe": true,
}

// WalkScanFiles walks root recursively and returns the regular text
// files beneath it that keep selects, applying the filters every
// directory-mode scanner needs: gateNoiseDirs are pruned; non-regular
// entries (symlinks, sockets, devices) are skipped so the walk can't be
// redirected out of the tree; and empty, oversized (> maxFileScanBytes),
// and binary files are dropped — scan_secrets has no binary detection of
// its own and errors on oversized input, so filtering here keeps a repo
// walk fast and stops a stray image or build artefact from aborting a
// scan or spraying entropy false positives.
//
// A nil keep accepts every surviving file; pass a predicate (e.g. "is
// this a lockfile?") to narrow the set. The keep check runs before the
// size/binary I/O so a name-based predicate stays cheap. Unreadable
// entries are skipped rather than aborting the walk.
//
// This is the single walker behind `gate <dir>`, `scan-secrets <dir>`,
// and `scan-dependencies <dir>`, so all three prune the same directories
// and binaries.
func WalkScanFiles(root string, keep func(path string) bool) ([]string, error) {
	var files []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if gateNoiseDirs[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		if keep != nil && !keep(p) {
			return nil
		}
		fi, e := d.Info()
		if e != nil || fi.Size() == 0 || fi.Size() > maxFileScanBytes {
			return nil
		}
		if isProbablyBinary(p) {
			return nil
		}
		files = append(files, p)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return files, nil
}

// ExpandGateFiles flattens a mix of file and directory arguments into the
// concrete file list the gate should scan. File arguments pass through
// unchanged (so naming a file explicitly always scans it). A directory
// argument is walked via WalkScanFiles with a nil predicate: gate scans
// every text file under it, and PolicyCheck routes each to its
// specialised scanner (Dockerfile / lockfile / workflow) or to the
// secret scan. The returned list preserves argument order.
func ExpandGateFiles(args []string) ([]string, error) {
	var files []string
	for _, arg := range args {
		info, err := os.Stat(arg)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			files = append(files, arg)
			continue
		}
		found, err := WalkScanFiles(arg, nil)
		if err != nil {
			return nil, err
		}
		files = append(files, found...)
	}
	return files, nil
}

// isProbablyBinary reports whether the file at p looks binary, using the
// classic NUL-byte heuristic over the first 8 KiB. It catches images,
// fonts, and compiled artefacts — including extensionless ones an
// extension denylist would miss — so the directory-mode secret scan
// doesn't waste time or emit entropy false positives on them. A read
// error is treated as binary so an unreadable file is skipped, not
// handed to the scanner.
func isProbablyBinary(p string) bool {
	f, err := os.Open(p)
	if err != nil {
		return true
	}
	defer f.Close()
	buf := make([]byte, 8192)
	n, _ := f.Read(buf)
	return bytes.IndexByte(buf[:n], 0) >= 0
}

func pickScan(filePath string) (string, error) {
	base := filepath.Base(filePath)
	switch base {
	case "package-lock.json", "npm-shrinkwrap.json", "package.json", "yarn.lock", "pnpm-lock.yaml",
		"Pipfile.lock", "poetry.lock", "go.sum", "Cargo.lock",
		"pom.xml", "gradle.lockfile", "build.gradle.lockfile",
		"packages.lock.json", "Gemfile.lock",
		"composer.lock", "Package.resolved", "pubspec.lock":
		return "scan_dependencies", nil
	case "Dockerfile":
		return "scan_dockerfile", nil
	}
	lower := strings.ToLower(base)
	if strings.HasSuffix(lower, ".dockerfile") {
		return "scan_dockerfile", nil
	}
	if strings.HasPrefix(lower, "requirements") && strings.HasSuffix(lower, ".txt") {
		return "scan_dependencies", nil
	}
	if strings.HasSuffix(lower, ".csproj") ||
		strings.HasSuffix(lower, ".fsproj") ||
		strings.HasSuffix(lower, ".vbproj") {
		return "scan_dependencies", nil
	}
	if strings.HasSuffix(lower, ".yml") || strings.HasSuffix(lower, ".yaml") {
		clean := filepath.ToSlash(filepath.Clean(filePath))
		if strings.Contains(clean, "/.github/workflows/") {
			return "scan_github_actions", nil
		}
	}
	// No file-type-specific scanner matched. Fall back to a secret scan:
	// a credential can live in any file, so for a gate run over an
	// arbitrary set of changed files this is safer (and quieter) than
	// failing closed on every unrecognised path. Routable types above
	// still get their specialised scanner.
	return "scan_secrets", nil
}

// knownSeverity validates the severity_floor argument.
func knownSeverity(s string) bool {
	switch s {
	case "critical", "high", "medium", "low", "info":
		return true
	}
	return false
}

// severityRank maps the SARIF / secure-vibe severity vocabulary
// to a numeric scale where higher is worse.
func severityRank(s string) int {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return 4
	case "high", "error":
		return 3
	case "medium", "warning":
		return 2
	case "low":
		return 1
	}
	return 0
}

// excerpt returns the first n runes of s, with leading/trailing
// whitespace stripped and a trailing "…" when the input was longer.
func excerpt(s string, n int) string {
	s = strings.TrimSpace(s)
	if len([]rune(s)) <= n {
		return s
	}
	r := []rune(s)
	return strings.TrimSpace(string(r[:n])) + "…"
}

// collapseWS replaces runs of whitespace (including newlines from
// the source YAML's folded block scalars) with a single space.
func collapseWS(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// blankYAMLComments returns text with every YAML comment replaced by
// spaces of the same length, preserving newlines and every byte offset
// so downstream lineInfo / snippet logic stays accurate. A comment
// begins at an unquoted `#` that is at the start of the line (after
// indentation) or preceded by whitespace; quote tracking (single and
// double) keeps a `#` inside a quoted scalar from being mistaken for a
// comment. This is a lexical pass, not a full YAML parse — sufficient
// to stop comment text from acting as a regex anchor for the hardening
// checks while never touching an executable token.
func blankYAMLComments(text string) string {
	b := []byte(text)
	inSingle, inDouble := false, false
	lineStart := true // still in the leading-whitespace run of the line
	for i := 0; i < len(b); i++ {
		switch b[i] {
		case '\n':
			inSingle, inDouble = false, false
			lineStart = true
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
			lineStart = false
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
			lineStart = false
		case ' ', '\t':
			// whitespace does not end the leading-whitespace run
		case '#':
			prevWS := i == 0 || b[i-1] == ' ' || b[i-1] == '\t'
			if !inSingle && !inDouble && (lineStart || prevWS) {
				for j := i; j < len(b) && b[j] != '\n'; j++ {
					b[j] = ' '
				}
			}
			lineStart = false
		default:
			lineStart = false
		}
	}
	return string(b)
}

// workflowStepItem matches a YAML sequence item at step indentation
// (`      - name:`, `      - uses:`, `      - run:`) — the start of a
// new workflow step.
var workflowStepItem = regexp.MustCompile(`(?m)^[ \t]*-[ \t]`)

// workflowStepChunks splits text into byte ranges [start,end) delimited
// by step-sequence-item boundaries, so a per-step regex pass can't bridge
// two steps. The region before the first step item is its own chunk
// (it never holds a `run:` so it is harmless to include). Offsets are
// preserved for accurate line reporting.
func workflowStepChunks(text string) [][]int {
	bounds := workflowStepItem.FindAllStringIndex(text, -1)
	if len(bounds) == 0 {
		return [][]int{{0, len(text)}}
	}
	var chunks [][]int
	prev := 0
	for _, b := range bounds {
		if b[0] > prev {
			chunks = append(chunks, []int{prev, b[0]})
		}
		prev = b[0]
	}
	chunks = append(chunks, []int{prev, len(text)})
	return chunks
}

// lineInfo returns (1-based line number, trimmed line content) for
// the byte offset `at` inside `text`. Used by the scanners to
// surface where a regex match landed.
func lineInfo(text string, at int) (int, string) {
	if at < 0 || at > len(text) {
		return 0, ""
	}
	line := 1
	start := 0
	for i := 0; i < at; i++ {
		if text[i] == '\n' {
			line++
			start = i + 1
		}
	}
	end := strings.IndexByte(text[start:], '\n')
	var snippet string
	if end < 0 {
		snippet = text[start:]
	} else {
		snippet = text[start : start+end]
	}
	return line, strings.TrimSpace(snippet)
}

// skillBodyText collapses the parsed body subsections back into a
// single searchable blob. Used by ExplainFinding for substring /
// CWE-ID matches; the verbose `RawRules` field is intentionally
// included so anchor lines like "MITRE: CWE-77" inside ALWAYS/NEVER
// bullets are reachable.
func skillBodyText(s *skill.Skill) string {
	var parts []string
	parts = append(parts, s.Body.Title)
	parts = append(parts, s.Body.Always...)
	parts = append(parts, s.Body.Never...)
	parts = append(parts, s.Body.KnownFalsePositives...)
	parts = append(parts, s.Body.Context)
	parts = append(parts, s.Body.References)
	parts = append(parts, s.Body.RawRules)
	return strings.Join(parts, "\n")
}
