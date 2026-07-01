// SARIF 2.1.0 output for the scan_secrets and check_dependency tools.
//
// SARIF is the OASIS-standardised Static Analysis Results Interchange
// Format; CI integrations (GitHub Advanced Security, Azure DevOps,
// SonarQube, Splunk) all ingest it natively. Emitting SARIF alongside
// the existing rich JSON lets the MCP server feed scanner output into
// CI dashboards without an external converter.
//
// The shape implemented here is the subset of SARIF 2.1.0 that the
// upstream consumers we care about actually look at: a single Run
// with a Tool driver, an optional list of Rules, and per-finding
// Results with locations and free-form properties. The schema is
// stable and we encode it explicitly (rather than pulling a third-
// party library) so the on-disk format is auditable line-by-line.
//
// Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
package tools

import (
	"fmt"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
)

// SARIFVersion / SARIFSchema pin the spec revision we emit.
const (
	SARIFVersion = "2.1.0"
	SARIFSchema  = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)

// SARIFToolName is the SARIF run.tool.driver.name advertised by the
// MCP server. Kept stable so downstream filters (e.g. GitHub Advanced
// Security category filters) can pin against it.
const SARIFToolName = "secure-vibe"

// SARIFLog is the top-level SARIF document.
type SARIFLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

// SARIFRun is one analyzer invocation.
type SARIFRun struct {
	Tool    SARIFTool     `json:"tool"`
	Results []SARIFResult `json:"results"`
}

// SARIFTool wraps the analyzer's identity.
type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

// SARIFDriver describes the analyzer that produced the run.
//
// Rules deliberately omits `omitempty` so a zero-finding run still
// serialises driver.rules as `[]`, matching the shape downstream
// CI consumers (e.g. GitHub Advanced Security) expect and keeping
// ScanSecretsSARIF / CheckDependencySARIF output symmetric. All
// emitters use make([]SARIFRule, 0) or a populated slice so the
// field is never nil.
type SARIFDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []SARIFRule `json:"rules"`
}

// SARIFRule documents one detection rule. We emit one rule per
// secret-detection pattern (or per malicious-package entry) so a
// downstream UI can hyperlink the finding back to its definition.
type SARIFRule struct {
	ID               string            `json:"id"`
	Name             string            `json:"name,omitempty"`
	ShortDescription *SARIFMultiformat `json:"shortDescription,omitempty"`
	FullDescription  *SARIFMultiformat `json:"fullDescription,omitempty"`
	HelpURI          string            `json:"helpUri,omitempty"`
	Properties       map[string]any    `json:"properties,omitempty"`
	DefaultConfig    *SARIFRuleConfig  `json:"defaultConfiguration,omitempty"`
}

// SARIFRuleConfig is the run-wide default for a rule (level, rank).
type SARIFRuleConfig struct {
	Level string `json:"level,omitempty"`
}

// SARIFMultiformat carries plain-text / Markdown variants of a
// human-readable description.
//
// Text deliberately omits `omitempty`. SARIF 2.1.0 §3.11.11 requires
// a `message` object to have at least `text` or `id`; since we never
// emit `id`, the `text` key must always be present even when empty.
// All current call sites populate it via fmt.Sprintf with a non-empty
// format, but the tag was a foot-gun: a future code path passing an
// empty string would otherwise produce invalid SARIF that GitHub
// Advanced Security rejects on ingest. Markdown stays omitempty
// because the spec lists it as optional.
type SARIFMultiformat struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown,omitempty"`
}

// SARIFResult is one finding.
//
// RuleIndex deliberately omits `omitempty`: SARIF treats ruleIndex=0
// as "the first rule in tool.driver.rules" (a valid, distinct value
// from "unset"), and Go's `omitempty` on int would silently drop
// every finding whose rule sorted first.
type SARIFResult struct {
	RuleID     string           `json:"ruleId"`
	RuleIndex  int              `json:"ruleIndex"`
	Level      string           `json:"level,omitempty"`
	Message    SARIFMultiformat `json:"message"`
	Locations  []SARIFLocation  `json:"locations,omitempty"`
	Properties map[string]any   `json:"properties,omitempty"`
}

// SARIFLocation pins a finding to a file (and optionally an offset
// range within it).
type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

// SARIFPhysicalLocation is the file / region pair.
type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           *SARIFRegion          `json:"region,omitempty"`
}

// SARIFArtifactLocation points at a file (URI form).
type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

// SARIFRegion is a byte / character offset region within an artifact.
// We populate ByteOffset / ByteLength because the secret-detection
// matches are byte-indexed; downstream consumers that prefer
// line/column can re-derive them from the URI's contents.
//
// ByteOffset / ByteLength deliberately omit `omitempty`: a match
// starting at the first byte of a file has ByteOffset=0, which is
// semantically distinct from "unspecified". StartLine keeps
// `omitempty` because we don't compute it yet; emitting a literal 0
// there would be wrong.
type SARIFRegion struct {
	StartLine  int `json:"startLine,omitempty"`
	ByteOffset int `json:"byteOffset"`
	ByteLength int `json:"byteLength"`
}

// ScanSecretsSARIF converts a ScanSecretsResult into a SARIF 2.1.0
// log. When res.FilePath is empty (i.e. the scan ran against inline
// text) the artifact URI is "stdin://text" so the result is still
// well-formed SARIF. File-scan paths are emitted as RFC 3986
// file:// URIs (SARIF 2.1.0 §3.4.4 says uri SHOULD conform to RFC
// 3986; a bare absolute path is technically a valid relative URI
// reference, but strict SARIF validators flag it).
func ScanSecretsSARIF(res *ScanSecretsResult) *SARIFLog {
	if res == nil {
		return emptyLog("scan_secrets")
	}
	uri := "stdin://text"
	if res.FilePath != "" {
		uri = fileURI(res.FilePath)
	}
	// Build one rule per distinct pattern name so the rules table
	// stays deduplicated.
	//
	// Use make([], 0) rather than `var rules []SARIFRule` so the
	// driver.rules JSON is `[]` rather than `null` on a zero-finding
	// scan — mirrors the fix CheckDependencySARIF received and keeps
	// the output shape consistent across the two tools for downstream
	// CI consumers.
	//
	// ruleIndex is keyed by m.Name so the dedup loop stays O(matches);
	// a second map (idByName) prevents the rare slug-collision case
	// where two distinct pattern names map to the same
	// sarifIDForPattern slug. Without this guard the second pattern
	// would silently overwrite the first in idxAfterSort and every
	// finding for the loser pattern would point at the wrong
	// ruleIndex. We currently have no colliding patterns, but the
	// guard is cheap insurance against a future pattern addition.
	ruleIndex := map[string]int{}
	idByName := map[string]string{}
	usedIDs := map[string]string{} // id -> firstName that claimed it
	rules := make([]SARIFRule, 0)
	for _, m := range res.Matches {
		if _, ok := ruleIndex[m.Name]; ok {
			continue
		}
		id := sarifIDForPattern(m.Name)
		if firstName, clash := usedIDs[id]; clash && firstName != m.Name {
			// Disambiguate by appending a stable per-name suffix. We
			// use a short hex of len(rules) to avoid leaking the
			// original name into the slug while keeping it
			// deterministic for a given match order.
			id = fmt.Sprintf("%s.dup-%d", id, len(rules))
		}
		usedIDs[id] = m.Name
		idByName[m.Name] = id
		ruleIndex[m.Name] = len(rules)
		rules = append(rules, SARIFRule{
			ID:   id,
			Name: m.Name,
			ShortDescription: &SARIFMultiformat{
				Text: fmt.Sprintf("Secret-detection rule %q (severity %s)", m.Name, m.Severity),
			},
			DefaultConfig: &SARIFRuleConfig{Level: sarifLevel(m.Severity)},
			Properties: map[string]any{
				"severity": m.Severity,
				"source":   "skills/secret-detection/checklists/secret_detection.yaml",
			},
		})
	}
	results := make([]SARIFResult, 0, len(res.Matches))
	for _, m := range res.Matches {
		results = append(results, SARIFResult{
			RuleID:    idByName[m.Name],
			RuleIndex: ruleIndex[m.Name],
			Level:     sarifLevel(m.Severity),
			Message: SARIFMultiformat{
				Text: fmt.Sprintf("%s match (score=%.2f, entropy=%.2f, hotword_hit=%v, known_false_positive=%v)",
					m.Name, m.Score, m.Entropy, m.HotwordHit, m.KnownFalsePositive),
			},
			Locations: []SARIFLocation{{
				PhysicalLocation: SARIFPhysicalLocation{
					ArtifactLocation: SARIFArtifactLocation{URI: uri},
					Region: &SARIFRegion{
						ByteOffset: m.Start,
						ByteLength: m.End - m.Start,
					},
				},
			}},
			Properties: map[string]any{
				"score":                m.Score,
				"entropy":              m.Entropy,
				"hotword_hit":          m.HotwordHit,
				"known_false_positive": m.KnownFalsePositive,
				"severity":             m.Severity,
			},
		})
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	// Re-anchor RuleIndex after sort.
	idxAfterSort := map[string]int{}
	for i, r := range rules {
		idxAfterSort[r.ID] = i
	}
	for i := range results {
		results[i].RuleIndex = idxAfterSort[results[i].RuleID]
	}
	return &SARIFLog{
		Schema:  SARIFSchema,
		Version: SARIFVersion,
		Runs: []SARIFRun{{
			Tool: SARIFTool{Driver: SARIFDriver{
				Name:           SARIFToolName,
				InformationURI: "https://github.com/shieldnet-360/secure-vibe",
				Rules:          rules,
			}},
			Results: results,
		}},
	}
}

// CheckDependencySARIF converts a CheckDependencyResult into a SARIF
// 2.1.0 log so CI pipelines can ingest dependency findings the same
// way they ingest other static-analysis output.
func CheckDependencySARIF(res *CheckDependencyResult) *SARIFLog {
	if res == nil {
		return emptyLog("check_dependency")
	}
	uri := fmt.Sprintf("pkg://%s/%s", res.Ecosystem, res.Package)
	if res.Version != "" {
		uri += "@" + res.Version
	}
	// Three rule kinds: malicious package, typosquat alert, CVE
	// pattern. Each gets a stable rule ID so downstream filters can
	// pin on category.
	rules := []SARIFRule{
		{
			ID:   "secure-vibe.malicious-package",
			Name: "Malicious package",
			ShortDescription: &SARIFMultiformat{
				Text: "Package matched against the supply-chain malicious-packages database.",
			},
			DefaultConfig: &SARIFRuleConfig{Level: "error"},
		},
		{
			ID:   "secure-vibe.typosquat",
			Name: "Known typosquat",
			ShortDescription: &SARIFMultiformat{
				Text: "Package matched against the curated typosquat database.",
			},
			DefaultConfig: &SARIFRuleConfig{Level: "warning"},
		},
		{
			ID:   "secure-vibe.cve-pattern",
			Name: "CVE pattern hit",
			ShortDescription: &SARIFMultiformat{
				Text: "Package name or description matched a tracked CVE pattern.",
			},
			DefaultConfig: &SARIFRuleConfig{Level: "warning"},
		},
	}
	ruleIndex := map[string]int{
		"secure-vibe.malicious-package": 0,
		"secure-vibe.typosquat":         1,
		"secure-vibe.cve-pattern":       2,
	}
	// Use make([], 0) rather than `var results []SARIFResult` so that
	// when zero rules match, the marshalled SARIF Run.Results is "[]"
	// rather than "null". SARIF 2.1.0 specifies results as an array;
	// `null` means "results were not computed", which is misleading
	// for a clean scan, and GitHub Advanced Security rejects the
	// null form on ingestion.
	results := make([]SARIFResult, 0)
	for _, m := range res.Malicious {
		results = append(results, SARIFResult{
			RuleID:    "secure-vibe.malicious-package",
			RuleIndex: ruleIndex["secure-vibe.malicious-package"],
			Level:     sarifLevel(m.Severity),
			Message: SARIFMultiformat{
				Text: fmt.Sprintf("%s/%s flagged as %s: %s", res.Ecosystem, m.Name, m.Type, m.Description),
			},
			Locations: []SARIFLocation{{
				PhysicalLocation: SARIFPhysicalLocation{
					ArtifactLocation: SARIFArtifactLocation{URI: uri},
				},
			}},
			Properties: map[string]any{
				"ecosystem":         res.Ecosystem,
				"versions_affected": m.VersionsAffected,
				"cve":               m.CVE,
				"attack_type":       m.AttackType,
				"severity":          m.Severity,
				"references":        m.References,
			},
		})
	}
	for _, t := range res.Typosquats {
		results = append(results, SARIFResult{
			RuleID:    "secure-vibe.typosquat",
			RuleIndex: ruleIndex["secure-vibe.typosquat"],
			Level:     "warning",
			Message: SARIFMultiformat{
				Text: fmt.Sprintf("%s/%s squats %s (Levenshtein distance %d)", t.Ecosystem, t.Typosquat, t.Target, t.LevenshteinDistance),
			},
			Locations: []SARIFLocation{{
				PhysicalLocation: SARIFPhysicalLocation{
					ArtifactLocation: SARIFArtifactLocation{URI: uri},
				},
			}},
			Properties: map[string]any{
				"target":               t.Target,
				"typosquat":            t.Typosquat,
				"levenshtein_distance": t.LevenshteinDistance,
				"status":               t.Status,
			},
		})
	}
	for _, c := range res.CVEs {
		results = append(results, SARIFResult{
			RuleID:    "secure-vibe.cve-pattern",
			RuleIndex: ruleIndex["secure-vibe.cve-pattern"],
			Level:     sarifLevel(c.Severity),
			Message: SARIFMultiformat{
				Text: fmt.Sprintf("%s (%s): %s", c.CVE, c.Name, c.Description),
			},
			Locations: []SARIFLocation{{
				PhysicalLocation: SARIFPhysicalLocation{
					ArtifactLocation: SARIFArtifactLocation{URI: uri},
				},
			}},
			Properties: map[string]any{
				"cve":         c.CVE,
				"severity":    c.Severity,
				"attack_type": c.AttackType,
				"references":  c.References,
				"languages":   c.Languages,
			},
		})
	}
	return &SARIFLog{
		Schema:  SARIFSchema,
		Version: SARIFVersion,
		Runs: []SARIFRun{{
			Tool: SARIFTool{Driver: SARIFDriver{
				Name:           SARIFToolName,
				InformationURI: "https://github.com/shieldnet-360/secure-vibe",
				Rules:          rules,
			}},
			Results: results,
		}},
	}
}

// PolicyCheckSARIF converts the aggregated results of a `gate` run —
// one PolicyCheckResult per file argument — into a single SARIF 2.1.0
// log so a CI step can `upload-sarif` the gate's verdict to GitHub
// Code Scanning. Every finding across every file becomes one result in
// a single run; the rules table is deduplicated by the finding's
// RuleID so a dashboard can hyperlink each result back to its rule.
//
// Findings carry an artifactLocation only (no byte region): the gate
// flattens line-indexed scanner findings, whereas SARIFRegion is
// byte-indexed (built for the secret scanner), so emitting a region
// would force a misleading byteOffset=0/byteLength=0. The line number
// is carried in result.properties.line instead. Emitting SARIF never
// changes the gate's exit code — it only shapes stdout.
//
// baseDir controls the artifact URI shape. GitHub Code Scanning only
// anchors an alert to a file when the URI is RELATIVE to the checkout
// root — an absolute file:// URI ingests fine but renders as a dead
// /Users/... path (verified on a live fixture repo). When baseDir is
// non-empty, any finding whose file lives under it gets a clean
// repo-relative URI; files outside baseDir (and the baseDir=="" case)
// fall back to the absolute file:// form so the document stays
// well-formed rather than emitting a ../../ escape path.
func PolicyCheckSARIF(results []*PolicyCheckResult, baseDir string) *SARIFLog {
	if len(results) == 0 {
		return emptyLog("gate")
	}
	// Deduplicate the rules table by RuleID across every file. The
	// first finding to use a RuleID defines its rule metadata.
	ruleIndex := map[string]int{}
	rules := make([]SARIFRule, 0)
	registerRule := func(f PolicyCheckFinding) string {
		id := f.RuleID
		if id == "" {
			id = "secure-vibe.gate.unspecified"
		}
		if _, seen := ruleIndex[id]; !seen {
			desc := f.Title
			if desc == "" {
				desc = id
			}
			ruleIndex[id] = len(rules)
			rules = append(rules, SARIFRule{
				ID:               id,
				Name:             f.Title,
				ShortDescription: &SARIFMultiformat{Text: desc},
				DefaultConfig:    &SARIFRuleConfig{Level: sarifLevel(f.Severity)},
			})
		}
		return id
	}

	out := make([]SARIFResult, 0)
	for _, res := range results {
		if res == nil {
			continue
		}
		uri := fileURI(res.FilePath)
		if baseDir != "" {
			if rel, err := filepath.Rel(baseDir, res.FilePath); err == nil &&
				rel != "." && !strings.HasPrefix(rel, "..") {
				uri = filepath.ToSlash(rel)
			}
		}
		for _, f := range res.Findings {
			id := registerRule(f)
			msg := f.Title
			if msg == "" {
				msg = id
			}
			if f.Package != "" {
				msg = fmt.Sprintf("%s [%s", msg, f.Package)
				if f.Version != "" {
					msg += "@" + f.Version
				}
				msg += "]"
			}
			props := map[string]any{
				"severity": f.Severity,
				"scan":     res.Scan,
			}
			if f.Confidence != "" {
				props["confidence"] = f.Confidence
			}
			if f.Line > 0 {
				props["line"] = f.Line
			}
			if f.Snippet != "" {
				props["snippet"] = f.Snippet
			}
			if f.Package != "" {
				props["package"] = f.Package
			}
			if f.Version != "" {
				props["version"] = f.Version
			}
			out = append(out, SARIFResult{
				RuleID:    id,
				RuleIndex: ruleIndex[id],
				Level:     sarifLevel(f.Severity),
				Message:   SARIFMultiformat{Text: msg},
				Locations: []SARIFLocation{{
					PhysicalLocation: SARIFPhysicalLocation{
						ArtifactLocation: SARIFArtifactLocation{URI: uri},
					},
				}},
				Properties: props,
			})
		}
	}

	// Stable rule order + re-anchored ruleIndex so the document is
	// deterministic across runs (mirrors ScanSecretsSARIF).
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	idxAfterSort := map[string]int{}
	for i, r := range rules {
		idxAfterSort[r.ID] = i
	}
	for i := range out {
		out[i].RuleIndex = idxAfterSort[out[i].RuleID]
	}

	return &SARIFLog{
		Schema:  SARIFSchema,
		Version: SARIFVersion,
		Runs: []SARIFRun{{
			Tool: SARIFTool{Driver: SARIFDriver{
				Name:           SARIFToolName,
				InformationURI: "https://github.com/shieldnet-360/secure-vibe",
				Rules:          rules,
			}},
			Results: out,
		}},
	}
}

// fileURI converts a local absolute path to an RFC 3986 file:// URI.
// validateScanPath guarantees the path is absolute when reaching
// the SARIF emitter; if a non-absolute or empty path slips through
// (e.g. tests passing a bare name) we fall back to the raw string
// to keep the SARIF document well-formed rather than panicking.
func fileURI(path string) string {
	if path == "" {
		return path
	}
	if strings.HasPrefix(path, "/") {
		return (&url.URL{Scheme: "file", Path: path}).String()
	}
	// Non-absolute (e.g. Windows-style "C:\\..." before normalisation,
	// or a test fixture) — emit as-is. Callers that need a strict
	// file:// scheme on Windows can pre-normalise the path.
	return path
}

// emptyLog returns a SARIF document with a single empty run so a
// caller can still serialise nil results as well-formed SARIF.
func emptyLog(tool string) *SARIFLog {
	return &SARIFLog{
		Schema:  SARIFSchema,
		Version: SARIFVersion,
		Runs: []SARIFRun{{
			Tool: SARIFTool{Driver: SARIFDriver{
				Name:           SARIFToolName,
				InformationURI: "https://github.com/shieldnet-360/secure-vibe",
				Rules:          []SARIFRule{},
			}},
			Results: []SARIFResult{},
		}},
	}
}

// sarifIDForPattern derives a stable SARIF rule ID from a pattern
// name. The form `secure-vibe.dlp.<slug>` keeps every rule the MCP
// server emits inside the `secure-vibe mcp.` namespace so downstream
// dashboards can filter all of them at once.
func sarifIDForPattern(name string) string {
	out := make([]rune, 0, len(name))
	for _, r := range name {
		switch {
		case r >= 'A' && r <= 'Z':
			out = append(out, r-'A'+'a')
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			out = append(out, r)
		default:
			if len(out) > 0 && out[len(out)-1] != '-' {
				out = append(out, '-')
			}
		}
	}
	for len(out) > 0 && out[len(out)-1] == '-' {
		out = out[:len(out)-1]
	}
	if len(out) == 0 {
		return "secure-vibe.dlp.unknown"
	}
	return "secure-vibe.dlp." + string(out)
}

// sarifLevel maps the library's severity vocabulary to the SARIF
// "level" enum (note / warning / error). The "none" level is omitted
// so undecorated findings default to warning, which is what most CI
// dashboards expect.
func sarifLevel(severity string) string {
	switch severity {
	case "critical", "high":
		return "error"
	case "medium", "moderate":
		return "warning"
	case "low":
		return "note"
	case "":
		return "warning"
	}
	return "warning"
}
