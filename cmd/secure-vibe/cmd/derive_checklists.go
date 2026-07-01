package cmd

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/shieldnet-360/secure-vibe/internal/skill"
)

// HTML-comment pattern marker: a bullet in SKILL.md can be promoted to a
// structured entry in checklists/<framework>.yaml by appending a comment
// of the form
//
//	<!-- pattern: { id: <kebab-id>, severity: <bucket>, cwe: <num>, framework: <name> } -->
//
// The inner payload is YAML flow style. Fields:
//
//	id        REQUIRED. kebab-case. unique within the skill.
//	severity  OPTIONAL. critical | high | medium | low | info.
//	          Defaults: ALWAYS → "high", NEVER → "critical",
//	          KNOWN FALSE POSITIVES → "info".
//	cwe       OPTIONAL. CWE identifier (integer).
//	framework OPTIONAL. Required only when the skill has > 1 checklist
//	          YAML file under checklists/. With a single checklist the
//	          tool infers from the file name.
//
// Bullets without this marker are not touched — they remain prose-only
// knowledge that AI consults at code-generation time. The two states
// (prose-only and prose+structured) coexist on purpose: not every
// recommendation needs to be a programmatic check.
//
// htmlPatternMarker captures the YAML payload from the bullet text the
// internal/skill parser produces (which collapses continuation lines
// into a single string, so the marker can appear anywhere in that
// string).
var htmlPatternMarker = regexp.MustCompile(`<!--\s*pattern\s*:\s*(\{[^<]*?\})\s*-->`)

// patternMarker is the parsed payload from a single bullet's HTML
// comment. Severity is left empty when the comment did not set it; the
// caller fills in the section-default after deciding which section the
// bullet came from.
type patternMarker struct {
	ID        string `yaml:"id"`
	Severity  string `yaml:"severity,omitempty"`
	CWE       int    `yaml:"cwe,omitempty"`
	Framework string `yaml:"framework,omitempty"`
	// Check marks a pattern as SCANNER-BOUND rather than a governance
	// checklist row: "deterministic" means a Go scanner check enforces
	// it, "llm" means the agent reasons from SKILL.md. Markers with a
	// non-empty Check are the contract the gate's trace test reads
	// directly and are deliberately EXCLUDED from checklists/*.yaml
	// generation — so a scanner-bound skill (container/cicd) emits no
	// checklist YAML at all.
	Check string `yaml:"check,omitempty"`
}

// derivedPattern is one entry in the generated YAML file. Mirrors the
// existing flat schema in skills/*/checklists/*.yaml.
type derivedPattern struct {
	ID       string `yaml:"id"`
	Severity string `yaml:"severity"`
	Rule     string `yaml:"rule"`
	CWE      int    `yaml:"cwe,omitempty"`
}

// checklistFile mirrors the top-level structure of the existing
// dockerfile_hardening.yaml / k8s_pod_security.yaml files. Fields we
// don't touch (description, references, etc.) are preserved verbatim
// via yamlPreservingMarshal below.
type checklistFile struct {
	SchemaVersion string           `yaml:"schema_version"`
	Framework     string           `yaml:"framework,omitempty"`
	LastUpdated   string           `yaml:"last_updated,omitempty"`
	Description   string           `yaml:"description,omitempty"`
	GeneratedFrom string           `yaml:"generated_from,omitempty"`
	Patterns      []derivedPattern `yaml:"patterns"`
}

// deriveChecklistsCmd is the public Cobra factory. The tool runs in two
// modes: write (default) and --check (dry-run). Both modes resolve the
// same SKILL.md → in-memory desired checklist content; --check exits
// 1 when the in-memory form differs from the file on disk, so CI can
// gate merges on the two staying in sync.
func deriveChecklistsCmd() *cobra.Command {
	var (
		repoPath  string
		framework string
		check     bool
	)
	c := &cobra.Command{
		Use:   "derive-checklists <skill-id>",
		Short: "Derive checklists/*.yaml from a skill's SKILL.md HTML-comment pattern markers",
		Long: `derive-checklists treats SKILL.md as the single source of truth for
each skill's structured rule list. Bullets in the ALWAYS / NEVER / KNOWN
FALSE POSITIVES sections can carry an HTML comment marker of the form

  <!-- pattern: { id: my-rule-id, severity: critical, cwe: 250 } -->

For each tagged bullet, the tool writes (or, with --check, verifies) a
matching row into checklists/<framework>.yaml. Bullets without a marker
are ignored — they remain prose knowledge the AI assistant consults at
code-generation time but no automated tool fires on.

Existing rows in the target YAML whose ID does not appear in any
SKILL.md marker are preserved (they are "manual" rows the human
maintainer owns); the tool only adds new rows or refreshes existing
ones whose ID does appear. This MERGE semantics is what lets the
SKILL.md author add knowledge incrementally without losing data
maintainers have curated by hand.

Severity defaults when the marker omits it: ALWAYS → high,
NEVER → critical, KNOWN FALSE POSITIVES → info.

The rule text is the bullet's prose with the HTML marker stripped.`,
		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			skillID := args[0]
			abs, err := filepath.Abs(repoPath)
			if err != nil {
				return err
			}
			return runDeriveChecklists(c.OutOrStdout(), abs, skillID, framework, check)
		},
	}
	c.Flags().StringVar(&repoPath, "path", ".", "path to the secure-vibe checkout (default cwd)")
	c.Flags().StringVar(&framework, "framework", "", "target checklist framework when the skill has more than one (must match the YAML file's basename)")
	c.Flags().BoolVar(&check, "check", false, "dry-run; exit 1 if any target YAML differs from the derived form")
	return c
}

// runDeriveChecklists is the testable core of the command. Returns
// an error with a human-readable explanation when anything goes wrong;
// the Cobra layer prints it and exits non-zero.
func runDeriveChecklists(stdout interface{ Write([]byte) (int, error) }, repoRoot, skillID, framework string, check bool) error {
	skillDir := filepath.Join(repoRoot, "skills", skillID)
	skillPath := filepath.Join(skillDir, "SKILL.md")
	s, err := skill.Parse(skillPath)
	if err != nil {
		return fmt.Errorf("parse skill %s: %w", skillID, err)
	}
	markers, err := extractPatternMarkers(s)
	if err != nil {
		return fmt.Errorf("parse markers in %s: %w", skillPath, err)
	}
	if len(markers) == 0 {
		fmt.Fprintf(stdout, "derive-checklists: %s has 0 tagged bullets; no checklists touched\n", skillID)
		return nil
	}
	// Scanner-bound markers (check: deterministic|llm) are the contract
	// the gate's trace test reads straight from SKILL.md; they never
	// become governance checklist rows. Drop them before generating so a
	// fully scanner-bound skill (container/cicd) produces no YAML.
	governance := make([]bulletWithMarker, 0, len(markers))
	scannerBound := 0
	for _, m := range markers {
		if strings.TrimSpace(m.marker.Check) != "" {
			scannerBound++
			continue
		}
		governance = append(governance, m)
	}
	if len(governance) == 0 {
		fmt.Fprintf(stdout, "derive-checklists: %s has %d scanner-bound (check:) marker(s) and no governance bullets; no checklists touched\n", skillID, scannerBound)
		return nil
	}
	markers = governance
	byFramework, err := groupByFramework(markers, skillDir, framework)
	if err != nil {
		return err
	}
	anyDrift := false
	for fwName, fwMarkers := range byFramework {
		fwPath := filepath.Join(skillDir, "checklists", fwName+".yaml")
		merged, hadFile, err := mergeChecklist(fwPath, fwMarkers, skillID, fwName)
		if err != nil {
			return fmt.Errorf("merge %s: %w", fwPath, err)
		}
		serialised, err := marshalChecklist(merged)
		if err != nil {
			return fmt.Errorf("marshal %s: %w", fwPath, err)
		}
		if check {
			drift, err := diffChecklistOnDisk(fwPath, serialised)
			if err != nil {
				return err
			}
			if drift {
				anyDrift = true
				fmt.Fprintf(stdout, "derive-checklists: %s is out of sync with %s; re-run without --check to regenerate\n", fwPath, skillPath)
			}
		} else {
			if err := os.MkdirAll(filepath.Dir(fwPath), 0o755); err != nil {
				return err
			}
			if err := os.WriteFile(fwPath, serialised, 0o644); err != nil {
				return err
			}
			action := "updated"
			if !hadFile {
				action = "created"
			}
			fmt.Fprintf(stdout, "derive-checklists: %s %s (%d entries from skill, %d preserved)\n", action, fwPath, len(fwMarkers), len(merged.Patterns)-len(fwMarkers))
		}
	}
	if check && anyDrift {
		return fmt.Errorf("derive-checklists --check failed: one or more checklists out of sync with SKILL.md")
	}
	return nil
}

// bulletWithMarker pairs the parsed marker with the prose text it
// came from (HTML comment stripped) and the section the bullet came
// from. The section determines the severity default when the marker
// omits it.
type bulletWithMarker struct {
	marker  patternMarker
	rule    string
	section string // "always" / "never" / "kfp"
}

// extractPatternMarkers walks every bullet in the skill's ALWAYS /
// NEVER / KNOWN FALSE POSITIVES sections and returns the ones that
// carry an HTML pattern marker. Bullets without a marker are skipped
// silently.
//
// Returning an error means at least one marker was present but did
// not parse (malformed YAML inside the comment, duplicate id, etc.).
// Skipping a bullet without a marker is not an error — the SKILL.md
// author may legitimately want some bullets to remain prose-only.
func extractPatternMarkers(s *skill.Skill) ([]bulletWithMarker, error) {
	out := make([]bulletWithMarker, 0)
	seen := map[string]string{}
	pull := func(section string, bullets []string) error {
		for _, raw := range bullets {
			m := htmlPatternMarker.FindStringSubmatch(raw)
			if m == nil {
				continue
			}
			payload := m[1]
			var parsed patternMarker
			if err := yaml.Unmarshal([]byte(payload), &parsed); err != nil {
				return fmt.Errorf("section %q bullet %q: invalid pattern marker %q: %w", section, truncateForError(raw), payload, err)
			}
			if strings.TrimSpace(parsed.ID) == "" {
				return fmt.Errorf("section %q bullet %q: pattern marker missing required field 'id'", section, truncateForError(raw))
			}
			if other, dup := seen[parsed.ID]; dup {
				return fmt.Errorf("duplicate pattern id %q in %s: also appears in %s", parsed.ID, section, other)
			}
			seen[parsed.ID] = section
			rule := strings.TrimSpace(htmlPatternMarker.ReplaceAllString(raw, ""))
			rule = collapseWhitespace(rule)
			out = append(out, bulletWithMarker{marker: parsed, rule: rule, section: section})
		}
		return nil
	}
	if err := pull("always", s.Body.Always); err != nil {
		return nil, err
	}
	if err := pull("never", s.Body.Never); err != nil {
		return nil, err
	}
	if err := pull("kfp", s.Body.KnownFalsePositives); err != nil {
		return nil, err
	}
	return out, nil
}

// groupByFramework partitions markers by their target checklist file.
// The CLI's --framework flag pins all unframed markers to that name;
// when --framework is empty and the skill has exactly one .yaml under
// checklists/, the basename of that file is used. Otherwise every
// marker must declare framework: explicitly.
func groupByFramework(markers []bulletWithMarker, skillDir, cliFramework string) (map[string][]bulletWithMarker, error) {
	inferred := cliFramework
	if inferred == "" {
		matches, _ := filepath.Glob(filepath.Join(skillDir, "checklists", "*.yaml"))
		if len(matches) == 1 {
			inferred = strings.TrimSuffix(filepath.Base(matches[0]), ".yaml")
		}
	}
	out := map[string][]bulletWithMarker{}
	for _, b := range markers {
		fw := b.marker.Framework
		if fw == "" {
			fw = inferred
		}
		if fw == "" {
			return nil, fmt.Errorf("pattern %q in %s has no framework: set 'framework:' in the marker, or pass --framework on the command line, or place a single .yaml under checklists/", b.marker.ID, b.section)
		}
		out[fw] = append(out[fw], b)
	}
	return out, nil
}

// mergeChecklist reads the on-disk checklist (when it exists),
// preserves top-level fields and any entries whose id is not in
// markers, and adds / refreshes the entries that are. The second
// return value reports whether the file already existed (drives the
// "created" vs "updated" log line).
func mergeChecklist(path string, markers []bulletWithMarker, skillID, fwName string) (*checklistFile, bool, error) {
	existing, had, err := readChecklist(path)
	if err != nil {
		return nil, false, err
	}
	if existing.SchemaVersion == "" {
		existing.SchemaVersion = "1.0"
	}
	if existing.Framework == "" {
		existing.Framework = fwName
	}
	existing.GeneratedFrom = fmt.Sprintf("skills/%s/SKILL.md", skillID)
	prevPatterns := existing.Patterns
	prevLastUpdated := existing.LastUpdated
	desired := map[string]derivedPattern{}
	for _, b := range markers {
		sev := b.marker.Severity
		if sev == "" {
			sev = defaultSeverity(b.section)
		}
		desired[b.marker.ID] = derivedPattern{
			ID:       b.marker.ID,
			Severity: sev,
			Rule:     b.rule,
			CWE:      b.marker.CWE,
		}
	}
	merged := make([]derivedPattern, 0, len(existing.Patterns)+len(desired))
	seen := map[string]bool{}
	// Walk existing entries in original order; replace IDs that
	// re-appear in desired.
	for _, p := range existing.Patterns {
		if d, ok := desired[p.ID]; ok {
			merged = append(merged, d)
			seen[p.ID] = true
		} else {
			merged = append(merged, p)
			seen[p.ID] = true
		}
	}
	// Append desired entries that did not already exist, sorted by
	// id for deterministic output.
	newIDs := make([]string, 0)
	for id := range desired {
		if !seen[id] {
			newIDs = append(newIDs, id)
		}
	}
	sort.Strings(newIDs)
	for _, id := range newIDs {
		merged = append(merged, desired[id])
	}
	existing.Patterns = merged
	// Stamp today's date ONLY when the derived patterns actually changed (or
	// the checklist is new). Stamping unconditionally with time.Now made
	// `derive-checklists --check` report spurious drift on a UTC-day rollover
	// and fail unrelated PRs the day after a checklist was last generated.
	if !had || !reflect.DeepEqual(prevPatterns, merged) {
		existing.LastUpdated = time.Now().UTC().Format("2006-01-02")
	} else {
		existing.LastUpdated = prevLastUpdated
	}
	return existing, had, nil
}

// readChecklist reads the checklist at path. A missing file is not an
// error; it returns a zero-valued checklistFile + had=false so the
// caller can populate top-level fields fresh.
func readChecklist(path string) (*checklistFile, bool, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &checklistFile{}, false, nil
		}
		return nil, false, err
	}
	var f checklistFile
	if err := yaml.Unmarshal(body, &f); err != nil {
		return nil, false, fmt.Errorf("parse %s: %w", path, err)
	}
	return &f, true, nil
}

// marshalChecklist produces the canonical YAML form of the merged
// checklist. Uses a 2-space indent to match the existing files in the
// repo and emits a trailing newline.
func marshalChecklist(c *checklistFile) ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(c); err != nil {
		return nil, err
	}
	_ = enc.Close()
	return buf.Bytes(), nil
}

// diffChecklistOnDisk compares the marshalled merge result against the
// file on disk. Whitespace at end-of-file is normalised so a missing
// trailing newline does not register as drift.
func diffChecklistOnDisk(path string, desired []byte) (bool, error) {
	actual, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return true, nil
		}
		return false, err
	}
	return !bytes.Equal(bytes.TrimRight(actual, "\n"), bytes.TrimRight(desired, "\n")), nil
}

// defaultSeverity maps a SKILL.md section name to the severity used
// when a pattern marker did not set its own. The mapping mirrors how
// the existing dockerfile_hardening.yaml curates severities: ALWAYS
// rules describe positive controls and tend to land in "high"; NEVER
// rules describe attack vectors and land in "critical"; KNOWN FALSE
// POSITIVES land in "info" because they exist to suppress noise.
func defaultSeverity(section string) string {
	switch section {
	case "always":
		return "high"
	case "never":
		return "critical"
	case "kfp":
		return "info"
	}
	return "medium"
}

// truncateForError returns at most 80 chars of s, suitable for an
// error message that needs to identify the offending bullet without
// flooding the terminal.
func truncateForError(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= 80 {
		return s
	}
	return s[:77] + "..."
}

// collapseWhitespace normalises any run of whitespace (spaces, tabs,
// newlines from continuation lines) to a single space. Used to turn
// the parser's already-joined bullet text into one tidy rule string.
func collapseWhitespace(s string) string {
	fields := strings.Fields(s)
	return strings.Join(fields, " ")
}
