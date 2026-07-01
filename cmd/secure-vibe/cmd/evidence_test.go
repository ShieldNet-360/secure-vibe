package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEvidenceCmdSOC2JSON(t *testing.T) {
	root := repoRoot(t)
	stdout, _, err := executeRoot(t,
		"evidence",
		"--library", root,
		"--framework", "SOC2",
		"--format", "json",
	)
	if err != nil {
		t.Fatalf("evidence returned error: %v\n%s", err, stdout)
	}
	var report EvidenceReport
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("failed to parse JSON: %v\n%s", err, stdout)
	}
	if report.Framework == "" {
		t.Error("expected framework name")
	}
	if len(report.Controls) == 0 {
		t.Error("expected at least one control")
	}
	if report.SkillsCount < 7 {
		t.Errorf("expected >=7 skills, got %d", report.SkillsCount)
	}
}

func TestEvidenceCmdHIPAAMarkdown(t *testing.T) {
	root := repoRoot(t)
	stdout, _, err := executeRoot(t,
		"evidence",
		"--library", root,
		"--framework", "HIPAA",
		"--format", "markdown",
	)
	if err != nil {
		t.Fatalf("evidence returned error: %v", err)
	}
	if !strings.Contains(stdout, "# Compliance Evidence Report") {
		t.Errorf("missing markdown header: %s", stdout)
	}
	if !strings.Contains(stdout, "HIPAA") {
		t.Errorf("missing framework name: %s", stdout)
	}
}

func TestEvidenceCmdPCIDSS(t *testing.T) {
	root := repoRoot(t)
	stdout, _, err := executeRoot(t,
		"evidence",
		"--library", root,
		"--framework", "PCI-DSS",
		"--format", "json",
	)
	if err != nil {
		t.Fatalf("evidence returned error: %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, "PCI-DSS") {
		t.Errorf("missing framework name")
	}
}

func TestEvidenceCmdMissingFramework(t *testing.T) {
	root := repoRoot(t)
	_, _, err := executeRoot(t,
		"evidence",
		"--library", root,
	)
	if err == nil {
		t.Fatal("expected error when --framework is missing")
	}
}

// TestEscapeMarkdownTableCellPipes is the regression test for the bug
// where renderEvidenceMarkdown wrote control IDs and skill names
// directly into a GFM table without escaping `|`. A future compliance
// framework that uses `|` in a control ID (or a skill name) would have
// silently broken the table structure (extra columns / shifted rows).
//
// The fix is the escapeMarkdownTableCell helper, which:
//   - replaces `|` with `\|`
//   - replaces newline variants (\n, \r, \r\n) with `<br>` so a
//     multi-line value doesn't terminate the row
//
// We render a synthetic table row by calling the helper directly (the
// renderEvidenceMarkdown function takes the full EvidenceReport struct,
// which is heavier than needed for this targeted check).
func TestEscapeMarkdownTableCellPipes(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{name: "no special chars", in: "AC-2", want: "AC-2"},
		{name: "single pipe", in: "a|b", want: `a\|b`},
		{name: "multiple pipes", in: "a|b|c", want: `a\|b\|c`},
		{name: "newline", in: "a\nb", want: "a<br>b"},
		{name: "crlf", in: "a\r\nb", want: "a<br>b"},
		{name: "pipe and newline together", in: "a|b\nc", want: `a\|b<br>c`},
		// Pre-existing backslash must be escaped first; otherwise our
		// pipe escape would create an ambiguous double-escape sequence.
		{name: "pre-existing backslash", in: `a\b`, want: `a\\b`},
	}
	for _, tc := range cases {
		got := escapeMarkdownTableCell(tc.in)
		if got != tc.want {
			t.Errorf("%s: escape(%q) = %q, want %q", tc.name, tc.in, got, tc.want)
		}
	}
}

// TestRenderEvidenceMarkdownEscapesPipesInControlAndSkillIDs is the
// integration-level regression for M4: synthesize an EvidenceReport with
// a `|` in both the control ID and a skill name, render it, and assert
// every interpolated cell is escaped so the table parses to the correct
// number of columns.
func TestRenderEvidenceMarkdownEscapesPipesInControlAndSkillIDs(t *testing.T) {
	r := EvidenceReport{
		Framework: "TEST",
		Controls: []ControlEvidence{
			{
				ID:     "CTRL|UNUSUAL",
				Status: "covered",
				PresentSkills: []SkillSummary{
					{ID: "skill|with-pipe", Version: "1.0.0"},
				},
				MissingSkills: []string{"missing|skill"},
			},
		},
	}
	out := renderEvidenceMarkdown(r)
	// Every literal `|` from input data must be escaped.
	if strings.Contains(out, "CTRL|UNUSUAL") {
		t.Errorf("control ID pipe was not escaped:\n%s", out)
	}
	if !strings.Contains(out, `CTRL\|UNUSUAL`) {
		t.Errorf("expected escaped control ID, got:\n%s", out)
	}
	if !strings.Contains(out, `skill\|with-pipe@1.0.0`) {
		t.Errorf("expected escaped present-skill ID, got:\n%s", out)
	}
	if !strings.Contains(out, `missing\|skill`) {
		t.Errorf("expected escaped missing-skill ID, got:\n%s", out)
	}
	// Sanity check the table row has the expected column count. The
	// rendered row should contain exactly 5 `|` characters (4 cells
	// → 5 separators), where each escaped `\|` inside a cell does NOT
	// count as a column separator.
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, `CTRL\|UNUSUAL`) {
			continue
		}
		// Count unescaped `|` separators only.
		separators := 0
		for i := 0; i < len(line); i++ {
			if line[i] != '|' {
				continue
			}
			if i > 0 && line[i-1] == '\\' {
				continue
			}
			separators++
		}
		if separators != 5 {
			t.Errorf("control row has %d unescaped `|` separators, want 5; line: %q", separators, line)
		}
		return
	}
	t.Errorf("could not find rendered control row in output:\n%s", out)
}

func TestEvidenceCmdUnknownFramework(t *testing.T) {
	root := repoRoot(t)
	_, _, err := executeRoot(t,
		"evidence",
		"--library", root,
		"--framework", "NoSuchFramework",
	)
	if err == nil {
		t.Fatal("expected error for unknown framework")
	}
}

// TestEvidenceCmdRejectsPathTraversalFramework is the regression for L2: a
// caller passing path-traversal characters in --framework must be rejected
// at flag-validation time, before the value is concatenated into a filepath.
// Pre-fix, `--framework ../../etc/passwd` would compute
// fwSlug=`../../etc/passwd` and try to read compliance/../../etc/passwd_mapping.yaml.
func TestEvidenceCmdRejectsPathTraversalFramework(t *testing.T) {
	root := repoRoot(t)
	cases := []struct {
		name      string
		framework string
	}{
		{name: "parent traversal", framework: "../../etc/passwd"},
		{name: "forward slash", framework: "soc2/extra"},
		{name: "backslash", framework: `soc2\extra`},
		{name: "double dot", framework: ".."},
		{name: "leading dot", framework: ".soc2"},
		{name: "embedded space", framework: "soc 2"},
		{name: "null byte", framework: "soc2\x00extra"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := executeRoot(t,
				"evidence",
				"--library", root,
				"--framework", tc.framework,
				"--format", "json",
			)
			if err == nil {
				t.Fatalf("expected error for --framework %q, got nil", tc.framework)
			}
			if !strings.Contains(err.Error(), "invalid") {
				t.Errorf("expected error message to mention 'invalid' for %q, got: %v",
					tc.framework, err)
			}
		})
	}
}

// TestEvidenceCmdAcceptsValidFrameworkSlug confirms the slug validator
// allows the canonical framework names (alphanumerics plus `-` and `_`).
func TestEvidenceCmdAcceptsValidFrameworkSlug(t *testing.T) {
	root := repoRoot(t)
	for _, fw := range []string{"SOC2", "HIPAA", "PCI-DSS"} {
		t.Run(fw, func(t *testing.T) {
			_, _, err := executeRoot(t,
				"evidence",
				"--library", root,
				"--framework", fw,
				"--format", "json",
			)
			if err != nil {
				t.Fatalf("expected %q to be accepted by the slug validator, got: %v", fw, err)
			}
		})
	}
}

// TestEvidenceCmdUnmappedControlsPopulated verifies that controls whose
// skills: list is empty are aggregated into UnmappedControls in the JSON
// report and surfaced in the markdown summary + section. Regression for the
// bug where UnmappedControls was declared but never set.
func TestEvidenceCmdUnmappedControlsPopulated(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "compliance"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "skills"), 0o755); err != nil {
		t.Fatal(err)
	}
	mapping := `schema_version: "1.0.0"
framework: "TEST"
version: "1.0"
last_updated: "2026-05-13"
controls:
  - id: "CTRL-COVERED"
    title: "Covered control"
    skills:
      - "ghost-skill"
  - id: "CTRL-UNMAPPED-A"
    title: "Has no mapped skills A"
    skills: []
  - id: "CTRL-UNMAPPED-B"
    title: "Has no mapped skills B"
    skills: []
`
	if err := os.WriteFile(filepath.Join(dir, "compliance", "test_mapping.yaml"), []byte(mapping), 0o644); err != nil {
		t.Fatal(err)
	}

	jsonOut, _, err := executeRoot(t,
		"evidence",
		"--library", dir,
		"--framework", "TEST",
		"--format", "json",
	)
	if err != nil {
		t.Fatalf("evidence returned error: %v\n%s", err, jsonOut)
	}
	var report EvidenceReport
	if err := json.Unmarshal([]byte(jsonOut), &report); err != nil {
		t.Fatalf("failed to parse JSON: %v\n%s", err, jsonOut)
	}
	if len(report.UnmappedControls) != 2 {
		t.Fatalf("expected 2 UnmappedControls, got %d: %v", len(report.UnmappedControls), report.UnmappedControls)
	}
	if report.UnmappedControls[0] != "CTRL-UNMAPPED-A" || report.UnmappedControls[1] != "CTRL-UNMAPPED-B" {
		t.Errorf("UnmappedControls not sorted as expected: %v", report.UnmappedControls)
	}
	if !strings.Contains(jsonOut, `"unmapped_controls": [`) {
		t.Errorf("expected unmapped_controls array in JSON, got null: %s", jsonOut)
	}

	mdOut, _, err := executeRoot(t,
		"evidence",
		"--library", dir,
		"--framework", "TEST",
		"--format", "markdown",
	)
	if err != nil {
		t.Fatalf("evidence (markdown) returned error: %v\n%s", err, mdOut)
	}
	if !strings.Contains(mdOut, "- Unmapped: 2") {
		t.Errorf("expected markdown summary to include `- Unmapped: 2`, got:\n%s", mdOut)
	}
	if !strings.Contains(mdOut, "## Controls with no mapped skills") {
		t.Errorf("expected markdown to include unmapped-controls section, got:\n%s", mdOut)
	}
	if !strings.Contains(mdOut, "- CTRL-UNMAPPED-A") || !strings.Contains(mdOut, "- CTRL-UNMAPPED-B") {
		t.Errorf("expected both unmapped control IDs listed in markdown, got:\n%s", mdOut)
	}
}

// TestEvidenceCmdJSONEmptySlicesShapeAsArrays verifies that empty per-control
// (PresentSkills, MissingSkills) and top-level (UnmappedSkills,
// UnmappedControls) slices serialize as JSON arrays `[]` rather than `null`.
// Audit consumers and strict JSON-schema validators distinguish the two; the
// report must be shape-stable across emptiness.
func TestEvidenceCmdJSONEmptySlicesShapeAsArrays(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "compliance"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "skills"), 0o755); err != nil {
		t.Fatal(err)
	}
	// One control with no skills mapped + empty library -> every nil-able slice
	// is empty in the output, so any null in the JSON is a regression.
	mapping := `schema_version: "1.0.0"
framework: "TEST"
version: "1.0"
last_updated: "2026-05-13"
controls:
  - id: "CTRL-EMPTY"
    title: "Control with no mapped skills"
    skills: []
`
	if err := os.WriteFile(filepath.Join(dir, "compliance", "test_mapping.yaml"), []byte(mapping), 0o644); err != nil {
		t.Fatal(err)
	}

	jsonOut, _, err := executeRoot(t,
		"evidence",
		"--library", dir,
		"--framework", "TEST",
		"--format", "json",
	)
	if err != nil {
		t.Fatalf("evidence returned error: %v\n%s", err, jsonOut)
	}

	// Every nil-able slice must marshal as `[]`. None of the four may render as
	// `null` — Go's encoding/json emits null for nil slices, so a null here is
	// proof the field was never initialized.
	mustHave := []string{
		`"unmapped_skills": []`,
		`"present_skills": []`,
		`"missing_skills": []`,
	}
	for _, want := range mustHave {
		if !strings.Contains(jsonOut, want) {
			t.Errorf("expected JSON to contain %q, got:\n%s", want, jsonOut)
		}
	}
	mustNotHave := []string{
		`"unmapped_skills": null`,
		`"unmapped_controls": null`,
		`"present_skills": null`,
		`"missing_skills": null`,
	}
	for _, bad := range mustNotHave {
		if strings.Contains(jsonOut, bad) {
			t.Errorf("expected JSON to not contain %q (nil-slice marshaling regression), got:\n%s", bad, jsonOut)
		}
	}

	// Round-trip: after Unmarshal of `[]`, slices are non-nil empty;
	// after Unmarshal of `null`, slices are nil. A nil here means the JSON
	// emitted null and the regression slipped past the string checks above.
	var report EvidenceReport
	if err := json.Unmarshal([]byte(jsonOut), &report); err != nil {
		t.Fatalf("failed to parse JSON: %v\n%s", err, jsonOut)
	}
	if report.UnmappedSkills == nil {
		t.Error("UnmappedSkills should be non-nil empty after round-trip")
	}
	if report.UnmappedControls == nil {
		t.Error("UnmappedControls should be non-nil empty after round-trip")
	}
	if len(report.Controls) != 1 {
		t.Fatalf("expected 1 control, got %d", len(report.Controls))
	}
	ctrl := report.Controls[0]
	if ctrl.PresentSkills == nil {
		t.Error("PresentSkills should be non-nil empty after round-trip")
	}
	if ctrl.MissingSkills == nil {
		t.Error("MissingSkills should be non-nil empty after round-trip")
	}
}
