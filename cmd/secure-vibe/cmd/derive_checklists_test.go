package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// writeSkill is a test helper that drops a SKILL.md plus a checklists
// subdirectory at root/skills/<id>/. The skill frontmatter is the
// minimum the internal/skill parser will accept so we can exercise the
// derive-checklists logic against a real Parse() result.
func writeSkill(t *testing.T, root, id, body string) {
	t.Helper()
	dir := filepath.Join(root, "skills", id)
	if err := os.MkdirAll(filepath.Join(dir, "checklists"), 0o755); err != nil {
		t.Fatal(err)
	}
	front := `---
id: ` + id + `
version: "1.0.0"
title: "Test"
description: "Test skill"
category: prevention
severity: high
applies_to: ["test"]
languages: ["*"]
token_budget:
  minimal: 100
  compact: 200
  full: 300
last_updated: "2026-01-01"
sources:
  - "test"
---

# Test

` + body + `

## Context (for humans)

placeholder

## References

placeholder
`
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte(front), 0o644); err != nil {
		t.Fatal(err)
	}
}

// readYAML returns the bytes of the named checklist file under
// root/skills/<id>/checklists/<framework>.yaml, or "" when missing.
func readYAML(t *testing.T, root, id, framework string) string {
	t.Helper()
	p := filepath.Join(root, "skills", id, "checklists", framework+".yaml")
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return string(b)
}

func TestDeriveChecklistsCreatesYAMLFromTaggedBullets(t *testing.T) {
	root := t.TempDir()
	writeSkill(t, root, "test-skill", `
## Rules (for AI agents)

### ALWAYS
- Run as a non-root user, with a numeric UID greater than 10000.
  <!-- pattern: { id: tst-non-root, severity: critical, cwe: 250 } -->
- Pin every base image by SHA256 digest.
  <!-- pattern: { id: tst-pinned-digest, framework: dockerfile_hardening } -->

### NEVER
- Embed credentials in image layers.
  <!-- pattern: { id: tst-no-secrets-in-env, cwe: 798 } -->

### KNOWN FALSE POSITIVES
- Operator pods may legitimately need cluster-admin.
  <!-- pattern: { id: tst-operator-exception } -->

- A prose-only bullet without a marker is ignored.
`)
	// Pre-create an empty (zero-byte) yaml so groupByFramework's
	// "single file under checklists/" inference fires.
	os.WriteFile(filepath.Join(root, "skills", "test-skill", "checklists", "dockerfile_hardening.yaml"), []byte(""), 0o644)

	var stdout bytes.Buffer
	if err := runDeriveChecklists(&stdout, root, "test-skill", "", false); err != nil {
		t.Fatalf("runDeriveChecklists: %v", err)
	}
	got := readYAML(t, root, "test-skill", "dockerfile_hardening")
	if got == "" {
		t.Fatal("expected YAML to be written, got empty file")
	}

	// All four tagged bullets must appear; the prose-only bullet
	// must NOT.
	wants := []string{
		"id: tst-non-root",
		"severity: critical",
		"cwe: 250",
		"id: tst-pinned-digest",
		"severity: high", // default for ALWAYS
		"id: tst-no-secrets-in-env",
		"cwe: 798",
		"id: tst-operator-exception",
		"severity: info", // default for KNOWN FALSE POSITIVES
	}
	for _, w := range wants {
		if !strings.Contains(got, w) {
			t.Errorf("YAML missing %q\n--- yaml ---\n%s", w, got)
		}
	}
	if strings.Contains(got, "prose-only bullet without a marker") {
		t.Error("untagged prose bullet leaked into YAML")
	}
	// generated_from must point back at the source skill so
	// reviewers see where the file came from.
	if !strings.Contains(got, "generated_from: skills/test-skill/SKILL.md") {
		t.Errorf("YAML missing generated_from marker\n%s", got)
	}
}

func TestDeriveChecklistsPreservesUntaggedExistingEntries(t *testing.T) {
	// MERGE semantics: a row whose id is NOT referenced by any
	// SKILL.md marker must survive. This is how human-curated rules
	// stay alongside SKILL.md-derived ones until they are tagged.
	root := t.TempDir()
	writeSkill(t, root, "test-skill", `
## Rules (for AI agents)

### ALWAYS
- A new rule landed via SKILL.md.
  <!-- pattern: { id: new-rule } -->

### NEVER

### KNOWN FALSE POSITIVES
`)
	existing := `schema_version: "1.0"
framework: dockerfile_hardening
description: "Manual rules curated by humans"
patterns:
  - id: legacy-manual-rule
    severity: high
    rule: "Stays even though no SKILL.md marker references it"
    cwe: 1357
`
	p := filepath.Join(root, "skills", "test-skill", "checklists", "dockerfile_hardening.yaml")
	if err := os.WriteFile(p, []byte(existing), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	if err := runDeriveChecklists(&stdout, root, "test-skill", "", false); err != nil {
		t.Fatalf("runDeriveChecklists: %v", err)
	}
	got := readYAML(t, root, "test-skill", "dockerfile_hardening")
	if !strings.Contains(got, "id: legacy-manual-rule") {
		t.Errorf("manual rule disappeared from YAML\n%s", got)
	}
	if !strings.Contains(got, "id: new-rule") {
		t.Errorf("new SKILL.md-derived rule missing\n%s", got)
	}
	// Top-level description must survive too.
	if !strings.Contains(got, "Manual rules curated by humans") {
		t.Errorf("description field lost during merge\n%s", got)
	}
}

func TestDeriveChecklistsCheckExitsOnDrift(t *testing.T) {
	// --check mode: re-derive in memory, compare with file. When the
	// file lacks an entry the tool would produce, exit non-zero
	// (returned as an error from runDeriveChecklists).
	root := t.TempDir()
	writeSkill(t, root, "test-skill", `
## Rules (for AI agents)

### ALWAYS
- A rule that is in SKILL.md but not yet in the YAML.
  <!-- pattern: { id: drifted-rule } -->

### NEVER

### KNOWN FALSE POSITIVES
`)
	// Empty target file → maximal drift, --check must complain.
	p := filepath.Join(root, "skills", "test-skill", "checklists", "dockerfile_hardening.yaml")
	if err := os.WriteFile(p, []byte("schema_version: \"1.0\"\npatterns: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	err := runDeriveChecklists(&stdout, root, "test-skill", "", true)
	if err == nil {
		t.Fatal("--check did not flag drift; expected error")
	}
	if !strings.Contains(err.Error(), "out of sync") {
		t.Errorf("error message does not mention drift: %v", err)
	}
	if !strings.Contains(stdout.String(), "drifted-rule") || true { // stdout has the file path, not the id
		// Drift report references the file path. Don't over-assert
		// the exact wording; just confirm we said something.
		if !strings.Contains(stdout.String(), "dockerfile_hardening") {
			t.Errorf("drift report missing target file:\n%s", stdout.String())
		}
	}
}

func TestDeriveChecklistsCheckPassesWhenInSync(t *testing.T) {
	root := t.TempDir()
	writeSkill(t, root, "test-skill", `
## Rules (for AI agents)

### ALWAYS
- Synced rule.
  <!-- pattern: { id: synced-rule } -->

### NEVER

### KNOWN FALSE POSITIVES
`)
	// First generate the file (write mode), then verify --check
	// reports clean.
	var w bytes.Buffer
	os.WriteFile(filepath.Join(root, "skills", "test-skill", "checklists", "dockerfile_hardening.yaml"), []byte(""), 0o644)
	if err := runDeriveChecklists(&w, root, "test-skill", "", false); err != nil {
		t.Fatalf("write pass: %v", err)
	}
	var check bytes.Buffer
	if err := runDeriveChecklists(&check, root, "test-skill", "", true); err != nil {
		t.Errorf("--check after write pass complained about drift: %v\n%s", err, check.String())
	}
}

func TestDeriveChecklistsRejectsDuplicateIDs(t *testing.T) {
	root := t.TempDir()
	writeSkill(t, root, "test-skill", `
## Rules (for AI agents)

### ALWAYS
- Bullet one.
  <!-- pattern: { id: same-id } -->

### NEVER
- Bullet two.
  <!-- pattern: { id: same-id } -->

### KNOWN FALSE POSITIVES
`)
	os.WriteFile(filepath.Join(root, "skills", "test-skill", "checklists", "dockerfile_hardening.yaml"), []byte(""), 0o644)
	var stdout bytes.Buffer
	err := runDeriveChecklists(&stdout, root, "test-skill", "", false)
	if err == nil {
		t.Fatal("expected duplicate-id error")
	}
	if !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("error does not mention duplicate: %v", err)
	}
}

func TestDeriveChecklistsRejectsMissingID(t *testing.T) {
	root := t.TempDir()
	writeSkill(t, root, "test-skill", `
## Rules (for AI agents)

### ALWAYS
- Missing id field in marker.
  <!-- pattern: { severity: high } -->

### NEVER

### KNOWN FALSE POSITIVES
`)
	os.WriteFile(filepath.Join(root, "skills", "test-skill", "checklists", "dockerfile_hardening.yaml"), []byte(""), 0o644)
	var stdout bytes.Buffer
	err := runDeriveChecklists(&stdout, root, "test-skill", "", false)
	if err == nil {
		t.Fatal("expected missing-id error")
	}
	if !strings.Contains(err.Error(), "id") {
		t.Errorf("error does not mention id: %v", err)
	}
}

func TestDeriveChecklistsRequiresFrameworkWhenMultipleChecklistsExist(t *testing.T) {
	root := t.TempDir()
	writeSkill(t, root, "test-skill", `
## Rules (for AI agents)

### ALWAYS
- Ambiguous bullet.
  <!-- pattern: { id: ambiguous } -->

### NEVER

### KNOWN FALSE POSITIVES
`)
	dir := filepath.Join(root, "skills", "test-skill", "checklists")
	os.WriteFile(filepath.Join(dir, "framework_a.yaml"), []byte(""), 0o644)
	os.WriteFile(filepath.Join(dir, "framework_b.yaml"), []byte(""), 0o644)
	var stdout bytes.Buffer
	err := runDeriveChecklists(&stdout, root, "test-skill", "", false)
	if err == nil {
		t.Fatal("expected framework-required error")
	}
	if !strings.Contains(err.Error(), "framework") {
		t.Errorf("error does not mention framework: %v", err)
	}
	// With --framework flag, same skill should succeed.
	if err := runDeriveChecklists(&stdout, root, "test-skill", "framework_a", false); err != nil {
		t.Fatalf("--framework flag did not unblock: %v", err)
	}
}

func TestDeriveChecklistsSeverityDefaultsBySection(t *testing.T) {
	root := t.TempDir()
	writeSkill(t, root, "test-skill", `
## Rules (for AI agents)

### ALWAYS
- An ALWAYS bullet.
  <!-- pattern: { id: rule-always } -->

### NEVER
- A NEVER bullet.
  <!-- pattern: { id: rule-never } -->

### KNOWN FALSE POSITIVES
- A KFP bullet.
  <!-- pattern: { id: rule-kfp } -->
`)
	os.WriteFile(filepath.Join(root, "skills", "test-skill", "checklists", "dockerfile_hardening.yaml"), []byte(""), 0o644)
	var stdout bytes.Buffer
	if err := runDeriveChecklists(&stdout, root, "test-skill", "", false); err != nil {
		t.Fatal(err)
	}
	got := readYAML(t, root, "test-skill", "dockerfile_hardening")

	cases := []struct{ id, sev string }{
		{"rule-always", "severity: high"},
		{"rule-never", "severity: critical"},
		{"rule-kfp", "severity: info"},
	}
	for _, c := range cases {
		// We can't simply Contains() because there are three
		// "severity: ..." lines. Find the id first, then check
		// the next severity line falls within a few lines.
		idIdx := strings.Index(got, "id: "+c.id)
		if idIdx == -1 {
			t.Errorf("YAML missing id %q\n%s", c.id, got)
			continue
		}
		windowEnd := idIdx + 200
		if windowEnd > len(got) {
			windowEnd = len(got)
		}
		window := got[idIdx:windowEnd]
		if !strings.Contains(window, c.sev) {
			t.Errorf("entry %q did not default to %q\nwindow=%q", c.id, c.sev, window)
		}
	}
}

func TestExtractPatternMarkersStripsCommentFromRule(t *testing.T) {
	// The rule text saved in YAML must NOT contain the HTML comment.
	// Sanity check on the extractor in isolation.
	root := t.TempDir()
	writeSkill(t, root, "test-skill", `
## Rules (for AI agents)

### ALWAYS
- A clean rule statement.
  <!-- pattern: { id: clean-rule } -->

### NEVER

### KNOWN FALSE POSITIVES
`)
	os.WriteFile(filepath.Join(root, "skills", "test-skill", "checklists", "dockerfile_hardening.yaml"), []byte(""), 0o644)
	var stdout bytes.Buffer
	if err := runDeriveChecklists(&stdout, root, "test-skill", "", false); err != nil {
		t.Fatal(err)
	}
	got := readYAML(t, root, "test-skill", "dockerfile_hardening")
	if strings.Contains(got, "pattern:") && strings.Contains(got, "<!--") {
		t.Errorf("YAML rule text leaked the HTML comment:\n%s", got)
	}
	if !strings.Contains(got, "rule: A clean rule statement.") {
		t.Errorf("expected rule text 'A clean rule statement.' in YAML:\n%s", got)
	}
}

// TestDeriveChecklistsPreservesLastUpdatedWhenUnchanged locks the fix for the
// date-drift regression: re-deriving a checklist whose pattern content has not
// changed must NOT re-stamp last_updated to today (which made
// `derive-checklists --check` fail unrelated PRs on a UTC-day rollover).
func TestDeriveChecklistsPreservesLastUpdatedWhenUnchanged(t *testing.T) {
	root := t.TempDir()
	writeSkill(t, root, "test-skill", `
## Rules (for AI agents)

### ALWAYS
- Pin every base image by SHA256 digest.
  <!-- pattern: { id: tst-pinned, framework: dockerfile_hardening } -->

### NEVER

### KNOWN FALSE POSITIVES
`)
	p := filepath.Join(root, "skills", "test-skill", "checklists", "dockerfile_hardening.yaml")
	os.WriteFile(p, []byte(""), 0o644)

	var out bytes.Buffer
	if err := runDeriveChecklists(&out, root, "test-skill", "", false); err != nil {
		t.Fatalf("first derive: %v", err)
	}

	// Simulate the checklist having been generated on a prior day.
	const old = "2020-01-01"
	body := readYAML(t, root, "test-skill", "dockerfile_hardening")
	rewritten := regexp.MustCompile(`(?m)^last_updated: .*$`).ReplaceAllString(body, `last_updated: "`+old+`"`)
	if rewritten == body {
		t.Fatal("could not find a last_updated line to rewrite")
	}
	os.WriteFile(p, []byte(rewritten), 0o644)

	// Re-derive with identical patterns.
	if err := runDeriveChecklists(&out, root, "test-skill", "", false); err != nil {
		t.Fatalf("second derive: %v", err)
	}
	got := readYAML(t, root, "test-skill", "dockerfile_hardening")
	if !strings.Contains(got, `last_updated: "`+old+`"`) {
		t.Errorf("last_updated must be preserved (%s) when patterns are unchanged; got:\n%s", old, got)
	}
}
