package cmd

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestValidateRejectsDanglingSkillReferenceInComplianceMapping verifies that
// the validator fails CI when a compliance mapping references a skill ID
// that has no corresponding skills/<id>/SKILL.md. This is the regression
// test for findings like the previously-broken `iam-best-practices`
// reference: a dangling ID would silently flow through to the evidence
// command as falsely-`missing` coverage.
func TestValidateRejectsDanglingSkillReferenceInComplianceMapping(t *testing.T) {
	tmp := buildMinimalLibrary(t)

	// Inject a compliance mapping that points at a skill ID that does not
	// exist in skills/.
	mapping := []byte(`schema_version: "1.0"
framework: "TEST"
version: "test-1.0"
last_updated: "2026-05-13"
controls:
  - id: "CTRL-1"
    title: "Test Control"
    description: "x"
    skills: ["api-security", "no-such-skill-xyz"]
`)
	if err := os.WriteFile(filepath.Join(tmp, "compliance", "test_mapping.yaml"), mapping, 0o644); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, err := executeRoot(t, "validate", "--path", tmp)
	if err == nil {
		t.Fatalf("expected validate to fail on dangling skill ID\nstdout:%s\nstderr:%s", stdout, stderr)
	}
	if !strings.Contains(stderr, "no-such-skill-xyz") {
		t.Errorf("expected stderr to name the dangling ID, got:\n%s", stderr)
	}
	if !strings.Contains(stderr, "unknown skill ID") {
		t.Errorf("expected 'unknown skill ID' in stderr, got:\n%s", stderr)
	}
	if !strings.Contains(stderr, "control CTRL-1") {
		t.Errorf("expected stderr to name the control, got:\n%s", stderr)
	}
}

// TestValidateRejectsDanglingSkillReferenceInProfile verifies the same
// invariant for profiles/*.yaml (both the top-level skills list and the
// per-control list).
func TestValidateRejectsDanglingSkillReferenceInProfile(t *testing.T) {
	tmp := buildMinimalLibrary(t)

	profile := []byte(`schema_version: "1.0"
name: "test-profile"
description: "x"
last_updated: "2026-05-13"
skills:
  - api-security
  - no-such-skill-in-profile
controls:
  - control_id: "CTRL-2"
    framework: "TEST"
    skills: ["another-missing-skill"]
`)
	if err := os.WriteFile(filepath.Join(tmp, "profiles", "test-profile.yaml"), profile, 0o644); err != nil {
		t.Fatal(err)
	}

	_, stderr, err := executeRoot(t, "validate", "--path", tmp)
	if err == nil {
		t.Fatalf("expected validate to fail on dangling profile references; stderr:%s", stderr)
	}
	if !strings.Contains(stderr, "no-such-skill-in-profile") {
		t.Errorf("expected stderr to name the top-level dangling ID, got:\n%s", stderr)
	}
	if !strings.Contains(stderr, "another-missing-skill") {
		t.Errorf("expected stderr to name the per-control dangling ID, got:\n%s", stderr)
	}
	if !strings.Contains(stderr, "top-level skills list") {
		t.Errorf("expected stderr to label the top-level location, got:\n%s", stderr)
	}
	if !strings.Contains(stderr, "control CTRL-2") {
		t.Errorf("expected stderr to label the per-control location, got:\n%s", stderr)
	}
}

// TestValidateRejectsPerControlSkillMissingFromProfileTopLevel verifies
// that the validator catches the profile-internal inconsistency where a
// per-control `skills:` list names a skill ID that is NOT in the
// profile's top-level `skills:` list. filterSkillsByProfile (init.go:115)
// uses ONLY the top-level list to filter the generated IDE config, so a
// per-control reference that is missing from the top-level list would be
// silently dropped — the profile would claim to cover a control while
// `init --profile <name>` produces a config that excludes the required
// skill.
func TestValidateRejectsPerControlSkillMissingFromProfileTopLevel(t *testing.T) {
	tmp := buildMinimalLibrary(t)

	// Copy a second real skill so the per-control reference is to a
	// known-good skill ID (this isolates the per-control ⊆ top-level
	// check from the dangling-ID check).
	root := repoRoot(t)
	srcSkill := filepath.Join(root, "skills", "auth-security")
	dstSkill := filepath.Join(tmp, "skills", "auth-security")
	if err := copyDir(srcSkill, dstSkill); err != nil {
		t.Fatal(err)
	}

	// auth-security IS a real skill, but the profile does NOT include
	// it in the top-level skills list — only api-security is. The
	// per-control list references auth-security, so filterSkillsByProfile
	// would silently drop it from the generated IDE config.
	profile := []byte(`schema_version: "1.0"
name: "inconsistent-profile"
description: "x"
last_updated: "2026-05-13"
skills:
  - api-security
controls:
  - control_id: "CTRL-MISSING"
    framework: "TEST"
    skills: ["api-security", "auth-security"]
`)
	if err := os.WriteFile(filepath.Join(tmp, "profiles", "inconsistent.yaml"), profile, 0o644); err != nil {
		t.Fatal(err)
	}

	_, stderr, err := executeRoot(t, "validate", "--path", tmp)
	if err == nil {
		t.Fatalf("expected validate to fail on per-control skill missing from top-level; stderr:%s", stderr)
	}
	if !strings.Contains(stderr, "auth-security") {
		t.Errorf("expected stderr to name the per-control skill ID, got:\n%s", stderr)
	}
	if !strings.Contains(stderr, "missing from the profile's top-level skills list") {
		t.Errorf("expected stderr to explain the top-level mismatch, got:\n%s", stderr)
	}
	if !strings.Contains(stderr, "control CTRL-MISSING") {
		t.Errorf("expected stderr to label the offending control, got:\n%s", stderr)
	}
	// api-security IS in the top-level list, so it should NOT be flagged
	// even though it also appears in the per-control list.
	if strings.Contains(stderr, "api-security") &&
		strings.Contains(stderr, "missing from the profile's top-level skills list") &&
		!strings.Contains(stderr, "auth-security") {
		t.Errorf("api-security is in the top-level list; should not be flagged. stderr:\n%s", stderr)
	}
}

// TestValidateReportsMalformedComplianceYAML verifies that a YAML syntax
// error in compliance/*.yaml is surfaced by `secure-vibe validate`
// instead of being silently dropped. validateRuleFiles only walks
// skills/, so without this check a broken compliance mapping would pass
// `validate` and crash later inside the evidence command at YAML load
// time. Regression test for the silent-`continue` bug in
// collectComplianceSkillRefs.
func TestValidateReportsMalformedComplianceYAML(t *testing.T) {
	tmp := buildMinimalLibrary(t)

	// Intentional YAML syntax error: unbalanced bracket inside the
	// skills list. yaml.Unmarshal will return an error which previously
	// was discarded.
	broken := []byte("controls:\n  - id: \"CTRL-1\"\n    skills: [api-security,\n")
	brokenPath := filepath.Join(tmp, "compliance", "broken_mapping.yaml")
	if err := os.WriteFile(brokenPath, broken, 0o644); err != nil {
		t.Fatal(err)
	}

	_, stderr, err := executeRoot(t, "validate", "--path", tmp)
	if err == nil {
		t.Fatalf("expected validate to fail on malformed compliance YAML; stderr:%s", stderr)
	}
	if !strings.Contains(stderr, "broken_mapping.yaml") {
		t.Errorf("expected stderr to name the broken file, got:\n%s", stderr)
	}
	if !strings.Contains(stderr, "invalid YAML") {
		t.Errorf("expected 'invalid YAML' in stderr, got:\n%s", stderr)
	}
}

// TestValidateReportsMalformedProfileYAML verifies the same invariant
// for profiles/*.yaml. validateRuleFiles only walks skills/, so a
// broken profile would otherwise pass `validate` and crash later inside
// the init / regenerate commands at profile-load time. Regression test
// for the silent-`continue` bug in collectProfileSkillRefs.
func TestValidateReportsMalformedProfileYAML(t *testing.T) {
	tmp := buildMinimalLibrary(t)

	broken := []byte("name: \"broken-profile\"\nskills:\n  - api-security\n  - [unbalanced\n")
	brokenPath := filepath.Join(tmp, "profiles", "broken-profile.yaml")
	if err := os.WriteFile(brokenPath, broken, 0o644); err != nil {
		t.Fatal(err)
	}

	_, stderr, err := executeRoot(t, "validate", "--path", tmp)
	if err == nil {
		t.Fatalf("expected validate to fail on malformed profile YAML; stderr:%s", stderr)
	}
	if !strings.Contains(stderr, "broken-profile.yaml") {
		t.Errorf("expected stderr to name the broken file, got:\n%s", stderr)
	}
	if !strings.Contains(stderr, "invalid YAML") {
		t.Errorf("expected 'invalid YAML' in stderr, got:\n%s", stderr)
	}
}

// TestValidateAcceptsAllCurrentSkillReferences is the positive-path test:
// the real repository's compliance and profile YAMLs reference only skills
// that exist. This guards against future regressions where a new mapping
// references a skill we forgot to create.
func TestValidateAcceptsAllCurrentSkillReferences(t *testing.T) {
	root := repoRoot(t)
	stdout, stderr, err := executeRoot(t, "validate", "--path", root)
	if err != nil {
		t.Fatalf("validate on real repo failed: %v\nstdout:%s\nstderr:%s", err, stdout, stderr)
	}
	if !strings.Contains(stdout, "ok:") {
		t.Errorf("expected ok line, got %q", stdout)
	}
}

// TestValidateUnwrapsAccumulatedValidateErrors verifies the CLI properly
// unwraps the multi-error returned by skill.(*Skill).Validate() — every
// sub-error must surface as its own "FAIL:" line and the final summary
// count must reflect the true number of defects (not "1" per skill).
//
// Regression for Devin Review finding on PR #42: before this change,
// `validate.go` appended `err.Error()` directly, so a skill with 3
// defects produced one "FAIL: <newline-joined>" line and the summary
// said "1 validation problem(s)".
func TestValidateUnwrapsAccumulatedValidateErrors(t *testing.T) {
	tmp := buildMinimalLibrary(t)

	// Corrupt api-security's frontmatter so it has three defects that
	// only Validate (not ParseBytes) catches: empty title, description,
	// and last_updated. The keys remain present (so the raw-map
	// presence check in ParseBytes still passes), but the values are
	// empty strings — exactly the gap Validate fills.
	skillPath := filepath.Join(tmp, "skills", "api-security", "SKILL.md")
	raw, err := os.ReadFile(skillPath)
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	for find, replace := range map[string]string{
		`title: "API Security"`: `title: ""`,
		`description: "Apply OWASP API Top 10 patterns to authentication, authorization, and input validation"`: `description: ""`,
	} {
		next := strings.Replace(body, find, replace, 1)
		if next == body {
			t.Fatalf("setup: failed to swap %q in api-security SKILL.md", find)
		}
		body = next
	}
	// last_updated carries a date that gets bumped over time — blank it
	// regardless of the current value rather than hard-coding the date.
	if next := regexp.MustCompile(`last_updated: "[^"]*"`).ReplaceAllString(body, `last_updated: ""`); next != body {
		body = next
	} else {
		t.Fatal("setup: failed to blank last_updated in api-security SKILL.md")
	}
	if err := os.WriteFile(skillPath, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	_, stderr, err := executeRoot(t, "validate", "--path", tmp)
	if err == nil {
		t.Fatalf("expected validate to fail with 3 defects; stderr:\n%s", stderr)
	}

	// Each sub-error must be on its own FAIL: line.
	wantFails := []string{
		"FAIL: " + skillPath + ": missing title",
		"FAIL: " + skillPath + ": missing description",
		"FAIL: " + skillPath + ": missing last_updated",
	}
	for _, want := range wantFails {
		if !strings.Contains(stderr, want) {
			t.Errorf("expected stderr to contain its own line %q; got:\n%s", want, stderr)
		}
	}

	// Summary count must reflect the true number of defects (>=3 — the
	// rule-file walk may report extras; what matters is it's not "1").
	if strings.Contains(err.Error(), "1 validation problem(s)") {
		t.Errorf("summary undercounted defects as '1 validation problem(s)'; got: %v\nstderr:\n%s", err, stderr)
	}
}

// buildMinimalLibrary builds a small valid library on disk with one real
// skill (api-security copied from the repo) and the minimum directory
// scaffolding needed for `validate` to run. Returns the absolute path.
func buildMinimalLibrary(t *testing.T) string {
	t.Helper()
	root := repoRoot(t)
	tmp := t.TempDir()

	for _, sub := range []string{"skills", "compliance", "profiles", "dictionaries", "vulnerabilities"} {
		if err := os.MkdirAll(filepath.Join(tmp, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	// Copy api-security as the single available skill.
	srcSkill := filepath.Join(root, "skills", "api-security")
	dstSkill := filepath.Join(tmp, "skills", "api-security")
	if err := copyDir(srcSkill, dstSkill); err != nil {
		t.Fatal(err)
	}

	return tmp
}

func copyDir(src, dst string) error {
	return filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, info.Mode())
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, info.Mode())
	})
}
