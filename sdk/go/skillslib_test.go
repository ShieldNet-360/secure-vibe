package skillslib

import (
	"path/filepath"
	"testing"

	"github.com/shieldnet-360/secure-vibe/internal/skill"
)

// repoRoot finds the repo root by walking up until go.mod is found.
func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	for dir := wd; dir != "/"; dir = filepath.Dir(dir) {
		if _, err := filepath.Glob(filepath.Join(dir, "go.mod")); err == nil {
			if matches, _ := filepath.Glob(filepath.Join(dir, "go.mod")); len(matches) > 0 {
				if filepath.Base(dir) == "secure-vibe" || hasSkillsDir(dir) {
					return dir
				}
			}
		}
	}
	t.Fatalf("could not find repo root")
	return ""
}

func hasSkillsDir(dir string) bool {
	matches, _ := filepath.Glob(filepath.Join(dir, "skills"))
	return len(matches) > 0
}

func TestLoadSkillSecretDetection(t *testing.T) {
	root := repoRoot(t)
	s, err := LoadSkill(filepath.Join(root, "skills", "secret-detection", "SKILL.md"))
	if err != nil {
		t.Fatal(err)
	}
	if s.Frontmatter.ID != "secret-detection" {
		t.Errorf("unexpected id %q", s.Frontmatter.ID)
	}
	if errs := Validate(s); len(errs) != 0 {
		t.Errorf("expected no validation errors, got %v", errs)
	}
}

func TestLoadAllSkills(t *testing.T) {
	root := repoRoot(t)
	all, err := LoadAll(filepath.Join(root, "skills"))
	if err != nil {
		t.Fatal(err)
	}
	if len(all) < 20 {
		t.Errorf("expected >=20 skills, got %d", len(all))
	}
}

func TestExtractTiers(t *testing.T) {
	root := repoRoot(t)
	s, err := LoadSkill(filepath.Join(root, "skills", "secret-detection", "SKILL.md"))
	if err != nil {
		t.Fatal(err)
	}
	min := Extract(s, TierMinimal)
	compact := Extract(s, TierCompact)
	full := Extract(s, TierFull)
	if len(min) == 0 || len(compact) == 0 || len(full) == 0 {
		t.Fatal("expected non-empty extracts")
	}
	if len(compact) < len(min) {
		t.Errorf("compact (%d) should be >= minimal (%d)", len(compact), len(min))
	}
	if len(full) < len(compact) {
		t.Errorf("full (%d) should be >= compact (%d)", len(full), len(compact))
	}
}

func TestValidateNilSkill(t *testing.T) {
	if errs := Validate(nil); len(errs) != 1 {
		t.Errorf("expected 1 error for nil, got %v", errs)
	}
}

// TestValidateMatchesCrossSDKContract feeds a deliberately-malformed,
// programmatically-constructed Skill into Validate() and asserts every
// check that the Python and TypeScript SDKs perform is also caught here.
//
// Before this PR, the Go SDK's Validate() only checked ID + category +
// severity (it delegated to internal/skill.(*Skill).Validate()), so a
// Skill with empty title, invalid semver, no languages, zero
// token_budget values, missing last_updated, and an empty body would
// pass the Go SDK while failing both other SDKs. This test pins down the
// cross-SDK contract that all three SDKs must report the same set of
// violations for the same input shape.
func TestValidateMatchesCrossSDKContract(t *testing.T) {
	bad := &Skill{
		Frontmatter: Frontmatter{
			ID:          "Bad ID!", // not lowercase, has space
			Version:     "1.0",     // not semver
			Title:       "",
			Description: "",
			Category:    "nope", // not in AllowedCategories
			Severity:    "huge", // not in AllowedSeverities
			Languages:   nil,    // empty
			TokenBudget: skill.TokenBudget{Minimal: 0, Compact: 0, Full: 0},
			LastUpdated: "",
		},
		// Body is zero-value: all parsed sections empty.
	}
	errs := Validate(bad)
	want := []string{
		"id",
		"version",
		"title is required",
		"description is required",
		"category",
		"severity",
		"languages",
		"token_budget.minimal",
		"token_budget.compact",
		"token_budget.full",
		"last_updated is required",
		"SKILL body is empty",
	}
	if len(errs) != len(want) {
		t.Errorf("expected %d errors, got %d: %v", len(want), len(errs), errs)
	}
	for _, fragment := range want {
		if !errsContain(errs, fragment) {
			t.Errorf("missing expected error containing %q in: %v", fragment, errs)
		}
	}
}

// TestValidateAcceptsRealSkill is the positive-path check for the
// extended Validate(): the canonical secret-detection skill on disk
// must pass with zero errors.
func TestValidateAcceptsRealSkill(t *testing.T) {
	root := repoRoot(t)
	s, err := LoadSkill(filepath.Join(root, "skills", "secret-detection", "SKILL.md"))
	if err != nil {
		t.Fatal(err)
	}
	if errs := Validate(s); len(errs) != 0 {
		t.Errorf("real skill should pass validation, got %v", errs)
	}
}

func errsContain(errs []error, fragment string) bool {
	for _, e := range errs {
		if e != nil && contains(e.Error(), fragment) {
			return true
		}
	}
	return false
}

func contains(haystack, needle string) bool {
	if needle == "" {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
