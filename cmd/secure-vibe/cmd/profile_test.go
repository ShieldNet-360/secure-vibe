package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitWithProfile(t *testing.T) {
	root := repoRoot(t)
	tmp := t.TempDir()
	stdout, _, err := executeRoot(t,
		"init",
		"--library", root,
		"--tool", "universal",
		"--profile", "financial-services",
		"--out", tmp,
		"--no-prompt",
	)
	if err != nil {
		t.Fatalf("init returned error: %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, "wrote") {
		t.Errorf("unexpected stdout: %s", stdout)
	}
}

func TestInitWithUnknownProfile(t *testing.T) {
	root := repoRoot(t)
	tmp := t.TempDir()
	_, _, err := executeRoot(t,
		"init",
		"--library", root,
		"--tool", "universal",
		"--profile", "no-such-profile",
		"--out", tmp,
		"--no-prompt",
	)
	if err == nil {
		t.Fatal("expected error for unknown profile")
	}
}

// TestInitSkillsAndProfileIntersect pins down the documented behavior
// for the case where both --skills and --profile are set: the resulting
// skill set is the INTERSECTION (both filters apply), not an override
// where --skills silently wins.
//
// The configure.go flag help text now reads "narrows the --profile
// selection when both are set"; this test is the runtime guarantee that
// matches it. A regression that flipped to override semantics (e.g. early
// return after the --skills filter) would silently drop the --profile
// constraint and this test would fail on the resulting output.
func TestInitSkillsAndProfileIntersect(t *testing.T) {
	root := repoRoot(t)
	tmp := t.TempDir()

	// financial-services profile includes api-security and auth-security
	// among others, but NOT mobile-security or ml-security (those are real
	// skills in the repo but not in this profile).
	//
	// We pass --skills "api-security,mobile-security":
	//   - api-security:    in --skills AND in profile  → intersection includes
	//   - mobile-security: in --skills but NOT in profile → intersection excludes
	//   - auth-security:   NOT in --skills but in profile → intersection excludes
	//
	// Override semantics (where --skills wins, profile is ignored)
	// would (incorrectly) include mobile-security and exclude
	// auth-security. Intersection semantics give a third, distinct
	// shape: api-security only. That makes the two semantics
	// distinguishable from the rendered output.
	_, _, err := executeRoot(t,
		"init",
		"--library", root,
		"--tool", "universal",
		"--profile", "financial-services",
		"--skills", "api-security,mobile-security",
		"--out", tmp,
		"--no-prompt",
	)
	if err != nil {
		t.Fatalf("init returned error: %v", err)
	}

	body, err := os.ReadFile(filepath.Join(tmp, "SECURITY-SKILLS.md"))
	if err != nil {
		t.Fatal(err)
	}
	out := string(body)

	// api-security is in both --skills and --profile financial-services
	// → included.
	if !strings.Contains(out, "api-security") {
		t.Errorf("api-security should be in the intersection (--skills AND --profile)")
	}
	// mobile-security IS a real skill and IS in --skills, but it is NOT
	// in the financial-services profile. Intersection semantics MUST
	// exclude it; override semantics would (wrongly) include it.
	if strings.Contains(out, "mobile-security") {
		t.Errorf("mobile-security is not in the financial-services profile; intersection should exclude it. Override semantics would (wrongly) include it.")
	}
	// auth-security IS in the financial-services profile but is NOT in
	// --skills. Intersection MUST exclude it (override would too — this
	// covers the half of the intersection that is symmetric).
	if strings.Contains(out, "auth-security") {
		t.Errorf("auth-security is in the profile but not in --skills; intersection should exclude it")
	}
}
