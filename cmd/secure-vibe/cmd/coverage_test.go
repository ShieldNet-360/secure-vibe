package cmd

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/shieldnet-360/secure-vibe/internal/tools"
)

// TestCoverageDeterministicMarkersMatchScanner asserts, from the CLI
// side, that container-security's `check: deterministic` markers map
// 1:1 to the rule ids the dockerfile scanner actually emits. This is
// the same contract the internal/tools trace test guards, checked here
// against the live DockerfileRuleIDs() the coverage command consumes.
func TestCoverageDeterministicMarkersMatchScanner(t *testing.T) {
	root := repoRoot(t)
	markers, err := readCoverageMarkers(filepath.Join(root, "skills", "container-security", "SKILL.md"))
	if err != nil {
		t.Fatal(err)
	}
	det := map[string]bool{}
	for _, m := range markers {
		if m.Check == "deterministic" {
			det[m.ID] = true
		}
	}
	if len(det) == 0 {
		t.Fatal("no deterministic markers found in container-security SKILL.md")
	}
	goIDs := tools.DockerfileRuleIDs()
	for id := range det {
		if !goIDs[id] {
			t.Errorf("deterministic marker %q has no matching dockerfile scanner rule", id)
		}
	}
	for id := range goIDs {
		if !det[id] {
			t.Errorf("dockerfile scanner rule %q has no `check: deterministic` marker", id)
		}
	}
}

// TestCoverageCommandReports smoke-tests the coverage command output.
func TestCoverageCommandReports(t *testing.T) {
	root := repoRoot(t)
	stdout, _, err := executeRoot(t, "coverage", "container-security", "--path", root)
	if err != nil {
		t.Fatalf("coverage: %v", err)
	}
	for _, want := range []string{
		"ENFORCED BY GATE (deterministic)",
		"AGENT-REASONED (llm",
		"dkr-missing-user-directive",
		"dkr-eol-base-image",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("coverage output missing %q\n---\n%s", want, stdout)
		}
	}
}
