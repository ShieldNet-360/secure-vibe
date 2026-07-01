package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewCmdCreatesSkill(t *testing.T) {
	tmp := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tmp, "skills"), 0o755); err != nil {
		t.Fatal(err)
	}

	stdout, _, err := executeRoot(t,
		"new", "demo-skill",
		"--library", tmp,
		"--title", "Demo Skill",
		"--description", "A demonstration skill.",
		"--category", "prevention",
		"--severity", "medium",
		"--languages", "go,python",
		"--rules-kind", "rules",
	)
	if err != nil {
		t.Fatalf("new returned error: %v", err)
	}
	if !strings.Contains(stdout, "Created skills/demo-skill/") {
		t.Errorf("unexpected stdout: %s", stdout)
	}

	skillDir := filepath.Join(tmp, "skills", "demo-skill")
	for _, name := range []string{"SKILL.md", "rules/patterns.json", "tests/corpus.json"} {
		if _, err := os.Stat(filepath.Join(skillDir, name)); err != nil {
			t.Errorf("expected %s to exist: %v", name, err)
		}
	}

	body, err := os.ReadFile(filepath.Join(skillDir, "SKILL.md"))
	if err != nil {
		t.Fatal(err)
	}
	bodyStr := string(body)
	if !strings.Contains(bodyStr, "id: demo-skill") {
		t.Errorf("SKILL.md missing id")
	}
	if !strings.Contains(bodyStr, "category: prevention") {
		t.Errorf("SKILL.md missing category")
	}
	if !strings.Contains(bodyStr, "severity: medium") {
		t.Errorf("SKILL.md missing severity")
	}
}

func TestNewCmdRejectsBadID(t *testing.T) {
	tmp := t.TempDir()
	_, _, err := executeRoot(t,
		"new", "BadID",
		"--library", tmp,
	)
	if err == nil {
		t.Fatal("expected error for invalid id")
	}
}

func TestNewCmdChecklistsKind(t *testing.T) {
	tmp := t.TempDir()
	_, _, err := executeRoot(t,
		"new", "demo-check",
		"--library", tmp,
		"--rules-kind", "checklists",
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(tmp, "skills", "demo-check", "checklists", "checklist.yaml")); err != nil {
		t.Errorf("expected checklist file: %v", err)
	}
}
