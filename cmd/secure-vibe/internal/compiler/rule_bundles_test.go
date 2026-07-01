package compiler

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestWriteRuleBundlesEmitsPerSkillFiles(t *testing.T) {
	skills := loadAllSkills(t)
	if len(skills) == 0 {
		t.Skip("no skills available")
	}
	outDir := t.TempDir()
	if err := WriteRuleBundles(skills, outDir); err != nil {
		t.Fatalf("WriteRuleBundles: %v", err)
	}
	cursorDir := filepath.Join(outDir, "cursor-rules", ".cursor", "rules")
	copilotDir := filepath.Join(outDir, "copilot-rules", ".github", "instructions")
	devinDir := filepath.Join(outDir, "devin-rules", ".devin", "rules")
	for _, s := range skills {
		mdc := filepath.Join(cursorDir, s.Frontmatter.ID+".mdc")
		ins := filepath.Join(copilotDir, s.Frontmatter.ID+".instructions.md")
		dvn := filepath.Join(devinDir, s.Frontmatter.ID+".md")
		for _, p := range []string{mdc, ins, dvn} {
			if info, err := os.Stat(p); err != nil || info.Size() == 0 {
				t.Errorf("missing/empty %s: %v", p, err)
			}
		}
	}
}

// TestDevinBundleFormat confirms the Devin bundle is emitted under
// .devin/rules with a trigger frontmatter (glob | model_decision) and a
// Devin-branded generated-by banner.
func TestDevinBundleFormat(t *testing.T) {
	skills := loadAllSkills(t)
	if len(skills) == 0 {
		t.Skip("no skills available")
	}
	outDir := t.TempDir()
	if err := WriteRuleBundles(skills, outDir); err != nil {
		t.Fatalf("WriteRuleBundles: %v", err)
	}
	devinDir := filepath.Join(outDir, "devin-rules", ".devin", "rules")
	for _, s := range skills {
		id := s.Frontmatter.ID
		dvn := readFile(t, filepath.Join(devinDir, id+".md"))
		fm := frontmatter(dvn)
		if !strings.Contains(fm, "trigger:") {
			t.Errorf("%s: devin rule missing trigger frontmatter:\n%s", id, firstLines(dvn, 5))
		}
		if !strings.Contains(dvn, "SecureVibe rule for Devin") {
			t.Errorf("%s: devin rule missing Devin-branded banner:\n%s", id, firstLines(dvn, 3))
		}
	}
}

// TestRuleBundleScoping checks the token-optimization contract: a
// language-specific skill auto-attaches by glob, while a broad (languages:
// ["*"]) skill drops globs (Cursor Agent-Requested) and applies to "**"
// (Copilot).
func TestRuleBundleScoping(t *testing.T) {
	skills := loadAllSkills(t)
	byID := map[string]bool{}
	for _, s := range skills {
		byID[s.Frontmatter.ID] = true
	}
	for _, id := range []string{"container-security", "secret-detection"} {
		if !byID[id] {
			t.Skipf("required skill %q not present", id)
		}
	}
	outDir := t.TempDir()
	if err := WriteRuleBundles(skills, outDir); err != nil {
		t.Fatalf("WriteRuleBundles: %v", err)
	}

	// container-security: language-specific -> has globs in .mdc.
	csMdc := readFile(t, filepath.Join(outDir, "cursor-rules", ".cursor", "rules", "container-security.mdc"))
	if !strings.Contains(csMdc, "\nglobs: ") {
		t.Errorf("container-security.mdc should carry a globs line; got:\n%s", firstLines(csMdc, 5))
	}
	if !strings.Contains(csMdc, "Dockerfile") {
		t.Errorf("container-security.mdc globs should include a Dockerfile pattern")
	}

	// secret-detection: broad -> NO globs line; copilot applyTo "**".
	sdMdc := readFile(t, filepath.Join(outDir, "cursor-rules", ".cursor", "rules", "secret-detection.mdc"))
	if strings.Contains(sdMdc, "\nglobs: ") {
		t.Errorf("secret-detection.mdc (broad) should NOT carry globs; got:\n%s", firstLines(sdMdc, 5))
	}
	sdIns := readFile(t, filepath.Join(outDir, "copilot-rules", ".github", "instructions", "secret-detection.instructions.md"))
	var fm struct {
		ApplyTo string `yaml:"applyTo"`
	}
	if err := yaml.Unmarshal([]byte(frontmatter(sdIns)), &fm); err != nil {
		t.Fatalf("secret-detection.instructions.md frontmatter not valid YAML: %v", err)
	}
	if fm.ApplyTo != "**" {
		t.Errorf("secret-detection applyTo = %q, want \"**\"", fm.ApplyTo)
	}
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read %s: %v", p, err)
	}
	return string(b)
}

func frontmatter(s string) string {
	parts := strings.SplitN(s, "---", 3)
	if len(parts) < 3 {
		return ""
	}
	return parts[1]
}

func firstLines(s string, n int) string {
	lines := strings.SplitN(s, "\n", n+1)
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}
