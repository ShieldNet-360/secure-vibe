package compiler

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestSigmaRulesParseAndCarryRequiredFields walks every rule under
// rules/**/*.yml, parses it as YAML, and asserts the fields the CI
// pipeline and downstream consumers rely on are present:
//   - schema_version, title, id, level, status, description
//   - logsource (product/service)
//   - detection (selection + condition)
//   - at least one http reference URL
//   - at least one attack.* tag
func TestSigmaRulesParseAndCarryRequiredFields(t *testing.T) {
	rulesRoot := filepath.Join(repoRoot(t), "rules")
	if _, err := os.Stat(rulesRoot); err != nil {
		t.Fatalf("rules/ directory missing: %v", err)
	}

	var rulePaths []string
	if err := filepath.WalkDir(rulesRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if strings.HasSuffix(path, ".yml") || strings.HasSuffix(path, ".yaml") {
			rulePaths = append(rulePaths, path)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(rulePaths) == 0 {
		t.Fatal("no rule files found under rules/")
	}

	type rule struct {
		SchemaVersion string                 `yaml:"schema_version"`
		Title         string                 `yaml:"title"`
		ID            string                 `yaml:"id"`
		Status        string                 `yaml:"status"`
		Level         string                 `yaml:"level"`
		Description   string                 `yaml:"description"`
		References    []string               `yaml:"references"`
		Tags          []string               `yaml:"tags"`
		Logsource     map[string]any         `yaml:"logsource"`
		Detection     map[string]interface{} `yaml:"detection"`
	}

	for _, p := range rulePaths {
		body, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("read %s: %v", p, err)
		}
		var r rule
		if err := yaml.Unmarshal(body, &r); err != nil {
			t.Errorf("%s: parse error: %v", p, err)
			continue
		}
		if r.SchemaVersion == "" {
			t.Errorf("%s: missing schema_version", p)
		}
		if r.Title == "" {
			t.Errorf("%s: missing title", p)
		}
		if r.ID == "" {
			t.Errorf("%s: missing id", p)
		}
		if r.Status == "" {
			t.Errorf("%s: missing status", p)
		}
		if r.Level == "" {
			t.Errorf("%s: missing level", p)
		}
		if r.Description == "" {
			t.Errorf("%s: missing description", p)
		}
		if r.Logsource["product"] == nil {
			t.Errorf("%s: logsource.product missing", p)
		}
		if _, ok := r.Detection["condition"]; !ok {
			t.Errorf("%s: detection.condition missing", p)
		}
		hasSelection := false
		for k := range r.Detection {
			if strings.HasPrefix(k, "selection") {
				hasSelection = true
				break
			}
		}
		if !hasSelection {
			t.Errorf("%s: detection has no selection* clause", p)
		}
		hasHTTP := false
		for _, ref := range r.References {
			if strings.HasPrefix(ref, "http") {
				hasHTTP = true
				break
			}
		}
		if !hasHTTP {
			t.Errorf("%s: at least one http reference is required; got %v", p, r.References)
		}
		hasAttack := false
		for _, tag := range r.Tags {
			if strings.HasPrefix(tag, "attack.") {
				hasAttack = true
				break
			}
		}
		if !hasAttack {
			t.Errorf("%s: at least one attack.* tag is required; got %v", p, r.Tags)
		}
	}
}

// TestSigmaRulesCoverAllRequiredDirectories asserts every Sigma rule
// directory the library commits to ships at least 2 rules.
func TestSigmaRulesCoverAllRequiredDirectories(t *testing.T) {
	required := []string{
		"rules/cloud/aws",
		"rules/cloud/gcp",
		"rules/cloud/azure",
		"rules/endpoint/linux",
		"rules/endpoint/macos",
		"rules/endpoint/windows",
		"rules/container/k8s",
		"rules/saas/o365",
		"rules/saas/google_workspace",
		"rules/saas/salesforce",
		"rules/saas/slack",
	}
	root := repoRoot(t)
	for _, rel := range required {
		dir := filepath.Join(root, rel)
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Errorf("%s: %v", rel, err)
			continue
		}
		count := 0
		for _, e := range entries {
			if !e.IsDir() && (strings.HasSuffix(e.Name(), ".yml") || strings.HasSuffix(e.Name(), ".yaml")) {
				count++
			}
		}
		if count < 2 {
			t.Errorf("%s: expected at least 2 Sigma rules, got %d", rel, count)
		}
	}
}
