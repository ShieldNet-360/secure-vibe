package compiler

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestWriteNativeBundlesEmitsAllThreeTrees(t *testing.T) {
	skills := loadAllSkills(t)
	outDir := t.TempDir()
	if err := WriteNativeBundles(skills, outDir); err != nil {
		t.Fatalf("WriteNativeBundles: %v", err)
	}

	// Every default bundle should produce one directory per skill,
	// each containing SKILL.md + metadata.json.
	for _, bundle := range DefaultNativeBundles {
		t.Run(bundle.Subdir, func(t *testing.T) {
			root := filepath.Join(outDir, bundle.Subdir, bundle.InstallPath)
			for _, s := range skills {
				skillMD := filepath.Join(root, s.Frontmatter.ID, "SKILL.md")
				meta := filepath.Join(root, s.Frontmatter.ID, "metadata.json")
				if info, err := os.Stat(skillMD); err != nil || info.Size() == 0 {
					t.Errorf("missing or empty %s: %v", skillMD, err)
				}
				if info, err := os.Stat(meta); err != nil || info.Size() == 0 {
					t.Errorf("missing or empty %s: %v", meta, err)
				}
			}
		})
	}
}

func TestNativeSkillMDIsPortable(t *testing.T) {
	skills := loadAllSkills(t)
	if len(skills) == 0 {
		t.Skip("no skills available")
	}
	outDir := t.TempDir()
	if err := WriteNativeBundles(skills, outDir); err != nil {
		t.Fatalf("WriteNativeBundles: %v", err)
	}
	s := skills[0]
	for _, bundle := range DefaultNativeBundles {
		p := filepath.Join(outDir, bundle.Subdir, bundle.InstallPath, s.Frontmatter.ID, "SKILL.md")
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("read %s: %v", p, err)
		}
		body := string(raw)
		// Native portable frontmatter is just `name` + `description`.
		// Custom fields like severity / token_budget must live in
		// metadata.json, not in the SKILL.md frontmatter — otherwise
		// IDE parsers that enforce the portable schema (e.g. Claude
		// Code) reject the bundle.
		head := body
		if len(head) > 160 {
			head = head[:160]
		}
		if !strings.HasPrefix(body, "---\nname: ") {
			t.Errorf("%s: SKILL.md must start with portable `name:` frontmatter, got:\n%s", bundle.Subdir, head)
		}
		if !strings.Contains(body, "description: ") {
			t.Errorf("%s: SKILL.md missing `description:` frontmatter", bundle.Subdir)
		}
		for _, banned := range []string{"\nseverity:", "\nseverity: ", "\ncategory:", "\ntoken_budget:"} {
			if strings.Contains(body, banned) {
				t.Errorf("%s: SKILL.md contains non-portable frontmatter field %q (must live in metadata.json instead)", bundle.Subdir, strings.TrimPrefix(banned, "\n"))
			}
		}
	}
}

func TestNativeMetadataJSONPreservesFullFrontmatter(t *testing.T) {
	skills := loadAllSkills(t)
	if len(skills) == 0 {
		t.Skip("no skills available")
	}
	outDir := t.TempDir()
	if err := WriteNativeBundles(skills, outDir); err != nil {
		t.Fatalf("WriteNativeBundles: %v", err)
	}
	s := skills[0]
	bundle := DefaultNativeBundles[0]
	p := filepath.Join(outDir, bundle.Subdir, bundle.InstallPath, s.Frontmatter.ID, "metadata.json")
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read %s: %v", p, err)
	}
	var m nativeMetadata
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal metadata.json: %v", err)
	}
	if m.ID != s.Frontmatter.ID {
		t.Errorf("metadata.json id = %q, want %q", m.ID, s.Frontmatter.ID)
	}
	if m.Version != s.Frontmatter.Version {
		t.Errorf("metadata.json version = %q, want %q", m.Version, s.Frontmatter.Version)
	}
	if m.Severity != s.Frontmatter.Severity {
		t.Errorf("metadata.json severity = %q, want %q", m.Severity, s.Frontmatter.Severity)
	}
	if m.TokenBudget.Compact != s.Frontmatter.TokenBudget.Compact {
		t.Errorf("metadata.json token_budget.compact = %d, want %d", m.TokenBudget.Compact, s.Frontmatter.TokenBudget.Compact)
	}
}

// TestWriteNativeBundlesPurgesStaleSkillDirs locks in the cleanup
// pass at the top of writeBundle: a previously-emitted skill that no
// longer exists in skills/ must be removed when regenerating, so IDE
// auto-discovery never surfaces a stub for a renamed/deleted skill.
// Foreign directories (no SKILL.md inside) are intentionally left
// untouched.
func TestWriteNativeBundlesPurgesStaleSkillDirs(t *testing.T) {
	skills := loadAllSkills(t)
	if len(skills) == 0 {
		t.Skip("no skills available")
	}
	outDir := t.TempDir()

	// Seed a stale skill directory under each native bundle root.
	const staleID = "old-renamed-skill"
	const foreignDir = "operator-readme"
	for _, bundle := range DefaultNativeBundles {
		root := filepath.Join(outDir, bundle.Subdir, bundle.InstallPath)
		if err := os.MkdirAll(filepath.Join(root, staleID), 0o755); err != nil {
			t.Fatalf("seed stale %s: %v", root, err)
		}
		if err := os.WriteFile(filepath.Join(root, staleID, "SKILL.md"), []byte("---\nname: old-renamed-skill\ndescription: x\n---\n"), 0o644); err != nil {
			t.Fatalf("seed stale SKILL.md: %v", err)
		}
		if err := os.MkdirAll(filepath.Join(root, foreignDir), 0o755); err != nil {
			t.Fatalf("seed foreign dir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(root, foreignDir, "NOTES.md"), []byte("operator notes\n"), 0o644); err != nil {
			t.Fatalf("seed foreign file: %v", err)
		}
	}

	if err := WriteNativeBundles(skills, outDir); err != nil {
		t.Fatalf("WriteNativeBundles: %v", err)
	}

	for _, bundle := range DefaultNativeBundles {
		root := filepath.Join(outDir, bundle.Subdir, bundle.InstallPath)
		if _, err := os.Stat(filepath.Join(root, staleID)); !os.IsNotExist(err) {
			t.Errorf("%s: stale skill dir %s should have been removed, stat err=%v", root, staleID, err)
		}
		if _, err := os.Stat(filepath.Join(root, foreignDir, "NOTES.md")); err != nil {
			t.Errorf("%s: foreign dir without SKILL.md should be preserved, got err=%v", root, err)
		}
		for _, s := range skills {
			if _, err := os.Stat(filepath.Join(root, s.Frontmatter.ID, "SKILL.md")); err != nil {
				t.Errorf("%s: expected current skill %s to be present, got err=%v", root, s.Frontmatter.ID, err)
			}
		}
	}
}

// TestNativeSkillMDFrontmatterIsValidYAML parses the YAML frontmatter
// of every generated native SKILL.md and asserts both that the parse
// succeeds and that `description` round-trips to the same Go string
// that nativeDescription() returns. This catches plain-scalar regressions
// when descriptions contain ":", "—", or other YAML-significant punctuation
// — which is the case for almost every skill in the library.
func TestNativeSkillMDFrontmatterIsValidYAML(t *testing.T) {
	skills := loadAllSkills(t)
	if len(skills) == 0 {
		t.Skip("no skills available")
	}
	outDir := t.TempDir()
	if err := WriteNativeBundles(skills, outDir); err != nil {
		t.Fatalf("WriteNativeBundles: %v", err)
	}
	for _, bundle := range DefaultNativeBundles {
		for _, s := range skills {
			p := filepath.Join(outDir, bundle.Subdir, bundle.InstallPath, s.Frontmatter.ID, "SKILL.md")
			raw, err := os.ReadFile(p)
			if err != nil {
				t.Fatalf("read %s: %v", p, err)
			}
			body := string(raw)
			if !strings.HasPrefix(body, "---\n") {
				t.Fatalf("%s: missing leading `---` fence", p)
			}
			end := strings.Index(body[4:], "\n---\n")
			if end < 0 {
				t.Fatalf("%s: missing trailing `---` fence", p)
			}
			fm := body[4 : 4+end]
			var parsed struct {
				Name        string `yaml:"name"`
				Description string `yaml:"description"`
			}
			if err := yaml.Unmarshal([]byte(fm), &parsed); err != nil {
				t.Errorf("%s: frontmatter is not valid YAML: %v\n%s", p, err, fm)
				continue
			}
			if parsed.Name != s.Frontmatter.ID {
				t.Errorf("%s: parsed name = %q, want %q", p, parsed.Name, s.Frontmatter.ID)
			}
			if parsed.Description != nativeDescription(s) {
				t.Errorf("%s: parsed description = %q, want %q", p, parsed.Description, nativeDescription(s))
			}
		}
	}
}
