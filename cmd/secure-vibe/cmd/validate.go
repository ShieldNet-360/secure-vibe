package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/shieldnet-360/secure-vibe/cmd/secure-vibe/internal/token"
	"github.com/shieldnet-360/secure-vibe/internal/skill"
)

func validateCmd() *cobra.Command {
	var path string
	c := &cobra.Command{
		Use:   "validate",
		Short: "Validate SKILL.md frontmatter, rule files, and token budgets",
		RunE: func(c *cobra.Command, args []string) error {
			abs, err := filepath.Abs(path)
			if err != nil {
				return err
			}
			skills, err := skill.LoadAll(filepath.Join(abs, "skills"))
			if err != nil {
				return err
			}

			var problems []string
			for _, s := range skills {
				if err := s.Validate(); err != nil {
					// Validate returns errors.Join(...) when a skill has
					// multiple defects. Unwrap into individual sub-errors so
					// each gets its own "FAIL:" line and the problem count
					// reflects the true number of defects (not "1" per
					// skill).
					if joined, ok := err.(interface{ Unwrap() []error }); ok {
						for _, sub := range joined.Unwrap() {
							problems = append(problems, sub.Error())
						}
					} else {
						problems = append(problems, err.Error())
					}
				}
				expected := s.Frontmatter.ID
				actual := filepath.Base(filepath.Dir(s.Path))
				if expected != actual {
					problems = append(problems, fmt.Sprintf("%s: frontmatter id %q does not match directory %q", s.Path, expected, actual))
				}
				if rp := s.Frontmatter.RulesPath; rp != "" {
					full := filepath.Join(filepath.Dir(s.Path), rp)
					if _, err := os.Stat(full); err != nil {
						problems = append(problems, fmt.Sprintf("%s: rules_path %q not found", s.Path, rp))
					}
				}
				for _, tier := range []skill.Tier{skill.TierMinimal, skill.TierCompact, skill.TierFull} {
					limit := budgetFor(s, tier)
					if limit <= 0 {
						problems = append(problems, fmt.Sprintf("%s: missing positive %s budget", s.Path, tier))
						continue
					}
					tc, err := token.Count(s.Extract(tier))
					if err != nil {
						return err
					}
					if tc.Claude > limit {
						problems = append(problems, fmt.Sprintf(
							"%s: %s tier %d tokens (claude) exceeds declared budget %d",
							s.Path, tier, tc.Claude, limit,
						))
					}
				}
			}

			if err := validateRuleFiles(abs, &problems); err != nil {
				return err
			}

			knownIDs := make(map[string]bool, len(skills))
			for _, s := range skills {
				knownIDs[s.Frontmatter.ID] = true
			}
			if err := validateSkillReferences(abs, knownIDs, &problems); err != nil {
				return err
			}

			if len(problems) > 0 {
				for _, p := range problems {
					fmt.Fprintln(c.ErrOrStderr(), "FAIL:", p)
				}
				return fmt.Errorf("%d validation problem(s)", len(problems))
			}
			fmt.Fprintf(c.OutOrStdout(), "ok: %d skills validated\n", len(skills))
			return nil
		},
	}
	c.Flags().StringVar(&path, "path", ".", "library root")
	return c
}

func budgetFor(s *skill.Skill, tier skill.Tier) int {
	switch tier {
	case skill.TierMinimal:
		return s.Frontmatter.TokenBudget.Minimal
	case skill.TierCompact:
		return s.Frontmatter.TokenBudget.Compact
	case skill.TierFull:
		return s.Frontmatter.TokenBudget.Full
	}
	return 0
}

func validateRuleFiles(root string, problems *[]string) error {
	return filepath.Walk(filepath.Join(root, "skills"), func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		switch strings.ToLower(filepath.Ext(p)) {
		case ".json":
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			var v any
			if err := json.Unmarshal(b, &v); err != nil {
				*problems = append(*problems, fmt.Sprintf("%s: invalid JSON: %v", p, err))
				return nil
			}
			validateSchemaShape(p, v, problems)
		case ".yaml", ".yml":
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			var v any
			if err := yaml.Unmarshal(b, &v); err != nil {
				*problems = append(*problems, fmt.Sprintf("%s: invalid YAML: %v", p, err))
				return nil
			}
			validateSchemaShape(p, v, problems)
		}
		return nil
	})
}

// validateSchemaShape enforces the lightweight rule-file conventions used
// across the library: every rule file should declare a schema_version and a
// last_updated date.
func validateSchemaShape(path string, v any, problems *[]string) {
	m, ok := v.(map[string]any)
	if !ok {
		// Bare arrays or scalars are allowed; structural rule files only.
		return
	}
	if _, ok := m["schema_version"]; !ok {
		*problems = append(*problems, fmt.Sprintf("%s: rule file missing %q", path, "schema_version"))
	}
}

// validateSkillReferences cross-checks every skill ID referenced in
// compliance/*.yaml and profiles/*.yaml against the set of skill IDs that
// actually exist under skills/. A dangling reference would cause the
// evidence command to report falsely-`missing` coverage, so the validator
// fails CI on any unknown ID.
func validateSkillReferences(root string, knownIDs map[string]bool, problems *[]string) error {
	check := func(yamlPath string, refs []skillRef) {
		for _, r := range refs {
			if r.skillID == "" {
				continue
			}
			if !knownIDs[r.skillID] {
				*problems = append(*problems, fmt.Sprintf(
					"%s: %s references unknown skill ID %q (no skills/%s/SKILL.md)",
					yamlPath, r.where, r.skillID, r.skillID,
				))
			}
		}
	}

	compDir := filepath.Join(root, "compliance")
	if refs, err := collectComplianceSkillRefs(compDir, problems); err != nil {
		return err
	} else {
		for path, controlRefs := range refs {
			check(path, controlRefs)
		}
	}

	profDir := filepath.Join(root, "profiles")
	profRefs, err := collectProfileSkillRefs(profDir, problems)
	if err != nil {
		return err
	}
	for path, pr := range profRefs {
		check(path, pr.topLevelRefs)
		check(path, pr.perControl)
		// Per-control ⊆ top-level: every skill ID referenced by a
		// per-control list must also appear in the profile's top-level
		// skills list. filterSkillsByProfile (init.go:115) uses only the
		// top-level list to filter generated IDE configs, so a per-control
		// skill that is missing from the top-level list would be silently
		// excluded from `secure-vibe init --profile <name>` output even
		// though the profile declares it covers the relevant controls.
		for _, r := range pr.perControl {
			if r.skillID == "" {
				continue
			}
			if !pr.topLevel[r.skillID] {
				*problems = append(*problems, fmt.Sprintf(
					"%s: %s references skill %q which is missing from the profile's top-level skills list "+
						"(filterSkillsByProfile uses only the top-level list, so `init --profile` would silently exclude this skill from generated IDE configs)",
					path, r.where, r.skillID,
				))
			}
		}
	}

	return nil
}

// skillRef captures one referenced skill ID and a human-readable label of
// where in the YAML it came from (control id, profile name, etc.).
type skillRef struct {
	skillID string
	where   string
}

// collectComplianceSkillRefs walks compliance/<framework>_mapping.yaml files
// and returns, per file, the skill IDs referenced under each control.
//
// YAML parse errors are appended to `problems` rather than silently dropped:
// validateRuleFiles only walks skills/, so compliance/ syntax errors would
// otherwise pass `secure-vibe dev validate` and crash later in the evidence
// command at YAML load time.
func collectComplianceSkillRefs(dir string, problems *[]string) (map[string][]skillRef, error) {
	out := make(map[string][]skillRef)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil
		}
		return nil, err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}
		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		var mapping struct {
			Controls []struct {
				ID     string   `yaml:"id"`
				Skills []string `yaml:"skills"`
			} `yaml:"controls"`
		}
		if err := yaml.Unmarshal(data, &mapping); err != nil {
			*problems = append(*problems, fmt.Sprintf("%s: invalid YAML: %v", path, err))
			continue
		}
		refs := make([]skillRef, 0)
		for _, ctrl := range mapping.Controls {
			for _, sid := range ctrl.Skills {
				refs = append(refs, skillRef{
					skillID: strings.TrimSpace(sid),
					where:   fmt.Sprintf("control %s", ctrl.ID),
				})
			}
		}
		out[path] = refs
	}
	return out, nil
}

// profileSkillRefs captures both the top-level skill IDs declared by a
// profile and the per-control skill IDs referenced by its controls. The
// distinction matters because filterSkillsByProfile uses only the
// top-level list to filter generated IDE configs (init.go:115).
type profileSkillRefs struct {
	// topLevel is the set of skill IDs declared in the profile's
	// top-level `skills:` list.
	topLevel map[string]bool
	// topLevelRefs is the same data as `topLevel` but in parallel-list
	// form, used for the dangling-skill-ID check.
	topLevelRefs []skillRef
	// perControl is the list of skill IDs referenced by each control,
	// with the control ID stored in `where`.
	perControl []skillRef
}

// collectProfileSkillRefs walks profiles/*.yaml files and returns, per file,
// the skill IDs referenced in both the top-level `skills:` list and the
// per-control `skills:` lists, preserving the distinction so callers can
// enforce the per-control ⊆ top-level invariant.
//
// YAML parse errors are appended to `problems` rather than silently dropped:
// validateRuleFiles only walks skills/, so profiles/ syntax errors would
// otherwise pass `secure-vibe dev validate` and crash later in the init /
// regenerate commands at profile-load time.
func collectProfileSkillRefs(dir string, problems *[]string) (map[string]profileSkillRefs, error) {
	out := make(map[string]profileSkillRefs)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil
		}
		return nil, err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}
		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		var prof struct {
			Name     string   `yaml:"name"`
			Skills   []string `yaml:"skills"`
			Controls []struct {
				ControlID string   `yaml:"control_id"`
				Skills    []string `yaml:"skills"`
			} `yaml:"controls"`
		}
		if err := yaml.Unmarshal(data, &prof); err != nil {
			*problems = append(*problems, fmt.Sprintf("%s: invalid YAML: %v", path, err))
			continue
		}
		psr := profileSkillRefs{topLevel: map[string]bool{}}
		for _, sid := range prof.Skills {
			sid = strings.TrimSpace(sid)
			if sid != "" {
				psr.topLevel[sid] = true
			}
			psr.topLevelRefs = append(psr.topLevelRefs, skillRef{
				skillID: sid,
				where:   "top-level skills list",
			})
		}
		for _, ctrl := range prof.Controls {
			for _, sid := range ctrl.Skills {
				psr.perControl = append(psr.perControl, skillRef{
					skillID: strings.TrimSpace(sid),
					where:   fmt.Sprintf("control %s", ctrl.ControlID),
				})
			}
		}
		out[path] = psr
	}
	return out, nil
}
