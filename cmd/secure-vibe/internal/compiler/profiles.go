// Package compiler — profiles.go: enterprise compliance profile registry.
package compiler

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/shieldnet-360/secure-vibe/internal/skill"
)

// Profile bundles a curated skill set plus compliance-framework references for
// a particular vertical (financial services, healthcare, government).
type Profile struct {
	Name          string   `yaml:"name"`
	Description   string   `yaml:"description"`
	SchemaVersion string   `yaml:"schema_version"`
	LastUpdated   string   `yaml:"last_updated"`
	Skills        []string `yaml:"skills"`
	Frameworks    []string `yaml:"frameworks"`
	Controls      []struct {
		ControlID string   `yaml:"control_id"`
		Framework string   `yaml:"framework"`
		Skills    []string `yaml:"skills"`
	} `yaml:"controls"`
}

// LoadProfile reads a single profile YAML file from `profiles/<name>.yaml`.
func LoadProfile(libraryRoot, name string) (*Profile, error) {
	if name == "" {
		return nil, fmt.Errorf("profile name is required")
	}
	p := filepath.Join(libraryRoot, "profiles", name+".yaml")
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("read profile %s: %w", name, err)
	}
	var prof Profile
	if err := yaml.Unmarshal(data, &prof); err != nil {
		return nil, fmt.Errorf("parse profile %s: %w", name, err)
	}
	if prof.SchemaVersion == "" {
		return nil, fmt.Errorf("profile %s missing schema_version", name)
	}
	if prof.Name == "" {
		prof.Name = name
	}
	return &prof, nil
}

// ListProfiles returns the names of all available profile files under
// `profiles/`.
func ListProfiles(libraryRoot string) ([]string, error) {
	dir := filepath.Join(libraryRoot, "profiles")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		if !strings.HasSuffix(n, ".yaml") && !strings.HasSuffix(n, ".yml") {
			continue
		}
		names = append(names, strings.TrimSuffix(strings.TrimSuffix(n, ".yml"), ".yaml"))
	}
	sort.Strings(names)
	return names, nil
}

// FilterSkillsByProfile returns only those skills whose ID is listed in the
// profile's Skills set. If the profile has no Skills entries, all skills pass
// through unchanged.
//
// The returned slice is a freshly-allocated copy; the caller's allSkills
// slice and its backing array are never mutated. This contract is
// load-bearing for callers that pass the same slice through multiple
// filter stages (init.go runs --skills and --profile filters back-to-back
// on the same input).
func FilterSkillsByProfile(allSkills []*skill.Skill, profile *Profile) []*skill.Skill {
	if profile == nil || len(profile.Skills) == 0 {
		return allSkills
	}
	allowed := make(map[string]bool, len(profile.Skills))
	for _, s := range profile.Skills {
		allowed[s] = true
	}
	out := make([]*skill.Skill, 0, len(allSkills))
	for _, s := range allSkills {
		if allowed[s.Frontmatter.ID] {
			out = append(out, s)
		}
	}
	return out
}
