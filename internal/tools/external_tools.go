package tools

import (
	"os/exec"
	"sort"

	"github.com/shieldnet-360/secure-vibe/internal/skill"
)

// ExternalToolStatus is one row of the list_external_tools response: an
// external CLI a skill recommends, decorated with whether it resolves
// on the current host's PATH. The server only *discovers* tools — it
// never runs them. The agent runs the chosen tool via the shell.
type ExternalToolStatus struct {
	Name         string `json:"name"`
	Purpose      string `json:"purpose,omitempty"`
	Command      string `json:"command,omitempty"`
	SkillID      string `json:"skill_id"`
	Installed    bool   `json:"installed"`
	ResolvedPath string `json:"resolved_path,omitempty"`
}

// ListExternalToolsResult is the list_external_tools tool response.
type ListExternalToolsResult struct {
	Tools []ExternalToolStatus `json:"tools"`
}

// ListExternalTools harvests every `external_tools` entry declared in
// skill frontmatter (the single source of truth) and reports, per tool,
// whether its binary is on PATH. This is discovery only: the agent uses
// the result to decide which tool to run, then runs it itself via the
// shell — SecureVibe does not execute external binaries.
//
// Tools are de-duplicated by name (first skill to declare it wins,
// ordered by skill id) and returned sorted with installed tools first,
// then alphabetically, so the most useful options surface at the top.
func (l *Library) ListExternalTools() (*ListExternalToolsResult, error) {
	skills, err := l.loadSkills()
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	out := make([]ExternalToolStatus, 0)
	for _, s := range skills {
		for _, t := range frontmatterTools(s) {
			if t.Name == "" || seen[t.Name] {
				continue
			}
			seen[t.Name] = true
			st := ExternalToolStatus{
				Name:    t.Name,
				Purpose: t.Purpose,
				Command: t.Command,
				SkillID: s.Frontmatter.ID,
			}
			if path, err := exec.LookPath(t.Name); err == nil {
				st.Installed = true
				st.ResolvedPath = path
			}
			out = append(out, st)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Installed != out[j].Installed {
			return out[i].Installed // installed first
		}
		return out[i].Name < out[j].Name
	})
	return &ListExternalToolsResult{Tools: out}, nil
}

// frontmatterTools is a tiny accessor kept separate so the loop above
// reads cleanly and so a future change to where tools are declared has
// one place to update.
func frontmatterTools(s *skill.Skill) []skill.ExternalTool {
	return s.Frontmatter.ExternalTools
}
