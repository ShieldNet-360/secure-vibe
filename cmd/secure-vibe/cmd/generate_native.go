package cmd

import (
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/shieldnet-360/secure-vibe/cmd/secure-vibe/internal/compiler"
	"github.com/shieldnet-360/secure-vibe/internal/skill"
)

// generateNativeCmd emits the IDE-native skill bundles under
// dist/agent-skills/, dist/copilot-skills/, dist/claude-skills/. Each
// bundle contains one directory per skill with a SKILL.md whose
// frontmatter is the portable `name` + `description` shape, plus a
// metadata.json carrying the full custom frontmatter.
//
// `secure-vibe dev regenerate` invokes this for every full run; this
// dedicated command exists for operators who want to refresh the
// native bundles without regenerating the per-tool dist/ files.
func generateNativeCmd() *cobra.Command {
	var path string
	c := &cobra.Command{
		Use:   "generate-native",
		Short: "Generate native skill bundles under dist/agent-skills, dist/copilot-skills, dist/claude-skills",
		Long: `Generate the native skill bundles consumed by Claude Code, GitHub
Copilot, and the cross-tool agent-skills convention.

For each skill in skills/, this writes three on-disk trees:

  dist/agent-skills/.agents/skills/<skill-id>/SKILL.md
  dist/copilot-skills/.github/skills/<skill-id>/SKILL.md
  dist/claude-skills/.claude/skills/<skill-id>/SKILL.md

plus a companion metadata.json next to each SKILL.md preserving the
full custom frontmatter (severity, token budgets, etc.).
`,
		RunE: func(c *cobra.Command, args []string) error {
			abs, err := filepath.Abs(path)
			if err != nil {
				return err
			}
			skills, err := skill.LoadAll(filepath.Join(abs, "skills"))
			if err != nil {
				return err
			}
			outDir := filepath.Join(abs, "dist")
			if err := compiler.WriteNativeBundles(skills, outDir); err != nil {
				return err
			}
			out := c.OutOrStdout()
			for _, bundle := range compiler.DefaultNativeBundles {
				rel := filepath.Join("dist", bundle.Subdir, bundle.InstallPath)
				fmt.Fprintf(out, "%-15s -> %s/<skill-id>/ (%d skills)\n", bundle.Subdir, rel, len(skills))
			}
			return nil
		},
	}
	c.Flags().StringVar(&path, "path", ".", "library root")
	return c
}
