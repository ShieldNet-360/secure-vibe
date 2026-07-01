package cmd

import (
	"fmt"
	"path/filepath"
	"sort"

	"github.com/spf13/cobra"

	"github.com/shieldnet-360/secure-vibe/cmd/secure-vibe/internal/compiler"
	"github.com/shieldnet-360/secure-vibe/internal/skill"
)

func regenerateCmd() *cobra.Command {
	var path, tool, budget, profileName string
	var fullInline, legacy, skipNative bool
	c := &cobra.Command{
		Use:   "regenerate",
		Short: "Rebuild dist/ files from the current skills/",
		RunE: func(c *cobra.Command, args []string) error {
			abs, err := filepath.Abs(path)
			if err != nil {
				return err
			}
			skills, err := skill.LoadAll(filepath.Join(abs, "skills"))
			if err != nil {
				return err
			}
			if profileName != "" {
				prof, err := compiler.LoadProfile(abs, profileName)
				if err != nil {
					return err
				}
				skills = compiler.FilterSkillsByProfile(skills, prof)
				if len(skills) == 0 {
					return fmt.Errorf("profile %q matched no skills", profileName)
				}
			}
			ctx, err := compiler.LoadContext(abs)
			if err != nil {
				return err
			}
			// --full-inline (alias --legacy) restores the pre-v2
			// monolithic dist/ output that inlines every skill body
			// across all per-tool files (CLAUDE.md, .cursorrules,
			// copilot-instructions.md, AGENTS.md, devin.md,
			// .windsurfrules, .clinerules). The default since v2 is
			// the minimal pointer file documented in pointer.go.
			if fullInline || legacy {
				ctx.FullInline = true
			}
			outDir := filepath.Join(abs, "dist")

			var formatters []compiler.Formatter
			if tool == "" || tool == "all" {
				formatters = compiler.AllTools()
			} else {
				f, ok := compiler.Registry[tool]
				if !ok {
					return fmt.Errorf("unknown tool %q", tool)
				}
				formatters = []compiler.Formatter{f}
			}

			out := c.OutOrStdout()
			var warnings []string
			for _, f := range formatters {
				tier := f.DefaultTier()
				if budget != "" {
					if !skill.IsValidTier(budget) {
						return fmt.Errorf("invalid budget %q (valid: minimal, compact, full)", budget)
					}
					tier = skill.Tier(budget)
				}
				report, warns, err := compiler.WriteFile(skills, f.Name(), tier, ctx, outDir)
				if err != nil {
					return err
				}
				fmt.Fprintf(out, "%-10s -> dist/%s  total=%d openai / %d claude tokens (%s tier)\n",
					f.Name(), f.OutputName(), report.Total.OpenAI, report.Total.Claude, tier)
				warnings = append(warnings, warns...)
			}
			sort.Strings(warnings)
			for _, w := range warnings {
				fmt.Fprintln(c.ErrOrStderr(), "warn:", w)
			}

			// Native skill bundles. These are emitted alongside the
			// per-tool pointer files so consumers of Claude / Copilot /
			// agent-skills conventions get auto-discoverable SKILL.md
			// trees out of the same `regenerate` run. Operators that
			// only want to refresh the per-tool files (or scope a
			// regen to a single tool with --tool) can suppress this
			// with --skip-native.
			if !skipNative && (tool == "" || tool == "all") {
				if err := compiler.WriteNativeBundles(skills, outDir); err != nil {
					return err
				}
				for _, bundle := range compiler.DefaultNativeBundles {
					rel := filepath.Join("dist", bundle.Subdir, bundle.InstallPath)
					fmt.Fprintf(out, "%-10s -> %s/<skill-id>/  (%d skills, native bundle)\n",
						bundle.Subdir, rel, len(skills))
				}
				// Per-skill, context-scoped rule files for IDEs that load
				// rules selectively (Cursor .mdc with globs; Copilot
				// .instructions.md with applyTo) — the progressive-disclosure
				// equivalent of the native bundles, so non-Claude IDEs also
				// pull only the relevant rule into context.
				if err := compiler.WriteRuleBundles(skills, outDir); err != nil {
					return err
				}
				fmt.Fprintf(out, "%-10s -> dist/cursor-rules/.cursor/rules/<skill-id>.mdc  (%d skills, scoped rules)\n", "cursor-rules", len(skills))
				fmt.Fprintf(out, "%-10s -> dist/copilot-rules/.github/instructions/<skill-id>.instructions.md  (%d skills, scoped rules)\n", "copilot-rules", len(skills))
				fmt.Fprintf(out, "%-10s -> dist/devin-rules/.devin/rules/<skill-id>.md  (%d skills, scoped rules)\n", "devin-rules", len(skills))
			}
			return nil
		},
	}
	c.Flags().StringVar(&path, "path", ".", "library root")
	c.Flags().StringVar(&tool, "tool", "", "single tool to regenerate (default all)")
	c.Flags().StringVar(&budget, "budget", "", "override tier (minimal|compact|full)")
	c.Flags().StringVar(&profileName, "profile", "", "enterprise profile (e.g., financial-services|healthcare|government)")
	c.Flags().BoolVar(&fullInline, "full-inline", false, "render the legacy monolithic per-tool dist/ output that inlines every skill body (default is the minimal pointer file)")
	c.Flags().BoolVar(&legacy, "legacy", false, "alias for --full-inline")
	c.Flags().BoolVar(&skipNative, "skip-native", false, "skip emitting dist/agent-skills, dist/copilot-skills, dist/claude-skills native bundles")
	return c
}
