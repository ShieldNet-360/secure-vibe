package cmd

import (
	"fmt"
	"path/filepath"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/shieldnet-360/secure-vibe/cmd/secure-vibe/internal/token"
	"github.com/shieldnet-360/secure-vibe/internal/skill"
)

func listCmd() *cobra.Command {
	var path, category string
	c := &cobra.Command{
		Use:   "list",
		Short: "List skills with category, severity, and token counts",
		RunE: func(c *cobra.Command, args []string) error {
			skills, err := skill.LoadAll(filepath.Join(resolveLibraryRoot(path), "skills"))
			if err != nil {
				return err
			}
			out := c.OutOrStdout()
			w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tTITLE\tCATEGORY\tSEVERITY\tMINIMAL\tCOMPACT\tFULL")
			for _, s := range skills {
				if category != "" && s.Frontmatter.Category != category {
					continue
				}
				min := token.MustCount(s.Extract(skill.TierMinimal)).Claude
				comp := token.MustCount(s.Extract(skill.TierCompact)).Claude
				full := token.MustCount(s.Extract(skill.TierFull)).Claude
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%d\t%d\n",
					s.Frontmatter.ID,
					s.Frontmatter.Title,
					s.Frontmatter.Category,
					s.Frontmatter.Severity,
					min, comp, full,
				)
			}
			return w.Flush()
		},
	}
	c.Flags().StringVar(&path, "path", ".", "library root (default: $SECURE_VIBE_LIBRARY_PATH, else cwd)")
	c.Flags().StringVar(&category, "category", "", "filter by category")
	return c
}
