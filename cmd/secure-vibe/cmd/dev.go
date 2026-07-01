package cmd

import "github.com/spf13/cobra"

// devCmd groups the maintainer-only commands that author and maintain the
// skills library itself — validating skills, scaffolding/regenerating bundles,
// signing the root manifest, refreshing vulnerability data, and running the
// per-skill test corpus. They are nested under `dev` so the top-level --help
// stays focused on the end-user runtime surface (scan/check/gate/mcp/
// contribute). End users running scans or the MCP server do not need these.
//
// Invocation moves under the group, e.g. `secure-vibe dev validate`,
// `secure-vibe dev manifest compute --write`, `secure-vibe dev test <skill-id>`.
func devCmd() *cobra.Command {
	c := &cobra.Command{
		Use:     "dev",
		Short:   "Maintainer commands for authoring & maintaining the skills library",
		Long:    `dev groups the commands used to author and maintain the skills library itself — validating skills, scaffolding new ones, regenerating dist/ bundles, signing the root manifest, refreshing vulnerability data, deriving checklists, and running the per-skill test corpus. End users running scans or the MCP server do not need these.`,
		Aliases: []string{"maint"},
	}
	c.AddCommand(validateCmd())
	c.AddCommand(coverageCmd())
	c.AddCommand(regenerateCmd())
	c.AddCommand(generateNativeCmd())
	c.AddCommand(manifestCmd())
	c.AddCommand(schedulerCmd())
	c.AddCommand(newCmd())
	c.AddCommand(testCmd())
	c.AddCommand(evidenceCmd())
	c.AddCommand(fetchVulnsCmd())
	c.AddCommand(deriveChecklistsCmd())
	return c
}
