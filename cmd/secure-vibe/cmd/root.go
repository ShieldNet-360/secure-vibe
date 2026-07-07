// Package cmd implements the Cobra command tree for the secure-vibe CLI.
// The source directory stays cmd/secure-vibe (a stable technical identifier);
// the shipped binary and the user-facing command are both `secure-vibe`.
package cmd

import (
	"github.com/spf13/cobra"
)

// CLIVersion is the semantic version of the secure-vibe binary. It is
// stamped at build time via -ldflags "-X github.com/.../cmd.CLIVersion=...".
var CLIVersion = "0.1.0-dev"

// Root returns the configured root command.
func Root() *cobra.Command {
	root := &cobra.Command{
		Use:   "secure-vibe",
		Short: "SecureVibe — security skills, scanners, and MCP server",
		Long: `secure-vibe is the SecureVibe CLI.

It scans for secrets / vulnerable dependencies / misconfig, gates a build in
CI, serves the security skills over MCP (secure-vibe mcp), and installs IDE
config. Maintainer commands for building the skills library live under
"secure-vibe dev".`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		// Bare `secure-vibe` prints the splash (logo + version + links +
		// quick start) instead of the raw help dump.
		Run: func(c *cobra.Command, _ []string) {
			renderBanner(c.OutOrStdout())
		},
	}

	// End-user runtime commands (the focused top-level surface).
	root.AddCommand(initCmd())
	root.AddCommand(scanCmd())        // auto-detect scanner, report only
	root.AddCommand(auditCmd())       // whole-tree fan-out: dedup, rank, triage
	root.AddCommand(policyCheckCmd()) // gate: same detection, CI exit code
	root.AddCommand(checkCmd())       // single-package malicious/typosquat/CVE/OSV lookup
	root.AddCommand(contributeCmd())  // LEARN loop
	root.AddCommand(mcpCmd())         // MCP server (+ `mcp connect`)
	root.AddCommand(updateCmd())      // library data (+ `--self` for the binary)
	root.AddCommand(statusCmd())
	root.AddCommand(listCmd())
	root.AddCommand(configureCmd())
	root.AddCommand(versionCmd())
	lc := logoCmd()
	lc.Hidden = true // still runnable, kept out of the help list
	root.AddCommand(lc)
	// Maintainer commands, grouped under `dev` to keep top-level help focused.
	root.AddCommand(devCmd())

	// Show the mark above the root help — bare `secure-vibe` (which prints
	// help) and `secure-vibe --help`. Scoped to the root so subcommand help
	// (e.g. `secure-vibe gate --help`) stays clean.
	defaultHelp := root.HelpFunc()
	root.SetHelpFunc(func(c *cobra.Command, args []string) {
		if c == root {
			renderBanner(c.OutOrStdout())
		}
		defaultHelp(c, args)
	})
	return root
}
