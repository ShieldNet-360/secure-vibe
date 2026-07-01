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
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	// End-user runtime commands (the focused top-level surface).
	root.AddCommand(initCmd())
	root.AddCommand(updateCmd())
	root.AddCommand(selfUpdateCmd())
	root.AddCommand(configureCmd())
	root.AddCommand(statusCmd())
	root.AddCommand(listCmd())
	root.AddCommand(versionCmd())
	root.AddCommand(connectMCPCmd())
	root.AddCommand(mcpCmd())
	// Scan / lookup surface — twins of the MCP tools, see tools_cli.go.
	root.AddCommand(checkDependencyCmd())
	root.AddCommand(checkTyposquatCmd())
	root.AddCommand(lookupVulnerabilityCmd())
	root.AddCommand(scanSecretsCmd())
	root.AddCommand(scanDependenciesCmd())
	root.AddCommand(scanDockerfileCmd())
	root.AddCommand(scanGitHubActionsCmd())
	root.AddCommand(policyCheckCmd())
	root.AddCommand(contributeCmd())
	// Maintainer commands, grouped under `dev` to keep top-level help focused.
	root.AddCommand(devCmd())
	return root
}
