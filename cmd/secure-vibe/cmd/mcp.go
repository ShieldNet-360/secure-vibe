package cmd

import (
	"github.com/shieldnet-360/secure-vibe/internal/mcp"
	"github.com/spf13/cobra"
)

// mcpCmd runs the Model Context Protocol server (JSON-RPC 2.0 over stdio),
// the in-process twin of the standalone secure-vibe mcp binary. Both delegate to
// internal/mcp.RunStdio so they expose an identical tool surface and safety
// model. This is what an MCP client should launch, e.g.:
//
//	claude mcp add secure-vibe -- secure-vibe mcp --path ./lib
func mcpCmd() *cobra.Command {
	var path, allowedRoots, vulnSource string
	var allowAnyPath bool
	c := &cobra.Command{
		Use:   "mcp",
		Short: "Run the MCP server (JSON-RPC 2.0 over stdio)",
		Long: `mcp serves the Skills Library over the Model Context Protocol
(JSON-RPC 2.0, one message per line on stdin/stdout). It exposes the same
tools as the standalone secure-vibe mcp binary (search_skills, get_skill,
scan_secrets, scan_dependencies, check_dependency, gate, audit, ...).

Register it with an MCP client rather than running it by hand, e.g.:

    claude mcp add secure-vibe -- secure-vibe mcp --path ./lib

The library root is resolved from --path, then $SECURE_VIBE_LIBRARY_PATH, then the
directory of this binary. File-reading tools default to the current working
directory as their only allowed root unless --allowed-roots or --allow-any-path
is given; sensitive system directories are always denied.`,
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, args []string) error {
			return mcp.RunStdio(mcp.StdioOptions{
				Path:         path,
				AllowedRoots: allowedRoots,
				AllowAnyPath: allowAnyPath,
				VulnSource:   vulnSource,
			})
		},
	}
	c.Flags().StringVar(&path, "path", "", "path to the secure-vibe checkout (default: $SECURE_VIBE_LIBRARY_PATH or dir of the binary)")
	c.Flags().StringVar(&allowedRoots, "allowed-roots", "", "comma-separated absolute directories that file-reading tools may read from (default: the current working directory). Sensitive dirs (~/.ssh, ~/.aws, ~/.gnupg, /etc/shadow, ...) are always denied.")
	c.Flags().BoolVar(&allowAnyPath, "allow-any-path", false, "disable the default-to-cwd allow-list and accept any absolute path the process can stat (local debugging only; mutually exclusive with --allowed-roots)")
	c.Flags().StringVar(&vulnSource, "vuln-source", "local", "where lookup_vulnerability / check_dependency read OSV advisories from: 'local' (no network, default), 'external' (api.osv.dev only), or 'hybrid' (osv.dev first, fall back to local)")
	// `secure-vibe mcp connect` registers this server with Claude Code.
	c.AddCommand(connectMCPCmd())
	return c
}
