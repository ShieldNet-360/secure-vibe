package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
)

// defaultMCPName is the server name registered when connect-mcp is run
// with no positional name.
const defaultMCPName = "secure-vibe"

// connectMCPCmd wires the SecureVibe MCP server into Claude Code by
// shelling out to `claude mcp add`. With one binary, the server is just
// `secure-vibe mcp` — connect-mcp registers this binary running that
// subcommand. It is onboarding sugar, not part of the scan engine: the
// engine never runs external binaries, but setup commands do (see
// `scheduler`, which drives launchd/systemd/Task Scheduler).
func connectMCPCmd() *cobra.Command {
	var scope, pathFlag, binary string
	var printOnly bool
	c := &cobra.Command{
		Use:   "connect-mcp [name] [-- command args...]",
		Short: "Register the SecureVibe MCP server (`secure-vibe mcp`) with Claude Code (wraps `claude mcp add`)",
		Long: `connect-mcp wires the SecureVibe MCP server into Claude Code.

With no arguments it registers this binary running its "mcp" subcommand
(secure-vibe mcp), pointed at the resolved library root:

    secure-vibe connect-mcp
    # → claude mcp add -s local secure-vibe -- secure-vibe mcp --path <root>

To register an arbitrary MCP server instead, pass a name and a command
after "--":

    secure-vibe connect-mcp my-server -- npx -y @scope/some-mcp

It shells out to the Claude Code CLI ("claude mcp add"), mirroring how the
"scheduler" command drives OS tools. If the claude CLI is not on PATH (or
you pass --print), it prints the exact command plus an .mcp.json snippet to
apply by hand instead of running anything.`,
		RunE: func(c *cobra.Command, args []string) error {
			out := c.OutOrStdout()

			// Split args around an optional "--": everything before is
			// the (optional) server name, everything after is the server
			// command. cobra records the dash position for us.
			var before, after []string
			if dash := c.ArgsLenAtDash(); dash >= 0 {
				before, after = args[:dash], args[dash:]
			} else {
				before = args
			}

			name := defaultMCPName
			if len(before) > 0 {
				name = before[0]
			}

			// Resolve the command to register. A user-supplied command
			// (after "--") wins; otherwise default to THIS binary running
			// its "mcp" subcommand, pointed at the resolved, absolute
			// library root so the stored command works regardless of
			// Claude's launch cwd.
			var command []string
			if len(after) > 0 {
				command = after
			} else {
				root := resolveLibraryRoot(pathFlag)
				if abs, err := filepath.Abs(root); err == nil {
					root = abs
				}
				command = []string{resolveSelfBinary(binary), "mcp", "--path", root}
			}

			addArgs := []string{"mcp", "add"}
			if scope != "" {
				addArgs = append(addArgs, "-s", scope)
			}
			addArgs = append(addArgs, name, "--")
			addArgs = append(addArgs, command...)

			if printOnly {
				fmt.Fprintf(out, "claude %s\n\n", shellJoin(addArgs))
				fmt.Fprint(out, mcpJSONSnippet(name, command))
				return nil
			}

			if _, err := exec.LookPath("claude"); err != nil {
				e := c.ErrOrStderr()
				fmt.Fprintln(e, "secure-vibe: the Claude Code CLI ('claude') was not found on PATH.")
				fmt.Fprintln(e, "Run this yourself once Claude Code is installed:")
				fmt.Fprintf(e, "  claude %s\n\n", shellJoin(addArgs))
				fmt.Fprintln(e, "Or add it to your MCP client config manually:")
				fmt.Fprint(e, mcpJSONSnippet(name, command))
				return fmt.Errorf("claude CLI not found on PATH")
			}

			run := exec.Command("claude", addArgs...)
			run.Stdout, run.Stderr, run.Stdin = out, c.ErrOrStderr(), os.Stdin
			if err := run.Run(); err != nil {
				return fmt.Errorf("claude mcp add failed: %w", err)
			}
			fmt.Fprintf(out, "registered MCP server %q with Claude Code (scope: %s)\n", name, scope)
			return nil
		},
	}
	c.Flags().StringVar(&scope, "scope", "local", "claude mcp scope: local | user | project")
	c.Flags().StringVar(&pathFlag, "path", ".", "library root for the default server (default: $SECURE_VIBE_LIBRARY_PATH, else cwd)")
	c.Flags().StringVar(&binary, "binary", "", "path to the secure-vibe binary to register (default: this running binary, else PATH)")
	c.Flags().BoolVar(&printOnly, "print", false, "print the claude command + .mcp.json snippet instead of running it")
	return c
}

// selfBinaryName is the per-OS secure-vibe executable name.
func selfBinaryName() string {
	if runtime.GOOS == "windows" {
		return "secure-vibe.exe"
	}
	return "secure-vibe"
}

// resolveSelfBinary locates the secure-vibe binary to register (to be run as
// `secure-vibe mcp`): an explicit flag wins, then the running binary's own
// path, then PATH, then the bare name as a last resort (Claude resolves it
// at launch time).
func resolveSelfBinary(flagVal string) string {
	if flagVal != "" {
		return flagVal
	}
	if exe, err := os.Executable(); err == nil {
		return exe
	}
	if p, err := exec.LookPath(selfBinaryName()); err == nil {
		return p
	}
	return selfBinaryName()
}

// mcpJSONSnippet renders the .mcp.json fragment a user can paste into a
// client that has no `mcp add` command (e.g. Cursor).
func mcpJSONSnippet(name string, command []string) string {
	type server struct {
		Command string   `json:"command"`
		Args    []string `json:"args"`
	}
	args := []string{}
	if len(command) > 1 {
		args = command[1:]
	}
	cfg := map[string]any{
		"mcpServers": map[string]any{
			name: server{Command: command[0], Args: args},
		},
	}
	b, _ := json.MarshalIndent(cfg, "", "  ")
	return string(b) + "\n"
}

// shellJoin renders an argv for copy-paste display, single-quoting any
// element that contains whitespace or shell metacharacters.
func shellJoin(args []string) string {
	parts := make([]string, len(args))
	for i, a := range args {
		if a == "" || strings.ContainsAny(a, " \t\n\"'\\$&|;<>()") {
			parts[i] = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
		} else {
			parts[i] = a
		}
	}
	return strings.Join(parts, " ")
}
