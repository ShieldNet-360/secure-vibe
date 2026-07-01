package mcp

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/shieldnet-360/secure-vibe/internal/tools"
)

// StdioOptions configures RunStdio. The zero value mirrors the historical
// secure-vibe mcp defaults: library root resolved from --path / $SECURE_VIBE_LIBRARY_PATH
// / the binary directory, vuln-source "local", and the file allow-list
// defaulting to the current working directory.
type StdioOptions struct {
	Path         string // --path: secure-vibe checkout (default: $SECURE_VIBE_LIBRARY_PATH or binary dir)
	AllowedRoots string // --allowed-roots: comma-separated absolute dirs for file-reading tools
	AllowAnyPath bool   // --allow-any-path: disable the default-to-cwd allow-list
	VulnSource   string // --vuln-source: local | external | hybrid (default: local)
}

// RunStdio resolves configuration and serves the MCP protocol over
// stdin/stdout (JSON-RPC 2.0, one message per line). It is shared by the
// standalone secure-vibe mcp binary and the `secure-vibe mcp` subcommand so both
// behave identically. It blocks until stdin is closed or an error occurs, and
// returns the error instead of exiting so callers control the exit path.
//
// Allow-list resolution, in order of precedence:
//  1. AllowedRoots set        -> use exactly those (mutually exclusive with AllowAnyPath).
//  2. AllowAnyPath            -> no restriction (legacy local-debug behaviour).
//  3. (neither)               -> restrict to the current working directory.
//
// The CWD default keeps the server fail-safe: a caller who simply runs the
// server from a project root cannot ask it to read /etc/<anything>, another
// user's home, or arbitrary host paths. The sensitive-directory deny-list
// (~/.ssh, ~/.aws, ~/.gnupg, /etc/shadow, ...) always applies.
func RunStdio(o StdioOptions) error {
	vulnSourceArg := o.VulnSource
	if vulnSourceArg == "" {
		vulnSourceArg = "local"
	}
	vulnSource, err := tools.ParseVulnSource(vulnSourceArg)
	if err != nil {
		return err
	}
	root, err := resolveLibraryRoot(o.Path)
	if err != nil {
		return err
	}
	srv, err := NewServer(root, tools.WithVulnSource(vulnSource))
	if err != nil {
		return err
	}
	switch {
	case o.AllowedRoots != "":
		if o.AllowAnyPath {
			return fmt.Errorf("--allowed-roots and --allow-any-path are mutually exclusive")
		}
		if err := srv.SetAllowedRoots(strings.Split(o.AllowedRoots, ",")); err != nil {
			return err
		}
	case o.AllowAnyPath:
		// Leave the allow-list empty (no restriction).
	default:
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("resolve cwd for default allow-list: %w", err)
		}
		if err := srv.SetAllowedRoots([]string{cwd}); err != nil {
			return fmt.Errorf("default allow-list: %w", err)
		}
	}
	return srv.Serve(bufio.NewReader(os.Stdin), os.Stdout)
}

// resolveLibraryRoot determines the secure-vibe root, in order:
// --path, $SECURE_VIBE_LIBRARY_PATH, the per-user default data dir (populated by
// install.sh), then the directory of the running binary.
func resolveLibraryRoot(arg string) (string, error) {
	if arg != "" {
		return filepath.Abs(arg)
	}
	if env := os.Getenv("SECURE_VIBE_LIBRARY_PATH"); env != "" {
		return filepath.Abs(env)
	}
	if d := tools.DefaultDataDir(); tools.IsLibraryRoot(d) {
		return filepath.Abs(d)
	}
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("resolve binary path: %w", err)
	}
	return filepath.Dir(exe), nil
}
