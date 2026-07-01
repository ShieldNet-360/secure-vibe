package cmd

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// runConnectMCP executes `connect-mcp <args...>` against a fresh command
// tree and returns combined stdout/stderr plus any error.
func runConnectMCP(t *testing.T, args ...string) (string, error) {
	t.Helper()
	root := Root()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs(append([]string{"connect-mcp"}, args...))
	err := root.Execute()
	return buf.String(), err
}

// TestConnectMCPPrintDefault asserts the default (no-arg) form prints a
// `claude mcp add` line for the default server name plus a valid .mcp.json
// snippet — and never executes claude.
func TestConnectMCPPrintDefault(t *testing.T) {
	out, err := runConnectMCP(t, "--print", "--binary", "/opt/secure-vibe", "--path", "/lib/root")
	if err != nil {
		t.Fatalf("connect-mcp --print errored: %v", err)
	}
	if !strings.Contains(out, "claude mcp add -s local "+defaultMCPName+" --") {
		t.Errorf("missing claude command for default name; got:\n%s", out)
	}
	if !strings.Contains(out, "/opt/secure-vibe mcp --path /lib/root") {
		t.Errorf("default command should register `secure-vibe mcp` + library root; got:\n%s", out)
	}
	assertSnippetServer(t, out, defaultMCPName, "/opt/secure-vibe", []string{"mcp", "--path", "/lib/root"})
}

// TestConnectMCPPrintCustom covers the "register any MCP" form: a custom
// name and a command after "--", with a non-default scope.
func TestConnectMCPPrintCustom(t *testing.T) {
	out, err := runConnectMCP(t, "my-server", "--scope", "project", "--print",
		"--", "npx", "-y", "@scope/some-mcp")
	if err != nil {
		t.Fatalf("connect-mcp custom --print errored: %v", err)
	}
	if !strings.Contains(out, "claude mcp add -s project my-server -- npx -y @scope/some-mcp") {
		t.Errorf("custom command line wrong; got:\n%s", out)
	}
	assertSnippetServer(t, out, "my-server", "npx", []string{"-y", "@scope/some-mcp"})
}

func TestShellJoinQuotesSpaces(t *testing.T) {
	got := shellJoin([]string{"mcp", "add", "/path with space/secure-vibe", "--path", "/a/b"})
	want := "mcp add '/path with space/secure-vibe' --path /a/b"
	if got != want {
		t.Errorf("shellJoin = %q, want %q", got, want)
	}
}

// assertSnippetServer parses the JSON object embedded in out and checks the
// named server has the expected command + args.
func assertSnippetServer(t *testing.T, out, name, wantCmd string, wantArgs []string) {
	t.Helper()
	start := strings.Index(out, "{")
	if start < 0 {
		t.Fatalf("no JSON snippet in output:\n%s", out)
	}
	var parsed struct {
		MCPServers map[string]struct {
			Command string   `json:"command"`
			Args    []string `json:"args"`
		} `json:"mcpServers"`
	}
	if err := json.Unmarshal([]byte(out[start:]), &parsed); err != nil {
		t.Fatalf("snippet is not valid JSON: %v\n%s", err, out[start:])
	}
	srv, ok := parsed.MCPServers[name]
	if !ok {
		t.Fatalf("snippet missing server %q; got %+v", name, parsed.MCPServers)
	}
	if srv.Command != wantCmd {
		t.Errorf("server command = %q, want %q", srv.Command, wantCmd)
	}
	if strings.Join(srv.Args, " ") != strings.Join(wantArgs, " ") {
		t.Errorf("server args = %v, want %v", srv.Args, wantArgs)
	}
}
