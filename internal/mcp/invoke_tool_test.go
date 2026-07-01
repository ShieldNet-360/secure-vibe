package mcp

import (
	"os"
	"path/filepath"
	"testing"
)

// TestSetAllowedRoots confirms the happy-path delegation to the Library
// accepts a real directory.
func TestSetAllowedRoots(t *testing.T) {
	srv := newServer(t)
	if err := srv.SetAllowedRoots([]string{t.TempDir()}); err != nil {
		t.Fatalf("SetAllowedRoots(valid dir): %v", err)
	}
}

// TestInvokeToolDispatch exercises the invokeTool switch across every
// keyless tool the server exposes, plus the SARIF-format branch and the
// unknown-tool error path. It is the dispatch coverage the JSON-RPC
// round-trip tests only hit for a couple of tools.
func TestInvokeToolDispatch(t *testing.T) {
	srv := newServer(t)
	tmp := t.TempDir()
	if err := srv.SetAllowedRoots([]string{tmp}); err != nil {
		t.Fatalf("SetAllowedRoots: %v", err)
	}

	reqs := filepath.Join(tmp, "requirements.txt")
	mustWrite(t, reqs, "requests==2.31.0\n")
	dockerfile := filepath.Join(tmp, "Dockerfile")
	mustWrite(t, dockerfile, "FROM ubuntu:latest\nUSER root\n")
	wf := filepath.Join(tmp, "ci.yml")
	mustWrite(t, wf, "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n")

	cases := []struct {
		name string
		args map[string]interface{}
	}{
		{"lookup_vulnerability", map[string]interface{}{"package": "left-pad", "ecosystem": "npm", "version": "1.0.0"}},
		{"check_secret_pattern", map[string]interface{}{"text": "AKIAIOSFODNN7EXAMPLE"}},
		{"get_skill", map[string]interface{}{"skill_id": "container-security", "budget": "minimal"}},
		{"search_skills", map[string]interface{}{"query": "docker"}},
		{"scan_secrets", map[string]interface{}{"text": "hello world, no secret here"}},
		{"check_dependency", map[string]interface{}{"package": "left-pad", "version": "1.0.0", "ecosystem": "npm"}},
		{"check_typosquat", map[string]interface{}{"package": "requsts", "ecosystem": "pypi"}},
		{"version_status", map[string]interface{}{}},
		{"list_external_tools", map[string]interface{}{}},
		{"scan_dependencies", map[string]interface{}{"file_path": reqs}},
		{"scan_github_actions", map[string]interface{}{"file_path": wf}},
		{"scan_dockerfile", map[string]interface{}{"file_path": dockerfile}},
	}
	for _, c := range cases {
		res, err := srv.invokeTool(c.name, c.args)
		if err != nil {
			t.Errorf("invokeTool(%s) error: %v", c.name, err)
			continue
		}
		if res == nil {
			t.Errorf("invokeTool(%s) returned nil result", c.name)
		}
	}

	// SARIF-format branch of a scan tool.
	if res, err := srv.invokeTool("scan_dependencies", map[string]interface{}{"file_path": reqs, "format": "sarif"}); err != nil || res == nil {
		t.Errorf("invokeTool(scan_dependencies, sarif) = %v, %v", res, err)
	}

	// Unknown tool must error rather than panic or silently succeed.
	if _, err := srv.invokeTool("does_not_exist", nil); err == nil {
		t.Error("invokeTool(unknown) should return an error")
	}
}

func mustWrite(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
