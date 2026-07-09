package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitClaudeWritesWorkflow(t *testing.T) {
	root := repoRoot(t)
	tmp := t.TempDir()
	stdout, _, err := executeRoot(t, "init", "--tool", "claude", "--library", root, "--out", tmp,
		"--no-prompt", "--no-attest-hook")
	if err != nil {
		t.Fatalf("init: %v\n%s", err, stdout)
	}
	wf := filepath.Join(tmp, workflowRelPath)
	body, err := os.ReadFile(wf)
	if err != nil {
		t.Fatalf("expected workflow at %s: %v", wf, err)
	}
	for _, want := range []string{"secure-vibe-audit", "secure-vibe audit", "phase("} {
		if !strings.Contains(string(body), want) {
			t.Errorf("workflow missing %q", want)
		}
	}
	// The dead --model advice must be gone.
	if strings.Contains(string(body), "--model") {
		t.Error("workflow still references the removed --model lane")
	}
	if !strings.Contains(stdout, "use a workflow") {
		t.Errorf("init should hint the workflow entry point; got:\n%s", stdout)
	}
}

func TestInitCursorSkipsWorkflow(t *testing.T) {
	root := repoRoot(t)
	tmp := t.TempDir()
	if _, _, err := executeRoot(t, "init", "--tool", "cursor", "--library", root, "--out", tmp,
		"--no-prompt", "--no-attest-hook"); err != nil {
		t.Fatalf("init: %v", err)
	}
	if _, err := os.Stat(filepath.Join(tmp, workflowRelPath)); !os.IsNotExist(err) {
		t.Errorf("cursor init should not write a Claude workflow (err=%v)", err)
	}
}

func TestInitNoWorkflowFlag(t *testing.T) {
	root := repoRoot(t)
	tmp := t.TempDir()
	if _, _, err := executeRoot(t, "init", "--tool", "claude", "--library", root, "--out", tmp,
		"--no-prompt", "--no-attest-hook", "--no-workflow"); err != nil {
		t.Fatalf("init: %v", err)
	}
	if _, err := os.Stat(filepath.Join(tmp, workflowRelPath)); !os.IsNotExist(err) {
		t.Errorf("--no-workflow should suppress the workflow (err=%v)", err)
	}
}

func TestWriteAuditWorkflowIsIdempotent(t *testing.T) {
	tmp := t.TempDir()
	path, wrote, err := writeAuditWorkflow(tmp)
	if err != nil || !wrote {
		t.Fatalf("first write: wrote=%v err=%v", wrote, err)
	}
	// A user customises the file; a second init must not clobber it.
	if err := os.WriteFile(path, []byte("// custom\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, wrote2, err := writeAuditWorkflow(tmp)
	if err != nil || wrote2 {
		t.Fatalf("second write should be a no-op: wrote=%v err=%v", wrote2, err)
	}
	body, _ := os.ReadFile(path)
	if string(body) != "// custom\n" {
		t.Error("writeAuditWorkflow clobbered a user-customised workflow")
	}
}

// TestWorkflowTemplateMatchesRepo guards against the embedded template and the
// repo's own .claude/workflows/ copy drifting apart. The embedded one is the
// source of truth; keep the repo copy synced (cp the template over it).
func TestWorkflowTemplateMatchesRepo(t *testing.T) {
	repoCopy := filepath.Join(repoRoot(t), workflowRelPath)
	body, err := os.ReadFile(repoCopy)
	if err != nil {
		t.Skipf("repo workflow copy not found (%v)", err)
	}
	if string(body) != workflowTemplate {
		t.Errorf("%s has drifted from the embedded template; re-sync it:\n  cp cmd/secure-vibe/cmd/templates/secure-vibe-audit.js %s", repoCopy, repoCopy)
	}
}
