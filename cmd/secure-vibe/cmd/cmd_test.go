package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for dir := wd; dir != "/"; dir = filepath.Dir(dir) {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
	}
	t.Fatalf("could not find repo root from %s", wd)
	return ""
}

// devSubcommands are the maintainer commands that moved under the `dev`
// group (see root.go / dev.go). Tests still invoke them by their bare name
// for brevity; executeRoot transparently routes those through `dev` so the
// test exercises the command exactly where it now lives.
var devSubcommands = map[string]bool{
	"validate":          true,
	"coverage":          true,
	"regenerate":        true,
	"generate-native":   true,
	"manifest":          true,
	"scheduler":         true,
	"new":               true,
	"test":              true,
	"evidence":          true,
	"fetch-vulns":       true,
	"derive-checklists": true,
}

func executeRoot(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	if len(args) > 0 && devSubcommands[args[0]] {
		args = append([]string{"dev"}, args...)
	}
	r := Root()
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	r.SetOut(stdout)
	r.SetErr(stderr)
	r.SetIn(&bytes.Buffer{})
	r.SetArgs(args)
	err := r.Execute()
	return stdout.String(), stderr.String(), err
}

// TestCommandGrouping locks the UX contract: maintainer commands live under
// `dev` (not at the top level), while end-user commands stay at the top.
func TestCommandGrouping(t *testing.T) {
	root := repoRoot(t)
	// A maintainer command must NOT resolve at the top level...
	if _, _, err := rawExecuteRoot(t, "validate", "--path", root); err == nil {
		t.Error("expected `validate` to be unknown at top level (it should live under `dev`)")
	}
	// ...but must resolve under `dev`.
	if _, _, err := rawExecuteRoot(t, "dev", "validate", "--path", root); err != nil {
		t.Errorf("`dev validate` should work: %v", err)
	}
	// An end-user command stays at the top level.
	if _, _, err := rawExecuteRoot(t, "list", "--path", root); err != nil {
		t.Errorf("`list` should remain a top-level command: %v", err)
	}
}

// rawExecuteRoot runs the root command with args verbatim (no dev-routing),
// for tests that assert on the command tree shape itself.
func rawExecuteRoot(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	r := Root()
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	r.SetOut(stdout)
	r.SetErr(stderr)
	r.SetIn(&bytes.Buffer{})
	r.SetArgs(args)
	err := r.Execute()
	return stdout.String(), stderr.String(), err
}

func TestValidateOnRepoPasses(t *testing.T) {
	root := repoRoot(t)
	stdout, stderr, err := executeRoot(t, "validate", "--path", root)
	if err != nil {
		t.Fatalf("validate failed: %v\nstdout:%s\nstderr:%s", err, stdout, stderr)
	}
	if !strings.Contains(stdout, "ok:") {
		t.Errorf("expected ok line, got %q", stdout)
	}
}

func TestListOutputsAllSeven(t *testing.T) {
	root := repoRoot(t)
	stdout, _, err := executeRoot(t, "list", "--path", root)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{
		"api-security", "compliance-awareness", "dependency-audit",
		"container-security", "secret-detection",
		"secure-code-review", "supply-chain-security",
	} {
		if !strings.Contains(stdout, id) {
			t.Errorf("list output missing %s", id)
		}
	}
}

func TestListCategoryFilter(t *testing.T) {
	root := repoRoot(t)
	stdout, _, err := executeRoot(t, "list", "--path", root, "--category", "supply-chain")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "supply-chain-security") {
		t.Errorf("supply-chain category should include supply-chain-security")
	}
	if strings.Contains(stdout, "api-security") {
		t.Errorf("api-security should be filtered out")
	}
}

func TestVersionFormat(t *testing.T) {
	root := repoRoot(t)
	stdout, _, err := executeRoot(t, "version", "--path", root)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"secure-vibe", "library", "go"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("version output missing %q\n%s", want, stdout)
		}
	}
}

func TestInitGeneratesToolFile(t *testing.T) {
	root := repoRoot(t)
	tmp := t.TempDir()
	stdout, _, err := executeRoot(t, "init", "--tool", "cursor", "--library", root, "--out", tmp)
	if err != nil {
		t.Fatalf("init: %v\n%s", err, stdout)
	}
	out := filepath.Join(tmp, ".cursorrules")
	info, err := os.Stat(out)
	if err != nil {
		t.Fatalf("expected %s: %v", out, err)
	}
	if info.Size() == 0 {
		t.Errorf("%s is empty", out)
	}
}

func TestInitNoPromptIsQuiet(t *testing.T) {
	root := repoRoot(t)
	tmp := t.TempDir()
	stdout, stderr, err := executeRoot(t, "init",
		"--tool", "cursor", "--library", root, "--out", tmp, "--no-prompt")
	if err != nil {
		t.Fatalf("init --no-prompt: %v\nstdout:%s\nstderr:%s", err, stdout, stderr)
	}
	if strings.Contains(stdout, "automatic background updates") {
		t.Errorf("--no-prompt must not print the scheduler prompt; got:\n%s", stdout)
	}
}

func TestInitFiltersSkillsList(t *testing.T) {
	root := repoRoot(t)
	tmp := t.TempDir()
	_, _, err := executeRoot(t, "init", "--tool", "universal", "--library", root, "--out", tmp,
		"--skills", "supply-chain-security,secret-detection")
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	body, err := os.ReadFile(filepath.Join(tmp, "SECURITY-SKILLS.md"))
	if err != nil {
		t.Fatal(err)
	}
	got := string(body)
	if !strings.Contains(got, "supply-chain-security") {
		t.Errorf("expected supply-chain-security in output")
	}
	if !strings.Contains(got, "secret-detection") {
		t.Errorf("expected secret-detection in output")
	}
	if strings.Contains(got, "compliance-awareness") {
		t.Errorf("compliance-awareness should be filtered out")
	}
}

func TestRegenerateDeterministic(t *testing.T) {
	root := repoRoot(t)
	tmp1 := t.TempDir()
	tmp2 := t.TempDir()

	// Symlink the repo into temp directories so each regenerate has the
	// same input but a different output dir.
	for _, tmp := range []string{tmp1, tmp2} {
		for _, name := range []string{"skills", "dictionaries", "vulnerabilities", "manifest.json"} {
			src := filepath.Join(root, name)
			dst := filepath.Join(tmp, name)
			if err := os.Symlink(src, dst); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, _, err := executeRoot(t, "regenerate", "--path", tmp1); err != nil {
		t.Fatalf("regenerate 1: %v", err)
	}
	if _, _, err := executeRoot(t, "regenerate", "--path", tmp2); err != nil {
		t.Fatalf("regenerate 2: %v", err)
	}
	for _, name := range []string{"CLAUDE.md", ".cursorrules", "AGENTS.md", "devin.md"} {
		a, err := os.ReadFile(filepath.Join(tmp1, "dist", name))
		if err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(filepath.Join(tmp2, "dist", name))
		if err != nil {
			t.Fatal(err)
		}
		if string(a) != string(b) {
			t.Errorf("%s is not deterministic between runs", name)
		}
	}
}
