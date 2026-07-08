package cmd

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestChangedFiles(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir := t.TempDir()
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t.co",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t.co")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	git("init")
	git("config", "user.email", "t@t.co")
	git("config", "user.name", "t")
	write("unchanged.txt", "stable\n")
	write("committed.txt", "v1\n")
	git("add", "-A")
	git("commit", "-m", "init")

	// Modify a committed file and add an untracked one.
	write("committed.txt", "v2\n")
	write("new.txt", "fresh\n")

	got, err := changedFiles(dir, "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, p := range got {
		if !filepath.IsAbs(p) {
			t.Errorf("path not absolute: %s", p)
		}
		names[filepath.Base(p)] = true
	}
	if !names["committed.txt"] {
		t.Error("modified committed.txt should be in the changed set")
	}
	if !names["new.txt"] {
		t.Error("untracked new.txt should be in the changed set")
	}
	if names["unchanged.txt"] {
		t.Error("unchanged.txt must NOT be in the changed set")
	}
}
