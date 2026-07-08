package cmd

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// changedFiles returns the absolute paths of files that changed under root
// relative to the given git ref — added / copied / modified / renamed tracked
// files (deletions skipped, since there is nothing left to scan) plus untracked
// new files. This is the surface `audit --diff` scans: a PR's changed set rather
// than the whole tree. ref "" defaults to HEAD (working-tree changes); in CI a
// caller passes the PR base (e.g. origin/main).
func changedFiles(root, ref string) ([]string, error) {
	if strings.TrimSpace(ref) == "" {
		ref = "HEAD"
	}
	tracked, err := gitLines(root, "diff", "--name-only", "--diff-filter=ACMR", ref)
	if err != nil {
		return nil, err
	}
	// Untracked files are best-effort — a bare repo or odd state shouldn't sink
	// the run, and tracked changes are the primary signal.
	untracked, _ := gitLines(root, "ls-files", "--others", "--exclude-standard")

	seen := map[string]bool{}
	out := make([]string, 0, len(tracked)+len(untracked))
	for _, rel := range append(tracked, untracked...) {
		p := filepath.Join(root, rel)
		if seen[p] {
			continue
		}
		info, err := os.Stat(p)
		if err != nil || info.IsDir() {
			continue // skip deletions that slipped through and directories
		}
		seen[p] = true
		out = append(out, p)
	}
	return out, nil
}

// gitLines runs `git -C root <args...>` and returns non-empty trimmed stdout
// lines. A non-zero exit (e.g. not a git repo, unknown ref) is returned as an
// error with git's stderr for context.
func gitLines(root string, args ...string) ([]string, error) {
	cmd := exec.Command("git", append([]string{"-C", root}, args...)...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("git %s: %s", strings.Join(args, " "), msg)
	}
	var lines []string
	for _, l := range strings.Split(stdout.String(), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			lines = append(lines, l)
		}
	}
	return lines, nil
}
