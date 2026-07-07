package attest

import (
	"errors"
	"os/exec"
	"strings"
)

// ErrNoGit is returned when the `git` binary is not on PATH. Callers treat
// this as a fail-open bypass (attestation is skipped, work is never blocked).
var ErrNoGit = errors.New("git not found on PATH")

// HaveGit reports whether the git binary is available.
func HaveGit() bool {
	_, err := exec.LookPath("git")
	return err == nil
}

// git runs `git -C dir args...` and returns trimmed stdout.
func git(dir string, args ...string) (string, error) {
	if !HaveGit() {
		return "", ErrNoGit
	}
	full := append([]string{"-C", dir}, args...)
	out, err := exec.Command("git", full...).Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// IsGitRepo reports whether dir is inside a git working tree.
func IsGitRepo(dir string) bool {
	out, err := git(dir, "rev-parse", "--is-inside-work-tree")
	return err == nil && out == "true"
}

// RepoRoot returns the absolute path of the working-tree root containing dir.
func RepoRoot(dir string) (string, error) {
	return git(dir, "rev-parse", "--show-toplevel")
}

// StagedTreeSHA writes the current index to a tree object and returns its SHA.
// This is the content-addressed subject signed at commit time: it is exactly
// the tree the pending commit will point at, and it is stable regardless of
// diff configuration.
func StagedTreeSHA(dir string) (string, error) {
	return git(dir, "write-tree")
}

// CommitTreeSHA returns the tree SHA of an existing commit (ref may be a SHA,
// "HEAD", a branch, etc.). Used on verify to recompute the subject a committed
// attestation must match.
func CommitTreeSHA(dir, ref string) (string, error) {
	return git(dir, "rev-parse", ref+"^{tree}")
}

// CommitMessage returns the full commit message (subject + body + trailers)
// for ref.
func CommitMessage(dir, ref string) (string, error) {
	return git(dir, "log", "-1", "--format=%B", ref)
}

// HooksDir returns the absolute path of the git hooks directory for dir,
// honoring core.hooksPath and worktree layouts.
func HooksDir(dir string) (string, error) {
	return git(dir, "rev-parse", "--absolute-git-path", "hooks")
}

// CommitsInRange lists commit SHAs (newest first) for a git rev-range such as
// "origin/main..HEAD" or "HEAD~20..HEAD". A single ref lists just that commit.
func CommitsInRange(dir, revRange string) ([]string, error) {
	out, err := git(dir, "rev-list", revRange)
	if err != nil {
		return nil, err
	}
	if out == "" {
		return nil, nil
	}
	return strings.Split(out, "\n"), nil
}
