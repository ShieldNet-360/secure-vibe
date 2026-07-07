package cmd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/shieldnet-360/secure-vibe/internal/attest"
)

// setupAttestation is the init-time entry point: it marks dir's repo as
// SecureVibe-prepared and installs the attestation hook. Every branch is
// fail-open — it prints a hint and returns rather than failing `init`.
func setupAttestation(dir string, out, errOut io.Writer) {
	if dir == "" {
		dir, _ = os.Getwd()
	}
	if !attest.HaveGit() {
		fmt.Fprintln(out, "note: git not found — commit attestation skipped (install git, then `secure-vibe attest install-hooks`).")
		return
	}
	if !attest.IsGitRepo(dir) {
		fmt.Fprintln(out, "note: not a git repo — run `git init`, then `secure-vibe attest install-hooks` to attest commits.")
		return
	}
	repoRoot, err := attest.RepoRoot(dir)
	if err != nil {
		repoRoot = dir
	}
	if err := attest.WriteMarker(repoRoot, CLIVersion); err != nil {
		fmt.Fprintln(errOut, "warn: could not write .secure-vibe.yml marker:", err)
	}
	installed, err := InstallAttestHook(dir)
	if err != nil {
		fmt.Fprintln(errOut, "warn: could not install attestation hook:", err)
		return
	}
	if installed {
		fmt.Fprintln(out, "attestation: installed prepare-commit-msg hook — commits will carry a SecureVibe usage attestation.")
	}
}

// hookSentinel marks the prepare-commit-msg block this CLI installs, so
// re-running install is idempotent and never double-appends.
const hookSentinel = "secure-vibe attest hook"

// InstallAttestHook installs (or chains) a prepare-commit-msg hook in the repo
// containing dir. It returns installed=false when the hook already attests.
//
// It is safe by construction: an existing FOREIGN hook is preserved and our
// invocation is appended after it (guarded with `|| true` so it can never
// break a commit). Fail-open — any error resolving the repo is surfaced, but
// the hook body itself never blocks a commit.
func InstallAttestHook(dir string) (bool, error) {
	if !attest.HaveGit() {
		return false, attest.ErrNoGit
	}
	if !attest.IsGitRepo(dir) {
		return false, fmt.Errorf("not a git repository: %s", dir)
	}
	hooksDir, err := attest.HooksDir(dir)
	if err != nil || hooksDir == "" {
		// Fallback for old git without --absolute-git-path.
		root, rerr := attest.RepoRoot(dir)
		if rerr != nil {
			return false, rerr
		}
		hooksDir = filepath.Join(root, ".git", "hooks")
	}
	if err := os.MkdirAll(hooksDir, 0o755); err != nil {
		return false, err
	}
	hookPath := filepath.Join(hooksDir, "prepare-commit-msg")

	snippet := attestHookSnippet()

	existing, readErr := os.ReadFile(hookPath)
	if readErr == nil {
		if strings.Contains(string(existing), hookSentinel) {
			return false, nil // already ours
		}
		// Chain onto a foreign hook rather than clobbering it.
		body := strings.TrimRight(string(existing), "\n") + "\n\n" + snippet + "\n"
		if err := os.WriteFile(hookPath, []byte(body), 0o755); err != nil {
			return false, err
		}
		return true, nil
	}

	content := "#!/bin/sh\n" + snippet + "\n"
	if err := os.WriteFile(hookPath, []byte(content), 0o755); err != nil {
		return false, err
	}
	return true, nil
}

// attestHookSnippet is the shell block that invokes the attestation. It prefers
// a `secure-vibe` on PATH and falls back to the absolute path of the binary
// that installed the hook, so it keeps working for a global install even if the
// dev checkout moves.
func attestHookSnippet() string {
	binPath, _ := os.Executable()
	binPath, _ = filepath.Abs(binPath)
	return strings.Join([]string{
		"# " + hookSentinel + " (auto-installed; delete this block to disable)",
		`SV="$(command -v secure-vibe 2>/dev/null || true)"`,
		fmt.Sprintf(`[ -z "$SV" ] && SV=%q`, binPath),
		`[ -x "$SV" ] || exit 0`,
		`"$SV" attest sign --if-material --message-file "$1" >/dev/null 2>&1 || true`,
		"exit 0",
	}, "\n")
}
