package attest

import (
	"os"
	"path/filepath"
)

// MaterialMarker names the small file `secure-vibe init` drops at the repo root
// so the pre-commit hook (and anyone auditing usage) can cheaply tell that the
// repo was set up with SecureVibe.
const MaterialMarker = ".secure-vibe.yml"

// materialPaths are, relative to the repo root, the artifacts that indicate a
// repo "prepared SecureVibe material". Presence of ANY one is enough.
var materialPaths = []string{
	MaterialMarker,
	".secure-vibe",                     // overlay dir (LEARN loop)
	filepath.Join(".claude", "skills"), // native skills install
	"CLAUDE.md",                        // assistant config written by init
	".cursorrules",
	filepath.Join(".github", "copilot-instructions.md"),
}

// DetectMaterial reports whether repoRoot looks like it was prepared with
// SecureVibe. It is intentionally permissive: the caller uses it only to decide
// whether to ATTEMPT attestation, and a false result means "skip, fail-open".
//
// The strongest signal is the marker file, so it is checked first and reported
// separately via strong.
func DetectMaterial(repoRoot string) (present bool, strong bool) {
	markerPath := filepath.Join(repoRoot, MaterialMarker)
	if fi, err := os.Stat(markerPath); err == nil && !fi.IsDir() {
		return true, true
	}
	for _, rel := range materialPaths {
		if _, err := os.Stat(filepath.Join(repoRoot, rel)); err == nil {
			present = true
			break
		}
	}
	return present, false
}

// WriteMarker creates the material marker file at repoRoot if it does not
// already exist. Called by `secure-vibe init` so subsequent commits attest.
func WriteMarker(repoRoot, toolVersion string) error {
	path := filepath.Join(repoRoot, MaterialMarker)
	if _, err := os.Stat(path); err == nil {
		return nil // already present, leave the user's content alone
	}
	content := "# Marks this repo as prepared with SecureVibe (https://github.com/ShieldNet-360/secure-vibe).\n" +
		"# The pre-commit hook uses this to attach a usage attestation to each commit.\n" +
		"schema: v1\n" +
		"tool: secure-vibe " + toolVersion + "\n"
	return os.WriteFile(path, []byte(content), 0o644)
}
