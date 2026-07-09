package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// repoRootForTest walks up from CWD until it finds go.mod, mirroring
// the helper in internal/tools/library_test.go. Saves every test from
// re-implementing the same walk.
func repoRootForTest(t *testing.T) string {
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
	t.Fatalf("could not find go.mod from %s", wd)
	return ""
}

// TestResolveLibraryRoot locks in the precedence that lets the file
// scanners run inside an arbitrary project: explicit --path wins, then
// $SECURE_VIBE_LIBRARY_PATH, then the "." cwd default. The env step is what
// makes `secure-vibe policy-check` usable from a user's CI / pre-commit
// without a secure-vibe checkout in the working directory.
func TestResolveLibraryRoot(t *testing.T) {
	// Isolate the data-dir fallback to an empty dir so the "stays cwd" cases
	// are deterministic regardless of a real ~/.local/share/secure-vibe.
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	cases := []struct {
		name    string
		flagVal string
		env     string // "" means unset
		want    string
	}{
		{"explicit path beats env", "/explicit/root", "/env/root", "/explicit/root"},
		{"explicit path, no env", "/explicit/root", "", "/explicit/root"},
		{"dot default falls through to env", ".", "/env/root", "/env/root"},
		{"empty falls through to env", "", "/env/root", "/env/root"},
		{"dot default, no env, stays cwd", ".", "", "."},
		{"empty, no env, becomes cwd", "", "", "."},
		{"env is trimmed", ".", "  /env/root  ", "/env/root"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.env == "" {
				os.Unsetenv("SECURE_VIBE_LIBRARY_PATH")
			} else {
				t.Setenv("SECURE_VIBE_LIBRARY_PATH", tc.env)
			}
			if got := resolveLibraryRoot(tc.flagVal); got != tc.want {
				t.Errorf("resolveLibraryRoot(%q) with env %q = %q; want %q",
					tc.flagVal, tc.env, got, tc.want)
			}
		})
	}
}

// run executes one subcommand against the real repo and returns
// stdout, stderr, and the resulting error. The returned error is
// whatever the RunE handler produced — *not* an os.Exit — so tests
// can branch on the policy-failure sentinel.
func run(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	cmd := Root()
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return stdout.String(), stderr.String(), err
}

// TestResolveLibraryRootDataDirFallback locks in the install.sh path: when
// neither --path nor $SECURE_VIBE_LIBRARY_PATH is set and the cwd is not itself a
// checkout, resolution falls back to the per-user data dir an installer
// populated — but a cwd that IS a checkout still wins (contributor default).
func TestResolveLibraryRootDataDirFallback(t *testing.T) {
	os.Unsetenv("SECURE_VIBE_LIBRARY_PATH")

	xdg := t.TempDir()
	t.Setenv("XDG_DATA_HOME", xdg)
	dataDir := filepath.Join(xdg, "secure-vibe")
	if err := os.MkdirAll(filepath.Join(dataDir, "skills"), 0o755); err != nil {
		t.Fatal(err)
	}

	// Non-library cwd → fall back to the populated data dir.
	withCwd(t, t.TempDir())
	if got := resolveLibraryRoot("."); got != dataDir {
		t.Errorf("non-library cwd: resolveLibraryRoot(\".\") = %q; want data dir %q", got, dataDir)
	}

	// A cwd that is itself a checkout wins over the data dir.
	libCwd := t.TempDir()
	if err := os.MkdirAll(filepath.Join(libCwd, "skills"), 0o755); err != nil {
		t.Fatal(err)
	}
	withCwd(t, libCwd)
	if got := resolveLibraryRoot("."); got != "." {
		t.Errorf("library cwd: resolveLibraryRoot(\".\") = %q; want \".\"", got)
	}
}

// withCwd chdir's into dir for the rest of the test (Go 1.22-compatible; no t.Chdir).
func withCwd(t *testing.T, dir string) {
	t.Helper()
	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(orig) })
}

func TestCheckHappyPath(t *testing.T) {
	out, _, err := run(t, "check", "express@4.18.0", "-e", "npm", "--path", repoRootForTest(t))
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !strings.Contains(out, "check express@4.18.0 (npm)") {
		t.Errorf("expected heading missing\n%s", out)
	}
	// PR #1: express@npm must not leak Java CVE pattern hits.
	if !strings.Contains(out, "CVE pattern hits:   0") {
		t.Errorf("express@npm leaked a CVE pattern hit:\n%s", out)
	}
}

func TestCheckJSONFormat(t *testing.T) {
	out, _, err := run(t, "check", "express@4.18.0", "-e", "npm", "--path", repoRootForTest(t), "--format", "json")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	var got map[string]interface{}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("invalid JSON output: %v\n%s", err, out)
	}
	if got["package"] != "express" || got["ecosystem"] != "npm" {
		t.Errorf("JSON payload missing expected fields: %v", got)
	}
}

func TestCheckRejectsMissingEcosystem(t *testing.T) {
	_, _, err := run(t, "check", "express", "--path", repoRootForTest(t))
	if err == nil || !strings.Contains(err.Error(), "ecosystem") {
		t.Fatalf("expected ecosystem-required error, got %v", err)
	}
}

func TestCheckRejectsUnknownFormat(t *testing.T) {
	_, _, err := run(t, "check", "express", "-e", "npm", "--path", repoRootForTest(t), "--format", "xml")
	if err == nil || !strings.Contains(err.Error(), "format") {
		t.Fatalf("expected format error, got %v", err)
	}
}

func TestCheckTyposquat(t *testing.T) {
	out, _, err := run(t, "check", "lodahs", "-e", "npm", "--path", repoRootForTest(t))
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	// lodahs is the canonical typosquat of lodash in the bundled DB.
	if !strings.Contains(out, "lodash") {
		t.Errorf("lodahs did not resolve to lodash:\n%s", out)
	}
}

func TestCheckMalicious(t *testing.T) {
	out, _, err := run(t, "check", "event-stream@3.3.6", "-e", "npm", "--path", repoRootForTest(t))
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	// event-stream@3.3.6 is the canonical malicious release.
	if !strings.Contains(out, "Malicious entries:") || strings.Contains(out, "Malicious entries:  0") {
		t.Errorf("event-stream was not flagged malicious:\n%s", out)
	}
}

func TestPolicyFailureSentinelIsDistinguishable(t *testing.T) {
	// IsPolicyFailure is exported so external callers (and a future
	// outer wrapper) can branch on "findings found" vs "tool errored".
	// Verify the predicate distinguishes the two paths correctly.
	err := &policyFailureError{count: 3, floor: "high"}
	if !IsPolicyFailure(err) {
		t.Error("IsPolicyFailure should accept *policyFailureError")
	}
	if IsPolicyFailure(errors.New("some other error")) {
		t.Error("IsPolicyFailure should reject unrelated errors")
	}
	if IsPolicyFailure(nil) {
		t.Error("IsPolicyFailure should reject nil")
	}
	want := "gate: 3 finding(s) at or above high"
	if got := err.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

// parser dispatch table in internal/tools/parsers/parsers.go. composer.lock,
// Package.resolved, and pubspec.lock parsers shipped, but knownLockfileName
// was not updated to match, so `scan-dependencies <dir>` silently skipped
// them while single-file scans worked. Guards that regression.
func TestKnownLockfileNameNewParsers(t *testing.T) {
	for _, base := range []string{"composer.lock", "Package.resolved", "pubspec.lock"} {
		if !knownLockfileName(base) {
			t.Errorf("knownLockfileName(%q) = false; directory discovery would skip it "+
				"even though parsers.Parse recognises it", base)
		}
	}
	// A non-lockfile name must still be rejected.
	if knownLockfileName("README.md") {
		t.Errorf("knownLockfileName(README.md) = true, want false")
	}
}
