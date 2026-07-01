package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shieldnet-360/secure-vibe/internal/tools"
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

func TestScanSecretsFile(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "secret.txt")
	const fake = "STRIPE_KEY = \"sk_live_51H8xYzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdef\"\n"
	if err := os.WriteFile(tmp, []byte(fake), 0o644); err != nil {
		t.Fatal(err)
	}
	out, _, err := run(t, "scan", "--path", repoRootForTest(t), tmp)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !strings.Contains(out, "Scanner used: scan_secrets") {
		t.Errorf("scan did not auto-pick the secret scanner:\n%s", out)
	}
	if strings.Contains(out, "Findings: 0") {
		t.Errorf("scan missed a Stripe live key in the fixture:\n%s", out)
	}
}

func TestScanDockerfile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "Dockerfile")
	const docker = "FROM node:latest\nUSER root\nRUN curl http://example.com | sh\n"
	if err := os.WriteFile(path, []byte(docker), 0o644); err != nil {
		t.Fatal(err)
	}
	out, _, err := run(t, "scan", "--path", repoRootForTest(t), path)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if strings.Contains(out, "Findings: 0") {
		t.Errorf("scan missed obvious Dockerfile anti-patterns:\n%s", out)
	}
}

// policy_check dispatches scanners by file basename: "Dockerfile" →
// scan_dockerfile, lockfile names → scan_dependencies, etc. So tests
// for policy-check must use the canonical basename inside an
// otherwise-unique temp directory, not a unique filename.
func writeFixedNameFixture(t *testing.T, basename, body string) string {
	t.Helper()
	dir := t.TempDir()
	full := filepath.Join(dir, basename)
	if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return full
}

func TestPolicyCheckFailsOnBadDockerfile(t *testing.T) {
	const docker = `FROM node:latest
USER root
RUN curl http://example.com | sh
`
	path := writeFixedNameFixture(t, "Dockerfile", docker)
	out, _, err := run(t,
		"gate",
		"--path", repoRootForTest(t),
		"--severity-floor", "high",
		path,
	)
	if err == nil {
		t.Fatalf("policy-check did not signal failure for bad Dockerfile:\n%s", out)
	}
	if !IsPolicyFailure(err) {
		t.Errorf("expected policy-failure sentinel, got %T: %v", err, err)
	}
	if !strings.Contains(out, "FAIL") {
		t.Errorf("output does not show FAIL verdict:\n%s", out)
	}
}

func TestPolicyCheckPassesOnCleanDockerfile(t *testing.T) {
	const docker = `FROM node:18@sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890
USER 10001
RUN echo "no remote fetch, no curl|sh"
HEALTHCHECK CMD true
CMD ["node", "server.js"]
`
	path := writeFixedNameFixture(t, "Dockerfile", docker)
	out, _, err := run(t,
		"gate",
		"--path", repoRootForTest(t),
		"--severity-floor", "high",
		path,
	)
	if err != nil {
		t.Fatalf("policy-check failed on clean Dockerfile (unexpected): %v\n%s", err, out)
	}
	if !strings.Contains(out, "PASS") {
		t.Errorf("output does not show PASS verdict:\n%s", out)
	}
}

// TestGateMultipleFilesFailsIfAnyFails confirms `gate file1 file2 …` — what a
// pre-commit hook passes for the whole staged set — gates over every file and
// fails if ANY of them has a finding at or above the floor.
func TestGateMultipleFilesFailsIfAnyFails(t *testing.T) {
	bad := writeFixedNameFixture(t, "Dockerfile", "FROM node:latest\nUSER root\n")
	clean := writeFixedNameFixture(t, "notes.txt", "nothing secret here\n")
	out, _, err := run(t,
		"gate",
		"--path", repoRootForTest(t),
		"--severity-floor", "high",
		bad, clean,
	)
	if err == nil {
		t.Fatalf("gate did not fail when one of two files is bad:\n%s", out)
	}
	if !IsPolicyFailure(err) {
		t.Errorf("expected policy-failure sentinel, got %T: %v", err, err)
	}
	if !strings.Contains(out, "2 file(s), 1 failing") {
		t.Errorf("multi-file summary missing:\n%s", out)
	}
}

// TestGateMultipleFilesPassesWhenAllClean is the inverse: a clean staged set
// exits 0.
func TestGateMultipleFilesPassesWhenAllClean(t *testing.T) {
	a := writeFixedNameFixture(t, "a.txt", "clean one\n")
	b := writeFixedNameFixture(t, "b.txt", "clean two\n")
	out, _, err := run(t,
		"gate",
		"--path", repoRootForTest(t),
		"--severity-floor", "high",
		a, b,
	)
	if err != nil {
		t.Fatalf("gate failed on two clean files (unexpected): %v\n%s", err, out)
	}
	if !strings.Contains(out, "2 file(s), 0 failing") {
		t.Errorf("multi-file summary missing:\n%s", out)
	}
}

// TestGateDirectoryModeWalksAndSkips confirms a directory argument is
// walked for both specialised findings (the workflow) and secrets in
// ordinary text files (config/app.env), while noise dirs (node_modules)
// and binary files (a NUL-containing .png) are skipped.
func TestGateDirectoryModeWalksAndSkips(t *testing.T) {
	root := t.TempDir()
	mustWrite := func(rel string, body []byte) {
		full := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, body, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite("svc/.github/workflows/ci.yml",
		[]byte("name: ci\non: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@main\n"))
	// Secret in an ordinary file the walk must now reach.
	mustWrite("config/app.env", []byte("AWS_ACCESS_KEY_ID = AKIAZ1234567890ABCDE\n"))
	// Binary file (NUL bytes) carrying a key-shaped string: must be skipped.
	mustWrite("assets/logo.png", []byte("PNG\x00\x00AKIAZ1234567890ABCDE\x00"))
	// Secret inside a noise dir: must be skipped.
	mustWrite("node_modules/evil/leak.env", []byte("AWS_ACCESS_KEY_ID = AKIAZ0000000000NMOD\n"))

	out, _, err := run(t,
		"gate", "--path", repoRootForTest(t),
		"--severity-floor", "high", root,
	)
	if err == nil {
		t.Fatalf("directory gate should fail on the env secret:\n%s", out)
	}
	if !IsPolicyFailure(err) {
		t.Errorf("expected policy-failure sentinel, got %T: %v", err, err)
	}
	if !strings.Contains(out, filepath.FromSlash("config/app.env")) {
		t.Errorf("secret in config/app.env was not gated (secret-scan should run across the walk):\n%s", out)
	}
	if !strings.Contains(out, filepath.FromSlash("svc/.github/workflows/ci.yml")) {
		t.Errorf("workflow not gated:\n%s", out)
	}
	if strings.Contains(out, "node_modules") {
		t.Errorf("node_modules must be skipped:\n%s", out)
	}
	if strings.Contains(out, "logo.png") {
		t.Errorf("binary file must be skipped:\n%s", out)
	}
}

// TestGateEmptyDirectoryPassesQuietly confirms a directory with no
// scannable files (only a binary) exits 0 with a clear message rather
// than erroring.
func TestGateEmptyDirectoryPassesQuietly(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "icon.ico"), []byte("\x00\x00\x01\x00binary"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, _, err := run(t, "gate", "--path", repoRootForTest(t), dir)
	if err != nil {
		t.Fatalf("directory with only a binary should pass: %v\n%s", err, out)
	}
	if !strings.Contains(out, "nothing to gate") {
		t.Errorf("expected a 'nothing to gate' message:\n%s", out)
	}
}

// TestGateReportDir confirms gate --report-dir writes an HTML + PDF
// report for a directory of files AND still fails the build (the report
// is written before the exit-code decision, like SARIF).
func TestGateReportDir(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "Dockerfile"),
		[]byte("FROM node:latest\nUSER root\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	reportDir := t.TempDir()
	out, _, err := run(t, "gate",
		"--path", repoRootForTest(t), "--severity-floor", "medium",
		"--report-dir", reportDir, root,
	)
	if err == nil {
		t.Fatalf("gate --report-dir should still fail on the bad Dockerfile:\n%s", out)
	}
	if !IsPolicyFailure(err) {
		t.Errorf("expected policy-failure sentinel, got %T: %v", err, err)
	}
	html := filepath.Join(reportDir, "gate-report.html")
	pdf := filepath.Join(reportDir, "gate-report.pdf")
	for _, p := range []string{html, pdf} {
		fi, statErr := os.Stat(p)
		if statErr != nil {
			t.Fatalf("expected report file %s: %v", p, statErr)
		}
		if fi.Size() == 0 {
			t.Errorf("report file %s is empty", p)
		}
	}
	body, _ := os.ReadFile(html)
	if !strings.Contains(string(body), "Dockerfile") {
		t.Errorf("HTML report does not mention the scanned Dockerfile:\n%s", body)
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

// TestGateSARIFOnFailingFile locks the contract for `gate --format
// sarif`: stdout is a schema-valid SARIF 2.1.0 document carrying the
// planted finding, AND the command still exits non-zero. The SARIF is
// written before the failure sentinel is returned, so a CI step can
// both fail the build and upload-sarif the findings in one invocation.
func TestGateSARIFOnFailingFile(t *testing.T) {
	const docker = `FROM node:latest
USER root
RUN curl http://example.com | sh
`
	path := writeFixedNameFixture(t, "Dockerfile", docker)
	out, _, err := run(t,
		"gate",
		"--path", repoRootForTest(t),
		"--severity-floor", "high",
		"--format", "sarif",
		path,
	)
	// Exit code preserved: a failing gate must still signal failure.
	if err == nil {
		t.Fatalf("gate --format sarif did not signal failure for bad Dockerfile:\n%s", out)
	}
	if !IsPolicyFailure(err) {
		t.Errorf("expected policy-failure sentinel, got %T: %v", err, err)
	}
	// Stdout must be a schema-valid SARIF 2.1.0 log carrying the finding.
	var log tools.SARIFLog
	if jerr := json.Unmarshal([]byte(out), &log); jerr != nil {
		t.Fatalf("gate SARIF output is not valid JSON: %v\n%s", jerr, out)
	}
	if log.Version != "2.1.0" {
		t.Errorf("SARIF version = %q, want 2.1.0", log.Version)
	}
	if log.Schema == "" {
		t.Error("SARIF $schema is empty")
	}
	if len(log.Runs) != 1 {
		t.Fatalf("want exactly 1 run, got %d", len(log.Runs))
	}
	if len(log.Runs[0].Results) == 0 {
		t.Errorf("planted finding did not appear in SARIF results:\n%s", out)
	}
	if len(log.Runs[0].Tool.Driver.Rules) == 0 {
		t.Errorf("SARIF rules table is empty; results cannot reference a rule:\n%s", out)
	}
	// Every result must reference a rule that exists in the table, and
	// carry a non-empty message (SARIF 2.1.0 requires message.text).
	for i, res := range log.Runs[0].Results {
		if res.RuleIndex < 0 || res.RuleIndex >= len(log.Runs[0].Tool.Driver.Rules) {
			t.Errorf("result %d ruleIndex %d out of range (rules=%d)",
				i, res.RuleIndex, len(log.Runs[0].Tool.Driver.Rules))
		}
		if res.Message.Text == "" {
			t.Errorf("result %d has empty message.text (invalid SARIF)", i)
		}
	}
}

// TestGateSARIFRelativeURIs locks the URI contract that GitHub Code
// Scanning anchoring depends on (verified on a live fixture repo:
// absolute file:// URIs ingest but render as dead paths; repo-relative
// URIs anchor to the file). With --sarif-base pointing at the
// directory containing the scanned file, the artifact URI must be the
// bare relative path; without it (default cwd, which the temp fixture
// lives outside of), the URI must fall back to an absolute file:// —
// never a ../../ escape path.
func TestGateSARIFRelativeURIs(t *testing.T) {
	const docker = `FROM node:latest
USER root
`
	path := writeFixedNameFixture(t, "Dockerfile", docker)

	uriOf := func(out string) string {
		t.Helper()
		var log tools.SARIFLog
		if err := json.Unmarshal([]byte(out), &log); err != nil {
			t.Fatalf("not valid SARIF JSON: %v\n%s", err, out)
		}
		res := log.Runs[0].Results
		if len(res) == 0 {
			t.Fatalf("no results in SARIF:\n%s", out)
		}
		return res[0].Locations[0].PhysicalLocation.ArtifactLocation.URI
	}

	// --sarif-base = the fixture's dir → bare relative path.
	out, _, err := run(t,
		"gate",
		"--path", repoRootForTest(t),
		"--severity-floor", "high",
		"--format", "sarif",
		"--sarif-base", filepath.Dir(path),
		path,
	)
	if err == nil {
		t.Fatal("gate should fail on the planted Dockerfile")
	}
	if got := uriOf(out); got != "Dockerfile" {
		t.Errorf("with --sarif-base, uri = %q, want %q", got, "Dockerfile")
	}

	// Default base (cwd) — fixture lives outside it → absolute
	// file:// fallback, never a ../.. escape.
	out, _, err = run(t,
		"gate",
		"--path", repoRootForTest(t),
		"--severity-floor", "high",
		"--format", "sarif",
		path,
	)
	if err == nil {
		t.Fatal("gate should fail on the planted Dockerfile")
	}
	if got := uriOf(out); !strings.HasPrefix(got, "file://") {
		t.Errorf("outside-base uri = %q, want absolute file:// fallback", got)
	} else if strings.Contains(got, "..") {
		t.Errorf("outside-base uri %q contains a path escape", got)
	}
}

// TestGateSARIFOnCleanFileIsWellFormed confirms a passing gate still
// emits well-formed SARIF with empty-but-non-null results/rules arrays
// (GitHub Advanced Security rejects the JSON `null` form) and exits 0.
func TestGateSARIFOnCleanFileIsWellFormed(t *testing.T) {
	clean := writeFixedNameFixture(t, "notes.txt", "nothing secret here\n")
	out, _, err := run(t,
		"gate",
		"--path", repoRootForTest(t),
		"--severity-floor", "high",
		"--format", "sarif",
		clean,
	)
	if err != nil {
		t.Fatalf("gate --format sarif failed on clean file (unexpected): %v\n%s", err, out)
	}
	var log tools.SARIFLog
	if jerr := json.Unmarshal([]byte(out), &log); jerr != nil {
		t.Fatalf("clean-gate SARIF is not valid JSON: %v\n%s", jerr, out)
	}
	if log.Version != "2.1.0" || len(log.Runs) != 1 {
		t.Fatalf("malformed SARIF skeleton: version=%q runs=%d", log.Version, len(log.Runs))
	}
	if len(log.Runs[0].Results) != 0 {
		t.Errorf("clean gate should have 0 results, got %d", len(log.Runs[0].Results))
	}
	// Lock the null-avoidance contract GHAS depends on.
	if !strings.Contains(out, `"results": []`) {
		t.Errorf("results array serialised as null, not []:\n%s", out)
	}
	if !strings.Contains(out, `"rules": []`) {
		t.Errorf("rules array serialised as null, not []:\n%s", out)
	}
}

// TestKnownLockfileNameNewParsers locks the directory-discovery list to the
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
