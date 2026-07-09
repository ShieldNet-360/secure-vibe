package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const fakePAT = "const gh = \"ghp_016C6eB6D6a1F2b3C4d5E6f7A8b9C0d1E2f3G4H5\";\n"

// auditTarget writes a tree with a real secret in app code and the same secret
// inside a testdata fixture (which audit should triage).
func auditTarget(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "app", "testdata"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "app", "config.js"), []byte(fakePAT), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "app", "testdata", "leak.js"), []byte(fakePAT), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestAuditReportsAndTriagesFixtures(t *testing.T) {
	dir := auditTarget(t)
	out, _, err := run(t, "audit", dir, "--path", repoRootForTest(t))
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if !strings.Contains(out, "GitHub Personal Access Token") {
		t.Errorf("confirmed secret missing from report:\n%s", out)
	}
	if !strings.Contains(out, "triaged") {
		t.Errorf("fixture secret was not triaged:\n%s", out)
	}
}

// TestAuditTextPresentation locks in the v1.2 presentation: a compact header,
// repo-relative paths (not absolute), a per-finding class tag, and a footer.
func TestAuditTextPresentation(t *testing.T) {
	dir := auditTarget(t)
	out, _, err := run(t, "audit", dir, "--path", repoRootForTest(t))
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	for _, want := range []string{"secure-vibe audit ·", "app/config.js", "(secret)", "Next:"} {
		if !strings.Contains(out, want) {
			t.Errorf("presentation missing %q in:\n%s", want, out)
		}
	}
	// The confirmed finding's line must NOT show the absolute temp-dir path.
	if strings.Contains(out, filepath.Join(dir, "app", "config.js")) {
		t.Errorf("report shows an absolute path; expected relative:\n%s", out)
	}
}

func TestAuditFailOnExitsNonZero(t *testing.T) {
	dir := auditTarget(t)
	_, _, err := run(t, "audit", dir, "--path", repoRootForTest(t), "--fail-on", "high")
	if !IsPolicyFailure(err) {
		t.Fatalf("expected a policy failure with confirmed findings, got %v", err)
	}
}

func TestAuditFailOnCleanPasses(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ok.txt"), []byte("nothing to see here\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := run(t, "audit", dir, "--path", repoRootForTest(t), "--fail-on", "high"); err != nil {
		t.Fatalf("clean dir should pass the gate, got %v", err)
	}
}

// --no-triage flips a fixture-only secret from demoted (gate passes) to confirmed
// (gate trips), locking in the strict-gate behaviour.
func TestAuditNoTriageIncludesFixtures(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "testdata"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "testdata", "leak.js"), []byte(fakePAT), 0o644); err != nil {
		t.Fatal(err)
	}
	root := repoRootForTest(t)
	if _, _, err := run(t, "audit", dir, "--path", root, "--fail-on", "high"); err != nil {
		t.Fatalf("triaged fixture should not fail the gate, got %v", err)
	}
	if _, _, err := run(t, "audit", dir, "--path", root, "--fail-on", "high", "--no-triage"); !IsPolicyFailure(err) {
		t.Fatalf("--no-triage should fail on the fixture secret, got %v", err)
	}
}

func TestAuditSARIF(t *testing.T) {
	dir := auditTarget(t)
	out, _, err := run(t, "audit", dir, "--path", repoRootForTest(t), "--format", "sarif")
	if err != nil {
		t.Fatalf("audit --format sarif: %v", err)
	}
	var log struct {
		Runs []struct {
			Results []struct {
				RuleID string `json:"ruleId"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(out), &log); err != nil {
		t.Fatalf("invalid SARIF JSON: %v\n%s", err, out)
	}
	if len(log.Runs) != 1 || len(log.Runs[0].Results) == 0 {
		t.Errorf("expected at least one SARIF result:\n%s", out)
	}
}
