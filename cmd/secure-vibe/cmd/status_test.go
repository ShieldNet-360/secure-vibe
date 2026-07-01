package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	tm, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return tm.UTC()
}

// writeStatusFixture builds a minimal library root with a manifest, one
// OSV ecosystem index, and one skill so buildStatusReport has something
// to summarise.
func writeStatusFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	must := func(p, body string) {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	must("manifest.json", `{"schema_version":"1.0","version":"2026.05.12.1","released_at":"2026-05-12T10:00:00Z"}`)
	must("vulnerabilities/osv/npm/index.json", `{
		"last_updated": "2026-05-16T00:00:00Z",
		"by_package": {
			"a": [{"id":"GHSA-1"},{"id":"GHSA-2"}],
			"b": [{"id":"GHSA-2"}]
		}
	}`)
	must("skills/auth-security/SKILL.md", "# skill\n")
	return root
}

func TestStatusReportCounts(t *testing.T) {
	root := writeStatusFixture(t)
	now := mustTime(t, "2026-05-20T00:00:00Z")
	rep := buildStatusReport(root, now)

	if rep.LibraryVersion != "2026.05.12.1" {
		t.Errorf("version = %q", rep.LibraryVersion)
	}
	if rep.LibraryAgeDays != 7 {
		t.Errorf("library age = %d, want 7", rep.LibraryAgeDays)
	}
	// GHSA-2 is shared across packages -> 2 DISTINCT advisories, not 3.
	if rep.VulnAdvisories != 2 {
		t.Errorf("distinct advisories = %d, want 2 (dedup by ID)", rep.VulnAdvisories)
	}
	if rep.VulnEcosystems != 1 {
		t.Errorf("ecosystems = %d, want 1", rep.VulnEcosystems)
	}
	if rep.Skills != 1 {
		t.Errorf("skills = %d, want 1", rep.Skills)
	}
	if rep.VulnAgeDays != 4 {
		t.Errorf("vuln age = %d, want 4", rep.VulnAgeDays)
	}
	if rep.Freshness != "fresh" {
		t.Errorf("freshness = %q, want fresh", rep.Freshness)
	}
}

func TestStatusFreshnessVerdict(t *testing.T) {
	cases := []struct {
		age  int
		want string
	}{
		{-1, "unknown"},
		{0, "fresh"},
		{7, "fresh"},
		{8, "aging"},
		{30, "aging"},
		{31, "stale"},
		{365, "stale"},
	}
	for _, c := range cases {
		if got := freshnessVerdict(c.age); got != c.want {
			t.Errorf("freshnessVerdict(%d) = %q, want %q", c.age, got, c.want)
		}
	}
}

// TestStatusStaleRendersWarning confirms the human output names the
// remedy when the data is old.
func TestStatusStaleRendersWarning(t *testing.T) {
	root := writeStatusFixture(t)
	now := mustTime(t, "2026-09-01T00:00:00Z") // ~3.5 months later
	rep := buildStatusReport(root, now)
	if rep.Freshness != "stale" {
		t.Fatalf("expected stale, got %q", rep.Freshness)
	}
	var buf bytes.Buffer
	renderStatus(&buf, rep)
	if !bytes.Contains(buf.Bytes(), []byte("secure-vibe update")) {
		t.Errorf("stale output should recommend an update; got:\n%s", buf.String())
	}
}

// TestStatusMissingDataDegrades confirms an empty root does not error.
func TestStatusMissingDataDegrades(t *testing.T) {
	root := t.TempDir()
	now := mustTime(t, "2026-05-20T00:00:00Z")
	rep := buildStatusReport(root, now)
	if rep.LibraryVersion != "unknown" {
		t.Errorf("missing manifest: version = %q, want unknown", rep.LibraryVersion)
	}
	if rep.Freshness != "unknown" {
		t.Errorf("no vuln data: freshness = %q, want unknown", rep.Freshness)
	}
	// JSON round-trips without panic.
	if _, err := json.Marshal(rep); err != nil {
		t.Errorf("marshal: %v", err)
	}
}

// runStatus executes `status <args...>` and returns stdout + error.
func runStatus(t *testing.T, args ...string) (string, error) {
	t.Helper()
	root := Root()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs(append([]string{"status"}, args...))
	return func() (string, error) { e := root.Execute(); return buf.String(), e }()
}

func TestStatusFailIfStaleGate(t *testing.T) {
	root := writeStatusFixture(t) // newest index 2026-05-16

	// Fresh relative to a near now: gate passes.
	if _, err := runStatus(t, "--path", root, "--fail-if-stale", "--now", "2026-05-18T00:00:00Z"); err != nil {
		t.Errorf("fresh data should pass the gate: %v", err)
	}
	// Old relative to a far now: gate fails.
	if _, err := runStatus(t, "--path", root, "--fail-if-stale", "--now", "2026-09-01T00:00:00Z"); err == nil {
		t.Error("stale data should fail --fail-if-stale")
	}
	// --max-age-days overrides the default threshold.
	if _, err := runStatus(t, "--path", root, "--max-age-days", "3", "--now", "2026-05-20T00:00:00Z"); err == nil {
		t.Error("4-day-old data should fail --max-age-days 3")
	}
	if _, err := runStatus(t, "--path", root, "--max-age-days", "30", "--now", "2026-05-20T00:00:00Z"); err != nil {
		t.Errorf("4-day-old data should pass --max-age-days 30: %v", err)
	}
}
