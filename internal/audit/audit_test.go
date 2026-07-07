package audit

import (
	"strings"
	"testing"

	"github.com/shieldnet-360/secure-vibe/internal/tools"
)

func TestBuildDedupTriageRank(t *testing.T) {
	results := []*tools.PolicyCheckResult{
		{
			FilePath: "/repo/app/config.js",
			Scan:     "scan_secrets",
			Findings: []tools.PolicyCheckFinding{
				{RuleID: "gh-pat", Severity: "critical", Title: "GitHub PAT", Line: 1},
				{RuleID: "gh-pat", Severity: "critical", Title: "GitHub PAT", Line: 1}, // exact dup
				{RuleID: "weak-hash", Severity: "low", Title: "Weak hash", Line: 5},
			},
		},
		{
			FilePath: "/repo/app/testdata/leak.js", // fixture path -> triaged
			Scan:     "scan_secrets",
			Findings: []tools.PolicyCheckFinding{
				{RuleID: "gh-pat", Severity: "critical", Title: "GitHub PAT", Line: 1},
			},
		},
		{
			FilePath: "/repo/Dockerfile",
			Scan:     "scan_dockerfile",
			Findings: []tools.PolicyCheckFinding{
				{RuleID: "root-user", Severity: "high", Title: "USER root", Line: 3},
			},
		},
	}

	rep := build("/repo", results)

	if rep.FilesScanned != 3 {
		t.Errorf("FilesScanned = %d, want 3", rep.FilesScanned)
	}
	if got := rep.Total(); got != 3 {
		t.Errorf("confirmed = %d, want 3 (dup collapsed, fixture excluded)", got)
	}
	if rep.Triaged != 1 {
		t.Errorf("triaged = %d, want 1", rep.Triaged)
	}
	if rep.Counts["critical"] != 1 || rep.Counts["high"] != 1 || rep.Counts["low"] != 1 {
		t.Errorf("counts = %v, want critical:1 high:1 low:1", rep.Counts)
	}

	// Ranking: confirmed findings ordered critical -> high -> low.
	confirmed := rep.Confirmed()
	if len(confirmed) != 3 {
		t.Fatalf("Confirmed() len = %d, want 3", len(confirmed))
	}
	wantOrder := []string{"critical", "high", "low"}
	for i, w := range wantOrder {
		if confirmed[i].Severity != w {
			t.Errorf("confirmed[%d].Severity = %q, want %q", i, confirmed[i].Severity, w)
		}
	}

	// The triaged finding sorts last and keeps its fixture path.
	last := rep.Findings[len(rep.Findings)-1]
	if last.Triage != "likely-fixture" {
		t.Errorf("last finding Triage = %q, want likely-fixture", last.Triage)
	}
	if !strings.Contains(last.FilePath, "testdata") {
		t.Errorf("triaged finding FilePath = %q, want testdata path", last.FilePath)
	}
}

func TestBuildDedupKeepsDistinctLines(t *testing.T) {
	// Same rule + file but different lines are distinct findings.
	results := []*tools.PolicyCheckResult{{
		FilePath: "/repo/a.js",
		Scan:     "scan_secrets",
		Findings: []tools.PolicyCheckFinding{
			{RuleID: "key", Severity: "high", Title: "Key", Line: 1},
			{RuleID: "key", Severity: "high", Title: "Key", Line: 9},
		},
	}}
	rep := build("/repo", results)
	if rep.Total() != 2 {
		t.Errorf("confirmed = %d, want 2 (distinct lines not deduped)", rep.Total())
	}
}

func TestTriagePath(t *testing.T) {
	cases := map[string]string{
		"/repo/app/config.js":           "",
		"/repo/src/main.go":             "",
		"/repo/app/testdata/x.js":       "likely-fixture",
		"/repo/tests/thing.go":          "likely-fixture",
		"/repo/examples/demo/app.js":    "likely-fixture",
		"/repo/pkg/fixtures/data.json":  "likely-fixture",
		"/repo/internal/__tests__/a.ts": "likely-fixture",
	}
	for p, want := range cases {
		if got := triagePath(p); got != want {
			t.Errorf("triagePath(%q) = %q, want %q", p, got, want)
		}
	}
}

func TestSeverityRankOrder(t *testing.T) {
	if !(severityRank("critical") > severityRank("high") &&
		severityRank("high") > severityRank("medium") &&
		severityRank("medium") > severityRank("low") &&
		severityRank("low") > severityRank("info")) {
		t.Fatal("severity ordering broken")
	}
	if severityRank("HIGH ") != severityRank("high") {
		t.Fatal("severityRank should trim + lowercase")
	}
}
