package audit

import (
	"strings"
	"testing"

	"github.com/shieldnet-360/secure-vibe/internal/tools"
)

func TestReportSARIFFullLane(t *testing.T) {
	rep := &Report{Findings: []Finding{
		{ // deterministic
			PolicyCheckFinding: tools.PolicyCheckFinding{RuleID: "secure-vibe.secret.gh", Severity: "critical", Title: "GitHub PAT", Line: 3},
			FilePath:           "/repo/config.js", Scan: "scan_secrets",
		},
		{ // model-semantic — must reach SARIF (full-lane)
			PolicyCheckFinding: tools.PolicyCheckFinding{RuleID: "secure-vibe.llm.sqli", Severity: "high", Title: "SQL injection"},
			FilePath:           "/repo/db.go", Scan: semanticScan,
		},
		{ // triaged fixture — must be excluded
			PolicyCheckFinding: tools.PolicyCheckFinding{RuleID: "secure-vibe.secret.gh", Severity: "critical", Title: "GitHub PAT", Line: 1},
			FilePath:           "/repo/testdata/x.js", Scan: "scan_secrets", Triage: "likely-fixture",
		},
	}}

	log := rep.SARIF("/repo")
	if len(log.Runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(log.Runs))
	}
	res := log.Runs[0].Results
	if len(res) != 2 {
		t.Fatalf("results = %d, want 2 (triaged excluded)", len(res))
	}

	var sawSemantic, sawSecret bool
	for _, r := range res {
		switch r.RuleID {
		case "secure-vibe.llm.sqli":
			sawSemantic = true
		case "secure-vibe.secret.gh":
			sawSecret = true
		}
		if uri := r.Locations[0].PhysicalLocation.ArtifactLocation.URI; strings.HasPrefix(uri, "/") || strings.HasPrefix(uri, "file://") {
			t.Errorf("URI not repo-relative: %q", uri)
		}
	}
	if !sawSemantic {
		t.Error("model-semantic finding missing from SARIF (full-lane broken)")
	}
	if !sawSecret {
		t.Error("deterministic finding missing from SARIF")
	}
	if log.Runs[0].Tool.Driver.Name != "secure-vibe" {
		t.Errorf("driver name = %q", log.Runs[0].Tool.Driver.Name)
	}
	if log.Version != tools.SARIFVersion {
		t.Errorf("version = %q", log.Version)
	}
}
