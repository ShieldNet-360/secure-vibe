package audit

import (
	"strings"
	"testing"

	"github.com/shieldnet-360/secure-vibe/internal/tools"
)

func TestReportSARIF(t *testing.T) {
	rep := &Report{Findings: []Finding{
		{
			PolicyCheckFinding: tools.PolicyCheckFinding{RuleID: "secure-vibe.secret.gh", Severity: "critical", Title: "GitHub PAT", Line: 3},
			FilePath:           "/repo/config.js", Scan: "scan_secrets",
		},
		{
			PolicyCheckFinding: tools.PolicyCheckFinding{RuleID: "secure-vibe.dockerfile.root", Severity: "high", Title: "USER root"},
			FilePath:           "/repo/Dockerfile", Scan: "scan_dockerfile",
		},
		{ // triaged fixture — must be excluded from SARIF
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
	for _, r := range res {
		if r.RuleID == "secure-vibe.secret.gh" && strings.Contains(r.Locations[0].PhysicalLocation.ArtifactLocation.URI, "testdata") {
			t.Error("triaged fixture leaked into SARIF")
		}
		if uri := r.Locations[0].PhysicalLocation.ArtifactLocation.URI; strings.HasPrefix(uri, "/") || strings.HasPrefix(uri, "file://") {
			t.Errorf("URI not repo-relative: %q", uri)
		}
	}
	if log.Runs[0].Tool.Driver.Name != "secure-vibe" {
		t.Errorf("driver name = %q", log.Runs[0].Tool.Driver.Name)
	}
	if log.Version != tools.SARIFVersion {
		t.Errorf("version = %q", log.Version)
	}
}
