package cmd

import (
	"strings"
	"testing"

	"github.com/shieldnet-360/secure-vibe/internal/tools"
)

// TestSeverityRGB pins the badge colours for every severity branch plus
// the unknown-severity fallback so a colour regression is caught.
func TestSeverityRGB(t *testing.T) {
	cases := map[string][3]int{
		"critical": {176, 0, 32},
		"CRITICAL": {176, 0, 32}, // case-insensitive
		"high":     {217, 72, 15},
		"medium":   {176, 137, 0},
		"low":      {47, 111, 235},
		"info":     {91, 100, 112}, // default
		"":         {91, 100, 112}, // default
	}
	for sev, want := range cases {
		r, g, b := severityRGB(sev)
		if [3]int{r, g, b} != want {
			t.Errorf("severityRGB(%q) = %d,%d,%d; want %v", sev, r, g, b, want)
		}
	}
}

// TestPDFText folds typographic runes to ASCII and drops anything else
// outside printable ASCII so fpdf's Latin-1 fonts never render mojibake.
func TestPDFText(t *testing.T) {
	got := pdfText("em—dash · arrow→ “quote” it’s 90%")
	if strings.ContainsAny(got, "—·→““”’") {
		t.Errorf("pdfText left a non-ASCII rune: %q", got)
	}
	if !strings.Contains(got, "em-dash") || !strings.Contains(got, "arrow->") {
		t.Errorf("pdfText did not fold dashes/arrows: %q", got)
	}
	// Newlines and tabs collapse to spaces; other control/non-ASCII drop.
	if got := pdfText("a\nb\tc\x00é"); got != "a b c" {
		t.Errorf("pdfText control/non-ASCII handling = %q; want %q", got, "a b c")
	}
}

// TestDependencySection maps a ScanDependenciesResult into the generic
// report model, exercising both the plain-category and CVE locations.
func TestDependencySection(t *testing.T) {
	res := &tools.ScanDependenciesResult{
		FilePath:     "package-lock.json",
		Ecosystem:    "npm",
		Dependencies: 2,
		Findings: []tools.DependencyFinding{
			{Package: "evil", Version: "1.0.0", Severity: "critical", Category: "malicious", Message: "known bad"},
			{Package: "old", Version: "2.0.0", Severity: "high", Category: "cve", CVE: "CVE-2024-9999", Message: "vuln"},
		},
	}
	s := dependencySection(res)
	if s.Title != "package-lock.json" || !strings.Contains(s.Subtitle, "ecosystem=npm") {
		t.Fatalf("unexpected section header: %+v", s)
	}
	if len(s.Findings) != 2 {
		t.Fatalf("want 2 findings, got %d", len(s.Findings))
	}
	if s.Findings[0].Title != "evil@1.0.0" || s.Findings[0].Location != "malicious" {
		t.Errorf("finding[0] = %+v", s.Findings[0])
	}
	if s.Findings[1].Location != "cve · CVE-2024-9999" {
		t.Errorf("finding[1] location = %q; want CVE-joined", s.Findings[1].Location)
	}
}

// TestDockerfileSection carries the rule/line location and the fix through.
func TestDockerfileSection(t *testing.T) {
	res := &tools.ScanDockerfileResult{
		Findings: []tools.DockerfileFinding{
			{RuleID: "user-root", Severity: "high", Title: "runs as root", Line: 7, Snippet: "USER root", Fix: "add a non-root USER"},
		},
	}
	s := dockerfileSection("Dockerfile", res)
	if s.Title != "Dockerfile" || len(s.Findings) != 1 {
		t.Fatalf("unexpected section: %+v", s)
	}
	f := s.Findings[0]
	if f.Location != "user-root · line 7" || f.Fix != "add a non-root USER" || f.Detail != "USER root" {
		t.Errorf("dockerfile finding = %+v", f)
	}
}

// TestGitHubActionsSection joins rationale + snippet into Detail and
// keeps rationale-only / snippet-only paths correct.
func TestGitHubActionsSection(t *testing.T) {
	res := &tools.ScanGitHubActionsResult{
		Findings: []tools.WorkflowFinding{
			{RuleID: "inj", Severity: "critical", Title: "script injection", Line: 12, Rationale: "untrusted input", Snippet: "${{ github.event.issue.title }}", Fix: "use env"},
			{RuleID: "pin", Severity: "medium", Title: "unpinned", Line: 3, Snippet: "uses: foo/bar@main"},
		},
	}
	s := githubActionsSection("ci.yml", res)
	if len(s.Findings) != 2 {
		t.Fatalf("want 2 findings, got %d", len(s.Findings))
	}
	if got := s.Findings[0].Detail; !strings.Contains(got, "untrusted input — ") || !strings.Contains(got, "github.event.issue.title") {
		t.Errorf("rationale+snippet join = %q", got)
	}
	if s.Findings[0].Location != "inj · line 12" {
		t.Errorf("location = %q", s.Findings[0].Location)
	}
	if s.Findings[1].Detail != "uses: foo/bar@main" {
		t.Errorf("snippet-only detail = %q", s.Findings[1].Detail)
	}
}

// TestGateSection covers the line-based, package-based, and bare-rule
// location branches of the homogeneous gate finding shape.
func TestGateSection(t *testing.T) {
	res := &tools.PolicyCheckResult{
		FilePath:      "go.sum",
		Scan:          "scan_dependencies",
		SeverityFloor: "high",
		Findings: []tools.PolicyCheckFinding{
			{RuleID: "line-rule", Severity: "high", Title: "bad line", Line: 4, Snippet: "x"},
			{RuleID: "pkg-rule", Severity: "critical", Title: "bad pkg", Package: "evil", Version: "1.2.3"},
			{RuleID: "bare-rule", Severity: "medium", Title: "no loc"},
		},
	}
	s := gateSection(res)
	if s.Subtitle != "dependency scan" {
		t.Fatalf("subtitle = %q; want %q", s.Subtitle, "dependency scan")
	}
	wantLoc := []string{"line-rule · line 4", "pkg-rule · evil@1.2.3", "bare-rule"}
	for i, w := range wantLoc {
		if s.Findings[i].Location != w {
			t.Errorf("finding[%d] location = %q; want %q", i, s.Findings[i].Location, w)
		}
	}
}

// TestScannerRuleIDs confirms the skill->scanner-ruleset mapping returns
// a non-empty set for the two backed skills and nil otherwise.
func TestScannerRuleIDs(t *testing.T) {
	if len(scannerRuleIDs("container-security")) == 0 {
		t.Error("container-security should map to the dockerfile rule set")
	}
	if len(scannerRuleIDs("cicd-security")) == 0 {
		t.Error("cicd-security should map to the github-actions rule set")
	}
	if scannerRuleIDs("api-security") != nil {
		t.Error("a skill with no deterministic scanner should map to nil")
	}
}

// TestTestRunnerHelpers covers the small pure helpers in test.go
// (hasRule / ruleIDs / boolStr) that the corpus runner uses.
func TestTestRunnerHelpers(t *testing.T) {
	findings := []tools.PolicyCheckFinding{{RuleID: "a"}, {RuleID: "b"}}
	if !hasRule(findings, "a") || hasRule(findings, "z") {
		t.Error("hasRule mismatch")
	}
	if got := ruleIDs(findings); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("ruleIDs = %v", got)
	}
	if ruleIDs(nil) == nil {
		t.Error("ruleIDs(nil) should return a non-nil empty slice")
	}
	if boolStr(true) != "detect" || boolStr(false) != "ignore" {
		t.Error("boolStr mismatch")
	}
}
