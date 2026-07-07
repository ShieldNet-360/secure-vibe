package cmd

import (
	"context"
	"testing"

	"github.com/shieldnet-360/secure-vibe/internal/audit"
	"github.com/shieldnet-360/secure-vibe/internal/tools"
)

func TestRunDynamicVerifyDryRun(t *testing.T) {
	rep := &audit.Report{Findings: []audit.Finding{
		{ // dynamically verifiable
			PolicyCheckFinding: tools.PolicyCheckFinding{RuleID: "secure-vibe.llm.sqli", Title: "SQL injection", Severity: "high"},
			FilePath:           "/app/db.go", Scan: "llm-semantic",
		},
		{ // not a dynamic class -> skipped
			PolicyCheckFinding: tools.PolicyCheckFinding{RuleID: "secret", Title: "API key", Severity: "critical"},
			FilePath:           "/app/config.js", Scan: "scan_secrets",
		},
	}}

	// confirm=false => dry-run, no network, no scope needed.
	n := runDynamicVerify(context.Background(), rep, "http://example.test/api", "q", "", false)
	if n != 1 {
		t.Fatalf("probed %d findings, want 1 (only the sqli)", n)
	}
	v := rep.Findings[0].Verify
	if v == nil || v.Class != "sqli" || !v.DryRun {
		t.Fatalf("sqli verify = %+v, want a dry-run sqli verdict", v)
	}
	if rep.Findings[1].Verify != nil {
		t.Errorf("non-dynamic finding should not be probed")
	}
}

func TestScopeAllowFunc(t *testing.T) {
	t.Setenv("SECURE_VIBE_VERIFY_SCOPE", "staging.internal, 127.0.0.1")
	allow := scopeAllowFunc()
	if !allow("http://staging.internal/api") {
		t.Error("staging.internal should be in scope")
	}
	if allow("http://prod.example.com/api") {
		t.Error("prod should be out of scope")
	}

	t.Setenv("SECURE_VIBE_VERIFY_SCOPE", "")
	if scopeAllowFunc()("http://anything") {
		t.Error("empty scope must deny everything")
	}
}
