package audit

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shieldnet-360/secure-vibe/internal/llm"
	"github.com/shieldnet-360/secure-vibe/internal/tools"
)

// fakeReviewer is a deterministic stand-in for the LLM lane.
type fakeReviewer struct {
	sweep    []Finding
	refuteIf func(Finding) bool
}

func (r *fakeReviewer) Sweep(_ context.Context, path, _ string) ([]Finding, error) {
	var out []Finding
	for _, s := range r.sweep {
		if s.FilePath == path {
			out = append(out, s)
		}
	}
	return out, nil
}

func (r *fakeReviewer) Refute(_ context.Context, f Finding, _ string) (bool, string, error) {
	if r.refuteIf != nil && r.refuteIf(f) {
		return true, "test fixture", nil
	}
	return false, "", nil
}

func TestEnrichSweepAndRefute(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "app.go")
	if err := os.WriteFile(src, []byte("package main\n// db.Query(q + userInput)\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	rep := build(dir, []*tools.PolicyCheckResult{{
		FilePath: src,
		Scan:     "scan_secrets",
		Findings: []tools.PolicyCheckFinding{
			{RuleID: "gh-pat", Severity: "critical", Title: "GitHub PAT", Line: 1},
		},
	}})
	if rep.Total() != 1 {
		t.Fatalf("pre-enrich confirmed = %d, want 1", rep.Total())
	}

	fr := &fakeReviewer{
		sweep: []Finding{{
			PolicyCheckFinding: tools.PolicyCheckFinding{RuleID: "secure-vibe.llm.sqli", Severity: "high", Title: "SQL injection", Line: 2},
			FilePath:           src,
			Scan:               semanticScan,
		}},
		refuteIf: func(f Finding) bool { return strings.Contains(f.RuleID, "gh-pat") },
	}
	if err := enrich(context.Background(), rep, []string{src}, fr, 2); err != nil {
		t.Fatal(err)
	}

	// The swept SQLi finding is added and confirmed; the deterministic gh-pat is
	// refuted (triaged) by the adversarial pass.
	if rep.Total() != 1 {
		t.Errorf("post-enrich confirmed = %d, want 1 (sqli only)", rep.Total())
	}
	if rep.Triaged != 1 {
		t.Errorf("triaged = %d, want 1 (gh-pat refuted)", rep.Triaged)
	}
	if rep.Counts["high"] != 1 || rep.Counts["critical"] != 0 {
		t.Errorf("counts = %v, want high:1 critical:0", rep.Counts)
	}
	var sawSQLi, ghRefuted bool
	for _, f := range rep.Findings {
		if f.RuleID == "secure-vibe.llm.sqli" && f.Triage == "" {
			sawSQLi = true
		}
		if f.RuleID == "gh-pat" && strings.HasPrefix(f.Triage, "refuted") {
			ghRefuted = true
		}
	}
	if !sawSQLi {
		t.Error("swept sqli finding missing or not confirmed")
	}
	if !ghRefuted {
		t.Error("gh-pat should be refuted")
	}
}

// fakeProvider returns a canned completion, counting calls.
type fakeProvider struct {
	resp  string
	calls int
}

func (p *fakeProvider) Name() string { return "fake" }
func (p *fakeProvider) Complete(_ context.Context, _ llm.Request) (string, error) {
	p.calls++
	return p.resp, nil
}

func TestLLMReviewerSweep(t *testing.T) {
	prov := &fakeProvider{resp: "```json\n[{\"rule_id\":\"sqli\",\"severity\":\"high\",\"title\":\"SQLi\",\"line\":5}]\n```"}
	r := &LLMReviewer{Provider: prov, Lens: "test lens"}
	found, err := r.Sweep(context.Background(), "/repo/app.go", "code")
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 1 {
		t.Fatalf("found %d, want 1", len(found))
	}
	if found[0].RuleID != "secure-vibe.llm.sqli" || found[0].Severity != "high" || found[0].Scan != semanticScan {
		t.Errorf("finding = %+v", found[0])
	}
}

func TestLLMReviewerRefuteMajority(t *testing.T) {
	// All rounds refute -> refuted.
	prov := &fakeProvider{resp: `{"refuted":true,"reason":"unreachable"}`}
	r := &LLMReviewer{Provider: prov, Votes: 3}
	refuted, reason, err := r.Refute(context.Background(), Finding{PolicyCheckFinding: tools.PolicyCheckFinding{RuleID: "x", Title: "t"}}, "code")
	if err != nil {
		t.Fatal(err)
	}
	if !refuted || reason == "" {
		t.Errorf("refuted=%v reason=%q, want true + reason", refuted, reason)
	}
	if prov.calls != 3 {
		t.Errorf("calls = %d, want 3 (one per vote)", prov.calls)
	}

	// No round refutes -> stands.
	prov2 := &fakeProvider{resp: `{"refuted":false,"reason":"real"}`}
	r2 := &LLMReviewer{Provider: prov2, Votes: 3}
	if refuted, _, _ := r2.Refute(context.Background(), Finding{}, "code"); refuted {
		t.Error("finding should stand when no round refutes")
	}
}

func TestExtractJSON(t *testing.T) {
	if got := extractJSON("```json\n[{\"a\":1}]\n```", '['); got != `[{"a":1}]` {
		t.Errorf("array: got %q", got)
	}
	if got := extractJSON("here is the verdict: {\"x\":true} thanks", '{'); got != `{"x":true}` {
		t.Errorf("object: got %q", got)
	}
}
