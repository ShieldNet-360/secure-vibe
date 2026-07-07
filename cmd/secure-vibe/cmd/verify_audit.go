package cmd

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/shieldnet-360/secure-vibe/internal/audit"
	"github.com/shieldnet-360/secure-vibe/internal/verify"
)

// runDynamicVerify maps each confirmed, dynamically-verifiable finding to a
// verify probe against target and records the verdict on the finding. It is
// dry-run unless confirm is set AND the target matches SECURE_VIBE_VERIFY_SCOPE
// — the same double gate the MCP verify_finding tool enforces. A refuted probe
// demotes the finding. Returns how many findings were probed.
func runDynamicVerify(ctx context.Context, rep *audit.Report, target, param, method string, confirm bool) int {
	opts := verify.Opts{
		Confirm:     confirm,
		AllowTarget: scopeAllowFunc(),
		Timeout:     8 * time.Second,
	}
	probed := 0
	for i := range rep.Findings {
		if rep.Findings[i].Triage != "" {
			continue // only probe confirmed findings
		}
		class := audit.DynamicClass(rep.Findings[i])
		if class == "" {
			continue
		}
		res, err := verify.Run(ctx, verify.Finding{Type: class, Target: target, Param: param, Method: method}, opts)
		if err != nil {
			continue
		}
		rep.Findings[i].Verify = &audit.VerifyInfo{
			Class:     class,
			Confirmed: res.Confirmed,
			Refuted:   res.Refuted,
			DryRun:    res.DryRun,
			Payload:   res.Payload,
			Evidence:  res.Evidence,
		}
		if res.Refuted {
			rep.Findings[i].Triage = "refuted: dynamic probe"
		}
		probed++
	}
	return probed
}

// scopeAllowFunc builds the target allow-list from SECURE_VIBE_VERIFY_SCOPE (a
// comma-separated list of host substrings), matching the MCP verify scope. An
// empty scope denies everything, so live probing stays off until the operator
// explicitly opts in.
func scopeAllowFunc() func(string) bool {
	raw := strings.TrimSpace(os.Getenv("SECURE_VIBE_VERIFY_SCOPE"))
	if raw == "" {
		return func(string) bool { return false }
	}
	var hosts []string
	for _, h := range strings.Split(raw, ",") {
		if h = strings.TrimSpace(h); h != "" {
			hosts = append(hosts, h)
		}
	}
	return func(target string) bool {
		for _, h := range hosts {
			if strings.Contains(target, h) {
				return true
			}
		}
		return false
	}
}

// dynamicVerifiable counts confirmed findings that map to a verify probe class.
func dynamicVerifiable(rep *audit.Report) int {
	n := 0
	for _, f := range rep.Findings {
		if f.Triage == "" && audit.DynamicClass(f) != "" {
			n++
		}
	}
	return n
}
