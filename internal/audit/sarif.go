package audit

import "github.com/shieldnet-360/secure-vibe/internal/tools"

// SARIF renders the audit's confirmed findings — deterministic scanners AND the
// model-semantic lane — as a SARIF 2.1.0 log for GitHub Code Scanning. It reuses
// tools.PolicyCheckSARIF so the document shape is byte-for-byte the same as the
// gate's (URI anchoring, rule table, deterministic ordering), which Code Scanning
// already ingests.
//
// The difference from calling PolicyCheckSARIF on the raw deterministic results:
// this walks the *enriched* finding set, so model-found findings reach Code
// Scanning too ("full-lane"). Triaged findings — likely fixtures and
// adversarially-refuted candidates — are omitted, because they are intentionally
// not alerts.
func (r *Report) SARIF(baseDir string) *tools.SARIFLog {
	// Regroup confirmed findings into per-(file, lane) results so each carries a
	// consistent Scan (a file can hold both a secret and an llm-semantic finding).
	byKey := map[string]*tools.PolicyCheckResult{}
	order := make([]string, 0)
	for _, f := range r.Findings {
		if f.Triage != "" {
			continue
		}
		key := f.FilePath + "\x00" + f.Scan
		res, ok := byKey[key]
		if !ok {
			res = &tools.PolicyCheckResult{FilePath: f.FilePath, Scan: f.Scan}
			byKey[key] = res
			order = append(order, key)
		}
		res.Findings = append(res.Findings, f.PolicyCheckFinding)
	}
	results := make([]*tools.PolicyCheckResult, 0, len(order))
	for _, k := range order {
		results = append(results, byKey[k])
	}
	return tools.PolicyCheckSARIF(results, baseDir)
}
