package tools

import (
	"encoding/json"
	"math"
	"os"
	"strconv"
	"strings"
)

// resolveOSVSeverity reads an OSV record JSON file from disk and
// returns a severity bucket ("critical", "high", "medium", "low") or
// "" when no structured severity is available. Errors reading or
// parsing the file collapse to "" so callers fall back to a default
// rather than failing the whole scan.
//
// The translation prefers in order:
//
//  1. database_specific.severity — GitHub-style qualitative band
//     (LOW / MODERATE / HIGH / CRITICAL). This is the canonical
//     GitHub-assigned severity on GHSA-* records and is more useful
//     than any single CVSS payload because GHSA editors sometimes
//     override the upstream score.
//  2. severity[] — the OSV-standard array of structured scores.
//     For each entry whose type starts with CVSS_, the score field
//     is parsed either as a plain decimal (e.g. "7.5") or, when it
//     is a vector string, as a CVSS v3.x / v3.0 / v3.1 base-score
//     vector. The highest score across the array wins. CVSS v2 is
//     parsed best-effort; CVSS v4 is not (its formula is substantially
//     more complex and we prefer the explicit fallback over an
//     incorrect translation).
//  3. "" — no structured severity. Callers map this to their
//     human-visible default (typically "medium").
func resolveOSVSeverity(path string) string {
	body, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var raw struct {
		Severity []struct {
			Type  string `json:"type"`
			Score string `json:"score"`
		} `json:"severity"`
		DatabaseSpecific struct {
			Severity string `json:"severity"`
		} `json:"database_specific"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return ""
	}
	if sev := normaliseSeverity(raw.DatabaseSpecific.Severity); sev != "" {
		return sev
	}
	var best float64
	for _, s := range raw.Severity {
		score := scoreFromCVSS(s.Type, s.Score)
		if score > best {
			best = score
		}
	}
	if best > 0 {
		return bucketFromScore(best)
	}
	return ""
}

// normaliseSeverity maps a free-form qualitative severity string
// (case-insensitive: LOW / MODERATE / MEDIUM / HIGH / CRITICAL, plus
// the lowercase forms we emit ourselves) onto the four-bucket scale
// the rest of the codebase uses. Anything unrecognised returns "".
//
// "MODERATE" is the GitHub Advisory canonical name; OSV records
// otherwise use "MEDIUM". We accept both spellings so the same
// helper can pull data straight from a GHSA payload OR from a
// hand-curated database_specific block.
func normaliseSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "moderate", "medium":
		return "medium"
	case "low":
		return "low"
	}
	return ""
}

// bucketFromScore maps a numeric CVSS base score onto the same
// four-bucket scale. The thresholds are the CVSS v3 specification's
// qualitative severity ranges (NVD CVSS Calculator §5).
func bucketFromScore(score float64) string {
	switch {
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	case score > 0:
		return "low"
	}
	return ""
}

// scoreFromCVSS parses a CVSS "score" field as it appears in OSV
// records. The score string is either:
//
//   - A plain decimal (e.g. "7.5") — used when the producer already
//     computed a base score. Parsed via strconv.
//   - A CVSS vector (e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
//     for v3.x or "AV:N/AC:M/Au:N/C:N/I:P/A:N" for v2) — computed via
//     the v3 or v2 base-score formulas below.
//
// CVSS_V4 vectors are recognised but not computed; the function
// returns 0 for them so the caller falls back to the next signal
// (the GitHub-style database_specific.severity, if any) or "".
func scoreFromCVSS(typ, score string) float64 {
	score = strings.TrimSpace(score)
	if score == "" {
		return 0
	}
	if v, err := strconv.ParseFloat(score, 64); err == nil {
		return v
	}
	upper := strings.ToUpper(typ)
	switch {
	case strings.HasPrefix(upper, "CVSS_V3"):
		return cvssV3BaseScore(score)
	case strings.HasPrefix(upper, "CVSS_V2"):
		return cvssV2BaseScore(score)
	}
	return 0
}

// cvssV3BaseScore implements the CVSS v3.0 / v3.1 base-score formula
// (FIRST CVSS v3.1 specification §7.1). The function intentionally
// rejects unknown metric values rather than guessing, returning 0
// so the caller can degrade to the next severity signal.
func cvssV3BaseScore(vector string) float64 {
	m := parseCVSSVector(vector)
	av, ok := v3Metric(m, "AV", map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2})
	if !ok {
		return 0
	}
	ac, ok := v3Metric(m, "AC", map[string]float64{"L": 0.77, "H": 0.44})
	if !ok {
		return 0
	}
	ui, ok := v3Metric(m, "UI", map[string]float64{"N": 0.85, "R": 0.62})
	if !ok {
		return 0
	}
	scope := strings.ToUpper(m["S"])
	if scope != "U" && scope != "C" {
		return 0
	}
	// Privileges-required values depend on Scope (PR contributes a
	// higher weight when an authenticated user can affect resources
	// outside their authorisation boundary).
	prTable := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	if scope == "C" {
		prTable = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.50}
	}
	pr, ok := v3Metric(m, "PR", prTable)
	if !ok {
		return 0
	}
	cImpact, ok := v3Metric(m, "C", map[string]float64{"N": 0, "L": 0.22, "H": 0.56})
	if !ok {
		return 0
	}
	iImpact, ok := v3Metric(m, "I", map[string]float64{"N": 0, "L": 0.22, "H": 0.56})
	if !ok {
		return 0
	}
	aImpact, ok := v3Metric(m, "A", map[string]float64{"N": 0, "L": 0.22, "H": 0.56})
	if !ok {
		return 0
	}
	iss := 1 - (1-cImpact)*(1-iImpact)*(1-aImpact)
	var impact float64
	if scope == "U" {
		impact = 6.42 * iss
	} else {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	}
	if impact <= 0 {
		return 0
	}
	exploitability := 8.22 * av * ac * pr * ui
	var base float64
	if scope == "U" {
		base = math.Min(impact+exploitability, 10)
	} else {
		base = math.Min(1.08*(impact+exploitability), 10)
	}
	// CVSS v3 roundup: smallest x such that x >= n and (x * 10) is
	// an integer divisible by 10. Equivalent to ceil to 1 decimal.
	return math.Ceil(base*10) / 10
}

// cvssV2BaseScore implements the legacy CVSS v2 base-score formula
// well enough to map onto our four-bucket scale. CVSS v2 is rare in
// the OSV cache (GHSA emits v3 / v4) but RUSTSEC records sometimes
// pre-date v3 adoption, so the v2 path keeps those from collapsing
// to the default-medium fallback.
func cvssV2BaseScore(vector string) float64 {
	m := parseCVSSVector(vector)
	av, ok := v3Metric(m, "AV", map[string]float64{"L": 0.395, "A": 0.646, "N": 1.0})
	if !ok {
		return 0
	}
	ac, ok := v3Metric(m, "AC", map[string]float64{"H": 0.35, "M": 0.61, "L": 0.71})
	if !ok {
		return 0
	}
	au, ok := v3Metric(m, "AU", map[string]float64{"M": 0.45, "S": 0.56, "N": 0.704})
	if !ok {
		return 0
	}
	cImpact, ok := v3Metric(m, "C", map[string]float64{"N": 0, "P": 0.275, "C": 0.660})
	if !ok {
		return 0
	}
	iImpact, ok := v3Metric(m, "I", map[string]float64{"N": 0, "P": 0.275, "C": 0.660})
	if !ok {
		return 0
	}
	aImpact, ok := v3Metric(m, "A", map[string]float64{"N": 0, "P": 0.275, "C": 0.660})
	if !ok {
		return 0
	}
	impact := 10.41 * (1 - (1-cImpact)*(1-iImpact)*(1-aImpact))
	exploitability := 20 * av * ac * au
	fImpact := 1.176
	if impact == 0 {
		fImpact = 0
	}
	base := ((0.6 * impact) + (0.4 * exploitability) - 1.5) * fImpact
	// Round to one decimal.
	base = math.Round(base*10) / 10
	if base < 0 {
		base = 0
	}
	if base > 10 {
		base = 10
	}
	return base
}

// parseCVSSVector splits a CVSS vector string ("CVSS:3.1/AV:N/AC:L/..."
// or "AV:N/AC:M/..." for v2) into a map[metric]value. The optional
// "CVSS:<version>" prefix is discarded; unknown segments are kept
// so callers can decide whether to ignore them. Metric keys are
// returned uppercase.
func parseCVSSVector(vector string) map[string]string {
	out := map[string]string{}
	for _, seg := range strings.Split(vector, "/") {
		seg = strings.TrimSpace(seg)
		if seg == "" {
			continue
		}
		k, v, ok := strings.Cut(seg, ":")
		if !ok {
			continue
		}
		k = strings.ToUpper(strings.TrimSpace(k))
		v = strings.TrimSpace(v)
		if k == "CVSS" {
			continue
		}
		out[k] = v
	}
	return out
}

// v3Metric looks up `key` in `m` and returns the matching weight
// from `weights`. The second return value is false when the metric
// is missing or its value is not in the table — in that case the
// caller treats the vector as unparseable and skips it. We do NOT
// silently substitute defaults here: an unrecognised value usually
// signals either a vector from a newer spec we don't model or a
// malformed record, both of which deserve the "no signal" outcome
// rather than a fabricated one.
func v3Metric(m map[string]string, key string, weights map[string]float64) (float64, bool) {
	raw, ok := m[strings.ToUpper(key)]
	if !ok {
		return 0, false
	}
	w, ok := weights[strings.ToUpper(raw)]
	if !ok {
		return 0, false
	}
	return w, true
}
