package tools

import (
	"math"
	"os"
	"path/filepath"
	"testing"
)

func TestNormaliseSeverity(t *testing.T) {
	cases := map[string]string{
		"":         "",
		"unknown":  "",
		"CRITICAL": "critical",
		"high":     "high",
		"High":     "high",
		"MODERATE": "medium",
		"moderate": "medium",
		"medium":   "medium",
		"LOW":      "low",
		"  low  ":  "low",
	}
	for in, want := range cases {
		if got := normaliseSeverity(in); got != want {
			t.Errorf("normaliseSeverity(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBucketFromScore(t *testing.T) {
	cases := []struct {
		score float64
		want  string
	}{
		{0, ""},
		{0.5, "low"},
		{3.9, "low"},
		{4.0, "medium"},
		{6.9, "medium"},
		{7.0, "high"},
		{8.9, "high"},
		{9.0, "critical"},
		{10.0, "critical"},
	}
	for _, c := range cases {
		if got := bucketFromScore(c.score); got != c.want {
			t.Errorf("bucketFromScore(%v) = %q, want %q", c.score, got, c.want)
		}
	}
}

func TestCVSSV3BaseScoreKnownVectors(t *testing.T) {
	// Pinned to NVD calculator output so the implementation can be
	// re-checked against an authoritative source.
	cases := []struct {
		name   string
		vector string
		want   float64
	}{
		// CVE-2017-5638 (Apache Struts S2-045) — Critical/10.0
		{"struts-s2-045", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},
		// Network/High AC/None/Required, Low Conf only — 4.3 (medium).
		{"low-impact-confidentiality-only", "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.1},
		// Network/Low AC/None/None, full impact, scope unchanged — 9.8 critical.
		{"network-no-auth-full-impact", "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},
		// Scope changed (e.g. CVE-2021-44228 Log4Shell vector)
		{"log4shell", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0},
		// Adjacent network, single privilege required — 6.5 medium
		{"adjacent-low-pr", "CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 5.7},
	}
	for _, c := range cases {
		got := cvssV3BaseScore(c.vector)
		if math.Abs(got-c.want) > 0.1 {
			t.Errorf("cvssV3BaseScore(%q) = %v, want %v", c.vector, got, c.want)
		}
	}
}

func TestCVSSV3BaseScoreRejectsBadVectors(t *testing.T) {
	cases := []string{
		"",
		"not-a-vector",
		"CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // bad AV
		"CVSS:3.1/AV:N",                   // missing required metrics
		"AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H", // missing A
	}
	for _, v := range cases {
		if got := cvssV3BaseScore(v); got != 0 {
			t.Errorf("cvssV3BaseScore(%q) = %v, want 0 for unparseable vector", v, got)
		}
	}
}

func TestScoreFromCVSSNumericPasses(t *testing.T) {
	// OSV records sometimes supply a plain decimal in the score
	// field (the spec allows either a vector or a numeric score).
	cases := map[string]float64{
		"7.5":  7.5,
		"10.0": 10.0,
		"3.1":  3.1,
	}
	for s, want := range cases {
		got := scoreFromCVSS("CVSS_V3", s)
		if math.Abs(got-want) > 1e-9 {
			t.Errorf("scoreFromCVSS(CVSS_V3, %q) = %v, want %v", s, got, want)
		}
	}
}

func TestScoreFromCVSSV4ReturnsZero(t *testing.T) {
	// CVSS v4 vectors are intentionally not computed — see the
	// comment on scoreFromCVSS. We accept the 0 return so the
	// caller falls back to database_specific.severity or "" and
	// ultimately to the "medium" default at the scan handler.
	v4 := "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"
	if got := scoreFromCVSS("CVSS_V4", v4); got != 0 {
		t.Errorf("scoreFromCVSS(CVSS_V4, %q) = %v, want 0 (v4 unimplemented)", v4, got)
	}
}

// TestResolveOSVSeverityFromFiles drives the file-based parser
// through three hand-written advisories that exercise each
// translation path: a GHSA record with a database_specific band, a
// RUSTSEC record carrying only a CVSS_V3 vector, and a record with
// no severity at all. Hand-writing the fixtures (rather than reading
// the live cache) makes the test stable across `ingest-osv.py`
// refreshes that swap in new advisories.
func TestResolveOSVSeverityFromFiles(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "ghsa-database-specific.json",
			body: `{
				"id": "GHSA-fake-band-high",
				"severity": [
					{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"}
				],
				"database_specific": {"severity": "HIGH"}
			}`,
			want: "high",
		},
		{
			name: "rustsec-cvss-only.json",
			body: `{
				"id": "RUSTSEC-fake",
				"severity": [
					{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
				]
			}`,
			want: "critical",
		},
		{
			name: "mal-no-severity.json",
			body: `{"id": "MAL-fake", "severity": []}`,
			want: "",
		},
		{
			name: "ghsa-moderate-band.json",
			body: `{
				"id": "GHSA-fake-moderate",
				"database_specific": {"severity": "MODERATE"}
			}`,
			want: "medium",
		},
		{
			name: "cvss-v4-only-falls-through.json",
			body: `{
				"id": "GHSA-fake-v4",
				"severity": [
					{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"}
				]
			}`,
			want: "",
		},
		{
			name: "numeric-score.json",
			body: `{
				"id": "FAKE-numeric",
				"severity": [{"type": "CVSS_V3", "score": "9.2"}]
			}`,
			want: "critical",
		},
	}
	for _, c := range cases {
		path := filepath.Join(dir, c.name)
		if err := os.WriteFile(path, []byte(c.body), 0o644); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
		got := resolveOSVSeverity(path)
		if got != c.want {
			t.Errorf("resolveOSVSeverity(%s) = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestResolveOSVSeverityMissingFileReturnsEmpty(t *testing.T) {
	// A read error must not panic and must not synthesise a
	// severity — the caller falls back to "medium" at its own
	// layer for missing-data cases.
	if got := resolveOSVSeverity("/nonexistent/path/does-not-exist.json"); got != "" {
		t.Errorf("resolveOSVSeverity(missing) = %q, want \"\"", got)
	}
}

// TestLookupOSVPopulatesSeverityFromIndex confirms that the
// pre-computed severity field on an index entry is surfaced
// straight to callers. We bypass the on-disk cache build by
// constructing a synthetic library root.
func TestLookupOSVPopulatesSeverityFromIndex(t *testing.T) {
	tmp := t.TempDir()
	mustMkdir := func(p string) {
		if err := os.MkdirAll(filepath.Join(tmp, p), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite := func(p, body string) {
		if err := os.WriteFile(filepath.Join(tmp, p), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mustMkdir("skills")
	mustMkdir("vulnerabilities/supply-chain/malicious-packages")
	mustMkdir("vulnerabilities/osv/npm")
	mustWrite("vulnerabilities/supply-chain/malicious-packages/npm.json",
		`{"ecosystem":"npm","entries":[]}`)
	mustWrite("vulnerabilities/osv/npm/GHSA-foo-bar-baz.json",
		`{"id":"GHSA-foo-bar-baz","database_specific":{"severity":"CRITICAL"}}`)
	mustWrite("vulnerabilities/osv/npm/index.json", `{
		"schema_version": "1.0",
		"by_package": {
			"victim": [
				{"id":"GHSA-foo-bar-baz","file":"GHSA-foo-bar-baz.json","summary":"x","aliases":[],"severity":"critical"}
			],
			"victim-without-precomputed": [
				{"id":"GHSA-foo-bar-baz","file":"GHSA-foo-bar-baz.json","summary":"x","aliases":[]}
			]
		}
	}`)
	lib, err := NewLibrary(tmp)
	if err != nil {
		t.Fatal(err)
	}
	got := lib.lookupOSV("npm", "victim", "")
	if len(got) != 1 {
		t.Fatalf("lookupOSV: got %d entries, want 1", len(got))
	}
	if got[0].Severity != "critical" {
		t.Errorf("Severity = %q, want \"critical\" from pre-computed index", got[0].Severity)
	}
	// And the lazy fall-through path: same advisory, no severity
	// in the index entry, should be read from the record file and
	// land on "critical".
	got = lib.lookupOSV("npm", "victim-without-precomputed", "")
	if len(got) != 1 || got[0].Severity != "critical" {
		t.Fatalf("lazy fall-through failed: got %+v", got)
	}
}
