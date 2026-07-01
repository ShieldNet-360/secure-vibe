package tools

import (
	"os"
	"path/filepath"
	"testing"
)

// newOSVTestLibrary builds a synthetic library root holding a single
// pypi OSV advisory for `requests` whose affected range is
// [introduced=2.3.0, fixed=2.31.0). It returns the constructed Library.
func newOSVTestLibrary(t *testing.T) *Library {
	t.Helper()
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
	mustMkdir("vulnerabilities/osv/pypi")
	mustWrite("vulnerabilities/supply-chain/malicious-packages/pypi.json",
		`{"ecosystem":"pypi","entries":[]}`)
	mustWrite("vulnerabilities/osv/pypi/GHSA-req.json", `{
		"id": "GHSA-req",
		"summary": "requests leaks Proxy-Authorization on redirect",
		"affected": [
			{
				"package": {"name": "requests", "ecosystem": "PyPI"},
				"ranges": [
					{"type": "ECOSYSTEM", "events": [
						{"introduced": "2.3.0"},
						{"fixed": "2.31.0"}
					]}
				]
			}
		]
	}`)
	mustWrite("vulnerabilities/osv/pypi/index.json", `{
		"schema_version": "1.0",
		"by_package": {
			"requests": [
				{"id":"GHSA-req","file":"GHSA-req.json","summary":"x","aliases":[],"severity":"high"}
			]
		}
	}`)
	lib, err := NewLibrary(tmp)
	if err != nil {
		t.Fatalf("NewLibrary: %v", err)
	}
	return lib
}

// TestLookupOSVVersionRangeFiltering is the regression test for the
// scanner-eval FP: requests pinned to the FIXED version (2.31.0) must
// not be flagged for the [2.3.0, 2.31.0) advisory, a vulnerable version
// in range must be flagged and version-confirmed, and an empty version
// must preserve the name-only behaviour.
func TestLookupOSVVersionRangeFiltering(t *testing.T) {
	lib := newOSVTestLibrary(t)

	cases := []struct {
		name          string
		version       string
		wantLen       int
		wantConfirmed bool
	}{
		{"fixed version is dropped", "2.31.0", 0, false},
		{"newer than fixed is dropped", "2.32.0", 0, false},
		{"in-range version is confirmed", "2.20.0", 1, true},
		{"introduced boundary is in range", "2.3.0", 1, true},
		{"below introduced is dropped", "2.2.0", 0, false},
		{"empty version keeps name match unconfirmed", "", 1, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := lib.lookupOSV("pypi", "requests", c.version)
			if len(got) != c.wantLen {
				t.Fatalf("lookupOSV(requests@%q): got %d advisories, want %d", c.version, len(got), c.wantLen)
			}
			if c.wantLen == 1 && got[0].VersionConfirmed != c.wantConfirmed {
				t.Errorf("lookupOSV(requests@%q): VersionConfirmed=%v, want %v", c.version, got[0].VersionConfirmed, c.wantConfirmed)
			}
		})
	}
}

// TestLookupOSVFailsOpenOnUnevaluableRecord verifies the conservative
// stance: when the affected ranges cannot be evaluated for the
// ecosystem (here a GIT range with commit-hash events), the advisory is
// kept rather than dropped, and left version-unconfirmed.
func TestLookupOSVFailsOpenOnUnevaluableRecord(t *testing.T) {
	tmp := t.TempDir()
	must := func(p, body string) {
		full := filepath.Join(tmp, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(tmp, "skills"), 0o755); err != nil {
		t.Fatal(err)
	}
	must("vulnerabilities/supply-chain/malicious-packages/pypi.json", `{"ecosystem":"pypi","entries":[]}`)
	must("vulnerabilities/osv/pypi/GHSA-git.json", `{
		"id": "GHSA-git",
		"summary": "only a GIT range",
		"affected": [
			{"package": {"name": "somepkg", "ecosystem": "PyPI"},
			 "ranges": [{"type": "GIT", "events": [{"introduced": "abc123"}, {"fixed": "def456"}]}]}
		]
	}`)
	must("vulnerabilities/osv/pypi/index.json", `{
		"schema_version": "1.0",
		"by_package": {"somepkg": [{"id":"GHSA-git","file":"GHSA-git.json","summary":"x","aliases":[],"severity":"high"}]}
	}`)
	lib, err := NewLibrary(tmp)
	if err != nil {
		t.Fatalf("NewLibrary: %v", err)
	}
	got := lib.lookupOSV("pypi", "somepkg", "1.0.0")
	if len(got) != 1 {
		t.Fatalf("fail-open: got %d advisories, want 1 (unevaluable record must be kept)", len(got))
	}
	if got[0].VersionConfirmed {
		t.Errorf("fail-open: VersionConfirmed should be false for an unevaluable record")
	}
}

// TestOSVExplicitVersionsList checks that the explicit affected-versions
// enumeration is honoured even when no ranges are present.
func TestOSVExplicitVersionsList(t *testing.T) {
	tmp := t.TempDir()
	must := func(p, body string) {
		full := filepath.Join(tmp, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(tmp, "skills"), 0o755); err != nil {
		t.Fatal(err)
	}
	must("vulnerabilities/supply-chain/malicious-packages/pypi.json", `{"ecosystem":"pypi","entries":[]}`)
	must("vulnerabilities/osv/pypi/GHSA-list.json", `{
		"id": "GHSA-list",
		"summary": "enumerated versions only",
		"affected": [
			{"package": {"name": "listpkg", "ecosystem": "PyPI"}, "versions": ["1.0.0", "1.1.0"]}
		]
	}`)
	must("vulnerabilities/osv/pypi/index.json", `{
		"schema_version": "1.0",
		"by_package": {"listpkg": [{"id":"GHSA-list","file":"GHSA-list.json","summary":"x","aliases":[],"severity":"high"}]}
	}`)
	lib, err := NewLibrary(tmp)
	if err != nil {
		t.Fatalf("NewLibrary: %v", err)
	}
	if got := lib.lookupOSV("pypi", "listpkg", "1.1.0"); len(got) != 1 || !got[0].VersionConfirmed {
		t.Errorf("enumerated hit: got %+v, want one version-confirmed advisory", got)
	}
	if got := lib.lookupOSV("pypi", "listpkg", "2.0.0"); len(got) != 0 {
		t.Errorf("version absent from enumeration must be dropped: got %+v", got)
	}
}

// TestLoadOSVAffectedRejectsPathEscape hardens the OSV record reader:
// an index entry whose "file" carries a path separator or ".." must be
// refused rather than read from outside the ecosystem directory.
func TestLoadOSVAffectedRejectsPathEscape(t *testing.T) {
	lib := newOSVTestLibrary(t)
	for _, bad := range []string{
		"../../../../etc/passwd",
		"sub/dir/x.json",
		`..\..\windows`,
		"a/../../b.json",
	} {
		if got := lib.loadOSVAffected("pypi", bad); got != nil {
			t.Errorf("loadOSVAffected(%q) = %v; want nil (path escape must be refused)", bad, got)
		}
	}
	// A legitimate bare filename still loads.
	if got := lib.loadOSVAffected("pypi", "GHSA-req.json"); got == nil {
		t.Error("loadOSVAffected on a valid bare filename returned nil")
	}
}

// TestOSVLastAffectedRange exercises the `last_affected` range event
// (an alternative to `fixed` used by real OSV records): versions at or
// below last_affected are affected; strictly greater ones are not. This
// is the path that drives versionGreater.
func TestOSVLastAffectedRange(t *testing.T) {
	tmp := t.TempDir()
	must := func(p, body string) {
		full := filepath.Join(tmp, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(tmp, "skills"), 0o755); err != nil {
		t.Fatal(err)
	}
	must("vulnerabilities/supply-chain/malicious-packages/pypi.json", `{"ecosystem":"pypi","entries":[]}`)
	must("vulnerabilities/osv/pypi/GHSA-la.json", `{
		"id": "GHSA-la",
		"summary": "affected up to and including 2.5.0",
		"affected": [
			{"package": {"name": "lapkg", "ecosystem": "PyPI"},
			 "ranges": [{"type": "ECOSYSTEM", "events": [
				{"introduced": "1.0.0"},
				{"last_affected": "2.5.0"}
			]}]}
		]
	}`)
	must("vulnerabilities/osv/pypi/index.json", `{
		"schema_version": "1.0",
		"by_package": {"lapkg": [{"id":"GHSA-la","file":"GHSA-la.json","summary":"x","aliases":[],"severity":"high"}]}
	}`)
	lib, err := NewLibrary(tmp)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		version string
		wantLen int
	}{
		{"2.5.0", 1}, // last affected, inclusive
		{"2.4.9", 1}, // within range
		{"1.0.0", 1}, // introduced boundary
		{"2.5.1", 0}, // strictly greater than last_affected -> not affected
		{"3.0.0", 0},
		{"0.9.0", 0}, // below introduced
	}
	for _, c := range cases {
		got := lib.lookupOSV("pypi", "lapkg", c.version)
		if len(got) != c.wantLen {
			t.Errorf("lapkg@%s: got %d advisories, want %d", c.version, len(got), c.wantLen)
		}
	}
}

// TestLookupOSVDedupesByID guards against an index that lists the same
// advisory ID multiple times for one package (observed upstream in the
// composer index): the scanner must report it once, not once per entry.
func TestLookupOSVDedupesByID(t *testing.T) {
	tmp := t.TempDir()
	must := func(p, body string) {
		full := filepath.Join(tmp, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(tmp, "skills"), 0o755); err != nil {
		t.Fatal(err)
	}
	must("vulnerabilities/supply-chain/malicious-packages/pypi.json", `{"ecosystem":"pypi","entries":[]}`)
	// GHSA-dup listed three times for the same package.
	must("vulnerabilities/osv/pypi/index.json", `{
		"schema_version": "1.0",
		"by_package": {"dupe": [
			{"id":"GHSA-dup","file":"","summary":"x","aliases":[],"severity":"high"},
			{"id":"GHSA-dup","file":"","summary":"x","aliases":[],"severity":"high"},
			{"id":"GHSA-dup","file":"","summary":"x","aliases":[],"severity":"high"},
			{"id":"GHSA-other","file":"","summary":"y","aliases":[],"severity":"low"}
		]}
	}`)
	lib, err := NewLibrary(tmp)
	if err != nil {
		t.Fatal(err)
	}
	got := lib.lookupOSV("pypi", "dupe", "")
	if len(got) != 2 {
		t.Fatalf("got %d advisories, want 2 (GHSA-dup deduped to 1 + GHSA-other)", len(got))
	}
	counts := map[string]int{}
	for _, a := range got {
		counts[a.ID]++
	}
	if counts["GHSA-dup"] != 1 {
		t.Errorf("GHSA-dup reported %d times, want 1", counts["GHSA-dup"])
	}
}
