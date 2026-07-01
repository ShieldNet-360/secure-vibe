package cmd

import (
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

// TestSelectFetchEcosystemsAll empty --only selects every supported
// ecosystem in sorted order.
func TestSelectFetchEcosystemsAll(t *testing.T) {
	got := selectFetchEcosystems(nil)
	want := append([]string{}, fetchVulnsEcosystems...)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("selectFetchEcosystems(nil) = %v, want %v", got, want)
	}
}

// TestSelectFetchEcosystemsFiltering covers --only handling: comma
// expansion, whitespace tolerance, dedup, unknown rejection, and the
// final result being sorted for output stability.
func TestSelectFetchEcosystemsFiltering(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{"single", []string{"npm"}, []string{"npm"}},
		{"comma-separated", []string{"npm,pypi"}, []string{"npm", "pypi"}},
		{"comma+spaces", []string{" npm , pypi "}, []string{"npm", "pypi"}},
		{"multiple flags", []string{"npm", "pypi"}, []string{"npm", "pypi"}},
		{"dedup", []string{"npm", "npm,npm"}, []string{"npm"}},
		{"unknown filtered", []string{"npm", "bogus"}, []string{"npm"}},
		{"sorted output", []string{"swift", "npm", "go"}, []string{"go", "npm", "swift"}},
		{"all-unknown empties", []string{"x", "y"}, []string{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := selectFetchEcosystems(tc.in)
			if len(got) == 0 && len(tc.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("selectFetchEcosystems(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// TestDefaultFetchVulnsCachePrecedence walks the resolution chain: an
// explicit SECURE_VIBE_MCP_CACHE wins over XDG_CACHE_HOME, which wins over
// $HOME/.cache/.... The empty case (no env, no HOME) is checked
// implicitly by the production code path; we don't strip $HOME in
// tests because doing so destabilises other tests in the package.
func TestDefaultFetchVulnsCachePrecedence(t *testing.T) {
	t.Setenv("SECURE_VIBE_MCP_CACHE", "")
	t.Setenv("XDG_CACHE_HOME", "")
	// With no overrides, the resolution falls back to $HOME/.cache/...
	got := defaultFetchVulnsCache()
	if got == "" {
		t.Fatalf("defaultFetchVulnsCache() returned empty with HOME set")
	}
	if !filepath.IsAbs(got) {
		t.Errorf("default cache path %q should be absolute", got)
	}

	t.Setenv("XDG_CACHE_HOME", "/tmp/xdg-test")
	if got := defaultFetchVulnsCache(); got != "/tmp/xdg-test/secure-vibe/vulns" {
		t.Errorf("XDG override: got %q, want /tmp/xdg-test/secure-vibe/vulns", got)
	}

	t.Setenv("SECURE_VIBE_MCP_CACHE", "/explicit/override")
	if got := defaultFetchVulnsCache(); got != "/explicit/override" {
		t.Errorf("SECURE_VIBE_MCP_CACHE override: got %q, want /explicit/override", got)
	}
}

// TestPerEcosystemDisplay renders 0 as the human-readable "unlimited"
// (matches what ingest-osv.py does internally) and any positive N
// passes through as the decimal string.
func TestPerEcosystemDisplay(t *testing.T) {
	cases := map[int]string{
		0:    "unlimited (full archive)",
		-1:   "unlimited (full archive)",
		500:  "500",
		2000: "2000",
	}
	for in, want := range cases {
		if got := perEcosystemDisplay(in); got != want {
			t.Errorf("perEcosystemDisplay(%d) = %q, want %q", in, got, want)
		}
	}
}

// TestCacheIndexPaths produces one absolute path per ecosystem under
// the supplied root, with the expected `<root>/osv/<eco>/index.json`
// shape. The output preserves caller order so a callsite that
// iterates ecosystems in display order gets the matching paths.
func TestCacheIndexPaths(t *testing.T) {
	got := cacheIndexPaths("/cache", []string{"npm", "pypi"})
	want := []string{
		"/cache/osv/npm/index.json",
		"/cache/osv/pypi/index.json",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("cacheIndexPaths = %v, want %v", got, want)
	}
}

// TestResolveReleaseAssetURL covers the three resolution paths for
// --from-release: explicit --release-url wins, --release-tag=latest
// builds the GitHub "latest" redirect URL, and any other tag value
// builds the per-tag download URL. An empty tag is rejected.
func TestResolveReleaseAssetURL(t *testing.T) {
	cases := []struct {
		name        string
		explicitURL string
		tag         string
		want        string
		wantErr     bool
	}{
		{
			name: "latest tag uses /releases/latest/download/",
			tag:  "latest",
			want: "https://github.com/shieldnet-360/secure-vibe/releases/latest/download/osv-cache.tar.gz",
		},
		{
			name: "specific tag uses /releases/download/<tag>/",
			tag:  "v0.1.1",
			want: "https://github.com/shieldnet-360/secure-vibe/releases/download/v0.1.1/osv-cache.tar.gz",
		},
		{
			name:        "explicit URL overrides tag",
			explicitURL: "https://example.test/custom.tar.gz",
			tag:         "v0.1.1",
			want:        "https://example.test/custom.tar.gz",
		},
		{
			name:    "empty tag without explicit URL errors",
			tag:     "",
			wantErr: true,
		},
		{
			name:    "whitespace-only tag errors",
			tag:     "   ",
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveReleaseAssetURL(tc.explicitURL, tc.tag)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}
