package semver

import "testing"

func TestMatchNpm(t *testing.T) {
	cases := []struct {
		name        string
		constraint  string
		version     string
		wantMatched bool
		wantOK      bool
	}{
		// Exact equality, with and without leading "=" / "v".
		{"exact-eq", "1.2.3", "1.2.3", true, true},
		{"exact-eq-v-prefix", "v1.2.3", "1.2.3", true, true},
		{"exact-eq-equals-prefix", "=1.2.3", "1.2.3", true, true},
		{"exact-neq", "1.2.3", "1.2.4", false, true},
		// Comparators.
		{"gte-yes", ">=1.2.3", "1.2.3", true, true},
		{"gte-yes-higher", ">=1.2.3", "1.5.0", true, true},
		{"gte-no", ">=1.2.3", "1.2.2", false, true},
		{"lt-yes", "<2.0.0", "1.9.9", true, true},
		{"lt-no-eq", "<2.0.0", "2.0.0", false, true},
		// AND composites.
		{"and-yes", ">=1.0.0 <2.0.0", "1.5.0", true, true},
		{"and-no", ">=1.0.0 <2.0.0", "2.0.0", false, true},
		// OR composites.
		{"or-first", "1.x || 2.x", "1.5.0", true, true},
		{"or-second", "1.x || 2.x", "2.0.0", true, true},
		{"or-neither", "1.x || 2.x", "3.0.0", false, true},
		// Caret ranges.
		{"caret-1.2.3-yes", "^1.2.3", "1.5.0", true, true},
		{"caret-1.2.3-no-major", "^1.2.3", "2.0.0", false, true},
		{"caret-0.2.3-yes", "^0.2.3", "0.2.9", true, true},
		{"caret-0.2.3-no-minor", "^0.2.3", "0.3.0", false, true},
		{"caret-0.0.3-yes", "^0.0.3", "0.0.3", true, true},
		{"caret-0.0.3-no", "^0.0.3", "0.0.4", false, true},
		// Tilde ranges.
		{"tilde-1.2.3-yes", "~1.2.3", "1.2.9", true, true},
		{"tilde-1.2.3-no", "~1.2.3", "1.3.0", false, true},
		// X-ranges / wildcards.
		{"xrange-1.x", "1.x", "1.99.99", true, true},
		{"xrange-1.x-no", "1.x", "2.0.0", false, true},
		{"xrange-1.2.x", "1.2.x", "1.2.99", true, true},
		{"xrange-1.2.x-no", "1.2.x", "1.3.0", false, true},
		{"any-star", "*", "9.9.9", true, true},
		// Hyphen ranges.
		{"hyphen-yes", "1.2.0 - 1.5.0", "1.3.5", true, true},
		{"hyphen-no", "1.2.0 - 1.5.0", "1.6.0", false, true},
		// Pre-release ordering vs. plain release.
		{"prerelease-lt", "<1.2.3", "1.2.3-beta.1", true, true},
		{"prerelease-gte", ">=1.2.3", "1.2.3-beta.1", false, true},
		// Build metadata is ignored.
		{"build-meta-eq", "1.2.3", "1.2.3+build.7", true, true},
		// Unparseable version → ok=false.
		{"bad-version", ">=1.2.3", "garbage", false, false},
		{"bad-constraint", "@@@", "1.2.3", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			matched, ok := Match(Npm, tc.constraint, tc.version)
			if matched != tc.wantMatched || ok != tc.wantOK {
				t.Fatalf("Match(npm, %q, %q) = (%v, %v); want (%v, %v)",
					tc.constraint, tc.version, matched, ok, tc.wantMatched, tc.wantOK)
			}
		})
	}
}

func TestMatchPypi(t *testing.T) {
	cases := []struct {
		name        string
		constraint  string
		version     string
		wantMatched bool
		wantOK      bool
	}{
		{"exact-eq", "1.2.3", "1.2.3", true, true},
		{"eq-op", "==1.2.3", "1.2.3", true, true},
		{"ne-yes", "!=1.2.3", "1.2.4", true, true},
		{"ne-no", "!=1.2.3", "1.2.3", false, true},
		{"ge", ">=1.2.3", "1.2.3", true, true},
		{"lt-pre", "<1.2.3", "1.2.3a1", true, true},
		{"pre-equal-canonical", "1.2.3rc1", "1.2.3.rc1", true, true},
		{"pre-canonical-c-rc", "1.2.3c1", "1.2.3rc1", true, true},
		{"post-greater", ">1.2.3", "1.2.3.post1", true, true},
		{"dev-less", "<1.2.3", "1.2.3.dev1", true, true},
		// Compatible release "~=".
		{"compatible-1.2.3", "~=1.2.3", "1.2.9", true, true},
		{"compatible-1.2.3-no", "~=1.2.3", "1.3.0", false, true},
		{"compatible-1.2", "~=1.2", "1.9.9", true, true},
		{"compatible-1.2-no", "~=1.2", "2.0.0", false, true},
		// Comma-separated AND.
		{"and-yes", ">=1.0,<2.0", "1.5", true, true},
		{"and-no", ">=1.0,<2.0", "2.0", false, true},
		// Epoch.
		{"epoch", ">=1!1.0", "1!2.0", true, true},
		// Unparseable.
		{"bad-version", ">=1.2", "@@@", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			matched, ok := Match(Pypi, tc.constraint, tc.version)
			if matched != tc.wantMatched || ok != tc.wantOK {
				t.Fatalf("Match(pypi, %q, %q) = (%v, %v); want (%v, %v)",
					tc.constraint, tc.version, matched, ok, tc.wantMatched, tc.wantOK)
			}
		})
	}
}

func TestMatchGo(t *testing.T) {
	cases := []struct {
		name        string
		constraint  string
		version     string
		wantMatched bool
		wantOK      bool
	}{
		{"exact-tag", "v1.2.3", "v1.2.3", true, true},
		{"ge-tag", ">=v1.2.0", "v1.2.3", true, true},
		{"pseudo-vs-tag", "<v1.2.3", "v1.2.3-0.20210101120000-abcd1234ef56", true, true},
		{"pseudo-ts-ordering", ">=v0.0.0-20210101000000-abcd1234ef56", "v0.0.0-20210101120000-abcd1234ef56", true, true},
		{"pseudo-ts-ordering-no", "<v0.0.0-20210101000000-abcd1234ef56", "v0.0.0-20210101120000-abcd1234ef56", false, true},
		{"prerelease-rc-lt-release", "<v1.2.3", "v1.2.3-rc.1", true, true},
		{"hyphen-range", "v1.0.0 - v1.5.0", "v1.3.0", true, true},
		// Standard semver compare.
		{"bare-numeric", "1.2.3", "1.2.3", true, true},
		// Unparseable.
		{"bad", ">=v1.2.3", "abc", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			matched, ok := Match(Go, tc.constraint, tc.version)
			if matched != tc.wantMatched || ok != tc.wantOK {
				t.Fatalf("Match(go, %q, %q) = (%v, %v); want (%v, %v)",
					tc.constraint, tc.version, matched, ok, tc.wantMatched, tc.wantOK)
			}
		})
	}
}

func TestUnknownEcosystem(t *testing.T) {
	// An unknown ecosystem with a clean dotted-numeric version now falls
	// through to the generic comparator (so OSV ranges for crates, maven,
	// nuget, rubygems, composer, … are version-filtered too).
	if matched, ok := Match("haskell", "==1.2.3", "1.2.3"); !ok || !matched {
		t.Fatalf("generic fallback: Match(haskell, ==1.2.3, 1.2.3) = (%v, %v); want (true, true)", matched, ok)
	}
	// A version the generic parser cannot make sense of still falls open.
	if _, ok := Match("haskell", "==1.2.3", "not-a-version"); ok {
		t.Fatal("unparseable version should return ok=false (caller falls open)")
	}
}

func TestEmptyInputs(t *testing.T) {
	if _, ok := Match(Npm, "", "1.2.3"); ok {
		t.Fatal("empty constraint should return ok=false")
	}
	if _, ok := Match(Npm, ">=1.2.3", ""); ok {
		t.Fatal("empty version should return ok=false")
	}
}
