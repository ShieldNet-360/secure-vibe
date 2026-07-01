package semver

import "testing"

func TestGenericMatchAcrossEcosystems(t *testing.T) {
	cases := []struct {
		eco        string
		constraint string
		version    string
		wantMatch  bool
		wantOK     bool
	}{
		// crates (real semver)
		{"crates", ">=1.0.0", "1.2.3", true, true},
		{"crates", "<1.0.0", "1.2.3", false, true},
		{"crates", ">=1.0.0,<2.0.0", "1.5.0", true, true},
		{"crates", ">=1.0.0,<2.0.0", "2.0.0", false, true},
		// the OSV [introduced, fixed) shape: fixed version is NOT affected
		{"crates", ">=1.2.0", "1.5.0", true, true},
		// maven
		{"maven", ">=2.0", "2.5.1", true, true},
		{"maven", "<2.0", "1.9.9", true, true},
		// nuget with pre-release: 1.0.0-beta < 1.0.0
		{"nuget", "<1.0.0", "1.0.0-beta", true, true},
		{"nuget", ">=1.0.0", "1.0.0-beta", false, true},
		{"nuget", ">=1.0.0", "1.0.0", true, true},
		// rubygems
		{"rubygems", ">=3.0.0", "3.1.4", true, true},
		// composer with leading v
		{"composer", ">=v1.0.0", "1.2.0", true, true},
		// equality
		{"swift", "==1.2.3", "1.2.3", true, true},
		{"swift", "==1.2.3", "1.2.4", false, true},
		// unparseable -> fall open
		{"crates", ">=1.0.0", "main", false, false},
		{"crates", ">=garbage", "1.0.0", false, false},
	}
	for _, c := range cases {
		matched, ok := Match(c.eco, c.constraint, c.version)
		if matched != c.wantMatch || ok != c.wantOK {
			t.Errorf("Match(%s, %q, %q) = (%v, %v); want (%v, %v)",
				c.eco, c.constraint, c.version, matched, ok, c.wantMatch, c.wantOK)
		}
	}
}

func TestCompareGenericPrecedence(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.0", 0},
		{"1.0.0", "1.0.1", -1},
		{"1.2.0", "1.1.9", 1},
		{"1.0", "1.0.0", 0},        // missing segment == 0
		{"2.0", "2.0.1", -1},       // 2.0.0 < 2.0.1
		{"1.0.0-rc1", "1.0.0", -1}, // pre-release < release
		{"1.0.0", "1.0.0-rc1", 1},
		{"1.0.0-alpha", "1.0.0-beta", -1},   // alphanumeric lexical
		{"1.0.0-1", "1.0.0-2", -1},          // numeric pre-release
		{"1.0.0-1", "1.0.0-alpha", -1},      // numeric < alphanumeric
		{"1.0.0-alpha.1", "1.0.0-alpha", 1}, // longer set outranks prefix
	}
	for _, c := range cases {
		av, aok := parseGeneric(c.a)
		bv, bok := parseGeneric(c.b)
		if !aok || !bok {
			t.Fatalf("parse failed for %q/%q", c.a, c.b)
		}
		if got := compareGeneric(av, bv); got != c.want {
			t.Errorf("compareGeneric(%q, %q) = %d; want %d", c.a, c.b, got, c.want)
		}
	}
}
