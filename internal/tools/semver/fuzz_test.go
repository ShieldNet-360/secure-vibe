package semver

import "testing"

// FuzzMatch ensures no constraint/version pair panics any ecosystem
// matcher, and that the generic comparator's ordering is antisymmetric
// (a<b iff b>a) for inputs both sides can parse.
func FuzzMatch(f *testing.F) {
	seeds := []struct{ eco, c, v string }{
		{"npm", "^1.0.0", "1.2.3"},
		{"pypi", ">=1.0,<2", "1.5"},
		{"go", ">=v1.0.0", "v1.2.3"},
		{"crates", ">=1.0.0,<2.0.0", "1.5.0"},
		{"maven", "<2.0", "1.9.9-RELEASE"},
		{"nuget", "<1.0.0", "1.0.0-beta"},
		{"unknown", "==1.2.3", "1.2.3"},
		{"crates", ">=garbage", "main"},
	}
	for _, s := range seeds {
		f.Add(s.eco, s.c, s.v)
	}
	f.Fuzz(func(t *testing.T, eco, c, v string) {
		// Must not panic.
		_, _ = Match(eco, c, v)

		// Generic comparator antisymmetry, for inputs it parses.
		av, aok := parseGeneric(c)
		bv, bok := parseGeneric(v)
		if aok && bok {
			ab := compareGeneric(av, bv)
			ba := compareGeneric(bv, av)
			if ab != -ba {
				t.Fatalf("compareGeneric not antisymmetric: cmp(%q,%q)=%d cmp(%q,%q)=%d", c, v, ab, v, c, ba)
			}
		}
	})
}
