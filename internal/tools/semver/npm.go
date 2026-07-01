package semver

import (
	"strconv"
	"strings"
)

// npmVersion represents a parsed node-semver version.
//
// node-semver is a strict superset of semver 2.0.0. Production npm
// constraints rely on three behaviours the approximate matcher in
// library.go does not handle:
//
//  1. Pre-release ordering: 1.2.3-beta < 1.2.3, and a pre-release
//     version only satisfies a range like ">=1.2.0 <2.0.0" when the
//     lower bound itself names a pre-release on the same M.m.p tuple.
//     (See https://github.com/npm/node-semver#prerelease-tags.)
//  2. Build metadata stripping: 1.2.3+build1 == 1.2.3 for comparison.
//  3. Caret/tilde semantics: ^0.x and ^1.x have different rules.
//
// We implement the published ordering rules but model constraints as
// the AND/OR composites that show up in real package.json entries.
type npmVersion struct {
	major, minor, patch int
	pre                 []string
}

func parseNpmVersion(s string) (npmVersion, bool) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "v")
	s = strings.TrimPrefix(s, "=")
	s = strings.TrimSpace(s)
	if s == "" {
		return npmVersion{}, false
	}
	if plus := strings.Index(s, "+"); plus >= 0 {
		s = s[:plus]
	}
	var pre []string
	if dash := strings.Index(s, "-"); dash >= 0 {
		raw := s[dash+1:]
		s = s[:dash]
		if raw != "" {
			pre = strings.Split(raw, ".")
		}
	}
	parts := strings.Split(s, ".")
	if len(parts) == 0 || len(parts) > 3 {
		return npmVersion{}, false
	}
	out := npmVersion{pre: pre}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return npmVersion{}, false
		}
		switch i {
		case 0:
			out.major = n
		case 1:
			out.minor = n
		case 2:
			out.patch = n
		}
	}
	return out, true
}

// compareNpm returns -1, 0, +1 for a < b, a == b, a > b. Build
// metadata is already stripped by parseNpmVersion.
func compareNpm(a, b npmVersion) int {
	if a.major != b.major {
		return sign(a.major - b.major)
	}
	if a.minor != b.minor {
		return sign(a.minor - b.minor)
	}
	if a.patch != b.patch {
		return sign(a.patch - b.patch)
	}
	// Pre-release ordering: a version *with* a pre-release sorts
	// before the same M.m.p without one.
	if len(a.pre) == 0 && len(b.pre) == 0 {
		return 0
	}
	if len(a.pre) == 0 {
		return 1
	}
	if len(b.pre) == 0 {
		return -1
	}
	for i := 0; i < len(a.pre) && i < len(b.pre); i++ {
		ai, aIsNum := atoi(a.pre[i])
		bi, bIsNum := atoi(b.pre[i])
		switch {
		case aIsNum && bIsNum:
			if ai != bi {
				return sign(ai - bi)
			}
		case aIsNum && !bIsNum:
			return -1
		case !aIsNum && bIsNum:
			return 1
		default:
			if c := strings.Compare(a.pre[i], b.pre[i]); c != 0 {
				return c
			}
		}
	}
	return sign(len(a.pre) - len(b.pre))
}

func sign(x int) int {
	switch {
	case x < 0:
		return -1
	case x > 0:
		return 1
	default:
		return 0
	}
}

func atoi(s string) (int, bool) {
	n, err := strconv.Atoi(s)
	return n, err == nil
}

// matchNpm reports whether `v` satisfies `c`. Returns (matched, ok)
// where ok=false means we could not parse the constraint or version
// and the caller should fall back.
//
// Supported constraint forms (npm's "advanced range syntax"):
//
//   - "*", "" (any) — matches every release version.
//   - "1.2.3" / "=1.2.3" — exact equality.
//   - ">=1.2.3", "<=1.2.3", ">1.2.3", "<1.2.3" — comparators.
//   - "~1.2.3" — allows patch-level changes (>=1.2.3 <1.3.0).
//   - "^1.2.3" — allows minor-level changes for non-zero major
//     (>=1.2.3 <2.0.0), patch-level for 0.x.y (>=0.2.3 <0.3.0).
//   - "1.x" / "1.2.x" / "*" — X-ranges.
//   - "1.2.3 - 1.5.0" — inclusive hyphen ranges.
//   - "a || b || c" — OR composites.
//   - ">=1.0 <2.0" — AND composites (any whitespace-separated set).
func matchNpm(c, v string) (matched, ok bool) {
	ver, vok := parseNpmVersion(v)
	if !vok {
		return false, false
	}
	for _, alt := range strings.Split(c, "||") {
		alt = strings.TrimSpace(alt)
		if alt == "" {
			continue
		}
		got, okAlt := matchNpmAlt(alt, ver)
		if !okAlt {
			return false, false
		}
		if got {
			return true, true
		}
	}
	return false, true
}

func matchNpmAlt(c string, v npmVersion) (matched, ok bool) {
	// Hyphen ranges: "X - Y" — note the spaces.
	if i := strings.Index(c, " - "); i > 0 {
		lo, okLo := parseNpmVersion(c[:i])
		hi, okHi := parseNpmRangeHigh(c[i+3:])
		if !okLo || !okHi {
			return false, false
		}
		if compareNpm(v, lo) < 0 {
			return false, true
		}
		if compareNpm(v, hi) > 0 {
			return false, true
		}
		return true, true
	}
	// AND composite: split by whitespace, every clause must match.
	parts := strings.Fields(c)
	for _, p := range parts {
		got, okP := matchNpmAtom(p, v)
		if !okP {
			return false, false
		}
		if !got {
			return false, true
		}
	}
	return true, true
}

// parseNpmRangeHigh parses an X-range like "1.5" or "1.x" into the
// inclusive upper bound it implies — so "1.5" becomes 1.5.MAX_PATCH
// for the purposes of hyphen ranges.
func parseNpmRangeHigh(s string) (npmVersion, bool) {
	s = strings.TrimSpace(s)
	parts := strings.Split(s, ".")
	switch len(parts) {
	case 1:
		// "1 -> 1.X.X" upper bound: 1.999999.999999
		major, err := strconv.Atoi(parts[0])
		if err != nil {
			return npmVersion{}, false
		}
		return npmVersion{major: major, minor: 1<<30 - 1, patch: 1<<30 - 1}, true
	case 2:
		major, err := strconv.Atoi(parts[0])
		if err != nil {
			return npmVersion{}, false
		}
		minor, err := strconv.Atoi(parts[1])
		if err != nil {
			return npmVersion{}, false
		}
		return npmVersion{major: major, minor: minor, patch: 1<<30 - 1}, true
	default:
		return parseNpmVersion(s)
	}
}

func matchNpmAtom(c string, v npmVersion) (matched, ok bool) {
	c = strings.TrimSpace(c)
	if c == "" || c == "*" || c == "x" || c == "X" {
		return true, true
	}
	// Operator prefix detection.
	switch {
	case strings.HasPrefix(c, ">="):
		w, okW := parseNpmVersion(c[2:])
		if !okW {
			return false, false
		}
		return compareNpm(v, w) >= 0, true
	case strings.HasPrefix(c, "<="):
		w, okW := parseNpmVersion(c[2:])
		if !okW {
			return false, false
		}
		return compareNpm(v, w) <= 0, true
	case strings.HasPrefix(c, ">"):
		w, okW := parseNpmVersion(c[1:])
		if !okW {
			return false, false
		}
		return compareNpm(v, w) > 0, true
	case strings.HasPrefix(c, "<"):
		w, okW := parseNpmVersion(c[1:])
		if !okW {
			return false, false
		}
		return compareNpm(v, w) < 0, true
	case strings.HasPrefix(c, "~"):
		w, okW := parseNpmVersion(c[1:])
		if !okW {
			return false, false
		}
		// ~1.2.3 := >=1.2.3 <1.3.0
		// ~1.2   := >=1.2.0 <1.3.0
		// ~1     := >=1.0.0 <2.0.0
		hi := w
		if strings.Count(strings.TrimPrefix(c[1:], "v"), ".") <= 0 {
			hi = npmVersion{major: w.major + 1}
		} else {
			hi = npmVersion{major: w.major, minor: w.minor + 1}
		}
		return compareNpm(v, w) >= 0 && compareNpm(v, hi) < 0, true
	case strings.HasPrefix(c, "^"):
		w, okW := parseNpmVersion(c[1:])
		if !okW {
			return false, false
		}
		// ^1.2.3 := >=1.2.3 <2.0.0
		// ^0.2.3 := >=0.2.3 <0.3.0
		// ^0.0.3 := >=0.0.3 <0.0.4
		var hi npmVersion
		switch {
		case w.major > 0:
			hi = npmVersion{major: w.major + 1}
		case w.minor > 0:
			hi = npmVersion{major: 0, minor: w.minor + 1}
		default:
			hi = npmVersion{major: 0, minor: 0, patch: w.patch + 1}
		}
		return compareNpm(v, w) >= 0 && compareNpm(v, hi) < 0, true
	case strings.HasPrefix(c, "="):
		w, okW := parseNpmVersion(c[1:])
		if !okW {
			return false, false
		}
		return compareNpm(v, w) == 0, true
	}
	// X-ranges: "1.x", "1.2.x", "1", "1.2"
	if strings.ContainsAny(c, "xX*") || strings.Count(c, ".") < 2 {
		return matchNpmXRange(c, v)
	}
	// Bare version → equality.
	w, okW := parseNpmVersion(c)
	if !okW {
		return false, false
	}
	return compareNpm(v, w) == 0, true
}

func matchNpmXRange(c string, v npmVersion) (matched, ok bool) {
	c = strings.TrimPrefix(c, "v")
	parts := strings.Split(c, ".")
	if len(parts) == 0 || len(parts) > 3 {
		return false, false
	}
	for i, p := range parts {
		if p == "" || p == "x" || p == "X" || p == "*" {
			// All remaining components are wildcards too.
			return true, true
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return false, false
		}
		switch i {
		case 0:
			if v.major != n {
				return false, true
			}
		case 1:
			if v.minor != n {
				return false, true
			}
		case 2:
			if v.patch != n {
				return false, true
			}
		}
	}
	return true, true
}
