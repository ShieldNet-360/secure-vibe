package semver

import (
	"strconv"
	"strings"
)

// genericVersion is a permissive dotted-numeric version with an optional
// pre-release tail, used for ecosystems that do not have a dedicated
// matcher (crates, maven, nuget, rubygems, composer, pub, swift). It is
// deliberately a lowest-common-denominator model: a leading run of
// dot-separated integers (the release), followed by everything after the
// first '-' (or a non-numeric segment) as an opaque pre-release tail.
//
// This is enough to evaluate the comparator bounds OSV ranges actually
// use (>=, >, <, <=, ==) against the clean numeric versions those ranges
// almost always carry. Anything it cannot parse returns ok=false so the
// caller falls open (keeps the advisory) rather than risking a wrong
// "not affected".
type genericVersion struct {
	release []int
	pre     string // pre-release identifiers joined by '.', "" = none
}

// parseGeneric parses s into a genericVersion. A leading 'v'/'V' and an
// epoch-free build-metadata suffix ('+...') are stripped. Parsing fails
// (ok=false) when there is no leading numeric segment at all.
func parseGeneric(s string) (genericVersion, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return genericVersion{}, false
	}
	if s[0] == 'v' || s[0] == 'V' {
		s = s[1:]
	}
	// Strip build metadata.
	if i := strings.IndexByte(s, '+'); i >= 0 {
		s = s[:i]
	}
	// Split the pre-release tail at the first '-' (semver style).
	var pre string
	if i := strings.IndexByte(s, '-'); i >= 0 {
		pre = s[i+1:]
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	var rel []int
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			// A non-numeric segment (e.g. maven's ".RELEASE") ends the
			// numeric release and becomes part of the pre-release tail.
			if pre == "" {
				pre = strings.Join(parts[len(rel):], ".")
			}
			break
		}
		rel = append(rel, n)
	}
	if len(rel) == 0 {
		return genericVersion{}, false
	}
	return genericVersion{release: rel, pre: pre}, true
}

// compareGeneric returns -1, 0, or 1 for a<b, a==b, a>b. Release
// segments compare numerically with missing segments treated as 0; a
// version WITH a pre-release sorts BEFORE the same release without one
// (1.0.0-rc < 1.0.0), matching semver and the OSV ecosystems' rules.
func compareGeneric(a, b genericVersion) int {
	n := len(a.release)
	if len(b.release) > n {
		n = len(b.release)
	}
	for i := 0; i < n; i++ {
		av, bv := 0, 0
		if i < len(a.release) {
			av = a.release[i]
		}
		if i < len(b.release) {
			bv = b.release[i]
		}
		if av != bv {
			if av < bv {
				return -1
			}
			return 1
		}
	}
	switch {
	case a.pre == "" && b.pre == "":
		return 0
	case a.pre == "" && b.pre != "":
		return 1 // a (release) > b (pre-release)
	case a.pre != "" && b.pre == "":
		return -1
	default:
		return comparePreRelease(a.pre, b.pre)
	}
}

// comparePreRelease compares two dot-separated pre-release strings per
// the semver precedence rules: identifiers are compared left to right;
// numeric identifiers compare numerically and rank below alphanumeric
// ones; a larger set of identifiers outranks a smaller prefix-equal set.
func comparePreRelease(a, b string) int {
	as := strings.Split(a, ".")
	bs := strings.Split(b, ".")
	n := len(as)
	if len(bs) < n {
		n = len(bs)
	}
	for i := 0; i < n; i++ {
		ai, aNum := strconv.Atoi(as[i])
		bi, bNum := strconv.Atoi(bs[i])
		switch {
		case aNum == nil && bNum == nil:
			if ai != bi {
				if ai < bi {
					return -1
				}
				return 1
			}
		case aNum == nil && bNum != nil:
			return -1 // numeric < alphanumeric
		case aNum != nil && bNum == nil:
			return 1
		default:
			if as[i] != bs[i] {
				if as[i] < bs[i] {
					return -1
				}
				return 1
			}
		}
	}
	switch {
	case len(as) < len(bs):
		return -1
	case len(as) > len(bs):
		return 1
	default:
		return 0
	}
}

// matchGeneric evaluates a comma-separated constraint (every clause must
// hold) against version using the generic comparator. It supports the
// comparator operators OSV ranges use; an unparseable clause or version
// returns ok=false so the caller falls open.
func matchGeneric(constraint, version string) (matched, ok bool) {
	v, vok := parseGeneric(version)
	if !vok {
		return false, false
	}
	for _, clause := range strings.Split(constraint, ",") {
		clause = strings.TrimSpace(clause)
		if clause == "" {
			continue
		}
		op, rhs := splitGenericOp(clause)
		w, wok := parseGeneric(rhs)
		if !wok {
			return false, false
		}
		cmp := compareGeneric(v, w)
		var got bool
		switch op {
		case "", "==", "===":
			got = cmp == 0
		case ">=":
			got = cmp >= 0
		case "<=":
			got = cmp <= 0
		case ">":
			got = cmp > 0
		case "<":
			got = cmp < 0
		case "!=":
			got = cmp != 0
		default:
			return false, false
		}
		if !got {
			return false, true
		}
	}
	return true, true
}

func splitGenericOp(c string) (op, rhs string) {
	for _, prefix := range []string{"===", "==", ">=", "<=", "!=", ">", "<"} {
		if strings.HasPrefix(c, prefix) {
			return prefix, strings.TrimSpace(c[len(prefix):])
		}
	}
	return "", strings.TrimSpace(c)
}
