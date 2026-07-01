package semver

import (
	"regexp"
	"strconv"
	"strings"
)

// goVersion is a parsed Go-module version per
// https://go.dev/ref/mod#versions.
//
// Two forms of input show up in real Go module manifests:
//
//  1. Standard semver tags: v1.2.3, v1.2.3-rc.1
//  2. Pseudo-versions: v0.0.0-20210101120000-abcd1234ef56 (or
//     v1.2.3-pre.0.20210101120000-abcd1234ef56 / v1.2.4-0.…).
//
// Pseudo-versions encode a UTC timestamp and a 12-char commit prefix.
// They share an ordering with the underlying semver-ish prefix, with
// the timestamp acting as a tie-breaker. We parse the timestamp into
// a single integer so comparison is lexicographic-safe.
type goVersion struct {
	major, minor, patch int
	pre                 string // pre-release tag including everything before the pseudo timestamp
	timestamp           uint64 // 0 if not a pseudo-version
	commit              string
}

// goPseudoTS matches the 14-digit UTC timestamp portion of a Go
// pseudo-version (YYYYMMDDhhmmss) followed by a "-" and a hex commit
// prefix.
var goPseudoTS = regexp.MustCompile(`(\d{14})-([0-9a-f]{12,})$`)

func parseGoVersion(s string) (goVersion, bool) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "v") && !looksLikeGoSemver(s) {
		return goVersion{}, false
	}
	s = strings.TrimPrefix(s, "v")
	if s == "" {
		return goVersion{}, false
	}
	out := goVersion{}
	pre := ""
	if dash := strings.Index(s, "-"); dash >= 0 {
		pre = s[dash+1:]
		s = s[:dash]
	}
	parts := strings.Split(s, ".")
	if len(parts) > 3 {
		return goVersion{}, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return goVersion{}, false
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
	if pre != "" {
		if m := goPseudoTS.FindStringSubmatch(pre); m != nil {
			ts, err := strconv.ParseUint(m[1], 10, 64)
			if err != nil {
				return goVersion{}, false
			}
			out.timestamp = ts
			out.commit = m[2]
			// Strip pseudo suffix from the pre-release tag so the
			// remainder ("rc1.0" in vX.Y.Z-rc1.0.TS-COMMIT) still
			// participates in ordering.
			head := pre[:len(pre)-len(m[0])]
			out.pre = strings.TrimRight(head, ".-_ ")
		} else {
			out.pre = pre
		}
	}
	return out, true
}

func looksLikeGoSemver(s string) bool {
	// Allow inputs without the "v" prefix when they are
	// dotted-numeric — go.sum sometimes carries those.
	if len(s) == 0 {
		return false
	}
	r := s[0]
	return r >= '0' && r <= '9'
}

func compareGo(a, b goVersion) int {
	if a.major != b.major {
		return sign(a.major - b.major)
	}
	if a.minor != b.minor {
		return sign(a.minor - b.minor)
	}
	if a.patch != b.patch {
		return sign(a.patch - b.patch)
	}
	// At the same M.m.p: any pre-release sorts before none.
	if a.pre == "" && b.pre == "" {
		// Both are clean releases (or both pseudo with same prefix);
		// fall through to the timestamp comparator below.
	} else if a.pre == "" {
		return 1
	} else if b.pre == "" {
		return -1
	} else if c := compareGoPre(a.pre, b.pre); c != 0 {
		return c
	}
	// Pseudo timestamp tie-break.
	if a.timestamp != b.timestamp {
		if a.timestamp < b.timestamp {
			return -1
		}
		return 1
	}
	return 0
}

func compareGoPre(a, b string) int {
	ap := strings.Split(a, ".")
	bp := strings.Split(b, ".")
	for i := 0; i < len(ap) && i < len(bp); i++ {
		ai, aIsNum := atoi(ap[i])
		bi, bIsNum := atoi(bp[i])
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
			if c := strings.Compare(ap[i], bp[i]); c != 0 {
				return c
			}
		}
	}
	return sign(len(ap) - len(bp))
}

// matchGo handles the constraint forms that show up in Go module
// data: bare versions (exact), ">=", "<=", ">", "<", "=", and the
// hyphen range syntax our internal data uses. There is no native Go
// constraint grammar — `go.mod` uses `require pkg v1.2.3` (exact) and
// MVS resolves transitively — so this matcher mirrors what we get
// from the malicious-packages / OSV feed.
func matchGo(c, v string) (matched, ok bool) {
	ver, vok := parseGoVersion(v)
	if !vok {
		return false, false
	}
	// AND composite split by comma OR space.
	clauses := splitGoClauses(c)
	for _, clause := range clauses {
		got, okClause := matchGoAtom(clause, ver)
		if !okClause {
			return false, false
		}
		if !got {
			return false, true
		}
	}
	return true, true
}

func splitGoClauses(c string) []string {
	if strings.Contains(c, ",") {
		var out []string
		for _, p := range strings.Split(c, ",") {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
		return out
	}
	// Hyphen range "X - Y" must stay together.
	if strings.Contains(c, " - ") {
		return []string{c}
	}
	return []string{strings.TrimSpace(c)}
}

func matchGoAtom(c string, v goVersion) (matched, ok bool) {
	c = strings.TrimSpace(c)
	if c == "" || c == "*" {
		return true, true
	}
	if i := strings.Index(c, " - "); i > 0 {
		lo, okLo := parseGoVersion(c[:i])
		hi, okHi := parseGoVersion(c[i+3:])
		if !okLo || !okHi {
			return false, false
		}
		return compareGo(v, lo) >= 0 && compareGo(v, hi) <= 0, true
	}
	op, rhs := splitGoOp(c)
	w, okW := parseGoVersion(rhs)
	if !okW {
		return false, false
	}
	switch op {
	case "", "=", "==":
		return compareGo(v, w) == 0, true
	case ">=":
		return compareGo(v, w) >= 0, true
	case "<=":
		return compareGo(v, w) <= 0, true
	case ">":
		return compareGo(v, w) > 0, true
	case "<":
		return compareGo(v, w) < 0, true
	default:
		return false, false
	}
}

func splitGoOp(c string) (op, rhs string) {
	for _, prefix := range []string{">=", "<=", "==", ">", "<", "="} {
		if strings.HasPrefix(c, prefix) {
			return prefix, strings.TrimSpace(c[len(prefix):])
		}
	}
	return "", strings.TrimSpace(c)
}
