package semver

import (
	"regexp"
	"strconv"
	"strings"
)

// pypiVersion is a parsed PEP 440 version.
//
// PEP 440 differs from semver in several important ways:
//   - Pre-release markers are "a"/"alpha", "b"/"beta", "rc"/"c"
//     (canonical: "a", "b", "rc").
//   - Post-releases ".postN" sort AFTER the underlying release.
//   - Dev releases ".devN" sort BEFORE everything else at that
//     release number.
//   - The "~=" comparator means "compatible release": ~=1.2 implies
//     >=1.2, <2; ~=1.2.3 implies >=1.2.3, <1.3.
//
// See https://peps.python.org/pep-0440/ for the canonical grammar.
// We model the segments the malicious-packages / OSV data uses in
// practice and accept anything that round-trips through that subset.
type pypiVersion struct {
	epoch    int
	release  []int
	preStage string // "a"|"b"|"rc"|""
	preNum   int
	hasPre   bool
	postNum  int
	hasPost  bool
	devNum   int
	hasDev   bool
}

// pypiRe matches the PEP 440 "public version identifier" we care about.
// Local versions (after a "+") are stripped before this match.
var pypiRe = regexp.MustCompile(
	`^(?:(\d+)!)?` + // epoch
		`(\d+(?:\.\d+)*)` + // release segments
		`(?:[.\-_]?(a|alpha|b|beta|c|rc|pre|preview)[.\-_]?(\d+)?)?` + // pre
		`(?:[.\-_]?post[.\-_]?(\d+)?)?` + // post
		`(?:[.\-_]?dev[.\-_]?(\d+)?)?` + // dev
		`$`)

func parsePypi(raw string) (pypiVersion, bool) {
	s := strings.TrimSpace(raw)
	s = strings.ToLower(s)
	s = strings.TrimPrefix(s, "v")
	if plus := strings.Index(s, "+"); plus >= 0 {
		s = s[:plus] // strip local version
	}
	m := pypiRe.FindStringSubmatch(s)
	if m == nil {
		return pypiVersion{}, false
	}
	out := pypiVersion{}
	if m[1] != "" {
		out.epoch, _ = strconv.Atoi(m[1])
	}
	for _, part := range strings.Split(m[2], ".") {
		n, err := strconv.Atoi(part)
		if err != nil {
			return pypiVersion{}, false
		}
		out.release = append(out.release, n)
	}
	if m[3] != "" {
		out.hasPre = true
		switch m[3] {
		case "a", "alpha":
			out.preStage = "a"
		case "b", "beta":
			out.preStage = "b"
		case "c", "rc", "pre", "preview":
			out.preStage = "rc"
		}
		if m[4] != "" {
			out.preNum, _ = strconv.Atoi(m[4])
		}
	}
	// Detect optional post via m[5] (numeric group only matches if
	// the literal "post" was present in the string).
	if strings.Contains(s, "post") {
		out.hasPost = true
		if m[5] != "" {
			out.postNum, _ = strconv.Atoi(m[5])
		}
	}
	if strings.Contains(s, "dev") {
		out.hasDev = true
		if m[6] != "" {
			out.devNum, _ = strconv.Atoi(m[6])
		}
	}
	return out, true
}

// comparePypi returns -1/0/+1.
func comparePypi(a, b pypiVersion) int {
	if a.epoch != b.epoch {
		return sign(a.epoch - b.epoch)
	}
	for i := 0; i < max(len(a.release), len(b.release)); i++ {
		av := segOrZero(a.release, i)
		bv := segOrZero(b.release, i)
		if av != bv {
			return sign(av - bv)
		}
	}
	// Pre-release ordering: any pre < no pre at the same release.
	if a.hasPre != b.hasPre {
		if a.hasPre {
			return -1
		}
		return 1
	}
	if a.hasPre && b.hasPre {
		if a.preStage != b.preStage {
			return strings.Compare(a.preStage, b.preStage)
		}
		if a.preNum != b.preNum {
			return sign(a.preNum - b.preNum)
		}
	}
	// Post-release: with-post > without-post at same release/pre.
	if a.hasPost != b.hasPost {
		if a.hasPost {
			return 1
		}
		return -1
	}
	if a.hasPost && b.hasPost && a.postNum != b.postNum {
		return sign(a.postNum - b.postNum)
	}
	// Dev release: with-dev < without-dev at same release.
	if a.hasDev != b.hasDev {
		if a.hasDev {
			return -1
		}
		return 1
	}
	if a.hasDev && b.hasDev && a.devNum != b.devNum {
		return sign(a.devNum - b.devNum)
	}
	return 0
}

func segOrZero(s []int, i int) int {
	if i < len(s) {
		return s[i]
	}
	return 0
}

// matchPypi reports whether `v` satisfies `c`. Supports
// comma-separated AND clauses as in `requirements.txt`:
//   - "==1.2.3", "===1.2.3"  (exact)
//   - ">=1.2", "<=1.2"
//   - ">1.2", "<1.2"
//   - "!=1.2.3"
//   - "~=1.2.3" (compatible release per PEP 440 §3.5)
//   - bare "1.2.3" → exact equality
func matchPypi(c, v string) (matched, ok bool) {
	ver, vok := parsePypi(v)
	if !vok {
		return false, false
	}
	for _, clause := range strings.Split(c, ",") {
		clause = strings.TrimSpace(clause)
		if clause == "" {
			continue
		}
		got, okClause := matchPypiAtom(clause, ver)
		if !okClause {
			return false, false
		}
		if !got {
			return false, true
		}
	}
	return true, true
}

func matchPypiAtom(c string, v pypiVersion) (matched, ok bool) {
	op, rhs := splitPypiOp(c)
	w, okW := parsePypi(rhs)
	if !okW {
		return false, false
	}
	switch op {
	case "==", "===", "":
		return comparePypi(v, w) == 0, true
	case ">=":
		return comparePypi(v, w) >= 0, true
	case "<=":
		return comparePypi(v, w) <= 0, true
	case ">":
		return comparePypi(v, w) > 0, true
	case "<":
		return comparePypi(v, w) < 0, true
	case "!=":
		return comparePypi(v, w) != 0, true
	case "~=":
		// Compatible release: drop the last release segment, then
		// require >= w and < (w with last segment bumped). PEP 440
		// requires the constraint version have at least 2 segments.
		if len(w.release) < 2 {
			return false, false
		}
		upper := pypiVersion{epoch: w.epoch}
		upper.release = append(upper.release, w.release[:len(w.release)-1]...)
		upper.release[len(upper.release)-1]++
		return comparePypi(v, w) >= 0 && comparePypi(v, upper) < 0, true
	default:
		return false, false
	}
}

func splitPypiOp(c string) (op, rhs string) {
	for _, prefix := range []string{"===", "==", ">=", "<=", "!=", "~=", ">", "<"} {
		if strings.HasPrefix(c, prefix) {
			return prefix, strings.TrimSpace(c[len(prefix):])
		}
	}
	return "", strings.TrimSpace(c)
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
