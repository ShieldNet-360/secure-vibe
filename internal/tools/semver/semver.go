// Package semver provides ecosystem-native version-range matchers
// for the MCP tools. Each ecosystem (npm, PyPI, Go) has its own
// constraint grammar and pre-release-comparison rules, so the
// approximate matcher in library.go produces false negatives on
// real-world inputs. This package implements the published rules
// for each ecosystem behind a single dispatch function.
//
// Match returns (matched, ok). Callers should treat ok=false as
// "could not parse — fall back to whatever matcher you had before",
// not as a no-match. This lets the legacy approximate matcher remain
// a safety net for exotic constraints we don't yet model.
package semver

import "strings"

// Ecosystem labels match the ecosystem strings used elsewhere in
// the repo's malicious-packages files.
const (
	Npm  = "npm"
	Pypi = "pypi"
	Go   = "go"
)

// Match dispatches `constraint` and `version` to the matcher
// appropriate for the named ecosystem.
//
// Returns (matched, ok). When ok is false, neither side could be
// parsed by the native matcher and the caller should fall back to
// its own logic. When ok is true, matched reflects whether the
// version satisfies the constraint per the ecosystem's published
// rules.
func Match(ecosystem, constraint, version string) (matched, ok bool) {
	c := strings.TrimSpace(constraint)
	v := strings.TrimSpace(version)
	if c == "" || v == "" {
		return false, false
	}
	switch strings.ToLower(strings.TrimSpace(ecosystem)) {
	case Npm:
		return matchNpm(c, v)
	case Pypi:
		return matchPypi(c, v)
	case Go:
		return matchGo(c, v)
	default:
		// crates, maven, nuget, rubygems, composer, pub, swift, and any
		// other ecosystem fall back to the generic dotted-numeric
		// comparator. It handles the comparator bounds OSV ranges use and
		// returns ok=false on anything it cannot parse, so the caller
		// still falls open on exotic version strings.
		return matchGeneric(c, v)
	}
}
