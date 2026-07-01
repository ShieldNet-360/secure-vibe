// Package parsers reads dependency manifest / lockfile formats and
// returns a uniform list of (name, version, ecosystem) tuples that the
// scan_dependencies MCP tool can hand off to the existing
// malicious-package, typosquat, and CVE-pattern checks.
//
// Each parser deliberately limits itself to extracting the set of
// installed packages — we do not interpret semver ranges, peer
// dependencies, or transitive resolution beyond what the lockfile
// itself records. That matches how a fresh install would resolve and
// keeps the per-format code short enough to audit line-by-line.
//
// All parsers are pure functions over file contents: no shell, no
// network. The caller (Library.ScanDependencies) is responsible for
// validating the on-disk path before reading the bytes.
package parsers

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

// Dependency is one resolved (name, version, ecosystem) tuple.
//
// Source records the lockfile-relative locator (for npm
// package-lock.json that is the JSON pointer-style path; for go.sum it
// is the line; for Cargo.lock it is the `[[package]]` section index).
// It is surfaced verbatim in SARIF output so a CI consumer can jump
// from a finding back to the offending line.
type Dependency struct {
	Name      string `json:"name"`
	Version   string `json:"version,omitempty"`
	Ecosystem string `json:"ecosystem"`
	Source    string `json:"source,omitempty"`
}

// ErrUnknownLockfile is returned by Parse when the file's base name
// does not match any recognised lockfile format. The caller should
// surface this as a user-facing error rather than retrying.
var ErrUnknownLockfile = errors.New("parsers: unrecognised lockfile format")

// Parse dispatches on the base name of path and returns the parsed
// dependency list. It accepts the raw file bytes so callers can apply
// their own size / read-policy controls.
//
// Recognised file names:
//
//   - package-lock.json, npm-shrinkwrap.json     -> npm
//   - package.json                               -> npm (manifest)
//   - yarn.lock                                  -> npm
//   - pnpm-lock.yaml                             -> npm
//   - requirements.txt, requirements-*.txt       -> pypi
//   - Pipfile.lock                               -> pypi
//   - poetry.lock                                -> pypi
//   - go.sum                                     -> go
//   - Cargo.lock                                 -> crates
//   - pom.xml                                    -> maven
//   - gradle.lockfile, build.gradle.lockfile     -> maven
//   - packages.lock.json                         -> nuget
//   - *.csproj, *.fsproj, *.vbproj               -> nuget
//   - Gemfile.lock                               -> rubygems
//   - composer.lock                              -> composer
//   - Package.resolved                           -> swift
//   - pubspec.lock                               -> pub
//
// Any other base name returns ErrUnknownLockfile.
func Parse(path string, body []byte) ([]Dependency, error) {
	base := filepath.Base(path)
	switch {
	case base == "package-lock.json", base == "npm-shrinkwrap.json":
		return parseNPMPackageLock(body)
	case base == "package.json":
		return parsePackageJSON(body)
	case base == "yarn.lock":
		return parseYarnLock(body)
	case base == "pnpm-lock.yaml":
		return parsePnpmLock(body)
	case base == "Pipfile.lock":
		return parsePipfileLock(body)
	case base == "poetry.lock":
		return parsePoetryLock(body)
	case base == "go.sum":
		return parseGoSum(body)
	case base == "Cargo.lock":
		return parseCargoLock(body)
	case base == "pom.xml":
		return parsePomXML(body)
	case base == "gradle.lockfile", base == "build.gradle.lockfile":
		return parseGradleLockfile(body)
	case base == "packages.lock.json":
		return parseNuGetPackagesLock(body)
	case base == "Gemfile.lock":
		return parseGemfileLock(body)
	case base == "composer.lock":
		return parseComposerLock(body)
	case base == "Package.resolved":
		return parseSwiftPackageResolved(body)
	case base == "pubspec.lock":
		return parsePubspecLock(body)
	}
	lower := strings.ToLower(base)
	if strings.HasSuffix(lower, ".csproj") ||
		strings.HasSuffix(lower, ".fsproj") ||
		strings.HasSuffix(lower, ".vbproj") {
		return parseCSProj(body)
	}
	if strings.HasSuffix(base, ".txt") && (base == "requirements.txt" || strings.HasPrefix(base, "requirements")) {
		return parseRequirementsTxt(body)
	}
	return nil, fmt.Errorf("%w: %s", ErrUnknownLockfile, base)
}

// dedupe returns deps with exact duplicates collapsed. Order is
// preserved on first occurrence so the lockfile reading order is
// stable across runs. We only fold genuinely identical rows so a
// transitive that legitimately appears twice (e.g. at different
// versions) is kept.
func dedupe(deps []Dependency) []Dependency {
	if len(deps) <= 1 {
		return deps
	}
	seen := make(map[Dependency]struct{}, len(deps))
	out := make([]Dependency, 0, len(deps))
	for _, d := range deps {
		key := Dependency{Name: d.Name, Version: d.Version, Ecosystem: d.Ecosystem}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, d)
	}
	return out
}
