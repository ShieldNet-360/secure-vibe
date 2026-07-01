package parsers

import (
	"bufio"
	"bytes"
	"fmt"
	"regexp"
	"strings"
)

// gemfileLockSpec captures one resolved gem from the `specs:`
// block of a `Gemfile.lock`. Bundler writes lines like:
//
//	GEM
//	  remote: https://rubygems.org/
//	  specs:
//	    rails (7.1.2)
//	      actionmailer (= 7.1.2)
//	      activesupport (= 7.1.2)
//
// Real specs are indented 4 spaces and have the shape
// `name (version)`. Transitive declarations are indented 6 spaces
// and use `name (= version)` / `name (>= 1.0)` / similar; we only
// emit the resolved top-of-spec rows, since those are the rows
// Bundler actually installs and the `>=`-style transitives are
// just dependency ranges (the resolved version still appears as
// its own top-of-spec row).
var gemfileLockSpec = regexp.MustCompile(`^    ([A-Za-z0-9_\-\.]+) \(([^\s\)]+)\)\s*$`)

// parseGemfileLock reads `Gemfile.lock`. It walks the GEM block
// looking for indented `name (version)` lines under `specs:`.
// Sections other than GEM (PATH, GIT, BUNDLED WITH, DEPENDENCIES,
// PLATFORMS) are ignored — PATH/GIT gems are local or
// VCS-installed and therefore not subject to the rubygems.org
// malicious-package / typosquat database, and the other sections
// don't describe installable artefacts.
func parseGemfileLock(body []byte) ([]Dependency, error) {
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 64*1024), 1<<20)

	var (
		out     []Dependency
		section string
		inSpecs bool
	)
	for scanner.Scan() {
		raw := scanner.Text()
		// Section headers are unindented words ending with no
		// trailing whitespace, e.g. "GEM", "PATH", "GIT",
		// "PLATFORMS", "DEPENDENCIES", "BUNDLED WITH".
		if len(raw) > 0 && raw[0] != ' ' {
			section = strings.TrimSpace(raw)
			inSpecs = false
			continue
		}
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		// Enter / exit the specs sub-block inside the GEM section.
		if section == "GEM" && trimmed == "specs:" {
			inSpecs = true
			continue
		}
		if !inSpecs {
			continue
		}
		m := gemfileLockSpec.FindStringSubmatch(raw)
		if m == nil {
			continue
		}
		name, version := m[1], m[2]
		if name == "" || version == "" {
			continue
		}
		out = append(out, Dependency{
			Name:      name,
			Version:   version,
			Ecosystem: "rubygems",
			Source:    name,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("rubygems: scan Gemfile.lock: %w", err)
	}
	return dedupe(out), nil
}
