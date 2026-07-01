package parsers

import (
	"bufio"
	"bytes"
	"fmt"
	"regexp"
	"strings"
)

var (
	cargoNameLine    = regexp.MustCompile(`^name\s*=\s*"([^"]+)"`)
	cargoVersionLine = regexp.MustCompile(`^version\s*=\s*"([^"]+)"`)
	cargoSourceLine  = regexp.MustCompile(`^source\s*=\s*"([^"]+)"`)
)

// parseCargoLock reads `Cargo.lock`. Like poetry.lock the file is
// TOML with `[[package]]` tables — we hand-roll the parser to avoid
// pulling in a TOML library for one consumer.
//
// A package only counts as a real `crates.io` dependency when its
// table has a `source = "..."` line. Vendored / path / workspace
// crates have no source field and are not registry packages, so we
// skip them — they cannot be subject to a registry typosquat or
// malicious-package finding.
func parseCargoLock(body []byte) ([]Dependency, error) {
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 64*1024), 1<<20)

	inPackage := false
	var name, version, source string
	flush := func(out *[]Dependency) {
		if inPackage && name != "" && version != "" && source != "" {
			*out = append(*out, Dependency{
				Name:      name,
				Version:   version,
				Ecosystem: "crates",
				Source:    name,
			})
		}
		name, version, source = "", "", ""
		inPackage = false
	}
	var out []Dependency
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") {
			flush(&out)
			if trimmed == "[[package]]" {
				inPackage = true
			}
			continue
		}
		if !inPackage {
			continue
		}
		switch {
		case cargoNameLine.MatchString(line):
			name = cargoNameLine.FindStringSubmatch(line)[1]
		case cargoVersionLine.MatchString(line):
			version = cargoVersionLine.FindStringSubmatch(line)[1]
		case cargoSourceLine.MatchString(line):
			source = cargoSourceLine.FindStringSubmatch(line)[1]
		}
	}
	flush(&out)
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("crates: scan Cargo.lock: %w", err)
	}
	return dedupe(out), nil
}
