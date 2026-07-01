package parsers

import (
	"bufio"
	"bytes"
	"fmt"
	"regexp"
	"strings"
)

var (
	// pubPackageName matches a package entry header under `packages:`: a
	// two-space-indented `name:` line.
	pubPackageName = regexp.MustCompile(`^  ([A-Za-z0-9_.\-]+):\s*$`)
	// pubVersionLine matches the `version: "x"` line nested under a
	// package (indented deeper than the name).
	pubVersionLine = regexp.MustCompile(`^\s{4,}version:\s*"?([^"\s]+)"?`)
)

// parsePubspecLock reads Dart/Flutter's pubspec.lock. The file is YAML
// with a top-level `packages:` map keyed by package name; each entry
// carries a nested `version: "x.y.z"`. We walk it line-by-line (no YAML
// dependency, matching the other lockfile parsers) and emit one
// dependency per package in the `packages:` block, ignoring the trailing
// `sdks:` section.
func parsePubspecLock(body []byte) ([]Dependency, error) {
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 64*1024), 1<<20)

	inPackages := false
	current := ""
	var out []Dependency
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, " ") && strings.TrimSpace(line) != "" {
			// A new top-level key. Enter the packages block on `packages:`,
			// leave it on anything else (e.g. `sdks:`).
			inPackages = strings.HasPrefix(line, "packages:")
			current = ""
			continue
		}
		if !inPackages {
			continue
		}
		if m := pubPackageName.FindStringSubmatch(line); m != nil {
			current = m[1]
			continue
		}
		if current == "" {
			continue
		}
		if m := pubVersionLine.FindStringSubmatch(line); m != nil {
			ver := strings.TrimPrefix(strings.TrimSpace(m[1]), "v")
			if ver != "" {
				out = append(out, Dependency{
					Name:      current,
					Version:   ver,
					Ecosystem: "pub",
					Source:    current,
				})
			}
			current = ""
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("pub: scan pubspec.lock: %w", err)
	}
	return dedupe(out), nil
}
