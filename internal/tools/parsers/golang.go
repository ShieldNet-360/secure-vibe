package parsers

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"
)

// parseGoSum reads a `go.sum` file. Each line has the shape:
//
//	<module> <version>[/go.mod] h1:<hash>=
//
// A go.sum records a `/go.mod` hash for EVERY module version in the
// build's module graph — including versions that were only consulted
// during minimal-version-selection and then superseded — but a content
// (`h1:`, no `/go.mod`) hash ONLY for module versions whose code is
// actually downloaded and compiled into the build. Only the latter are
// real dependencies: a version appearing solely in `/go.mod` lines is a
// resolution artifact whose code is not in the binary.
//
// So we emit a (module, version) only when it has a content-hash line.
// Treating every `/go.mod` line as a dependency over-reports — it flags
// advisories against old superseded versions that were never built
// (e.g. an x/crypto pseudo-version read during MVS while the selected,
// patched v0.53.0 is the only version actually compiled).
func parseGoSum(body []byte) ([]Dependency, error) {
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 64*1024), 1<<20)

	type modVer struct{ module, version string }
	seen := map[modVer]bool{}
	var out []Dependency
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		module, version := fields[0], fields[1]
		// A `/go.mod` line is a resolution artifact, not a built module.
		if strings.HasSuffix(version, "/go.mod") {
			continue
		}
		if module == "" || version == "" {
			continue
		}
		key := modVer{module, version}
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, Dependency{
			Name:      module,
			Version:   version,
			Ecosystem: "go",
			Source:    line,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("go: scan go.sum: %w", err)
	}
	return out, nil
}
