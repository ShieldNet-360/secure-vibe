package parsers

import (
	"encoding/json"
	"fmt"
	"strings"
)

// parseSwiftPackageResolved reads Swift Package Manager's
// Package.resolved. Two on-disk schemas exist:
//
//   - v1 (Xcode 11–12): {"object":{"pins":[{"package":"Name",
//     "state":{"version":"1.2.3"}}]}}
//   - v2/v3 (Xcode 13+): {"pins":[{"identity":"name",
//     "state":{"version":"1.2.3"}}],"version":2}
//
// Both are decoded; the package identity is taken from `identity`
// (v2/v3, already lower-cased by SwiftPM) or `package` (v1). Pins with
// no concrete `version` (branch/revision pins) are skipped — there is no
// released version to match against.
func parseSwiftPackageResolved(body []byte) ([]Dependency, error) {
	var doc struct {
		Pins   []swiftPin `json:"pins"`
		Object struct {
			Pins []swiftPin `json:"pins"`
		} `json:"object"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("swift: parse Package.resolved: %w", err)
	}
	pins := doc.Pins
	if len(pins) == 0 {
		pins = doc.Object.Pins
	}
	var out []Dependency
	for _, p := range pins {
		name := strings.TrimSpace(p.Identity)
		if name == "" {
			name = strings.TrimSpace(p.Package)
		}
		ver := strings.TrimSpace(p.State.Version)
		if name == "" || ver == "" {
			continue
		}
		out = append(out, Dependency{
			Name:      name,
			Version:   strings.TrimPrefix(ver, "v"),
			Ecosystem: "swift",
			Source:    name,
		})
	}
	return dedupe(out), nil
}

type swiftPin struct {
	Identity string `json:"identity"`
	Package  string `json:"package"`
	State    struct {
		Version string `json:"version"`
	} `json:"state"`
}
