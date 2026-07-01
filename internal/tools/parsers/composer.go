package parsers

import (
	"encoding/json"
	"fmt"
	"strings"
)

// parseComposerLock reads PHP Composer's composer.lock. The file is JSON
// with top-level `packages` (runtime) and `packages-dev` arrays, each
// element an object carrying `name` ("vendor/pkg") and `version`
// ("1.2.3" or "v1.2.3"). Both groups are emitted, tagged by section in
// Source, so a dev-only malicious dependency is not missed.
func parseComposerLock(body []byte) ([]Dependency, error) {
	var doc struct {
		Packages    []composerPackage `json:"packages"`
		PackagesDev []composerPackage `json:"packages-dev"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("composer: parse composer.lock: %w", err)
	}
	var out []Dependency
	groups := []struct {
		label string
		pkgs  []composerPackage
	}{
		{"packages", doc.Packages},
		{"packages-dev", doc.PackagesDev},
	}
	for _, g := range groups {
		for _, p := range g.pkgs {
			name := strings.TrimSpace(p.Name)
			if name == "" {
				continue
			}
			ver := strings.TrimSpace(p.Version)
			ver = strings.TrimPrefix(ver, "v")
			out = append(out, Dependency{
				Name:      name,
				Version:   ver,
				Ecosystem: "composer",
				Source:    g.label + ": " + name,
			})
		}
	}
	return dedupe(out), nil
}

type composerPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}
