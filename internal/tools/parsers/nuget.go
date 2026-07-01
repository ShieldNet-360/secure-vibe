package parsers

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

// parseNuGetPackagesLock reads `packages.lock.json`, the lockfile
// emitted by `dotnet restore --use-lock-file`. The file is keyed by
// target framework moniker (TFM) and lists every resolved
// dependency along with its `type` (Direct, Transitive, Project,
// CentralTransitive). We emit each unique (name, version) tuple
// once across all TFMs; `Project` references are skipped because
// they point at sibling projects in the same solution, not real
// NuGet packages.
//
// Schema (abbreviated):
//
//	{
//	  "version": 1,
//	  "dependencies": {
//	    "net8.0": {
//	      "Newtonsoft.Json": {
//	        "type": "Direct",
//	        "requested": "[13.0.3, )",
//	        "resolved": "13.0.3",
//	        "contentHash": "..."
//	      }
//	    }
//	  }
//	}
func parseNuGetPackagesLock(body []byte) ([]Dependency, error) {
	var doc struct {
		Version      int                                          `json:"version"`
		Dependencies map[string]map[string]nuGetPackagesLockEntry `json:"dependencies"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("nuget: parse packages.lock.json: %w", err)
	}
	var out []Dependency
	// Sort TFMs so output is deterministic across runs.
	tfms := make([]string, 0, len(doc.Dependencies))
	for k := range doc.Dependencies {
		tfms = append(tfms, k)
	}
	sort.Strings(tfms)
	for _, tfm := range tfms {
		pkgs := doc.Dependencies[tfm]
		names := make([]string, 0, len(pkgs))
		for k := range pkgs {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, name := range names {
			e := pkgs[name]
			if e.Resolved == "" || name == "" {
				continue
			}
			// Skip in-solution project references: those are not
			// NuGet artefacts and cannot be subject to a registry
			// malicious-package or typosquat finding.
			if strings.EqualFold(e.Type, "Project") {
				continue
			}
			out = append(out, Dependency{
				Name:      name,
				Version:   e.Resolved,
				Ecosystem: "nuget",
				Source:    tfm + "/" + name,
			})
		}
	}
	return dedupe(out), nil
}

type nuGetPackagesLockEntry struct {
	Type      string `json:"type,omitempty"`
	Requested string `json:"requested,omitempty"`
	Resolved  string `json:"resolved,omitempty"`
}

// parseCSProj reads a `.csproj` (or `.fsproj` / `.vbproj`) MSBuild
// project file and emits one Dependency per `<PackageReference>`.
// MSBuild's two pinning shapes are both accepted:
//
//	<PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
//
//	<PackageReference Include="Newtonsoft.Json">
//	  <Version>13.0.3</Version>
//	</PackageReference>
//
// A reference without any pinned version (relying on
// `<CentralPackageManagement>` resolution) emits the package with
// an empty version — downstream CheckDependency will then only
// look at name-based malicious-package / typosquat hits, which is
// the correct conservative behaviour.
func parseCSProj(body []byte) ([]Dependency, error) {
	dec := xml.NewDecoder(bytes.NewReader(body))
	var (
		out     []Dependency
		stack   []string
		current *csprojPkg
	)
	for {
		tok, err := dec.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("nuget: parse csproj: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			name := t.Name.Local
			stack = append(stack, name)
			if name == "PackageReference" {
				current = &csprojPkg{}
				for _, attr := range t.Attr {
					switch attr.Name.Local {
					case "Include":
						current.Name = strings.TrimSpace(attr.Value)
					case "Version":
						current.Version = strings.TrimSpace(attr.Value)
					}
				}
			}
		case xml.EndElement:
			if t.Name.Local == "PackageReference" {
				if current != nil && current.Name != "" {
					out = append(out, Dependency{
						Name:      current.Name,
						Version:   current.Version,
						Ecosystem: "nuget",
						Source:    current.Name,
					})
				}
				current = nil
			}
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		case xml.CharData:
			if current == nil || len(stack) == 0 {
				continue
			}
			leaf := stack[len(stack)-1]
			val := strings.TrimSpace(string(t))
			if val == "" {
				continue
			}
			if leaf == "Version" && current.Version == "" {
				// Nested <Version> child overrides nothing if the
				// attribute form already set it.
				current.Version = val
			}
		}
	}
	return dedupe(out), nil
}

type csprojPkg struct {
	Name    string
	Version string
}
