package parsers

import (
	"bufio"
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// parsePomXML reads a Maven POM (`pom.xml`) and emits one
// Dependency per `<dependency>` entry under `<dependencies>` (both
// top-level and inside `<dependencyManagement>`). Plugins and BOMs
// are intentionally NOT emitted — they describe build/tooling
// configuration, not runtime dependencies, and the
// malicious-packages / typosquat databases for the `maven`
// ecosystem are scoped to runtime artefacts.
//
// The XML is parsed with encoding/xml in streaming mode so a
// hand-edited POM with comments, processing instructions, or
// odd whitespace decodes cleanly. We deliberately do not
// expand `${property}` references — most pinned `<version>`
// elements are literal, and an unresolved property string is
// surfaced as the version verbatim so a downstream check_dependency
// call simply records no match rather than panicking.
func parsePomXML(body []byte) ([]Dependency, error) {
	dec := xml.NewDecoder(bytes.NewReader(body))
	var (
		out          []Dependency
		stack        []string
		current      *mavenCoord
		insideDepSet bool
	)
	for {
		tok, err := dec.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("maven: parse pom.xml: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			name := t.Name.Local
			stack = append(stack, name)
			// A <dependency> element only counts when it lives
			// directly under <dependencies> (which itself sits
			// directly under <project> or
			// <dependencyManagement>). This rejects plugin
			// <dependency> blocks nested under
			// <build><plugins><plugin><dependencies>…, which
			// are build-time tooling deps and must not be
			// treated as runtime artefacts by the scanner.
			if name == "dependency" && isRuntimeDependency(stack) {
				current = &mavenCoord{}
				insideDepSet = true
			}
		case xml.EndElement:
			name := t.Name.Local
			if insideDepSet && current != nil && name == "dependency" {
				if current.GroupID != "" && current.ArtifactID != "" {
					out = append(out, Dependency{
						Name:      current.GroupID + ":" + current.ArtifactID,
						Version:   current.Version,
						Ecosystem: "maven",
						Source:    current.GroupID + ":" + current.ArtifactID,
					})
				}
				current = nil
				insideDepSet = false
			}
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		case xml.CharData:
			if !insideDepSet || current == nil || len(stack) < 2 {
				continue
			}
			// Only consume <groupId>/<artifactId>/<version>
			// elements that are direct children of the
			// <dependency> being parsed. Without this guard, an
			// <exclusions><exclusion><groupId>commons-logging</groupId>...
			// block nested inside a <dependency> would overwrite
			// the parent dependency's groupId / artifactId
			// (`insideDepSet` would still be true at that depth),
			// so the scanner would emit the exclusion's
			// coordinates instead of the dependency's.
			if stack[len(stack)-2] != "dependency" {
				continue
			}
			leaf := stack[len(stack)-1]
			val := strings.TrimSpace(string(t))
			if val == "" {
				continue
			}
			switch leaf {
			case "groupId":
				current.GroupID = val
			case "artifactId":
				current.ArtifactID = val
			case "version":
				current.Version = val
			}
		}
	}
	return dedupe(out), nil
}

type mavenCoord struct {
	GroupID    string
	ArtifactID string
	Version    string
}

// isRuntimeDependency reports whether the current <dependency>
// element on top of stack is a project-level runtime dependency.
// That means:
//
//   - parent is <dependencies>
//   - grandparent is either <project> or <dependencyManagement>
//
// Anything else is intentionally rejected. In particular this
// drops two shapes that the malicious-package and typosquat
// scanners do not need to inspect:
//
//   - <build><plugins><plugin><dependencies><dependency>: deps
//     scoped to a build-tooling plugin, not the application.
//   - <profiles><profile>[/dependencyManagement]/dependencies/dependency:
//     deps that are conditionally activated by a Maven profile.
//     These can ship at runtime depending on which profile is
//     active at build time, so a future enhancement could opt in
//     by widening the grandparent check; for now they're a
//     deliberate blind spot rather than a silent bug.
func isRuntimeDependency(stack []string) bool {
	if len(stack) < 3 {
		return false
	}
	parent := stack[len(stack)-2]
	grand := stack[len(stack)-3]
	return parent == "dependencies" && (grand == "project" || grand == "dependencyManagement")
}

// gradleLockfileLine matches one line of a Gradle lockfile. The
// format Gradle 6+ emits is:
//
//	group:artifact:version=configuration1,configuration2
//
// Lines starting with `#` or `empty=` are metadata and skipped.
// The `=<configurations>` suffix is optional in older formats.
var gradleLockfileLine = regexp.MustCompile(`^([^:\s#=]+):([^:\s=]+):([^=\s]+)(?:=.*)?$`)

// parseGradleLockfile reads a `gradle.lockfile` (or
// `build.gradle.lockfile`) emitted by Gradle's dependency-locking
// feature. The format is line-based:
//
//	# This is a Gradle lockfile.
//	com.google.guava:guava:32.1.3-jre=runtimeClasspath
//	empty=annotationProcessor
//
// Each accepted line yields one Dependency keyed `group:artifact`
// with the resolved version. Configuration suffixes are dropped —
// they describe build-graph scope, not the artefact itself, and
// the same coordinate may appear once per configuration.
func parseGradleLockfile(body []byte) ([]Dependency, error) {
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 64*1024), 1<<20)
	var out []Dependency
	for scanner.Scan() {
		raw := scanner.Text()
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "empty=") {
			// Marker line for configurations with no locked deps.
			continue
		}
		m := gradleLockfileLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		group, artifact, version := m[1], m[2], m[3]
		if group == "" || artifact == "" || version == "" {
			continue
		}
		out = append(out, Dependency{
			Name:      group + ":" + artifact,
			Version:   version,
			Ecosystem: "maven",
			Source:    group + ":" + artifact,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("maven: scan gradle lockfile: %w", err)
	}
	return dedupe(out), nil
}
