package parsers

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// parseNPMPackageLock reads the npm v1, v2, and v3 lockfile shapes.
//
// v1 stores the dependency tree under a recursive `dependencies` map
// keyed by package name. v2 keeps the v1 tree for compatibility and
// adds a flat `packages` map keyed by the install-relative path
// ("node_modules/foo"). v3 drops the legacy `dependencies` tree and
// only emits `packages`. We prefer `packages` when present so we get
// the flat layout — it is what npm itself resolves against.
//
// `npm-shrinkwrap.json` uses the same schema and shares this parser.
func parseNPMPackageLock(body []byte) ([]Dependency, error) {
	var doc struct {
		LockfileVersion int `json:"lockfileVersion"`
		// v2/v3: flat keyed by "node_modules/<name>".
		Packages map[string]struct {
			Version string `json:"version"`
			Dev     bool   `json:"dev,omitempty"`
		} `json:"packages,omitempty"`
		// v1: recursive tree.
		Dependencies map[string]npmV1Entry `json:"dependencies,omitempty"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("npm: parse package-lock.json: %w", err)
	}
	var out []Dependency
	if len(doc.Packages) > 0 {
		// Sort keys so the output is deterministic across runs.
		keys := make([]string, 0, len(doc.Packages))
		for k := range doc.Packages {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if k == "" {
				// Root entry — describes the project itself, not a dep.
				continue
			}
			name := strings.TrimPrefix(k, "node_modules/")
			if i := strings.LastIndex(name, "/node_modules/"); i >= 0 {
				name = name[i+len("/node_modules/"):]
			}
			ver := doc.Packages[k].Version
			if name == "" || ver == "" {
				continue
			}
			out = append(out, Dependency{
				Name:      name,
				Version:   ver,
				Ecosystem: "npm",
				Source:    k,
			})
		}
		return dedupe(out), nil
	}
	flattenNPMv1(doc.Dependencies, "", &out)
	return dedupe(out), nil
}

type npmV1Entry struct {
	Version      string                `json:"version"`
	Dependencies map[string]npmV1Entry `json:"dependencies,omitempty"`
}

func flattenNPMv1(deps map[string]npmV1Entry, prefix string, out *[]Dependency) {
	if len(deps) == 0 {
		return
	}
	keys := make([]string, 0, len(deps))
	for k := range deps {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, name := range keys {
		entry := deps[name]
		if entry.Version != "" {
			src := name
			if prefix != "" {
				src = prefix + " > " + name
			}
			*out = append(*out, Dependency{
				Name:      name,
				Version:   entry.Version,
				Ecosystem: "npm",
				Source:    src,
			})
		}
		nested := name
		if prefix != "" {
			nested = prefix + " > " + name
		}
		flattenNPMv1(entry.Dependencies, nested, out)
	}
}

// parsePackageJSON reads an npm package.json manifest. Unlike a
// lockfile, a manifest records version *constraints* (`^1.2.3`,
// `>=2 <3`, `*`), not resolved installs, so there is no single
// "installed version" to emit. We still surface every declared
// dependency name — that is the signal the curated malicious-package
// and typosquat checks need, and catching a hostile package the moment
// it is *declared* (before a lockfile is even generated) is the whole
// point of supporting the manifest.
//
// A concrete version is emitted only when the constraint is an exact
// pin (e.g. "1.2.3" or "=1.2.3"); range/tag/url specs leave Version
// empty, which the OSV range filter treats as "cannot confirm — keep
// on name match". `npm:` aliases are resolved to their real registry
// target so an aliased malicious package is still checked under its
// true name.
//
// All four dependency groups are read (runtime, dev, optional, peer)
// so a dev-only or peer malicious dependency is not silently ignored.
func parsePackageJSON(body []byte) ([]Dependency, error) {
	var doc struct {
		Dependencies         map[string]string `json:"dependencies"`
		DevDependencies      map[string]string `json:"devDependencies"`
		OptionalDependencies map[string]string `json:"optionalDependencies"`
		PeerDependencies     map[string]string `json:"peerDependencies"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("npm: parse package.json: %w", err)
	}
	var out []Dependency
	groups := []struct {
		label string
		deps  map[string]string
	}{
		{"dependencies", doc.Dependencies},
		{"devDependencies", doc.DevDependencies},
		{"optionalDependencies", doc.OptionalDependencies},
		{"peerDependencies", doc.PeerDependencies},
	}
	for _, g := range groups {
		names := make([]string, 0, len(g.deps))
		for name := range g.deps {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			pkg, ver := resolveNPMManifestSpec(name, g.deps[name])
			if pkg == "" {
				continue
			}
			out = append(out, Dependency{
				Name:      pkg,
				Version:   ver,
				Ecosystem: "npm",
				Source:    g.label + ": " + name,
			})
		}
	}
	return dedupe(out), nil
}

// exactNPMVersion matches a fully-pinned npm version (optionally with a
// leading `=` or `v`), e.g. "1.2.3", "=1.2.3", "v1.0.0-beta.1". A spec
// that contains a range operator, wildcard, space, or url is not an
// exact pin and must not be reported as a resolved version.
var exactNPMVersion = regexp.MustCompile(`^[=v]?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.\-]+)?$`)

// resolveNPMManifestSpec maps a (name, spec) manifest entry to the
// (registry package, exact-version-or-empty) pair to check. It resolves
// `npm:<target>@<range>` aliases to <target> and drops the empty
// version when the spec is anything other than an exact pin.
func resolveNPMManifestSpec(name, spec string) (pkg, version string) {
	spec = strings.TrimSpace(spec)
	pkg = name
	// Registry alias: "foo": "npm:bar@1.2.3" actually installs `bar`.
	if rest, ok := strings.CutPrefix(spec, "npm:"); ok {
		at := strings.LastIndex(rest, "@")
		if at > 0 { // > 0 so a scoped "@scope/pkg" with no range keeps its leading @
			pkg = rest[:at]
			spec = rest[at+1:]
		} else {
			pkg = rest
			spec = ""
		}
	}
	if exactNPMVersion.MatchString(spec) {
		version = strings.TrimLeft(spec, "=v")
	}
	return pkg, version
}

// yarnEntryHeader matches the package descriptor line of a Yarn 1
// lockfile entry. The format is one or more comma-separated
// `<name>@<range>` patterns terminated by a colon. The name itself
// may contain a `@` when it is scoped (`@scope/pkg@1.x`); we handle
// both shapes.
var yarnEntryHeader = regexp.MustCompile(`^("?)((@[^"@,\s]+/)?[^"@,\s]+)@`)

// parseYarnLock reads the Yarn 1 lockfile format. Yarn 2+ ("Berry")
// emits an extended YAML-flavoured form by default but still falls
// back to this format under `nodeLinker: node-modules`; both shapes
// share the `version "<ver>"` line so the regex below catches them.
func parseYarnLock(body []byte) ([]Dependency, error) {
	scanner := bufio.NewScanner(bytes.NewReader(body))
	// Yarn entries can be long; bump the line cap to 1 MB.
	scanner.Buffer(make([]byte, 64*1024), 1<<20)

	var (
		current string
		out     []Dependency
	)
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		// An entry header is not indented and ends in ":".
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") && strings.HasSuffix(line, ":") {
			m := yarnEntryHeader.FindStringSubmatch(trimmed)
			if m == nil {
				current = ""
				continue
			}
			current = m[2]
			continue
		}
		if current == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "version ") || strings.HasPrefix(trimmed, "version:") {
			rest := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(trimmed, "version"), ":"))
			rest = strings.TrimSpace(rest)
			rest = strings.Trim(rest, "\"")
			if rest != "" {
				out = append(out, Dependency{
					Name:      current,
					Version:   rest,
					Ecosystem: "npm",
					Source:    current,
				})
			}
			current = ""
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("npm: scan yarn.lock: %w", err)
	}
	return dedupe(out), nil
}

// pnpmPackagePath matches a package key under pnpm-lock.yaml's
// `packages:` top-level across schema versions, which differ in how the
// key is written:
//
//   - lockfileVersion 5–8:  `  /<name>@<version>:`        (leading slash)
//   - lockfileVersion 9+:   `  '<name>@<version>':`       (quoted, no slash)
//   - simple v9 names:      `  <name>@<version>:`         (unquoted)
//
// The match is anchored at the two-space key indent (so deeper 4-space
// metadata lines like `resolution:` / `engines:` are ignored), allows an
// optional quote and optional leading slash, keeps a scoped name's
// leading `@`, and stops the version at the first peer-dep paren so a
// v8 `/a@1.0.0(b@2)` yields version `1.0.0`.
var pnpmPackagePath = regexp.MustCompile(`^  '?/?((?:@[^@/'\s]+/)?[^@/'\s]+)@([^'\s:()]+)`)

// parsePnpmLock reads pnpm-lock.yaml without a full YAML decoder.
//
// pnpm's lockfile schema is verbose and version-stamped; the only
// fields we need for scan_dependencies are the package keys under
// `packages:` (see pnpmPackagePath for the per-version key shapes).
// Walking the file line-by-line keeps the
// parser hermetic (no third-party YAML library) and is robust to the
// half-dozen incompatible schema versions pnpm has shipped.
func parsePnpmLock(body []byte) ([]Dependency, error) {
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 64*1024), 1<<20)

	inPackages := false
	var out []Dependency
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "packages:") {
			inPackages = true
			continue
		}
		if inPackages && !strings.HasPrefix(line, " ") && strings.TrimSpace(line) != "" {
			// Left the packages: block.
			inPackages = false
		}
		if !inPackages {
			continue
		}
		m := pnpmPackagePath.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		out = append(out, Dependency{
			Name:      m[1],
			Version:   m[2],
			Ecosystem: "npm",
			Source:    strings.TrimSpace(line),
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("npm: scan pnpm-lock.yaml: %w", err)
	}
	return dedupe(out), nil
}
