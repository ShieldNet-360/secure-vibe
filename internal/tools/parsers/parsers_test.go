package parsers

import (
	"errors"
	"sort"
	"testing"
)

// keyOf returns the (name, version, ecosystem) tuple as a comparable
// string so tests can assert membership without depending on the
// dedupe ordering or the Source field.
func keyOf(d Dependency) string {
	return d.Name + "@" + d.Version + "/" + d.Ecosystem
}

func keys(deps []Dependency) []string {
	out := make([]string, len(deps))
	for i, d := range deps {
		out[i] = keyOf(d)
	}
	sort.Strings(out)
	return out
}

func assertContains(t *testing.T, deps []Dependency, want ...string) {
	t.Helper()
	got := map[string]bool{}
	for _, k := range keys(deps) {
		got[k] = true
	}
	for _, w := range want {
		if !got[w] {
			t.Fatalf("expected dep %q in parser output, got %v", w, keys(deps))
		}
	}
}

func TestParseRejectsUnknownLockfile(t *testing.T) {
	// Pick a base name that no parser claims. "mix.lock" is a real
	// Elixir lockfile the library does not (yet) ship a parser for, so
	// it is a good sentinel for the "no dispatcher" branch.
	_, err := Parse("mix.lock", []byte("anything"))
	if !errors.Is(err, ErrUnknownLockfile) {
		t.Fatalf("expected ErrUnknownLockfile, got %v", err)
	}
}

func TestParseNPMPackageLockV3(t *testing.T) {
	body := []byte(`{
	  "name": "demo",
	  "lockfileVersion": 3,
	  "packages": {
	    "": { "name": "demo", "version": "1.0.0" },
	    "node_modules/lodash":     { "version": "4.17.21" },
	    "node_modules/@types/node": { "version": "20.10.0" },
	    "node_modules/foo/node_modules/lodash": { "version": "3.10.1" }
	  }
	}`)
	got, err := Parse("package-lock.json", body)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	assertContains(t, got,
		"lodash@4.17.21/npm",
		"lodash@3.10.1/npm",
		"@types/node@20.10.0/npm",
	)
}

func TestParseNPMPackageLockV1(t *testing.T) {
	body := []byte(`{
	  "name": "demo",
	  "lockfileVersion": 1,
	  "dependencies": {
	    "lodash": { "version": "4.17.21" },
	    "express": {
	      "version": "4.18.2",
	      "dependencies": {
	        "qs": { "version": "6.11.0" }
	      }
	    }
	  }
	}`)
	got, err := Parse("package-lock.json", body)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	assertContains(t, got,
		"lodash@4.17.21/npm",
		"express@4.18.2/npm",
		"qs@6.11.0/npm",
	)
}

func TestParseYarnLock(t *testing.T) {
	body := []byte(`# yarn lockfile v1

"@types/node@^20.0.0":
  version "20.10.0"
  resolved "https://registry.yarnpkg.com/@types/node/-/node-20.10.0.tgz"

lodash@^4.17.20, lodash@^4.17.21:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"

ms@2.1.2:
  version "2.1.2"
`)
	got, err := Parse("yarn.lock", body)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	assertContains(t, got,
		"@types/node@20.10.0/npm",
		"lodash@4.17.21/npm",
		"ms@2.1.2/npm",
	)
}

func TestParsePnpmLock(t *testing.T) {
	body := []byte(`lockfileVersion: '6.0'

dependencies:
  lodash:
    specifier: ^4.17.21
    version: 4.17.21

packages:

  /lodash@4.17.21:
    resolution: {integrity: sha512-deadbeef}
    dev: false

  /@types/node@20.10.0:
    resolution: {integrity: sha512-cafe}
`)
	got, err := Parse("pnpm-lock.yaml", body)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	assertContains(t, got,
		"lodash@4.17.21/npm",
		"@types/node@20.10.0/npm",
	)
}

// TestParsePnpmLockV9 covers the lockfileVersion 9 format, whose
// `packages:` keys are quoted `'name@version':` with no leading slash —
// a shape the v5–8 `/name@version:` regex missed entirely, so modern
// pnpm projects parsed zero dependencies (found by dogfooding).
func TestParsePnpmLockV9(t *testing.T) {
	body := []byte(`lockfileVersion: '9.0'

settings:
  autoInstallPeers: true

importers:
  .:
    devDependencies:
      typescript:
        specifier: ^5.4.0
        version: 5.9.3

packages:

  '@acemir/cssom@0.9.31':
    resolution: {integrity: sha512-ZnR3GSaH==}

  '@alloc/quick-lru@5.2.0':
    resolution: {integrity: sha512-UrcABB==}
    engines: {node: '>=10'}

  'typescript@5.9.3':
    resolution: {integrity: sha512-typescript==}
    engines: {node: '>=14.17'}

snapshots:

  '@acemir/cssom@0.9.31': {}
`)
	got, err := Parse("pnpm-lock.yaml", body)
	if err != nil {
		t.Fatalf("Parse v9: %v", err)
	}
	assertContains(t, got,
		"@acemir/cssom@0.9.31/npm",
		"@alloc/quick-lru@5.2.0/npm",
		"typescript@5.9.3/npm",
	)
	// The snapshots: section must not double-count (dedupe handles the
	// repeat, but the block boundary should also already exclude it).
	count := 0
	for _, d := range got {
		if d.Name == "@acemir/cssom" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("@acemir/cssom counted %d times, want 1", count)
	}
}

func TestParseRequirementsTxt(t *testing.T) {
	body := []byte(`# top-level deps
requests==2.31.0 --hash=sha256:dead # comment
Django==4.2.7
typing-extensions ; python_version < "3.11" == 4.7.1
-r other.txt
not-a-pin>=1.0
flask===2.0.0
`)
	got, err := Parse("requirements.txt", body)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	assertContains(t, got,
		"requests@2.31.0/pypi",
		"Django@4.2.7/pypi",
		"flask@2.0.0/pypi",
		// A loose range now emits the NAME (empty version) so the curated
		// malicious/typosquat checks still run; see
		// TestParseRequirementsRangesEmitNames for the full coverage.
		"not-a-pin@/pypi",
	)
	for _, d := range got {
		if d.Name == "not-a-pin" && d.Version != "" {
			t.Fatalf("loose range must not invent a version: %+v", d)
		}
	}
}

func TestParsePipfileLock(t *testing.T) {
	body := []byte(`{
	  "default": {
	    "requests": { "version": "==2.31.0" }
	  },
	  "develop": {
	    "pytest": { "version": "==7.4.0" }
	  }
	}`)
	got, err := Parse("Pipfile.lock", body)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	assertContains(t, got,
		"requests@2.31.0/pypi",
		"pytest@7.4.0/pypi",
	)
}

func TestParsePoetryLock(t *testing.T) {
	body := []byte(`# This file is automatically @generated by Poetry.
[[package]]
name = "requests"
version = "2.31.0"
description = "Python HTTP for Humans."

[[package]]
name = "urllib3"
version = "2.0.7"

[metadata]
lock-version = "2.0"
`)
	got, err := Parse("poetry.lock", body)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	assertContains(t, got,
		"requests@2.31.0/pypi",
		"urllib3@2.0.7/pypi",
	)
}

func TestParseGoSum(t *testing.T) {
	body := []byte(`github.com/stretchr/testify v1.8.4 h1:xxxxxx=
github.com/stretchr/testify v1.8.4/go.mod h1:yyyyy=
golang.org/x/text v0.14.0 h1:zzzzzz=
`)
	got, err := Parse("go.sum", body)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	assertContains(t, got,
		"github.com/stretchr/testify@v1.8.4/go",
		"golang.org/x/text@v0.14.0/go",
	)
	// /go.mod suffix should be deduped, not double-counted.
	count := 0
	for _, d := range got {
		if d.Name == "github.com/stretchr/testify" && d.Version == "v1.8.4" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly one testify entry, got %d (%v)", count, got)
	}
}

// TestParseGoSumSkipsGoModOnly is the regression for a false-positive
// source: a module version present only in `/go.mod` lines (consulted
// during MVS but superseded, so never built) must NOT be reported. Only
// the version with a content `h1:` hash is the compiled dependency.
func TestParseGoSumSkipsGoModOnly(t *testing.T) {
	body := []byte(`golang.org/x/crypto v0.0.0-20190308221718-c2843e01d9a2/go.mod h1:aaa=
golang.org/x/crypto v0.0.0-20220622213112-05595931fe9d/go.mod h1:bbb=
golang.org/x/crypto v0.53.0 h1:ccc=
golang.org/x/crypto v0.53.0/go.mod h1:ddd=
`)
	got, err := Parse("go.sum", body)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	// Only the built (content-hashed) version is a dependency.
	assertContains(t, got, "golang.org/x/crypto@v0.53.0/go")
	for _, d := range got {
		if d.Name == "golang.org/x/crypto" && d.Version != "v0.53.0" {
			t.Errorf("reported a /go.mod-only (unbuilt) version: %s@%s", d.Name, d.Version)
		}
	}
	if n := len(got); n != 1 {
		t.Errorf("got %d deps, want 1 (only the built x/crypto): %v", n, got)
	}
}

func TestParseCargoLock(t *testing.T) {
	body := []byte(`# This file is automatically @generated by Cargo.
[[package]]
name = "serde"
version = "1.0.190"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "my-local-crate"
version = "0.1.0"

[[package]]
name = "tokio"
version = "1.34.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
`)
	got, err := Parse("Cargo.lock", body)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	assertContains(t, got,
		"serde@1.0.190/crates",
		"tokio@1.34.0/crates",
	)
	for _, d := range got {
		if d.Name == "my-local-crate" {
			t.Fatalf("path/workspace crate without source should not be emitted: %+v", d)
		}
	}
}

func TestDedupePreservesDistinctVersions(t *testing.T) {
	deps := []Dependency{
		{Name: "lodash", Version: "4.17.21", Ecosystem: "npm"},
		{Name: "lodash", Version: "4.17.21", Ecosystem: "npm"},
		{Name: "lodash", Version: "3.10.1", Ecosystem: "npm"},
	}
	out := dedupe(deps)
	if len(out) != 2 {
		t.Fatalf("dedupe should keep two distinct versions, got %v", out)
	}
}
