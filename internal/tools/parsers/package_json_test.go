package parsers

import "testing"

func TestParsePackageJSON(t *testing.T) {
	body := []byte(`{
		"name": "demo-app",
		"version": "1.0.0",
		"dependencies": {
			"left-pad": "1.3.0",
			"lodash": "^4.17.21",
			"react": ">=17 <19",
			"aliased": "npm:underscore@1.13.6",
			"local": "file:../local",
			"tagged": "latest"
		},
		"devDependencies": {
			"typescript": "=5.4.5"
		},
		"peerDependencies": {
			"react-dom": "*"
		}
	}`)
	deps, err := Parse("package.json", body)
	if err != nil {
		t.Fatalf("Parse(package.json): %v", err)
	}

	// Exact pins surface a concrete version.
	assertContains(t, deps,
		"left-pad@1.3.0/npm",
		"typescript@5.4.5/npm",
		// npm: alias resolves to the real registry target + its pin.
		"underscore@1.13.6/npm",
	)

	// Range / tag / url specs surface the NAME with an empty version so
	// the curated malicious-package and typosquat checks still run, but
	// no false "resolved version" is invented.
	assertContains(t, deps,
		"lodash@/npm",
		"react@/npm",
		"local@/npm",
		"tagged@/npm",
		"react-dom@/npm",
	)

	// The aliased declaration name ("aliased") must NOT appear as a
	// package — only its resolved target does.
	for _, d := range deps {
		if d.Name == "aliased" {
			t.Errorf("npm: alias declaration name leaked as a package: %+v", d)
		}
	}
}

func TestParsePackageJSONEmptyAndMalformed(t *testing.T) {
	// No dependency groups: a valid but dependency-free manifest yields
	// no rows and no error.
	deps, err := Parse("package.json", []byte(`{"name":"x","version":"1.0.0"}`))
	if err != nil {
		t.Fatalf("empty manifest: %v", err)
	}
	if len(deps) != 0 {
		t.Errorf("empty manifest: got %d deps, want 0", len(deps))
	}

	// Malformed JSON is a parse error, not a panic.
	if _, err := Parse("package.json", []byte(`{not json`)); err == nil {
		t.Error("malformed package.json: want error, got nil")
	}
}
