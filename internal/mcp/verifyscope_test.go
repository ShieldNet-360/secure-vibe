package mcp

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadVerifyScope_File(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "scope.json")
	if err := os.WriteFile(f, []byte(`{"targets":[
		{"match":"localhost:4100","headers":{"Cookie":"sid=SECRET"}},
		{"match":"*.staging.myco.com","headers":{"Authorization":"Bearer X"}}
	]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SECURE_VIBE_VERIFY_SCOPE", "")
	t.Setenv("SECURE_VIBE_VERIFY_SCOPE_FILE", f)

	allow, headers, scoped := loadVerifyScope()
	if !scoped {
		t.Fatal("expected scoped")
	}
	if !allow("http://localhost:4100/research") {
		t.Error("localhost:4100 should be allowed")
	}
	if allow("http://evil.com/x") {
		t.Error("evil.com must NOT be allowed")
	}
	if h := headers("http://localhost:4100/research"); h["Cookie"] != "sid=SECRET" {
		t.Errorf("expected Cookie header, got %v", h)
	}
	// wildcard host match + its headers
	if !allow("https://app.staging.myco.com/q") {
		t.Error("wildcard host should match")
	}
	if h := headers("https://app.staging.myco.com/q"); h["Authorization"] != "Bearer X" {
		t.Errorf("expected Authorization header, got %v", h)
	}
	// out of scope → no headers leaked
	if h := headers("http://evil.com/x"); h != nil {
		t.Errorf("out-of-scope must have no headers, got %v", h)
	}
}

func TestLoadVerifyScope_EnvFallback(t *testing.T) {
	t.Setenv("SECURE_VIBE_VERIFY_SCOPE_FILE", "")
	t.Setenv("SECURE_VIBE_VERIFY_SCOPE", "localhost:4000")
	allow, headers, scoped := loadVerifyScope()
	if !scoped {
		t.Fatal("expected scoped from env")
	}
	if !allow("http://localhost:4000/x") {
		t.Error("env host should be allowed")
	}
	if headers("http://localhost:4000/x") != nil {
		t.Error("env fallback carries no auth headers")
	}
}

func TestLoadVerifyScope_NoneDenies(t *testing.T) {
	t.Setenv("SECURE_VIBE_VERIFY_SCOPE_FILE", "")
	t.Setenv("SECURE_VIBE_VERIFY_SCOPE", "")
	allow, _, scoped := loadVerifyScope()
	if scoped {
		t.Error("no config must be unscoped (dry-run)")
	}
	if allow("http://localhost:4000/x") {
		t.Error("no config must deny all")
	}
}

func TestLoadVerifyScope_BadFileDenies(t *testing.T) {
	t.Setenv("SECURE_VIBE_VERIFY_SCOPE", "")
	t.Setenv("SECURE_VIBE_VERIFY_SCOPE_FILE", "/nonexistent/scope.json")
	allow, _, scoped := loadVerifyScope()
	if scoped || allow("http://localhost:4000/x") {
		t.Error("unreadable scope file must fall back to deny-all (safe)")
	}
}
