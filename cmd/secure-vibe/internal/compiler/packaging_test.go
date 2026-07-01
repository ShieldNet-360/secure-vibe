package compiler

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestNfpmConfigParses verifies the Linux packaging configuration is
// syntactically valid YAML and exposes the fields nfpm needs to build a
// .deb and .rpm: name, contents listing a /usr/local/bin/secure-vibe
// destination, and a description.
func TestNfpmConfigParses(t *testing.T) {
	path := filepath.Join(repoRoot(t), "packaging", "linux", "nfpm.yaml")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Name        string `yaml:"name"`
		Description string `yaml:"description"`
		Maintainer  string `yaml:"maintainer"`
		License     string `yaml:"license"`
		Contents    []struct {
			Src string `yaml:"src"`
			Dst string `yaml:"dst"`
		} `yaml:"contents"`
	}
	if err := yaml.Unmarshal(body, &cfg); err != nil {
		t.Fatalf("parse nfpm.yaml: %v", err)
	}
	if cfg.Name != "secure-vibe" {
		t.Errorf("name=%q, want secure-vibe", cfg.Name)
	}
	if cfg.Description == "" {
		t.Error("description must be non-empty")
	}
	if cfg.License == "" {
		t.Error("license must be set")
	}
	var foundBinary bool
	for _, c := range cfg.Contents {
		if c.Dst == "/usr/local/bin/secure-vibe" {
			foundBinary = true
		}
	}
	if !foundBinary {
		t.Errorf("expected contents entry installing /usr/local/bin/secure-vibe; got %+v", cfg.Contents)
	}
}

// TestPackageManifestsPresent enforces that the per-platform manifests
// referenced in the install docs are checked in.
func TestPackageManifestsPresent(t *testing.T) {
	root := repoRoot(t)
	for _, rel := range []string{
		"packaging/linux/nfpm.yaml",
		"packaging/linux/Makefile",
		"packaging/homebrew/secure-vibe.rb",
		"packaging/winget/shieldnet-360.secure-vibe.yaml",
		"packaging/scoop/secure-vibe.json",
		"packaging/apt-yum/README.md",
		"packaging/apt-yum/Makefile",
		"packaging/codesign/README.md",
	} {
		full := filepath.Join(root, rel)
		if _, err := os.Stat(full); err != nil {
			t.Errorf("missing packaging file %s: %v", rel, err)
		}
	}
}

// TestHomebrewFormulaShape sniff-checks the Homebrew formula for the
// fields a downstream tap consumer will read: a `url`, a `sha256`, and a
// `def install` block.
func TestHomebrewFormulaShape(t *testing.T) {
	body, err := os.ReadFile(filepath.Join(repoRoot(t), "packaging", "homebrew", "secure-vibe.rb"))
	if err != nil {
		t.Fatal(err)
	}
	got := string(body)
	for _, needle := range []string{
		"class Securevibe",
		"url \"",
		"sha256 \"",
		"def install",
	} {
		if !strings.Contains(got, needle) {
			t.Errorf("homebrew formula missing %q\n%s", needle, got)
		}
	}
}
