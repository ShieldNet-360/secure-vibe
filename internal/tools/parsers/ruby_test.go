package parsers

import "testing"

func TestParseGemfileLock(t *testing.T) {
	body := []byte(`GEM
  remote: https://rubygems.org/
  specs:
    actionmailer (7.1.2)
      actionpack (= 7.1.2)
      activesupport (= 7.1.2)
    rails (7.1.2)
      actionmailer (= 7.1.2)
    rake (13.1.0)

PLATFORMS
  ruby

DEPENDENCIES
  rails (~> 7.1.2)
  rake

BUNDLED WITH
   2.5.3
`)
	got, err := Parse("Gemfile.lock", body)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	assertContains(t, got,
		"actionmailer@7.1.2/rubygems",
		"rails@7.1.2/rubygems",
		"rake@13.1.0/rubygems",
	)
	// The `(= 7.1.2)` style sub-bullets describe transitive
	// requirements, not installed gems; the parser must NOT emit
	// them as separate entries.
	for _, d := range got {
		if d.Name == "actionpack" && d.Version == "= 7.1.2" {
			t.Fatalf("transitive range emitted as resolved version: %+v", d)
		}
		if d.Name == "activesupport" && d.Version == "= 7.1.2" {
			t.Fatalf("transitive range emitted as resolved version: %+v", d)
		}
	}
}

func TestParseGemfileLockIgnoresGitAndPathSections(t *testing.T) {
	body := []byte(`PATH
  remote: ../my-local-gem
  specs:
    my-local-gem (0.1.0)

GIT
  remote: https://github.com/example/some-gem
  revision: deadbeef
  specs:
    some-gem (1.0.0)

GEM
  remote: https://rubygems.org/
  specs:
    rack (3.0.8)

PLATFORMS
  ruby

DEPENDENCIES
  rack
`)
	got, err := Parse("Gemfile.lock", body)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	assertContains(t, got, "rack@3.0.8/rubygems")
	// PATH / GIT specs are not rubygems.org artefacts and must
	// not be emitted.
	for _, d := range got {
		if d.Name == "my-local-gem" {
			t.Fatalf("PATH spec must not be emitted: %+v", d)
		}
		if d.Name == "some-gem" {
			t.Fatalf("GIT spec must not be emitted: %+v", d)
		}
	}
}
