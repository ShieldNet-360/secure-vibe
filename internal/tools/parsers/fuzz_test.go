package parsers

import "testing"

// FuzzParse drives the format dispatcher with arbitrary file names and
// bodies. A parser must never panic on adversarial input — a malformed
// lockfile is a user error to be returned, not a crash. Every recognised
// format is seeded so the fuzzer explores each parser's code path.
func FuzzParse(f *testing.F) {
	seeds := []struct{ name, body string }{
		{"package-lock.json", `{"lockfileVersion":3,"packages":{"node_modules/a":{"version":"1.0.0"}}}`},
		{"package.json", `{"dependencies":{"a":"^1.0.0","b":"npm:c@1.2.3"}}`},
		{"yarn.lock", "a@^1.0.0:\n  version \"1.0.0\"\n"},
		{"pnpm-lock.yaml", "packages:\n  /a@1.0.0:\n    resolution: {}\n"},
		{"requirements.txt", "a==1.0.0\nb @ https://x/y\n# comment\n"},
		{"Pipfile.lock", `{"default":{"a":{"version":"==1.0.0"}}}`},
		{"poetry.lock", "[[package]]\nname = \"a\"\nversion = \"1.0.0\"\n"},
		{"go.sum", "example.com/a v1.0.0 h1:abc=\n"},
		{"Cargo.lock", "[[package]]\nname = \"a\"\nversion = \"1.0.0\"\n"},
		{"pom.xml", "<project><dependencies><dependency><groupId>g</groupId><artifactId>a</artifactId><version>1.0.0</version></dependency></dependencies></project>"},
		{"packages.lock.json", `{"dependencies":{"net6.0":{"a":{"resolved":"1.0.0"}}}}`},
		{"Gemfile.lock", "GEM\n  specs:\n    a (1.0.0)\n"},
		{"app.csproj", `<Project><ItemGroup><PackageReference Include="a" Version="1.0.0"/></ItemGroup></Project>`},
		{"composer.lock", `{"packages":[{"name":"v/a","version":"1.0.0"}],"packages-dev":[]}`},
		{"Package.resolved", `{"pins":[{"identity":"a","state":{"version":"1.0.0"}}],"version":2}`},
		{"pubspec.lock", "packages:\n  a:\n    version: \"1.0.0\"\nsdks:\n  dart: \">=2.0.0\"\n"},
		{"unknown.bin", "\x00\x01\x02 not a lockfile"},
		{"requirements-dev.txt", ""},
	}
	for _, s := range seeds {
		f.Add(s.name, s.body)
	}
	f.Fuzz(func(t *testing.T, name, body string) {
		// Must not panic. The error/empty result is fine; we only assert
		// the call returns. A returned dependency list must be internally
		// consistent (no nil-name rows leak through).
		deps, err := Parse(name, []byte(body))
		if err != nil {
			return
		}
		for _, d := range deps {
			if d.Ecosystem == "" {
				t.Fatalf("Parse(%q) returned a dependency with empty ecosystem: %+v", name, d)
			}
		}
	})
}
