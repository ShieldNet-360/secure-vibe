package tools

import (
	"os"
	"path/filepath"
	"testing"
)

// benchRepoRoot walks up from the working directory to the module root
// (the directory holding go.mod) so benchmarks can construct a real
// Library over the committed data.
func benchRepoRoot(b *testing.B) string {
	b.Helper()
	wd, err := os.Getwd()
	if err != nil {
		b.Fatal(err)
	}
	for dir := wd; dir != "/"; dir = filepath.Dir(dir) {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
	}
	b.Fatal("go.mod not found")
	return ""
}

func benchLibrary(b *testing.B) *Library {
	b.Helper()
	l, err := NewLibrary(benchRepoRoot(b), WithOverlayPaths())
	if err != nil {
		b.Fatal(err)
	}
	return l
}

// BenchmarkScanDependencies measures a realistic lockfile scan against
// the curated DB + OSV cache. The prevention-first pitch is that the
// gate runs on every commit, so per-file latency has to stay low.
func BenchmarkScanDependencies(b *testing.B) {
	root := benchRepoRoot(b)
	lib, err := NewLibrary(root, WithOverlayPaths())
	if err != nil {
		b.Fatal(err)
	}
	// scan_dependencies dispatches on the base name, so the file must be
	// named package.json; write a representative manifest (one known-bad
	// plus several clean deps) into a temp dir inside the library root,
	// which is an allowed scan root.
	dir, err := os.MkdirTemp(root, "bench-deps-")
	if err != nil {
		b.Fatal(err)
	}
	defer os.RemoveAll(dir)
	manifest := filepath.Join(dir, "package.json")
	body := `{"dependencies":{"event-stream":"3.3.6","express":"4.18.2","lodash":"4.17.21","react":"18.2.0","axios":"1.6.0"}}`
	if err := os.WriteFile(manifest, []byte(body), 0o644); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := lib.ScanDependencies(manifest); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkScanGitHubActions measures a workflow scan including the
// comment-blanking pass and the AST pass.
func BenchmarkScanGitHubActions(b *testing.B) {
	root := benchRepoRoot(b)
	lib := benchLibrary(b)
	wf := filepath.Join(root, "evals", "fixtures", "cicd-hardening", "multiple-issues.yml")
	if _, err := os.Stat(wf); err != nil {
		b.Skip("fixture missing")
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := lib.ScanGitHubActions(wf); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkBlankYAMLComments measures the comment-stripping lexer on a
// moderately large workflow body.
func BenchmarkBlankYAMLComments(b *testing.B) {
	var sb []byte
	for i := 0; i < 200; i++ {
		sb = append(sb, []byte("      - run: curl https://x/y.sh | sh  # install step\n")...)
		sb = append(sb, []byte("# a full-line comment explaining the step above\n")...)
	}
	text := string(sb)
	b.SetBytes(int64(len(text)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = blankYAMLComments(text)
	}
}
