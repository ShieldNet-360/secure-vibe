package tools

import "testing"

// FuzzBlankYAMLComments asserts the lexer's core invariant — byte length
// (and therefore every offset) is preserved — and that it never panics
// on arbitrary input. A length change would desync the line numbers the
// scanner reports.
func FuzzBlankYAMLComments(f *testing.F) {
	seeds := []string{
		"# comment\nrun: ok",
		"run: echo \"a # b\" # trailing",
		"key: 'v#1'\n# full\n  - run: curl x | sh",
		"",
		"#",
		"\n\n#\n",
		"\"unterminated # quote",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		out := blankYAMLComments(s)
		if len(out) != len(s) {
			t.Fatalf("length changed: %d -> %d (offsets must be preserved)", len(s), len(out))
		}
		// Idempotent: blanking an already-blanked string changes nothing.
		if again := blankYAMLComments(out); again != out {
			t.Fatalf("not idempotent on %q", s)
		}
	})
}
