package cmd

import (
	"strings"
	"testing"
)

func TestTestCmdSecretDetection(t *testing.T) {
	root := repoRoot(t)
	stdout, _, err := executeRoot(t,
		"test", "secret-detection",
		"--library", root,
	)
	if err != nil {
		t.Fatalf("test returned error: %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, "passed") || !strings.Contains(stdout, "0 failed") {
		t.Errorf("unexpected stdout: %s", stdout)
	}
}

func TestTestCmdUnknownSkill(t *testing.T) {
	root := repoRoot(t)
	_, _, err := executeRoot(t,
		"test", "no-such-skill",
		"--library", root,
	)
	if err == nil {
		t.Fatal("expected error for unknown skill")
	}
}

// TestHotwordNearOutOfRangeIndicesSafe guards against a panic when matchIdx
// values exceed len(text). Although hotwordNear now receives the original
// text (so byte indices and slice operate on the same byte space),
// pathological callers must not be able to trigger an out-of-range slice.
func TestHotwordNearOutOfRangeIndicesSafe(t *testing.T) {
	text := "prefix payload aws_key=AKIA suffix"
	high := len(text) + 5
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("hotwordNear panicked on out-of-range indices: %v", r)
		}
	}()
	_ = hotwordNear(text, []int{high, high}, []string{"aws"}, 4)
}

// TestHotwordNearNonASCIIPrefixDetects verifies the correctness fix for the
// previous byte-space mismatch: indices come from the original text, and the
// lowered region is taken from a slice of that same text, so the window
// remains aligned even when strings.ToLower shrinks bytes earlier in the
// string (e.g. U+2126 OHM SIGN → U+03C9, 3 → 2 bytes; Turkish İ → i,
// 2 → 1 byte). Previously, hotwordNear examined the wrong region of the
// pre-lowered text and missed hotwords for non-ASCII input.
func TestHotwordNearNonASCIIPrefixDetects(t *testing.T) {
	text := "Ω AWS access key AKIAEXAMPLE in payload"
	idx := strings.Index(text, "AKIA")
	if idx < 0 {
		t.Fatalf("setup: payload not found in test text %q", text)
	}
	loc := []int{idx, idx + len("AKIAEXAMPLE")}
	if !hotwordNear(text, loc, []string{"aws"}, 16) {
		t.Fatal("hotwordNear failed to find 'aws' within window of match on non-ASCII-prefixed text")
	}
}

// TestHotwordNearTurkishIShrinkDetects covers the I→i (2→1 byte) shrinkage
// case specifically: a Turkish capital İ before the match would have caused
// the pre-lowered window to drift by one byte under the previous
// implementation.
func TestHotwordNearTurkishIShrinkDetects(t *testing.T) {
	text := "İSTANBUL AWS region us-east-1 AKIAEXAMPLE"
	idx := strings.Index(text, "AKIA")
	if idx < 0 {
		t.Fatalf("setup: payload not found in test text %q", text)
	}
	loc := []int{idx, idx + len("AKIAEXAMPLE")}
	if !hotwordNear(text, loc, []string{"aws"}, 32) {
		t.Fatal("hotwordNear failed to find 'aws' within window of match on Turkish-İ-prefixed text")
	}
}
