package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shieldnet-360/secure-vibe/cmd/secure-vibe/internal/manifest"
)

// stagedSignedRelease populates dir with files plus a signed manifest, then
// writes the private key to disk so SignManifest variants can be exercised.
// It returns the directory and the matching public key path.
func stagedSignedRelease(t *testing.T, dir string, files map[string]string, version string) string {
	t.Helper()
	for rel, body := range files {
		full := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	pub, priv, err := manifest.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	m := &manifest.Manifest{
		SchemaVersion: "1.0",
		Version:       version,
		ReleasedAt:    "2026-05-12T00:00:00Z",
		PublicKeyID:   "test-key",
	}
	for rel, body := range files {
		sum := sha256.Sum256([]byte(body))
		m.Files = append(m.Files, manifest.File{
			Path:   rel,
			SHA256: hex.EncodeToString(sum[:]),
			Size:   int64(len(body)),
		})
	}
	m.SortFiles()
	if err := m.SignWith(priv); err != nil {
		t.Fatal(err)
	}
	if err := m.Save(filepath.Join(dir, "manifest.json")); err != nil {
		t.Fatal(err)
	}
	pubPath := filepath.Join(dir, "pub.key")
	if err := os.WriteFile(pubPath, pub, 0o644); err != nil {
		t.Fatal(err)
	}
	return pubPath
}

func TestUpdateCheckOnlyReportsChangesAndSkipsApply(t *testing.T) {
	src := t.TempDir()
	pubPath := stagedSignedRelease(t, src, map[string]string{
		"skills/a/SKILL.md": "v2 body",
	}, "v2")

	local := t.TempDir()
	if err := os.MkdirAll(filepath.Join(local, "skills/a"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(local, "skills/a/SKILL.md"), []byte("v1 body"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := &manifest.Manifest{Version: "v1"}
	sum := sha256.Sum256([]byte("v1 body"))
	old.Files = append(old.Files, manifest.File{
		Path: "skills/a/SKILL.md", SHA256: hex.EncodeToString(sum[:]), Size: 7,
	})
	if err := old.Save(filepath.Join(local, "manifest.json")); err != nil {
		t.Fatal(err)
	}
	stdout, _, err := executeRoot(t, "update",
		"--path", local,
		"--source", src,
		"--public-key", pubPath,
		"--check-only",
	)
	if err != nil {
		t.Fatalf("update --check-only failed: %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, "updated") || !strings.Contains(stdout, "skills/a/SKILL.md") {
		t.Errorf("expected update for skills/a in output: %q", stdout)
	}
	// File on disk must be unchanged.
	got, _ := os.ReadFile(filepath.Join(local, "skills/a/SKILL.md"))
	if string(got) != "v1 body" {
		t.Errorf("check-only must not modify files: %q", got)
	}
}

func TestUpdateAppliesAndRollsBack(t *testing.T) {
	src := t.TempDir()
	pubPath := stagedSignedRelease(t, src, map[string]string{
		"skills/a/SKILL.md": "v2 body",
	}, "v2")

	local := t.TempDir()
	if err := os.MkdirAll(filepath.Join(local, "skills/a"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(local, "skills/a/SKILL.md"), []byte("v1 body"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := &manifest.Manifest{Version: "v1"}
	sum := sha256.Sum256([]byte("v1 body"))
	old.Files = append(old.Files, manifest.File{
		Path: "skills/a/SKILL.md", SHA256: hex.EncodeToString(sum[:]), Size: 7,
	})
	if err := old.Save(filepath.Join(local, "manifest.json")); err != nil {
		t.Fatal(err)
	}
	if stdout, _, err := executeRoot(t, "update",
		"--path", local,
		"--source", src,
		"--public-key", pubPath,
	); err != nil {
		t.Fatalf("update failed: %v\n%s", err, stdout)
	}
	got, _ := os.ReadFile(filepath.Join(local, "skills/a/SKILL.md"))
	if string(got) != "v2 body" {
		t.Errorf("file not updated: %q", got)
	}

	if _, _, err := executeRoot(t, "update", "--path", local, "--rollback"); err != nil {
		t.Fatalf("rollback failed: %v", err)
	}
	got, _ = os.ReadFile(filepath.Join(local, "skills/a/SKILL.md"))
	if string(got) != "v1 body" {
		t.Errorf("rollback did not restore v1: %q", got)
	}
}

func TestManifestSubcommandsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "skills/a"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "skills/a/SKILL.md"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	m := &manifest.Manifest{SchemaVersion: "1.0", Version: "rt", ReleasedAt: "2026-05-12T00:00:00Z"}
	if err := m.Save(filepath.Join(dir, "manifest.json")); err != nil {
		t.Fatal(err)
	}
	// compute --write
	if _, _, err := executeRoot(t, "manifest", "compute", "--path", dir, "--write"); err != nil {
		t.Fatalf("manifest compute: %v", err)
	}
	loaded, err := manifest.Load(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	entry := loaded.FileByPath("skills/a/SKILL.md")
	if entry == nil || entry.SHA256 == "" {
		t.Fatalf("compute did not populate checksum: %+v", loaded)
	}

	// Sign with a generated key, then verify.
	pub, priv, err := manifest.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "priv.bin")
	if err := os.WriteFile(keyPath, priv, 0o600); err != nil {
		t.Fatal(err)
	}
	pubPath := filepath.Join(dir, "pub.bin")
	if err := os.WriteFile(pubPath, pub, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := executeRoot(t, "manifest", "sign", "--path", dir, "--key", keyPath); err != nil {
		t.Fatalf("manifest sign: %v", err)
	}
	if _, _, err := executeRoot(t, "manifest", "verify", "--path", dir, "--public-key", pubPath); err != nil {
		t.Fatalf("manifest verify: %v", err)
	}
}

// TestManifestVerifyUnsignedPolicy locks in the post-PR-#11 contract
// for the local verify CLI: an unsigned (or placeholder-signature)
// manifest must be rejected unless the caller passes --checksums-only,
// mirroring the updater's --skip-signature semantics. See review flag
// "Manifest verify CLI uses different signature-skip logic than updater".
func TestManifestVerifyUnsignedPolicy(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "skills/a"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "skills/a/SKILL.md"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	m := &manifest.Manifest{SchemaVersion: "1.0", Version: "rt", ReleasedAt: "2026-05-12T00:00:00Z"}
	if err := m.Save(filepath.Join(dir, "manifest.json")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := executeRoot(t, "manifest", "compute", "--path", dir, "--write"); err != nil {
		t.Fatalf("manifest compute: %v", err)
	}

	// No flag and no signature: must refuse.
	if _, _, err := executeRoot(t, "manifest", "verify", "--path", dir); err == nil {
		t.Fatalf("manifest verify on unsigned manifest without --checksums-only should error")
	}

	// --checksums-only acknowledges the bypass and succeeds.
	stdout, _, err := executeRoot(t, "manifest", "verify", "--path", dir, "--checksums-only")
	if err != nil {
		t.Fatalf("manifest verify --checksums-only: %v\n%s", err, stdout)
	}
	if !strings.Contains(stdout, "signature: skipped") {
		t.Errorf("expected 'signature: skipped' in output, got:\n%s", stdout)
	}
}

// TestRegenerateAfterUpdateRespectsFullInline locks in the PR #15
// review-flag fix that `update --regenerate` was silently switching
// AGENTS.md to the minimal pointer file with no way to opt back into
// the legacy monolithic output. Asserts the boolean is plumbed through:
//
//  1. fullInline=false yields the minimal renderer's signature header
//     (`AGENTS.md — SecureVibe skills (minimal)`).
//  2. fullInline=true yields the legacy renderer's signature header
//     (`Skills Library — AGENTS.md (Codex / OpenAI agents)`).
//
// We don't compare sizes because, with no fixtures on disk and a
// single tiny skill, the legacy output is actually smaller than the
// minimal pointer file's static boilerplate. Header-string identity
// is what we care about: a regression that drops the flag would
// silently fall back to the minimal renderer.
func TestRegenerateAfterUpdateRespectsFullInline(t *testing.T) {
	root := t.TempDir()
	skillDir := filepath.Join(root, "skills", "demo")
	if err := os.MkdirAll(skillDir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := `---
id: demo
version: "1.0.0"
title: "Demo Skill"
description: "Single-purpose skill used only by update_test.go."
category: prevention
severity: low
applies_to:
  - "when writing test fixtures"
languages: ["*"]
token_budget:
  minimal: 100
  compact: 200
  full: 400
last_updated: "2026-05-14"
sources:
  - "internal test fixture"
---

# Demo Skill

Tiny body sufficient to exercise the regenerate pipeline.
`
	if err := os.WriteFile(filepath.Join(skillDir, "SKILL.md"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	var buf strings.Builder
	w := writeFunc(func(p []byte) (int, error) { return buf.Write(p) })

	// First run: minimal (default).
	if err := regenerateAfterUpdate(root, w, false); err != nil {
		t.Fatalf("regenerateAfterUpdate(false): %v\n%s", err, buf.String())
	}
	agentsPath := filepath.Join(root, "dist", "AGENTS.md")
	minimal, err := os.ReadFile(agentsPath)
	if err != nil {
		t.Fatalf("read minimal AGENTS.md: %v", err)
	}
	if !strings.Contains(string(minimal), "AGENTS.md \u2014 SecureVibe skills (minimal)") {
		t.Errorf("minimal output missing minimal-renderer header; got:\n%s", minimal)
	}

	// Second run: full-inline. Resulting AGENTS.md must come from
	// renderAgentsFullInline, proving the flag was propagated through.
	if err := regenerateAfterUpdate(root, w, true); err != nil {
		t.Fatalf("regenerateAfterUpdate(true): %v\n%s", err, buf.String())
	}
	full, err := os.ReadFile(agentsPath)
	if err != nil {
		t.Fatalf("read full AGENTS.md: %v", err)
	}
	if !strings.Contains(string(full), "Skills Library \u2014 AGENTS.md (Codex / OpenAI agents)") {
		t.Errorf("full-inline output missing legacy-renderer header; got:\n%s", full)
	}
	if strings.Contains(string(full), "AGENTS.md \u2014 SecureVibe skills (minimal)") {
		t.Errorf("full-inline output should not carry the minimal-renderer header; got:\n%s", full)
	}
}

// writeFunc adapts a plain func to the io.Writer-shaped interface
// regenerateAfterUpdate expects. We can't import io here without
// pulling in a wider dependency surface for this one test.
type writeFunc func(p []byte) (int, error)

func (f writeFunc) Write(p []byte) (int, error) { return f(p) }

func TestSchedulerPreviewOutputs(t *testing.T) {
	stdout, _, err := executeRoot(t, "scheduler", "preview", "--target", "darwin", "--binary", "/usr/local/bin/secure-vibe")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "com.secure-vibe.update") {
		t.Errorf("darwin preview missing label: %s", stdout)
	}
	stdout, _, err = executeRoot(t, "scheduler", "preview", "--target", "linux", "--binary", "/usr/local/bin/secure-vibe")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "OnBootSec=5min") {
		t.Errorf("linux preview missing timer config: %s", stdout)
	}
	stdout, _, err = executeRoot(t, "scheduler", "preview", "--target", "windows", "--binary", "C:/secure-vibe.exe")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "<Interval>PT6H</Interval>") {
		t.Errorf("windows preview missing repetition: %s", stdout)
	}
}
