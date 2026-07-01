package cmd

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shieldnet-360/secure-vibe/cmd/secure-vibe/internal/manifest"
)

// TestManifestSignVerifyFileRoundTrip exercises the offline release-signing
// path end to end through the CLI: `manifest sign-file` writes <file>.sig with
// a private key, `manifest verify-file` confirms it with the public key.
func TestManifestSignVerifyFileRoundTrip(t *testing.T) {
	pub, priv, err := manifest.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "key.b64")
	pubFile := filepath.Join(dir, "pub.b64")
	dataFile := filepath.Join(dir, "checksums-linux-amd64.txt")
	if err := os.WriteFile(keyFile, []byte(base64.StdEncoding.EncodeToString(priv)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pubFile, []byte(manifest.EncodePublicKey(pub)), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dataFile, []byte("abc123  secure-vibe-linux-amd64\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, _, err := executeRoot(t, "manifest", "sign-file", "--key", keyFile, dataFile); err != nil {
		t.Fatalf("sign-file: %v", err)
	}
	if _, err := os.Stat(dataFile + ".sig"); err != nil {
		t.Fatalf("expected %s.sig to be written: %v", dataFile, err)
	}

	stdout, _, err := executeRoot(t, "manifest", "verify-file", "--public-key", pubFile, dataFile)
	if err != nil {
		t.Fatalf("verify-file: %v", err)
	}
	if !strings.Contains(stdout, "signature: ok") {
		t.Errorf("verify-file output = %q, want 'signature: ok'", stdout)
	}
}

// TestManifestVerifyFileRejectsTamper confirms verify-file fails when the
// signed file's bytes change after signing.
func TestManifestVerifyFileRejectsTamper(t *testing.T) {
	pub, priv, err := manifest.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "key.b64")
	pubFile := filepath.Join(dir, "pub.b64")
	dataFile := filepath.Join(dir, "checksums.txt")
	_ = os.WriteFile(keyFile, []byte(base64.StdEncoding.EncodeToString(priv)), 0o600)
	_ = os.WriteFile(pubFile, []byte(manifest.EncodePublicKey(pub)), 0o644)
	_ = os.WriteFile(dataFile, []byte("original\n"), 0o644)

	if _, _, err := executeRoot(t, "manifest", "sign-file", "--key", keyFile, dataFile); err != nil {
		t.Fatalf("sign-file: %v", err)
	}
	// Tamper with the signed file.
	if err := os.WriteFile(dataFile, []byte("tampered\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := executeRoot(t, "manifest", "verify-file", "--public-key", pubFile, dataFile); err == nil {
		t.Fatal("expected verify-file to fail on tampered content; got nil")
	}
}
