package cmd

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/shieldnet-360/secure-vibe/cmd/secure-vibe/internal/manifest"
)

// checksumLine reproduces the exact bytes the fake release server emits for the
// checksum file, so a test can sign those bytes and serve a matching .sig.
func checksumLine(payload []byte) (binaryName, line string) {
	binaryName = fmt.Sprintf("secure-vibe-%s-%s", runtime.GOOS, runtime.GOARCH)
	if runtime.GOOS == "windows" {
		binaryName += ".exe"
	}
	sum := sha256.Sum256(payload)
	return binaryName, fmt.Sprintf("%s  %s\n", hex.EncodeToString(sum[:]), binaryName)
}

// withEmbeddedKey sets manifest.EmbeddedPublicKey for the duration of a test
// (the self-update signature path verifies against it) and restores it after.
func withEmbeddedKey(t *testing.T, b64 string) {
	t.Helper()
	prev := manifest.EmbeddedPublicKey
	manifest.EmbeddedPublicKey = b64
	t.Cleanup(func() { manifest.EmbeddedPublicKey = prev })
}

func TestSelfUpdateVerifiesSignature(t *testing.T) {
	payload := []byte("#!/bin/sh\necho signed binary\n")
	checksumName := fmt.Sprintf("checksums-%s-%s.txt", runtime.GOOS, runtime.GOARCH)
	_, sumLine := checksumLine(payload)

	pub, priv, err := manifest.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := manifest.SignDetached(priv, []byte(sumLine))
	if err != nil {
		t.Fatal(err)
	}
	withEmbeddedKey(t, manifest.EncodePublicKey(pub))

	alter := func(name string) (string, bool) {
		if name == checksumName+".sig" {
			return sig + "\n", true
		}
		return "", false
	}
	srv, _, _ := newFakeReleaseServer(t, payload, alter)

	tmp := filepath.Join(t.TempDir(), "secure-vibe")
	if err := os.WriteFile(tmp, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	out := &bytes.Buffer{}
	res, err := runSelfUpdate(out, srv.URL, runtime.GOOS, runtime.GOARCH, tmp, false, true)
	if err != nil {
		t.Fatalf("self-update with valid signature: %v\n%s", err, out.String())
	}
	if !res.SignatureVerified {
		t.Errorf("expected SignatureVerified=true; output=%s", out.String())
	}
}

func TestSelfUpdateRejectsBadSignature(t *testing.T) {
	payload := []byte("a signed-but-tampered binary")
	checksumName := fmt.Sprintf("checksums-%s-%s.txt", runtime.GOOS, runtime.GOARCH)

	// Sign DIFFERENT bytes than the served checksum file → signature won't match.
	pub, priv, err := manifest.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	badSig, err := manifest.SignDetached(priv, []byte("not the real checksum file"))
	if err != nil {
		t.Fatal(err)
	}
	withEmbeddedKey(t, manifest.EncodePublicKey(pub))

	alter := func(name string) (string, bool) {
		if name == checksumName+".sig" {
			return badSig + "\n", true
		}
		return "", false
	}
	srv, _, _ := newFakeReleaseServer(t, payload, alter)

	tmp := filepath.Join(t.TempDir(), "secure-vibe")
	if err := os.WriteFile(tmp, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	out := &bytes.Buffer{}
	if _, err := runSelfUpdate(out, srv.URL, runtime.GOOS, runtime.GOARCH, tmp, false, false); err == nil {
		t.Fatalf("expected error on bad signature; got nil. output=%s", out.String())
	}
	if body, _ := os.ReadFile(tmp); string(body) != "old" {
		t.Errorf("binary must not be replaced on signature failure; got %q", string(body))
	}
}

func TestSelfUpdateRequireSignatureFailsWhenAbsent(t *testing.T) {
	payload := []byte("an unsigned release")
	srv, _, _ := newFakeReleaseServer(t, payload, nil) // no .sig served

	tmp := filepath.Join(t.TempDir(), "secure-vibe")
	if err := os.WriteFile(tmp, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	out := &bytes.Buffer{}
	if _, err := runSelfUpdate(out, srv.URL, runtime.GOOS, runtime.GOARCH, tmp, false, true); err == nil {
		t.Fatalf("expected error when --require-signature and no .sig; got nil. output=%s", out.String())
	}
}

func TestSelfUpdateWarnsButSucceedsWhenUnsigned(t *testing.T) {
	payload := []byte("an unsigned release that should still update by default")
	srv, _, _ := newFakeReleaseServer(t, payload, nil) // no .sig served

	tmp := filepath.Join(t.TempDir(), "secure-vibe")
	if err := os.WriteFile(tmp, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	out := &bytes.Buffer{}
	res, err := runSelfUpdate(out, srv.URL, runtime.GOOS, runtime.GOARCH, tmp, false, false)
	if err != nil {
		t.Fatalf("default (non-strict) unsigned update should succeed: %v\n%s", err, out.String())
	}
	if res.SignatureVerified {
		t.Errorf("SignatureVerified must be false for an unsigned release")
	}
	if !strings.Contains(out.String(), "not Ed25519-signed") {
		t.Errorf("expected a fallback warning; output=%s", out.String())
	}
}

// newFakeReleaseServer stands up a httptest.Server that mimics GitHub
// Releases: it serves a fixed binary plus the matching SHA-256 checksum
// file for the current GOOS/GOARCH at the same paths the real CLI hits.
func newFakeReleaseServer(t *testing.T, binary []byte, alter func(name string) (string, bool)) (*httptest.Server, string, string) {
	t.Helper()
	binaryName := fmt.Sprintf("secure-vibe-%s-%s", runtime.GOOS, runtime.GOARCH)
	if runtime.GOOS == "windows" {
		binaryName += ".exe"
	}
	checksumName := fmt.Sprintf("checksums-%s-%s.txt", runtime.GOOS, runtime.GOARCH)

	sum := sha256.Sum256(binary)
	hexsum := hex.EncodeToString(sum[:])
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/")
		body, replaced := "", false
		if alter != nil {
			body, replaced = alter(name)
		}
		switch {
		case name == binaryName && !replaced:
			w.Write(binary)
		case name == checksumName && !replaced:
			fmt.Fprintf(w, "%s  %s\n", hexsum, binaryName)
		case replaced:
			fmt.Fprint(w, body)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, binaryName, hexsum
}

func TestSelfUpdateVerifiesChecksum(t *testing.T) {
	payload := []byte("#!/bin/sh\necho fake binary\n")
	srv, _, want := newFakeReleaseServer(t, payload, nil)

	tmp := filepath.Join(t.TempDir(), "secure-vibe")
	if err := os.WriteFile(tmp, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	out := &bytes.Buffer{}
	res, err := runSelfUpdate(out, srv.URL, runtime.GOOS, runtime.GOARCH, tmp, false, false)
	if err != nil {
		t.Fatalf("self-update: %v\n%s", err, out.String())
	}
	if res.SHA256 != want {
		t.Errorf("checksum=%q, want %q", res.SHA256, want)
	}
	got, err := os.ReadFile(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("binary not replaced")
	}
}

func TestSelfUpdateDetectsChecksumMismatch(t *testing.T) {
	payload := []byte("a fresh binary")
	checksumName := fmt.Sprintf("checksums-%s-%s.txt", runtime.GOOS, runtime.GOARCH)
	alter := func(name string) (string, bool) {
		if name == checksumName {
			return "deadbeef  secure-vibe-tampered\n", true
		}
		return "", false
	}
	srv, _, _ := newFakeReleaseServer(t, payload, alter)

	tmp := filepath.Join(t.TempDir(), "secure-vibe")
	if err := os.WriteFile(tmp, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	out := &bytes.Buffer{}
	if _, err := runSelfUpdate(out, srv.URL, runtime.GOOS, runtime.GOARCH, tmp, false, false); err == nil {
		t.Fatalf("expected error on missing checksum entry; got nil. output=%s", out.String())
	}
	body, _ := os.ReadFile(tmp)
	if string(body) != "old" {
		t.Errorf("binary should not have been replaced on checksum failure; got %q", string(body))
	}
}

func TestSelfUpdateDryRunDoesNotWrite(t *testing.T) {
	payload := []byte("new binary")
	srv, _, _ := newFakeReleaseServer(t, payload, nil)

	tmp := filepath.Join(t.TempDir(), "secure-vibe")
	if err := os.WriteFile(tmp, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	out := &bytes.Buffer{}
	if _, err := runSelfUpdate(out, srv.URL, runtime.GOOS, runtime.GOARCH, tmp, true, false); err != nil {
		t.Fatalf("dry-run: %v", err)
	}
	body, _ := os.ReadFile(tmp)
	if string(body) != "old" {
		t.Errorf("dry-run must not replace the binary; got %q", string(body))
	}
}

func TestLookupChecksumIgnoresStarPrefix(t *testing.T) {
	r := strings.NewReader("abc123  *secure-vibe-linux-amd64\ndef456  secure-vibe-windows-amd64.exe\n")
	got, err := lookupChecksum(r, "secure-vibe-linux-amd64")
	if err != nil {
		t.Fatal(err)
	}
	if got != "abc123" {
		t.Errorf("got=%q", got)
	}
}
