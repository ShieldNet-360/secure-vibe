package manifest

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteFileAtomicCreatesAndOverwrites(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "file.txt")

	if err := WriteFileAtomic(path, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello" {
		t.Errorf("got %q", got)
	}
	if err := WriteFileAtomic(path, []byte("world"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "world" {
		t.Errorf("got %q after overwrite", got)
	}

	// No leftover .tmp files.
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".tmp-") {
			t.Errorf("leftover temp file: %s", e.Name())
		}
	}
}

func TestComputeChecksumsHashesAllFiles(t *testing.T) {
	dir := t.TempDir()
	mustWrite := func(rel, body string) {
		full := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite("skills/a/SKILL.md", "alpha-content")
	mustWrite("skills/a/rules/r.json", "{}")
	mustWrite("vulnerabilities/x.json", `{"k": 1}`)
	mustWrite("dictionaries/y.yaml", "k: 1\n")
	mustWrite("dist/CLAUDE.md", "compiled")
	mustWrite("ignored/skip.txt", "should not be hashed")

	m := &Manifest{
		SchemaVersion: "1.0",
		Version:       "test",
		ReleasedAt:    "2026-05-12T00:00:00Z",
	}
	if err := m.ComputeChecksums(dir); err != nil {
		t.Fatal(err)
	}

	wanted := map[string]string{
		"skills/a/SKILL.md":      sha256Hex("alpha-content"),
		"skills/a/rules/r.json":  sha256Hex("{}"),
		"vulnerabilities/x.json": sha256Hex(`{"k": 1}`),
		"dictionaries/y.yaml":    sha256Hex("k: 1\n"),
		"dist/CLAUDE.md":         sha256Hex("compiled"),
	}
	for path, hash := range wanted {
		entry := m.FileByPath(path)
		if entry == nil {
			t.Errorf("expected %s in manifest", path)
			continue
		}
		if entry.SHA256 != hash {
			t.Errorf("%s sha256 mismatch: got %s want %s", path, entry.SHA256, hash)
		}
		if entry.Size <= 0 {
			t.Errorf("%s size %d should be positive", path, entry.Size)
		}
	}
	if got := m.FileByPath("ignored/skip.txt"); got != nil {
		t.Errorf("ignored file should not be in manifest")
	}
	// Files list must be sorted.
	for i := 1; i < len(m.Files); i++ {
		if m.Files[i-1].Path > m.Files[i].Path {
			t.Errorf("files not sorted at index %d: %q > %q", i, m.Files[i-1].Path, m.Files[i].Path)
		}
	}
}

func TestComputeChecksumsPreservesAndUpdatesExistingEntries(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "skills/a"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "skills/a/SKILL.md"), []byte("v1"), 0o644); err != nil {
		t.Fatal(err)
	}

	m := &Manifest{
		Version: "test",
		Files: []File{
			{Path: "skills/a/SKILL.md", SHA256: "TBD", Size: 0, Action: "added"},
		},
	}
	if err := m.ComputeChecksums(dir); err != nil {
		t.Fatal(err)
	}
	entry := m.FileByPath("skills/a/SKILL.md")
	if entry.SHA256 != sha256Hex("v1") {
		t.Errorf("checksum not updated: %s", entry.SHA256)
	}
	if entry.Action == "added" {
		t.Errorf("action should be promoted past 'added'")
	}
}

func TestSignAndVerifyRoundTrip(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	m := &Manifest{
		SchemaVersion: "1.0",
		Version:       "rt",
		ReleasedAt:    "2026-05-12T00:00:00Z",
		PublicKeyID:   "test-key",
		Files: []File{
			{Path: "b.json", SHA256: "deadbeef", Size: 4},
			{Path: "a.json", SHA256: "feedface", Size: 8},
		},
	}
	if err := m.SignWith(priv); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(m.Signature, SignaturePrefix) {
		t.Errorf("signature missing prefix: %q", m.Signature)
	}
	if err := m.VerifyWith(pub); err != nil {
		t.Fatalf("verify after sign should pass: %v", err)
	}

	// Tampering with any field invalidates the signature.
	m.Version = "tampered"
	if err := m.VerifyWith(pub); err == nil {
		t.Errorf("tampered manifest should fail verification")
	}
}

func TestVerifyRejectsUnsignedAndMissingPrefix(t *testing.T) {
	pub, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	m := &Manifest{Version: "x"}
	if err := m.VerifyWith(pub); err == nil {
		t.Errorf("empty signature must fail verification")
	}
	m.Signature = PlaceholderSignature
	if err := m.VerifyWith(pub); err == nil {
		t.Errorf("TBD signature must fail verification")
	}
	m.Signature = "rsa:foo"
	if err := m.VerifyWith(pub); err == nil {
		t.Errorf("non-ed25519 prefix must fail verification")
	}
}

func TestCanonicalSigningBytesIsStable(t *testing.T) {
	m := &Manifest{
		SchemaVersion: "1.0",
		Version:       "rt",
		ReleasedAt:    "2026-05-12T00:00:00Z",
		Files: []File{
			{Path: "b.json", SHA256: "x", Size: 1},
			{Path: "a.json", SHA256: "y", Size: 1},
		},
	}
	a, err := m.CanonicalSigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	b, err := m.CanonicalSigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Errorf("canonical encoding not stable across calls")
	}

	var got map[string]any
	if err := json.Unmarshal(a, &got); err != nil {
		t.Fatal(err)
	}
	if _, exists := got["signature"]; exists {
		t.Errorf("signature must be stripped from canonical bytes")
	}
}

func TestComputeDeltaIdentifiesAddedUpdatedRemoved(t *testing.T) {
	from := &Manifest{
		Version: "v1",
		Files: []File{
			{Path: "kept.txt", SHA256: "a", Size: 1},
			{Path: "changed.txt", SHA256: "b", Size: 2},
			{Path: "gone.txt", SHA256: "c", Size: 3},
		},
	}
	to := &Manifest{
		Version: "v2",
		Files: []File{
			{Path: "kept.txt", SHA256: "a", Size: 1},
			{Path: "changed.txt", SHA256: "bb", Size: 4},
			{Path: "new.txt", SHA256: "d", Size: 5},
		},
	}
	d := ComputeDelta(from, to)
	if d.FromVersion != "v1" || d.ToVersion != "v2" {
		t.Errorf("delta versions: %+v", d)
	}
	actions := map[string]string{}
	for _, e := range d.Entries {
		actions[e.Path] = e.Action
	}
	if actions["new.txt"] != "added" {
		t.Errorf("expected new.txt added, got %q", actions["new.txt"])
	}
	if actions["changed.txt"] != "updated" {
		t.Errorf("expected changed.txt updated, got %q", actions["changed.txt"])
	}
	if actions["gone.txt"] != "removed" {
		t.Errorf("expected gone.txt removed, got %q", actions["gone.txt"])
	}
	if _, ok := actions["kept.txt"]; ok {
		t.Errorf("unchanged file should not be in delta")
	}
}

func TestWriteDeltaFileIsAtomic(t *testing.T) {
	dir := t.TempDir()
	d := &Delta{
		SchemaVersion: "1.0",
		FromVersion:   "v1",
		ToVersion:     "v2",
		Entries: []DeltaEntry{
			{Path: "a.txt", Action: "added", ToSHA256: "x", ToSize: 1},
		},
	}
	path, err := WriteDeltaFile(d, dir)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(path) != "v1-to-v2.json" {
		t.Errorf("delta filename: %s", path)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var roundtrip Delta
	if err := json.Unmarshal(body, &roundtrip); err != nil {
		t.Fatal(err)
	}
	if len(roundtrip.Entries) != 1 || roundtrip.Entries[0].Path != "a.txt" {
		t.Errorf("delta roundtrip mismatch: %+v", roundtrip)
	}
}

func TestPrivateKeyRoundTripFromSeed(t *testing.T) {
	_, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "key.bin")
	if err := os.WriteFile(path, priv, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadPrivateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(loaded) != string(priv) {
		t.Errorf("private key roundtrip mismatch")
	}
}

func TestPrivateKeyRoundTripFromPKCS8PEM(t *testing.T) {
	_, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	dir := t.TempDir()
	path := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadPrivateKey(path)
	if err != nil {
		t.Fatalf("LoadPrivateKey: %v", err)
	}
	if string(loaded) != string(priv) {
		t.Errorf("PKCS#8 PEM private key roundtrip mismatch")
	}
}

func TestPublicKeyRoundTripFromSPKIPEM(t *testing.T) {
	pub, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	block := &pem.Block{Type: "PUBLIC KEY", Bytes: der}
	dir := t.TempDir()
	path := filepath.Join(dir, "pub.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadPublicKey(path)
	if err != nil {
		t.Fatalf("LoadPublicKey: %v", err)
	}
	if string(loaded) != string(pub) {
		t.Errorf("SPKI PEM public key roundtrip mismatch")
	}
}

func TestSignAndVerifyWithSPKIPublicKey(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "pub.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadPublicKey(path)
	if err != nil {
		t.Fatalf("LoadPublicKey: %v", err)
	}
	m := &Manifest{SchemaVersion: "1.0", Version: "v1"}
	if err := m.SignWith(priv); err != nil {
		t.Fatalf("SignWith: %v", err)
	}
	if err := m.VerifyWith(loaded); err != nil {
		t.Errorf("VerifyWith using SPKI-loaded key failed: %v", err)
	}
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
