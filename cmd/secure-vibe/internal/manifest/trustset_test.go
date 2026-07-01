package manifest

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
)

func TestVerifyAnyAcceptsAnyOfMultipleTrustedKeys(t *testing.T) {
	_, priv1, _ := GenerateKeyPair()
	pub2, _, _ := GenerateKeyPair()
	pub3, _, _ := GenerateKeyPair()

	m := &Manifest{
		SchemaVersion: "1.0",
		Version:       "1",
		ReleasedAt:    "2026-05-13T00:00:00Z",
		PublicKeyID:   "test",
		Files: []File{
			{Path: "skills/x/SKILL.md", SHA256: "deadbeef", Size: 7},
		},
	}
	if err := m.SignWith(priv1); err != nil {
		t.Fatal(err)
	}

	// Signed by priv1 but pub1 is in the middle of the trusted set.
	pub1 := priv1.Public().(ed25519.PublicKey)
	keys := []ed25519.PublicKey{pub2, pub1, pub3}
	pub, idx, err := m.VerifyAny(keys)
	if err != nil {
		t.Fatalf("VerifyAny: %v", err)
	}
	if idx != 1 {
		t.Errorf("expected idx=1, got %d", idx)
	}
	if string(pub) != string(pub1) {
		t.Errorf("returned key did not match pub1")
	}

	// Now strip pub1 and confirm it fails.
	pub, idx, err = m.VerifyAny([]ed25519.PublicKey{pub2, pub3})
	if err == nil {
		t.Errorf("expected error when signature key not in trust set; got idx=%d pub=%v", idx, pub)
	}
	if _, _, err := m.VerifyAny(nil); err == nil {
		t.Error("expected error for empty trust set")
	}
}

func TestLoadAdditionalPublicKeysReadsAndSkipsBlanks(t *testing.T) {
	tmp := t.TempDir()
	pub, _, _ := GenerateKeyPair()
	keyPath := filepath.Join(tmp, "k1.pub")
	if err := os.WriteFile(keyPath, []byte(EncodePublicKey(pub)), 0o600); err != nil {
		t.Fatal(err)
	}

	keys, err := LoadAdditionalPublicKeys([]string{"", keyPath, ""})
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
	if string(keys[0]) != string(pub) {
		t.Errorf("loaded key mismatch")
	}
}

func TestTrustedKeysReturnsErrorOnMalformedEmbeddedKey(t *testing.T) {
	saved := EmbeddedPublicKey
	t.Cleanup(func() { EmbeddedPublicKey = saved })
	EmbeddedPublicKey = "not-a-valid-base64-ed25519-key"
	if _, err := TrustedKeys(nil); err == nil {
		t.Fatal("expected TrustedKeys to return an error for a malformed embedded key")
	}
}

func TestTrustedKeysPrependsEmbedded(t *testing.T) {
	saved := EmbeddedPublicKey
	t.Cleanup(func() { EmbeddedPublicKey = saved })

	pub1, _, _ := GenerateKeyPair()
	pub2, _, _ := GenerateKeyPair()
	EmbeddedPublicKey = EncodePublicKey(pub1)

	tmp := t.TempDir()
	keyPath := filepath.Join(tmp, "k2.pub")
	_ = os.WriteFile(keyPath, []byte(EncodePublicKey(pub2)), 0o600)

	keys, err := TrustedKeys([]string{keyPath})
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(keys))
	}
	if string(keys[0]) != string(pub1) {
		t.Errorf("first key should be embedded")
	}
	if string(keys[1]) != string(pub2) {
		t.Errorf("second key should be loaded one")
	}
}
