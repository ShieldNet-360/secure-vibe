package manifest

import (
	"crypto/ed25519"
	"testing"
)

func TestSignVerifyDetachedRoundTrip(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("abc123  secure-vibe-linux-amd64\ndef456  secure-vibe-mcp-linux-amd64\n")
	sig, err := SignDetached(priv, data)
	if err != nil {
		t.Fatalf("SignDetached: %v", err)
	}
	if err := VerifyDetached(pub, data, sig); err != nil {
		t.Errorf("VerifyDetached on valid sig: %v", err)
	}
}

func TestVerifyDetachedRejectsTamperedData(t *testing.T) {
	pub, priv, _ := GenerateKeyPair()
	sig, _ := SignDetached(priv, []byte("the real bytes"))
	if err := VerifyDetached(pub, []byte("different bytes"), sig); err == nil {
		t.Error("expected failure verifying tampered data; got nil")
	}
}

func TestVerifyDetachedRejectsWrongKey(t *testing.T) {
	_, priv, _ := GenerateKeyPair()
	otherPub, _, _ := GenerateKeyPair()
	data := []byte("payload")
	sig, _ := SignDetached(priv, data)
	if err := VerifyDetached(otherPub, data, sig); err == nil {
		t.Error("expected failure verifying with the wrong public key; got nil")
	}
}

func TestVerifyDetachedAnyMatchesOneOfManyKeys(t *testing.T) {
	pub1, _, _ := GenerateKeyPair()
	pub2, priv2, _ := GenerateKeyPair()
	data := []byte("signed by key2")
	sig, _ := SignDetached(priv2, data)
	// Trust set holds an unrelated key plus the real signer.
	keys := []ed25519.PublicKey{pub1, pub2}
	if err := VerifyDetachedAny(keys, data, sig); err != nil {
		t.Errorf("VerifyDetachedAny should accept a sig from any trusted key: %v", err)
	}
}

func TestVerifyDetachedAnyEmptyKeysFails(t *testing.T) {
	_, priv, _ := GenerateKeyPair()
	sig, _ := SignDetached(priv, []byte("x"))
	if err := VerifyDetachedAny(nil, []byte("x"), sig); err == nil {
		t.Error("expected failure with no trusted keys; got nil")
	}
}

func TestVerifyDetachedRejectsMalformedSignature(t *testing.T) {
	pub, _, _ := GenerateKeyPair()
	for _, bad := range []string{"", "no-prefix", "ed25519:not-base64!!", "ed25519:YWJj"} {
		if err := VerifyDetached(pub, []byte("x"), bad); err == nil {
			t.Errorf("expected failure for malformed signature %q; got nil", bad)
		}
	}
}
