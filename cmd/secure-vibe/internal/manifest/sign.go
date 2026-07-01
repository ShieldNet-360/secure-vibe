package manifest

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
)

// EmbeddedPublicKey is the base64-encoded Ed25519 public key the CLI uses to
// verify manifests when no key is supplied explicitly. The build system can
// override it via:
//
//	go build -ldflags "-X github.com/.../manifest.EmbeddedPublicKey=<b64>"
//
// When left empty (the development default), VerifyManifest still works as
// long as the caller passes an explicit public key.
var EmbeddedPublicKey = ""

// EmbeddedPublicKeyID is the human-friendly key ID baked into the binary at
// build time. It is reported by `secure-vibe version` so operators can tell
// which signing key the binary trusts.
var EmbeddedPublicKeyID = ""

// CanonicalSigningBytes returns the deterministic JSON encoding of the
// manifest with the "signature" field stripped. Signing and verification both
// hash exactly these bytes, so they must be byte-stable across runs.
//
// Implementation: marshal the manifest, decode into a generic map, drop the
// "signature" key, sort file entries, then re-marshal with the compact
// json.Marshal form. Go's json.Marshal sorts object keys alphabetically for
// map[string]any, so the encoding is canonical.
func (m *Manifest) CanonicalSigningBytes() ([]byte, error) {
	dup := m.Clone()
	dup.SortFiles()
	dup.Signature = ""
	raw, err := json.Marshal(dup)
	if err != nil {
		return nil, err
	}
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		return nil, err
	}
	delete(generic, "signature")
	return json.Marshal(generic)
}

// SignManifest signs the manifest in-place using the Ed25519 private key
// found at privateKeyPath. The file may hold a 64-byte raw seed, a 64-byte
// raw private key, a base64-encoded variant of either, or a PEM block with
// type "PRIVATE KEY" or "ED25519 PRIVATE KEY".
//
// The resulting signature is stored as "ed25519:<base64>". The public key id
// is left intact so the operator can configure it explicitly.
func (m *Manifest) SignManifest(privateKeyPath string) error {
	priv, err := LoadPrivateKey(privateKeyPath)
	if err != nil {
		return err
	}
	return m.SignWith(priv)
}

// SignWith signs the manifest with an in-memory Ed25519 private key.
func (m *Manifest) SignWith(priv ed25519.PrivateKey) error {
	if len(priv) != ed25519.PrivateKeySize {
		return fmt.Errorf("ed25519 private key must be %d bytes, got %d", ed25519.PrivateKeySize, len(priv))
	}
	canon, err := m.CanonicalSigningBytes()
	if err != nil {
		return err
	}
	sig := ed25519.Sign(priv, canon)
	m.Signature = SignaturePrefix + base64.StdEncoding.EncodeToString(sig)
	return nil
}

// VerifyManifest verifies the manifest's signature against the embedded
// public key. If EmbeddedPublicKey is unset, an error is returned; callers
// that want to provide a key explicitly should use VerifyWith.
func (m *Manifest) VerifyManifest() error {
	pub, err := embeddedPublicKey()
	if err != nil {
		return err
	}
	return m.VerifyWith(pub)
}

// VerifyAny verifies the manifest's signature against any of the provided
// trusted Ed25519 public keys. The first key that successfully verifies the
// signature wins and that public key (and its index) is returned. This is
// the entry point used by private-repo deployments that trust the embedded
// upstream key plus one or more additional org-managed keys.
func (m *Manifest) VerifyAny(keys []ed25519.PublicKey) (ed25519.PublicKey, int, error) {
	if len(keys) == 0 {
		return nil, -1, errors.New("no trusted keys configured")
	}
	for i, pub := range keys {
		if err := m.VerifyWith(pub); err == nil {
			return pub, i, nil
		}
	}
	return nil, -1, errors.New("manifest signature did not match any trusted key")
}

// LoadAdditionalPublicKeys reads zero or more Ed25519 public keys from the
// given file paths. Each path may carry a PEM, base64, or raw key (the same
// formats accepted by LoadPublicKey). Empty / blank paths are skipped so
// callers can stitch together "embedded + configured" key lists without
// branching.
func LoadAdditionalPublicKeys(paths []string) ([]ed25519.PublicKey, error) {
	out := make([]ed25519.PublicKey, 0, len(paths))
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		pub, err := LoadPublicKey(p)
		if err != nil {
			return nil, fmt.Errorf("load trusted key %s: %w", p, err)
		}
		out = append(out, pub)
	}
	return out, nil
}

// TrustedKeys returns the embedded key (if present) prepended to additional
// keys loaded from caller-supplied paths. Callers pass the result directly
// to VerifyAny.
func TrustedKeys(additionalPaths []string) ([]ed25519.PublicKey, error) {
	keys := make([]ed25519.PublicKey, 0, 1+len(additionalPaths))
	if EmbeddedPublicKey != "" {
		pub, err := embeddedPublicKey()
		if err != nil {
			return nil, fmt.Errorf("load embedded public key: %w", err)
		}
		keys = append(keys, pub)
	}
	extra, err := LoadAdditionalPublicKeys(additionalPaths)
	if err != nil {
		return nil, err
	}
	keys = append(keys, extra...)
	return keys, nil
}

// VerifyWith verifies the manifest's signature against the provided
// Ed25519 public key.
func (m *Manifest) VerifyWith(pub ed25519.PublicKey) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("ed25519 public key must be %d bytes, got %d", ed25519.PublicKeySize, len(pub))
	}
	if m.Signature == "" || m.Signature == PlaceholderSignature {
		return errors.New("manifest is unsigned")
	}
	if !strings.HasPrefix(m.Signature, SignaturePrefix) {
		return fmt.Errorf("manifest signature missing %q prefix", SignaturePrefix)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(m.Signature, SignaturePrefix))
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	if len(raw) != ed25519.SignatureSize {
		return fmt.Errorf("signature length %d != %d", len(raw), ed25519.SignatureSize)
	}
	canon, err := m.CanonicalSigningBytes()
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, canon, raw) {
		return errors.New("ed25519 signature verification failed")
	}
	return nil
}

// SignDetached signs arbitrary bytes with an Ed25519 private key and returns
// an "ed25519:<base64>" detached signature string. Used to sign release
// artifacts (e.g. the per-platform checksums file) out of band with the same
// key that signs the manifest, so the SHA-256 a self-update trusts is itself
// anchored to the release key rather than to whatever source served it.
func SignDetached(priv ed25519.PrivateKey, data []byte) (string, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("ed25519 private key must be %d bytes, got %d", ed25519.PrivateKeySize, len(priv))
	}
	sig := ed25519.Sign(priv, data)
	return SignaturePrefix + base64.StdEncoding.EncodeToString(sig), nil
}

// VerifyDetached verifies an "ed25519:<base64>" detached signature over data
// against a single public key.
func VerifyDetached(pub ed25519.PublicKey, data []byte, sig string) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("ed25519 public key must be %d bytes, got %d", ed25519.PublicKeySize, len(pub))
	}
	s := strings.TrimSpace(sig)
	if s == "" {
		return errors.New("empty signature")
	}
	if !strings.HasPrefix(s, SignaturePrefix) {
		return fmt.Errorf("signature missing %q prefix", SignaturePrefix)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(s, SignaturePrefix))
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	if len(raw) != ed25519.SignatureSize {
		return fmt.Errorf("signature length %d != %d", len(raw), ed25519.SignatureSize)
	}
	if !ed25519.Verify(pub, data, raw) {
		return errors.New("ed25519 signature verification failed")
	}
	return nil
}

// VerifyDetachedAny verifies a detached signature over data against any of the
// trusted Ed25519 public keys (embedded + configured). Mirrors
// (*Manifest).VerifyAny for non-manifest artifacts.
func VerifyDetachedAny(keys []ed25519.PublicKey, data []byte, sig string) error {
	if len(keys) == 0 {
		return errors.New("no trusted keys configured")
	}
	for _, pub := range keys {
		if err := VerifyDetached(pub, data, sig); err == nil {
			return nil
		}
	}
	return errors.New("signature did not match any trusted key")
}

// GenerateKeyPair produces a fresh Ed25519 keypair for development and tests.
func GenerateKeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// LoadPrivateKey reads an Ed25519 private key from disk. Supported formats:
//
//   - PEM block of type "PRIVATE KEY" (PKCS#8 ASN.1 envelope as produced by
//     `openssl genpkey -algorithm Ed25519`).
//   - PEM block of type "ED25519 PRIVATE KEY" — decoded body of 32 or 64 bytes.
//   - Base64-encoded raw key — 32 byte seed or 64 byte expanded key.
//   - Raw binary — 32 byte seed or 64 byte expanded key.
func LoadPrivateKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return parsePrivateKeyBytes(data)
}

func parsePrivateKeyBytes(data []byte) (ed25519.PrivateKey, error) {
	if block, _ := pem.Decode(data); block != nil {
		return privateKeyFromPEMBlock(block)
	}
	trimmed := strings.TrimSpace(string(data))
	if decoded, err := base64.StdEncoding.DecodeString(trimmed); err == nil {
		if priv, err := privateKeyFromRaw(decoded); err == nil {
			return priv, nil
		}
	}
	return privateKeyFromRaw(data)
}

// privateKeyFromPEMBlock decodes an Ed25519 private key from a PEM block.
// PEM blocks of type "PRIVATE KEY" are decoded as PKCS#8 (the standard
// envelope used by `openssl genpkey -algorithm Ed25519`). Other block
// types fall back to treating the body as raw key material.
func privateKeyFromPEMBlock(block *pem.Block) (ed25519.PrivateKey, error) {
	if strings.EqualFold(block.Type, "PRIVATE KEY") {
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKCS#8 private key: %w", err)
		}
		priv, ok := key.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("PKCS#8 key is %T, not ed25519.PrivateKey", key)
		}
		return priv, nil
	}
	return privateKeyFromRaw(block.Bytes)
}

func privateKeyFromRaw(raw []byte) (ed25519.PrivateKey, error) {
	switch len(raw) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(raw), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(raw), nil
	default:
		return nil, fmt.Errorf("unsupported ed25519 private key length: %d", len(raw))
	}
}

// LoadPublicKey reads an Ed25519 public key from disk. Supported formats:
//
//   - PEM block of type "PUBLIC KEY" (SPKI / X.509 SubjectPublicKeyInfo, the
//     standard envelope produced by `openssl pkey -in key.pem -pubout`).
//   - PEM block of type "ED25519 PUBLIC KEY" — body is 32 raw bytes.
//   - Base64-encoded 32-byte raw key.
//   - Raw binary 32-byte key.
func LoadPublicKey(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return parsePublicKeyBytes(data)
}

func parsePublicKeyBytes(data []byte) (ed25519.PublicKey, error) {
	if block, _ := pem.Decode(data); block != nil {
		return publicKeyFromPEMBlock(block)
	}
	trimmed := strings.TrimSpace(string(data))
	if decoded, err := base64.StdEncoding.DecodeString(trimmed); err == nil {
		if pub, err := publicKeyFromRaw(decoded); err == nil {
			return pub, nil
		}
	}
	return publicKeyFromRaw(data)
}

// publicKeyFromPEMBlock decodes an Ed25519 public key from a PEM block.
// PEM blocks of type "PUBLIC KEY" carry an SPKI (X.509
// SubjectPublicKeyInfo) envelope — the standard format produced by
// `openssl pkey -pubout`. Other block types are treated as 32 raw bytes
// of key material so older keyfiles continue to load.
func publicKeyFromPEMBlock(block *pem.Block) (ed25519.PublicKey, error) {
	if strings.EqualFold(block.Type, "PUBLIC KEY") {
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse SPKI public key: %w", err)
		}
		pub, ok := key.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("SPKI key is %T, not ed25519.PublicKey", key)
		}
		return pub, nil
	}
	return publicKeyFromRaw(block.Bytes)
}

func publicKeyFromRaw(raw []byte) (ed25519.PublicKey, error) {
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("unsupported ed25519 public key length: %d", len(raw))
	}
	return ed25519.PublicKey(append([]byte(nil), raw...)), nil
}

// embeddedPublicKey returns the public key baked in via -ldflags. It is
// permitted to fail when no key is embedded so the CLI can fall back to a
// caller-supplied key in tests and development.
func embeddedPublicKey() (ed25519.PublicKey, error) {
	if EmbeddedPublicKey == "" {
		return nil, errors.New("no public key embedded in this build; pass --public-key explicitly")
	}
	raw, err := base64.StdEncoding.DecodeString(EmbeddedPublicKey)
	if err != nil {
		return nil, fmt.Errorf("decode embedded public key: %w", err)
	}
	return publicKeyFromRaw(raw)
}

// HasEmbeddedKey reports whether the CLI binary was built with a baked-in
// public key.
func HasEmbeddedKey() bool { return EmbeddedPublicKey != "" }

// EmbeddedKeyDisplay is the short string the version command prints for the
// embedded key, which falls back to the manifest-declared key id.
func EmbeddedKeyDisplay() string {
	if EmbeddedPublicKeyID != "" {
		return EmbeddedPublicKeyID
	}
	if EmbeddedPublicKey != "" {
		return "embedded"
	}
	return "unset"
}

// EncodePublicKey converts a public key to a base64 string suitable for
// passing to -ldflags -X.
func EncodePublicKey(pub ed25519.PublicKey) string {
	return base64.StdEncoding.EncodeToString(pub)
}
