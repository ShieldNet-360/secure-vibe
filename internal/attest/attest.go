// Package attest produces and verifies a SecureVibe "usage attestation" — a
// tamper-evident WATERMARK that a commit's code was scanned by secure-vibe and
// carries the resulting verdict.
//
// SCOPE / THREAT MODEL (read this before trusting it):
//
// This is a USAGE SIGNAL, not a security control. The signing key is an
// asymmetric Ed25519 key whose private seed is shipped inside the binary
// (EmbeddedSeed), so it is, by design, extractable. That is acceptable here
// because the goal is to DETECT that an honest developer used secure-vibe —
// not to PROVE to a third party that a malicious developer could not have
// forged it. A present, valid attestation is strong evidence of use; its
// absence proves nothing (the developer may have committed with --no-verify).
//
// Two deliberate design choices make the watermark robust and upgradeable:
//
//   - It signs a CONTENT-ADDRESSED subject (a git tree SHA), never a raw
//     `git diff` — diffs are non-canonical (config-dependent) and would cause
//     false negatives on verify.
//   - It is ASYMMETRIC: verification only ever needs the PUBLIC key
//     (EmbeddedPublicKey). If anti-forgery is ever required, the private seed
//     can move to a server-side signer with no change to the on-disk format or
//     the verify path.
package attest

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Version is the attestation schema version embedded in every trailer.
const Version = "v1"

// TrailerKey is the git trailer under which the attestation is stored in the
// commit message. Detecting usage across history is then a one-liner:
//
//	git log --grep '^SecureVibe-Attestation:'
const TrailerKey = "SecureVibe-Attestation"

// EmbeddedSeed is the base64-encoded 32-byte Ed25519 seed of the SecureVibe
// watermark key. It is intentionally shipped in the binary (see the package
// doc). A deployment that wants a private, server-side signer can override it
// at build time with:
//
//	-ldflags "-X github.com/shieldnet-360/secure-vibe/internal/attest.EmbeddedSeed=<b64>"
//
// and distribute a binary that carries only EmbeddedPublicKey.
var EmbeddedSeed = "H/DBwuw+FlfUU7gnd1UQtvOAOqUdXLek6Hk3yQ+Fzpk="

// EmbeddedPublicKey is the base64-encoded Ed25519 public key used to verify
// attestations. It is derived from EmbeddedSeed by default but kept as a
// separate variable so a build can ship the public key WITHOUT the seed.
var EmbeddedPublicKey = "dX9s3rMkALSjORCGnVfFqyLbWEbmW+LXCq6ecVboA/k="

// Counts is the per-severity finding tally recorded in an attestation.
type Counts struct {
	Critical int
	High     int
	Medium   int
	Low      int
}

// FromMap builds Counts from a severity->count map (as produced by the
// scanner's PolicyCheckResult.Counts). Unknown keys are ignored.
func CountsFromMap(m map[string]int) Counts {
	return Counts{
		Critical: m["critical"],
		High:     m["high"],
		Medium:   m["medium"],
		Low:      m["low"],
	}
}

// String renders the compact "c:h:m:l" form used in the trailer.
func (c Counts) String() string {
	return fmt.Sprintf("%d:%d:%d:%d", c.Critical, c.High, c.Medium, c.Low)
}

func parseCounts(s string) (Counts, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 4 {
		return Counts{}, fmt.Errorf("bad findings %q (want c:h:m:l)", s)
	}
	n := make([]int, 4)
	for i, p := range parts {
		v, err := strconv.Atoi(p)
		if err != nil {
			return Counts{}, fmt.Errorf("bad findings %q: %w", s, err)
		}
		n[i] = v
	}
	return Counts{Critical: n[0], High: n[1], Medium: n[2], Low: n[3]}, nil
}

// Attestation is the signed claim carried in the commit trailer.
type Attestation struct {
	Version  string // schema version, e.g. "v1"
	KeyID    string // short id of the signing key (16 hex)
	Tool     string // secure-vibe version that produced it
	Subject  string // content-addressed subject, e.g. "tree:<sha>"
	Verdict  string // "pass" or "fail"
	Floor    string // severity floor the scan used
	Findings Counts // per-severity tally
	Sig      string // base64url Ed25519 signature over CanonicalBytes()
}

// CanonicalBytes is the exact byte sequence that is signed and verified. It is
// a deterministic, ordered key=value encoding with the signature omitted, so
// signing and verification always hash identical bytes.
func (a Attestation) CanonicalBytes() []byte {
	fields := [][2]string{
		{"attestation", "secure-vibe"},
		{"version", a.Version},
		{"keyid", a.KeyID},
		{"tool", a.Tool},
		{"subject", a.Subject},
		{"verdict", a.Verdict},
		{"floor", a.Floor},
		{"findings", a.Findings.String()},
	}
	// Fields are already in a fixed order; sort defensively so a future
	// reordering of the literal above can never change the signed bytes.
	sort.SliceStable(fields, func(i, j int) bool { return fields[i][0] < fields[j][0] })
	var b strings.Builder
	for _, f := range fields {
		b.WriteString(f[0])
		b.WriteByte('=')
		b.WriteString(f[1])
		b.WriteByte('\n')
	}
	return []byte(b.String())
}

// KeyID returns the 16-hex short id of an Ed25519 public key.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])[:16]
}

// signingKey decodes EmbeddedSeed into an Ed25519 private key.
func signingKey() (ed25519.PrivateKey, error) {
	if EmbeddedSeed == "" {
		return nil, fmt.Errorf("no signing seed embedded in this build (verify-only binary)")
	}
	seed, err := base64.StdEncoding.DecodeString(EmbeddedSeed)
	if err != nil {
		return nil, fmt.Errorf("decode embedded seed: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("embedded seed is %d bytes, want %d", len(seed), ed25519.SeedSize)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// verifyingKey decodes EmbeddedPublicKey into an Ed25519 public key.
func verifyingKey() (ed25519.PublicKey, error) {
	if EmbeddedPublicKey == "" {
		return nil, fmt.Errorf("no public key embedded in this build")
	}
	pub, err := base64.StdEncoding.DecodeString(EmbeddedPublicKey)
	if err != nil {
		return nil, fmt.Errorf("decode embedded public key: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("embedded public key is %d bytes, want %d", len(pub), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(pub), nil
}

// Sign fills in KeyID/Version/Sig on a (partially populated) attestation using
// the embedded watermark key. Subject, Tool, Verdict, Floor and Findings must
// already be set by the caller.
func Sign(a Attestation) (Attestation, error) {
	priv, err := signingKey()
	if err != nil {
		return a, err
	}
	a.Version = Version
	a.KeyID = KeyID(priv.Public().(ed25519.PublicKey))
	sig := ed25519.Sign(priv, a.CanonicalBytes())
	a.Sig = base64.RawURLEncoding.EncodeToString(sig)
	return a, nil
}

// Verify checks the signature on an attestation against the embedded public
// key. It returns nil when the signature is valid and covers exactly these
// fields.
func Verify(a Attestation) error {
	pub, err := verifyingKey()
	if err != nil {
		return err
	}
	if a.KeyID != "" && a.KeyID != KeyID(pub) {
		return fmt.Errorf("attestation key id %q does not match this build's key %q", a.KeyID, KeyID(pub))
	}
	sig, err := base64.RawURLEncoding.DecodeString(a.Sig)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	if !ed25519.Verify(pub, a.CanonicalBytes(), sig) {
		return fmt.Errorf("signature does not verify (forged, tampered, or wrong key)")
	}
	return nil
}

// TrailerLine renders the single-line git trailer for a signed attestation.
func (a Attestation) TrailerLine() string {
	return fmt.Sprintf("%s: %s keyid=%s tool=%s subject=%s verdict=%s floor=%s findings=%s sig=%s",
		TrailerKey, a.Version, a.KeyID, a.Tool, a.Subject, a.Verdict, a.Floor, a.Findings, a.Sig)
}

// ParseTrailer extracts the FIRST SecureVibe-Attestation trailer from a commit
// message and returns the parsed attestation. ok is false when the message
// carries no such trailer.
func ParseTrailer(message string) (a Attestation, ok bool, err error) {
	prefix := TrailerKey + ":"
	for _, line := range strings.Split(message, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		return parseTrailerValue(strings.TrimSpace(strings.TrimPrefix(line, prefix)))
	}
	return Attestation{}, false, nil
}

func parseTrailerValue(val string) (Attestation, bool, error) {
	fields := strings.Fields(val)
	if len(fields) == 0 {
		return Attestation{}, false, fmt.Errorf("empty attestation trailer")
	}
	a := Attestation{Version: fields[0]}
	for _, f := range fields[1:] {
		k, v, found := strings.Cut(f, "=")
		if !found {
			continue
		}
		switch k {
		case "keyid":
			a.KeyID = v
		case "tool":
			a.Tool = v
		case "subject":
			a.Subject = v
		case "verdict":
			a.Verdict = v
		case "floor":
			a.Floor = v
		case "findings":
			c, err := parseCounts(v)
			if err != nil {
				return Attestation{}, false, err
			}
			a.Findings = c
		case "sig":
			a.Sig = v
		}
	}
	if a.Subject == "" || a.Sig == "" {
		return Attestation{}, false, fmt.Errorf("attestation trailer missing subject or sig")
	}
	return a, true, nil
}

// TreeSubject wraps a git tree SHA as the canonical subject string.
func TreeSubject(treeSHA string) string { return "tree:" + treeSHA }

// SubjectTreeSHA returns the tree SHA from a "tree:<sha>" subject, or "" if the
// subject is not a tree reference.
func SubjectTreeSHA(subject string) string {
	if sha, ok := strings.CutPrefix(subject, "tree:"); ok {
		return sha
	}
	return ""
}
