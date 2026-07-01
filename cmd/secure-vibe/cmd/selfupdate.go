package cmd

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/shieldnet-360/secure-vibe/cmd/secure-vibe/internal/manifest"
)

// DefaultSelfUpdateBaseURL is the GitHub Releases "latest" endpoint that
// hosts the secure-vibe binaries and the matching per-target SHA-256
// checksum files.
const DefaultSelfUpdateBaseURL = "https://github.com/shieldnet-360/secure-vibe/releases/latest/download"

// The former `self-update` command is now `secure-vibe update --self`; the
// runSelfUpdate flow below is shared by that flag (see update.go).

type selfUpdateResult struct {
	BinaryName        string
	SHA256            string
	SignatureVerified bool
}

// runSelfUpdate is split out from the cobra RunE so the test can exercise
// it directly against an httptest.Server without re-wiring cobra.
func runSelfUpdate(out io.Writer, baseURL, goos, goarch, targetPath string, dryRun, requireSig bool) (*selfUpdateResult, error) {
	binaryName := fmt.Sprintf("secure-vibe-%s-%s", goos, goarch)
	if goos == "windows" {
		binaryName += ".exe"
	}
	checksumName := fmt.Sprintf("checksums-%s-%s.txt", goos, goarch)

	binURL, err := joinURL(baseURL, binaryName)
	if err != nil {
		return nil, err
	}
	sumURL, err := joinURL(baseURL, checksumName)
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(out, "downloading %s\n", binURL)

	body, err := httpGet(binURL)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", binURL, err)
	}
	defer body.Close()
	binaryBytes, err := io.ReadAll(body)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", binURL, err)
	}

	fmt.Fprintf(out, "downloading %s\n", sumURL)
	sumBody, err := httpGet(sumURL)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", sumURL, err)
	}
	sumBytes, err := io.ReadAll(sumBody)
	sumBody.Close()
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", sumURL, err)
	}

	// Authenticate the checksum file with the release key BEFORE trusting any
	// hash inside it. Without this the SHA-256 only proves the binary matches
	// whatever the same source served — a compromised release or a malicious
	// --base-url could swap both. With it, the integrity of the binary chains
	// back to the embedded Ed25519 public key.
	sigVerified, err := verifyChecksumSignature(out, baseURL, checksumName, sumBytes, requireSig)
	if err != nil {
		return nil, err
	}

	expected, err := lookupChecksum(bytes.NewReader(sumBytes), binaryName)
	if err != nil {
		return nil, err
	}
	got := sha256.Sum256(binaryBytes)
	gotHex := hex.EncodeToString(got[:])
	if !strings.EqualFold(gotHex, expected) {
		return nil, fmt.Errorf("sha256 mismatch for %s: got %s want %s", binaryName, gotHex, expected)
	}
	res := &selfUpdateResult{BinaryName: binaryName, SHA256: gotHex, SignatureVerified: sigVerified}
	if dryRun {
		return res, nil
	}
	if err := manifest.WriteFileAtomic(targetPath, binaryBytes, 0o755); err != nil {
		return nil, fmt.Errorf("replace %s: %w", targetPath, err)
	}
	return res, nil
}

// verifyChecksumSignature fetches "<checksumName>.sig" and verifies it over
// sumBytes against the trusted keys (embedded release key + any configured).
// Returns whether a valid signature was confirmed.
//
// Policy (non-breaking transition):
//   - signature present + valid   -> verified (true).
//   - signature present + invalid -> hard error (tampering).
//   - signature absent            -> error if requireSig; otherwise a warning
//     and fall back to checksum-only integrity, so existing releases that
//     predate signed checksum files still self-update.
//   - no embedded key in this build -> cannot verify; error if requireSig,
//     else warn.
func verifyChecksumSignature(out io.Writer, baseURL, checksumName string, sumBytes []byte, requireSig bool) (bool, error) {
	sigName := checksumName + ".sig"
	sigURL, err := joinURL(baseURL, sigName)
	if err != nil {
		return false, err
	}
	sigBody, err := httpGet(sigURL)
	if err != nil {
		// Treat any fetch failure (typically 404) as "no signature published".
		if requireSig {
			return false, fmt.Errorf("--require-signature set but %s could not be fetched: %w", sigName, err)
		}
		fmt.Fprintf(out, "warning: release is not Ed25519-signed (%s not found); falling back to checksum-only integrity\n", sigName)
		return false, nil
	}
	defer sigBody.Close()
	sigBytes, err := io.ReadAll(sigBody)
	if err != nil {
		return false, fmt.Errorf("read %s: %w", sigURL, err)
	}

	keys, err := manifest.TrustedKeys(nil)
	if err != nil {
		return false, fmt.Errorf("load trusted keys: %w", err)
	}
	if len(keys) == 0 {
		if requireSig {
			return false, fmt.Errorf("--require-signature set but this build has no embedded public key to verify against")
		}
		fmt.Fprintf(out, "warning: %s is published but this build has no embedded public key; cannot verify\n", sigName)
		return false, nil
	}
	if err := manifest.VerifyDetachedAny(keys, sumBytes, strings.TrimSpace(string(sigBytes))); err != nil {
		return false, fmt.Errorf("checksum signature verification failed for %s: %w", sigName, err)
	}
	fmt.Fprintf(out, "checksum signature: verified (key %s)\n", manifest.EmbeddedKeyDisplay())
	return true, nil
}

func joinURL(base, name string) (string, error) {
	u, err := url.Parse(base)
	if err != nil {
		return "", fmt.Errorf("parse base url %s: %w", base, err)
	}
	u.Path = path.Join(u.Path, name)
	return u.String(), nil
}

func httpGet(u string) (io.ReadCloser, error) {
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Get(u)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		resp.Body.Close()
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	return resp.Body, nil
}

// lookupChecksum scans a `sha256sum`-style file (one entry per line:
// "<hex>  <filename>") and returns the hex digest for the file matching
// binaryName.
func lookupChecksum(r io.Reader, binaryName string) (string, error) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		hash := fields[0]
		name := strings.TrimPrefix(fields[len(fields)-1], "*")
		if name == binaryName {
			return strings.ToLower(hash), nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("checksum for %s not found", binaryName)
}
