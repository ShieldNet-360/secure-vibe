package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shieldnet-360/secure-vibe/internal/tools"
)

// runContribute executes `contribute <args...>` against a fresh command
// tree and returns stdout plus any error.
func runContribute(t *testing.T, args ...string) (string, error) {
	t.Helper()
	root := Root()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs(append([]string{"contribute"}, args...))
	err := root.Execute()
	return buf.String(), err
}

// TestContributeAddListRemove exercises the local-overlay lifecycle and
// asserts the written file is a valid overlay the Library can enforce.
func TestContributeAddListRemove(t *testing.T) {
	dir := t.TempDir()

	out, err := runContribute(t, "add", "--dir", dir, "-p", "evil-pkg", "-e", "npm", "--reason", "beacons to evil.example")
	if err != nil {
		t.Fatalf("add: %v (%s)", err, out)
	}
	if !strings.Contains(out, "Added evil-pkg") {
		t.Errorf("add output missing confirmation: %s", out)
	}

	// The overlay file must parse and enforce.
	overlayPath := filepath.Join(dir, ".secure-vibe", "overlay.json")
	body, err := os.ReadFile(overlayPath)
	if err != nil {
		t.Fatalf("overlay not written: %v", err)
	}
	var of tools.OverlayFile
	if err := json.Unmarshal(body, &of); err != nil {
		t.Fatalf("overlay invalid JSON: %v", err)
	}
	if len(of.MaliciousPackages) != 1 || of.MaliciousPackages[0].Name != "evil-pkg" {
		t.Fatalf("overlay content wrong: %+v", of.MaliciousPackages)
	}
	// Default severity must be gate-blocking.
	if of.MaliciousPackages[0].Severity != "high" {
		t.Errorf("default severity = %q, want high", of.MaliciousPackages[0].Severity)
	}

	// Adding the same (name, ecosystem) again updates in place.
	if _, err := runContribute(t, "add", "--dir", dir, "-p", "evil-pkg", "-e", "npm", "--severity", "critical", "--reason", "updated"); err != nil {
		t.Fatalf("update: %v", err)
	}
	body, _ = os.ReadFile(overlayPath)
	json.Unmarshal(body, &of)
	if len(of.MaliciousPackages) != 1 {
		t.Errorf("upsert duplicated entry: %d rows", len(of.MaliciousPackages))
	}
	if of.MaliciousPackages[0].Severity != "critical" {
		t.Errorf("update did not take: severity %q", of.MaliciousPackages[0].Severity)
	}

	// list shows it.
	out, err = runContribute(t, "list", "--dir", dir)
	if err != nil || !strings.Contains(out, "evil-pkg") {
		t.Errorf("list: err=%v out=%s", err, out)
	}

	// remove deletes it.
	if _, err := runContribute(t, "remove", "--dir", dir, "-p", "evil-pkg", "-e", "npm"); err != nil {
		t.Fatalf("remove: %v", err)
	}
	body, _ = os.ReadFile(overlayPath)
	of = tools.OverlayFile{}
	json.Unmarshal(body, &of)
	if len(of.MaliciousPackages) != 0 {
		t.Errorf("remove left %d rows", len(of.MaliciousPackages))
	}
}

// TestContributeEnforcedByLibrary confirms the file written by
// `contribute add` is actually enforced when a Library points at it —
// the end-to-end LEARN guarantee.
func TestContributeEnforcedByLibrary(t *testing.T) {
	dir := t.TempDir()
	if _, err := runContribute(t, "add", "--dir", dir, "-p", "malware", "-e", "npm", "--severity", "critical", "--reason", "x"); err != nil {
		t.Fatal(err)
	}
	overlayPath := filepath.Join(dir, ".secure-vibe", "overlay.json")

	// Minimal library root for enforcement.
	libRoot := t.TempDir()
	os.MkdirAll(filepath.Join(libRoot, "skills"), 0o755)
	os.MkdirAll(filepath.Join(libRoot, "vulnerabilities", "supply-chain", "malicious-packages"), 0o755)
	os.WriteFile(filepath.Join(libRoot, "vulnerabilities", "supply-chain", "malicious-packages", "npm.json"), []byte(`{"ecosystem":"npm","entries":[]}`), 0o644)
	lib, err := tools.NewLibrary(libRoot, tools.WithOverlayPaths(overlayPath))
	if err != nil {
		t.Fatal(err)
	}
	res, err := lib.LookupVulnerability("malware", "npm", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Matches) != 1 || res.Matches[0].Source != tools.OverlaySource {
		t.Fatalf("contributed rule not enforced: %+v", res.Matches)
	}
}

// TestContributeSignSubmitVerify covers the signed half of the loop:
// keygen, signed add, signed submit, verify (valid), and tamper
// detection.
func TestContributeSignSubmitVerify(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key.pem")

	if _, err := runContribute(t, "keygen", "--out", keyPath); err != nil {
		t.Fatalf("keygen: %v", err)
	}
	if fi, err := os.Stat(keyPath); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("key perms wrong: %v mode=%v", err, fi.Mode().Perm())
	}

	if _, err := runContribute(t, "add", "--dir", dir, "-p", "evil", "-e", "npm", "--reason", "x", "--key", keyPath); err != nil {
		t.Fatalf("signed add: %v", err)
	}
	candPath := filepath.Join(dir, "cand.json")
	if _, err := runContribute(t, "submit", "--dir", dir, "--key", keyPath, "--out", candPath); err != nil {
		t.Fatalf("submit: %v", err)
	}

	out, err := runContribute(t, "verify", candPath)
	if err != nil {
		t.Fatalf("verify valid candidate failed: %v (%s)", err, out)
	}
	if !strings.Contains(out, "signature valid") {
		t.Errorf("verify output unexpected: %s", out)
	}

	// Tamper: flip the package name; the signature (which binds the
	// name) must now fail.
	body, _ := os.ReadFile(candPath)
	tampered := strings.Replace(string(body), `"evil"`, `"evil-renamed"`, 1)
	os.WriteFile(candPath, []byte(tampered), 0o644)
	if _, err := runContribute(t, "verify", candPath); err == nil {
		t.Error("verify accepted a tampered candidate; want failure")
	}
}

// TestContributeRejectsKeyIDMismatch locks the security branch that stops a
// candidate from lying about which key signed it: public_key_id must hash-match
// the embedded public_key_b64. That check is DUPLICATED in verifyCandidate (the
// import pre-check) and contributeVerifyCmd (the standalone verify), so this
// asserts BOTH reject an otherwise-valid candidate whose declared id has been
// swapped — pinning the two copies to identical behaviour so they can't drift.
func TestContributeRejectsKeyIDMismatch(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key.pem")
	if _, err := runContribute(t, "keygen", "--out", keyPath); err != nil {
		t.Fatalf("keygen: %v", err)
	}
	if _, err := runContribute(t, "add", "--dir", dir, "-p", "evil", "-e", "npm", "--reason", "x", "--key", keyPath); err != nil {
		t.Fatalf("signed add: %v", err)
	}
	candPath := filepath.Join(dir, "cand.json")
	if _, err := runContribute(t, "submit", "--dir", dir, "--key", keyPath, "--out", candPath); err != nil {
		t.Fatalf("submit: %v", err)
	}

	// Swap ONLY the public_key_id value (string replace, every other byte —
	// the embedded key and every signature — untouched). The signatures still
	// verify against the embedded key; only the declared id is now a lie.
	body, _ := os.ReadFile(candPath)
	var cand struct {
		PublicKeyID string `json:"public_key_id"`
	}
	if err := json.Unmarshal(body, &cand); err != nil {
		t.Fatalf("unmarshal candidate: %v", err)
	}
	if cand.PublicKeyID == "" {
		t.Fatal("candidate has no public_key_id to tamper")
	}
	mangled := strings.Replace(string(body), cand.PublicKeyID, cand.PublicKeyID+"X", 1)
	if mangled == string(body) {
		t.Fatal("failed to swap public_key_id")
	}
	if err := os.WriteFile(candPath, []byte(mangled), 0o644); err != nil {
		t.Fatalf("write mangled: %v", err)
	}

	// Both paths must reject, and reject for the RIGHT reason (the id
	// mismatch) — not some incidental parse error.
	vout, verr := runContribute(t, "verify", candPath)
	if verr == nil {
		t.Errorf("verify accepted a key-id-mismatched candidate; want failure (%s)", vout)
	} else if !strings.Contains(verr.Error()+vout, "public_key_id") {
		t.Errorf("verify rejected for the wrong reason: %v / %s", verr, vout)
	}
	iout, ierr := runContribute(t, "import", candPath, "--dir", t.TempDir())
	if ierr == nil {
		t.Errorf("import accepted a key-id-mismatched candidate; want failure (%s)", iout)
	} else if !strings.Contains(ierr.Error()+iout, "public_key_id") {
		t.Errorf("import rejected for the wrong reason: %v / %s", ierr, iout)
	}
}

// TestContributeAddRequiresPackage guards the required-flag validation.
func TestContributeAddRequiresPackage(t *testing.T) {
	if _, err := runContribute(t, "add", "--dir", t.TempDir(), "-e", "npm"); err == nil {
		t.Error("add without --package should error")
	}
}

// TestContributeImportRoundTrip covers the receiving end of the sharing
// loop: a signed candidate produced on one machine imports into another
// machine's overlay and is enforced; unsigned and tampered candidates
// are refused.
func TestContributeImportRoundTrip(t *testing.T) {
	send := t.TempDir()
	keyPath := filepath.Join(send, "key.pem")
	if _, err := runContribute(t, "keygen", "--out", keyPath); err != nil {
		t.Fatalf("keygen: %v", err)
	}
	if _, err := runContribute(t, "add", "--dir", send, "-p", "shared-evil", "-e", "npm", "--reason", "x", "--key", keyPath); err != nil {
		t.Fatalf("signed add: %v", err)
	}
	signed := filepath.Join(send, "signed.json")
	if _, err := runContribute(t, "submit", "--dir", send, "--key", keyPath, "--out", signed); err != nil {
		t.Fatalf("submit signed: %v", err)
	}
	unsigned := filepath.Join(send, "unsigned.json")
	if _, err := runContribute(t, "submit", "--dir", send, "--out", unsigned); err != nil {
		t.Fatalf("submit unsigned: %v", err)
	}

	adopt := t.TempDir()

	// Signed candidate imports and is enforced.
	out, err := runContribute(t, "import", signed, "--dir", adopt)
	if err != nil {
		t.Fatalf("import signed: %v (%s)", err, out)
	}
	overlayPath := filepath.Join(adopt, ".secure-vibe", "overlay.json")
	body, _ := os.ReadFile(overlayPath)
	var of tools.OverlayFile
	json.Unmarshal(body, &of)
	if len(of.MaliciousPackages) != 1 || of.MaliciousPackages[0].Name != "shared-evil" {
		t.Fatalf("imported overlay wrong: %+v", of.MaliciousPackages)
	}

	// Unsigned candidate is refused without the opt-in flag, accepted with it.
	adopt2 := t.TempDir()
	if _, err := runContribute(t, "import", unsigned, "--dir", adopt2); err == nil {
		t.Error("unsigned candidate should be refused without --allow-unsigned")
	}
	if _, err := runContribute(t, "import", unsigned, "--dir", adopt2, "--allow-unsigned"); err != nil {
		t.Errorf("unsigned import with --allow-unsigned should succeed: %v", err)
	}

	// Tampered signed candidate is refused.
	tampered := filepath.Join(send, "tampered.json")
	b, _ := os.ReadFile(signed)
	os.WriteFile(tampered, []byte(strings.Replace(string(b), `"shared-evil"`, `"shared-evil2"`, 1)), 0o644)
	if _, err := runContribute(t, "import", tampered, "--dir", t.TempDir()); err == nil {
		t.Error("tampered candidate should be refused")
	}
}
