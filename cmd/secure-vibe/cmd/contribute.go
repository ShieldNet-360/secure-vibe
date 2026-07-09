package cmd

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/shieldnet-360/secure-vibe/cmd/secure-vibe/internal/manifest"
	"github.com/shieldnet-360/secure-vibe/internal/tools"
)

// overlayRelPath is the project-local overlay file the gate consults by
// default (NewLibrary seeds it from the working directory). `contribute`
// writes the same path so a record-then-gate round trip blocks
// immediately.
const overlayRelPath = ".secure-vibe/overlay.json"

// contributeCmd implements the LEARN loop's contribution half: record a
// bad package locally so the gate blocks it immediately (code never
// leaves the machine), then optionally export a portable, signed
// candidate to share upstream.
func contributeCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "contribute",
		Short: "Record a locally-discovered bad package so the gate blocks it immediately (LEARN loop)",
		Long: `Record a security finding into the local contribution overlay
(.secure-vibe/overlay.json) so the gate blocks the offending package on the
next run — no central round trip, the rule never leaves your machine.

Sharing the block (the LEARN flywheel), in order of blast radius:
  • Your machine — the overlay is read from .secure-vibe/overlay.json by every
    check/scan/gate run.
  • Your team   — commit .secure-vibe/overlay.json; git is the fan-out, so
    every teammate's gate (run from the repo root) enforces it on next pull.
  • Your org    — point $SECURE_VIBE_OVERLAY at a shared overlay file outside
    any single repo (OS path-list separated for more than one); every
    secure-vibe invocation folds it in, so an org-wide block applies across
    all repos and CI jobs.

Run "contribute submit" to export a portable, optionally-signed candidate you
can attach to an upstream issue/PR for review into the central database.

The same LEARN loop covers knowledge, not just data: when a coding agent finds
a skill is missing a fact or is wrong, it records an inert proposal via the
propose_skill_update MCP tool. Review those with "contribute skill".`,
	}
	c.AddCommand(contributeAddCmd())
	c.AddCommand(contributeListCmd())
	c.AddCommand(contributeRemoveCmd())
	c.AddCommand(contributeSubmitCmd())
	c.AddCommand(contributeKeygenCmd())
	c.AddCommand(contributeVerifyCmd())
	c.AddCommand(contributeImportCmd())
	c.AddCommand(contributeSkillCmd())
	return c
}

// verifyCandidate checks a candidate's embedded signatures and returns
// the resolved key id. It is the shared core of `verify` and the
// pre-merge check in `import`. A candidate with no embedded public key
// is reported as unsigned (keyID "").
func verifyCandidate(cand candidateFile) (keyID string, err error) {
	if cand.PublicKeyB64 == "" {
		return "", nil // unsigned
	}
	pubRaw, derr := base64.StdEncoding.DecodeString(cand.PublicKeyB64)
	if derr != nil || len(pubRaw) != ed25519.PublicKeySize {
		return "", fmt.Errorf("candidate public key is malformed")
	}
	pub := ed25519.PublicKey(pubRaw)
	declaredID := keyIDFor(pub)
	if cand.PublicKeyID != "" && cand.PublicKeyID != declaredID {
		return "", fmt.Errorf("candidate public_key_id %q does not match its embedded key (%q)", cand.PublicKeyID, declaredID)
	}
	for _, p := range cand.Packages {
		if p.Signature == "" {
			return "", fmt.Errorf("rule %s (%s) is unsigned in a signed candidate", p.Name, p.Ecosystem)
		}
		raw, derr := base64.StdEncoding.DecodeString(strings.TrimPrefix(p.Signature, manifest.SignaturePrefix))
		if derr != nil || !ed25519.Verify(pub, overlaySigningBytes(p), raw) {
			return "", fmt.Errorf("rule %s (%s) signature is INVALID", p.Name, p.Ecosystem)
		}
	}
	return declaredID, nil
}

// contributeImportCmd merges a shared candidate file into the local
// overlay — the receiving end of submit -> verify -> import. A signed
// candidate must verify before any rule is adopted; an unsigned one is
// refused unless --allow-unsigned is given, so provenance is the
// default. This is what lets a finding travel from one developer's
// machine to another's gate without going through the central pipeline.
func contributeImportCmd() *cobra.Command {
	var dir string
	var allowUnsigned bool
	c := &cobra.Command{
		Use:   "import <candidate.json>",
		Short: "Merge a shared candidate file into the local overlay (verifies signatures first)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			body, err := os.ReadFile(args[0])
			if err != nil {
				return err
			}
			var cand candidateFile
			if err := json.Unmarshal(body, &cand); err != nil {
				return fmt.Errorf("parse candidate: %w", err)
			}
			if len(cand.Packages) == 0 {
				return fmt.Errorf("candidate has no rules to import")
			}
			keyID, err := verifyCandidate(cand)
			if err != nil {
				return fmt.Errorf("refusing to import: %w", err)
			}
			if keyID == "" && !allowUnsigned {
				return fmt.Errorf("candidate is unsigned; re-run with --allow-unsigned to import without provenance")
			}
			path, err := overlayPathFor(dir)
			if err != nil {
				return err
			}
			of, err := loadOverlay(path)
			if err != nil {
				return err
			}
			added, updated := 0, 0
			for _, p := range cand.Packages {
				replaced := false
				for i, ex := range of.MaliciousPackages {
					if strings.EqualFold(ex.Name, p.Name) && strings.EqualFold(ex.Ecosystem, p.Ecosystem) {
						of.MaliciousPackages[i] = p
						replaced = true
						updated++
						break
					}
				}
				if !replaced {
					of.MaliciousPackages = append(of.MaliciousPackages, p)
					added++
				}
			}
			if err := saveOverlay(path, of); err != nil {
				return err
			}
			prov := "unsigned"
			if keyID != "" {
				prov = "verified, key " + keyID
			}
			fmt.Fprintf(cmd.OutOrStdout(),
				"Imported %d rule(s) (%d new, %d updated, %s) into %s\nThe gate will enforce them on its next run.\n",
				added+updated, added, updated, prov, path)
			return nil
		},
	}
	c.Flags().StringVar(&dir, "dir", "", "project directory (default: cwd)")
	c.Flags().BoolVar(&allowUnsigned, "allow-unsigned", false, "import a candidate that carries no signature/provenance")
	return c
}

// contributeVerifyCmd verifies the signatures on a candidate file — the
// check a reviewer (or the central pipeline) runs before promoting any
// rule into the canonical database. Each signed rule is checked against
// the public key embedded in the candidate; the command exits non-zero
// if any signature is missing or invalid.
func contributeVerifyCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "verify <candidate.json>",
		Short: "Verify the signatures on a submitted candidate file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			body, err := os.ReadFile(args[0])
			if err != nil {
				return err
			}
			var cand candidateFile
			if err := json.Unmarshal(body, &cand); err != nil {
				return fmt.Errorf("parse candidate: %w", err)
			}
			w := cmd.OutOrStdout()
			if cand.PublicKeyB64 == "" {
				return fmt.Errorf("candidate is unsigned (no public_key_b64); cannot verify provenance")
			}
			pubRaw, err := base64.StdEncoding.DecodeString(cand.PublicKeyB64)
			if err != nil || len(pubRaw) != ed25519.PublicKeySize {
				return fmt.Errorf("candidate public key is malformed")
			}
			pub := ed25519.PublicKey(pubRaw)
			declaredID := keyIDFor(pub)
			if cand.PublicKeyID != "" && cand.PublicKeyID != declaredID {
				return fmt.Errorf("candidate public_key_id %q does not match its embedded key (%q)", cand.PublicKeyID, declaredID)
			}
			bad := 0
			for _, p := range cand.Packages {
				if p.Signature == "" {
					fmt.Fprintf(w, "  ✗ %s (%s): unsigned\n", p.Name, p.Ecosystem)
					bad++
					continue
				}
				raw, derr := base64.StdEncoding.DecodeString(strings.TrimPrefix(p.Signature, manifest.SignaturePrefix))
				if derr != nil || !ed25519.Verify(pub, overlaySigningBytes(p), raw) {
					fmt.Fprintf(w, "  ✗ %s (%s): signature INVALID\n", p.Name, p.Ecosystem)
					bad++
					continue
				}
				fmt.Fprintf(w, "  ✓ %s (%s): signature valid\n", p.Name, p.Ecosystem)
			}
			if bad > 0 {
				return fmt.Errorf("%d of %d rule(s) failed verification", bad, len(cand.Packages))
			}
			fmt.Fprintf(w, "All %d rule(s) verified against key %s\n", len(cand.Packages), declaredID)
			return nil
		},
	}
	return c
}

// contributeKeygenCmd generates an Ed25519 keypair for signing
// contributions. It exists because signing should not require the user
// to fight platform openssl quirks (macOS LibreSSL, for instance, ships
// no ed25519 genpkey), which would otherwise be a real adoption barrier.
func contributeKeygenCmd() *cobra.Command {
	var out string
	c := &cobra.Command{
		Use:   "keygen",
		Short: "Generate an Ed25519 keypair for signing contributions",
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(out) == "" {
				return fmt.Errorf("--out is required (path for the private key)")
			}
			if _, err := os.Stat(out); err == nil {
				return fmt.Errorf("refusing to overwrite existing key at %s", out)
			}
			pub, priv, err := manifest.GenerateKeyPair()
			if err != nil {
				return err
			}
			der, err := x509.MarshalPKCS8PrivateKey(priv)
			if err != nil {
				return err
			}
			pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
			if err := manifest.WriteFileAtomic(out, pemBytes, 0o600); err != nil {
				return err
			}
			pubB64 := base64.StdEncoding.EncodeToString(pub)
			pubPath := out + ".pub"
			_ = os.WriteFile(pubPath, []byte(pubB64+"\n"), 0o644)
			fmt.Fprintf(cmd.OutOrStdout(),
				"Wrote private key to %s (0600) and public key to %s\nKey ID: %s\nSign contributions with: --key %s\n",
				out, pubPath, keyIDFor(pub), out)
			return nil
		},
	}
	c.Flags().StringVar(&out, "out", "", "path to write the Ed25519 private key (PEM, 0600)")
	return c
}

// overlayPathFor resolves the overlay file inside dir (default cwd).
func overlayPathFor(dir string) (string, error) {
	if strings.TrimSpace(dir) == "" {
		wd, err := os.Getwd()
		if err != nil {
			return "", err
		}
		dir = wd
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	return filepath.Join(abs, overlayRelPath), nil
}

// loadOverlay reads the overlay at path, returning an empty overlay when
// the file does not exist yet.
func loadOverlay(path string) (*tools.OverlayFile, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &tools.OverlayFile{SchemaVersion: "1.0", GeneratedBy: "secure-vibe contribute"}, nil
		}
		return nil, err
	}
	var of tools.OverlayFile
	if err := json.Unmarshal(body, &of); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if of.SchemaVersion == "" {
		of.SchemaVersion = "1.0"
	}
	return &of, nil
}

// saveOverlay writes the overlay atomically with a stable key order so
// the committed file has a clean, reviewable diff.
func saveOverlay(path string, of *tools.OverlayFile) error {
	sort.SliceStable(of.MaliciousPackages, func(i, j int) bool {
		a, b := of.MaliciousPackages[i], of.MaliciousPackages[j]
		if !strings.EqualFold(a.Ecosystem, b.Ecosystem) {
			return strings.ToLower(a.Ecosystem) < strings.ToLower(b.Ecosystem)
		}
		return strings.ToLower(a.Name) < strings.ToLower(b.Name)
	})
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(of, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return manifest.WriteFileAtomic(path, data, 0o644)
}

// overlaySigningBytes is the deterministic content signed for an entry.
// It binds the security-relevant fields (not provenance fields like the
// contributor name or timestamp), so the same rule signs identically
// regardless of who recorded it or when.
func overlaySigningBytes(p tools.OverlayPackage) []byte {
	versions := append([]string(nil), p.VersionsAffected...)
	sort.Strings(versions)
	refs := append([]string(nil), p.References...)
	sort.Strings(refs)
	canon := struct {
		Name             string   `json:"name"`
		Ecosystem        string   `json:"ecosystem"`
		VersionsAffected []string `json:"versions_affected"`
		Severity         string   `json:"severity"`
		Type             string   `json:"type"`
		Description      string   `json:"description"`
		References       []string `json:"references"`
	}{
		Name:             strings.ToLower(strings.TrimSpace(p.Name)),
		Ecosystem:        strings.ToLower(strings.TrimSpace(p.Ecosystem)),
		VersionsAffected: versions,
		Severity:         strings.ToLower(strings.TrimSpace(p.Severity)),
		Type:             strings.TrimSpace(p.Type),
		Description:      strings.TrimSpace(p.Description),
		References:       refs,
	}
	b, _ := json.Marshal(canon)
	return b
}

// keyIDFor derives a short, stable identifier for a public key so a
// signed entry records WHICH key signed it without embedding the key.
func keyIDFor(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return "secure-vibe-contrib-" + base64.RawURLEncoding.EncodeToString(sum[:6])
}

// signOverlayEntry signs p in place with the key at keyPath.
func signOverlayEntry(p *tools.OverlayPackage, keyPath string) error {
	priv, err := manifest.LoadPrivateKey(keyPath)
	if err != nil {
		return fmt.Errorf("load signing key: %w", err)
	}
	sig := ed25519.Sign(priv, overlaySigningBytes(*p))
	p.Signature = manifest.SignaturePrefix + base64.StdEncoding.EncodeToString(sig)
	p.PublicKeyID = keyIDFor(priv.Public().(ed25519.PublicKey))
	return nil
}

func contributeAddCmd() *cobra.Command {
	var (
		dir, pkg, ecosystem, severity, typ, desc string
		versions, references                     []string
		contributor, keyPath                     string
	)
	c := &cobra.Command{
		Use:   "add",
		Short: "Add or update a bad-package rule in the local overlay",
		Example: `  # Block a package you saw misbehave, everywhere, immediately:
  secure-vibe contribute add -p evil-pkg -e npm --reason "exfiltrates AWS creds in postinstall"

  # Block only specific versions, and sign the entry for provenance:
  secure-vibe contribute add -p left-pad -e npm --versions 1.0.0,1.1.0 --key ~/key.pem`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(pkg) == "" || strings.TrimSpace(ecosystem) == "" {
				return fmt.Errorf("--package and --ecosystem are required")
			}
			path, err := overlayPathFor(dir)
			if err != nil {
				return err
			}
			of, err := loadOverlay(path)
			if err != nil {
				return err
			}
			if contributor == "" {
				contributor = strings.TrimSpace(os.Getenv("USER"))
			}
			entry := tools.OverlayPackage{
				Name:             strings.TrimSpace(pkg),
				Ecosystem:        strings.ToLower(strings.TrimSpace(ecosystem)),
				VersionsAffected: cleanList(versions),
				Severity:         strings.ToLower(strings.TrimSpace(severity)),
				Type:             strings.TrimSpace(typ),
				Description:      strings.TrimSpace(desc),
				References:       cleanList(references),
				Reason:           strings.TrimSpace(desc),
				Contributor:      contributor,
				Added:            time.Now().UTC().Format("2006-01-02"),
			}
			if keyPath != "" {
				if err := signOverlayEntry(&entry, keyPath); err != nil {
					return err
				}
			}
			// Upsert on (name, ecosystem).
			replaced := false
			for i, ex := range of.MaliciousPackages {
				if strings.EqualFold(ex.Name, entry.Name) && strings.EqualFold(ex.Ecosystem, entry.Ecosystem) {
					of.MaliciousPackages[i] = entry
					replaced = true
					break
				}
			}
			if !replaced {
				of.MaliciousPackages = append(of.MaliciousPackages, entry)
			}
			if err := saveOverlay(path, of); err != nil {
				return err
			}
			verb := "Added"
			if replaced {
				verb = "Updated"
			}
			signed := ""
			if entry.Signature != "" {
				signed = fmt.Sprintf(" (signed, key %s)", entry.PublicKeyID)
			}
			fmt.Fprintf(cmd.OutOrStdout(),
				"%s %s (%s) in %s%s\nThe gate will block this package on its next run. Commit the file to share it with your team.\n",
				verb, entry.Name, entry.Ecosystem, path, signed)
			return nil
		},
	}
	c.Flags().StringVar(&dir, "dir", "", "project directory holding .secure-vibe/overlay.json (default: cwd)")
	c.Flags().StringVarP(&pkg, "package", "p", "", "package name (required)")
	c.Flags().StringVarP(&ecosystem, "ecosystem", "e", "", "ecosystem: npm, pypi, crates, go, rubygems, maven, nuget, composer (required)")
	c.Flags().StringSliceVar(&versions, "versions", nil, "affected versions/ranges (comma-separated; default: all versions)")
	c.Flags().StringVar(&severity, "severity", "high", "severity: critical|high|medium|low (default high so the gate blocks)")
	c.Flags().StringVar(&typ, "type", "", "finding type label (default: locally_flagged)")
	c.Flags().StringVar(&desc, "reason", "", "why this package is flagged (shown in the finding)")
	c.Flags().StringSliceVar(&references, "references", nil, "evidence URLs (comma-separated)")
	c.Flags().StringVar(&contributor, "by", "", "contributor identifier (default: $USER)")
	c.Flags().StringVar(&keyPath, "key", "", "Ed25519 private key (PEM/raw) to sign the entry for provenance")
	return c
}

func contributeListCmd() *cobra.Command {
	var dir string
	var asJSON bool
	c := &cobra.Command{
		Use:   "list",
		Short: "List the rules in the local overlay",
		RunE: func(cmd *cobra.Command, args []string) error {
			path, err := overlayPathFor(dir)
			if err != nil {
				return err
			}
			of, err := loadOverlay(path)
			if err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			if asJSON {
				enc := json.NewEncoder(w)
				enc.SetIndent("", "  ")
				return enc.Encode(of)
			}
			if len(of.MaliciousPackages) == 0 {
				fmt.Fprintf(w, "No overlay rules yet (%s).\nAdd one with: secure-vibe contribute add -p <pkg> -e <eco> --reason <why>\n", path)
				return nil
			}
			fmt.Fprintf(w, "%d overlay rule(s) in %s:\n", len(of.MaliciousPackages), path)
			for _, p := range of.MaliciousPackages {
				vers := "all versions"
				if len(p.VersionsAffected) > 0 {
					vers = strings.Join(p.VersionsAffected, ", ")
				}
				sig := ""
				if p.Signature != "" {
					sig = " [signed]"
				}
				fmt.Fprintf(w, "  - %s (%s) sev=%s versions=%s%s\n", p.Name, p.Ecosystem, p.Severity, vers, sig)
				if p.Reason != "" {
					fmt.Fprintf(w, "      reason: %s\n", p.Reason)
				}
			}
			return nil
		},
	}
	c.Flags().StringVar(&dir, "dir", "", "project directory (default: cwd)")
	c.Flags().BoolVar(&asJSON, "json", false, "emit the raw overlay JSON")
	return c
}

func contributeRemoveCmd() *cobra.Command {
	var dir, pkg, ecosystem string
	c := &cobra.Command{
		Use:   "remove",
		Short: "Remove a rule from the local overlay",
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(pkg) == "" || strings.TrimSpace(ecosystem) == "" {
				return fmt.Errorf("--package and --ecosystem are required")
			}
			path, err := overlayPathFor(dir)
			if err != nil {
				return err
			}
			of, err := loadOverlay(path)
			if err != nil {
				return err
			}
			kept := of.MaliciousPackages[:0]
			removed := false
			for _, p := range of.MaliciousPackages {
				if strings.EqualFold(p.Name, pkg) && strings.EqualFold(p.Ecosystem, ecosystem) {
					removed = true
					continue
				}
				kept = append(kept, p)
			}
			of.MaliciousPackages = kept
			if !removed {
				return fmt.Errorf("no overlay rule for %s (%s)", pkg, ecosystem)
			}
			if err := saveOverlay(path, of); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Removed %s (%s) from %s\n", pkg, ecosystem, path)
			return nil
		},
	}
	c.Flags().StringVar(&dir, "dir", "", "project directory (default: cwd)")
	c.Flags().StringVarP(&pkg, "package", "p", "", "package name (required)")
	c.Flags().StringVarP(&ecosystem, "ecosystem", "e", "", "ecosystem (required)")
	return c
}

// candidateFile is the portable, shareable export produced by
// `contribute submit`: the overlay rules plus, when signed, the public
// key so a reviewer can verify provenance before promoting any rule into
// the central database. This is the only artifact that ever leaves the
// machine, and only on the explicit `submit`.
type candidateFile struct {
	SchemaVersion string                 `json:"schema_version"`
	Kind          string                 `json:"kind"`
	GeneratedBy   string                 `json:"generated_by"`
	GeneratedAt   string                 `json:"generated_at"`
	PublicKeyB64  string                 `json:"public_key_b64,omitempty"`
	PublicKeyID   string                 `json:"public_key_id,omitempty"`
	Packages      []tools.OverlayPackage `json:"malicious_packages"`
}

func contributeSubmitCmd() *cobra.Command {
	var dir, out, keyPath, only string
	c := &cobra.Command{
		Use:   "submit",
		Short: "Export the overlay as a portable (optionally signed) candidate to share upstream",
		Long: `Bundle the local overlay rules into a single candidate file you can attach to
an upstream issue or PR. Nothing is uploaded — this only writes a file. When
--key is supplied every rule is signed and the public key is embedded so a
reviewer can verify provenance before promoting a rule into the central,
centrally-signed database.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			path, err := overlayPathFor(dir)
			if err != nil {
				return err
			}
			of, err := loadOverlay(path)
			if err != nil {
				return err
			}
			pkgs := of.MaliciousPackages
			if only != "" {
				filtered := pkgs[:0:0]
				for _, p := range pkgs {
					if strings.EqualFold(p.Name, only) {
						filtered = append(filtered, p)
					}
				}
				pkgs = filtered
			}
			if len(pkgs) == 0 {
				return fmt.Errorf("no overlay rules to submit in %s", path)
			}
			cand := candidateFile{
				SchemaVersion: "1.0",
				Kind:          "secure-vibe-contribution-candidate",
				GeneratedBy:   "secure-vibe contribute submit",
				GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
				Packages:      append([]tools.OverlayPackage(nil), pkgs...),
			}
			if keyPath != "" {
				priv, err := manifest.LoadPrivateKey(keyPath)
				if err != nil {
					return fmt.Errorf("load signing key: %w", err)
				}
				pub := priv.Public().(ed25519.PublicKey)
				cand.PublicKeyB64 = base64.StdEncoding.EncodeToString(pub)
				cand.PublicKeyID = keyIDFor(pub)
				for i := range cand.Packages {
					if err := signOverlayEntry(&cand.Packages[i], keyPath); err != nil {
						return err
					}
				}
			}
			data, err := json.MarshalIndent(cand, "", "  ")
			if err != nil {
				return err
			}
			data = append(data, '\n')
			var w io.Writer = cmd.OutOrStdout()
			if out != "" {
				if err := manifest.WriteFileAtomic(out, data, 0o644); err != nil {
					return err
				}
				signed := "unsigned"
				if cand.PublicKeyID != "" {
					signed = "signed by " + cand.PublicKeyID
				}
				fmt.Fprintf(cmd.OutOrStdout(), "Wrote %d-rule candidate (%s) to %s\n", len(cand.Packages), signed, out)
				return nil
			}
			_, err = w.Write(data)
			return err
		},
	}
	c.Flags().StringVar(&dir, "dir", "", "project directory (default: cwd)")
	c.Flags().StringVar(&out, "out", "", "write the candidate to this file (default: stdout)")
	c.Flags().StringVar(&only, "package", "", "submit only this package's rule (default: all)")
	c.Flags().StringVar(&keyPath, "key", "", "Ed25519 private key to sign the candidate for provenance")
	return c
}

// cleanList trims and drops empty entries from a comma-separated flag.
func cleanList(in []string) []string {
	var out []string
	for _, s := range in {
		if t := strings.TrimSpace(s); t != "" {
			out = append(out, t)
		}
	}
	return out
}
