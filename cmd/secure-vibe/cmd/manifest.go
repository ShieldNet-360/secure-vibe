package cmd

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/shieldnet-360/secure-vibe/cmd/secure-vibe/internal/manifest"
)

func manifestCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "manifest",
		Short: "Inspect, recompute, sign, and verify the root manifest.json",
	}
	c.AddCommand(manifestComputeCmd())
	c.AddCommand(manifestVerifyCmd())
	c.AddCommand(manifestSignCmd())
	c.AddCommand(manifestSignFileCmd())
	c.AddCommand(manifestVerifyFileCmd())
	c.AddCommand(manifestDeltaCmd())
	return c
}

func manifestComputeCmd() *cobra.Command {
	var path string
	var write bool
	var prune bool
	c := &cobra.Command{
		Use:   "compute",
		Short: "Walk distributable roots and update manifest.json with real SHA-256 checksums",
		RunE: func(c *cobra.Command, args []string) error {
			root, err := filepath.Abs(resolveLibraryRoot(path))
			if err != nil {
				return err
			}
			mfPath := filepath.Join(root, "manifest.json")
			m, err := manifest.Load(mfPath)
			if err != nil {
				return err
			}
			if err := m.ComputeChecksums(root); err != nil {
				return err
			}
			out := c.OutOrStdout()
			if prune {
				dropped, err := m.PruneMissing(root)
				if err != nil {
					return err
				}
				fmt.Fprintf(out, "prune: removed %d entries no longer present on disk\n", len(dropped))
			}
			fmt.Fprintf(out, "manifest %s: %d files\n", m.Version, len(m.Files))
			if write {
				if err := m.Save(mfPath); err != nil {
					return err
				}
				fmt.Fprintf(out, "wrote %s\n", mfPath)
			} else {
				body, err := m.MarshalIndent()
				if err != nil {
					return err
				}
				if _, err := out.Write(body); err != nil {
					return err
				}
			}
			return nil
		},
	}
	c.Flags().StringVar(&path, "path", ".", "library root (default: $SECURE_VIBE_LIBRARY_PATH, else cwd)")
	c.Flags().BoolVar(&write, "write", false, "write updated manifest.json back to disk")
	c.Flags().BoolVar(&prune, "prune", false, "drop manifest entries whose files no longer exist on disk")
	return c
}

func manifestVerifyCmd() *cobra.Command {
	var path, pubKeyPath string
	var checksumsOnly bool
	c := &cobra.Command{
		Use:   "verify",
		Short: "Verify manifest signature and per-file SHA-256 checksums",
		RunE: func(c *cobra.Command, args []string) error {
			root, err := filepath.Abs(resolveLibraryRoot(path))
			if err != nil {
				return err
			}
			mfPath := filepath.Join(root, "manifest.json")
			m, err := manifest.Load(mfPath)
			if err != nil {
				return err
			}
			out := c.OutOrStdout()
			signed := m.Signature != "" && m.Signature != manifest.PlaceholderSignature
			switch {
			case checksumsOnly:
				// Explicit opt-out from signature verification. This is the
				// mirror of the updater's --skip-signature flag and is the
				// only way to silently accept an unsigned local manifest.
				fmt.Fprintln(out, "signature: skipped")
			case signed:
				switch {
				case pubKeyPath != "":
					pub, err := manifest.LoadPublicKey(pubKeyPath)
					if err != nil {
						return err
					}
					if err := m.VerifyWith(pub); err != nil {
						return err
					}
				case manifest.HasEmbeddedKey():
					if err := m.VerifyManifest(); err != nil {
						return err
					}
				default:
					return fmt.Errorf("manifest is signed but no public key was provided and none is embedded; pass --public-key or --checksums-only")
				}
				fmt.Fprintln(out, "signature: ok")
			default:
				// Unsigned (or placeholder-signature) local manifest with no
				// explicit opt-out. Refuse to silently call this verified;
				// require --checksums-only to acknowledge the bypass. Keeps
				// the CLI consistent with updater.verifyRemoteSignature.
				return fmt.Errorf("manifest is unsigned; pass --checksums-only to verify file hashes only, or sign the manifest with `secure-vibe dev manifest sign`")
			}

			mismatched := 0
			missing := 0
			for _, f := range m.Files {
				abs := filepath.Join(root, f.Path)
				if f.SHA256 == "" || f.SHA256 == manifest.PlaceholderSignature {
					missing++
					fmt.Fprintf(out, "  - %s: no checksum recorded\n", f.Path)
					continue
				}
				gotHash, gotSize, err := manifest.HashFile(abs)
				if err != nil {
					missing++
					fmt.Fprintf(out, "  - %s: %v\n", f.Path, err)
					continue
				}
				if gotHash != f.SHA256 {
					mismatched++
					fmt.Fprintf(out, "  - %s: sha256 mismatch (want %s, got %s)\n", f.Path, f.SHA256, gotHash)
					continue
				}
				if f.Size != 0 && gotSize != f.Size {
					mismatched++
					fmt.Fprintf(out, "  - %s: size mismatch (want %d, got %d)\n", f.Path, f.Size, gotSize)
				}
			}
			fmt.Fprintf(out, "files: %d checked, %d mismatched, %d missing\n", len(m.Files), mismatched, missing)
			if mismatched > 0 || missing > 0 {
				return fmt.Errorf("manifest verification failed (%d mismatched, %d missing)", mismatched, missing)
			}
			return nil
		},
	}
	c.Flags().StringVar(&path, "path", ".", "library root (default: $SECURE_VIBE_LIBRARY_PATH, else cwd)")
	c.Flags().StringVar(&pubKeyPath, "public-key", "", "path to Ed25519 public key (default: embedded)")
	c.Flags().BoolVar(&checksumsOnly, "checksums-only", false, "skip signature verification, only check SHA-256")
	return c
}

func manifestSignCmd() *cobra.Command {
	var path, keyPath string
	c := &cobra.Command{
		Use:   "sign",
		Short: "Sign manifest.json with an Ed25519 private key",
		RunE: func(c *cobra.Command, args []string) error {
			root, err := filepath.Abs(resolveLibraryRoot(path))
			if err != nil {
				return err
			}
			mfPath := filepath.Join(root, "manifest.json")
			m, err := manifest.Load(mfPath)
			if err != nil {
				return err
			}
			if err := m.SignManifest(keyPath); err != nil {
				return err
			}
			if err := m.Save(mfPath); err != nil {
				return err
			}
			fmt.Fprintf(c.OutOrStdout(), "signed manifest %s\n", mfPath)
			return nil
		},
	}
	c.Flags().StringVar(&path, "path", ".", "library root (default: $SECURE_VIBE_LIBRARY_PATH, else cwd)")
	c.Flags().StringVar(&keyPath, "key", "", "path to Ed25519 private key (required)")
	_ = c.MarkFlagRequired("key")
	return c
}

// manifestSignFileCmd writes a detached "<file>.sig" Ed25519 signature for an
// arbitrary release artifact (e.g. a checksums-<goos>-<goarch>.txt file). The
// release manager runs this offline with the release key — the same key that
// signs manifest.json — so the SHA-256 a self-update consumes is anchored to
// the release identity, not to the source that served the binary.
func manifestSignFileCmd() *cobra.Command {
	var keyPath, outPath string
	c := &cobra.Command{
		Use:   "sign-file <file>",
		Short: "Write a detached Ed25519 signature (<file>.sig) for a release artifact",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			priv, err := manifest.LoadPrivateKey(keyPath)
			if err != nil {
				return err
			}
			data, err := os.ReadFile(args[0])
			if err != nil {
				return err
			}
			sig, err := manifest.SignDetached(priv, data)
			if err != nil {
				return err
			}
			if outPath == "" {
				outPath = args[0] + ".sig"
			}
			if err := os.WriteFile(outPath, []byte(sig+"\n"), 0o644); err != nil {
				return err
			}
			fmt.Fprintf(c.OutOrStdout(), "wrote %s\n", outPath)
			return nil
		},
	}
	c.Flags().StringVar(&keyPath, "key", "", "path to Ed25519 private key (required)")
	c.Flags().StringVar(&outPath, "out", "", "output signature path (default: <file>.sig)")
	_ = c.MarkFlagRequired("key")
	return c
}

// manifestVerifyFileCmd verifies a detached "<file>.sig" signature against the
// embedded public key (or an explicit --public-key). The mirror of sign-file,
// and what `self-update` runs against the downloaded checksums file.
func manifestVerifyFileCmd() *cobra.Command {
	var pubKeyPath, sigPath string
	c := &cobra.Command{
		Use:   "verify-file <file>",
		Short: "Verify a detached Ed25519 signature for a release artifact",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			data, err := os.ReadFile(args[0])
			if err != nil {
				return err
			}
			if sigPath == "" {
				sigPath = args[0] + ".sig"
			}
			sigBytes, err := os.ReadFile(sigPath)
			if err != nil {
				return err
			}
			var keys []ed25519.PublicKey
			if pubKeyPath != "" {
				pub, err := manifest.LoadPublicKey(pubKeyPath)
				if err != nil {
					return err
				}
				keys = []ed25519.PublicKey{pub}
			} else {
				keys, err = manifest.TrustedKeys(nil)
				if err != nil {
					return err
				}
				if len(keys) == 0 {
					return fmt.Errorf("no public key embedded in this build; pass --public-key")
				}
			}
			if err := manifest.VerifyDetachedAny(keys, data, strings.TrimSpace(string(sigBytes))); err != nil {
				return err
			}
			fmt.Fprintln(c.OutOrStdout(), "signature: ok")
			return nil
		},
	}
	c.Flags().StringVar(&pubKeyPath, "public-key", "", "path to Ed25519 public key (default: embedded)")
	c.Flags().StringVar(&sigPath, "sig", "", "path to the .sig file (default: <file>.sig)")
	return c
}

func manifestDeltaCmd() *cobra.Command {
	var fromPath, toPath, outDir string
	c := &cobra.Command{
		Use:   "delta",
		Short: "Compute a delta patch between two manifest.json files",
		RunE: func(c *cobra.Command, args []string) error {
			from, err := manifest.Load(fromPath)
			if err != nil {
				return err
			}
			to, err := manifest.Load(toPath)
			if err != nil {
				return err
			}
			delta := manifest.ComputeDelta(from, to)
			absOut, err := filepath.Abs(outDir)
			if err != nil {
				return err
			}
			written, err := manifest.WriteDeltaFile(delta, absOut)
			if err != nil {
				return err
			}
			fmt.Fprintf(c.OutOrStdout(), "wrote delta %s (%d entries)\n", written, len(delta.Entries))
			return nil
		},
	}
	c.Flags().StringVar(&fromPath, "from", "", "path to previous manifest.json")
	c.Flags().StringVar(&toPath, "to", "", "path to current manifest.json")
	c.Flags().StringVar(&outDir, "out", "deltas", "directory to write delta patches")
	_ = c.MarkFlagRequired("from")
	_ = c.MarkFlagRequired("to")
	return c
}
