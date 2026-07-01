package manifest

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// DefaultDistributableRoots is the canonical set of top-level paths whose
// contents are signed and shipped via the manifest. Adding a new directory
// here is how new release artifacts join the update channel.
var DefaultDistributableRoots = []string{
	"skills",
	"vulnerabilities",
	"dictionaries",
	"dist",
	"rules",
	"compliance",
	"profiles",
}

// ComputeChecksums walks the configured distributable roots under repoRoot,
// computes the SHA-256 hash of every file, and updates the manifest's Files
// list with the real checksum and size (replacing any "TBD" placeholder).
//
// Files that exist on disk but are missing from the manifest are added with
// action="added". Files present in the manifest but missing from disk are
// preserved verbatim so an operator can see "removed" entries. The list is
// sorted by path on return.
//
// This function intentionally resets m.Signature to PlaceholderSignature
// because the canonical bytes are now stale: callers must re-sign the
// manifest after computing checksums. The release workflow runs
// `manifest compute --write` before the out-of-band signing step.
func (m *Manifest) ComputeChecksums(repoRoot string) error {
	return m.ComputeChecksumsForRoots(repoRoot, DefaultDistributableRoots)
}

// ComputeChecksumsForRoots is the variant that lets callers (for example,
// tests) pin the exact set of roots to walk. It is additive: entries
// already in the manifest that are no longer on disk are left intact.
// Use PruneMissing (or the `manifest compute --prune` CLI flag) when a
// large batch of files has been intentionally removed.
func (m *Manifest) ComputeChecksumsForRoots(repoRoot string, roots []string) error {
	seen := make(map[string]struct{}, len(m.Files))
	for i := range m.Files {
		seen[m.Files[i].Path] = struct{}{}
	}

	// Collect (path, sha256, size) tuples from disk first so we can produce
	// errors before mutating the manifest.
	type entry struct {
		path string
		hash string
		size int64
	}
	var entries []entry

	for _, root := range roots {
		full := filepath.Join(repoRoot, root)
		st, err := os.Stat(full)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("stat %s: %w", full, err)
		}
		if !st.IsDir() {
			continue
		}
		err = filepath.WalkDir(full, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			// Skip dotfiles inside dist/ that get written by macOS et al.
			name := d.Name()
			if strings.HasPrefix(name, ".DS_Store") || strings.HasPrefix(name, ".tmp-") {
				return nil
			}
			rel, err := filepath.Rel(repoRoot, p)
			if err != nil {
				return err
			}
			rel = filepath.ToSlash(rel)
			sum, size, err := HashFile(p)
			if err != nil {
				return err
			}
			entries = append(entries, entry{path: rel, hash: sum, size: size})
			return nil
		})
		if err != nil {
			return fmt.Errorf("walk %s: %w", full, err)
		}
	}

	// Also include any non-root files that happen to live in the repo root
	// itself (currently none) - left as a future hook by intentionally not
	// iterating over the root directly.

	// Sort entries for deterministic order.
	sort.Slice(entries, func(i, j int) bool { return entries[i].path < entries[j].path })

	// Update or append.
	for _, e := range entries {
		if existing := m.FileByPath(e.path); existing != nil {
			existing.SHA256 = e.hash
			existing.Size = e.size
			// e.hash is always non-empty here — HashFile returns an error
			// path for unreadable files and entries with that error are
			// not appended to `entries`. Promote any prior "added" marker
			// to "unchanged" now that we have a recorded hash on disk.
			if existing.Action == "added" {
				existing.Action = "unchanged"
			}
			delete(seen, e.path)
			continue
		}
		m.Files = append(m.Files, File{
			Path:   e.path,
			SHA256: e.hash,
			Size:   e.size,
			Action: "added",
		})
	}
	// Any files that were in the manifest but not found on disk: leave the
	// `seen` set populated with their paths and let the caller decide via
	// PruneMissing whether to drop them. We deliberately do not prune by
	// default to keep `manifest compute` non-destructive when invoked on
	// a partial checkout.
	_ = seen

	m.SortFiles()
	// Invalidate any prior signature: the bytes changed.
	m.Signature = PlaceholderSignature
	return nil
}

// PruneMissing removes entries from m.Files whose paths do not exist
// on disk under repoRoot. Returns the list of removed paths so callers
// can report what was dropped. Use this after a wholesale regeneration
// that intentionally deleted files (for example, swapping the OSV
// stride-sample for a latest-first sample).
func (m *Manifest) PruneMissing(repoRoot string) ([]string, error) {
	var dropped []string
	kept := m.Files[:0]
	for _, f := range m.Files {
		abs := filepath.Join(repoRoot, f.Path)
		if _, err := os.Stat(abs); err == nil {
			kept = append(kept, f)
			continue
		} else if !errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("stat %s: %w", abs, err)
		}
		dropped = append(dropped, f.Path)
	}
	m.Files = kept
	if len(dropped) > 0 {
		m.SortFiles()
		m.Signature = PlaceholderSignature
	}
	return dropped, nil
}

// HashFile returns the lowercase hex SHA-256 and size of the file at path.
func HashFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return "", 0, fmt.Errorf("stat %s: %w", path, err)
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", 0, fmt.Errorf("read %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), st.Size(), nil
}

// HashBytes returns the lowercase hex SHA-256 of an in-memory byte slice.
func HashBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
