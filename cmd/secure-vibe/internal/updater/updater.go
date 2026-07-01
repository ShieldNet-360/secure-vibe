package updater

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/shieldnet-360/secure-vibe/cmd/secure-vibe/internal/manifest"
)

// BackupDirName is where the last applied update stashes the files it
// replaced so --rollback can restore them.
const BackupDirName = ".secure-vibe-previous"

// applyOneReadSlack is the small allowance added on top of a manifest
// entry's declared Size when bounding the response body read in applyOne.
// We allow a few KiB of slack so transports that frame the body slightly
// differently (HTTP chunked encoding, trailers, etc.) don't fail the
// honest case, while still defeating OOM-style abuse where a malicious
// source serves gigabytes for a path the manifest claims is small. The
// downstream SHA-256 check rejects anything that doesn't match exactly.
const applyOneReadSlack int64 = 4096

// addedPathsManifest is the relative path inside BackupDirName where
// Apply records files that did not exist before the update. Rollback
// reads this list and removes the corresponding files so the on-disk
// tree matches the pre-update state. The leading dot keeps the file
// out of any future manifest walk, and the underscore-prefixed segment
// avoids any collision with a real file path slugged through
// filepath.Join.
const addedPathsManifest = "_added_paths.txt"

// Options control how Apply behaves. All fields are optional.
type Options struct {
	// PublicKey, when set, is used to verify the remote manifest's
	// signature. If nil, the embedded key in the manifest package is used.
	PublicKey ed25519.PublicKey
	// SkipSignature disables signature verification entirely. Intended for
	// tests and the rare bootstrap case where no key exists yet. The user
	// must opt in explicitly.
	SkipSignature bool
}

// Change describes one file the updater will modify when Apply is called.
type Change struct {
	Path   string
	Action string // "added", "updated", "removed"
	From   string
	To     string
	Size   int64
}

// CheckResult is what CheckOnly returns: the new manifest fetched from the
// source plus the list of changes that would be applied.
type CheckResult struct {
	Source         Source
	RemoteManifest *manifest.Manifest
	Changes        []Change
}

// CheckOnly fetches the remote manifest, verifies its signature, and returns
// the diff against the local manifest. No filesystem changes are made.
func CheckOnly(localRoot string, src Source, opts Options) (*CheckResult, error) {
	local, err := loadLocalManifest(localRoot)
	if err != nil {
		return nil, err
	}
	remote, err := src.Manifest()
	if err != nil {
		return nil, fmt.Errorf("fetch remote manifest: %w", err)
	}
	if err := verifyRemoteSignature(remote, opts); err != nil {
		return nil, err
	}
	return &CheckResult{
		Source:         src,
		RemoteManifest: remote,
		Changes:        diffManifests(local, remote),
	}, nil
}

// Apply downloads every changed file, verifies its SHA-256, and atomically
// renames it into place. The previous on-disk content is moved into
// BackupDirName so a later --rollback can restore it.
func Apply(localRoot string, src Source, opts Options) (*CheckResult, error) {
	res, err := CheckOnly(localRoot, src, opts)
	if err != nil {
		return nil, err
	}
	backupRoot := filepath.Join(localRoot, BackupDirName)
	// Clean a stale backup so the rollback set is always exactly the
	// previous applied update.
	if err := os.RemoveAll(backupRoot); err != nil && !os.IsNotExist(err) {
		return res, fmt.Errorf("reset backup dir: %w", err)
	}

	var added []string
	for _, change := range res.Changes {
		switch change.Action {
		case "added":
			if err := applyOne(localRoot, backupRoot, src, change, res.RemoteManifest); err != nil {
				return res, fmt.Errorf("apply %s: %w", change.Path, err)
			}
			added = append(added, change.Path)
		case "updated":
			if err := applyOne(localRoot, backupRoot, src, change, res.RemoteManifest); err != nil {
				return res, fmt.Errorf("apply %s: %w", change.Path, err)
			}
		case "removed":
			if err := backupExisting(localRoot, backupRoot, change.Path); err != nil {
				return res, fmt.Errorf("backup remove %s: %w", change.Path, err)
			}
			abs, err := safeJoin(localRoot, change.Path)
			if err != nil {
				return res, fmt.Errorf("remove %s: %w", change.Path, err)
			}
			if err := os.Remove(abs); err != nil && !os.IsNotExist(err) {
				return res, fmt.Errorf("remove %s: %w", change.Path, err)
			}
		}
	}
	if len(added) > 0 {
		if err := writeAddedManifest(backupRoot, added); err != nil {
			return res, fmt.Errorf("record added paths: %w", err)
		}
	}

	// Swap manifest into place atomically, but only after every file has
	// been written successfully — see "verify-before-replace" in
	// ARCHITECTURE.md.
	mfPath := filepath.Join(localRoot, "manifest.json")
	// Backup old manifest too.
	if err := backupExisting(localRoot, backupRoot, "manifest.json"); err != nil {
		return res, fmt.Errorf("backup manifest: %w", err)
	}
	if err := res.RemoteManifest.Save(mfPath); err != nil {
		return res, fmt.Errorf("write manifest: %w", err)
	}
	return res, nil
}

// Rollback restores files from BackupDirName, undoing the most recent
// Apply. Files that the previous Apply *added* (i.e. did not exist
// before) are removed entirely so the on-disk tree matches the
// pre-update state.
func Rollback(localRoot string) error {
	backupRoot := filepath.Join(localRoot, BackupDirName)
	st, err := os.Stat(backupRoot)
	if err != nil {
		if os.IsNotExist(err) {
			return errors.New("no previous update to roll back from")
		}
		return err
	}
	if !st.IsDir() {
		return fmt.Errorf("%s is not a directory", backupRoot)
	}
	added, err := readAddedManifest(backupRoot)
	if err != nil {
		return fmt.Errorf("read added-paths manifest: %w", err)
	}
	for _, rel := range added {
		dst, err := safeJoin(localRoot, rel)
		if err != nil {
			return fmt.Errorf("remove added file %s: %w", rel, err)
		}
		if err := os.Remove(dst); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove added file %s: %w", rel, err)
		}
	}
	err = filepath.Walk(backupRoot, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(backupRoot, p)
		if err != nil {
			return err
		}
		if filepath.ToSlash(rel) == addedPathsManifest {
			return nil
		}
		dst, err := safeJoin(localRoot, filepath.ToSlash(rel))
		if err != nil {
			return err
		}
		return manifest.CopyFileAtomic(p, dst, info.Mode())
	})
	if err != nil {
		return err
	}
	return os.RemoveAll(backupRoot)
}

// writeAddedManifest persists the list of files Apply newly created so
// Rollback can remove them. One path per line, slash-separated.
func writeAddedManifest(backupRoot string, paths []string) error {
	if err := os.MkdirAll(backupRoot, 0o755); err != nil {
		return err
	}
	sorted := append([]string(nil), paths...)
	sort.Strings(sorted)
	var buf bytes.Buffer
	for _, p := range sorted {
		buf.WriteString(filepath.ToSlash(p))
		buf.WriteByte('\n')
	}
	return manifest.WriteFileAtomic(filepath.Join(backupRoot, addedPathsManifest), buf.Bytes(), 0o644)
}

// readAddedManifest loads the list of paths Apply previously created.
// A missing file means no files were added (older backup format).
func readAddedManifest(backupRoot string) ([]string, error) {
	f, err := os.Open(filepath.Join(backupRoot, addedPathsManifest))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	var out []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		out = append(out, line)
	}
	return out, scanner.Err()
}

// FormatChanges renders the change list as a small human-readable summary.
func FormatChanges(changes []Change) string {
	if len(changes) == 0 {
		return "already up to date\n"
	}
	var added, updated, removed int
	for _, c := range changes {
		switch c.Action {
		case "added":
			added++
		case "updated":
			updated++
		case "removed":
			removed++
		}
	}
	out := fmt.Sprintf("%d added, %d updated, %d removed\n", added, updated, removed)
	sorted := append([]Change(nil), changes...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Action != sorted[j].Action {
			return sorted[i].Action < sorted[j].Action
		}
		return sorted[i].Path < sorted[j].Path
	})
	for _, c := range sorted {
		out += fmt.Sprintf("  [%s] %s\n", c.Action, c.Path)
	}
	return out
}

func loadLocalManifest(root string) (*manifest.Manifest, error) {
	path := filepath.Join(root, "manifest.json")
	st, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &manifest.Manifest{Files: nil}, nil
		}
		return nil, err
	}
	if st.IsDir() {
		return nil, fmt.Errorf("%s is a directory", path)
	}
	return manifest.Load(path)
}

func verifyRemoteSignature(m *manifest.Manifest, opts Options) error {
	if opts.SkipSignature {
		return nil
	}
	switch {
	case opts.PublicKey != nil:
		return m.VerifyWith(opts.PublicKey)
	case manifest.HasEmbeddedKey():
		return m.VerifyManifest()
	}
	// No key available at all. Refuse — silently accepting an unsigned
	// (or signed-but-unverifiable) manifest here would let a network
	// attacker substitute arbitrary content. The only intentional
	// bypass is the explicit SkipSignature opt-in handled above.
	return errors.New("no public key available to verify manifest; use --skip-signature to explicitly bypass")
}

func diffManifests(local, remote *manifest.Manifest) []Change {
	localIdx := make(map[string]manifest.File, len(local.Files))
	for _, f := range local.Files {
		localIdx[f.Path] = f
	}
	remoteIdx := make(map[string]manifest.File, len(remote.Files))
	for _, f := range remote.Files {
		remoteIdx[f.Path] = f
	}

	var out []Change
	for _, f := range remote.Files {
		prev, ok := localIdx[f.Path]
		switch {
		case !ok:
			out = append(out, Change{Path: f.Path, Action: "added", To: f.SHA256, Size: f.Size})
		case prev.SHA256 != f.SHA256:
			out = append(out, Change{
				Path: f.Path, Action: "updated", From: prev.SHA256, To: f.SHA256, Size: f.Size,
			})
		}
	}
	for _, f := range local.Files {
		if _, ok := remoteIdx[f.Path]; !ok {
			out = append(out, Change{Path: f.Path, Action: "removed", From: f.SHA256})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

func applyOne(localRoot, backupRoot string, src Source, change Change, remote *manifest.Manifest) error {
	entry := remote.FileByPath(change.Path)
	if entry == nil {
		return fmt.Errorf("manifest is missing file entry for %s", change.Path)
	}
	body, err := src.File(change.Path)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	defer body.Close()
	// Cap the read at the manifest's declared size plus a small slack so
	// the SHA-256 check (which would catch a truncated or oversized body
	// after the fact) can never be reached with a body large enough to
	// OOM the process. A malicious source might serve gigabytes for a
	// path the manifest claims is small; LimitReader bounds the damage.
	limited := io.LimitReader(body, entry.Size+applyOneReadSlack)
	data, err := io.ReadAll(limited)
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}
	got := manifest.HashBytes(data)
	if got != entry.SHA256 {
		return fmt.Errorf("sha256 mismatch (want %s, got %s)", entry.SHA256, got)
	}
	if err := backupExisting(localRoot, backupRoot, change.Path); err != nil {
		return fmt.Errorf("backup: %w", err)
	}
	dst, err := safeJoin(localRoot, change.Path)
	if err != nil {
		return fmt.Errorf("validate path: %w", err)
	}
	return manifest.WriteFileAtomic(dst, data, 0o644)
}

func backupExisting(localRoot, backupRoot, relPath string) error {
	src, err := safeJoin(localRoot, relPath)
	if err != nil {
		return err
	}
	if _, err := os.Stat(src); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	dst, err := safeJoin(backupRoot, relPath)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	return manifest.CopyFileAtomic(src, dst, 0o644)
}

// safeJoin joins relPath (a slash-separated path from a manifest) onto
// root, refusing any relPath that is absolute, contains parent-directory
// segments, or otherwise escapes root. This is a defence against
// malicious manifests that ship paths like "../../etc/cron.d/backdoor":
// the SHA-256 check in applyOne cannot help when the attacker controls
// both the manifest entry and the served bytes.
func safeJoin(root, relPath string) (string, error) {
	if relPath == "" {
		return "", errors.New("path is empty")
	}
	clean := filepath.Clean(filepath.FromSlash(relPath))
	if !filepath.IsLocal(clean) {
		return "", fmt.Errorf("unsafe path %q escapes root", relPath)
	}
	return filepath.Join(root, clean), nil
}
