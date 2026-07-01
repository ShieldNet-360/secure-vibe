package updater

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/shieldnet-360/secure-vibe/cmd/secure-vibe/internal/manifest"
)

// stagedRelease creates a directory containing a signed manifest plus files
// listed in it. It returns the directory, the verifying public key, and the
// produced manifest object.
func stagedRelease(t *testing.T, files map[string]string, version string) (string, []byte, *manifest.Manifest) {
	t.Helper()
	dir := t.TempDir()
	for rel, body := range files {
		full := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	pub, priv, err := manifest.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	m := &manifest.Manifest{
		SchemaVersion: "1.0",
		Version:       version,
		ReleasedAt:    "2026-05-12T00:00:00Z",
		PublicKeyID:   "test-key",
	}
	for rel, body := range files {
		sum := sha256.Sum256([]byte(body))
		m.Files = append(m.Files, manifest.File{
			Path:   rel,
			SHA256: hex.EncodeToString(sum[:]),
			Size:   int64(len(body)),
		})
	}
	m.SortFiles()
	if err := m.SignWith(priv); err != nil {
		t.Fatal(err)
	}
	if err := m.Save(filepath.Join(dir, "manifest.json")); err != nil {
		t.Fatal(err)
	}
	return dir, pub, m
}

// localLibrary builds a writable library root populated with v1 of files.
func localLibrary(t *testing.T, files map[string]string, version string) (string, *manifest.Manifest) {
	t.Helper()
	dir := t.TempDir()
	for rel, body := range files {
		full := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	m := &manifest.Manifest{
		SchemaVersion: "1.0",
		Version:       version,
		ReleasedAt:    "2026-05-12T00:00:00Z",
	}
	for rel, body := range files {
		sum := sha256.Sum256([]byte(body))
		m.Files = append(m.Files, manifest.File{
			Path:   rel,
			SHA256: hex.EncodeToString(sum[:]),
			Size:   int64(len(body)),
		})
	}
	m.SortFiles()
	if err := m.Save(filepath.Join(dir, "manifest.json")); err != nil {
		t.Fatal(err)
	}
	return dir, m
}

func TestCheckOnlyReportsDiff(t *testing.T) {
	remoteFiles := map[string]string{
		"skills/a/SKILL.md":      "updated content",
		"vulnerabilities/x.json": `{"k":1}`,
		"skills/c/SKILL.md":      "brand new",
	}
	srcDir, pub, _ := stagedRelease(t, remoteFiles, "v2")
	localFiles := map[string]string{
		"skills/a/SKILL.md":      "original content",
		"vulnerabilities/x.json": `{"k":1}`,
		"skills/b/SKILL.md":      "going away",
	}
	localRoot, _ := localLibrary(t, localFiles, "v1")
	src, err := NewSource(srcDir)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	res, err := CheckOnly(localRoot, src, Options{PublicKey: pub})
	if err != nil {
		t.Fatal(err)
	}
	actions := map[string]string{}
	for _, c := range res.Changes {
		actions[c.Path] = c.Action
	}
	if actions["skills/a/SKILL.md"] != "updated" {
		t.Errorf("skills/a should be updated: %+v", actions)
	}
	if actions["skills/c/SKILL.md"] != "added" {
		t.Errorf("skills/c should be added: %+v", actions)
	}
	if actions["skills/b/SKILL.md"] != "removed" {
		t.Errorf("skills/b should be removed: %+v", actions)
	}
	if _, ok := actions["vulnerabilities/x.json"]; ok {
		t.Errorf("unchanged file should not appear in diff: %+v", actions)
	}
}

func TestApplyVerifiesAndAtomicallyRenames(t *testing.T) {
	remoteFiles := map[string]string{
		"skills/a/SKILL.md": "updated content",
		"skills/c/SKILL.md": "brand new",
	}
	srcDir, pub, _ := stagedRelease(t, remoteFiles, "v2")
	localFiles := map[string]string{
		"skills/a/SKILL.md": "original content",
		"skills/b/SKILL.md": "going away",
	}
	localRoot, _ := localLibrary(t, localFiles, "v1")
	src, err := NewSource(srcDir)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	res, err := Apply(localRoot, src, Options{PublicKey: pub})
	if err != nil {
		t.Fatal(err)
	}
	// New version on disk.
	gotA, _ := os.ReadFile(filepath.Join(localRoot, "skills/a/SKILL.md"))
	if string(gotA) != "updated content" {
		t.Errorf("expected updated content for a: %q", gotA)
	}
	gotC, _ := os.ReadFile(filepath.Join(localRoot, "skills/c/SKILL.md"))
	if string(gotC) != "brand new" {
		t.Errorf("expected brand new for c: %q", gotC)
	}
	if _, err := os.Stat(filepath.Join(localRoot, "skills/b/SKILL.md")); !os.IsNotExist(err) {
		t.Errorf("skills/b should have been removed; err=%v", err)
	}
	// Backup contains the previous version.
	prevA, _ := os.ReadFile(filepath.Join(localRoot, BackupDirName, "skills/a/SKILL.md"))
	if string(prevA) != "original content" {
		t.Errorf("backup of a not preserved: %q", prevA)
	}
	prevB, _ := os.ReadFile(filepath.Join(localRoot, BackupDirName, "skills/b/SKILL.md"))
	if string(prevB) != "going away" {
		t.Errorf("backup of b not preserved: %q", prevB)
	}
	if res.RemoteManifest.Version != "v2" {
		t.Errorf("manifest version mismatch: %s", res.RemoteManifest.Version)
	}
}

func TestApplyRejectsTamperedFile(t *testing.T) {
	remoteFiles := map[string]string{"skills/a/SKILL.md": "promised content"}
	srcDir, pub, _ := stagedRelease(t, remoteFiles, "v2")
	// Tamper: overwrite the file body on the source after the manifest has
	// been signed. The recorded checksum no longer matches.
	if err := os.WriteFile(filepath.Join(srcDir, "skills/a/SKILL.md"), []byte("MALICIOUS"), 0o644); err != nil {
		t.Fatal(err)
	}
	localRoot, _ := localLibrary(t, map[string]string{"skills/a/SKILL.md": "old"}, "v1")
	src, err := NewSource(srcDir)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	if _, err := Apply(localRoot, src, Options{PublicKey: pub}); err == nil {
		t.Fatal("Apply should fail when a file's checksum does not match the signed manifest")
	}
	// Original is intact.
	got, _ := os.ReadFile(filepath.Join(localRoot, "skills/a/SKILL.md"))
	if string(got) != "old" {
		t.Errorf("file was modified despite checksum failure: %q", got)
	}
}

func TestRollbackRestoresPrevious(t *testing.T) {
	remoteFiles := map[string]string{"skills/a/SKILL.md": "updated"}
	srcDir, pub, _ := stagedRelease(t, remoteFiles, "v2")
	localFiles := map[string]string{"skills/a/SKILL.md": "original"}
	localRoot, _ := localLibrary(t, localFiles, "v1")
	src, err := NewSource(srcDir)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	if _, err := Apply(localRoot, src, Options{PublicKey: pub}); err != nil {
		t.Fatal(err)
	}
	if err := Rollback(localRoot); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(filepath.Join(localRoot, "skills/a/SKILL.md"))
	if string(got) != "original" {
		t.Errorf("rollback did not restore original: %q", got)
	}
	if _, err := os.Stat(filepath.Join(localRoot, BackupDirName)); !os.IsNotExist(err) {
		t.Errorf("backup dir should be gone after rollback: %v", err)
	}
}

func TestRollbackRemovesAddedFiles(t *testing.T) {
	// Remote has a file the local tree does not, so Apply will add it.
	// After Rollback, the file must be gone again.
	remoteFiles := map[string]string{
		"skills/a/SKILL.md":        "existed before",
		"vulnerabilities/new.json": "brand new",
	}
	srcDir, pub, _ := stagedRelease(t, remoteFiles, "v2")
	localFiles := map[string]string{
		"skills/a/SKILL.md": "existed before",
	}
	localRoot, _ := localLibrary(t, localFiles, "v1")
	src, err := NewSource(srcDir)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()

	res, err := Apply(localRoot, src, Options{PublicKey: pub})
	if err != nil {
		t.Fatal(err)
	}
	var added int
	for _, c := range res.Changes {
		if c.Action == "added" {
			added++
		}
	}
	if added != 1 {
		t.Fatalf("expected 1 added change, got %d (%+v)", added, res.Changes)
	}

	addedPath := filepath.Join(localRoot, "vulnerabilities/new.json")
	if _, err := os.Stat(addedPath); err != nil {
		t.Fatalf("added file should exist post-Apply: %v", err)
	}

	if err := Rollback(localRoot); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(addedPath); !os.IsNotExist(err) {
		t.Errorf("Rollback must remove file added by Apply; stat err = %v", err)
	}
	// And the unchanged file must remain intact at its pre-Apply content.
	got, _ := os.ReadFile(filepath.Join(localRoot, "skills/a/SKILL.md"))
	if string(got) != "existed before" {
		t.Errorf("Rollback corrupted unchanged file: %q", got)
	}
}

func TestUnsignedManifestPolicy(t *testing.T) {
	// Build an unsigned remote: same shape as stagedRelease but without
	// calling SignWith.
	dir := t.TempDir()
	body := "hello"
	if err := os.MkdirAll(filepath.Join(dir, "skills/a"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "skills/a/SKILL.md"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(body))
	m := &manifest.Manifest{Version: "v2", Files: []manifest.File{
		{Path: "skills/a/SKILL.md", SHA256: hex.EncodeToString(sum[:]), Size: int64(len(body))},
	}}
	if err := m.Save(filepath.Join(dir, "manifest.json")); err != nil {
		t.Fatal(err)
	}
	src, err := NewSource(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	localRoot, _ := localLibrary(t, map[string]string{}, "v1")

	// Case 1: no public key + unsigned manifest = rejected. There is no
	// way to authenticate the bytes, so the updater must refuse rather
	// than silently install attacker-controlled content. The only
	// permitted bypass is the explicit SkipSignature opt-in (Case 3).
	if _, err := CheckOnly(localRoot, src, Options{}); err == nil {
		t.Errorf("no key + unsigned must be rejected without SkipSignature")
	}
	// Case 2: explicit public key + unsigned manifest = rejected.
	pub, _, err := manifest.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CheckOnly(localRoot, src, Options{PublicKey: pub}); err == nil {
		t.Errorf("explicit key + unsigned should be rejected")
	}
	// Case 3: SkipSignature overrides everything, including the
	// no-key/no-signature path. This is the only intentional bypass.
	if _, err := CheckOnly(localRoot, src, Options{SkipSignature: true}); err != nil {
		t.Errorf("SkipSignature should override no-key/unsigned: %v", err)
	}
	if _, err := CheckOnly(localRoot, src, Options{PublicKey: pub, SkipSignature: true}); err != nil {
		t.Errorf("SkipSignature should override: %v", err)
	}
}

func TestHTTPSourceServesManifestAndFiles(t *testing.T) {
	files := map[string]string{"skills/a/SKILL.md": "updated"}
	srcDir, pub, _ := stagedRelease(t, files, "v2")
	server := httptest.NewServer(http.FileServer(http.Dir(srcDir)))
	defer server.Close()

	localRoot, _ := localLibrary(t, map[string]string{}, "v1")
	src, err := NewSource(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	res, err := Apply(localRoot, src, Options{PublicKey: pub})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Changes) != 1 || res.Changes[0].Action != "added" {
		t.Errorf("expected 1 added change, got %+v", res.Changes)
	}
	got, _ := os.ReadFile(filepath.Join(localRoot, "skills/a/SKILL.md"))
	if string(got) != "updated" {
		t.Errorf("file body mismatch: %q", got)
	}
}

func TestTarballSourceExtractsAndVerifies(t *testing.T) {
	files := map[string]string{"skills/a/SKILL.md": "tarball content"}
	srcDir, pub, _ := stagedRelease(t, files, "v2")
	// Build a .tar.gz from srcDir.
	archive := filepath.Join(t.TempDir(), "release.tar.gz")
	f, err := os.Create(archive)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	err = filepath.Walk(srcDir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(srcDir, p)
		if rel == "." {
			return nil
		}
		hdr := &tar.Header{
			Name: filepath.ToSlash(rel),
			Mode: int64(info.Mode().Perm()),
			Size: info.Size(),
		}
		if info.IsDir() {
			hdr.Typeflag = tar.TypeDir
			hdr.Name = filepath.ToSlash(rel) + "/"
			return tw.WriteHeader(hdr)
		}
		hdr.Typeflag = tar.TypeReg
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		body, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		_, err = tw.Write(body)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	localRoot, _ := localLibrary(t, map[string]string{}, "v1")
	src, err := NewSource(archive)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(src.Description(), "tarball:") {
		t.Errorf("expected tarball source description, got %q", src.Description())
	}
	defer src.Close()
	if _, err := Apply(localRoot, src, Options{PublicKey: pub}); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(filepath.Join(localRoot, "skills/a/SKILL.md"))
	if string(got) != "tarball content" {
		t.Errorf("file body mismatch: %q", got)
	}
}

func TestExtractTarballRejectsOversizedEntry(t *testing.T) {
	saved := MaxTarballEntrySize
	MaxTarballEntrySize = 16
	t.Cleanup(func() { MaxTarballEntrySize = saved })

	dir := t.TempDir()
	archive := filepath.Join(dir, "bomb.tar")
	f, err := os.Create(archive)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(f)
	body := strings.Repeat("A", 64)
	hdr := &tar.Header{
		Name:     "big.bin",
		Mode:     0o644,
		Size:     int64(len(body)),
		Typeflag: tar.TypeReg,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(dir, "out")
	if err := ExtractTarball(archive, dest); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Errorf("expected oversized entry rejection, got %v", err)
	}
}

// TestExtractTarballRejectsUnsafePaths exercises the filepath.IsLocal guard
// inside ExtractTarball. The check must reject parent-directory escapes,
// POSIX absolute paths, and (on Windows) drive-rooted paths so a tarball
// fetched via `--source` cannot write outside the destination directory.
// Drive-letter paths are tested only on Windows because filepath.IsLocal
// is platform-aware: on Linux, "C:\\foo" is a normal filename and is
// correctly treated as local.
func TestExtractTarballRejectsUnsafePaths(t *testing.T) {
	type tc struct {
		name string
		path string
	}
	cases := []tc{
		{"parent", "../escaped"},
		{"posix-absolute", "/etc/passwd"},
		{"embedded-parent", "skills/../../etc/passwd"},
	}
	if runtime.GOOS == "windows" {
		cases = append(cases,
			tc{"windows-absolute-backslash", `C:\Windows\evil.dll`},
			tc{"windows-absolute-forwardslash", "C:/Windows/evil.dll"},
		)
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			archive := filepath.Join(dir, "evil.tar")
			f, err := os.Create(archive)
			if err != nil {
				t.Fatal(err)
			}
			tw := tar.NewWriter(f)
			body := "x"
			if err := tw.WriteHeader(&tar.Header{
				Name:     c.path,
				Mode:     0o644,
				Size:     int64(len(body)),
				Typeflag: tar.TypeReg,
			}); err != nil {
				t.Fatal(err)
			}
			if _, err := tw.Write([]byte(body)); err != nil {
				t.Fatal(err)
			}
			if err := tw.Close(); err != nil {
				t.Fatal(err)
			}
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
			dest := filepath.Join(dir, "out")
			err = ExtractTarball(archive, dest)
			if err == nil {
				t.Fatalf("expected unsafe path rejection for %q, got nil", c.path)
			}
			if !strings.Contains(err.Error(), "unsafe path") {
				t.Errorf("expected 'unsafe path' error for %q, got %v", c.path, err)
			}
		})
	}
}

func TestApplyRejectsPathTraversal(t *testing.T) {
	// Forge a release dir whose manifest lists a file outside the source
	// root. Sign it so verifyRemoteSignature passes. Apply must refuse to
	// write because the destination resolves outside localRoot.
	srcDir := t.TempDir()
	body := "malicious"
	sum := sha256.Sum256([]byte(body))

	pub, priv, err := manifest.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	m := &manifest.Manifest{
		SchemaVersion: "1.0",
		Version:       "v2",
		ReleasedAt:    "2026-05-12T00:00:00Z",
		PublicKeyID:   "test-key",
		Files: []manifest.File{{
			Path:   "../escaped",
			SHA256: hex.EncodeToString(sum[:]),
			Size:   int64(len(body)),
		}},
	}
	if err := m.SignWith(priv); err != nil {
		t.Fatal(err)
	}
	if err := m.Save(filepath.Join(srcDir, "manifest.json")); err != nil {
		t.Fatal(err)
	}

	localRoot, _ := localLibrary(t, map[string]string{}, "v1")
	src, err := NewSource(srcDir)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()

	_, err = Apply(localRoot, src, Options{PublicKey: pub})
	if err == nil {
		t.Fatal("Apply must reject manifest with path traversal")
	}
	if !strings.Contains(err.Error(), "unsafe path") {
		t.Fatalf("expected 'unsafe path' error, got: %v", err)
	}
	// Nothing should have been written next to localRoot either.
	escaped := filepath.Join(filepath.Dir(localRoot), "escaped")
	if _, err := os.Stat(escaped); !os.IsNotExist(err) {
		t.Errorf("traversal write reached %s; stat err = %v", escaped, err)
	}
}

func TestDirSourceFileRejectsTraversal(t *testing.T) {
	// DirSource.File must refuse a relative path that escapes the source
	// root, even when the caller is the updater itself.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(`{"schema_version":"1.0"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	// Put a real file outside the source root that the traversal would
	// otherwise read.
	outside := filepath.Join(filepath.Dir(dir), "outside.txt")
	if err := os.WriteFile(outside, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(outside)

	src, err := NewDirSource(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{
		"../outside.txt",
		"/etc/passwd",
		"",
		"a/../../outside.txt",
	} {
		if rc, err := src.File(p); err == nil {
			rc.Close()
			t.Errorf("DirSource.File(%q) should have failed", p)
		}
	}
}

func TestSafeJoinRejectsEscapes(t *testing.T) {
	root := filepath.Join(t.TempDir(), "root")
	cases := []struct {
		name string
		path string
		want bool // true == must reject
	}{
		{"empty", "", true},
		{"parent", "../etc/passwd", true},
		{"absolute", "/etc/passwd", true},
		{"hidden parent", "skills/../../etc/passwd", true},
		{"normal", "skills/a/SKILL.md", false},
		{"deep", "skills/a/b/c.md", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := safeJoin(root, tc.path)
			if tc.want {
				if err == nil {
					t.Errorf("safeJoin(%q) should error; got %q", tc.path, got)
				}
				return
			}
			if err != nil {
				t.Errorf("safeJoin(%q) unexpected error: %v", tc.path, err)
			}
			if !strings.HasPrefix(got, root+string(filepath.Separator)) && got != root {
				t.Errorf("safeJoin(%q) = %q, not rooted at %q", tc.path, got, root)
			}
		})
	}
}

func TestFormatChangesEmptyHasTrailingNewline(t *testing.T) {
	got := FormatChanges(nil)
	if !strings.HasSuffix(got, "\n") {
		t.Errorf("empty FormatChanges should end with newline, got %q", got)
	}
}

func TestFormatChangesIsStable(t *testing.T) {
	c := []Change{
		{Path: "b", Action: "added"},
		{Path: "a", Action: "added"},
		{Path: "c", Action: "updated"},
	}
	got := FormatChanges(c)
	if !strings.Contains(got, "2 added, 1 updated, 0 removed") {
		t.Errorf("unexpected summary line: %q", got)
	}
}

// oversizedSource serves a body much larger than the manifest's declared
// Size for every file. It is the minimal hostile Source for proving that
// the LimitReader inside applyOne keeps the process from being OOM'd
// before the SHA-256 check rejects the response.
type oversizedSource struct{ DirSource }

func (o *oversizedSource) File(path string) (io.ReadCloser, error) {
	// Always serve a 4 MiB payload regardless of what the manifest says.
	// 4 MiB is comfortably above the LimitReader slack (4 KiB) so the
	// SHA-256 check is the only thing that can fire.
	return io.NopCloser(strings.NewReader(strings.Repeat("X", 4<<20))), nil
}
func (o *oversizedSource) Description() string { return "oversized:test" }
func (o *oversizedSource) Close() error        { return nil }

// TestApplyLimitsReadAllToManifestSize ensures applyOne caps the body
// read at the manifest's declared Size plus a small slack. Without the
// cap, a malicious source could serve gigabytes for a path the manifest
// says is small and exhaust process memory before the SHA-256 check
// runs. With the cap, the truncated body fails the SHA-256 check
// (because hash(truncated XXXX...) != hash(real body)).
func TestApplyLimitsReadAllToManifestSize(t *testing.T) {
	files := map[string]string{"skills/a/SKILL.md": "real body"}
	dir, pub, _ := stagedRelease(t, files, "v2")
	localRoot, _ := localLibrary(t, map[string]string{}, "v1")

	// Wrap the legitimate DirSource so .Manifest() returns the signed
	// manifest with the real (small) declared Size, but .File() returns
	// a 4 MiB body.
	base, err := NewDirSource(dir)
	if err != nil {
		t.Fatal(err)
	}
	src := &oversizedSource{DirSource: *base}

	_, err = Apply(localRoot, src, Options{PublicKey: pub})
	if err == nil {
		t.Fatal("expected Apply to reject oversized body, got nil error")
	}
	if !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Errorf("expected sha256 mismatch error (body truncated by LimitReader), got %v", err)
	}
}

// TestHTTPTarballSourceRoundtrip proves the default update channel works
// end-to-end: an httptest server publishes a .tar.gz at
// /secure-vibe-data.tar.gz, NewSource routes to NewHTTPTarballSource,
// the bundle is downloaded + extracted, and Apply writes the unpacked
// files into the local library root.
func TestHTTPTarballSourceRoundtrip(t *testing.T) {
	files := map[string]string{
		"skills/a/SKILL.md":                   "bundled skill body",
		"vulnerabilities/supply-chain/x.json": `{"k":"v"}`,
	}
	srcDir, pub, _ := stagedRelease(t, files, "v2")

	// Build the data bundle the release workflow would publish: a gzip
	// tarball whose top level contains manifest.json plus the staged
	// distributable tree.
	archive := filepath.Join(t.TempDir(), "secure-vibe-data.tar.gz")
	f, err := os.Create(archive)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	err = filepath.Walk(srcDir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(srcDir, p)
		if rel == "." {
			return nil
		}
		hdr := &tar.Header{
			Name: filepath.ToSlash(rel),
			Mode: int64(info.Mode().Perm()),
			Size: info.Size(),
		}
		if info.IsDir() {
			hdr.Typeflag = tar.TypeDir
			hdr.Name = filepath.ToSlash(rel) + "/"
			return tw.WriteHeader(hdr)
		}
		hdr.Typeflag = tar.TypeReg
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		body, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		_, err = tw.Write(body)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []io.Closer{tw, gz, f} {
		if err := c.Close(); err != nil {
			t.Fatal(err)
		}
	}

	// Serve the archive at /secure-vibe-data.tar.gz so NewSource
	// matches the .tar.gz suffix and dispatches to the HTTP-tarball
	// path.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/secure-vibe-data.tar.gz" {
			http.NotFound(w, r)
			return
		}
		http.ServeFile(w, r, archive)
	}))
	defer server.Close()

	url := server.URL + "/secure-vibe-data.tar.gz"
	src, err := NewSource(url)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	if !strings.HasPrefix(src.Description(), "tarball:") {
		t.Errorf("expected tarball source description, got %q", src.Description())
	}

	localRoot, _ := localLibrary(t, map[string]string{}, "v1")
	res, err := Apply(localRoot, src, Options{PublicKey: pub})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Changes) != 2 {
		t.Errorf("expected 2 added changes, got %+v", res.Changes)
	}
	got, _ := os.ReadFile(filepath.Join(localRoot, "skills/a/SKILL.md"))
	if string(got) != "bundled skill body" {
		t.Errorf("file body mismatch: %q", got)
	}
}
