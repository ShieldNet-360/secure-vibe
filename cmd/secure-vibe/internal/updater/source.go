// Package updater implements the remote-update protocol for Skills Library.
//
// The update flow is:
//
//  1. Resolve a Source from --source (HTTP URL, directory, or tarball).
//  2. Fetch the remote manifest.
//  3. Verify the manifest's Ed25519 signature (when a public key is available).
//  4. Diff against the local manifest; collect "added" and "updated" files.
//  5. For each changed file: download, verify the SHA-256, write to a sibling
//     temp file, and rename into place. Any failure aborts before the next
//     file is touched.
//  6. On full success, swap the manifest into place atomically.
//
// The previous on-disk copy of each replaced file is backed up under
// ".secure-vibe-previous/" so --rollback can restore it without re-fetching.
package updater

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/shieldnet-360/secure-vibe/cmd/secure-vibe/internal/manifest"
)

// Source abstracts where a manifest and its referenced files come from. The
// updater interacts only with this interface, so adding a new transport
// (S3, sftp, devin sandbox, etc.) means writing one Source implementation.
type Source interface {
	// Manifest returns the freshly fetched root manifest.
	Manifest() (*manifest.Manifest, error)
	// File opens the named file (relative to the source root). The caller
	// owns the returned ReadCloser.
	File(path string) (io.ReadCloser, error)
	// Description is a human-readable string for logs ("https://...",
	// "tarball:/path", etc.).
	Description() string
	// Close releases any resources held by the source (extracted tarball
	// directories, open HTTP clients, etc.).
	Close() error
}

// NewSource parses a source string and returns the appropriate Source. The
// rules:
//
//   - "https://..." or "http://..." ending in .tar.gz/.tgz → HTTPTarballSource
//   - "https://..." or "http://..."                        → HTTPSource
//   - "file:///..."                                        → DirSource(stripped)
//   - <path>.tar.gz / .tgz                                 → TarballSource(extracted)
//   - <directory path>                                     → DirSource
func NewSource(spec string) (Source, error) {
	if spec == "" {
		return nil, errors.New("source is empty")
	}
	if strings.HasPrefix(spec, "http://") || strings.HasPrefix(spec, "https://") {
		if strings.HasSuffix(spec, ".tar.gz") || strings.HasSuffix(spec, ".tgz") {
			return NewHTTPTarballSource(spec)
		}
		return NewHTTPSource(spec)
	}
	if strings.HasPrefix(spec, "file://") {
		parsed, err := url.Parse(spec)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", spec, err)
		}
		return NewDirSource(parsed.Path)
	}
	if strings.HasSuffix(spec, ".tar.gz") || strings.HasSuffix(spec, ".tgz") {
		return NewTarballSource(spec)
	}
	st, err := os.Stat(spec)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", spec, err)
	}
	if !st.IsDir() {
		// Fall back to tarball if the file ends in a recognised archive ext.
		if strings.HasSuffix(spec, ".tar") {
			return NewTarballSource(spec)
		}
		return nil, fmt.Errorf("source %s is neither a directory nor a recognised archive", spec)
	}
	return NewDirSource(spec)
}

// DirSource reads manifest.json and files from a local directory tree.
type DirSource struct {
	Root string
}

// NewDirSource constructs a DirSource and verifies the manifest exists.
func NewDirSource(root string) (*DirSource, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(filepath.Join(abs, "manifest.json")); err != nil {
		return nil, fmt.Errorf("source %s does not contain manifest.json: %w", abs, err)
	}
	return &DirSource{Root: abs}, nil
}

func (d *DirSource) Manifest() (*manifest.Manifest, error) {
	return manifest.Load(filepath.Join(d.Root, "manifest.json"))
}

func (d *DirSource) File(path string) (io.ReadCloser, error) {
	abs, err := safeJoin(d.Root, path)
	if err != nil {
		return nil, err
	}
	return os.Open(abs)
}

func (d *DirSource) Description() string { return "dir:" + d.Root }
func (d *DirSource) Close() error        { return nil }

// HTTPSource fetches manifest.json and files from a base URL.
// When BearerToken is non-empty, every request is sent with an
// Authorization: Bearer <token> header, enabling authenticated pulls from
// private repositories.
type HTTPSource struct {
	Base        string
	BearerToken string
	Headers     map[string]string
	Client      *http.Client
}

// NewHTTPSource constructs an HTTPSource with sensible defaults.
func NewHTTPSource(base string) (*HTTPSource, error) {
	if _, err := url.Parse(base); err != nil {
		return nil, fmt.Errorf("parse %s: %w", base, err)
	}
	base = strings.TrimRight(base, "/")
	return &HTTPSource{
		Base:   base,
		Client: &http.Client{Timeout: 60 * time.Second},
	}, nil
}

func (h *HTTPSource) Manifest() (*manifest.Manifest, error) {
	body, err := h.fetch("manifest.json")
	if err != nil {
		return nil, err
	}
	defer body.Close()
	data, err := io.ReadAll(body)
	if err != nil {
		return nil, err
	}
	var m manifest.Manifest
	if err := unmarshalManifest(data, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

func (h *HTTPSource) File(path string) (io.ReadCloser, error) {
	return h.fetch(path)
}

func (h *HTTPSource) Description() string { return h.Base }
func (h *HTTPSource) Close() error        { return nil }

func (h *HTTPSource) fetch(path string) (io.ReadCloser, error) {
	if h.Client == nil {
		h.Client = http.DefaultClient
	}
	target := h.Base + "/" + strings.TrimLeft(path, "/")
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "secure-vibe/updater")
	if h.BearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+h.BearerToken)
	}
	for k, v := range h.Headers {
		req.Header.Set(k, v)
	}
	resp, err := h.Client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("GET %s: HTTP %d (authentication failed; check bearer token)", target, resp.StatusCode)
	}
	if resp.StatusCode/100 != 2 {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("GET %s: HTTP %d", target, resp.StatusCode)
	}
	return resp.Body, nil
}

// NewHTTPSourceWithAuth returns an HTTPSource that authenticates each request
// with the supplied bearer token. The token may be empty, in which case this
// behaves identically to NewHTTPSource.
//
// When the token is non-empty, the base URL MUST use https://. A plaintext
// http:// scheme combined with a bearer token would leak the credential on
// every request. The check is also enforced at config-write time
// (cmd.ValidateSourceWithToken); this is the defence-in-depth second line.
// Operators that explicitly accept the risk for internal-only setups can
// use NewHTTPSourceWithAuthInsecure.
func NewHTTPSourceWithAuth(base, bearerToken string) (*HTTPSource, error) {
	if bearerToken != "" && strings.HasPrefix(base, "http://") {
		return nil, fmt.Errorf(
			"refusing to attach bearer token to plaintext http:// source %q; "+
				"use https:// (recommended) or NewHTTPSourceWithAuthInsecure to opt in",
			base,
		)
	}
	s, err := NewHTTPSource(base)
	if err != nil {
		return nil, err
	}
	s.BearerToken = bearerToken
	return s, nil
}

// NewHTTPSourceWithAuthInsecure is the explicit escape hatch for internal
// networks that legitimately serve over plaintext http:// and want to
// authenticate the updater. Use only when the network boundary itself
// provides confidentiality.
func NewHTTPSourceWithAuthInsecure(base, bearerToken string) (*HTTPSource, error) {
	s, err := NewHTTPSource(base)
	if err != nil {
		return nil, err
	}
	s.BearerToken = bearerToken
	return s, nil
}

// TarballSource extracts a tar (optionally gzipped) archive to a temp dir
// on construction and serves files from there. Close removes the temp dir.
type TarballSource struct {
	Archive string
	tmp     *DirSource
}

// NewTarballSource extracts the named archive and returns a Source backed by
// the extracted directory.
func NewTarballSource(archive string) (*TarballSource, error) {
	tmp, err := os.MkdirTemp("", "secure-vibe-tarball-*")
	if err != nil {
		return nil, err
	}
	if err := ExtractTarball(archive, tmp); err != nil {
		_ = os.RemoveAll(tmp)
		return nil, err
	}
	dir, err := NewDirSource(tmp)
	if err != nil {
		_ = os.RemoveAll(tmp)
		return nil, err
	}
	return &TarballSource{Archive: archive, tmp: dir}, nil
}

func (t *TarballSource) Manifest() (*manifest.Manifest, error) { return t.tmp.Manifest() }
func (t *TarballSource) File(path string) (io.ReadCloser, error) {
	return t.tmp.File(path)
}
func (t *TarballSource) Description() string { return "tarball:" + t.Archive }
func (t *TarballSource) Close() error        { return os.RemoveAll(t.tmp.Root) }

// MaxTarballEntrySize caps the number of bytes ExtractTarball will copy for
// any single regular file in the archive. It is a defence-in-depth guard
// against tar bombs that pad a single entry to exhaust disk or memory; the
// signed manifest is the primary check that any extracted file is legitimate.
//
// Declared as a var (rather than a const) so tests can lower the limit
// without writing hundreds of megabytes to disk. Production builds should
// not mutate this value.
var MaxTarballEntrySize int64 = 512 * 1024 * 1024 // 512 MiB

// ExtractTarball expands the named archive into dest. It auto-detects gzip
// based on extension. Path traversal is rejected and each regular file is
// limited to MaxTarballEntrySize bytes.
func ExtractTarball(archive, dest string) error {
	f, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer f.Close()

	var r io.Reader = f
	if strings.HasSuffix(archive, ".gz") || strings.HasSuffix(archive, ".tgz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return fmt.Errorf("gzip: %w", err)
		}
		defer gz.Close()
		r = gz
	}
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		clean := filepath.Clean(filepath.FromSlash(hdr.Name))
		if !filepath.IsLocal(clean) {
			return fmt.Errorf("rejecting tar entry with unsafe path: %s", hdr.Name)
		}
		target := filepath.Join(dest, clean)
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		// tar.Reader normalises the legacy GNU regular-file type
		// (the old '\x00' / TypeRegA) to TypeReg on read, so a single
		// TypeReg case covers both modern and legacy archives.
		case tar.TypeReg:
			if hdr.Size > MaxTarballEntrySize {
				return fmt.Errorf("tar entry %s exceeds %d byte limit (declared size %d)", hdr.Name, MaxTarballEntrySize, hdr.Size)
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, os.FileMode(hdr.Mode)&0o644|0o600)
			if err != nil {
				return err
			}
			limited := io.LimitReader(tr, MaxTarballEntrySize+1)
			written, err := io.Copy(out, limited)
			if err != nil {
				_ = out.Close()
				return err
			}
			if written > MaxTarballEntrySize {
				_ = out.Close()
				return fmt.Errorf("tar entry %s exceeded %d byte limit while reading", hdr.Name, MaxTarballEntrySize)
			}
			if err := out.Close(); err != nil {
				return err
			}
		}
	}
}

// MaxHTTPTarballBytes caps how many bytes NewHTTPTarballSource will copy
// from the remote response into the on-disk archive before extracting it.
// This is a defence-in-depth guard against a malicious or compromised
// release host serving an arbitrarily large body; the per-entry size
// guard inside ExtractTarball and the SHA-256 check against the signed
// manifest in applyOne are the deeper checks.
//
// Declared as a var (not a const) so tests can lower the limit without
// allocating gigabytes. Production builds should not mutate this value.
var MaxHTTPTarballBytes int64 = 1 << 30 // 1 GiB

// NewHTTPTarballSource downloads a .tar.gz/.tgz archive from rawURL into
// a temp file, extracts it via NewTarballSource (which validates entry
// paths and per-entry size), and returns the resulting Source. The
// temp archive is removed after extraction; only the extracted
// directory tree remains, and Close() removes that too.
//
// This is the canonical channel for the default update source: the
// release workflow publishes a single secure-vibe-data.tar.gz
// containing manifest.json plus the distributable tree, so the updater
// can pull the whole library in one HTTP request rather than 404ing
// on per-file paths that are not published as release assets.
func NewHTTPTarballSource(rawURL string) (*TarballSource, error) {
	if _, err := url.Parse(rawURL); err != nil {
		return nil, fmt.Errorf("parse %s: %w", rawURL, err)
	}
	client := &http.Client{Timeout: 5 * time.Minute}
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "secure-vibe/updater")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", rawURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("GET %s: HTTP %d", rawURL, resp.StatusCode)
	}

	tmpFile, err := os.CreateTemp("", "secure-vibe-download-*.tar.gz")
	if err != nil {
		return nil, err
	}
	tmpPath := tmpFile.Name()
	// Always remove the on-disk archive: NewTarballSource extracts it
	// to a separate temp dir, so we no longer need the archive after
	// construction succeeds (or fails).
	defer os.Remove(tmpPath)

	// Cap the body read so a hostile source cannot exhaust local disk.
	// We allow one extra byte so that a body that is exactly the limit
	// succeeds while a body even one byte larger surfaces as an error.
	limited := io.LimitReader(resp.Body, MaxHTTPTarballBytes+1)
	n, err := io.Copy(tmpFile, limited)
	if cerr := tmpFile.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", rawURL, err)
	}
	if n > MaxHTTPTarballBytes {
		return nil, fmt.Errorf("download %s exceeded %d byte limit", rawURL, MaxHTTPTarballBytes)
	}

	return NewTarballSource(tmpPath)
}

// unmarshalManifest is a thin wrapper so the package keeps a single import
// path for the manifest type without circular references.
func unmarshalManifest(data []byte, into *manifest.Manifest) error {
	tmp, err := manifest.LoadBytes(data)
	if err != nil {
		return err
	}
	*into = *tmp
	return nil
}
