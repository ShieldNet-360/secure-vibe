// Package manifest reads, writes, and signs the root manifest.json that
// drives the Skills Library update protocol.
//
// The manifest is a JSON document listing every distributable file with its
// SHA-256 checksum and size. The "signature" field carries an Ed25519
// signature over the manifest with that field excluded; the public key is
// either declared inline (public_key_id) and looked up via the embedded key,
// or the verification helper accepts an explicit key.
//
// All file-system writes go through atomic.WriteFile so that a crash in the
// middle of an update never leaves the library in a half-applied state.
package manifest

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
)

// SignaturePrefix is the canonical algorithm tag every signature carries.
const SignaturePrefix = "ed25519:"

// PlaceholderSignature is what scaffolded manifests use before a real
// signing key has been applied. ComputeChecksums and VerifyManifest both
// treat it as "no signature yet" rather than as a malformed signature.
const PlaceholderSignature = "TBD"

// File is a single file entry in the manifest.
type File struct {
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	Size      int64  `json:"size"`
	Action    string `json:"action,omitempty"`
	DeltaFrom string `json:"delta_from,omitempty"`
	DeltaSHA  string `json:"delta_sha256,omitempty"`
	DeltaSize int64  `json:"delta_size,omitempty"`
}

// Manifest is the typed root manifest.json structure.
//
// PreviousVersion is `any` because legacy manifests sometimes encode null and
// sometimes a string; we tolerate both on read and round-trip safely.
type Manifest struct {
	SchemaVersion   string `json:"schema_version"`
	Version         string `json:"version"`
	PreviousVersion any    `json:"previous_version,omitempty"`
	ReleasedAt      string `json:"released_at"`
	Signature       string `json:"signature,omitempty"`
	PublicKeyID     string `json:"public_key_id,omitempty"`
	Description     string `json:"description,omitempty"`
	Files           []File `json:"files,omitempty"`
}

// Load reads and decodes the manifest file at path.
func Load(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return LoadBytes(data)
}

// LoadBytes decodes an already-fetched manifest JSON payload.
func LoadBytes(data []byte) (*Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("invalid manifest JSON: %w", err)
	}
	return &m, nil
}

// Save renders the manifest to JSON and writes it atomically to path.
func (m *Manifest) Save(path string) error {
	data, err := m.MarshalIndent()
	if err != nil {
		return err
	}
	return WriteFileAtomic(path, data, 0o644)
}

// MarshalIndent renders the manifest with the same two-space indentation the
// repository uses for its checked-in manifest.json, so editing via the CLI
// does not produce noisy diffs.
func (m *Manifest) MarshalIndent() ([]byte, error) {
	buf, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	// Append trailing newline for POSIX-friendly diffs.
	return append(buf, '\n'), nil
}

// FileByPath returns a pointer to the File entry with the given path, or nil.
func (m *Manifest) FileByPath(path string) *File {
	for i := range m.Files {
		if m.Files[i].Path == path {
			return &m.Files[i]
		}
	}
	return nil
}

// SortFiles orders the file list by path. Deterministic order is required
// for stable diffs, stable delta patches, and stable signatures.
func (m *Manifest) SortFiles() {
	sort.Slice(m.Files, func(i, j int) bool { return m.Files[i].Path < m.Files[j].Path })
}

// Clone returns a deep copy of the manifest.
func (m *Manifest) Clone() *Manifest {
	out := *m
	out.Files = append([]File(nil), m.Files...)
	return &out
}
