package manifest

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
)

// DeltaEntry describes a single change in a delta patch. The action is one
// of "added", "updated", "removed".
type DeltaEntry struct {
	Path       string `json:"path"`
	Action     string `json:"action"`
	FromSHA256 string `json:"from_sha256,omitempty"`
	ToSHA256   string `json:"to_sha256,omitempty"`
	ToSize     int64  `json:"to_size,omitempty"`
}

// Delta is the JSON document written under deltas/<from>-<to>.json that
// describes what changed between two manifest versions.
type Delta struct {
	SchemaVersion string       `json:"schema_version"`
	FromVersion   string       `json:"from_version"`
	ToVersion     string       `json:"to_version"`
	Entries       []DeltaEntry `json:"entries"`
}

// ComputeDelta diffs two manifests and returns the changed-file list.
//
// Both manifests are read by file path. A file present in `to` but not in
// `from` is "added". Present in both with a different SHA-256 is "updated".
// Present in `from` but not in `to` is "removed".
func ComputeDelta(from, to *Manifest) *Delta {
	fromIndex := make(map[string]File, len(from.Files))
	for _, f := range from.Files {
		fromIndex[f.Path] = f
	}
	toIndex := make(map[string]File, len(to.Files))
	for _, f := range to.Files {
		toIndex[f.Path] = f
	}

	var entries []DeltaEntry

	for _, f := range to.Files {
		prev, ok := fromIndex[f.Path]
		switch {
		case !ok:
			entries = append(entries, DeltaEntry{
				Path:     f.Path,
				Action:   "added",
				ToSHA256: f.SHA256,
				ToSize:   f.Size,
			})
		case prev.SHA256 != f.SHA256:
			entries = append(entries, DeltaEntry{
				Path:       f.Path,
				Action:     "updated",
				FromSHA256: prev.SHA256,
				ToSHA256:   f.SHA256,
				ToSize:     f.Size,
			})
		}
	}
	for _, f := range from.Files {
		if _, ok := toIndex[f.Path]; !ok {
			entries = append(entries, DeltaEntry{
				Path:       f.Path,
				Action:     "removed",
				FromSHA256: f.SHA256,
			})
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })

	return &Delta{
		SchemaVersion: "1.0",
		FromVersion:   from.Version,
		ToVersion:     to.Version,
		Entries:       entries,
	}
}

// WriteDeltaFile renders a Delta to JSON and writes it atomically under
// deltasRoot/<from>-<to>.json. The directory is created if it does not exist.
func WriteDeltaFile(d *Delta, deltasRoot string) (string, error) {
	name := fmt.Sprintf("%s-to-%s.json", sanitizeVersion(d.FromVersion), sanitizeVersion(d.ToVersion))
	path := filepath.Join(deltasRoot, name)
	body, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return "", err
	}
	body = append(body, '\n')
	if err := WriteFileAtomic(path, body, 0o644); err != nil {
		return "", err
	}
	return path, nil
}

// sanitizeVersion turns a version like "2026.05.12.1" into something safe
// for use inside a filename across all the operating systems the CLI runs on.
func sanitizeVersion(v string) string {
	if v == "" {
		return "unknown"
	}
	out := make([]byte, 0, len(v))
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c >= '0' && c <= '9':
			out = append(out, c)
		case c >= 'a' && c <= 'z':
			out = append(out, c)
		case c >= 'A' && c <= 'Z':
			out = append(out, c)
		case c == '.' || c == '-' || c == '_':
			out = append(out, c)
		default:
			out = append(out, '_')
		}
	}
	return string(out)
}
