package tools

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/shieldnet-360/secure-vibe/internal/tools/semver"
)

// osvAffected is the subset of one `affected[]` element of an OSV
// record that we need to decide whether a resolved package version is
// in range. The on-disk OSV schema carries much more (database_specific
// payloads, source URLs, ecosystem-specific extras); we decode only the
// package coordinates, the explicit version enumeration, and the
// introduced/fixed/last_affected range events.
//
// See https://ossf.github.io/osv-schema/#affected-fields.
type osvAffected struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Ranges   []osvRange `json:"ranges"`
	Versions []string   `json:"versions"`
}

// osvRange is one `affected[].ranges[]` element.
type osvRange struct {
	Type   string     `json:"type"`
	Events []osvEvent `json:"events"`
}

// osvEvent is one ordered range event. Exactly one of the three fields
// is set per the OSV schema.
type osvEvent struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
}

// osvRecordFile is the minimal projection of an on-disk OSV record used
// for version-range filtering.
type osvRecordFile struct {
	Affected []osvAffected `json:"affected"`
}

// loadOSVAffected reads and memoises the `affected[]` section of the
// per-advisory record at <osvDir>/<file>. A missing or malformed
// record returns nil, which lookupOSV treats as "cannot evaluate —
// keep the advisory" (fail open). The cache key matches osvSeverity's
// "<ecosystem>/<file>" convention so the two lazy record readers stay
// aligned.
func (l *Library) loadOSVAffected(eco, file string) []osvAffected {
	if file == "" {
		return nil
	}
	// Defence in depth: an OSV record lives as a flat file in the
	// ecosystem directory, so its index-declared name must be a bare
	// base name. Reject anything carrying a path separator or "..", so a
	// tampered index.json cannot redirect the read outside the OSV tree.
	if file != filepath.Base(file) || strings.Contains(file, "..") ||
		strings.ContainsAny(file, `/\`) {
		return nil
	}
	cacheKey := eco + "/" + file
	l.osvRecordMu.Lock()
	if cached, ok := l.osvRecord[cacheKey]; ok {
		l.osvRecordMu.Unlock()
		return cached
	}
	l.osvRecordMu.Unlock()

	var affected []osvAffected
	path := filepath.Join(l.osvDir(eco), file)
	if body, err := os.ReadFile(path); err == nil {
		var rec osvRecordFile
		if json.Unmarshal(body, &rec) == nil {
			affected = rec.Affected
		}
	}

	l.osvRecordMu.Lock()
	l.osvRecord[cacheKey] = affected
	l.osvRecordMu.Unlock()
	return affected
}

// osvVersionStatus is the outcome of checking a resolved version
// against an advisory's affected ranges.
type osvVersionStatus int

const (
	// osvUnknown — the record carries no ranges/versions we can
	// evaluate for this ecosystem (unsupported grammar, empty data, or
	// an unreadable record). The caller should fail open: keep the
	// advisory but leave it version-unconfirmed.
	osvUnknown osvVersionStatus = iota
	// osvInRange — the version falls inside an affected range or is
	// listed in the explicit affected-versions enumeration. The finding
	// is version-confirmed.
	osvInRange
	// osvNotAffected — every affected entry for this package was
	// evaluable and none covered the version (e.g. the version is the
	// fixed release). The advisory should be dropped.
	osvNotAffected
)

// osvVersionAffected decides whether `version` of `pkg` (in ecosystem
// `eco`) is affected by the advisory described by `affected`.
//
// Evaluation only trusts an affected entry whose package name matches
// `pkg`. For each such entry it consults the explicit `versions` list
// first (an exact, unambiguous signal), then the ECOSYSTEM/SEMVER
// ranges using the native semver matcher. A range is only considered
// when every one of its bound comparisons parses for this ecosystem;
// if any bound is unparseable the entry contributes osvUnknown rather
// than a false "not affected", so we never silently drop a real
// advisory because the grammar was richer than our matcher.
func osvVersionAffected(eco, pkg, version string, affected []osvAffected) osvVersionStatus {
	version = strings.TrimSpace(version)
	if version == "" || len(affected) == 0 {
		return osvUnknown
	}
	sawEvaluable := false
	for _, a := range affected {
		if a.Package.Name != "" && !strings.EqualFold(a.Package.Name, pkg) {
			continue
		}
		// Explicit affected-versions enumeration: an exact membership
		// hit is authoritative.
		for _, v := range a.Versions {
			if strings.EqualFold(strings.TrimSpace(v), version) {
				return osvInRange
			}
		}
		if len(a.Versions) > 0 {
			sawEvaluable = true
		}
		for _, r := range a.Ranges {
			// Only ECOSYSTEM/SEMVER ranges are version-comparable; GIT
			// ranges reference commit hashes and are skipped.
			if r.Type != "" && r.Type != "ECOSYSTEM" && r.Type != "SEMVER" {
				continue
			}
			inRange, evaluable := osvRangeAffects(eco, version, r.Events)
			if evaluable {
				sawEvaluable = true
				if inRange {
					return osvInRange
				}
			}
		}
	}
	if sawEvaluable {
		return osvNotAffected
	}
	return osvUnknown
}

// osvRangeAffects evaluates one OSV range's ordered event list against
// `version`. It returns (inRange, evaluable). evaluable is false when
// any bound comparison could not be parsed for this ecosystem, so the
// caller can fall open instead of trusting a partial evaluation.
//
// Per the OSV spec, events are processed in their given order: an
// `introduced` bound opens the affected interval, and a later `fixed`
// or `last_affected` bound closes it. "introduced": "0" means "from the
// beginning of time". This faithfully handles the common single
// [introduced, fixed) pair as well as multiple disjoint intervals
// expressed as one event stream.
func osvRangeAffects(eco, version string, events []osvEvent) (inRange, evaluable bool) {
	affected := false
	for _, ev := range events {
		switch {
		case ev.Introduced != "":
			if ev.Introduced == "0" {
				affected = true
				continue
			}
			ge, ok := versionAtLeast(eco, version, ev.Introduced)
			if !ok {
				return false, false
			}
			if ge {
				affected = true
			}
		case ev.Fixed != "":
			ge, ok := versionAtLeast(eco, version, ev.Fixed)
			if !ok {
				return false, false
			}
			if ge {
				affected = false
			}
		case ev.LastAffected != "":
			gt, ok := versionGreater(eco, version, ev.LastAffected)
			if !ok {
				return false, false
			}
			if gt {
				affected = false
			}
		}
	}
	return affected, true
}

// versionAtLeast reports whether version >= bound for the ecosystem,
// returning ok=false when the native matcher cannot parse either side.
func versionAtLeast(eco, version, bound string) (ge, ok bool) {
	return semver.Match(eco, ">="+bound, version)
}

// versionGreater reports whether version > bound for the ecosystem,
// returning ok=false when the native matcher cannot parse either side.
func versionGreater(eco, version, bound string) (gt, ok bool) {
	return semver.Match(eco, ">"+bound, version)
}
