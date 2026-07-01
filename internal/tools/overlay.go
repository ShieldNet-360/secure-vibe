package tools

import (
	"encoding/json"
	"os"
	"strings"
	"sync"
)

// OverlaySource is the Source value carried by every finding that came
// from a local contribution overlay rather than the curated, centrally
// reviewed database. Downstream consumers (scan_dependencies confidence
// banding, gate output) key on this to label the provenance honestly:
// an overlay entry is user-asserted, not central-canon.
const OverlaySource = "local-overlay"

// OverlayFile is the on-disk shape of a contribution overlay
// (.secure-vibe/overlay.json). It is the LEARN loop's "private half":
// a developer records a bad package locally so the gate blocks it
// immediately — the entry never leaves the machine unless they also run
// `contribute submit`. Committing the file to a repo shares the block
// with the whole team (herd immunity within a project) without going
// through the central pipeline.
//
// The schema is deliberately a strict subset of the curated
// malicious-packages format so an overlay entry flows through exactly
// the same LookupVulnerability matching, version-range filtering, and
// gate enforcement as a canonical row — there is no second code path to
// keep in sync.
type OverlayFile struct {
	SchemaVersion     string           `json:"schema_version"`
	GeneratedBy       string           `json:"generated_by,omitempty"`
	MaliciousPackages []OverlayPackage `json:"malicious_packages"`
}

// OverlayPackage is one user-contributed bad-package rule.
type OverlayPackage struct {
	Name             string   `json:"name"`
	Ecosystem        string   `json:"ecosystem"`
	VersionsAffected []string `json:"versions_affected,omitempty"`
	Severity         string   `json:"severity,omitempty"`
	Type             string   `json:"type,omitempty"`
	Description      string   `json:"description,omitempty"`
	References       []string `json:"references,omitempty"`
	// Reason is the contributor's free-text justification ("saw it
	// exfiltrate env vars in CI on 2026-06-20"). It is surfaced in the
	// finding so a teammate hitting the block understands why.
	Reason string `json:"reason,omitempty"`
	// Contributor / Added record provenance for the local audit trail
	// and for a future `submit` to attribute the candidate.
	Contributor string `json:"contributor,omitempty"`
	Added       string `json:"added,omitempty"`
	// Signature / PublicKeyID are optional Ed25519 provenance over the
	// entry's canonical content, set when the contributor signs. They
	// are advisory for a purely-local overlay (the file is the user's
	// own) and become meaningful when the entry is shared via `submit`.
	Signature   string `json:"signature,omitempty"`
	PublicKeyID string `json:"public_key_id,omitempty"`
}

// toVulnEntry projects an overlay rule onto the canonical VulnEntry the
// matcher consumes. An unset severity defaults to "high" so a freshly
// contributed block fails the default gate floor; an unset
// versions_affected defaults to ["any"] so the block applies to every
// installed version until the contributor narrows it.
func (p OverlayPackage) toVulnEntry() VulnEntry {
	sev := strings.TrimSpace(p.Severity)
	if sev == "" {
		sev = "high"
	}
	versions := p.VersionsAffected
	if len(versions) == 0 {
		versions = []string{"any"}
	}
	typ := strings.TrimSpace(p.Type)
	if typ == "" {
		typ = "locally_flagged"
	}
	desc := strings.TrimSpace(p.Description)
	if desc == "" {
		desc = strings.TrimSpace(p.Reason)
	}
	if desc == "" {
		desc = "Flagged in the local contribution overlay (.secure-vibe/overlay.json)"
	}
	return VulnEntry{
		Name:             p.Name,
		VersionsAffected: versions,
		Severity:         sev,
		Type:             typ,
		Description:      desc,
		References:       p.References,
		Ecosystem:        strings.ToLower(strings.TrimSpace(p.Ecosystem)),
		Source:           OverlaySource,
	}
}

// overlayCache memoises the merged overlay so repeated LookupVulnerability
// calls within one process do not re-read the files. Keyed on the Library
// like the other per-instance caches.
type overlayCache struct {
	mu     sync.Mutex
	loaded bool
	merged []OverlayPackage
}

var overlayCaches sync.Map // *Library -> *overlayCache

func (l *Library) overlay() *overlayCache {
	if v, ok := overlayCaches.Load(l); ok {
		return v.(*overlayCache)
	}
	v, _ := overlayCaches.LoadOrStore(l, &overlayCache{})
	return v.(*overlayCache)
}

// loadOverlayPackages reads and merges every configured overlay path. A
// missing or malformed file is skipped (an overlay is optional and must
// never break a scan); later paths override earlier ones on a
// (name, ecosystem) collision so a project-local rule can supersede a
// user-global one. The result is memoised per Library.
func (l *Library) loadOverlayPackages() []OverlayPackage {
	oc := l.overlay()
	oc.mu.Lock()
	defer oc.mu.Unlock()
	if oc.loaded {
		return oc.merged
	}
	oc.loaded = true

	type key struct{ name, eco string }
	order := []key{}
	byKey := map[key]OverlayPackage{}
	for _, path := range l.overlayPaths {
		if strings.TrimSpace(path) == "" {
			continue
		}
		body, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var of OverlayFile
		if json.Unmarshal(body, &of) != nil {
			continue
		}
		for _, p := range of.MaliciousPackages {
			if strings.TrimSpace(p.Name) == "" {
				continue
			}
			k := key{
				name: strings.ToLower(strings.TrimSpace(p.Name)),
				eco:  strings.ToLower(strings.TrimSpace(p.Ecosystem)),
			}
			if _, seen := byKey[k]; !seen {
				order = append(order, k)
			}
			byKey[k] = p
		}
	}
	merged := make([]OverlayPackage, 0, len(order))
	for _, k := range order {
		merged = append(merged, byKey[k])
	}
	oc.merged = merged
	return merged
}

// overlayMatches returns the overlay rules that apply to (pkg, version)
// in the given ecosystem, projected onto VulnEntry. An empty ecosystem
// matches any ecosystem (the caller's "all ecosystems" sweep); a
// non-empty one filters to that ecosystem. Version-range filtering
// reuses the same versionInAnyRangeEco logic as the curated DB.
func (l *Library) overlayMatches(eco, pkg, version string) []VulnEntry {
	pkgs := l.loadOverlayPackages()
	if len(pkgs) == 0 {
		return nil
	}
	eco = strings.ToLower(strings.TrimSpace(eco))
	var out []VulnEntry
	for _, p := range pkgs {
		if !strings.EqualFold(strings.TrimSpace(p.Name), pkg) {
			continue
		}
		pEco := strings.ToLower(strings.TrimSpace(p.Ecosystem))
		if eco != "" && pEco != "" && pEco != eco {
			continue
		}
		ent := p.toVulnEntry()
		if version != "" && len(ent.VersionsAffected) > 0 {
			matchEco := pEco
			if matchEco == "" {
				matchEco = eco
			}
			if !versionInAnyRangeEco(matchEco, version, ent.VersionsAffected) {
				continue
			}
		}
		out = append(out, ent)
	}
	return out
}
