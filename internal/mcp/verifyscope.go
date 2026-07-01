package mcp

import (
	"encoding/json"
	"net/url"
	"os"
	"path"
	"strings"
)

// verifyScopeFile is the operator-controlled scope for verify_finding (Cách B):
// a single file OUTSIDE any project repo (chmod 600), pointed to by
// SECURE_VIBE_VERIFY_SCOPE_FILE. It lists the targets a probe may fire at and,
// per target, the auth headers to send. The token lives here (operator's
// machine), never in the scanned repo and never chosen by the model.
//
//	{ "targets": [
//	    { "match": "localhost:4000", "headers": { "Cookie": "connect.sid=..." } },
//	    { "match": "*.staging.myco.com", "headers": { "Authorization": "Bearer ..." } }
//	] }
type verifyScopeFile struct {
	Targets []verifyScopeTarget `json:"targets"`
}

type verifyScopeTarget struct {
	Match   string            `json:"match"`
	Headers map[string]string `json:"headers"`
}

// loadVerifyScope resolves the scope gate + auth headers for verify_finding.
// Precedence:
//  1. SECURE_VIBE_VERIFY_SCOPE_FILE — full scope file with per-target headers.
//  2. SECURE_VIBE_VERIFY_SCOPE      — comma host[:port] allow-list, no auth.
//  3. nothing                      — deny all (dry-run only).
//
// Returns: allow(target), headers(target), and whether any scope is configured.
// A missing/unreadable/invalid file falls back to deny-all (safe), so a
// misconfigured operator never accidentally fires live.
func loadVerifyScope() (allow func(string) bool, headers func(string) map[string]string, scoped bool) {
	deny := func(string) bool { return false }
	none := func(string) map[string]string { return nil }

	if p := strings.TrimSpace(os.Getenv("SECURE_VIBE_VERIFY_SCOPE_FILE")); p != "" {
		data, err := os.ReadFile(p)
		if err != nil {
			return deny, none, false
		}
		var sf verifyScopeFile
		if err := json.Unmarshal(data, &sf); err != nil {
			return deny, none, false
		}
		find := func(target string) (verifyScopeTarget, bool) {
			for _, t := range sf.Targets {
				if t.Match != "" && targetMatches(target, t.Match) {
					return t, true
				}
			}
			return verifyScopeTarget{}, false
		}
		allow = func(target string) bool { _, ok := find(target); return ok }
		headers = func(target string) map[string]string {
			if t, ok := find(target); ok {
				return t.Headers
			}
			return nil
		}
		return allow, headers, len(sf.Targets) > 0
	}

	// Fallback: simple host-list env, no auth headers.
	raw := strings.TrimSpace(os.Getenv("SECURE_VIBE_VERIFY_SCOPE"))
	if raw == "" {
		return deny, none, false
	}
	var allowed []string
	for _, p := range strings.Split(raw, ",") {
		if p = strings.TrimSpace(p); p != "" {
			allowed = append(allowed, p)
		}
	}
	allow = func(target string) bool {
		for _, a := range allowed {
			if strings.Contains(target, a) {
				return true
			}
		}
		return false
	}
	return allow, none, len(allowed) > 0
}

// targetMatches reports whether target is covered by a scope pattern. A pattern
// with wildcards is matched against the target's host (path.Match); every
// pattern also matches as a plain substring of the full target URL.
func targetMatches(target, pattern string) bool {
	if strings.ContainsAny(pattern, "*?[") {
		host := target
		if u, err := url.Parse(target); err == nil && u.Host != "" {
			host = u.Host
		}
		if ok, _ := path.Match(pattern, host); ok {
			return true
		}
	}
	return strings.Contains(target, pattern)
}
