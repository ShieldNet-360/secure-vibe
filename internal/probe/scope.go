// Package probe provides the small, scope-gated primitives an AI coding agent
// uses to dynamically verify a security finding: http_probe (send one request to
// an authorized target) and an out-of-band listener (catch blind callbacks). The
// agent crafts the payloads and reads the oracles — guided by the
// dynamic-verification skill — so SecureVibe ships building blocks, not a
// hard-coded verification engine. The scope gate here is the one safety control:
// a probe never fires at a target the operator did not authorize.
package probe

import (
	"encoding/json"
	"net/url"
	"os"
	"path"
	"strings"
)

// Scope is the operator-controlled allow-list that decides where a probe may
// fire and with which auth. It comes from the environment, never from the agent:
//
//   - SECURE_VIBE_VERIFY_SCOPE_FILE — JSON {"targets":[{"match":"host[:port] or
//     path.Match glob","headers":{...}}]} — per-target auth (cookies, bearer).
//   - SECURE_VIBE_VERIFY_SCOPE — a simpler comma-separated host[:port] substring
//     allow-list (no auth).
//
// With neither set, Scope is unconfigured: every probe is dry-run.
type Scope struct {
	targets []scopeTarget
	hosts   []string
}

type scopeTarget struct {
	Match   string            `json:"match"`
	Headers map[string]string `json:"headers"`
}

// LoadScope reads the scope from the environment. An unreadable/invalid scope
// file fails safe (deny-all) rather than opening the gate.
func LoadScope() *Scope {
	s := &Scope{}
	if f := strings.TrimSpace(os.Getenv("SECURE_VIBE_VERIFY_SCOPE_FILE")); f != "" {
		if raw, err := os.ReadFile(f); err == nil {
			var doc struct {
				Targets []scopeTarget `json:"targets"`
			}
			if json.Unmarshal(raw, &doc) == nil {
				s.targets = doc.Targets
			}
		}
	}
	if raw := strings.TrimSpace(os.Getenv("SECURE_VIBE_VERIFY_SCOPE")); raw != "" {
		for _, h := range strings.Split(raw, ",") {
			if h = strings.TrimSpace(h); h != "" {
				s.hosts = append(s.hosts, h)
			}
		}
	}
	return s
}

// Configured reports whether any allow-list entry exists. Unconfigured => every
// probe is dry-run.
func (s *Scope) Configured() bool { return len(s.targets) > 0 || len(s.hosts) > 0 }

// Allows reports whether rawurl's host is in scope.
func (s *Scope) Allows(rawurl string) bool {
	host := hostOf(rawurl)
	if host == "" {
		return false
	}
	for _, t := range s.targets {
		if matchHost(t.Match, host) {
			return true
		}
	}
	for _, h := range s.hosts {
		if strings.Contains(host, h) {
			return true
		}
	}
	return false
}

// Headers returns the operator-configured auth headers for rawurl's target (from
// the scope file), or nil. These are merged into a probe by the caller; the agent
// never supplies auth for an out-of-scope host.
func (s *Scope) Headers(rawurl string) map[string]string {
	host := hostOf(rawurl)
	for _, t := range s.targets {
		if matchHost(t.Match, host) && len(t.Headers) > 0 {
			return t.Headers
		}
	}
	return nil
}

func hostOf(rawurl string) string {
	u, err := url.Parse(rawurl)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Host
}

// matchHost supports path.Match globs against the host plus a plain substring
// fallback, mirroring the old verify scope semantics.
func matchHost(pattern, host string) bool {
	if pattern == "" {
		return false
	}
	if ok, err := path.Match(pattern, host); err == nil && ok {
		return true
	}
	return strings.Contains(host, pattern)
}
