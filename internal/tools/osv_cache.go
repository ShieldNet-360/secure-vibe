package tools

import (
	"strings"
	"sync"
	"time"
)

// DefaultOSVCacheTTL is how long a single Query result is reused before
// the cache treats it as stale and re-queries OSV.dev. Five minutes is
// short enough that a freshly-published advisory shows up the same
// session, but long enough that a tight loop (e.g. scan_dependencies
// walking a 200-row lockfile that repeats packages) doesn't hammer the
// upstream API or burn its 1000-req/hr free-tier limit.
const DefaultOSVCacheTTL = 5 * time.Minute

// OSVCache is an in-memory TTL cache keyed by (ecosystem, package,
// version). It is safe for concurrent use.
//
// Cache misses are not stored — the dispatcher decides whether to
// fall back to local data, and we don't want a single network failure
// to poison the cache with empty entries.
//
// Disk persistence is intentionally not part of Phase 1 — the MCP
// server is a per-session subprocess so cross-session reuse buys
// little, and adding the disk layer doubles the test surface
// (corruption, partial writes, multi-process locking). A follow-up PR
// can add it under the same Get/Set interface if benchmarks show RAM
// hit-rate is too low in practice.
type OSVCache struct {
	mu      sync.RWMutex
	entries map[string]osvCacheEntry
	ttl     time.Duration
	now     func() time.Time // injectable for tests
}

type osvCacheEntry struct {
	advisories []OSVAdvisory
	expires    time.Time
}

// NewOSVCache returns an empty cache with the default TTL.
func NewOSVCache() *OSVCache {
	return &OSVCache{
		entries: make(map[string]osvCacheEntry),
		ttl:     DefaultOSVCacheTTL,
		now:     time.Now,
	}
}

// NewOSVCacheWithTTL is the test constructor — pass a short TTL to
// drive expiry behaviour without sleeping.
func NewOSVCacheWithTTL(ttl time.Duration) *OSVCache {
	c := NewOSVCache()
	c.ttl = ttl
	return c
}

// osvCacheKey is the canonical cache key for the (eco, pkg, ver)
// triple. Lower-cased so callers that send "Express" and "express"
// share a slot — matching the case-insensitive contract LookupOSV
// already enforces in the local cache.
func osvCacheKey(eco, pkg, version string) string {
	return strings.ToLower(strings.TrimSpace(eco)) + "|" +
		strings.ToLower(strings.TrimSpace(pkg)) + "|" +
		strings.TrimSpace(version)
}

// Get returns cached advisories for the given triple together with a
// boolean indicating a cache hit. Expired entries are treated as
// misses; the caller is responsible for re-querying and calling Set
// with fresh data.
//
// Get does NOT delete the expired entry — Set will overwrite it on
// the next successful query, and leaving expired entries in place
// avoids contending the write lock for a read-only path. Stale
// entries only accumulate when a key is queried once and never
// again, which is bounded by the working-set size of a single MCP
// session.
func (c *OSVCache) Get(eco, pkg, version string) ([]OSVAdvisory, bool) {
	if c == nil {
		return nil, false
	}
	key := osvCacheKey(eco, pkg, version)
	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()
	if !ok {
		return nil, false
	}
	if c.now().After(entry.expires) {
		return nil, false
	}
	return entry.advisories, true
}

// Set caches the advisories for the given triple with the cache's
// configured TTL. Passing a nil slice caches "no advisories" so a
// negative result is not re-queried on every call.
func (c *OSVCache) Set(eco, pkg, version string, advs []OSVAdvisory) {
	if c == nil {
		return
	}
	key := osvCacheKey(eco, pkg, version)
	c.mu.Lock()
	c.entries[key] = osvCacheEntry{
		advisories: advs,
		expires:    c.now().Add(c.ttl),
	}
	c.mu.Unlock()
}
