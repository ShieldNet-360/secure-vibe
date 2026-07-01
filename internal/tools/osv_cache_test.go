package tools

import (
	"testing"
	"time"
)

func TestOSVCacheHitAndMiss(t *testing.T) {
	c := NewOSVCache()
	if _, hit := c.Get("npm", "axios", "0.21.1"); hit {
		t.Fatal("empty cache reported hit")
	}
	advs := []OSVAdvisory{{ID: "GHSA-test", Package: "axios", Ecosystem: "npm"}}
	c.Set("npm", "axios", "0.21.1", advs)
	got, hit := c.Get("npm", "axios", "0.21.1")
	if !hit {
		t.Fatal("set then get: miss")
	}
	if len(got) != 1 || got[0].ID != "GHSA-test" {
		t.Errorf("got %+v, want one GHSA-test entry", got)
	}
}

func TestOSVCacheTTLExpiry(t *testing.T) {
	// Inject a frozen clock so expiry is deterministic — sleeping
	// makes tests slow and flaky.
	c := NewOSVCache()
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	c.now = func() time.Time { return now }
	c.ttl = 5 * time.Minute
	c.Set("npm", "axios", "0.21.1", []OSVAdvisory{{ID: "GHSA-test"}})

	// Still within TTL.
	now = now.Add(4*time.Minute + 59*time.Second)
	if _, hit := c.Get("npm", "axios", "0.21.1"); !hit {
		t.Error("expected hit at 4m59s post-set")
	}

	// One second after TTL.
	now = now.Add(2 * time.Second)
	if _, hit := c.Get("npm", "axios", "0.21.1"); hit {
		t.Error("expected miss at 5m01s post-set")
	}
}

func TestOSVCacheCaseInsensitiveKey(t *testing.T) {
	// Local cache treats package names case-insensitively; the
	// external cache must match so reads stay consistent across the
	// dispatcher's source switch.
	c := NewOSVCache()
	c.Set("npm", "Express", "4.18.0", []OSVAdvisory{{ID: "GHSA-x"}})

	cases := []struct{ eco, pkg, ver string }{
		{"npm", "express", "4.18.0"},
		{"NPM", "EXPRESS", "4.18.0"},
		{"npm", "Express", "4.18.0"},
	}
	for _, c2 := range cases {
		t.Run(c2.eco+"/"+c2.pkg, func(t *testing.T) {
			if _, hit := c.Get(c2.eco, c2.pkg, c2.ver); !hit {
				t.Errorf("Get(%q,%q,%q): expected hit (case folding)", c2.eco, c2.pkg, c2.ver)
			}
		})
	}
}

func TestOSVCacheVersionIsCaseSensitive(t *testing.T) {
	// Versions are case-significant in many ecosystems (Maven's
	// "FINAL" classifier, npm dist-tags). Don't lowercase them.
	c := NewOSVCache()
	c.Set("maven", "spring-core", "5.3.0-RC1", []OSVAdvisory{{ID: "GHSA-x"}})
	if _, hit := c.Get("maven", "spring-core", "5.3.0-rc1"); hit {
		t.Error("version case folding leaked: '5.3.0-rc1' should NOT hit a key stored as '5.3.0-RC1'")
	}
	if _, hit := c.Get("maven", "spring-core", "5.3.0-RC1"); !hit {
		t.Error("exact version case match should hit")
	}
}

func TestOSVCacheNilSliceIsCachedAsNegative(t *testing.T) {
	// Real OSV.dev returns "no advisories" all the time for clean
	// packages. We need to cache that result so a clean dependency
	// doesn't burn an API call on every retry.
	c := NewOSVCache()
	c.Set("npm", "lodash", "4.17.21", nil)
	got, hit := c.Get("npm", "lodash", "4.17.21")
	if !hit {
		t.Fatal("nil-result cache: want hit, got miss")
	}
	if got != nil {
		t.Errorf("nil-result cache: got %v, want nil slice", got)
	}
}

func TestOSVCacheNilReceiverDoesNotPanic(t *testing.T) {
	// Defensive: nil cache acts like a permanent miss / no-op write.
	// Lets call sites elide a nil check without subtle bugs.
	var c *OSVCache
	if _, hit := c.Get("npm", "x", "1"); hit {
		t.Error("nil cache reported hit")
	}
	c.Set("npm", "x", "1", []OSVAdvisory{{ID: "x"}}) // must not panic
}
