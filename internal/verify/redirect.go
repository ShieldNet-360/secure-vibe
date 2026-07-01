package verify

import (
	"net/http"
	"net/url"
	"strings"
)

// redirectEvilHost is the attacker destination probes try to bounce to.
const redirectEvilHost = "evil.example.com"

// redirectPayloads include common open-redirect filter bypasses.
func redirectPayloads() []string {
	return []string{
		"https://" + redirectEvilHost + "/",
		"//" + redirectEvilHost + "/",      // scheme-relative
		"https:/" + redirectEvilHost + "/", // missing-slash
	}
}

// RedirectProbe verifies open redirect: set the param to an attacker URL and
// check whether the app issues a 3xx whose Location points to that host.
// It uses a no-follow client so the redirect response itself is observable.
type RedirectProbe struct{}

func (RedirectProbe) Kind() string { return "redirect" }

func (RedirectProbe) Plan(f Finding, _ string) Plan {
	return Plan{Summary: methodOf(f) + " " + f.Target +
		"  [" + f.Param + " = " + redirectPayloads()[0] + " (+ bypass variants)]"}
}

func (RedirectProbe) Execute(f Finding, env *Env) Result {
	r := Result{}
	client := &http.Client{
		Timeout: env.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse // do NOT follow — we want to see the 3xx
		},
	}
	for _, payload := range redirectPayloads() {
		u, err := buildURL(f, f.Param, payload)
		if err != nil {
			continue
		}
		req, err := http.NewRequest(methodOf(f), u, nil)
		if err != nil {
			continue
		}
		applyHeaders(req, f)
		resp, err := client.Do(req.WithContext(env.Ctx))
		if err != nil {
			continue
		}
		loc := resp.Header.Get("Location")
		resp.Body.Close()
		if resp.StatusCode >= 300 && resp.StatusCode < 400 && pointsToHost(loc, redirectEvilHost) {
			r.Confirmed = true
			r.Evidence = "HTTP " + resp.Status + " → Location: " + loc + " (redirects to attacker host)"
			return r
		}
	}
	r.Refuted = true
	r.Evidence = "no payload produced a 3xx Location to the attacker host"
	return r
}

// pointsToHost reports whether a Location header sends the browser to host
// (handles absolute and scheme-relative //host/ forms).
func pointsToHost(loc, host string) bool {
	loc = strings.TrimSpace(loc)
	if loc == "" {
		return false
	}
	if strings.HasPrefix(loc, "//") {
		return strings.HasPrefix(strings.TrimPrefix(loc, "//"), host)
	}
	u, err := url.Parse(loc)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Hostname(), host)
}

func init() { Register(RedirectProbe{}) }
