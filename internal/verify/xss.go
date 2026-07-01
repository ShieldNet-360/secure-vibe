package verify

import (
	"html"
	"net/http"
	"strings"
)

// XSSProbe verifies reflected XSS: inject a unique marker payload and check
// whether it is reflected into the response UNESCAPED (angle brackets/quotes
// survive intact). Raw reflection ⇒ confirmed; HTML-escaped reflection ⇒
// refuted (output encoding is working); no reflection ⇒ refuted.
//
// This is the lightweight reflection oracle (no browser): it catches reflected
// XSS and misses DOM-only XSS. The stronger upgrade is a headless-browser
// oracle (Playwright/chromedp) that checks ACTUAL JS execution — deferred.
type XSSProbe struct{}

func (XSSProbe) Kind() string { return "xss" }

// payload breaks out of both attribute and text contexts; alert() is harmless.
func (XSSProbe) payload(nonce string) string {
	return `"'><svg/onload=alert(` + nonce + `)>`
}

func (p XSSProbe) Plan(f Finding, _ string) Plan {
	u, _ := buildURL(f, f.Param, p.payload("NONCE"))
	return Plan{Summary: methodOf(f) + " " + u + "   [" + f.Param + " = " + p.payload("NONCE") + "]"}
}

func (p XSSProbe) Execute(f Finding, env *Env) Result {
	r := Result{}
	nonce := newNonce()
	pl := p.payload(nonce)

	u, err := buildURL(f, f.Param, pl)
	if err != nil {
		r.Evidence = "build url: " + err.Error()
		return r
	}
	req, err := http.NewRequest(methodOf(f), u, nil)
	if err != nil {
		r.Evidence = "build request: " + err.Error()
		return r
	}
	applyHeaders(req, f)

	_, body, err := env.do(req)
	if err != nil {
		r.Evidence = "request error (inconclusive): " + err.Error()
		return r
	}

	switch {
	case strings.Contains(body, pl):
		r.Confirmed = true
		r.Evidence = "reflected UNESCAPED: payload appears raw in the response (executable) — reflected XSS"
	case strings.Contains(body, html.EscapeString(pl)):
		r.Refuted = true
		r.Evidence = "reflected but HTML-escaped — output encoding is working"
	default:
		r.Refuted = true
		r.Evidence = "payload not reflected (param may not reach an HTML sink)"
	}
	return r
}

func init() { Register(XSSProbe{}) }
