package verify

import (
	"crypto/rand"
	"encoding/hex"
	"net"
	"net/http"
	"strings"
	"sync"
)

// OOBListener is a tiny local HTTP server that records callbacks keyed by the
// requested path. A blind probe smuggles "http://<addr>/<nonce>" into the
// target; if the target dereferences it, the hit is recorded here — proving a
// server-side fetch happened even when nothing is reflected in the response.
type OOBListener struct {
	srv  *http.Server
	ln   net.Listener
	mu   sync.Mutex
	hits map[string]bool
}

// StartOOB binds a listener on a random loopback port. On failure it returns a
// degraded listener (URL() == "") so reflection-based oracles still work.
func StartOOB() *OOBListener {
	o := &OOBListener{hits: map[string]bool{}}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return o
	}
	o.ln = ln
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		o.mu.Lock()
		o.hits[r.URL.Path] = true
		o.mu.Unlock()
		_, _ = w.Write([]byte("ok"))
	})
	o.srv = &http.Server{Handler: mux}
	go func() { _ = o.srv.Serve(ln) }()
	return o
}

// URL is the base callback URL to smuggle into a probe, or "" if unavailable.
func (o *OOBListener) URL() string {
	if o.ln == nil {
		return ""
	}
	return "http://" + o.ln.Addr().String()
}

// anyHitPrefix reports whether any recorded callback path starts with prefix.
func (o *OOBListener) anyHitPrefix(prefix string) bool {
	if o.ln == nil {
		return false
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	for p := range o.hits {
		if strings.HasPrefix(p, prefix) {
			return true
		}
	}
	return false
}

// Close shuts the listener down.
func (o *OOBListener) Close() {
	if o.srv != nil {
		_ = o.srv.Close()
	}
}

// newNonce returns an unguessable token so an OOB hit can't be spoofed.
func newNonce() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
