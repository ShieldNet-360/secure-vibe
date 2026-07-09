package probe

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Hit is one request the out-of-band listener received — evidence that a blind
// payload reached the outside world (SSRF / XXE / blind command injection).
type Hit struct {
	Method     string              `json:"method"`
	Path       string              `json:"path"`
	RemoteAddr string              `json:"remote_addr"`
	Headers    map[string][]string `json:"headers,omitempty"`
	At         string              `json:"at"`
}

// OOB is a process-local out-of-band HTTP listener. Allocate lazily starts a
// server on 127.0.0.1 and hands out a unique callback URL; any request to that
// URL is recorded and surfaced by Poll. It is reachable only from the same host
// — enough for a local or staging target on the tester's machine; a target that
// cannot reach 127.0.0.1 needs an external OOB service (out of scope here).
type OOB struct {
	mu   sync.Mutex
	base string // http://127.0.0.1:<port>
	hits map[string][]Hit
}

var (
	oobOnce sync.Once
	oobInst *OOB
)

// Listener returns the process-wide OOB listener (created on first use).
func Listener() *OOB {
	oobOnce.Do(func() { oobInst = &OOB{hits: map[string][]Hit{}} })
	return oobInst
}

func (o *OOB) ensureServer() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.base != "" {
		return nil
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("start oob listener: %w", err)
	}
	o.base = "http://" + ln.Addr().String()
	mux := http.NewServeMux()
	mux.HandleFunc("/oob/", func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.URL.Path, "/oob/")
		if i := strings.IndexByte(token, '/'); i >= 0 {
			token = token[:i]
		}
		o.mu.Lock()
		o.hits[token] = append(o.hits[token], Hit{
			Method:     r.Method,
			Path:       r.URL.String(),
			RemoteAddr: r.RemoteAddr,
			Headers:    r.Header,
			At:         time.Now().UTC().Format(time.RFC3339),
		})
		o.mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	go func() { _ = http.Serve(ln, mux) }()
	return nil
}

// Allocate returns a fresh callback URL + token to weave into a blind payload.
func (o *OOB) Allocate() (callbackURL, token string, err error) {
	if err := o.ensureServer(); err != nil {
		return "", "", err
	}
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	token = hex.EncodeToString(b)
	o.mu.Lock()
	o.hits[token] = []Hit{} // register the token so Poll distinguishes "no hits yet" from "unknown"
	o.mu.Unlock()
	return fmt.Sprintf("%s/oob/%s", o.base, token), token, nil
}

// Poll returns the hits recorded for token so far (empty slice if none yet).
func (o *OOB) Poll(token string) []Hit {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.hits[token]
}
