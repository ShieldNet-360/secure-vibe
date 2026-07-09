package probe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestScopeConfiguredAndAllows(t *testing.T) {
	t.Setenv("SECURE_VIBE_VERIFY_SCOPE_FILE", "")
	t.Setenv("SECURE_VIBE_VERIFY_SCOPE", "staging.internal, 127.0.0.1")
	s := LoadScope()
	if !s.Configured() {
		t.Fatal("scope should be configured")
	}
	if !s.Allows("http://staging.internal/x") {
		t.Error("staging.internal should be allowed")
	}
	if !s.Allows("http://127.0.0.1:4000/x") {
		t.Error("127.0.0.1 should be allowed")
	}
	if s.Allows("http://prod.example.com/x") {
		t.Error("prod must be denied")
	}

	t.Setenv("SECURE_VIBE_VERIFY_SCOPE", "")
	if LoadScope().Configured() {
		t.Error("empty scope must be unconfigured (dry-run)")
	}
}

func TestHTTPProbeDryRunWithoutScope(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("probe must NOT fire when scope is unconfigured")
	}))
	defer srv.Close()

	t.Setenv("SECURE_VIBE_VERIFY_SCOPE", "")
	resp, err := HTTPProbe(context.Background(), LoadScope(), Request{URL: srv.URL + "/x"}, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	if resp.Sent {
		t.Error("Sent should be false in dry-run")
	}
	if resp.Plan == "" || !strings.Contains(resp.Note, "dry-run") {
		t.Errorf("expected a dry-run plan, got %+v", resp)
	}
}

func TestHTTPProbeDryRunOutOfScope(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("probe must NOT fire for an out-of-scope target")
	}))
	defer srv.Close()

	t.Setenv("SECURE_VIBE_VERIFY_SCOPE", "some-other-host")
	resp, _ := HTTPProbe(context.Background(), LoadScope(), Request{URL: srv.URL + "/x"}, srv.Client())
	if resp.Sent {
		t.Error("out-of-scope target must be dry-run")
	}
}

func TestHTTPProbeFiresInScope(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer op-token" {
			t.Errorf("operator auth header missing: %q", r.Header.Get("Authorization"))
		}
		w.WriteHeader(418)
		_, _ = w.Write([]byte("PROBE-REFLECTED"))
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	t.Setenv("SECURE_VIBE_VERIFY_SCOPE", host)
	scope := &Scope{targets: []scopeTarget{{Match: host, Headers: map[string]string{"Authorization": "Bearer op-token"}}}, hosts: []string{host}}

	resp, err := HTTPProbe(context.Background(), scope, Request{URL: srv.URL + "/x", Method: "GET"}, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Sent {
		t.Fatalf("in-scope probe should fire, got %+v", resp)
	}
	if resp.Status != 418 || !strings.Contains(resp.Body, "PROBE-REFLECTED") {
		t.Errorf("unexpected response: status=%d body=%q", resp.Status, resp.Body)
	}
}
