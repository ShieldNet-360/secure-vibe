package updater

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHTTPSourceBearerAuth(t *testing.T) {
	var seenAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"version":"1","generated":"2026-05-13T00:00:00Z","files":[]}`)
	}))
	t.Cleanup(srv.Close)

	// httptest.NewServer is http://, so use the explicit insecure
	// constructor — the guard is verified separately in
	// TestNewHTTPSourceWithAuthRejectsHTTPWithToken.
	src, err := NewHTTPSourceWithAuthInsecure(srv.URL, "tok-12345")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := src.Manifest(); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(seenAuth, "Bearer ") {
		t.Errorf("expected Bearer auth, got %q", seenAuth)
	}
	if !strings.HasSuffix(seenAuth, "tok-12345") {
		t.Errorf("expected token in auth, got %q", seenAuth)
	}
}

func TestHTTPSourceReturnsAuthErrorOn401(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no", http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)

	src, err := NewHTTPSourceWithAuthInsecure(srv.URL, "bad")
	if err != nil {
		t.Fatal(err)
	}
	_, err = src.Manifest()
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "authentication failed") {
		t.Errorf("expected authentication failure message, got %v", err)
	}
}

func TestHTTPSourceNoAuthHeaderWhenEmptyToken(t *testing.T) {
	var seenAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenAuth = r.Header.Get("Authorization")
		_, _ = io.WriteString(w, `{"version":"1","generated":"2026-05-13T00:00:00Z","files":[]}`)
	}))
	t.Cleanup(srv.Close)

	src, err := NewHTTPSource(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := src.Manifest(); err != nil {
		t.Fatal(err)
	}
	if seenAuth != "" {
		t.Errorf("expected no auth header, got %q", seenAuth)
	}
}

// TestNewHTTPSourceWithAuthRejectsHTTPWithToken verifies the defence-in-depth
// guard at the updater layer: even if a misconfigured caller skips the
// configure-time check, NewHTTPSourceWithAuth refuses to attach a bearer
// token to a plaintext http:// source.
func TestNewHTTPSourceWithAuthRejectsHTTPWithToken(t *testing.T) {
	_, err := NewHTTPSourceWithAuth("http://internal.corp.example.com/skills", "tok-12345")
	if err == nil {
		t.Fatal("expected error attaching bearer token to http://, got nil")
	}
	if !strings.Contains(err.Error(), "plaintext http://") {
		t.Errorf("expected plaintext-http error, got %v", err)
	}
}

// TestNewHTTPSourceWithAuthAllowsHTTPWithoutToken verifies the constructor
// still accepts http:// when no token is supplied (the token leak is the
// concern; plaintext fetches of public artifacts are not rejected here).
func TestNewHTTPSourceWithAuthAllowsHTTPWithoutToken(t *testing.T) {
	src, err := NewHTTPSourceWithAuth("http://public.example.com/skills", "")
	if err != nil {
		t.Fatalf("expected http:// without token to succeed, got: %v", err)
	}
	if src == nil {
		t.Fatal("expected non-nil source")
	}
}

// TestNewHTTPSourceWithAuthAllowsHTTPSWithToken is the positive path.
func TestNewHTTPSourceWithAuthAllowsHTTPSWithToken(t *testing.T) {
	src, err := NewHTTPSourceWithAuth("https://secure.example.com/skills", "tok-12345")
	if err != nil {
		t.Fatalf("expected https:// with token to succeed, got: %v", err)
	}
	if src.BearerToken != "tok-12345" {
		t.Errorf("expected token to be attached, got %q", src.BearerToken)
	}
}

// TestNewHTTPSourceWithAuthInsecureOptsIn verifies the explicit escape
// hatch for internal-only setups that legitimately use plaintext http://.
func TestNewHTTPSourceWithAuthInsecureOptsIn(t *testing.T) {
	src, err := NewHTTPSourceWithAuthInsecure("http://internal.corp.example.com/skills", "tok-12345")
	if err != nil {
		t.Fatalf("expected insecure constructor to bypass http+token check, got: %v", err)
	}
	if src.BearerToken != "tok-12345" {
		t.Errorf("expected token to be attached, got %q", src.BearerToken)
	}
}
