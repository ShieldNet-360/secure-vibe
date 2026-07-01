package verify

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// run is a tiny helper: verify f against srv with both safety rails satisfied.
func run(t *testing.T, f Finding) Result {
	t.Helper()
	res, err := Run(context.Background(), f, Opts{Confirm: true, AllowTarget: allowAll})
	if err != nil {
		t.Fatal(err)
	}
	if res.DryRun {
		t.Fatalf("must not be dry-run when Confirm + scope are satisfied: %+v", res)
	}
	return res
}

// --- path-traversal -------------------------------------------------------

func TestPathTraversalProbe_Confirms(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Vulnerable: any "../" path is "read" and we serve a passwd-like body.
		if strings.Contains(r.URL.Query().Get("file"), "..") {
			_, _ = w.Write([]byte("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/usr/sbin:/usr/sbin/nologin\n"))
			return
		}
		_, _ = w.Write([]byte("welcome"))
	}))
	defer srv.Close()
	res := run(t, Finding{Type: "path-traversal", Target: srv.URL, Param: "file"})
	if !res.Confirmed {
		t.Fatalf("expected confirmed, got %+v", res)
	}
}

func TestPathTraversalProbe_RefutesSafe(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Safe: rejects traversal, never returns file contents.
		if strings.Contains(r.URL.Query().Get("file"), "..") {
			http.Error(w, "invalid path", http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte("welcome"))
	}))
	defer srv.Close()
	res := run(t, Finding{Type: "path-traversal", Target: srv.URL, Param: "file"})
	if res.Confirmed {
		t.Fatalf("safe server must not confirm, got %+v", res)
	}
	if !res.Refuted {
		t.Errorf("expected refuted, got %+v", res)
	}
}

// --- command-injection ----------------------------------------------------

func TestCmdiProbe_OOBConfirms(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Vulnerable: "execute" the injected command by fetching any URL in it.
		v := r.URL.Query().Get("host")
		if i := strings.Index(v, "http://"); i >= 0 {
			if resp, err := http.Get(v[i:]); err == nil { //nolint -- intentionally vulnerable fixture
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
		}
		_, _ = w.Write([]byte("pong"))
	}))
	defer srv.Close()
	res := run(t, Finding{Type: "command-injection", Target: srv.URL, Param: "host"})
	if !res.Confirmed {
		t.Fatalf("expected OOB confirm, got %+v", res)
	}
	if !strings.Contains(res.Evidence, "out-of-band") {
		t.Errorf("expected OOB evidence, got %q", res.Evidence)
	}
}

func TestCmdiProbe_TimeBasedConfirms(t *testing.T) {
	old := cmdiSleep
	cmdiSleep = 300 * time.Millisecond
	defer func() { cmdiSleep = old }()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Vulnerable: pause when the injected command says "sleep"; no OOB egress.
		if strings.Contains(r.URL.Query().Get("host"), "sleep") {
			time.Sleep(cmdiSleep)
		}
		_, _ = w.Write([]byte("pong"))
	}))
	defer srv.Close()
	res := run(t, Finding{Type: "command-injection", Target: srv.URL, Param: "host"})
	if !res.Confirmed {
		t.Fatalf("expected time-based confirm, got %+v", res)
	}
	if !strings.Contains(res.Evidence, "time-based") {
		t.Errorf("expected time-based evidence, got %q", res.Evidence)
	}
}

func TestCmdiProbe_RefutesSafe(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("pong")) // never executes anything
	}))
	defer srv.Close()
	res := run(t, Finding{Type: "command-injection", Target: srv.URL, Param: "host"})
	if res.Confirmed {
		t.Fatalf("safe server must not confirm, got %+v", res)
	}
	if !res.Refuted {
		t.Errorf("expected refuted, got %+v", res)
	}
}

// --- ssti -----------------------------------------------------------------

func TestSSTIProbe_Confirms(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Vulnerable: evaluate the arithmetic, emitting the product (not the expr).
		v := r.URL.Query().Get("name")
		if strings.Contains(v, sstiExprBody) {
			_, _ = w.Write([]byte("Hello " + sstiProduct))
			return
		}
		_, _ = w.Write([]byte("Hello " + v))
	}))
	defer srv.Close()
	res := run(t, Finding{Type: "ssti", Target: srv.URL, Param: "name"})
	if !res.Confirmed {
		t.Fatalf("expected confirmed, got %+v", res)
	}
}

func TestSSTIProbe_RefutesReflectionOnly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Reflected but NOT evaluated: the raw expression echoes back verbatim.
		_, _ = w.Write([]byte("Hello " + r.URL.Query().Get("name")))
	}))
	defer srv.Close()
	res := run(t, Finding{Type: "ssti", Target: srv.URL, Param: "name"})
	if res.Confirmed {
		t.Fatalf("reflection-only must not confirm, got %+v", res)
	}
	if !res.Refuted {
		t.Errorf("expected refuted, got %+v", res)
	}
}

func TestSSTIProbe_NoFalsePositiveOnDigitRun(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// NOT vulnerable: ignores input, but the page contains the product as a
		// substring of a longer number (e.g. an order id / timestamp).
		_, _ = w.Write([]byte("order #16725936000 confirmed"))
	}))
	defer srv.Close()
	res := run(t, Finding{Type: "ssti", Target: srv.URL, Param: "name"})
	if res.Confirmed {
		t.Fatalf("must not confirm on a coincidental digit run, got %+v", res)
	}
	if !res.Refuted {
		t.Errorf("expected refuted, got %+v", res)
	}
}

// --- safety: dry-run must never fire, for every new probe -----------------

func TestNewProbes_DryRunNeverFires(t *testing.T) {
	for _, typ := range []string{"path-traversal", "command-injection", "ssti", "xxe"} {
		t.Run(typ, func(t *testing.T) {
			hit := false
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hit = true
				_, _ = io.Copy(io.Discard, r.Body)
				_, _ = w.Write([]byte("ok"))
			}))
			defer srv.Close()
			res, err := Run(context.Background(), Finding{Type: typ, Target: srv.URL, Param: "p"}, Opts{Confirm: false})
			if err != nil {
				t.Fatal(err)
			}
			if !res.DryRun {
				t.Errorf("expected dry-run, got %+v", res)
			}
			if res.Payload == "" {
				t.Error("dry-run should still build a payload to show")
			}
			if hit {
				t.Error("RAIL 1 violated: dry-run sent a request to the target")
			}
		})
	}
}

// --- xxe ------------------------------------------------------------------

func TestXXEProbe_OOBConfirms(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Vulnerable parser: resolve the external entity by fetching its SYSTEM URL.
		body, _ := io.ReadAll(r.Body)
		s := string(body)
		const marker = `SYSTEM "`
		if i := strings.Index(s, marker); i >= 0 {
			rest := s[i+len(marker):]
			if j := strings.Index(rest, `"`); j >= 0 {
				if resp, err := http.Get(rest[:j]); err == nil { //nolint -- intentionally vulnerable fixture
					_, _ = io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
				}
			}
		}
		_, _ = w.Write([]byte("<ok/>"))
	}))
	defer srv.Close()
	res := run(t, Finding{Type: "xxe", Target: srv.URL})
	if !res.Confirmed {
		t.Fatalf("expected OOB confirm, got %+v", res)
	}
}

func TestXXEProbe_RefutesSafe(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body) // safe parser: entities disabled, no fetch
		_, _ = w.Write([]byte("<ok/>"))
	}))
	defer srv.Close()
	res := run(t, Finding{Type: "xxe", Target: srv.URL})
	if res.Confirmed {
		t.Fatalf("safe parser must not confirm, got %+v", res)
	}
	if !res.Refuted {
		t.Errorf("expected refuted, got %+v", res)
	}
}
