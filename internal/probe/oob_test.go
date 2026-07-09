package probe

import (
	"net/http"
	"testing"
)

func TestOOBAllocatePollHit(t *testing.T) {
	o := Listener()
	url, token, err := o.Allocate()
	if err != nil {
		t.Fatal(err)
	}
	if url == "" || token == "" {
		t.Fatal("allocate returned empty url/token")
	}
	// No callback yet.
	if hits := o.Poll(token); len(hits) != 0 {
		t.Errorf("expected 0 hits before callback, got %d", len(hits))
	}
	// Simulate the target calling back to the OOB URL.
	resp, err := http.Get(url + "/leak?x=1")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	// The hit is now visible.
	hits := o.Poll(token)
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit after callback, got %d", len(hits))
	}
	if hits[0].Method != "GET" {
		t.Errorf("hit method = %q", hits[0].Method)
	}
	// An unrelated token stays empty.
	if h := o.Poll("nope-not-a-token"); len(h) != 0 {
		t.Errorf("unknown token should have no hits, got %d", len(h))
	}
}
