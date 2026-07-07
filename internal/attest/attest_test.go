package attest

import (
	"strings"
	"testing"
)

func sampleAttestation() Attestation {
	return Attestation{
		Tool:     "0.0.0-test",
		Subject:  TreeSubject("4b825dc642cb6eb9a060e54bf8d69288fbee4904"),
		Verdict:  "pass",
		Floor:    "high",
		Findings: Counts{Critical: 0, High: 0, Medium: 2, Low: 1},
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	signed, err := Sign(sampleAttestation())
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if signed.Sig == "" || signed.KeyID == "" || signed.Version != Version {
		t.Fatalf("Sign left fields empty: %+v", signed)
	}
	if err := Verify(signed); err != nil {
		t.Fatalf("Verify of freshly signed attestation failed: %v", err)
	}
}

func TestVerifyDetectsTamper(t *testing.T) {
	signed, err := Sign(sampleAttestation())
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	// Flip the verdict without re-signing — the signature must no longer verify.
	tampered := signed
	tampered.Verdict = "fail"
	if err := Verify(tampered); err == nil {
		t.Fatalf("Verify accepted a tampered verdict")
	}
	// Tamper with the subject (the content-addressed binding).
	tampered = signed
	tampered.Subject = TreeSubject("0000000000000000000000000000000000000000")
	if err := Verify(tampered); err == nil {
		t.Fatalf("Verify accepted a tampered subject")
	}
}

func TestTrailerRoundTrip(t *testing.T) {
	signed, err := Sign(sampleAttestation())
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	msg := "feat: add thing\n\nbody text\n\n" + signed.TrailerLine() + "\n"
	parsed, ok, err := ParseTrailer(msg)
	if err != nil {
		t.Fatalf("ParseTrailer: %v", err)
	}
	if !ok {
		t.Fatalf("ParseTrailer did not find the trailer")
	}
	if err := Verify(parsed); err != nil {
		t.Fatalf("parsed attestation failed to verify: %v", err)
	}
	if parsed.Subject != signed.Subject || parsed.Verdict != signed.Verdict ||
		parsed.Findings != signed.Findings || parsed.Floor != signed.Floor {
		t.Fatalf("round-trip mismatch:\n got  %+v\n want %+v", parsed, signed)
	}
}

func TestParseTrailerAbsent(t *testing.T) {
	_, ok, err := ParseTrailer("just a normal commit\n\nno trailer here\n")
	if err != nil {
		t.Fatalf("ParseTrailer errored on a clean message: %v", err)
	}
	if ok {
		t.Fatalf("ParseTrailer reported a trailer where there is none")
	}
}

func TestCanonicalBytesStable(t *testing.T) {
	a := sampleAttestation()
	a.Version = Version
	a.KeyID = "deadbeefdeadbeef"
	if string(a.CanonicalBytes()) != string(a.CanonicalBytes()) {
		t.Fatalf("CanonicalBytes not deterministic")
	}
	if !strings.Contains(string(a.CanonicalBytes()), "subject=tree:") {
		t.Fatalf("CanonicalBytes missing subject:\n%s", a.CanonicalBytes())
	}
}

func TestCountsRoundTrip(t *testing.T) {
	c := Counts{Critical: 1, High: 2, Medium: 3, Low: 4}
	got, err := parseCounts(c.String())
	if err != nil {
		t.Fatalf("parseCounts: %v", err)
	}
	if got != c {
		t.Fatalf("counts round-trip: got %+v want %+v", got, c)
	}
}
