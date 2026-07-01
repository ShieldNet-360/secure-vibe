package parsers

import "testing"

func TestParseDockerfile_MultiStage(t *testing.T) {
	body := []byte(`# build stage
FROM golang:1.22 AS builder
USER root
RUN go build ./...

FROM gcr.io/distroless/static AS final
COPY --from=builder /out /
USER 10001
`)
	df := ParseDockerfile(body)
	if got := len(df.Stages); got != 2 {
		t.Fatalf("expected 2 stages, got %d", got)
	}
	if df.Stages[0].Alias != "builder" {
		t.Errorf("stage[0] alias = %q, want builder", df.Stages[0].Alias)
	}
	if df.Stages[1].Alias != "final" {
		t.Errorf("stage[1] alias = %q, want final", df.Stages[1].Alias)
	}
	if df.Stages[0].FinalUser != "root" {
		t.Errorf("stage[0] user = %q, want root", df.Stages[0].FinalUser)
	}
	if df.Stages[1].FinalUser != "10001" {
		t.Errorf("stage[1] user = %q, want 10001", df.Stages[1].FinalUser)
	}
	final := df.FinalStage()
	if final == nil || final.Alias != "final" {
		t.Fatalf("FinalStage() returned %+v", final)
	}
}

func TestParseDockerfile_ArgResolution(t *testing.T) {
	body := []byte(`ARG BASE_IMAGE=node:latest
FROM $BASE_IMAGE
USER root
`)
	df := ParseDockerfile(body)
	if len(df.Stages) != 1 {
		t.Fatalf("expected 1 stage, got %d", len(df.Stages))
	}
	if got := df.Stages[0].BaseImage; got != "$BASE_IMAGE" {
		t.Errorf("BaseImage = %q, want $BASE_IMAGE", got)
	}
	if got := df.Stages[0].ResolvedBase; got != "node:latest" {
		t.Errorf("ResolvedBase = %q, want node:latest", got)
	}
}

func TestParseDockerfile_ContinuationLines(t *testing.T) {
	body := []byte(`FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y curl \
 && rm -rf /var/lib/apt/lists/*
`)
	df := ParseDockerfile(body)
	if len(df.Lines) < 2 {
		t.Fatalf("expected at least 2 joined lines, got %d", len(df.Lines))
	}
	var runLine string
	for _, l := range df.Lines {
		if got := l.Text; len(got) > 4 && got[:4] == "RUN " {
			runLine = got
		}
	}
	if runLine == "" {
		t.Fatalf("no RUN line emitted: %+v", df.Lines)
	}
	wantHas := []string{"apt-get update", "apt-get install", "rm -rf"}
	for _, w := range wantHas {
		if !contains(runLine, w) {
			t.Errorf("RUN line %q missing %q", runLine, w)
		}
	}
}

func TestIsRootUser(t *testing.T) {
	cases := map[string]bool{
		"":           false,
		"root":       true,
		"0":          true,
		"ROOT":       true,
		"root:root":  true,
		"appuser":    false,
		"10001":      false,
		" 0":         true,
		"0 # banner": true,
	}
	for input, want := range cases {
		if got := IsRootUser(input); got != want {
			t.Errorf("IsRootUser(%q) = %v, want %v", input, got, want)
		}
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
