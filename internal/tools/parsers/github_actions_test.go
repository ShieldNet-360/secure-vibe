package parsers

import "testing"

func TestParseWorkflow_PinnedAndUnpinnedActions(t *testing.T) {
	body := []byte(`name: ci
on: [push]
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@a1b2c3d4e5f6789012345678901234567890abcd
      - uses: ./.github/actions/local
`)
	wf, err := ParseWorkflow(body)
	if err != nil {
		t.Fatalf("ParseWorkflow err: %v", err)
	}
	job, ok := wf.Jobs["build"]
	if !ok {
		t.Fatalf("expected build job, got %+v", wf.Jobs)
	}
	if len(job.Steps) != 3 {
		t.Fatalf("expected 3 steps, got %d", len(job.Steps))
	}
	want := []struct {
		uses   string
		pinned bool
	}{
		{"actions/checkout@v4", false},
		{"actions/setup-go@a1b2c3d4e5f6789012345678901234567890abcd", true},
		{"./.github/actions/local", true},
	}
	for i, w := range want {
		if got := job.Steps[i].Uses; got != w.uses {
			t.Errorf("step[%d].Uses = %q, want %q", i, got, w.uses)
		}
		if got := IsPinnedAction(job.Steps[i].Uses); got != w.pinned {
			t.Errorf("IsPinnedAction(%q) = %v, want %v", w.uses, got, w.pinned)
		}
	}
}

func TestParseWorkflow_PullRequestTarget(t *testing.T) {
	body := []byte(`on:
  pull_request_target:
    branches: [main]
jobs:
  fmt:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
`)
	wf, err := ParseWorkflow(body)
	if err != nil {
		t.Fatalf("ParseWorkflow err: %v", err)
	}
	if !wf.IsPullRequestTarget() {
		t.Error("IsPullRequestTarget() = false; want true")
	}
}

func TestParseWorkflow_NotPullRequestTarget(t *testing.T) {
	body := []byte(`on:
  pull_request:
    branches: [main]
jobs:
  fmt:
    runs-on: ubuntu-latest
    steps: []
`)
	wf, err := ParseWorkflow(body)
	if err != nil {
		t.Fatalf("ParseWorkflow err: %v", err)
	}
	if wf.IsPullRequestTarget() {
		t.Error("IsPullRequestTarget() = true; want false")
	}
}

func TestHasUntrustedExpressionInjection(t *testing.T) {
	cases := map[string]bool{
		"echo hello": false,
		"echo ${{ github.event.pull_request.title }}":    true,
		"echo ${{ github.head_ref }}":                    true,
		"echo ${{ github.event.comment.body }}":          true,
		"echo ${{ secrets.GITHUB_TOKEN }}":               false,
		"echo ${{ github.sha }}":                         false,
		"echo ${{ github.event.pull_request.head.sha }}": true,
		"echo ${{ github.event.issue.title }}":           true,
	}
	for input, want := range cases {
		if got := HasUntrustedExpressionInjection(input); got != want {
			t.Errorf("HasUntrustedExpressionInjection(%q) = %v, want %v", input, got, want)
		}
	}
}

func TestIsCheckoutAction(t *testing.T) {
	cases := map[string]bool{
		"":                           false,
		"actions/checkout@v4":        true,
		"actions/checkout":           true,
		"actions/Checkout@v4":        true,
		"actions/setup-go@v5":        false,
		"./.github/actions/checkout": false,
	}
	for input, want := range cases {
		if got := IsCheckoutAction(input); got != want {
			t.Errorf("IsCheckoutAction(%q) = %v, want %v", input, got, want)
		}
	}
}
