package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestScanSecretsWritesHTMLReport confirms the optional --report-dir
// flag produces both an HTML and a PDF report (instead of terminal
// output) and that the findings are rendered into the HTML.
func TestScanSecretsWritesHTMLReport(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "leak.txt")
	if err := os.WriteFile(src, []byte("aws_key = AKIA1234567890ABCDEF\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(dir, "reports")

	stdout, _, err := run(t, "scan-secrets", "--path", repoRootForTest(t), "--report-dir", outDir, src)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !strings.Contains(stdout, "Reports written") {
		t.Errorf("expected a confirmation line on stdout, got:\n%s", stdout)
	}
	// Terminal should NOT carry the usual scan output when reporting.
	if strings.Contains(stdout, "=== scan-secrets") {
		t.Errorf("terminal scan output leaked while --report-dir was set:\n%s", stdout)
	}

	htmlPath := filepath.Join(outDir, "scan-secrets-report.html")
	pdfPath := filepath.Join(outDir, "scan-secrets-report.pdf")
	body, err := os.ReadFile(htmlPath)
	if err != nil {
		t.Fatalf("read HTML report: %v", err)
	}
	html := string(body)
	for _, want := range []string{
		"<!DOCTYPE html>",
		"scan-secrets report",
		"file(s) scanned",
		"<table>",
		"badge sev-",
		`class="stat filter-btn`, // clickable severity filters
		`data-sev="files"`,       // "file(s) scanned" shows all incl. clean
		`data-sev="all"`,         // "finding(s)" shows only files with findings
		"click a count or severity to filter",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("report HTML missing %q:\n%s", want, html)
		}
	}
	// The PDF must exist and start with the %PDF magic header.
	pdf, err := os.ReadFile(pdfPath)
	if err != nil {
		t.Fatalf("read PDF report: %v", err)
	}
	if !strings.HasPrefix(string(pdf), "%PDF-") {
		t.Errorf("PDF report is not a valid PDF (missing %%PDF- header)")
	}
}

// TestScanDependenciesReportDirectory confirms directory scans render
// one report section per discovered lockfile.
func TestScanDependenciesReportDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.sum"),
		[]byte("github.com/stretchr/testify v1.8.4 h1:abc=\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(dir, "reports")
	stdout, _, err := run(t, "scan-dependencies", "--path", repoRootForTest(t), "--report-dir", outDir, dir)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !strings.Contains(stdout, "Reports written") {
		t.Errorf("expected confirmation line, got:\n%s", stdout)
	}
	body, err := os.ReadFile(filepath.Join(outDir, "scan-dependencies-report.html"))
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	html := string(body)
	if !strings.Contains(html, "scan-dependencies report") {
		t.Errorf("report missing title:\n%s", html)
	}
	if !strings.Contains(html, "go.sum") {
		t.Errorf("report missing the scanned lockfile section:\n%s", html)
	}
}
