// Self-contained HTML report rendering shared by the scan-* commands.
//
// Every scanner (scan-secrets, scan-dependencies, scan-dockerfile,
// scan-github-actions) can take an optional --report <file> flag. When
// set, the command renders its findings into a single styled, fully
// self-contained HTML file (inline CSS, no external assets) instead of
// printing to the terminal. The stylesheet includes a print media
// query so the user gets a clean PDF via the browser's "Print -> Save
// as PDF" — keeping the project's no-external-execution, zero-extra-
// dependency posture (html/template ships with the stdlib).
//
// The report model is deliberately scanner-agnostic: each command maps
// its own result shape into reportSection / reportFinding so the
// renderer and stylesheet stay in one place.

package cmd

import (
	"fmt"
	"html/template"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/go-pdf/fpdf"
	"github.com/spf13/cobra"

	"github.com/shieldnet-360/secure-vibe/internal/tools"
)

// htmlReport is the top-level model handed to the HTML template.
type htmlReport struct {
	Tool        string
	GeneratedAt string
	Targets     []string
	Sections    []reportSection
	Summary     reportSummary
}

// reportSection groups the findings for one scanned file (or, for the
// inline secret scan, one logical input).
type reportSection struct {
	Title    string
	Subtitle string
	Findings []reportFinding
}

// reportFinding is one normalised finding row. Location and Fix are
// optional; empty values are simply omitted in the rendered output.
type reportFinding struct {
	Severity string
	Title    string
	Location string
	Detail   string
	Fix      string
}

// reportSummary is the at-a-glance header: how many files were scanned,
// how many findings in total, and a per-severity breakdown.
type reportSummary struct {
	FilesScanned  int
	TotalFindings int
	BySeverity    []severityCount
}

type severityCount struct {
	Severity string
	Count    int
}

// severityOrder is the canonical high-to-low ordering used for the
// summary breakdown so a report is scannable top-down.
var severityOrder = []string{"critical", "high", "medium", "low", "info"}

// newReport builds a report shell with the tool name and timestamp set;
// callers append Sections and then call finalize.
func newReport(tool string, targets []string) *htmlReport {
	return &htmlReport{
		Tool:        tool,
		GeneratedAt: time.Now().Format(time.RFC1123),
		Targets:     targets,
		Sections:    []reportSection{},
	}
}

// finalize computes the summary counts from the accumulated sections.
// FilesScanned counts sections (including clean files) so the report
// reflects coverage, not just hits.
func (r *htmlReport) finalize() {
	counts := map[string]int{}
	total := 0
	for _, s := range r.Sections {
		for _, f := range s.Findings {
			total++
			counts[strings.ToLower(f.Severity)]++
		}
	}
	r.Summary.FilesScanned = len(r.Sections)
	r.Summary.TotalFindings = total
	for _, sev := range severityOrder {
		if n := counts[sev]; n > 0 {
			r.Summary.BySeverity = append(r.Summary.BySeverity, severityCount{Severity: sev, Count: n})
		}
	}

	// Sort findings within each section by severity (most severe first)
	// and float sections that have findings above clean ones, so the
	// most important results are at the top of the report.
	for i := range r.Sections {
		f := r.Sections[i].Findings
		sort.SliceStable(f, func(a, b int) bool {
			return severityRank(f[a].Severity) < severityRank(f[b].Severity)
		})
	}
	sort.SliceStable(r.Sections, func(i, j int) bool {
		return len(r.Sections[i].Findings) > 0 && len(r.Sections[j].Findings) == 0
	})
}

// severityRank orders severities from most to least severe; unknown
// severities sort last.
func severityRank(sev string) int {
	for i, s := range severityOrder {
		if strings.EqualFold(sev, s) {
			return i
		}
	}
	return len(severityOrder)
}

// reportHelpParagraph documents the --report-dir flag; appended to each
// scan command's long help so the feature is discoverable from --help.
const reportHelpParagraph = `Report output:
  Pass --report-dir <dir> to write both a self-contained HTML report and
  a matching PDF (<command>-report.html and <command>-report.pdf) into
  that directory instead of printing to the terminal. The directory is
  created if it does not already exist.`

// addReportFlag registers the shared --report-dir flag on a scan
// command.
func addReportFlag(c *cobra.Command, dst *string) {
	c.Flags().StringVar(dst, "report-dir", "",
		"write HTML + PDF reports into this directory (created if needed); if omitted, results print to the terminal")
}

// writeReport renders rep as both HTML and PDF into the directory dir
// and prints a confirmation listing both paths. dir is created if it
// does not exist. File names are derived from the tool name so multiple
// scanners can share one output directory without clobbering.
func writeReport(c *cobra.Command, dir string, rep *htmlReport) error {
	rep.finalize()
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("resolve report dir %q: %w", dir, err)
	}
	if err := os.MkdirAll(absDir, 0o755); err != nil {
		return fmt.Errorf("create report dir %s: %w", absDir, err)
	}
	base := strings.ReplaceAll(rep.Tool, " ", "-")
	htmlPath := filepath.Join(absDir, base+"-report.html")
	pdfPath := filepath.Join(absDir, base+"-report.pdf")

	f, err := os.Create(htmlPath)
	if err != nil {
		return fmt.Errorf("create report %s: %w", htmlPath, err)
	}
	if err := renderHTMLReport(f, rep); err != nil {
		f.Close()
		return fmt.Errorf("render HTML report %s: %w", htmlPath, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("write HTML report %s: %w", htmlPath, err)
	}
	if err := renderPDFReport(pdfPath, rep); err != nil {
		return fmt.Errorf("render PDF report %s: %w", pdfPath, err)
	}

	fmt.Fprintf(c.OutOrStdout(),
		"Reports written (%d finding(s) across %d file(s)):\n  %s\n  %s\n",
		rep.Summary.TotalFindings, rep.Summary.FilesScanned, htmlPath, pdfPath)
	return nil
}

// renderHTMLReport writes the HTML document for rep to w.
func renderHTMLReport(w io.Writer, rep *htmlReport) error {
	return reportTemplate.Execute(w, rep)
}

// renderPDFReport writes rep as a PDF document to path using the
// pure-Go fpdf library (no external binary / headless browser). The
// layout mirrors the HTML report: title + metadata, a summary line,
// then one block per scanned file with severity-coloured finding rows.
func renderPDFReport(path string, rep *htmlReport) error {
	const (
		left   = 15.0
		top    = 15.0
		bottom = 15.0
	)
	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetTitle(pdfText(rep.Tool+" report"), false)
	pdf.SetMargins(left, top, left)
	pdf.SetAutoPageBreak(true, bottom)
	pdf.AddPage()
	pageW, _ := pdf.GetPageSize()
	cw := pageW - 2*left // usable content width

	// Title + metadata.
	pdf.SetFont("Helvetica", "B", 18)
	pdf.SetTextColor(27, 31, 36)
	pdf.MultiCell(cw, 9, pdfText(rep.Tool+" report"), "", "L", false)
	pdf.SetFont("Helvetica", "", 9)
	pdf.SetTextColor(90, 100, 112)
	meta := "Generated " + rep.GeneratedAt
	if len(rep.Targets) > 0 {
		meta += "   Target: " + strings.Join(rep.Targets, ", ")
	}
	pdf.MultiCell(cw, 5, pdfText(meta), "", "L", false)
	pdf.Ln(2)

	// Summary line.
	pdf.SetFont("Helvetica", "B", 10)
	pdf.SetTextColor(27, 31, 36)
	summary := fmt.Sprintf("%d file(s) scanned   %d finding(s)",
		rep.Summary.FilesScanned, rep.Summary.TotalFindings)
	for _, sc := range rep.Summary.BySeverity {
		summary += fmt.Sprintf("   %s: %d", strings.ToUpper(sc.Severity), sc.Count)
	}
	pdf.MultiCell(cw, 6, pdfText(summary), "", "L", false)
	pdf.Ln(3)

	// On a folder scan (more than one section) clean files are omitted
	// so the PDF only carries files that actually have findings. A
	// single-file scan keeps its section so the PDF is never empty.
	multi := len(rep.Sections) > 1
	for _, sec := range rep.Sections {
		if multi && len(sec.Findings) == 0 {
			continue
		}
		pdf.SetFont("Helvetica", "B", 11)
		pdf.SetTextColor(27, 31, 36)
		pdf.MultiCell(cw, 6, pdfText(sec.Title), "B", "L", false)
		if sec.Subtitle != "" {
			pdf.SetFont("Helvetica", "", 8)
			pdf.SetTextColor(90, 100, 112)
			pdf.MultiCell(cw, 5, pdfText(sec.Subtitle), "", "L", false)
		}
		if len(sec.Findings) == 0 {
			pdf.SetFont("Helvetica", "I", 9)
			pdf.SetTextColor(26, 127, 55)
			pdf.MultiCell(cw, 5, "No findings.", "", "L", false)
			pdf.Ln(3)
			continue
		}
		for _, f := range sec.Findings {
			pdf.Ln(1)
			// Severity badge, then the title to its right with wrapped
			// lines aligned under the title via a temporary left margin.
			r, g, b := severityRGB(f.Severity)
			label := strings.ToUpper(f.Severity)
			if label == "" {
				label = "INFO"
			}
			pdf.SetFont("Helvetica", "B", 7)
			badgeW := pdf.GetStringWidth(label) + 4
			pdf.SetFillColor(r, g, b)
			pdf.SetTextColor(255, 255, 255)
			pdf.CellFormat(badgeW, 5, label, "", 0, "C", true, 0, "")

			titleX := pdf.GetX() + 1.5
			pdf.SetLeftMargin(titleX)
			pdf.SetX(titleX)
			pdf.SetFont("Helvetica", "B", 9)
			pdf.SetTextColor(27, 31, 36)
			pdf.MultiCell(cw-(titleX-left), 5, pdfText(f.Title), "", "L", false)
			pdf.SetLeftMargin(left)

			if f.Location != "" {
				pdf.SetFont("Helvetica", "", 8)
				pdf.SetTextColor(90, 100, 112)
				pdf.MultiCell(cw, 4, pdfText(f.Location), "", "L", false)
			}
			if f.Detail != "" {
				pdf.SetFont("Helvetica", "", 9)
				pdf.SetTextColor(27, 31, 36)
				pdf.MultiCell(cw, 4.5, pdfText(f.Detail), "", "L", false)
			}
			if f.Fix != "" {
				pdf.SetFont("Helvetica", "", 9)
				pdf.SetTextColor(26, 127, 55)
				pdf.MultiCell(cw, 4.5, pdfText("Fix: "+f.Fix), "", "L", false)
			}
		}
		pdf.Ln(3)
	}

	return pdf.OutputFileAndClose(path)
}

// severityRGB maps a severity label to the badge colour used in both
// the HTML and PDF reports (kept visually consistent with the CSS).
func severityRGB(sev string) (int, int, int) {
	switch strings.ToLower(sev) {
	case "critical":
		return 176, 0, 32
	case "high":
		return 217, 72, 15
	case "medium":
		return 176, 137, 0
	case "low":
		return 47, 111, 235
	default:
		return 91, 100, 112
	}
}

// pdfText makes a string safe for fpdf's Latin-1 core fonts: it folds a
// few common typographic runes to ASCII and drops anything else outside
// the printable ASCII range so findings never render as mojibake.
func pdfText(s string) string {
	s = strings.NewReplacer(
		"—", "-", "–", "-", "·", "-", "→", "->",
		"’", "'", "‘", "'", "“", `"`, "”", `"`, "•", "-", "…", "...",
	).Replace(s)
	return strings.Map(func(r rune) rune {
		if r >= 32 && r < 127 {
			return r
		}
		if r == '\n' || r == '\t' {
			return ' '
		}
		return -1
	}, s)
}

// -----------------------------------------------------------------------------
// Per-scanner section builders. Each maps one tool result into the
// scanner-agnostic reportSection model so the renderer stays generic.
// -----------------------------------------------------------------------------

func secretSection(label string, res *tools.ScanSecretsResult) reportSection {
	s := reportSection{Title: label}
	for _, m := range res.Matches {
		detail := fmt.Sprintf("score=%.2f, entropy=%.2f, hotword=%v", m.Score, m.Entropy, m.HotwordHit)
		if m.KnownFalsePositive {
			detail += " — known false positive"
		}
		s.Findings = append(s.Findings, reportFinding{
			Severity: m.Severity,
			Title:    m.Name,
			Location: fmt.Sprintf("offset %d-%d", m.Start, m.End),
			Detail:   detail,
		})
	}
	return s
}

func dependencySection(res *tools.ScanDependenciesResult) reportSection {
	s := reportSection{
		Title:    res.FilePath,
		Subtitle: fmt.Sprintf("%d dependencies parsed, ecosystem=%s", res.Dependencies, res.Ecosystem),
	}
	for _, f := range res.Findings {
		loc := f.Category
		if f.CVE != "" {
			loc = fmt.Sprintf("%s · %s", f.Category, f.CVE)
		}
		s.Findings = append(s.Findings, reportFinding{
			Severity: f.Severity,
			Title:    fmt.Sprintf("%s@%s", f.Package, f.Version),
			Location: loc,
			Detail:   f.Message,
		})
	}
	return s
}

func dockerfileSection(label string, res *tools.ScanDockerfileResult) reportSection {
	s := reportSection{Title: label}
	for _, f := range res.Findings {
		s.Findings = append(s.Findings, reportFinding{
			Severity: f.Severity,
			Title:    f.Title,
			Location: fmt.Sprintf("%s · line %d", f.RuleID, f.Line),
			Detail:   f.Snippet,
			Fix:      f.Fix,
		})
	}
	return s
}

// gateSection renders one gated file (a PolicyCheckResult) as a report
// section. gate flattens every scanner into PolicyCheckFinding, so the
// section is built from that homogeneous shape: line-based findings show
// "rule · line N", dependency findings show "rule · pkg@ver".
func gateSection(res *tools.PolicyCheckResult) reportSection {
	s := reportSection{
		Title:    res.FilePath,
		Subtitle: fmt.Sprintf("scanner=%s, floor=%s", res.Scan, res.SeverityFloor),
	}
	for _, f := range res.Findings {
		loc := f.RuleID
		switch {
		case f.Line > 0:
			loc = fmt.Sprintf("%s · line %d", f.RuleID, f.Line)
		case f.Package != "":
			pv := f.Package
			if f.Version != "" {
				pv += "@" + f.Version
			}
			loc = fmt.Sprintf("%s · %s", f.RuleID, pv)
		}
		s.Findings = append(s.Findings, reportFinding{
			Severity: f.Severity,
			Title:    f.Title,
			Location: loc,
			Detail:   f.Snippet,
		})
	}
	return s
}

func githubActionsSection(label string, res *tools.ScanGitHubActionsResult) reportSection {
	s := reportSection{Title: label}
	for _, f := range res.Findings {
		detail := f.Rationale
		if f.Snippet != "" {
			if detail != "" {
				detail += " — "
			}
			detail += f.Snippet
		}
		s.Findings = append(s.Findings, reportFinding{
			Severity: f.Severity,
			Title:    f.Title,
			Location: fmt.Sprintf("%s · line %d", f.RuleID, f.Line),
			Detail:   detail,
			Fix:      f.Fix,
		})
	}
	return s
}

// reportTemplate is parsed once at startup; a parse error here is a
// programming error in the literal below, so template.Must is correct.
var reportTemplate = template.Must(template.New("report").
	Funcs(template.FuncMap{"lower": strings.ToLower}).
	Parse(reportHTML))

const reportHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Tool}} report</title>
<style>
  :root {
    --bg: #f6f7f9; --card: #ffffff; --ink: #1b1f24; --muted: #5b6470;
    --border: #e2e6ea; --crit: #b00020; --high: #d9480f; --med: #b08900;
    --low: #2f6feb; --info: #5b6470;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; padding: 2rem; background: var(--bg); color: var(--ink);
    font: 15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  }
  .wrap { max-width: 960px; margin: 0 auto; }
  header.report { margin-bottom: 1.5rem; }
  header.report h1 { margin: 0 0 .25rem; font-size: 1.6rem; }
  .meta { color: var(--muted); font-size: .85rem; }
  .meta code { background: #eef0f3; padding: .05rem .35rem; border-radius: 4px; }
  .summary {
    display: flex; flex-wrap: wrap; gap: .6rem; align-items: center;
    margin: 1rem 0 1.5rem;
  }
  .stat {
    background: var(--card); border: 1px solid var(--border); border-radius: 8px;
    padding: .5rem .85rem; font-size: .85rem;
  }
  .stat strong { font-size: 1.05rem; }
  button.stat { cursor: pointer; font: inherit; color: inherit; line-height: 1; }
  button.stat:hover { border-color: var(--muted); }
  button.stat.active { border-color: var(--ink); box-shadow: 0 0 0 1px var(--ink) inset; }
  .filter-hint { color: var(--muted); font-size: .78rem; }
  [hidden] { display: none !important; }
  .badge {
    display: inline-block; font-size: .72rem; font-weight: 700; letter-spacing: .03em;
    text-transform: uppercase; color: #fff; padding: .12rem .5rem; border-radius: 999px;
  }
  .sev-critical { background: var(--crit); }
  .sev-high { background: var(--high); }
  .sev-medium { background: var(--med); }
  .sev-low { background: var(--low); }
  .sev-info { background: var(--info); }
  .badge.unknown, .sev- { background: var(--info); }
  section.file {
    background: var(--card); border: 1px solid var(--border); border-radius: 10px;
    margin-bottom: 1.1rem; overflow: hidden;
  }
  section.file > h2 {
    margin: 0; padding: .75rem 1rem; font-size: 1rem; border-bottom: 1px solid var(--border);
    word-break: break-all;
  }
  section.file > .subtitle { padding: .4rem 1rem 0; color: var(--muted); font-size: .8rem; }
  .clean { padding: .75rem 1rem; color: #1a7f37; font-size: .9rem; }
  table { width: 100%; border-collapse: collapse; }
  th, td { text-align: left; padding: .55rem 1rem; vertical-align: top; border-top: 1px solid var(--border); }
  th { font-size: .72rem; text-transform: uppercase; letter-spacing: .04em; color: var(--muted); background: #fafbfc; }
  td.sev { white-space: nowrap; }
  td .loc { color: var(--muted); font-size: .82rem; }
  td .fix { margin-top: .3rem; font-size: .85rem; }
  td .fix b { color: #1a7f37; }
  footer { margin-top: 2rem; color: var(--muted); font-size: .78rem; text-align: center; }
  @media print {
    body { background: #fff; padding: 0; font-size: 12px; }
    .filter-hint { display: none; }
    button.stat.active { box-shadow: none; }
    .stat, section.file { border-color: #ccc; }
    section.file { break-inside: avoid; }
    th { background: #f0f0f0 !important; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
    .badge { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
    footer { page-break-before: avoid; }
  }
</style>
</head>
<body>
<div class="wrap">
  <header class="report">
    <h1>{{.Tool}} report</h1>
    <div class="meta">
      Generated {{.GeneratedAt}}{{if .Targets}} &middot; Target{{if gt (len .Targets) 1}}s{{end}}:
      {{range $i, $t := .Targets}}{{if $i}}, {{end}}<code>{{$t}}</code>{{end}}{{end}}
    </div>
  </header>

  <div class="summary">
    <button type="button" class="stat filter-btn active" data-sev="files"><strong>{{.Summary.FilesScanned}}</strong> file(s) scanned</button>
    <button type="button" class="stat filter-btn" data-sev="all"><strong>{{.Summary.TotalFindings}}</strong> finding(s)</button>
    {{range .Summary.BySeverity}}
    <button type="button" class="stat filter-btn" data-sev="{{.Severity}}"><span class="badge sev-{{.Severity}}">{{.Severity}}</span> {{.Count}}</button>
    {{end}}
    <span class="filter-hint">click a count or severity to filter</span>
  </div>

  {{range .Sections}}
  <section class="file"{{if not .Findings}} data-clean="1"{{end}}>
    <h2>{{.Title}}</h2>
    {{if .Subtitle}}<div class="subtitle">{{.Subtitle}}</div>{{end}}
    {{if .Findings}}
    <table>
      <thead><tr><th>Severity</th><th>Finding</th><th>Details</th></tr></thead>
      <tbody>
      {{range .Findings}}
        <tr data-sev="{{lower .Severity}}">
          <td class="sev"><span class="badge sev-{{lower .Severity}}">{{.Severity}}</span></td>
          <td>
            {{.Title}}
            {{if .Location}}<div class="loc">{{.Location}}</div>{{end}}
          </td>
          <td>
            {{.Detail}}
            {{if .Fix}}<div class="fix"><b>Fix:</b> {{.Fix}}</div>{{end}}
          </td>
        </tr>
      {{end}}
      </tbody>
    </table>
    {{else}}
    <div class="clean">No findings.</div>
    {{end}}
  </section>
  {{end}}

  <footer>Generated by secure-vibe &middot; SecureVibe</footer>
</div>
<script>
(function () {
  // mode is one of: 'files' (every scanned file, including clean ones),
  // 'all' (only files that have findings), or a severity name.
  function apply(mode) {
    document.querySelectorAll('section.file').forEach(function (sec) {
      var rows = sec.querySelectorAll('tbody tr');
      if (rows.length === 0) {
        // Clean (no-finding) sections appear only in the 'files' view.
        sec.hidden = (mode !== 'files');
        return;
      }
      var visible = 0;
      rows.forEach(function (tr) {
        var show = (mode === 'files' || mode === 'all' || tr.getAttribute('data-sev') === mode);
        tr.hidden = !show;
        if (show) { visible++; }
      });
      sec.hidden = (visible === 0);
    });
    document.querySelectorAll('.filter-btn').forEach(function (b) {
      b.classList.toggle('active', b.getAttribute('data-sev') === mode);
    });
  }
  document.querySelectorAll('.filter-btn').forEach(function (b) {
    b.addEventListener('click', function () { apply(b.getAttribute('data-sev')); });
  });
})();
</script>
</body>
</html>
`
