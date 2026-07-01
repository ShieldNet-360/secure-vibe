package cmd

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

// The ShieldNet / SecureVibe mark — the dot-grid logo rendered as terminal
// blocks (1 cell top → three rows of 5 → a row of 3 → 1 cell base), matching
// the SVG. Brand blue is #255FE5 (RGB 37,95,229), emitted as a 24-bit ANSI
// escape only when the destination is an interactive terminal.
var logoRows = []string{
	"    ■",
	"■ ■ ■ ■ ■",
	"■ ■ ■ ■ ■",
	"■ ■ ■ ■ ■",
	"  ■ ■ ■",
	"    ■",
}

const (
	ansiBrandBlue = "\x1b[38;2;37;95;229m"
	ansiBold      = "\x1b[1m"
	ansiDim       = "\x1b[2m"
	ansiReset     = "\x1b[0m"
)

// colorTo reports whether ANSI styling should be written to w: only when w is
// an interactive terminal and neither NO_COLOR nor SECURE_VIBE_NO_LOGO is set.
func colorTo(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" || os.Getenv("SECURE_VIBE_NO_LOGO") != "" {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// renderLogo writes the 6-line mark to w, in brand blue when w is a TTY and
// as plain blocks otherwise (pipes, files, CI).
func renderLogo(w io.Writer) {
	color := colorTo(w)
	for _, row := range logoRows {
		if color {
			fmt.Fprintf(w, "%s%s%s\n", ansiBrandBlue, row, ansiReset)
		} else {
			fmt.Fprintln(w, row)
		}
	}
}

// padRight pads s with spaces to a visible width of w (rune-aware).
func padRight(s string, w int) string {
	if n := w - len([]rune(s)); n > 0 {
		return s + strings.Repeat(" ", n)
	}
	return s
}

// stripANSI removes CSI SGR escape sequences so a line's on-screen width can
// be measured for box alignment.
func stripANSI(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] == 0x1b {
			for i < len(s) && s[i] != 'm' {
				i++
			}
			if i < len(s) {
				i++ // consume the trailing 'm'
			}
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// visWidth is the on-screen column width of s, ignoring ANSI styling. Glyphs
// here (blocks, box rules, middle dots) render one cell wide on the terminals
// SecureVibe targets.
func visWidth(s string) int { return len([]rune(stripANSI(s))) }

// boxed draws a rounded frame around content, padding every line to the widest
// visible line so the right border stays flush.
func boxed(w io.Writer, lines []string, color bool) {
	inner := 0
	for _, ln := range lines {
		if v := visWidth(ln); v > inner {
			inner = v
		}
	}
	bd := func(s string) string {
		if color {
			return ansiDim + s + ansiReset
		}
		return s
	}
	fmt.Fprintln(w, "  "+bd("╭"+strings.Repeat("─", inner+2)+"╮"))
	for _, ln := range lines {
		fmt.Fprintf(w, "  %s %s%s %s\n", bd("│"), ln, strings.Repeat(" ", inner-visWidth(ln)), bd("│"))
	}
	fmt.Fprintln(w, "  "+bd("╰"+strings.Repeat("─", inner+2)+"╯"))
}

// renderBanner writes the framed splash: header (name + version), the mark
// beside a quick-start command list, and links — the launch/help screen.
func renderBanner(w io.Writer) {
	color := colorTo(w)
	st := func(code, s string) string {
		if !color {
			return s
		}
		return code + s + ansiReset
	}
	blue := func(s string) string { return st(ansiBrandBlue, s) }
	bold := func(s string) string { return st(ansiBold, s) }
	dim := func(s string) string { return st(ansiDim, s) }

	cmd := func(c, d string) string { return blue(padRight(c, 34)) + dim(d) }
	rows := []string{
		bold("Quick start"),
		cmd("secure-vibe init --tool <ide>", "embed skills in your IDE"),
		cmd("secure-vibe scan <path>", "find secrets / bad deps / misconfig"),
		cmd("secure-vibe gate <path>", "CI gate — fail on findings"),
		cmd("secure-vibe mcp", "MCP server over stdio"),
		cmd("secure-vibe --help", "list every command"),
	}

	lines := []string{
		fmt.Sprintf("%s %s  %s", bold("secure-vibe"), blue("v"+CLIVersion),
			dim("· ShieldNet360 · prevention-first security")),
		"",
	}
	const leftW = 12
	for i, lp := range logoRows {
		gap := leftW - len([]rune(lp))
		if gap < 1 {
			gap = 1
		}
		right := ""
		if i < len(rows) {
			right = rows[i]
		}
		lines = append(lines, blue(lp)+strings.Repeat(" ", gap)+right)
	}
	lines = append(lines,
		"",
		bold("SecureVibe")+"  "+dim("prevent · detect · enforce"),
		dim("repo  ")+blue("github.com/ShieldNet-360/secure-vibe"),
		dim("npm   ")+blue("npmjs.com/package/@shieldnet360/secure-vibe"),
	)

	fmt.Fprintln(w)
	boxed(w, lines, color)
	fmt.Fprintln(w)
}

func logoCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "logo",
		Short: "Print the ShieldNet / SecureVibe logo",
		Args:  cobra.NoArgs,
		Run: func(c *cobra.Command, _ []string) {
			renderBanner(c.OutOrStdout())
		},
	}
}
