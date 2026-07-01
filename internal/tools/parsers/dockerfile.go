package parsers

import (
	"bufio"
	"bytes"
	"regexp"
	"strings"
)

// DockerfileStage is one FROM ... block in a parsed Dockerfile.
//
// BaseImage records the image reference exactly as written (e.g.
// "node:20-alpine", "${BASE_IMAGE}", "node:latest"). When the value
// is an ARG-style placeholder, ResolvedBase carries the lookup-from
// the file's ARG defaults — empty when no default could be found.
//
// Alias is the optional `AS <name>` label so downstream rules can
// distinguish the final stage from intermediate builder stages. Line
// records the 1-based line number of the FROM directive so a finding
// can point back at the source.
type DockerfileStage struct {
	Index        int
	BaseImage    string
	ResolvedBase string
	Alias        string
	Line         int
	// FinalUser is the last `USER` directive observed inside this
	// stage. Empty when the stage never sets a USER (which means
	// the final user is inherited from the base image — and is
	// effectively root for most public images).
	FinalUser     string
	FinalUserLine int
}

// Dockerfile is the result of parsing a Dockerfile into stages with
// joined continuation lines. The intent is to support rules that
// only fire against the final stage (USER, FROM) — the regex-only
// fallback in ScanDockerfile fires per-line and can't distinguish
// a builder-stage `USER root` from a runtime `USER root`.
type Dockerfile struct {
	Stages []DockerfileStage

	// Args is the snapshot of ARG defaults visible at file scope
	// (the only scope ARG-substituted FROM values can read from).
	Args map[string]string

	// Lines retains the joined-line view of the Dockerfile so
	// downstream regex checks can run against the canonical form
	// (continuation lines coalesced). Each entry pairs the 1-based
	// source line where the joined directive started with the joined
	// text.
	Lines []DockerfileLine
}

// DockerfileLine is one logical Dockerfile directive after
// backslash-continuation joining.
type DockerfileLine struct {
	StartLine int
	Text      string
	// Stage is the 0-based index into Dockerfile.Stages for the
	// stage this line belongs to, or -1 for the file-scope lines
	// that precede the first FROM (typically ARG directives).
	Stage int
}

// FinalStage returns a pointer to the last stage in the file or nil
// when no FROM was seen.
func (d *Dockerfile) FinalStage() *DockerfileStage {
	if len(d.Stages) == 0 {
		return nil
	}
	return &d.Stages[len(d.Stages)-1]
}

// argRefPattern matches the two ARG-substitution forms accepted in a
// FROM base image: ${NAME} and $NAME. We deliberately do NOT support
// ${NAME:-default} fallbacks inside the FROM — that's a BuildKit
// extension and the safer interpretation when we can't resolve is to
// leave ResolvedBase empty so a downstream rule can fire on the
// unresolved form.
var argRefPattern = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)`)

// ParseDockerfile reads body (the Dockerfile contents) and returns
// a Dockerfile struct with stages, ARG defaults, and joined-line
// view. Comments and blank lines are dropped from the joined view.
//
// The parser is intentionally minimal — it understands FROM, AS,
// USER, and ARG. Everything else lands in Dockerfile.Lines for
// downstream regex rules to inspect. The caller can then run
// stage-aware checks (final-stage USER, FROM resolution) on the
// structured surface and fall back to the existing regex checks
// for the remainder.
func ParseDockerfile(body []byte) *Dockerfile {
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 64*1024), 1<<20)

	df := &Dockerfile{Args: map[string]string{}}

	var (
		joined      strings.Builder
		joinedStart int
		// stageIdx is the 0-based index of the stage we're currently
		// inside; -1 means "file scope, before the first FROM".
		stageIdx = -1
		lineNo   = 0
	)

	flush := func() {
		text := strings.TrimSpace(joined.String())
		joined.Reset()
		if text == "" {
			return
		}
		// Drop trailing comments. Inline comments after a `#` are
		// only valid at the start of a line in real Dockerfile
		// syntax, so this is conservative.
		if strings.HasPrefix(text, "#") {
			return
		}
		df.Lines = append(df.Lines, DockerfileLine{
			StartLine: joinedStart,
			Text:      text,
			Stage:     stageIdx,
		})
		instr, rest := splitInstruction(text)
		switch strings.ToUpper(instr) {
		case "ARG":
			name, def := parseArg(rest)
			if name != "" && def != "" {
				df.Args[name] = def
			}
		case "FROM":
			base, alias := parseFrom(rest)
			stageIdx++
			df.Stages = append(df.Stages, DockerfileStage{
				Index:        stageIdx,
				BaseImage:    base,
				ResolvedBase: resolveArgs(base, df.Args),
				Alias:        alias,
				Line:         joinedStart,
			})
			// Re-tag the FROM line itself as belonging to the new stage
			// (it was emitted with the previous stage index above).
			df.Lines[len(df.Lines)-1].Stage = stageIdx
		case "USER":
			user := strings.TrimSpace(rest)
			if user != "" && stageIdx >= 0 {
				df.Stages[stageIdx].FinalUser = user
				df.Stages[stageIdx].FinalUserLine = joinedStart
			}
		}
	}

	for scanner.Scan() {
		lineNo++
		raw := strings.TrimRight(scanner.Text(), "\r")
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			// Comment / blank ends any in-progress join because
			// Dockerfile continuation explicitly skips comment lines;
			// rebuild that behaviour by flushing first.
			if joined.Len() > 0 {
				flush()
			}
			continue
		}
		if joined.Len() == 0 {
			joinedStart = lineNo
		}
		if strings.HasSuffix(trimmed, "\\") {
			joined.WriteString(strings.TrimSuffix(trimmed, "\\"))
			joined.WriteByte(' ')
			continue
		}
		joined.WriteString(trimmed)
		flush()
	}
	if joined.Len() > 0 {
		flush()
	}
	return df
}

// splitInstruction returns (instr, rest) for a Dockerfile line.
func splitInstruction(line string) (string, string) {
	idx := strings.IndexFunc(line, func(r rune) bool { return r == ' ' || r == '\t' })
	if idx == -1 {
		return line, ""
	}
	return line[:idx], strings.TrimSpace(line[idx+1:])
}

// parseArg extracts `ARG NAME=default` -> ("NAME", "default"). When
// the default is missing the function returns ("NAME", ""). Quoted
// defaults are unwrapped.
func parseArg(rest string) (string, string) {
	rest = strings.TrimSpace(rest)
	if rest == "" {
		return "", ""
	}
	eq := strings.IndexByte(rest, '=')
	if eq == -1 {
		return rest, ""
	}
	name := strings.TrimSpace(rest[:eq])
	def := strings.TrimSpace(rest[eq+1:])
	if len(def) >= 2 && (def[0] == '"' || def[0] == '\'') && def[len(def)-1] == def[0] {
		def = def[1 : len(def)-1]
	}
	return name, def
}

// parseFrom returns (base, alias) for a FROM directive's tail. The
// optional `--platform=...` prefix is skipped, and case-insensitive
// `AS <alias>` is parsed off the end.
func parseFrom(rest string) (string, string) {
	rest = strings.TrimSpace(rest)
	// Drop the optional --platform= flag (and any future BuildKit
	// flags) so the base image is the first remaining token.
	for strings.HasPrefix(rest, "--") {
		sp := strings.IndexAny(rest, " \t")
		if sp == -1 {
			rest = ""
			break
		}
		rest = strings.TrimSpace(rest[sp+1:])
	}
	if rest == "" {
		return "", ""
	}
	fields := strings.Fields(rest)
	base := fields[0]
	alias := ""
	if len(fields) >= 3 && strings.EqualFold(fields[len(fields)-2], "AS") {
		alias = fields[len(fields)-1]
	}
	return base, alias
}

// resolveArgs expands ${VAR} / $VAR using args. Unknown variables
// resolve to the empty string so downstream rules see the gap rather
// than a literal placeholder.
func resolveArgs(value string, args map[string]string) string {
	if !strings.Contains(value, "$") {
		return value
	}
	return argRefPattern.ReplaceAllStringFunc(value, func(match string) string {
		m := argRefPattern.FindStringSubmatch(match)
		var name string
		switch {
		case m[1] != "":
			name = m[1]
		default:
			name = m[2]
		}
		if v, ok := args[name]; ok {
			return v
		}
		return ""
	})
}

// IsRootUser returns true when the value is the literal root user
// (uid 0 or the name `root`). Whitespace and inline comments are
// tolerated. Anything else — including the empty string — is
// treated as non-root for IsRootUser purposes; callers that care
// about an unset USER should check FinalUser == "" separately.
func IsRootUser(user string) bool {
	user = strings.TrimSpace(user)
	if user == "" {
		return false
	}
	// Drop trailing comment / colon-separated group ("root:root").
	if idx := strings.IndexAny(user, " :#"); idx > -1 {
		user = user[:idx]
	}
	return user == "0" || strings.EqualFold(user, "root")
}
