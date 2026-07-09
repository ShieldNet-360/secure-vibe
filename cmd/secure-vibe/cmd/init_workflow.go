package cmd

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
)

// workflowTemplate is the Claude Code Workflow that fans `secure-vibe audit`
// out per directory and synthesizes one ranked report. It is embedded so
// `init --tool claude` can drop it into a project without a separate download.
// This is the single source of truth; the repo's own copy under
// .claude/workflows/ is generated from it (see TestWorkflowTemplateMatchesRepo).
//
//go:embed templates/secure-vibe-audit.js
var workflowTemplate string

// workflowRelPath is where a Claude Code project looks for named workflows.
const workflowRelPath = ".claude/workflows/secure-vibe-audit.js"

// writeAuditWorkflow drops the bundled audit workflow into outDir. It never
// clobbers an existing file — a user may have customised it — so re-running
// init is safe. Returns the path written (or the pre-existing path) and
// whether a new file was created.
func writeAuditWorkflow(outDir string) (path string, wrote bool, err error) {
	path = filepath.Join(outDir, workflowRelPath)
	if _, statErr := os.Stat(path); statErr == nil {
		return path, false, nil // already present — leave the user's copy alone
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return path, false, err
	}
	if err := os.WriteFile(path, []byte(workflowTemplate), 0o644); err != nil {
		return path, false, err
	}
	return path, true, nil
}

// workflowNote is the one-liner init prints after installing the workflow, so
// the user knows the entry point.
func workflowNote(path string, wrote bool) string {
	if wrote {
		return fmt.Sprintf("wrote %s — run it from Claude Code with \"use a workflow\" › secure-vibe-audit", path)
	}
	return fmt.Sprintf("kept existing %s (not overwritten)", path)
}
