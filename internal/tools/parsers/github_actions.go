package parsers

import (
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Workflow is the parsed shape of a `.github/workflows/<name>.yml`
// file. The parser keeps only the fields the scanner rules examine —
// `on`, top-level `permissions`, and the per-job step list. Job
// `runs-on` is retained because future rules may distinguish
// self-hosted runners from GitHub-hosted ones.
//
// The `permissions` block is intentionally typed as
// `map[string]interface{}` rather than a concrete enum because GitHub
// accepts both the scalar form ("read-all"/"write-all") and the
// per-scope map form. Rules normalise on lookup.
type Workflow struct {
	OnRaw       yaml.Node              `yaml:"on"`
	Permissions interface{}            `yaml:"permissions"`
	Jobs        map[string]WorkflowJob `yaml:"jobs"`
}

// WorkflowJob is one job under `jobs:` in a workflow file.
type WorkflowJob struct {
	Permissions interface{}       `yaml:"permissions"`
	RunsOn      interface{}       `yaml:"runs-on"`
	Steps       []WorkflowStep    `yaml:"steps"`
	If          string            `yaml:"if"`
	Needs       interface{}       `yaml:"needs"`
	Env         map[string]string `yaml:"env"`
}

// WorkflowStep is one entry in a job's `steps:` list.
type WorkflowStep struct {
	Name string                 `yaml:"name"`
	ID   string                 `yaml:"id"`
	Uses string                 `yaml:"uses"`
	Run  string                 `yaml:"run"`
	With map[string]interface{} `yaml:"with"`
	Env  map[string]string      `yaml:"env"`
	If   string                 `yaml:"if"`
	// Line is the 1-based line number where this step's `-` marker
	// appears. Populated by ParseWorkflow on success.
	Line int `yaml:"-"`
}

// shaPinPattern recognises the canonical 40-character SHA used to
// pin third-party actions. GitHub also accepts 7-char short SHAs in
// the UI but `actions/checkout@<short>` is silently treated as a
// branch by the runner, so we deliberately do NOT accept short SHAs
// here.
var shaPinPattern = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)

// ParseWorkflow decodes a GitHub Actions workflow file. The returned
// pointer is nil and err is non-nil only when the YAML itself fails
// to decode; an empty / partial file decodes cleanly and yields a
// Workflow with zero-valued jobs.
func ParseWorkflow(body []byte) (*Workflow, error) {
	wf := &Workflow{}
	if err := yaml.Unmarshal(body, wf); err != nil {
		return nil, err
	}

	// Walk the raw YAML to attach line numbers to each step. The
	// strongly-typed unmarshal above loses node positions, so we
	// re-parse into a tree and zip the per-job step lists onto the
	// existing WorkflowStep slice. This costs one extra parse per
	// file but avoids a hand-written YAML decoder.
	var doc yaml.Node
	if err := yaml.Unmarshal(body, &doc); err == nil {
		attachStepLines(wf, &doc)
	}
	return wf, nil
}

// attachStepLines walks doc to find each job's steps sequence and
// copies the 1-based line number of each step into the corresponding
// WorkflowStep. Errors are silently swallowed because the strongly-
// typed decode has already produced a usable Workflow; line numbers
// are advisory.
func attachStepLines(wf *Workflow, doc *yaml.Node) {
	if doc == nil || len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return
	}
	root := doc.Content[0]
	var jobsNode *yaml.Node
	for i := 0; i+1 < len(root.Content); i += 2 {
		k := root.Content[i]
		if k.Value == "jobs" {
			jobsNode = root.Content[i+1]
			break
		}
	}
	if jobsNode == nil || jobsNode.Kind != yaml.MappingNode {
		return
	}
	for i := 0; i+1 < len(jobsNode.Content); i += 2 {
		jobName := jobsNode.Content[i].Value
		jobBody := jobsNode.Content[i+1]
		if jobBody.Kind != yaml.MappingNode {
			continue
		}
		var stepsNode *yaml.Node
		for j := 0; j+1 < len(jobBody.Content); j += 2 {
			if jobBody.Content[j].Value == "steps" {
				stepsNode = jobBody.Content[j+1]
				break
			}
		}
		if stepsNode == nil || stepsNode.Kind != yaml.SequenceNode {
			continue
		}
		job, ok := wf.Jobs[jobName]
		if !ok {
			continue
		}
		for k, item := range stepsNode.Content {
			if k >= len(job.Steps) {
				break
			}
			job.Steps[k].Line = item.Line
		}
		wf.Jobs[jobName] = job
	}
}

// HasPermissions returns true when the workflow declares any
// top-level `permissions:` block (whether scalar or per-scope).
func (w *Workflow) HasPermissions() bool {
	return w.Permissions != nil
}

// IsPinnedAction reports whether `uses` references an action pinned
// to a 40-character commit SHA. Anything else — version tag, branch
// name, local path, or unpinned reference — returns false. Local
// actions (`./.github/actions/foo`) and reusable workflows in the
// same repo (`./.github/workflows/x.yml`) are exempt because they
// share the calling repo's commit and can't drift independently.
func IsPinnedAction(uses string) bool {
	uses = strings.TrimSpace(uses)
	if uses == "" {
		return false
	}
	if strings.HasPrefix(uses, "./") {
		return true
	}
	at := strings.LastIndex(uses, "@")
	if at == -1 {
		return false
	}
	return shaPinPattern.MatchString(uses[at+1:])
}

// expressionInjectionPattern matches the `${{ github.event.* }}` and
// related untrusted-source expressions that are unsafe to interpolate
// directly into a `run:` block. The pattern deliberately stays loose
// (any `${{ github.event… }}` or `${{ github.head_ref }}`) to
// minimise false negatives; downstream rules can scope further.
var expressionInjectionPattern = regexp.MustCompile(
	`\$\{\{\s*github\.(event\.|head_ref|pull_request|issue\.title|issue\.body|comment\.body)`,
)

// HasUntrustedExpressionInjection scans s for the classic GHA
// expression-injection pattern: an untrusted attacker-controlled
// value (PR title, head ref, comment body, ...) interpolated into
// a `run:` block where the runner will shell-execute it.
func HasUntrustedExpressionInjection(s string) bool {
	return expressionInjectionPattern.MatchString(s)
}

// IsPullRequestTarget reports whether the workflow's `on:` trigger
// list includes `pull_request_target`. The trigger runs with the
// *base* repository's secrets even when the workflow file is being
// invoked from a forked PR; combining it with `actions/checkout@*`
// pointed at the PR head is the well-known PWN-request pattern.
func (w *Workflow) IsPullRequestTarget() bool {
	if w.OnRaw.Kind == 0 {
		return false
	}
	return yamlNodeMentions(&w.OnRaw, "pull_request_target")
}

// yamlNodeMentions returns true when the YAML tree under node
// contains the literal scalar `value` as either a sequence entry, a
// mapping key, or a scalar value. The check is intentionally
// permissive because the `on:` field accepts a wide variety of
// shapes (scalar string, sequence of strings, mapping of trigger →
// config).
func yamlNodeMentions(node *yaml.Node, value string) bool {
	if node == nil {
		return false
	}
	switch node.Kind {
	case yaml.ScalarNode:
		return node.Value == value
	case yaml.SequenceNode:
		for _, c := range node.Content {
			if yamlNodeMentions(c, value) {
				return true
			}
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(node.Content); i += 2 {
			if node.Content[i].Value == value {
				return true
			}
			if yamlNodeMentions(node.Content[i+1], value) {
				return true
			}
		}
	case yaml.DocumentNode, yaml.AliasNode:
		for _, c := range node.Content {
			if yamlNodeMentions(c, value) {
				return true
			}
		}
	}
	return false
}

// IsCheckoutAction returns true for steps that invoke
// `actions/checkout`. The match is deliberately loose (any version
// pin / SHA) because the rule wants to flag the combination of
// trigger + action, not the action's pin shape.
func IsCheckoutAction(uses string) bool {
	uses = strings.TrimSpace(uses)
	if uses == "" {
		return false
	}
	// Strip optional version pin after the @.
	if at := strings.LastIndex(uses, "@"); at != -1 {
		uses = uses[:at]
	}
	return strings.EqualFold(uses, "actions/checkout")
}
