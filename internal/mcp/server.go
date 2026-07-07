// Package mcp implements the Model Context Protocol server that backs
// the secure-vibe mcp binary. The transport is JSON-RPC 2.0 over stdio with
// one request per line.
package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/shieldnet-360/secure-vibe/internal/audit"
	"github.com/shieldnet-360/secure-vibe/internal/tools"
	"github.com/shieldnet-360/secure-vibe/internal/verify"
)

// Server is the JSON-RPC dispatcher. It owns one Library and exposes the
// 18 Skills Library tools as MCP tools: lookup_vulnerability,
// check_secret_pattern, get_skill, search_skills, scan_secrets,
// check_dependency, check_typosquat, map_compliance_control,
// get_sigma_rule, version_status, scan_dependencies,
// scan_github_actions, scan_dockerfile, list_external_tools,
// explain_finding, gate (formerly policy_check), verify_finding, and
// audit (whole-tree deterministic audit).
type Server struct {
	lib *tools.Library
}

// NewServer wires a Server up against the library rooted at root.
// Optional tools.LibraryOption values configure the underlying
// Library — e.g. tools.WithVulnSource(tools.SourceHybrid) to enable
// the external OSV.dev backend. Calling NewServer(root) with no
// options preserves the pre-existing behaviour exactly.
func NewServer(root string, opts ...tools.LibraryOption) (*Server, error) {
	lib, err := tools.NewLibrary(root, opts...)
	if err != nil {
		return nil, err
	}
	return &Server{lib: lib}, nil
}

// SetAllowedRoots restricts the scan_secrets file_path argument to
// the supplied directories. Delegates to the underlying Library so
// the policy lives on the same object that performs the check; see
// tools.Library.SetAllowedRoots for the canonicalisation rules.
func (s *Server) SetAllowedRoots(roots []string) error {
	return s.lib.SetAllowedRoots(roots)
}

// JSON-RPC 2.0 wire types.
type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  interface{}     `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    string `json:"data,omitempty"`
}

const (
	codeParseError     = -32700
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
	codeInternalError  = -32603
)

// SupportedProtocolVersion is the MCP spec revision this server implements.
// See https://modelcontextprotocol.io/specification/2025-11-25.
//
// Per the lifecycle spec, the server MUST respond to `initialize` with a
// protocol version it supports. We respond with this constant unless the
// client requested an older version we also recognise — in which case we
// echo back the requested version (see negotiateProtocolVersion).
const SupportedProtocolVersion = "2025-11-25"

// protocolVersionWithInstructions is the earliest MCP revision in which
// the server's `initialize` response may carry an `instructions`
// field. Per the MCP spec, claiming an older version while emitting
// fields from a newer revision is a protocol violation.
const protocolVersionWithInstructions = "2025-03-26"

// protocolVersionWithTitle is the earliest MCP revision in which the
// server's `initialize` response may carry `serverInfo.title`.
const protocolVersionWithTitle = "2025-11-25"

// supportedProtocolVersions is the descending list of MCP revisions this
// server can speak. The first entry is the preferred version and matches
// SupportedProtocolVersion.
var supportedProtocolVersions = []string{
	"2025-11-25",
	"2025-06-18",
	"2025-03-26",
	"2024-11-05",
}

// protocolVersionPattern matches the YYYY-MM-DD shape that the MCP
// spec uses for revision identifiers. The lexicographic `>=`
// comparisons in dispatch() that gate `instructions` and
// `serverInfo.title` are only correct as long as every value being
// compared has this fixed-width zero-padded shape — and the values
// being compared are exactly the entries of supportedProtocolVersions
// plus the two protocolVersionWith* constants. If MCP ever ships a
// non-date version identifier (e.g. `v3.0`), the comparison would
// silently produce the wrong gating decision. assertProtocolVersionShape
// turns that into a loud build-time failure instead.
var protocolVersionPattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)

func init() {
	assertProtocolVersionShape("SupportedProtocolVersion", SupportedProtocolVersion)
	assertProtocolVersionShape("protocolVersionWithInstructions", protocolVersionWithInstructions)
	assertProtocolVersionShape("protocolVersionWithTitle", protocolVersionWithTitle)
	for _, v := range supportedProtocolVersions {
		assertProtocolVersionShape("supportedProtocolVersions", v)
	}
}

func assertProtocolVersionShape(label, v string) {
	if !protocolVersionPattern.MatchString(v) {
		panic(fmt.Sprintf(
			"mcp: %s=%q does not match YYYY-MM-DD; the protocol-version "+
				"gating in dispatch() relies on lexicographic ordering of "+
				"date strings. Update the gating logic before introducing "+
				"a non-date version identifier.",
			label, v,
		))
	}
}

// negotiateProtocolVersion implements the MCP "Version Negotiation" rule:
// if the client requested a version we support, return it verbatim;
// otherwise return our latest supported version. An empty client version
// also falls back to our latest.
func negotiateProtocolVersion(requested string) string {
	if requested == "" {
		return SupportedProtocolVersion
	}
	for _, v := range supportedProtocolVersions {
		if v == requested {
			return v
		}
	}
	return SupportedProtocolVersion
}

// Serve reads JSON-RPC messages from r, dispatches them, and writes
// responses to w. One message per line. Notifications (no id) get no
// response.
func (s *Server) Serve(r io.Reader, w io.Writer) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(strings.TrimSpace(string(line))) == 0 {
			continue
		}
		resp := s.HandleLine(line)
		if resp == nil {
			continue
		}
		out, err := json.Marshal(resp)
		if err != nil {
			return fmt.Errorf("marshal response: %w", err)
		}
		out = append(out, '\n')
		if _, err := w.Write(out); err != nil {
			return err
		}
	}
	return scanner.Err()
}

// HandleLine parses one JSON-RPC line and returns the response (or nil
// for a notification). Exported so tests can drive the dispatcher
// without spinning up a real reader/writer pair.
func (s *Server) HandleLine(line []byte) *response {
	var req request
	if err := json.Unmarshal(line, &req); err != nil {
		return errorResponse(nil, codeParseError, "parse error: "+err.Error())
	}
	if req.JSONRPC != "2.0" {
		return errorResponse(req.ID, codeInvalidRequest, "jsonrpc must be 2.0")
	}
	// Per JSON-RPC 2.0 §4.1, a notification is a request without an
	// "id" member. Explicit `"id": null` is a request and MUST receive
	// a response.
	isNotification := len(req.ID) == 0
	resp := s.dispatch(&req)
	if isNotification {
		return nil
	}
	resp.ID = req.ID
	return resp
}

func (s *Server) dispatch(req *request) *response {
	switch req.Method {
	case "initialize":
		// Best-effort parse of the client-requested protocol version
		// for version negotiation. The field is OPTIONAL per the
		// MCP lifecycle spec; an empty/absent value falls back to
		// our latest supported version.
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		if len(req.Params) > 0 {
			_ = json.Unmarshal(req.Params, &p)
		}
		negotiated := negotiateProtocolVersion(p.ProtocolVersion)
		serverInfo := map[string]interface{}{
			"name":    "secure-vibe",
			"version": "0.1.0",
		}
		// serverInfo.title was introduced in 2025-11-25; emit it only
		// when we negotiated at least that revision. Per the MCP
		// lifecycle spec, claiming an older version while emitting
		// newer-spec fields is a protocol violation even though most
		// clients tolerate unknown fields.
		if negotiated >= protocolVersionWithTitle {
			serverInfo["title"] = "SecureVibe skills MCP server"
		}
		result := map[string]interface{}{
			"protocolVersion": negotiated,
			"serverInfo":      serverInfo,
			"capabilities": map[string]interface{}{
				"tools": map[string]interface{}{},
			},
		}
		// instructions was introduced in 2025-03-26; older clients
		// won't recognise it and we shouldn't claim to speak their
		// version while emitting it.
		if negotiated >= protocolVersionWithInstructions {
			result["instructions"] = "Use the SecureVibe skills before generating or reviewing security-sensitive code. For dependencies call check_dependency / check_typosquat / lookup_vulnerability; for secrets call scan_secrets or check_secret_pattern; for detection logic call get_sigma_rule; to map findings to compliance call map_compliance_control; to fetch a curated skill call get_skill / search_skills. Use version_status to confirm the data version and signature state before relying on results."
		}
		return successResponse(req.ID, result)
	case "tools/list":
		return successResponse(req.ID, map[string]interface{}{
			"tools": toolDefinitions(),
		})
	case "tools/call":
		return s.handleToolsCall(req)
	default:
		return errorResponse(req.ID, codeMethodNotFound, "method not found: "+req.Method)
	}
}

func (s *Server) handleToolsCall(req *request) *response {
	var p struct {
		Name      string                 `json:"name"`
		Arguments map[string]interface{} `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &p); err != nil {
		return errorResponse(req.ID, codeInvalidParams, "invalid params: "+err.Error())
	}
	if p.Arguments == nil {
		p.Arguments = map[string]interface{}{}
	}
	result, err := s.invokeTool(p.Name, p.Arguments)
	if err != nil {
		if errors.Is(err, errToolNotFound) {
			return errorResponse(req.ID, codeMethodNotFound, err.Error())
		}
		return errorResponse(req.ID, codeInternalError, err.Error())
	}
	body, err := json.Marshal(result)
	if err != nil {
		return errorResponse(req.ID, codeInternalError, "marshal tool result: "+err.Error())
	}
	return successResponse(req.ID, map[string]interface{}{
		"content": []map[string]string{
			{"type": "text", "text": string(body)},
		},
		"structuredContent": result,
	})
}

var errToolNotFound = errors.New("tool not found")

func (s *Server) invokeTool(name string, args map[string]interface{}) (interface{}, error) {
	switch name {
	case "lookup_vulnerability":
		return s.lib.LookupVulnerability(
			stringArg(args, "package"),
			stringArg(args, "ecosystem"),
			stringArg(args, "version"),
		)
	case "check_secret_pattern":
		return s.lib.CheckSecretPattern(stringArg(args, "text"))
	case "get_skill":
		return s.lib.GetSkill(
			stringArg(args, "skill_id"),
			stringArg(args, "budget"),
		)
	case "search_skills":
		return s.lib.SearchSkills(stringArg(args, "query"))
	case "scan_secrets":
		res, err := s.lib.ScanSecrets(
			stringArg(args, "text"),
			stringArg(args, "file_path"),
		)
		if err != nil {
			return nil, err
		}
		if strings.EqualFold(stringArg(args, "format"), "sarif") {
			return tools.ScanSecretsSARIF(res), nil
		}
		return res, nil
	case "check_dependency":
		res, err := s.lib.CheckDependency(
			stringArg(args, "package"),
			stringArg(args, "version"),
			stringArg(args, "ecosystem"),
		)
		if err != nil {
			return nil, err
		}
		if strings.EqualFold(stringArg(args, "format"), "sarif") {
			return tools.CheckDependencySARIF(res), nil
		}
		return res, nil
	case "check_typosquat":
		return s.lib.CheckTyposquat(
			stringArg(args, "package"),
			stringArg(args, "ecosystem"),
		)
	case "map_compliance_control":
		return s.lib.MapComplianceControl(
			stringArg(args, "skill_id"),
			stringArg(args, "query"),
			stringArg(args, "framework"),
		)
	case "get_sigma_rule":
		return s.lib.GetSigmaRule(
			stringArg(args, "rule_id"),
			stringArg(args, "query"),
			stringArg(args, "category"),
		)
	case "version_status":
		return s.lib.VersionStatus()
	case "scan_dependencies":
		res, err := s.lib.ScanDependencies(stringArg(args, "file_path"))
		if err != nil {
			return nil, err
		}
		if strings.EqualFold(stringArg(args, "format"), "sarif") {
			return tools.ScanDependenciesSARIF(res), nil
		}
		return res, nil
	case "scan_github_actions":
		res, err := s.lib.ScanGitHubActions(stringArg(args, "file_path"))
		if err != nil {
			return nil, err
		}
		if strings.EqualFold(stringArg(args, "format"), "sarif") {
			return tools.ScanGitHubActionsSARIF(res), nil
		}
		return res, nil
	case "scan_dockerfile":
		res, err := s.lib.ScanDockerfile(stringArg(args, "file_path"))
		if err != nil {
			return nil, err
		}
		if strings.EqualFold(stringArg(args, "format"), "sarif") {
			return tools.ScanDockerfileSARIF(res), nil
		}
		return res, nil
	case "list_external_tools":
		return s.lib.ListExternalTools()
	case "explain_finding":
		return s.lib.ExplainFinding(stringArg(args, "query"))
	case "gate", "policy_check":
		// "policy_check" kept as a back-compat alias for the renamed
		// "gate" tool so existing callers keep working.
		return s.lib.PolicyCheck(
			stringArg(args, "file_path"),
			stringArg(args, "severity_floor"),
		)
	case "verify_finding":
		// Active DAST verify. Scope + Confirm come from the operator's env,
		// never from the model: unset scope ⇒ dry-run only (builds payload,
		// sends nothing). See verify package safety rails.
		allow, headers, scoped := loadVerifyScope()
		target := stringArg(args, "target")
		f := verify.Finding{
			Type:   stringArg(args, "type"),
			Target: target,
			Param:  stringArg(args, "param"),
			Method: stringArg(args, "method"),
			Query:  mapArg(args, "query"),
			Header: headers(target), // operator-resolved auth (scope file), never from the model
		}
		return verify.Run(context.Background(), f, verify.Opts{
			Confirm:     scoped,
			AllowTarget: allow,
		})
	case "audit":
		// Whole-tree deterministic audit. Reuses the server Library (so the
		// allowed-roots sandbox is enforced) serially — jobs=1 avoids sharing
		// mutable library state across goroutines. The LLM lanes are a CLI
		// concern; here the calling agent is the reasoning layer.
		root := stringArg(args, "path")
		if strings.TrimSpace(root) == "" {
			root = "."
		}
		rootAbs, err := filepath.Abs(root)
		if err != nil {
			return nil, err
		}
		files, err := tools.ExpandGateFiles([]string{rootAbs})
		if err != nil {
			return nil, err
		}
		newLib := func() (*tools.Library, error) { return s.lib, nil }
		return audit.Run(context.Background(), files, newLib, audit.Options{
			Root:          rootAbs,
			SeverityFloor: stringArg(args, "severity_floor"),
			Jobs:          1,
		})
	}
	return nil, fmt.Errorf("%w: %s", errToolNotFound, name)
}

// mapArg extracts a string→string map argument (e.g. "query").
func mapArg(args map[string]interface{}, key string) map[string]string {
	out := map[string]string{}
	if v, ok := args[key].(map[string]interface{}); ok {
		for k, val := range v {
			if s, ok := val.(string); ok {
				out[k] = s
			}
		}
	}
	return out
}

func stringArg(args map[string]interface{}, key string) string {
	v, ok := args[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}

func successResponse(id json.RawMessage, result interface{}) *response {
	return &response{JSONRPC: "2.0", ID: id, Result: result}
}

func errorResponse(id json.RawMessage, code int, msg string) *response {
	return &response{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: msg}}
}
