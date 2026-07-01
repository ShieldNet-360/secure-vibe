//go:build js && wasm

// Command skills-wasm exposes the REAL SecureVibe scanners to the browser so
// the docs playground runs the same engine the CLI does — no backend, no
// network, no telemetry. The malicious-package DB, typosquat DB, and
// secret-detection rules are baked in via go:embed (populated by `make wasm`),
// and the Library reads them through its fs.FS data path (NewLibraryFS).
//
// JS API (set on the global object once the runtime is up):
//
//	svScanDeps(filename, content) -> JSON {deps, findings}
//	svScanSecrets(text)           -> JSON CheckSecretPatternResult
//	svReady                       -> true
//	window.svOnReady()            -> called if defined, after setup
package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"syscall/js"

	"github.com/shieldnet-360/secure-vibe/internal/tools"
	"github.com/shieldnet-360/secure-vibe/internal/tools/parsers"
)

// embed/ is a build-time copy of the real data tree (see the `wasm` Makefile
// target); it mirrors the repo layout so NewLibraryFS resolves the same
// root-relative paths the on-disk Library uses.
//
//go:embed embed
var embedded embed.FS

var lib *tools.Library

func main() {
	data, err := fs.Sub(embedded, "embed")
	if err != nil {
		panic(err)
	}
	lib = tools.NewLibraryFS(data)

	js.Global().Set("svScanDeps", js.FuncOf(scanDeps))
	js.Global().Set("svScanSecrets", js.FuncOf(scanSecrets))
	js.Global().Set("svReady", js.ValueOf(true))
	if cb := js.Global().Get("svOnReady"); cb.Type() == js.TypeFunction {
		cb.Invoke()
	}
	select {} // keep the Go runtime alive to service callbacks
}

// asJSON marshals v (or an {"error": ...} object) to a JSON string for JS.
func asJSON(v interface{}, err error) interface{} {
	if err != nil {
		b, _ := json.Marshal(map[string]string{"error": err.Error()})
		return string(b)
	}
	b, mErr := json.Marshal(v)
	if mErr != nil {
		return asJSON(nil, mErr)
	}
	return string(b)
}

func scanSecrets(_ js.Value, args []js.Value) interface{} {
	if len(args) < 1 {
		return asJSON(nil, fmt.Errorf("usage: svScanSecrets(text)"))
	}
	res, err := lib.CheckSecretPattern(args[0].String())
	return asJSON(res, err)
}

type depFinding struct {
	Name      string                          `json:"name"`
	Version   string                          `json:"version"`
	Ecosystem string                          `json:"ecosystem"`
	Result    *tools.LookupVulnerabilityResult `json:"result"`
}

func scanDeps(_ js.Value, args []js.Value) interface{} {
	if len(args) < 2 {
		return asJSON(nil, fmt.Errorf("usage: svScanDeps(filename, content)"))
	}
	name := args[0].String()
	deps, err := parsers.Parse(name, []byte(args[1].String()))
	if err != nil {
		return asJSON(nil, err)
	}
	findings := make([]depFinding, 0, len(deps))
	for _, d := range deps {
		r, _ := lib.LookupVulnerability(d.Name, d.Ecosystem, d.Version)
		findings = append(findings, depFinding{d.Name, d.Version, d.Ecosystem, r})
	}
	return asJSON(map[string]interface{}{"deps": deps, "findings": findings}, nil)
}
