---
id: electron-security
version: "1.2.0"
title: "Electron Desktop Security"
description: "Harden Electron apps: renderer trust boundary (nodeIntegration, contextIsolation, sandbox), contextBridge/IPC allowlists, shell.openExternal, navigation guards, deep-link auth, safeStorage"
category: hardening
severity: critical
applies_to:
  - "when generating Electron main-process code (BrowserWindow, ipcMain, app events)"
  - "when generating a preload script or contextBridge surface"
  - "when wiring custom-protocol / deep-link handlers"
  - "when storing tokens or secrets in an Electron app"
  - "when reviewing Electron IPC, navigation, or window configuration"
languages: ["javascript", "typescript"]
token_budget:
  minimal: 1400
  compact: 1900
  full: 3300
rules_path: "checklists/"
related_skills: ["frontend-security", "secret-detection", "auth-security", "container-security"]
last_updated: "2026-06-20"
sources:
  - "Electron Security Checklist (official docs)"
  - "OWASP — Electron / desktop application security"
  - "CWE-78, CWE-22, CWE-250, CWE-693, CWE-829, CWE-1188"
  - "Doyensec / Electronegativity research on Electron attack surface"
external_tools:
  - name: electronegativity
    purpose: "Electron app misconfiguration & anti-pattern scan"
    command: "electronegativity -i ."
---

# Electron Desktop Security

## Rules (for AI agents)

The unifying principle: **treat the renderer as untrusted**. Any renderer-side
code execution (XSS in rendered content, a redirect, a deep link) must NOT be
able to reach Node, the shell, the filesystem, or session tokens. Lock the
renderer-trust boundary first; every IPC sink is reachable from a compromised
renderer.

### ALWAYS
- Configure every `BrowserWindow` with `nodeIntegration: false`,
  `contextIsolation: true`, and `sandbox: true`. The preload + contextBridge
  is the supported way to give the renderer capabilities — the page never
  needs Node.
- Expose a **minimal, typed** API from the preload via `contextBridge.exposeInMainWorld`.
  Expose named functions only — never hand the renderer `ipcRenderer`,
  `require`, `process`, or whole modules.
- Validate **every** IPC argument in the main-process handler: type-check,
  bound, and allowlist. The renderer is an attacker-controlled input source.
- Spawn child processes with `execFile` / `spawn` and an **argument array** —
  never `exec` with a shell string built from renderer input. Allowlist each
  argument (e.g. `^[A-Za-z0-9_-]+$`).
- Confine filesystem paths: `path.resolve(base, input)` then verify the result
  `startsWith(base + path.sep)`. Reject absolute paths and `..` segments.
- Allowlist `shell.openExternal` to `https:` (and `mailto:` if needed) after
  parsing the URL. Reject `file:`, custom schemes, and anything else.
- Add navigation guards: `app.on('web-contents-created', …)` with
  `contents.on('will-navigate', …)` and `contents.setWindowOpenHandler(…)`
  that **deny by default** against a strict origin allowlist.
- Remember the contextBridge surface is exposed to **whatever origin the
  webContents currently holds** — `exposeInMainWorld` does *not* re-check origin
  after a navigation. So a single missing `will-navigate` guard lets a remote /
  attacker origin inherit your *entire* IPC surface (this is how a stored
  hyperlink → navigation becomes 1-click RCE). The nav guard is the primary
  control; as defense-in-depth, gate the preload on `location` before exposing.
- Before attaching session tokens / cookies to an outbound request, verify the
  target host is on your own-API allowlist. Never attach credentials to a
  renderer-supplied URL.
- Bind custom-protocol / deep-link auth to a one-time `state` / PKCE value the
  app generated and is waiting for; validate before storing any token.
- Store tokens with Electron `safeStorage` (OS keychain / DPAPI / libsecret),
  not app-level crypto. Enable ASAR integrity + code signing for release.
- Treat **every server the app connects to** — backend, simulation / compute
  node, auto-update channel, a multi-tenant cloud session — as potentially
  attacker-controlled (compromised, co-tenant, or MITM). Never load a server URL
  into a `BrowserWindow` / `<webview>` that carries your preload, and never feed
  a server response into an IPC sink (file path, shell arg, `openExternal` URL)
  without the same validation you apply to renderer input.
- Harden parsers that consume untrusted server / stream data (binary frames,
  SDF / XML, model files): bound every length field before allocating, cap
  recursion and `<include>`-style expansion (circular refs → infinite loop /
  fetch), and wrap the parse in try/catch. Otherwise a malicious server crashes
  or hangs the renderer (DoS), even when memory-safety prevents RCE.

### NEVER
- Set `nodeIntegration: true`, disable `contextIsolation`, disable
  `webSecurity`, or set `allowRunningInsecureContent: true` — especially when
  the window loads remote or navigable content.
- Concatenate renderer input into a shell string
  (`child_process.exec(\`docker kill ${names}\`)`) — command injection.
- Concatenate a renderer-supplied path for `fs` read/write
  (`${BASE}${filePath}`) — path traversal / arbitrary file write.
- Call `shell.openExternal` on an arbitrary or renderer-controlled URL —
  `file:` / custom protocol handlers are a local-launch / RCE vector.
- Attach `Authorization` / session cookies to a URL the renderer chose without
  a host allowlist — XSS then exfiltrates the token.
- Accept a deep-link auth token (`myapp://auth?refresh-token=…`) without
  origin / `state` validation — login CSRF / session fixation.
- Encrypt tokens at rest with AES-CBC (no integrity) or a key derived solely
  from a locally recoverable machine ID, and never keep a `PLAINTEXT:`
  fallback path.
- Ship a frameless / chromeless **navigable** window (`frame: false`, no address
  bar): after a redirect the user has no visual cue they left the app, so a
  phished navigation can silently clone your UI. Frameless is acceptable only
  behind a hard navigation guard.
- Assume the renderer (or its rendered content) is the *only* untrusted input —
  a backend / sim / update server the app trusts can itself be compromised or,
  in multi-tenant deployments, driven by another tenant.

### KNOWN FALSE POSITIVES
- Dev builds that load over `http://localhost:<port>` with relaxed settings —
  the rules apply to **release** builds; ensure dev config never ships.
- A custom protocol (`myapp://`) for OAuth callbacks is expected — the control
  is `state`/PKCE validation, not the scheme's existence.
- `contextBridge`-exposed functions are intentional capabilities; review what
  each one does (and whether it validates input), not the fact that the bridge
  exists.
- `shell.openExternal` on a hard-coded `https://` constant (not user input) is
  fine.
- A frameless window that loads **only** local first-party content (`file://` /
  packaged app) behind a deny-by-default nav guard is fine — the risk is
  frameless **plus** navigable to remote origins.
- Connecting to a backend and rendering its **data** (telemetry JSON, numbers,
  binary frames) is normal desktop behaviour. The control is bounding /
  validating that data and never treating it as HTML, a filesystem path, or a
  shell argument — not avoiding the connection itself.

## Context (for humans)

Electron ships a Chromium renderer and a Node main process in one app. The
single most dangerous misconfiguration is `nodeIntegration: true` with no
navigation guards: it turns any renderer-side bug (XSS in a report/telemetry
view, an open redirect, a deep link) into full host RCE. Every IPC handler the
preload exposes — file write, process exec, `openExternal`, token access — is
then reachable by attacker-controlled renderer code.

AI assistants frequently generate Electron windows with `nodeIntegration: true`
(it makes `require` "just work" in the page), `child_process.exec` with
template-string interpolation, `shell.openExternal(url)` with no validation,
and custom token crypto instead of `safeStorage`. This skill is the
counterweight: keep the renderer sandboxed and every IPC sink validated.

The renderer is the first untrusted boundary, but not the only one: a desktop
app also trusts every server it connects to. In multi-tenant or cloud-compute
setups (a shared simulation backend, a per-session remote node), a co-tenant who
compromises that server becomes an attacker feeding your privileged renderer —
so server URLs must never load into a preload-bearing window, and server data is
input to be validated, not trusted. The worst observed chain is the reverse of
the obvious one: server-controlled content → a navigable preload window →
`electronAPI` → local RCE.


### Verify & lock (triaging a finding)

A scanner/review hit (electronegativity flag, a `webPreferences` line, a raw
`exec`/`openExternal` call) is a *candidate*, not a confirmed bug. Confirm it,
fix it, then lock it so it can't come back.

1. **Confirm it's real (probe / inspect).** Load a test page in the *release*
   build's renderer and try to reach Node: `window.require`, `window.process`,
   `require('child_process').exec(...)`. Real if any resolve — `nodeIntegration:true`
   or `contextIsolation:false`/`sandbox:false`. For an IPC/sink hit, drive the
   exposed `electronAPI` function with hostile input (`../../etc/passwd`,
   `a; id`, `file:///…`, a foreign host for token attach) and watch whether the
   main process traverses/spawns/opens. For nav, attempt a `will-navigate` or
   `window.open` to an external origin and see if it lands. FP if isolation +
   sandbox are on and Node calls throw, the sink type-checks/allowlists and
   rejects, the nav guard denies by default, or it's dev-only config / a
   hard-coded `https:` constant / intentional `myapp://` OAuth with `state`/PKCE.
2. **Fix, then lock with a regression test** (unit *or* integration — dev's
   call). Assert the locked boundary: renderer cannot reach `require`/Node;
   every `BrowserWindow` carries `nodeIntegration:false`, `contextIsolation:true`,
   `sandbox:true`, `webSecurity:true`; IPC handlers reject traversal/injection/
   foreign-host args; the nav guard denies an external origin and
   `setWindowOpenHandler` returns deny; tokens go through `safeStorage` with no
   `PLAINTEXT:` fallback. Add one benign in-app action (valid IPC call, allowed
   `https:` open) that still works. Commit it so the guard can't be silently
   dropped.

## References

- `checklists/electron_hardening.yaml` — machine-readable hardening checks
  (window config, IPC sinks, navigation, deep-link, token storage).
- [Electron Security Checklist](https://www.electronjs.org/docs/latest/tutorial/security).
- [CWE-78 — OS Command Injection](https://cwe.mitre.org/data/definitions/78.html).
- [CWE-22 — Path Traversal](https://cwe.mitre.org/data/definitions/22.html).
- [CWE-250 — Execution with Unnecessary Privileges](https://cwe.mitre.org/data/definitions/250.html).
