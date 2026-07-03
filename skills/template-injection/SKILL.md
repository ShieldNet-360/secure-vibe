---
id: template-injection
version: "1.0.0"
title: "Template Injection (SSTI)"
description: "Prevent server-side template injection — user input reaching a template compiler, double-render pipelines, sandbox escapes, and template-driven resource exhaustion"
category: prevention
severity: critical
applies_to:
  - "when rendering templates with any user-influenced value (email / notification bodies, PDFs, HTML, config)"
  - "when a template's source string is assembled or stored from user input"
  - "when using a template engine (Jinja2, Twig, Freemarker, Velocity, ERB, Handlebars, Go text/html-template, Thymeleaf, Razor, Liquid, Mako, Pug)"
  - "when reviewing a two-step render / re-parse pipeline"
languages: ["*"]
token_budget:
  minimal: 900
  compact: 1300
  full: 2500
rules_path: "rules/"
tests_path: "tests/"
related_skills: ["api-security", "frontend-security", "llm-app-security"]
last_updated: "2026-07-02"
sources:
  - "OWASP Testing Guide — Server-Side Template Injection (WSTG-INPV-18)"
  - "PortSwigger — Server-Side Template Injection"
  - "CWE-1336: Improper Neutralization of Special Elements Used in a Template Engine"
  - "CWE-94: Improper Control of Generation of Code"
  - "CWE-770: Allocation of Resources Without Limits or Throttling"
---

# Template Injection (SSTI)

## Rules (for AI agents)

### ALWAYS
- Pass user data to a template only as **bound values / context variables**, never
  concatenated or interpolated into the template **source** string. `render(tmpl, {name})`
  is safe; `render("Hello " + name)` is SSTI.
- Keep the set of template sources **static and trusted** — load them from files or
  constants the user cannot influence. A template whose text comes from the DB, an API
  response, or a request field is attacker-controlled *code*, not data.
- Treat any **second render pass** as code execution. If the output of one render is
  parsed and executed as a template again (double render), a user value that survived
  the first pass as data becomes `{{ }}` code on the second. Never re-parse rendered
  output; if a two-step render is unavoidable, escape/neutralise template
  metacharacters (`{{`, `{%`, `${`, `#{`, `<%`) in user fields before the second pass.
- Use a **sandboxed / logic-less** engine for user-authored templates (Handlebars,
  Liquid, Jinja2 `SandboxedEnvironment`) and deny attribute/builtin/internals access
  (`__class__`, `__globals__`, `constructor`, `getClass()`).
- Keep **autoescaping on** for the correct context (HTML/JS/URL) — SSTI and XSS share
  the input path.
- **Bound every loop and output** driven by user input: cap iteration counts, recursion
  depth, and total rendered size at the template boundary. `range(n)` / `{{range n}}`
  with attacker-chosen `n` and no cap is an OOM DoS.

### NEVER
- Build a template's source string from user input (`Template("Hi " + user.name)`,
  f-strings / `String.format` / concat feeding the compiler). Bind values instead.
- Store a template body in a user-writable field (profile name, subject line, CMS block)
  and later feed it to the engine.
- Re-render engine output as a template without neutralising user-supplied
  metacharacters (double-render / "recursive template" pipelines).
- Expose the raw engine to untrusted authors without a sandbox and an attribute
  allowlist — SSTI escalates to RCE in most server engines (Jinja2, Twig, Freemarker,
  Velocity, ERB).
- Render an unbounded user-controlled loop / repetition / include count without a size
  and iteration cap.

### KNOWN FALSE POSITIVES
- User data passed as **context variables** to a static template is the correct pattern,
  not SSTI.
- Client-side template binding (React/Vue/Angular interpolation) is XSS-scope, not
  server SSTI (see frontend-security) — unless the template string itself is user-built
  (`v-html` of a template, `new Function`).
- Logic-less engines (Mustache, strict Handlebars) with no user-authored template and
  autoescape on are low-risk for RCE (still cap output size).
- A template loaded from a trusted file whose *values* include user data is fine.

## Context (for humans)

Server-Side Template Injection happens when user input is evaluated as part of a
template rather than passed as data to it. Because server engines expose rich object
access (attribute traversal, method calls, builtins), SSTI usually escalates from
information disclosure to remote code execution — `{{7*7}}` returning `49` is the classic
probe, `{{''.__class__.__mro__[1].__subclasses__()}}` the classic Jinja2 exploit.

Two variants are easy to miss in review:
1. **Double render.** A pipeline renders once (often "safely", data-only), then the
   result is parsed and executed as a template a second time — e.g. a body is built by
   splicing a display name into a template *string*, and a dispatcher then `Parse()`s and
   `Execute()`s that string. The name's `{{...}}` was inert data on pass one and executes
   on pass two. The fix is architectural: never re-parse rendered output, or filter
   template metacharacters from user fields before the re-parse.
2. **Template-driven DoS.** Even without RCE, a template is a denial-of-service sink: an
   attacker-controlled loop / `range` / `include` count with no output cap makes one
   request allocate unbounded memory and OOM the renderer — and a crash mid-pipeline
   (before a queue offset commit) can crash-loop.

### Verify & lock (triaging a finding)

A scanner/review hit is a *candidate*, not a confirmed bug. Confirm it, fix it, then lock it.

1. **Confirm it's real (probe the template boundary).** Put a math/marker probe in the
   user field that reaches the engine (`{{7*7}}`, `${7*7}`, `#{7*7}`, `<%= 7*7 %>`) and
   see if it *evaluates* (`49`) rather than echoing literally. For a **double render**, the
   probe must survive the first pass — inject it where the value is later re-parsed (a
   name/label spliced into a template source), then trigger the second render. For **DoS**,
   submit a large-but-bounded loop/`range` count and watch renderer memory/time; a real
   hit scales with the count with no cap.
2. **Fix, then lock with a regression test:** assert the probe input now renders as literal
   text (or is rejected), the sandbox denies attribute/builtins access, and an oversized
   loop/output is capped/rejected — plus a benign case (normal data in a static template)
   still renders. Commit it to CI so the guard can't be dropped in a later refactor.

## References

- `rules/template_injection.json`
- [OWASP WSTG — SSTI](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection).
- [PortSwigger — Server-Side Template Injection](https://portswigger.net/web-security/server-side-template-injection).
- [CWE-1336](https://cwe.mitre.org/data/definitions/1336.html) · [CWE-94](https://cwe.mitre.org/data/definitions/94.html) · [CWE-770](https://cwe.mitre.org/data/definitions/770.html).
