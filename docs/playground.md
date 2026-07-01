---
hide:
  - toc
---

# Playground

<p class="pg-lede">
This runs the <strong>real SecureVibe engine</strong> — the same scanners the CLI and MCP
server use — compiled to WebAssembly and executed <strong>entirely in your browser</strong>.
Nothing you paste here leaves your machine: no upload, no backend, no telemetry. The
malicious-package DB, typosquat DB, and secret-detection rules are baked into the
<code>.wasm</code> module.
</p>

<div id="pg-status" class="pg-status">Loading the engine (~8&nbsp;MB, one-time)…</div>

<div class="pg-grid" markdown>

<section class="pg-card">
<h3>🔎 Scan dependencies</h3>
<p class="pg-hint">Paste a lockfile / manifest. Pick the filename so the right parser runs.</p>
<label class="pg-label">Filename
<select id="pg-dep-name">
<option>requirements.txt</option>
<option>package.json</option>
<option>go.sum</option>
<option>Cargo.lock</option>
<option>composer.lock</option>
<option>Gemfile.lock</option>
<option>pom.xml</option>
</select>
</label>
<textarea id="pg-dep-input" class="pg-input" spellcheck="false" rows="6">requests==2.31.0
colourama==0.4.6
</textarea>
<button id="pg-dep-run" class="pg-btn" disabled>Scan dependencies</button>
<div id="pg-dep-out" class="pg-out"></div>
</section>

<section class="pg-card">
<h3>🔐 Scan for secrets</h3>
<p class="pg-hint">Paste code or config. Detection runs with entropy + hotword scoring.</p>
<textarea id="pg-sec-input" class="pg-input" spellcheck="false" rows="9">GITHUB_TOKEN = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"
STRIPE_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dcAbCdEfGhItuv"
# the canonical AWS docs example key is correctly NOT flagged:
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
</textarea>
<button id="pg-sec-run" class="pg-btn" disabled>Scan for secrets</button>
<div id="pg-sec-out" class="pg-out"></div>
</section>

</div>

<p class="pg-foot">
Want this in your editor or CI instead of a browser tab? See <a href="../quickstart/">Quick Start</a>.
The engine here is identical — it just happens to run client-side.
</p>

<script src="../assets/playground/wasm_exec.js"></script>
<script>
(function () {
  const base = "../assets/playground/";
  const status = document.getElementById("pg-status");

  // Verified examples per filename — each parses and flags a real malicious
  // package, so switching the filename always gives a working demo.
  const EXAMPLES = {
    "requirements.txt": "requests==2.31.0\ncolourama==0.4.6\n",
    "package.json": '{\n  "dependencies": {\n    "express": "4.18.2",\n    "solana-web3-v1": "1.0.0"\n  }\n}\n',
    "go.sum": "github.com/xinfeisoft/crypto v1.0.0 h1:abcdefghijklmnopqrstuvwxyz0123456789ABCD=\n",
    "Cargo.lock": '[[package]]\nname = "sui-sdk-build-utils"\nversion = "1.0.0"\n',
    "composer.lock": '{"packages":[{"name":"laravel-lang/lang","version":"1.0.0"}]}\n',
    "Gemfile.lock": "GEM\n  specs:\n    rest-client (1.6.10)\n",
    "pom.xml": '<project><dependencies>\n<dependency><groupId>org.fasterxml.jackson.core</groupId><artifactId>jackson-databind</artifactId><version>1.0.0</version></dependency>\n</dependencies></project>\n'
  };
  const sev = (s) => `<span class="pg-badge pg-${(s||'').toLowerCase()||'info'}">${(s||'finding').toUpperCase()}</span>`;
  const esc = (t) => (t||"").replace(/[&<>]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;"}[c]));
  const mask = (m) => !m ? "" : (m.length <= 10 ? m : m.slice(0,4) + "…" + m.slice(-4));

  function ready() {
    status.className = "pg-status pg-ok";
    status.innerHTML = "✓ Engine loaded — runs locally, nothing is uploaded.";
    document.getElementById("pg-dep-run").disabled = false;
    document.getElementById("pg-sec-run").disabled = false;
  }
  // svOnReady is invoked by the Go runtime once the funcs are registered.
  window.svOnReady = ready;

  // arrayBuffer instantiate (not instantiateStreaming) so it works regardless
  // of the server's .wasm MIME type (GitHub Pages and the static preview alike).
  const go = new Go();
  fetch(base + "skills.wasm")
    .then((r) => r.arrayBuffer())
    .then((buf) => WebAssembly.instantiate(buf, go.importObject))
    .then((res) => { go.run(res.instance); if (window.svReady) ready(); })
    .catch((e) => { status.className = "pg-status pg-err"; status.textContent = "Failed to load engine: " + e; });

  function renderDeps(json, box) {
    let r; try { r = JSON.parse(json); } catch { box.textContent = json; return; }
    if (r.error) {
      const fname = document.getElementById("pg-dep-name").value;
      const friendly = /parse|invalid|unrecognis|unrecogniz/i.test(r.error)
        ? `That doesn't look like a valid <code>${esc(fname)}</code>. Paste content in that format, or pick the filename that matches what you pasted.`
        : esc(r.error);
      box.innerHTML = `<div class="pg-row pg-err">${friendly}</div>`;
      return;
    }
    const deps = r.deps || [];
    // A dep is DANGEROUS when it hits the malicious-package DB, an OSV advisory,
    // or is itself a known typosquat. Being the *target* of typosquats (others
    // mimic this legit package) is informational, not a failure.
    const isTyposquatItself = (res, name) => (res.typosquats||[]).some(t => t.typosquat === name);
    const flagged = (r.findings || []).filter(f => f.result &&
      ((f.result.matches||[]).length || (f.result.osv_advisories||[]).length || isTyposquatItself(f.result, f.name)));
    if (!deps.length) { box.innerHTML = `<div class="pg-row">No dependencies parsed.</div>`; return; }
    let html = `<div class="pg-summary ${flagged.length ? 'pg-fail':'pg-pass'}">` +
      (flagged.length ? `✗ ${flagged.length} flagged of ${deps.length} parsed` : `✓ ${deps.length} parsed, none flagged`) + `</div>`;
    flagged.forEach(f => {
      const res = f.result;
      const tags = [];
      (res.matches||[]).forEach(m => tags.push(`${sev(m.severity)} ${esc(m.attack_type||m.type||'malicious package')}${m.description ? " · "+esc(m.description) : ""}`));
      (res.typosquats||[]).filter(t => t.typosquat === f.name).forEach(t => tags.push(`${sev('high')} typosquat of <code>${esc(t.target)}</code>`));
      (res.osv_advisories||[]).forEach(a => tags.push(`${sev(a.severity)} ${esc(a.id||'OSV advisory')}`));
      html += `<div class="pg-row pg-fail"><code>${esc(f.name)}@${esc(f.version||'*')}</code> <em>(${esc(f.ecosystem)})</em><div class="pg-tags">${tags.join("<br>")}</div></div>`;
    });
    box.innerHTML = html;
  }

  function renderSecrets(json, box) {
    let r; try { r = JSON.parse(json); } catch { box.textContent = json; return; }
    if (r.error) { box.innerHTML = `<div class="pg-row pg-err">${esc(r.error)}</div>`; return; }
    const m = (r.matches || []).filter(x => !x.known_false_positive);
    const fp = (r.matches || []).filter(x => x.known_false_positive);
    let html = `<div class="pg-summary ${m.length ? 'pg-fail':'pg-pass'}">` +
      (m.length ? `✗ ${m.length} secret${m.length>1?'s':''} detected` : `✓ no secrets detected`) + `</div>`;
    m.forEach(x => {
      html += `<div class="pg-row pg-fail">${sev(x.severity)} <strong>${esc(x.name)}</strong> <code>${esc(mask(x.match))}</code>` +
        `<span class="pg-meta">entropy ${x.entropy?.toFixed(1)}${x.hotword_hit ? " · hotword":""}</span></div>`;
    });
    if (fp.length) html += `<div class="pg-row pg-info">${fp.length} known-false-positive (e.g. docs example key) correctly ignored</div>`;
    box.innerHTML = html;
  }

  // Switching the filename loads a matching, known-good example so the demo
  // always parses (only when the box is empty or still holds another example).
  const depName = document.getElementById("pg-dep-name"), depInput = document.getElementById("pg-dep-input");
  const exampleValues = Object.keys(EXAMPLES).map(function (k) { return EXAMPLES[k]; });
  depName.addEventListener("change", function () {
    var cur = depInput.value.trim();
    var isExample = cur === "" || exampleValues.some(function (v) { return v.trim() === cur; });
    if (isExample && EXAMPLES[depName.value]) {
      depInput.value = EXAMPLES[depName.value];
      document.getElementById("pg-dep-out").innerHTML = "";
    }
  });
  document.getElementById("pg-dep-run").addEventListener("click", () => {
    const out = document.getElementById("pg-dep-out");
    if (!window.svScanDeps) { out.textContent = "engine not ready"; return; }
    renderDeps(window.svScanDeps(depName.value, depInput.value), out);
  });
  document.getElementById("pg-sec-run").addEventListener("click", () => {
    const out = document.getElementById("pg-sec-out");
    if (!window.svScanSecrets) { out.textContent = "engine not ready"; return; }
    renderSecrets(window.svScanSecrets(document.getElementById("pg-sec-input").value), out);
  });
})();
</script>
