---
hide:
  - toc
---

# Skills Catalogue

<p class="ti-lede">
The security knowledge SecureVibe feeds your AI assistant at generation time —
<strong>30 curated skills</strong>, each ranked by severity, mapped to CWEs, and
shipped in three token tiers. This is the actual corpus; browse it below.
</p>

<div id="sk-stats" class="ti-stats">Loading the catalogue…</div>

<div class="ti-controls">
  <input id="sk-q" class="ti-search" type="search" placeholder="Search skills…" autocomplete="off" disabled>
  <select id="sk-sev" class="ti-filter" disabled><option value="">All severities</option></select>
  <select id="sk-cat" class="ti-filter" disabled><option value="">All categories</option></select>
</div>

<div id="sk-count" class="ti-resultcount"></div>
<div id="sk-grid" class="sk-grid" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:.9rem;margin:1rem 0"></div>

<script>
(function () {
  var all = [], elS = document.getElementById("sk-stats"),
      elQ = document.getElementById("sk-q"), elSev = document.getElementById("sk-sev"),
      elCat = document.getElementById("sk-cat"), elGrid = document.getElementById("sk-grid"),
      elCount = document.getElementById("sk-count");
  var esc = function (t) { return (t == null ? "" : String(t)).replace(/[&<>"]/g, function (c) { return ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;"})[c]; }); };
  var cap = function (s) { return (s || "").replace(/(^|[\s-])\w/g, function (m) { return m.toUpperCase(); }).replace(/-/g, " "); };
  function opts(sel, vals) { vals.sort().forEach(function (v) { var o = document.createElement("option"); o.value = v; o.textContent = cap(v); sel.appendChild(o); }); }
  function uniq(key) { var s = {}; all.forEach(function (e) { if (e[key]) s[e[key]] = 1; }); return Object.keys(s); }

  function render() {
    var q = elQ.value.trim().toLowerCase(), sev = elSev.value, cat = elCat.value;
    var view = all.filter(function (s) {
      if (sev && s.severity !== sev) return false;
      if (cat && s.category !== cat) return false;
      if (q) { var hay = (s.title + " " + s.description + " " + (s.cwes || []).join(" ")).toLowerCase(); if (hay.indexOf(q) < 0) return false; }
      return true;
    });
    elCount.textContent = view.length + " skill" + (view.length === 1 ? "" : "s");
    elGrid.innerHTML = view.map(function (s) {
      var tb = s.token_budget || {};
      var cwes = (s.cwes || []).map(function (c) { return '<span class="sk-cwe">' + esc(c) + '</span>'; }).join("");
      var tools = (s.external_tools || []).map(function (t) { return '<code>' + esc(t) + '</code>'; }).join(" ");
      return '<a class="sk-card" style="display:block;border:1px solid var(--ss-border);border-radius:10px;padding:.9rem 1.05rem;background:var(--md-default-bg-color)" href="https://github.com/shieldnet-360/secure-vibe/blob/main/skills/' + esc(s.id) + '/SKILL.md" target="_blank" rel="noopener">' +
        '<div class="sk-top" style="display:flex;align-items:center;gap:.5rem"><span class="sk-title" style="flex:1;font-weight:700">' + esc(s.title) + '</span>' +
          '<span class="pg-badge pg-' + esc((s.severity || "info").toLowerCase()) + '">' + esc((s.severity || "").toUpperCase()) + '</span></div>' +
        '<div class="sk-desc">' + esc(s.description) + '</div>' +
        (cwes ? '<div class="sk-cwes">' + cwes + '</div>' : '') +
        '<div class="sk-meta">' +
          (s.category ? '<span>' + esc(cap(s.category)) + '</span>' : '') +
          (tb.minimal ? '<span>tiers ' + tb.minimal + '/' + (tb.compact||'·') + '/' + (tb.full||'·') + ' tok</span>' : '') +
          (tools ? '<span>tools: ' + tools + '</span>' : '') +
        '</div></a>';
    }).join("");
  }
  [elQ, elSev, elCat].forEach(function (el) { el.addEventListener("input", render); });

  fetch("../assets/data/skills.json").then(function (r) { return r.json(); }).then(function (d) {
    all = d.skills || [];
    var cwe = {}; all.forEach(function (s) { (s.cwes||[]).forEach(function (c) { cwe[c] = 1; }); });
    elS.className = "ti-stats ready";
    elS.innerHTML = '<span class="ti-stat"><b>' + all.length + '</b> skills</span>' +
      '<span class="ti-stat"><b>' + Object.keys(cwe).length + '</b> CWEs mapped</span>' +
      '<span class="ti-stat"><b>3</b> token tiers each</span>' +
      '<span class="ti-stat"><b>' + all.filter(function (s) { return s.severity === "critical"; }).length + '</b> critical</span>';
    opts(elSev, uniq("severity")); opts(elCat, uniq("category"));
    [elQ, elSev, elCat].forEach(function (el) { el.disabled = false; });
    try { var pq = new URLSearchParams(location.search).get("q"); if (pq) elQ.value = pq; } catch (e) {}
    render();
  }).catch(function (e) { elS.className = "ti-stats err"; elS.textContent = "Failed to load: " + e; });
})();
</script>
