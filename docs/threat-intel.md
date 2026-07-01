---
hide:
  - toc
---

# Threat Intelligence

<p class="ti-lede">
The curated malicious-package canon SecureVibe reads at generation time and
enforces at the gate. <strong>Every entry is sourced from a public advisory and
carries its reference link</strong> — nothing here is inferred or synthetic.
This is the data the scanners and the <a href="../playground/">Playground</a> run against.
</p>

<div id="ti-stats" class="ti-stats">Loading the curated database…</div>

<div class="ti-controls">
  <input id="ti-q" class="ti-search" type="search" placeholder="Search name or description…" autocomplete="off" disabled>
  <select id="ti-eco" class="ti-filter" disabled><option value="">All ecosystems</option></select>
  <select id="ti-sev" class="ti-filter" disabled><option value="">All severities</option></select>
  <select id="ti-atk" class="ti-filter" disabled><option value="">All attack types</option></select>
</div>

<div id="ti-count" class="ti-resultcount"></div>
<div id="ti-list" class="ti-list"></div>
<div id="ti-pager" class="ti-pager"></div>

<script>
(function () {
  var PAGE = 20, all = [], view = [], page = 0;
  var stats = document.getElementById("ti-stats");
  var elQ = document.getElementById("ti-q"), elEco = document.getElementById("ti-eco"),
      elSev = document.getElementById("ti-sev"), elAtk = document.getElementById("ti-atk"),
      elList = document.getElementById("ti-list"), elCount = document.getElementById("ti-count"),
      elPager = document.getElementById("ti-pager");
  var esc = function (t) { return (t == null ? "" : String(t)).replace(/[&<>"]/g, function (c) { return ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;"})[c]; }); };
  var titleize = function (s) { return (s || "").replace(/_/g, " "); };
  var host = function (u) { try { return new URL(u).hostname.replace(/^www\./, ""); } catch (e) { return "source"; } };

  function opts(sel, vals) {
    vals.sort().forEach(function (v) { var o = document.createElement("option"); o.value = v; o.textContent = v; sel.appendChild(o); });
  }
  function uniq(key) { var s = {}; all.forEach(function (e) { if (e[key]) s[e[key]] = 1; }); return Object.keys(s); }

  function render() {
    var q = elQ.value.trim().toLowerCase(), eco = elEco.value, sev = elSev.value, atk = elAtk.value;
    view = all.filter(function (e) {
      if (eco && e.ecosystem !== eco) return false;
      if (sev && e.severity !== sev) return false;
      if (atk && e.attack_type !== atk) return false;
      if (q) { var hay = (e.name + " " + (e.description || "")).toLowerCase(); if (hay.indexOf(q) < 0) return false; }
      return true;
    });
    page = 0; paint();
  }
  function paint() {
    var n = view.length, pages = Math.max(1, Math.ceil(n / PAGE));
    if (page >= pages) page = pages - 1;
    elCount.textContent = n.toLocaleString() + " entr" + (n === 1 ? "y" : "ies");
    var slice = view.slice(page * PAGE, page * PAGE + PAGE);
    elList.innerHTML = slice.map(function (e) {
      var refs = (e.references || []).slice(0, 3).map(function (u) {
        return '<a href="' + esc(u) + '" target="_blank" rel="noopener">' + esc(host(u)) + '</a>';
      }).join(" · ");
      return '<div class="ti-row">' +
        '<div class="ti-head"><code class="ti-name">' + esc(e.name) + '</code>' +
          '<span class="ti-badge ti-eco-b">' + esc(e.ecosystem) + '</span>' +
          '<span class="pg-badge pg-' + esc((e.severity || "info").toLowerCase()) + '">' + esc((e.severity || "").toUpperCase()) + '</span>' +
          '<span class="ti-atk">' + esc(titleize(e.attack_type)) + '</span>' +
          (e.discovered ? '<span class="ti-date">' + esc(e.discovered) + '</span>' : '') +
        '</div>' +
        '<div class="ti-desc">' + esc(e.description || "") + '</div>' +
        (refs ? '<div class="ti-refs">↳ ' + refs + '</div>' : '') +
        '</div>';
    }).join("");
    elPager.innerHTML = pages > 1
      ? '<button class="ti-pg" ' + (page === 0 ? "disabled" : "") + ' data-d="-1">← Prev</button>' +
        '<span class="ti-pginfo">Page ' + (page + 1) + " of " + pages + '</span>' +
        '<button class="ti-pg" ' + (page >= pages - 1 ? "disabled" : "") + ' data-d="1">Next →</button>'
      : "";
  }

  elPager.addEventListener("click", function (ev) {
    var b = ev.target.closest(".ti-pg"); if (!b) return;
    page += parseInt(b.getAttribute("data-d"), 10); paint();
    document.getElementById("ti-controls") || elList.scrollIntoView({ block: "start", behavior: "smooth" });
  });
  [elQ, elEco, elSev, elAtk].forEach(function (el) { el.addEventListener("input", render); });

  fetch("../assets/data/malicious-packages.json")
    .then(function (r) { return r.json(); })
    .then(function (d) {
      all = d.entries || [];
      var ecos = {}, sevs = {};
      all.forEach(function (e) { ecos[e.ecosystem] = (ecos[e.ecosystem] || 0) + 1; if (e.severity) sevs[e.severity] = (sevs[e.severity] || 0) + 1; });
      var ecoCount = Object.keys(ecos).length;
      stats.className = "ti-stats ready";
      stats.innerHTML =
        '<span class="ti-stat"><b>' + all.length.toLocaleString() + '</b> curated entries</span>' +
        '<span class="ti-stat"><b>' + ecoCount + '</b> ecosystems</span>' +
        '<span class="ti-stat"><b>100%</b> web-cited</span>' +
        '<span class="ti-stat"><b>' + (sevs.critical || 0) + '</b> critical</span>';
      opts(elEco, uniq("ecosystem")); opts(elSev, uniq("severity")); opts(elAtk, uniq("attack_type"));
      [elQ, elEco, elSev, elAtk].forEach(function (el) { el.disabled = false; });
      render();
    })
    .catch(function (e) { stats.className = "ti-stats err"; stats.textContent = "Failed to load database: " + e; });
})();
</script>
