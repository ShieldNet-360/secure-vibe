---
hide:
  - toc
---

# Coverage

<p class="ti-lede">
The shape of the canon, computed live from the real data — the curated
malicious-package DB, the skill catalogue, and the compliance mappings. Every
number below is derived client-side from the same files the scanners read.
</p>

<div id="cv-root" class="cv-root">Loading…</div>

<script>
(function () {
  var root = document.getElementById("cv-root");
  var esc = function (t) { return (t == null ? "" : String(t)).replace(/[&<>]/g, function (c) { return ({"&":"&amp;","<":"&lt;",">":"&gt;"})[c]; }); };
  var cap = function (s) { return (s || "").replace(/_/g, " "); };

  function bars(title, counts, opts) {
    opts = opts || {};
    var rows = Object.keys(counts).map(function (k) { return [k, counts[k]]; });
    rows.sort(function (a, b) { return opts.byKey ? (a[0] < b[0] ? -1 : 1) : b[1] - a[1]; });
    if (opts.top) rows = rows.slice(0, opts.top);
    var max = Math.max.apply(null, rows.map(function (r) { return r[1]; }).concat([1]));
    return '<section class="cv-card"><h3>' + esc(title) + '</h3><div class="cv-bars">' +
      rows.map(function (r) {
        var pct = Math.max(2, Math.round(100 * r[1] / max));
        return '<div class="cv-bar" style="display:flex;align-items:center;gap:.6rem;margin:.35rem 0;font-size:.8rem">' +
          '<span class="cv-lab" style="flex:0 0 130px;color:var(--ss-text-muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + esc(cap(r[0])) + '</span>' +
          '<span class="cv-track" style="flex:1;background:rgba(127,127,127,.18);border-radius:5px;height:16px;overflow:hidden">' +
            '<span class="cv-fill" style="display:block;height:100%;border-radius:5px;background:linear-gradient(90deg,#255FE5,#4d82ec);width:' + pct + '%"></span></span>' +
          '<span class="cv-val" style="flex:0 0 56px;text-align:right;font-weight:600;font-variant-numeric:tabular-nums">' + r[1].toLocaleString() + '</span></div>';
      }).join("") + '</div></section>';
  }

  Promise.all([
    fetch("../assets/data/malicious-packages.json").then(function (r) { return r.json(); }),
    fetch("../assets/data/skills.json").then(function (r) { return r.json(); }).catch(function () { return { skills: [] }; }),
    fetch("../assets/data/compliance.json").then(function (r) { return r.json(); }).catch(function () { return { frameworks: [], control_count: 0 }; })
  ]).then(function (res) {
    var mp = res[0].entries || [], sk = res[1].skills || [], cp = res[2];
    var byEco = {}, byAtk = {}, byYear = {}, bySev = {};
    mp.forEach(function (e) {
      byEco[e.ecosystem] = (byEco[e.ecosystem] || 0) + 1;
      if (e.attack_type) byAtk[e.attack_type] = (byAtk[e.attack_type] || 0) + 1;
      if (e.severity) bySev[e.severity] = (bySev[e.severity] || 0) + 1;
      var y = (e.discovered || "").slice(0, 4); if (/^\d{4}$/.test(y)) byYear[y] = (byYear[y] || 0) + 1;
    });
    var skCat = {}; sk.forEach(function (s) { if (s.category) skCat[s.category] = (skCat[s.category] || 0) + 1; });

    var head = '<div class="ti-stats ready">' +
      '<span class="ti-stat"><b>' + mp.length.toLocaleString() + '</b> malicious packages</span>' +
      '<span class="ti-stat"><b>' + Object.keys(byEco).length + '</b> ecosystems</span>' +
      '<span class="ti-stat"><b>' + sk.length + '</b> skills</span>' +
      '<span class="ti-stat"><b>' + (cp.control_count || 0) + '</b> compliance controls</span>' +
      '<span class="ti-stat"><b>100%</b> web-cited</span></div>';

    root.innerHTML = head + '<div class="cv-grid">' +
      bars("Malicious packages by ecosystem", byEco) +
      bars("By attack type", byAtk, { top: 8 }) +
      bars("Discoveries by year", byYear, { byKey: true }) +
      bars("By severity", bySev) +
      (Object.keys(skCat).length ? bars("Skills by category", skCat) : "") +
      '</div>';
  }).catch(function (e) { root.innerHTML = '<div class="ti-stats err">Failed to load: ' + esc(e) + '</div>'; });
})();
</script>
