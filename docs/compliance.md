---
hide:
  - toc
---

# Compliance Coverage

<p class="ti-lede">
Which skills satisfy which control, mapped from the real
<code>compliance/*.yaml</code> files. Developer-facing coverage — a starting map
for an audit conversation, <strong>not a substitute for a formal assessment</strong>.
Each control links the skills that address it; click a skill chip to read it.
</p>

<div id="cp-stats" class="ti-stats">Loading the mappings…</div>

<div class="ti-controls">
  <select id="cp-fw" class="ti-filter" disabled></select>
  <input id="cp-q" class="ti-search" type="search" placeholder="Search controls…" autocomplete="off" disabled>
</div>

<div id="cp-list" class="cp-list"></div>

<script>
(function () {
  var fws = [], elS = document.getElementById("cp-stats"), elFw = document.getElementById("cp-fw"),
      elQ = document.getElementById("cp-q"), elList = document.getElementById("cp-list");
  var esc = function (t) { return (t == null ? "" : String(t)).replace(/[&<>"]/g, function (c) { return ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;"})[c]; }); };

  function render() {
    var fw = fws[elFw.value], q = elQ.value.trim().toLowerCase();
    if (!fw) { elList.innerHTML = ""; return; }
    var controls = fw.controls.filter(function (c) {
      if (!q) return true;
      return (c.id + " " + c.title + " " + c.description + " " + (c.skills||[]).join(" ")).toLowerCase().indexOf(q) >= 0;
    });
    elList.innerHTML = '<div class="cp-fwhead"><strong>' + esc(fw.framework) + '</strong> · ' + esc(fw.version) +
      ' · ' + fw.control_count + ' controls mapped</div>' +
      controls.map(function (c) {
        var skills = (c.skills || []).map(function (s) {
          return '<a class="cp-skill" href="../skills/?q=' + encodeURIComponent(s) + '" title="' + esc(s) + '">' + esc(s) + '</a>';
        }).join("");
        return '<div class="cp-row" style="display:flex;gap:.9rem;padding:.7rem 0;border-top:1px solid var(--ss-border)">' +
          '<div class="cp-cid" style="flex:0 0 76px;font-weight:700;color:var(--md-primary-fg-color)">' + esc(c.id) + '</div>' +
          '<div class="cp-cbody" style="flex:1;min-width:0"><div class="cp-ctitle" style="font-weight:600">' + esc(c.title) + '</div>' +
            '<div class="cp-cdesc">' + esc(c.description) + '</div>' +
            '<div class="cp-skills">' + (skills || '<em class="cp-gap">no skill mapped</em>') + '</div></div>' +
          '</div>';
      }).join("");
  }
  elFw.addEventListener("change", render); elQ.addEventListener("input", render);

  fetch("../assets/data/compliance.json").then(function (r) { return r.json(); }).then(function (d) {
    fws = d.frameworks || [];
    elS.className = "ti-stats ready";
    elS.innerHTML = '<span class="ti-stat"><b>' + fws.length + '</b> frameworks</span>' +
      '<span class="ti-stat"><b>' + d.control_count + '</b> controls mapped</span>' +
      fws.map(function (f) { return '<span class="ti-stat">' + esc(f.framework) + ': <b>' + f.control_count + '</b></span>'; }).join("");
    fws.forEach(function (f, i) { var o = document.createElement("option"); o.value = i; o.textContent = f.framework; elFw.appendChild(o); });
    elFw.disabled = false; elQ.disabled = false;
    render();
  }).catch(function (e) { elS.className = "ti-stats err"; elS.textContent = "Failed to load: " + e; });
})();
</script>
