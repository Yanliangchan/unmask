// unmask — the graph workspace (Cytoscape, self-hosted).
//
// The graph is a view onto the case: hiding, isolating, filtering and laying out change only
// what is drawn (and can be undone); decisions go through the same audited endpoints as the
// Entities tab. Filters never re-run the layout, so findings stay where the analyst left them.
(function () {
  "use strict";
  if (window.unmaskGraph) { window.unmaskGraph.init(); return; }

  // --- Vocabulary ---------------------------------------------------------------------------
  // Every type has a glyph, so type never depends on colour alone. Glyphs are 16x16 strokes.
  var TYPES = {
    username: { label: "Username", glyph: '<circle cx="8" cy="8" r="2.6"/><path d="M10.6 8v1a1.9 1.9 0 0 0 3.8 0V8A6.4 6.4 0 1 0 11 13.6"/>' },
    email: { label: "Email", glyph: '<rect x="1.8" y="3.5" width="12.4" height="9" rx="1"/><path d="M2.2 4.2 8 8.8l5.8-4.6"/>' },
    account: { label: "Account", glyph: '<circle cx="8" cy="5.6" r="2.7"/><path d="M2.6 14a5.4 5.4 0 0 1 10.8 0"/>' },
    registration: { label: "Registration", glyph: '<rect x="2.5" y="2.5" width="11" height="11" rx="1"/><path d="M5 8.2l2 2 4-4.4"/>' },
    breach: { label: "Breach", glyph: '<path d="M8 2 14.5 13.5h-13z"/><path d="M8 6.4v3.2M8 11.6v.1"/>' },
    name: { label: "Name", glyph: '<rect x="1.8" y="3.2" width="12.4" height="9.6" rx="1"/><circle cx="5.6" cy="7.2" r="1.5"/><path d="M3.6 10.8a2 2 0 0 1 4 0M9.4 6.4h3M9.4 9h3"/>' },
    domain: { label: "Domain", glyph: '<circle cx="8" cy="8" r="6"/><path d="M2 8h12M8 2c2.4 2.6 2.4 9.4 0 12M8 2c-2.4 2.6-2.4 9.4 0 12"/>' },
    hostname: { label: "Hostname", glyph: '<rect x="2" y="2.5" width="12" height="4.5" rx="1"/><rect x="2" y="9" width="12" height="4.5" rx="1"/><path d="M4.5 4.8h.1M4.5 11.2h.1"/>' },
    ip: { label: "IP address", glyph: '<path d="M5.5 2.5 4 13.5M11.5 2.5 10 13.5M2.5 6h11M2 10.2h11"/>' },
    phone: { label: "Phone", glyph: '<rect x="4.5" y="1.8" width="7" height="12.4" rx="1.2"/><path d="M7.2 12h1.6"/>' },
    web_mention: { label: "Web mention", glyph: '<path d="M3.5 1.8h6l3 3v9.4h-9z"/><path d="M9.5 1.8v3h3M5.6 8h4.8M5.6 10.6h4.8"/>' },
    image: { label: "Image", glyph: '<rect x="2" y="2.8" width="12" height="10.4" rx="1"/><circle cx="6" cy="6.4" r="1.2"/><path d="M2.4 12.4 6.5 8.6l2.6 2.4 1.8-1.6 2.8 2.8"/>' },
    other: { label: "Other", glyph: '<circle cx="8" cy="8" r="2.4"/>' }
  };
  var STRENGTH = { target: "Target", confirmed: "Confirmed", likely: "Likely", possible: "Possible", unlikely: "Unlikely", unchecked: "Page not checked" };
  var BASIS = {
    observed: { label: "Observed", text: "A tool reported this link, or a fetched page shows it." },
    rule: { label: "Rule match", text: "Two values match by a fixed rule (same handle, address at a domain). It links values, not people." },
    similarity: { label: "Similarity", text: "Two values look alike above a threshold. Similarity suggests a link; it does not establish one." },
    analyst: { label: "Analyst", text: "A person decided this." }
  };
  var RANK = { target: 6, confirmed: 5, likely: 4, possible: 3, unlikely: 2, unchecked: 1 };
  var BIG = 600, HUGE = 2500;

  var current = document.currentScript;
  var SRC = {
    cytoscape: (current && current.dataset.cytoscape) || "/static/js/vendor/cytoscape.min.js",
    fcose: (current && current.dataset.fcose) || "/static/js/vendor/cytoscape-fcose.min.js"
  };
  var loading = {};
  function loadScript(key) {
    if (key === "cytoscape" && window.cytoscape) return Promise.resolve();
    if (key === "fcose" && window.cytoscapeFcose) return Promise.resolve();
    if (!loading[key]) {
      loading[key] = new Promise(function (resolve, reject) {
        var s = document.createElement("script");
        s.src = SRC[key];
        s.onload = resolve;
        s.onerror = function () { loading[key] = null; reject(new Error("could not load " + key)); };
        document.head.appendChild(s);
      });
    }
    return loading[key];
  }

  // Restyling is the expensive part of a big graph, so only touch elements whose class actually changes.
  function setClass(eles, cls, want) {
    var on = [], off = [];
    eles.forEach(function (x) { var w = !!want(x); if (w !== x.hasClass(cls)) (w ? on : off).push(x); });
    if (on.length) S.cy.collection(on).addClass(cls);
    if (off.length) S.cy.collection(off).removeClass(cls);
  }

  function reduced() { return window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches; }
  function el(tag, cls, text) { var e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; }
  function typeKey(t) { return TYPES[t] ? t : "other"; }
  function shortValue(v) {
    var t = String(v).replace(/^https?:\/\/(www\.)?/i, "").replace(/\/$/, "");
    return t.length > 30 ? t.slice(0, 29) + "…" : t;
  }
  function fmtDate(iso) {
    if (!iso) return "—";
    var d = new Date(iso);
    return isNaN(d) ? "—" : d.toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" });
  }
  function toast(msg, kind) { if (window.unmaskToast) window.unmaskToast(msg, kind); }

  // --- State --------------------------------------------------------------------------------
  var S = null;  // one workspace per page; rebuilt by init() after htmx navigation

  function fresh(root) {
    return {
      root: root, cy: null, data: null, layout: "rings", hidden: {}, collapsed: {},
      undo: [], redo: [], hits: [], hit: -1, pathFrom: null, paths: null, activePath: -1,
      key: "unmask:graph:" + root.dataset.case, showAll: false, minimapTimer: null
    };
  }

  function palette() {
    var css = getComputedStyle(document.documentElement);
    var v = function (n) { return css.getPropertyValue(n).trim(); };
    var types = {};
    Object.keys(TYPES).forEach(function (t) { types[t] = v("--t-" + t) || "#777"; });
    return { text: v("--text"), strong: v("--text-strong"), muted: v("--muted"), faint: v("--faint"), bg: v("--bg"),
             surface: v("--surface"), sunk: v("--bg-sunk"), line: v("--border-strong"), border: v("--border"),
             mark: v("--mark"), ok: v("--ok"), warn: v("--warn"), bad: v("--bad"), font: v("--font") || "sans-serif", types: types };
  }

  function glyphURI(type, color) {
    var svg = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="' + color +
      '" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">' + TYPES[type].glyph + "</svg>";
    return "data:image/svg+xml;utf8," + encodeURIComponent(svg);
  }

  // Precomputed per node so the stylesheet maps data instead of calling functions per frame.
  function decorate(n, c, sizeBy) {
    var t = typeKey(n.type);
    var base = sizeBy === "links" ? 20 + 26 * Math.min(1, (n.degree || 0) / 12) : 20 + 24 * n.confidence + 8 * n.centrality;
    n.sz = n.seed ? 50 : Math.round(base);
    n.short = shortValue(n.value);
    n.tcolor = c.types[t];
    n.icon = glyphURI(t, n.seed ? c.bg : c.types[t]);
    return n;
  }

  function style() {
    var c = palette();
    var big = S && S.data && S.data.nodes.length > BIG;
    return [
      { selector: "node", style: {
        "shape": "ellipse", "width": "data(sz)", "height": "data(sz)",
        "background-color": c.surface, "background-image": "data(icon)", "background-fit": "none",
        "background-width": "52%", "background-height": "52%", "background-clip": "none",
        "border-width": 1.75, "border-color": "data(tcolor)", "border-style": "solid",
        "label": "data(short)", "font-family": c.font, "font-size": 11, "color": c.strong,
        "text-valign": "bottom", "text-margin-y": 5, "text-wrap": "ellipsis", "text-max-width": 170,
        "text-background-color": c.bg, "text-background-opacity": 0.88, "text-background-padding": 2,
        "min-zoomed-font-size": 8, "text-opacity": 0, "text-events": "no"
      } },
      { selector: "node.lbl, node:selected, node.gx-hit, node.gx-path", style: { "text-opacity": 1 } },
      { selector: "node[strength = 'possible']", style: { "border-style": "dashed" } },
      { selector: "node[strength = 'unlikely'], node[strength = 'unchecked']", style: { "opacity": 0.55, "border-style": "dotted" } },
      { selector: "node[?confirmed]", style: { "border-width": 3, "border-color": c.ok, "opacity": 1 } },
      { selector: "node[?seed]", style: { "background-color": c.strong, "border-color": c.strong, "border-width": 3, "font-weight": 600, "text-opacity": 1 } },
      { selector: "node[collapsedCount > 0]", style: { "label": "data(collapsedLabel)", "border-width": 3, "border-style": "double" } },
      { selector: "node.gx-hit", style: { "underlay-color": c.mark, "underlay-opacity": 0.55, "underlay-padding": 6, "underlay-shape": "ellipse" } },
      { selector: "node:selected", style: { "underlay-color": c.mark, "underlay-opacity": 0.95, "underlay-padding": 7, "underlay-shape": "ellipse", "z-index": 20 } },
      { selector: "edge", style: {
        "width": 1.2, "line-color": c.line, "curve-style": big ? "haystack" : "bezier", "haystack-radius": 0.4,
        "target-arrow-shape": "none", "arrow-scale": 0.7, "target-arrow-color": c.line, "opacity": 0.9,
        "label": "data(label)", "font-family": c.font, "font-size": 10, "color": c.muted, "text-rotation": "autorotate",
        "text-background-color": c.bg, "text-background-opacity": 0.9, "text-background-padding": 2, "text-opacity": 0, "min-zoomed-font-size": 9
      } },
      { selector: "edge[?directed]", style: { "target-arrow-shape": big ? "none" : "triangle" } },
      { selector: "edge[basis = 'rule']", style: { "line-color": c.muted, "target-arrow-color": c.muted, "width": 1.6 } },
      { selector: "edge[basis = 'similarity']", style: { "line-style": "dashed", "line-dash-pattern": [5, 4], "line-color": c.muted } },
      { selector: "edge[basis = 'analyst']", style: { "line-color": c.strong, "width": 2.2 } },
      { selector: "edge[?suggested]", style: { "line-style": "dashed", "line-dash-pattern": [2, 3], "line-color": c.warn, "width": 1.6 } },
      { selector: "edge[kind = 'strong']", style: { "width": 2.2 } },
      { selector: "edge:selected, edge.hover", style: { "text-opacity": 1, "line-color": c.strong, "target-arrow-color": c.strong, "width": 3, "z-index": 30,
        "underlay-color": c.mark, "underlay-opacity": 0.6, "underlay-padding": 3 } },
      { selector: ".gx-dim", style: { "opacity": 0.12, "text-opacity": 0 } },
      { selector: "edge.gx-path", style: { "line-color": c.strong, "target-arrow-color": c.strong, "width": 3.4, "opacity": 1, "text-opacity": 1, "z-index": 25 } },
      { selector: "edge.gx-weak", style: { "line-color": c.bad, "target-arrow-color": c.bad, "line-style": "dashed" } },
      { selector: ".gx-off", style: { "display": "none" } }
    ];
  }

  // --- Layouts --------------------------------------------------------------------------------
  // Rings: every finding gets its own angle around the target it was found from; distance says strength.
  function ringPositions(nodes) {
    var pos = {};
    var seeds = nodes.filter(function (n) { return n.data("seed"); });
    var rest = nodes.filter(function (n) { return !n.data("seed"); });
    var seedIndex = {};
    seeds.forEach(function (n, i) {
      seedIndex[n.id()] = i;
      var a = (2 * Math.PI * i) / Math.max(1, seeds.length) - Math.PI / 2;
      var r = seeds.length > 1 ? 50 + 14 * seeds.length : 0;
      pos[n.id()] = { x: r * Math.cos(a), y: r * Math.sin(a) };
    });
    var ranks = [];
    rest.forEach(function (n) { var k = RANK[n.data("strength")] || 1; if (ranks.indexOf(k) === -1) ranks.push(k); });
    ranks.sort(function (a, b) { return b - a; });
    function group(n) {
      var best = 99;
      n.neighborhood("node").forEach(function (m) { if (m.id() in seedIndex) best = Math.min(best, seedIndex[m.id()]); });
      return best;
    }
    var sorted = rest.map(function (n) { return { n: n, g: group(n), k: RANK[n.data("strength")] || 1 }; })
      .sort(function (a, b) { return a.g - b.g || b.k - a.k || String(a.n.data("type")).localeCompare(b.n.data("type")); });
    var count = sorted.length;
    var inner = seeds.length > 1 ? 200 : 160;
    var step = Math.max(80, Math.min(140, 24 * count / Math.max(1, ranks.length)));
    var circumference = 2 * Math.PI * (inner + step * (ranks.length - 1) / 2);
    var spread = Math.max(1, (count * 46) / circumference);  // grow the rings when labels would collide
    sorted.forEach(function (item, i) {
      var ring = ranks.indexOf(item.k);
      var a = (2 * Math.PI * i) / Math.max(1, count) - Math.PI / 2;
      var r = (inner + ring * step) * spread + (count > 12 ? (i % 2) * 26 : 0);
      pos[item.n.id()] = { x: r * Math.cos(a), y: r * Math.sin(a) };
    });
    return pos;
  }

  // Groups: one block per type (the "block" layout of link-analysis tools), largest first.
  function groupPositions(nodes) {
    var by = {};
    nodes.forEach(function (n) { (by[typeKey(n.data("type"))] = by[typeKey(n.data("type"))] || []).push(n); });
    var keys = Object.keys(by).sort(function (a, b) { return by[b].length - by[a].length; });
    var pos = {}, x = 0, y = 0, rowH = 0, cell = 92, maxW = 1500;
    keys.forEach(function (k) {
      var list = by[k].sort(function (a, b) { return b.data("confidence") - a.data("confidence"); });
      var cols = Math.max(1, Math.ceil(Math.sqrt(list.length * 1.6)));
      var w = cols * cell, h = Math.ceil(list.length / cols) * cell;
      if (x > 0 && x + w > maxW) { x = 0; y += rowH + 80; rowH = 0; }
      list.forEach(function (n, i) { pos[n.id()] = { x: x + (i % cols) * cell, y: y + Math.floor(i / cols) * cell }; });
      x += w + 80; rowH = Math.max(rowH, h);
    });
    return pos;
  }

  function layoutFor(name, eles, animate) {
    var nodes = eles.nodes();
    var anim = animate && !reduced() && nodes.length < 400;
    if (name === "force") {
      return { name: "fcose", quality: nodes.length > 400 ? "draft" : "default", randomize: true, animate: anim, animationDuration: 450,
               nodeRepulsion: 9000, idealEdgeLength: 90, nodeSeparation: 80, packComponents: true, padding: 40, fit: true, eles: eles };
    }
    if (name === "tree") {
      var roots = nodes.filter(function (n) { return n.data("seed"); });
      return { name: "breadthfirst", roots: roots.length ? roots : undefined, directed: false, spacingFactor: 1.15,
               avoidOverlap: true, animate: anim, animationDuration: 400, padding: 40, fit: true, eles: eles };
    }
    var pos = name === "groups" ? groupPositions(nodes) : ringPositions(nodes);
    return { name: "preset", positions: function (n) { return pos[n.id()]; }, animate: anim, animationDuration: 400, padding: 40, fit: true, eles: eles };
  }

  function runLayout(name, opts) {
    var cy = S.cy;
    var visible = cy.elements().not(".gx-off");
    var go = function () {
      return new Promise(function (resolve) {
        var l = visible.layout(layoutFor(name, visible, !(opts && opts.instant)));
        l.one("layoutstop", function () {
          visible.nodes().forEach(function (n) { n.scratch("_gx", true); });
          if (cy.zoom() > 1.3) { cy.zoom(1.3); cy.center(visible); }
          labels(); minimapSoon(); resolve();
        });
        l.run();
      });
    };
    if (name === "force") {
      return loadScript("fcose").then(function () {
        if (!window.cytoscape.__fcose) { window.cytoscape.use(window.cytoscapeFcose); window.cytoscape.__fcose = true; }
        return go();
      }).catch(function () { toast("The force layout could not load; showing rings instead.", "error"); return runLayout("rings", opts); });
    }
    return go();
  }

  function setLayout(name, record) {
    if (record !== false) push();
    S.layout = name;
    S.root.querySelectorAll("[data-gx-layout]").forEach(function (b) { b.setAttribute("aria-pressed", String(b.dataset.gxLayout === name)); });
    return runLayout(name).then(save);
  }

  // A node that becomes visible without ever having been laid out goes next to a visible neighbour.
  function placeNew(nodes) {
    nodes.forEach(function (n) {
      if (n.scratch("_gx")) return;
      var anchor = n.neighborhood("node").filter(function (m) { return !m.hasClass("gx-off") && m.scratch("_gx"); })[0];
      var p = anchor ? anchor.position() : { x: 0, y: 0 };
      var a = Math.random() * 2 * Math.PI;
      n.position({ x: p.x + 90 * Math.cos(a), y: p.y + 90 * Math.sin(a) });
      n.scratch("_gx", true);
    });
  }

  // --- Visibility: filters, hides, collapses ---------------------------------------------------
  function filters() {
    var root = S.root;
    var checked = function (k) {
      var on = {};
      root.querySelectorAll('[data-gx-f="' + k + '"]').forEach(function (i) { if (i.checked) on[i.value] = true; });
      return on;
    };
    var min = root.querySelector('[data-gx-f="min"]');
    var from = root.querySelector('[data-gx-f="from"]');
    var size = root.querySelector('[data-gx-f="size"]:checked');
    return { strength: checked("strength"), basis: checked("basis"), type: checked("type"), source: checked("source"),
             min: min ? Number(min.value) / 100 : 0, from: from && from.value ? from.value : "", size: size ? size.value : "score" };
  }

  function setFilters(f) {
    var root = S.root;
    ["strength", "basis", "type", "source"].forEach(function (k) {
      root.querySelectorAll('[data-gx-f="' + k + '"]').forEach(function (i) { i.checked = !f[k] || !!f[k][i.value]; });
    });
    var min = root.querySelector('[data-gx-f="min"]');
    if (min) min.value = Math.round((f.min || 0) * 100);
    var from = root.querySelector('[data-gx-f="from"]');
    if (from) from.value = f.from || "";
    root.querySelectorAll('[data-gx-f="size"]').forEach(function (i) { i.checked = i.value === (f.size || "score"); });
  }

  function nodePasses(d, f) {
    if (d.seed) return true;  // targets anchor the picture
    if (!f.strength[d.strength]) return false;
    if (!f.type[typeKey(d.type)]) return false;
    if (d.sources && d.sources.length && !d.sources.some(function (s) { return f.source[s]; })) return false;
    if (d.confidence < f.min && !d.confirmed) return false;
    if (f.from && d.first_seen && d.first_seen.slice(0, 10) < f.from) return false;
    return true;
  }

  function apply() {
    var cy = S.cy;
    if (!cy) return;
    var f = filters();
    var count = 0;
    cy.batch(function () {
      setClass(cy.nodes(), "gx-off", function (n) {
        var off = !nodePasses(n.data(), f) || !!S.hidden[n.id()] || !!S.collapsedBy(n.id());
        if (off && !S.hidden[n.id()] && !S.collapsedBy(n.id())) count++;
        return off;
      });
      setClass(cy.edges(), "gx-off", function (e) {
        return e.source().hasClass("gx-off") || e.target().hasClass("gx-off") || !f.basis[e.data("basis")];
      });
    });
    placeNew(cy.nodes().not(".gx-off"));
    S.filtered = count;
    var nfilters = 0;
    ["strength", "basis", "type", "source"].forEach(function (k) {
      S.root.querySelectorAll('[data-gx-f="' + k + '"]').forEach(function (i) { if (!i.checked) nfilters++; });
    });
    if (f.min > 0) nfilters++;
    if (f.from) nfilters++;
    var badge = S.root.querySelector("[data-gx-filter-count]");
    if (badge) { badge.hidden = !nfilters; badge.textContent = nfilters; }
    if (S.sizeBy !== f.size) { S.sizeBy = f.size; resize(); }
    labels(); status(); minimapSoon();
  }

  function resize() {
    var c = palette();
    S.cy.batch(function () { S.cy.nodes().forEach(function (n) { n.data("sz", decorate(Object.assign({}, n.data()), c, S.sizeBy).sz); }); });
  }

  // Collapse: a finding's leaf neighbours (linked to nothing else) fold into it.
  function collapsedByFn() {
    var owner = {};
    Object.keys(S.collapsed).forEach(function (id) { S.collapsed[id].forEach(function (leaf) { owner[leaf] = id; }); });
    return function (id) { return owner[id]; };
  }

  // Labels: targets, confirmed, the selection and the most central always; the rest when zoomed in.
  function labels() {
    var cy = S.cy;
    if (!cy) return;
    var nodes = cy.nodes().not(".gx-off");
    var zoomed = cy.zoom() >= 1.2;
    var budget = Math.max(8, Math.round(60 / Math.max(1, nodes.length / 60)));
    var top = {};
    nodes.filter(function (n) { return !n.data("seed") && !n.data("confirmed"); })
      .sort(function (a, b) { return b.data("centrality") - a.data("centrality"); }).slice(0, budget)
      .forEach(function (n) { top[n.id()] = true; });
    cy.batch(function () {
      setClass(nodes, "lbl", function (n) { return zoomed || nodes.length <= 18 || n.data("confirmed") || !!top[n.id()]; });
    });
  }

  function status() {
    var cy = S.cy, el2 = S.root.querySelector("[data-gx-status]");
    if (!cy || !el2) return;
    var shown = cy.nodes().not(".gx-off").length, total = cy.nodes().length;
    var parts = [shown + " of " + total + " findings shown"];
    var hidden = Object.keys(S.hidden).length;
    if (hidden) parts.push(hidden + " hidden by you");
    if (S.filtered) parts.push(S.filtered + " filtered out");
    var sel = cy.$(":selected").length;
    if (sel) parts.push(sel + " selected");
    el2.textContent = parts.join(" · ");
    if (S.data.hidden && !S.showAll) {
      el2.appendChild(document.createTextNode(" · "));
      var more = el("button", "link-btn", "load " + S.data.hidden + " weaker finding" + (S.data.hidden === 1 ? "" : "s"));
      more.type = "button"; more.dataset.gx = "load-all";
      el2.appendChild(more);
    }
    toolbarState();
  }

  function toolbarState() {
    var sel = S.cy ? S.cy.$("node:selected") : [];
    var set = function (k, on) { var b = S.root.querySelector('[data-gx="' + k + '"]'); if (b) b.disabled = !on; };
    set("expand", sel.length > 0); set("isolate", sel.length > 0); set("hide", sel.length > 0); set("paths", sel.length === 2);
    set("undo", S.undo.length > 0); set("redo", S.redo.length > 0);
  }

  // --- Undo -------------------------------------------------------------------------------------
  function snapshot() {
    var pos = {};
    S.cy.nodes().forEach(function (n) { var p = n.position(); pos[n.id()] = [Math.round(p.x), Math.round(p.y)]; });
    return { hidden: Object.assign({}, S.hidden), collapsed: JSON.parse(JSON.stringify(S.collapsed)), filters: filters(), layout: S.layout, pos: pos };
  }
  function restore(snap) {
    S.hidden = Object.assign({}, snap.hidden);
    S.collapsed = JSON.parse(JSON.stringify(snap.collapsed));
    S.collapsedBy = collapsedByFn();
    setFilters(snap.filters);
    S.layout = snap.layout;
    S.root.querySelectorAll("[data-gx-layout]").forEach(function (b) { b.setAttribute("aria-pressed", String(b.dataset.gxLayout === snap.layout)); });
    S.cy.batch(function () {
      S.cy.nodes().forEach(function (n) { var p = snap.pos[n.id()]; if (p) { n.position({ x: p[0], y: p[1] }); n.scratch("_gx", true); } });
    });
    markCollapsed(); apply(); save();
  }
  function push() { if (!S.cy) return; S.undo.push(snapshot()); if (S.undo.length > 50) S.undo.shift(); S.redo = []; toolbarState(); }
  function undo() { if (!S.undo.length) return; S.redo.push(snapshot()); restore(S.undo.pop()); }
  function redo() { if (!S.redo.length) return; S.undo.push(snapshot()); restore(S.redo.pop()); }

  // The view survives a reload; it is a per-browser convenience, never case data.
  function save() {
    try {
      var snap = snapshot();
      localStorage.setItem(S.key, JSON.stringify({ v: 1, hidden: snap.hidden, collapsed: snap.collapsed, filters: snap.filters, layout: snap.layout, pos: snap.pos }));
    } catch (e) { /* storage unavailable: the view just isn't remembered */ }
  }
  function load() {
    try { var raw = localStorage.getItem(S.key); return raw ? JSON.parse(raw) : null; } catch (e) { return null; }
  }

  // --- View actions -----------------------------------------------------------------------------
  function selected() { return S.cy.$("node:selected"); }

  function hideSel() {
    var sel = selected().filter(function (n) { return !n.data("seed"); });
    if (!sel.length) { toast("Targets stay on the graph; they anchor everything else."); return; }
    push();
    sel.forEach(function (n) { S.hidden[n.id()] = true; });
    S.cy.elements().unselect();
    apply(); save(); inspectOverview();
    toast("Hidden " + sel.length + " from this view. Undo with Ctrl+Z.");
  }

  function isolateSel() {
    var sel = selected();
    if (!sel.length) return;
    push();
    var keep = {};
    sel.closedNeighborhood("node").forEach(function (n) { keep[n.id()] = true; });
    S.cy.nodes().forEach(function (n) { if (!keep[n.id()] && !n.data("seed")) S.hidden[n.id()] = true; else delete S.hidden[n.id()]; });
    apply(); save(); fit(sel.closedNeighborhood());
  }

  function expandSel() {
    var sel = selected();
    if (!sel.length) return;
    push();
    var shown = 0;
    sel.forEach(function (n) {
      delete S.collapsed[n.id()];
      n.neighborhood("node").forEach(function (m) { if (S.hidden[m.id()]) { delete S.hidden[m.id()]; shown++; } });
    });
    S.collapsedBy = collapsedByFn();
    markCollapsed(); apply(); save();
    if (!shown) toast("Nothing hidden next to the selection" + (S.filtered ? " (some links may be filtered out)" : "") + ".");
  }

  function collapseNode(n) {
    var leaves = n.neighborhood("node").filter(function (m) { return !m.data("seed") && m.degree(false) === 1 && !m.hasClass("gx-off"); });
    if (!leaves.length) { toast("No findings hang only off this one."); return; }
    push();
    S.collapsed[n.id()] = leaves.map(function (m) { return m.id(); });
    S.collapsedBy = collapsedByFn();
    markCollapsed(); apply(); save();
  }

  function markCollapsed() {
    S.cy.batch(function () {
      S.cy.nodes().forEach(function (n) {
        var k = (S.collapsed[n.id()] || []).length;
        n.data("collapsedCount", k);
        n.data("collapsedLabel", k ? n.data("short") + "  +" + k : "");
      });
    });
  }

  function fit(eles) {
    var target = eles && eles.length ? eles : S.cy.elements().not(".gx-off");
    S.cy.animate({ fit: { eles: target, padding: 50 } }, { duration: reduced() ? 0 : 250 });
  }

  function reset() {
    push();
    S.hidden = {}; S.collapsed = {}; S.collapsedBy = collapsedByFn();
    setFilters({});
    clearPath();
    markCollapsed(); apply();
    runLayout(S.layout).then(save);
  }

  // --- Search -----------------------------------------------------------------------------------
  function find(q) {
    var cy = S.cy;
    cy.nodes(".gx-hit").removeClass("gx-hit");
    S.hits = []; S.hit = -1;
    q = (q || "").trim().toLowerCase();
    var countEl = S.root.querySelector("[data-gx-find-count]");
    if (!q) { if (countEl) countEl.textContent = ""; return; }
    var field = null, m = q.match(/^(type|tool|site|is):(\S*)\s*(.*)$/);
    if (m) { field = m[1]; q = m[3]; }
    var want = m ? m[2] : "";
    S.hits = cy.nodes().filter(function (n) {
      var d = n.data();
      if (field === "type" && String(d.type).indexOf(want) !== 0 && TYPES[typeKey(d.type)].label.toLowerCase().indexOf(want) !== 0) return false;
      if (field === "tool" && !(d.sources || []).some(function (s) { return s.indexOf(want) === 0; })) return false;
      if (field === "site" && String(d.site || "").toLowerCase().indexOf(want) === -1) return false;
      if (field === "is" && d.strength !== want && !(want === "confirmed" && d.confirmed)) return false;
      if (!q) return true;
      return String(d.value).toLowerCase().indexOf(q) !== -1 || String(d.site || "").toLowerCase().indexOf(q) !== -1;
    }).toArray();
    S.hits.forEach(function (n) { n.addClass("gx-hit"); if (n.hasClass("gx-off")) { delete S.hidden[n.id()]; } });
    apply();
    if (countEl) countEl.textContent = S.hits.length ? S.hits.length + " found" : "none";
  }

  function stepHit(dir) {
    if (!S.hits.length) return;
    S.hit = (S.hit + dir + S.hits.length) % S.hits.length;
    var n = S.hits[S.hit];
    var countEl = S.root.querySelector("[data-gx-find-count]");
    if (countEl) countEl.textContent = (S.hit + 1) + " of " + S.hits.length;
    select(n, true);
  }

  // --- Selection and inspector --------------------------------------------------------------------
  function select(n, center) {
    if (!n || !n.length) return;
    S.cy.elements().unselect();
    n.select();
    if (center) {
      var z = Math.max(S.cy.zoom(), 1.1);
      S.cy.animate({ center: { eles: n }, zoom: z }, { duration: reduced() ? 0 : 250 });
    }
  }

  function body() { return S.root.querySelector("[data-gx-inspect-body]"); }

  function section(title) { var s = el("section", "gx-sec"); if (title) s.appendChild(el("h3", "eyebrow", title)); return s; }

  function kv(list) {
    var dl = el("dl", "gx-kv");
    list.forEach(function (row) {
      if (row[1] == null || row[1] === "") return;
      var d = el("div"); d.appendChild(el("dt", null, row[0]));
      var dd = el("dd"); if (row[1] instanceof Node) dd.appendChild(row[1]); else dd.textContent = row[1];
      d.appendChild(dd); dl.appendChild(d);
    });
    return dl;
  }

  function actionBtn(label, action, title, primary) {
    var b = el("button", "btn btn-sm" + (primary ? " btn-primary" : ""), label);
    b.type = "button"; b.dataset.gx = action; if (title) b.title = title;
    return b;
  }

  function inspectOverview() {
    var b = body();
    if (!b || !S.cy) return;
    b.innerHTML = "";
    var nodes = S.cy.nodes(), edges = S.cy.edges();
    var head = section();
    head.appendChild(el("p", "eyebrow", "This case"));
    head.appendChild(el("h2", "gx-title", nodes.length + " findings, " + edges.length + " links"));
    var cl = S.data.clusters || 1;
    head.appendChild(el("p", "muted small", cl > 1 ? cl + " separate groups: nothing collected links them to each other." : "Everything collected is connected."));
    b.appendChild(head);
    var counts = {};
    edges.forEach(function (e) { counts[e.data("basis")] = (counts[e.data("basis")] || 0) + 1; });
    var links = section("How the links were established");
    var ul = el("ul", "gx-bars");
    ["observed", "rule", "similarity", "analyst"].forEach(function (k) {
      if (!counts[k]) return;
      var li = el("li");
      li.appendChild(el("span", "gx-key gx-key-" + k));
      li.appendChild(el("span", "gx-bar-label", BASIS[k].label));
      li.appendChild(el("span", "gx-bar-num", String(counts[k])));
      li.title = BASIS[k].text;
      ul.appendChild(li);
    });
    links.appendChild(ul);
    b.appendChild(links);
    var hubs = nodes.filter(function (n) { return !n.data("seed"); }).sort(function (x, y) { return (y.data("degree") || 0) - (x.data("degree") || 0); }).slice(0, 5);
    if (hubs.length && hubs[0].data("degree") > 1) {
      var h = section("Most connected");
      var list = el("ol", "gx-list");
      hubs.forEach(function (n) {
        var li = el("li"), btn = el("button", "link-btn", n.data("short"));
        btn.type = "button"; btn.dataset.gxSelect = n.id();
        li.appendChild(btn); li.appendChild(el("span", "faint small", " " + n.data("degree") + " links"));
        list.appendChild(li);
      });
      h.appendChild(list);
      h.appendChild(el("p", "hint", "Connections show where findings meet, not who is behind them."));
      b.appendChild(h);
    }
    var how = section("Working the graph");
    var tips = el("ul", "gx-tips");
    ["Click a finding or a link to see its evidence.", "Shift-click or Shift-drag to select several.",
     "Select two findings and press Paths to see how they connect.", "Hide, isolate and filters change only this view; Ctrl+Z undoes."]
      .forEach(function (t) { tips.appendChild(el("li", null, t)); });
    how.appendChild(tips);
    b.appendChild(how);
  }

  function inspectNode(n) {
    var b = body();
    b.innerHTML = "";
    var d = n.data();
    var head = section();
    head.appendChild(el("p", "eyebrow", TYPES[typeKey(d.type)].label + (d.site ? " · " + d.site : "")));
    head.appendChild(el("h2", "gx-title ident", d.value));
    var stamp = el("span", "pill" + (d.confirmed ? " pill-ok" : ""), d.confirmed ? "Confirmed" : STRENGTH[d.strength] || d.strength);
    head.appendChild(stamp);
    if (d.merged) head.appendChild(el("span", "pill", d.merged + " merged"));
    b.appendChild(head);
    b.appendChild(kv([
      ["Score", d.seed ? "target" : d.confidence.toFixed(2)],
      ["Found by", (d.sources || []).join(", ")],
      ["Source grade", d.reliability ? d.reliability + " (Admiralty)" : ""],
      ["First seen", fmtDate(d.first_seen)],
      ["Last seen", fmtDate(d.last_seen)],
      ["Links", String(d.degree || 0)]
    ]));
    var acts = el("div", "gx-actions");
    acts.appendChild(actionBtn("Expand", "expand", "Show its hidden links"));
    acts.appendChild(actionBtn("Isolate", "isolate", "Only this and its direct links"));
    acts.appendChild(actionBtn("Collapse", "collapse", "Fold findings that hang only off this one"));
    if (!d.seed) acts.appendChild(actionBtn("Hide", "hide"));
    acts.appendChild(actionBtn(S.pathFrom === n.id() ? "Pick the other end…" : "Path from here", "path-from", "Then click the other finding"));
    b.appendChild(acts);
    var ev = el("div", "gx-evidence");
    ev.id = "gx-entity";
    ev.appendChild(el("p", "faint small", "Loading the evidence…"));
    b.appendChild(ev);
    window.htmx.ajax("GET", "/cases/" + S.root.dataset.case + "/entities/" + n.id() + "?panel=1", { target: "#gx-entity", swap: "innerHTML" })
      .catch(function () { ev.textContent = "Could not load the evidence for this finding."; });
  }

  function inspectEdge(e) {
    var b = body();
    b.innerHTML = "";
    var d = e.data(), src = e.source().data(), dst = e.target().data();
    var head = section();
    head.appendChild(el("p", "eyebrow", "Link · " + d.label));
    var t = el("h2", "gx-title gx-edge-title");
    t.appendChild(el("span", "ident", src.short));
    t.appendChild(el("span", "gx-arrow", d.directed ? " → " : " — "));
    t.appendChild(el("span", "ident", dst.short));
    head.appendChild(t);
    var basis = BASIS[d.basis] || { label: d.basis, text: "" };
    head.appendChild(el("span", "pill gx-basis-" + d.basis, basis.label));
    if (d.suggested) head.appendChild(el("span", "pill pill-warn", "Unreviewed duplicate"));
    head.appendChild(el("p", "small muted gx-basis-text", basis.text));
    b.appendChild(head);
    var conf = d.confidence ? d.confidence.toFixed(2) : "—";
    b.appendChild(kv([
      [d.basis === "similarity" ? "Similarity" : "Confidence", conf],
      ["Direction", d.directed ? "Found from " + src.short : "None: the two values were compared"],
      ["First seen", fmtDate(d.first_seen)],
      ["Last seen", fmtDate(d.last_seen)],
      ["Times seen", String(d.seen || 1)]
    ]));
    var evs = section("Evidence (" + d.evidence.length + ")");
    var list = el("ol", "gx-ev-list");
    d.evidence.forEach(function (x) {
      var li = el("li");
      var top = el("p", "gx-ev-head");
      top.appendChild(el("strong", null, x.tool === "correlation" ? "Matching engine" : x.tool === "analyst" ? "Analyst" : x.tool));
      top.appendChild(el("span", "faint small", " · " + (BASIS[x.basis] ? BASIS[x.basis].label : x.basis) + (x.confidence != null ? " · " + Number(x.confidence).toFixed(2) : "")));
      li.appendChild(top);
      if (x.why) li.appendChild(el("p", "gx-ev-why", x.why));
      li.appendChild(el("p", "faint small", "Recorded " + fmtDate(x.first_seen) + (x.seen > 1 ? ", seen " + x.seen + " times, last " + fmtDate(x.last_seen) : "")));
      list.appendChild(li);
    });
    evs.appendChild(list);
    b.appendChild(evs);
    if (d.basis === "similarity" || d.basis === "rule") {
      b.appendChild(el("p", "gx-caveat", "Inferred link. It connects two values; it does not show they belong to the same person."));
    }
    var acts = el("div", "gx-actions");
    var both = actionBtn("Select both ends", "select-ends"); both.dataset.edge = e.id();
    acts.appendChild(both);
    b.appendChild(acts);
  }

  function inspectMany(sel) {
    var b = body();
    b.innerHTML = "";
    var head = section();
    head.appendChild(el("p", "eyebrow", "Selection"));
    head.appendChild(el("h2", "gx-title", sel.length + " findings"));
    var by = {};
    sel.forEach(function (n) { var k = TYPES[typeKey(n.data("type"))].label; by[k] = (by[k] || 0) + 1; });
    head.appendChild(el("p", "muted small", Object.keys(by).map(function (k) { return by[k] + " " + k.toLowerCase(); }).join(", ")));
    b.appendChild(head);
    var acts = el("div", "gx-actions");
    if (sel.length === 2) acts.appendChild(actionBtn("Find paths", "paths", "Strongest evidence paths between these two", true));
    acts.appendChild(actionBtn("Isolate", "isolate")); acts.appendChild(actionBtn("Expand", "expand")); acts.appendChild(actionBtn("Hide", "hide"));
    b.appendChild(acts);
    {
      var dec = section("Decide");
      dec.appendChild(el("p", "hint", "Applies to every selected finding except targets, and is recorded in the case activity."));
      var row = el("div", "gx-actions");
      row.appendChild(actionBtn("Same person", "bulk-confirm"));
      row.appendChild(actionBtn("Not them", "bulk-dismiss"));
      dec.appendChild(row);
      b.appendChild(dec);
    }
    var list = el("ul", "gx-list");
    sel.slice(0, 40).forEach(function (n) {
      var li = el("li"), btn = el("button", "link-btn ident", n.data("short"));
      btn.type = "button"; btn.dataset.gxSelect = n.id();
      li.appendChild(btn); list.appendChild(li);
    });
    b.appendChild(list);
  }

  function bulk(action) {
    var ids = selected().filter(function (n) { return !n.data("seed"); }).map(function (n) { return n.id(); });
    if (!ids.length) return;
    window.htmx.ajax("POST", "/cases/" + S.root.dataset.case + "/entities/bulk",
      { source: S.root, values: { action: action, ids: ids.join(","), reason: "different_person" }, swap: "none" });
  }

  // --- Paths --------------------------------------------------------------------------------------
  function clearPath() {
    if (!S.cy) return;
    S.cy.elements(".gx-path, .gx-dim, .gx-weak").removeClass("gx-path gx-dim gx-weak");
    S.paths = null; S.activePath = -1;
  }

  function showPath(i) {
    var p = S.paths && S.paths.paths[i];
    if (!p) return;
    S.activePath = i;
    var cy = S.cy;
    var onPath = {};
    p.nodes.concat(p.edges).forEach(function (id) { onPath[id] = true; });
    cy.batch(function () {
      setClass(cy.elements(), "gx-dim", function (x) { return !onPath[x.id()]; });
      setClass(cy.elements(), "gx-path", function (x) { return !!onPath[x.id()]; });
      cy.elements(".gx-weak").removeClass("gx-weak");
      p.nodes.forEach(function (id) { var n = cy.getElementById(id); n.removeClass("gx-dim gx-off").addClass("gx-path"); delete S.hidden[id]; });
      p.edges.forEach(function (id) { var e = cy.getElementById(id); e.removeClass("gx-dim gx-off").addClass("gx-path"); if (id === p.weakest) e.addClass("gx-weak"); });
    });
    placeNew(cy.nodes().not(".gx-off"));
    body().querySelectorAll("[data-gx-path]").forEach(function (li) { li.classList.toggle("is-active", Number(li.dataset.gxPath) === i); });
    fit(cy.elements(".gx-path"));
  }

  function findPaths(a, b) {
    var url = S.root.dataset.paths + "?a=" + encodeURIComponent(a) + "&b=" + encodeURIComponent(b);
    var bd = body();
    bd.innerHTML = "";
    bd.appendChild(el("p", "faint small", "Looking for paths…"));
    fetch(url, { credentials: "same-origin" })
      .then(function (r) { if (!r.ok) throw new Error("HTTP " + r.status); return r.json(); })
      .then(function (res) { S.paths = res; renderPaths(a, b); if (res.paths.length) showPath(0); })
      .catch(function (err) { bd.innerHTML = ""; bd.appendChild(el("p", "alert alert-error", "Could not find paths: " + err.message)); });
  }

  function renderPaths(a, b) {
    var cy = S.cy, bd = body(), res = S.paths;
    bd.innerHTML = "";
    var head = section();
    head.appendChild(el("p", "eyebrow", "Paths"));
    var t = el("h2", "gx-title");
    t.appendChild(el("span", "ident", cy.getElementById(a).data("short")));
    t.appendChild(el("span", "gx-arrow", " ⋯ "));
    t.appendChild(el("span", "ident", cy.getElementById(b).data("short")));
    head.appendChild(t);
    bd.appendChild(head);
    if (!res.paths.length) {
      bd.appendChild(el("p", "muted", "Nothing collected connects these two within six links."));
      bd.appendChild(el("p", "hint", "That is a finding too: the evidence doesn't tie them together."));
    }
    var list = el("ol", "gx-paths");
    res.paths.forEach(function (p, i) {
      var li = el("li", "gx-path-item"); li.dataset.gxPath = i; li.tabIndex = 0; li.setAttribute("role", "button");
      var top = el("div", "gx-path-top");
      top.appendChild(el("strong", null, i === 0 ? "Strongest" : "Alternative " + i));
      var meter = el("span", "gx-meter"); var fill = el("span"); fill.style.width = Math.round(p.score * 100) + "%"; meter.appendChild(fill);
      top.appendChild(meter);
      top.appendChild(el("span", "mono small", p.score.toFixed(2)));
      li.appendChild(top);
      var chain = el("p", "gx-chain");
      p.nodes.forEach(function (id, k) {
        if (k) {
          var e = cy.getElementById(p.edges[k - 1]);
          chain.appendChild(el("span", "gx-hop" + (p.edges[k - 1] === p.weakest ? " is-weak" : ""), " " + (e.length ? e.data("label") : "link") + " "));
        }
        chain.appendChild(el("span", "ident", cy.getElementById(id).data("short")));
      });
      li.appendChild(chain);
      li.appendChild(el("p", "faint small", p.hops + " link" + (p.hops === 1 ? "" : "s") + ": " + p.observed + " observed, " + p.inferred + " inferred"));
      var weak = cy.getElementById(p.weakest);
      if (weak.length) li.appendChild(el("p", "small gx-weak-note", "Weakest link: " + (weak.data("why") || weak.data("label"))));
      p.flags.forEach(function (f) { li.appendChild(el("p", "small gx-flag", f)); });
      list.appendChild(li);
    });
    bd.appendChild(list);
    bd.appendChild(el("p", "gx-caveat", res.caveat));
    var acts = el("div", "gx-actions");
    acts.appendChild(actionBtn("Clear paths", "clear-path"));
    bd.appendChild(acts);
  }

  // --- Minimap --------------------------------------------------------------------------------------
  function minimapSoon() {
    clearTimeout(S.minimapTimer);
    S.minimapTimer = setTimeout(drawMinimap, 350);
  }
  function drawMinimap() {
    if (!S || !S.cy) return;
    var canvas = S.root.querySelector("[data-gx-minimap]");
    if (!canvas || !S.cy) return;
    var cy = S.cy, visible = cy.elements().not(".gx-off");
    canvas.hidden = visible.nodes().length < 12;
    if (canvas.hidden) return;
    var bb = visible.boundingBox();
    var scale = Math.min(canvas.width / Math.max(1, bb.w), canvas.height / Math.max(1, bb.h)) * 0.9;
    var ox = (canvas.width - bb.w * scale) / 2 - bb.x1 * scale, oy = (canvas.height - bb.h * scale) / 2 - bb.y1 * scale;
    S.mini = { scale: scale, ox: ox, oy: oy };
    var ctx = canvas.getContext("2d"), c = palette();
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    ctx.globalAlpha = 0.5; ctx.strokeStyle = c.line; ctx.lineWidth = 0.6;
    ctx.beginPath();
    visible.edges().forEach(function (e) {
      var a = e.source().position(), b = e.target().position();
      ctx.moveTo(a.x * scale + ox, a.y * scale + oy); ctx.lineTo(b.x * scale + ox, b.y * scale + oy);
    });
    ctx.stroke(); ctx.globalAlpha = 1;
    visible.nodes().forEach(function (n) {
      var p = n.position();
      ctx.fillStyle = n.data("seed") ? c.strong : n.data("tcolor");
      ctx.fillRect(p.x * scale + ox - 1.5, p.y * scale + oy - 1.5, 3, 3);
    });
    var ext = cy.extent();
    ctx.strokeStyle = c.strong; ctx.lineWidth = 1.2;
    ctx.strokeRect(ext.x1 * scale + ox, ext.y1 * scale + oy, ext.w * scale, ext.h * scale);
  }

  // --- Export ---------------------------------------------------------------------------------------
  function download(href, name) {
    var a = document.createElement("a");
    a.href = href; a.download = name;
    document.body.appendChild(a); a.click(); a.remove();
  }
  function baseName() { return (S.root.dataset.caseName || "case").replace(/[^\w.-]+/g, "-").slice(0, 60); }

  function exportPng(full) {
    var c = palette();
    S.cy.nodes().not(".gx-off").addClass("lbl");
    var url = S.cy.png({ full: full, scale: 2, bg: c.bg, output: "base64uri" });
    labels();
    download(url, baseName() + "-graph.png");
  }

  function exportJson() {
    var cy = S.cy, nodes = cy.nodes().not(".gx-off"), ids = {};
    nodes.forEach(function (n) { ids[n.id()] = true; });
    var out = {
      format: "unmask-subgraph", version: 1, exported_at: new Date().toISOString(),
      note: "The part of the case graph that was on screen. Links carry the evidence that established them; inferred links (rule, similarity) are not proof of identity.",
      nodes: nodes.map(function (n) { var d = n.data(); return { id: d.id, type: d.type, value: d.value, site: d.site, strength: d.strength, confidence: d.confidence, confirmed: d.confirmed, target: d.seed, sources: d.sources, reliability: d.reliability, first_seen: d.first_seen, last_seen: d.last_seen }; }),
      links: cy.edges().not(".gx-off").filter(function (e) { return ids[e.source().id()] && ids[e.target().id()]; }).map(function (e) {
        var d = e.data(); return { source: d.source, target: d.target, type: d.type, directed: d.directed, basis: d.basis, confidence: d.confidence, first_seen: d.first_seen, last_seen: d.last_seen, evidence: d.evidence };
      })
    };
    var blob = new Blob([JSON.stringify(out, null, 2)], { type: "application/json" });
    var url = URL.createObjectURL(blob);
    download(url, baseName() + "-subgraph.json");
    setTimeout(function () { URL.revokeObjectURL(url); }, 2000);
  }

  // --- Legend and filter lists ---------------------------------------------------------------------
  function buildLists() {
    var root = S.root, nodes = S.data.nodes;
    var types = {}, sources = {};
    nodes.forEach(function (n) {
      types[typeKey(n.type)] = (types[typeKey(n.type)] || 0) + 1;
      (n.sources || []).forEach(function (s) { sources[s] = (sources[s] || 0) + 1; });
    });
    var c = palette();
    var fill = function (box, entries, key, labelFn, glyph) {
      if (!box) return;
      box.innerHTML = "";
      entries.forEach(function (k) {
        var lab = el("label", "check");
        var input = el("input"); input.type = "checkbox"; input.value = k; input.checked = true; input.dataset.gxF = key;
        lab.appendChild(input);
        if (glyph) { var img = el("img", "gx-glyph"); img.src = glyphURI(k, c.types[k]); img.alt = ""; lab.appendChild(img); }
        lab.appendChild(el("span", null, labelFn(k)));
        lab.appendChild(el("span", "count", String((key === "type" ? types : sources)[k])));
        box.appendChild(lab);
      });
    };
    fill(root.querySelector("[data-gx-types]"), Object.keys(TYPES).filter(function (t) { return types[t]; }), "type", function (k) { return TYPES[k].label; }, true);
    fill(root.querySelector("[data-gx-sources]"), Object.keys(sources).sort(), "source", function (k) { return k === "analyst" ? "you (targets)" : k; }, false);
    var legend = root.querySelector("[data-gx-legend]");
    if (legend) {
      legend.innerHTML = "";
      var keys = [["gx-lk-target", "Target"], ["gx-lk-confirmed", "Confirmed"], ["gx-lk-possible", "Possible"], ["gx-lk-weak", "Weak / unchecked"]];
      keys.forEach(function (k) { var s = el("span", "gx-lk " + k[0]); legend.appendChild(s); legend.appendChild(el("span", null, k[1])); });
      [["observed", "Observed"], ["similarity", "Similarity"], ["suggested", "Possible duplicate"]].forEach(function (k) {
        legend.appendChild(el("span", "gx-key gx-key-" + k[0])); legend.appendChild(el("span", null, k[1]));
      });
    }
  }

  // --- Build ------------------------------------------------------------------------------------------
  function fetchGraph() {
    var url = S.root.dataset.graph + (S.showAll ? "?all=1" : "");
    return fetch(url, { credentials: "same-origin" }).then(function (r) { if (!r.ok) throw new Error("HTTP " + r.status); return r.json(); });
  }

  function state(kind, msg) {
    var box = S.root.querySelector("[data-gx-state]");
    if (!box) return;
    box.hidden = kind === "ready";
    if (kind === "ready") return;
    box.innerHTML = "";
    box.appendChild(el("p", kind === "error" ? "alert alert-error" : "muted", msg));
  }

  function build(data) {
    var c = palette();
    S.data = data;
    S.sizeBy = "score";
    data.nodes.forEach(function (n) { decorate(n, c, "score"); n.collapsedCount = 0; n.collapsedLabel = ""; });
    data.edges.forEach(function (e) { e.label = e.label || e.type; });
    var elements = data.nodes.map(function (n) { return { group: "nodes", data: n }; })
      .concat(data.edges.map(function (e) { return { group: "edges", data: e }; }));
    if (S.cy) S.cy.destroy();
    var big = data.nodes.length > BIG;
    S.cy = window.cytoscape({
      container: S.root.querySelector("#cy"), elements: elements, style: style(), layout: { name: "null" },
      minZoom: 0.08, maxZoom: 3.5, wheelSensitivity: 0.35, boxSelectionEnabled: true, selectionType: "single",
      textureOnViewport: big, hideEdgesOnViewport: big, pixelRatio: data.nodes.length > HUGE ? 1 : "auto"
    });
    var cy = S.cy;
    buildLists();
    S.collapsedBy = collapsedByFn();

    // Restore the analyst's last view of this case, if the graph still matches it.
    var saved = load();
    var restored = false;
    if (saved && saved.v === 1) {
      S.hidden = saved.hidden || {}; S.collapsed = saved.collapsed || {}; S.collapsedBy = collapsedByFn();
      setFilters(saved.filters || {});
      S.layout = saved.layout || "rings";
      var known = 0;
      cy.nodes().forEach(function (n) { var p = saved.pos && saved.pos[n.id()]; if (p) { n.position({ x: p[0], y: p[1] }); n.scratch("_gx", true); known++; } });
      restored = known >= cy.nodes().length * 0.8;
    }
    S.root.querySelectorAll("[data-gx-layout]").forEach(function (b) { b.setAttribute("aria-pressed", String(b.dataset.gxLayout === S.layout)); });
    markCollapsed();
    apply();
    var ready = restored ? Promise.resolve(cy.fit(cy.elements().not(".gx-off"), 50)) : runLayout(S.layout, { instant: true });
    Promise.resolve(ready).then(function () { labels(); minimapSoon(); state("ready"); if (restored) toast("Restored your last view of this graph. Reset view in Filters starts over."); });

    // Interaction.
    var hoverOK = data.nodes.length <= BIG;
    cy.on("mouseover", "edge", function (e) { e.target.addClass("hover"); });
    cy.on("mouseout", "edge", function (e) { e.target.removeClass("hover"); });
    if (hoverOK) {
      cy.on("mouseover", "node", function (e) {
        if (S.activePath >= 0) return;
        var hood = e.target.closedNeighborhood();
        cy.batch(function () { cy.elements().not(hood).addClass("gx-dim"); });
      });
      cy.on("mouseout", "node", function () { if (S.activePath < 0) cy.elements(".gx-dim").removeClass("gx-dim"); });
    }
    cy.on("zoom", function () { clearTimeout(S.zt); S.zt = setTimeout(function () { labels(); drawMinimap(); }, 120); });
    cy.on("pan", function () { clearTimeout(S.pt); S.pt = setTimeout(drawMinimap, 80); });
    cy.on("tap", "node", function (e) {
      var n = e.target;
      if (S.pathFrom && S.pathFrom !== n.id()) {
        var from = S.pathFrom; S.pathFrom = null;
        cy.elements().unselect(); cy.getElementById(from).select(); n.select();
        findPaths(from, n.id());
      }
    });
    cy.on("select unselect", function () {
      clearTimeout(S.st);
      S.st = setTimeout(function () {
        var sel = cy.$(":selected"), nodes = sel.nodes();
        status();
        if (S.paths && nodes.length === 2) return;
        if (nodes.length === 1 && sel.length === 1) inspectNode(nodes[0]);
        else if (nodes.length > 1) inspectMany(nodes);
        else if (sel.edges().length === 1) inspectEdge(sel.edges()[0]);
        else if (!S.paths) inspectOverview();
        var one = nodes[0];
        if (one) announce(TYPES[typeKey(one.data("type"))].label + " " + one.data("value") + ", " + (STRENGTH[one.data("strength")] || ""));
      }, 30);
    });
    cy.on("dragfree", "node", function () { save(); minimapSoon(); });
    inspectOverview();
  }

  function announce(text) { var s = S.root.querySelector("[data-gx-status]"); if (s) s.setAttribute("aria-label", text); }

  // After a decision: update node states in place, add anything new, keep positions.
  function refresh() {
    if (!S || !S.cy) return;
    fetchGraph().then(function (data) {
      var c = palette(), cy = S.cy, byId = {};
      data.nodes.forEach(function (n) { byId[n.id] = n; });
      cy.batch(function () {
        cy.nodes().forEach(function (n) {
          var d = byId[n.id()];
          if (!d) { n.remove(); return; }
          decorate(d, c, S.sizeBy); d.collapsedCount = n.data("collapsedCount"); d.collapsedLabel = n.data("collapsedLabel");
          n.data(d);
        });
        data.nodes.forEach(function (n) { if (!cy.getElementById(n.id).length) { decorate(n, c, S.sizeBy); n.collapsedCount = 0; n.collapsedLabel = ""; cy.add({ group: "nodes", data: n }); } });
        var edgeIds = {};
        data.edges.forEach(function (e) { edgeIds[e.id] = true; var ex = cy.getElementById(e.id); if (ex.length) ex.data(e); else cy.add({ group: "edges", data: e }); });
        cy.edges().forEach(function (e) { if (!edgeIds[e.id()]) e.remove(); });
      });
      S.data = data;
      buildLists(); apply();
      var sel = cy.$("node:selected");
      if (sel.length === 1) inspectNode(sel[0]);
    });
  }

  function restyle() { if (S && S.cy) { var c = palette(); S.cy.batch(function () { S.cy.nodes().forEach(function (n) { var d = n.data(); n.data("tcolor", c.types[typeKey(d.type)]); n.data("icon", glyphURI(typeKey(d.type), d.seed ? c.bg : c.types[typeKey(d.type)])); }); }); S.cy.style(style()); drawMinimap(); } }
  document.addEventListener("unmask:theme", restyle);
  if (window.matchMedia) {
    var mq = window.matchMedia("(prefers-color-scheme: dark)");
    if (mq.addEventListener) mq.addEventListener("change", restyle);
  }

  // --- Wiring ----------------------------------------------------------------------------------------
  function onClick(e) {
    var t = e.target.closest("[data-gx], [data-gx-layout], [data-gx-select], [data-gx-path]");
    if (!t || !S.cy) return;
    if (t.dataset.gxLayout) { setLayout(t.dataset.gxLayout); return; }
    if (t.dataset.gxSelect) { select(S.cy.getElementById(t.dataset.gxSelect), true); return; }
    if (t.dataset.gxPath != null && !t.dataset.gx) { showPath(Number(t.dataset.gxPath)); return; }
    var sel = selected();
    switch (t.dataset.gx) {
      case "expand": expandSel(); break;
      case "isolate": isolateSel(); break;
      case "hide": hideSel(); break;
      case "collapse": if (sel.length) collapseNode(sel[0]); break;
      case "paths": if (sel.length === 2) findPaths(sel[0].id(), sel[1].id()); break;
      case "path-from": if (sel.length) { S.pathFrom = sel[0].id(); toast("Now click the finding to find paths to."); inspectNode(sel[0]); } break;
      case "clear-path": clearPath(); inspectOverview(); S.cy.elements().unselect(); break;
      case "undo": undo(); break;
      case "redo": redo(); break;
      case "fit": fit(); break;
      case "relayout": push(); runLayout(S.layout).then(save); break;
      case "reset": reset(); break;
      case "filters": {
        var open = S.root.classList.toggle("gx-filters-closed");
        t.setAttribute("aria-expanded", String(!open));
        setTimeout(function () { S.cy.resize(); drawMinimap(); }, 200);
        break;
      }
      case "png-view": exportPng(false); break;
      case "png-all": exportPng(true); break;
      case "json": exportJson(); break;
      case "find-next": stepHit(1); break;
      case "find-prev": stepHit(-1); break;
      case "select-ends": { var edge = S.cy.getElementById(t.dataset.edge); S.cy.elements().unselect(); edge.connectedNodes().select(); break; }
      case "bulk-confirm": bulk("confirm"); break;
      case "bulk-dismiss": bulk("dismiss"); break;
      case "load-all": S.showAll = true; fetchGraph().then(build); break;
    }
    var menu = t.closest("details.menu");
    if (menu) menu.open = false;
  }

  function onKey(e) {
    if (!S || !S.cy) return;
    var typing = /^(INPUT|TEXTAREA|SELECT)$/.test(e.target.tagName) || e.target.isContentEditable;
    var mod = e.ctrlKey || e.metaKey;
    if (mod && e.key.toLowerCase() === "z" && !typing) { e.preventDefault(); if (e.shiftKey) redo(); else undo(); return; }
    if (mod && e.key.toLowerCase() === "y" && !typing) { e.preventDefault(); redo(); return; }
    if (typing || mod || e.altKey) return;
    var inside = S.root.contains(document.activeElement) || document.activeElement === document.body;
    if (!inside) return;
    var sel = selected();
    switch (e.key) {
      case "h": case "Delete": case "Backspace": if (sel.length) { e.preventDefault(); hideSel(); } break;
      case "i": if (sel.length) isolateSel(); break;
      case "e": if (sel.length) expandSel(); break;
      case "c": if (sel.length) collapseNode(sel[0]); break;
      case "p": if (sel.length === 2) findPaths(sel[0].id(), sel[1].id()); break;
      case "f": fit(); break;
      case "Escape": S.pathFrom = null; clearPath(); S.cy.elements().unselect(); inspectOverview(); break;
      case "ArrowRight": case "ArrowLeft": case "ArrowUp": case "ArrowDown": {
        if (!S.root.querySelector(".gx-stage").contains(document.activeElement)) return;
        e.preventDefault();
        var visible = S.cy.nodes().not(".gx-off");
        var from = sel[0];
        var pool = from ? from.neighborhood("node").not(".gx-off") : visible.filter(function (n) { return n.data("seed"); });
        if (!pool.length) pool = visible;
        S.kbIndex = ((S.kbIndex || 0) + (e.key === "ArrowLeft" || e.key === "ArrowUp" ? -1 : 1) + pool.length) % pool.length;
        select(pool[S.kbIndex], true);
        break;
      }
      case "Enter": if (sel.length === 1 && S.root.querySelector(".gx-stage").contains(document.activeElement)) inspectNode(sel[0]); break;
    }
  }

  // The workspace fills the window below where it starts, so the canvas, legend and overview are all in view.
  function fitHeight() {
    if (!S || window.matchMedia("(max-width: 900px)").matches) { if (S) S.root.style.height = ""; return; }
    var top = S.root.getBoundingClientRect().top + window.scrollY;
    S.root.style.height = Math.max(520, window.innerHeight - top - 16) + "px";
    if (S.cy) S.cy.resize();
  }

  function init() {
    var root = document.querySelector("[data-graph]");
    if (!root || root.dataset.ready) return;
    root.dataset.ready = "1";
    S = fresh(root);
    fitHeight();
    root.addEventListener("click", onClick);
    root.addEventListener("change", function (e) {
      if (!e.target.matches("[data-gx-f]")) return;
      push();
      if (e.target.dataset.gxF === "min") root.querySelector("[data-gx-min-out]").textContent = (Number(e.target.value) / 100).toFixed(2);
      apply(); save();
    });
    root.addEventListener("input", function (e) {
      if (e.target.matches('[data-gx-f="min"]')) root.querySelector("[data-gx-min-out]").textContent = (Number(e.target.value) / 100).toFixed(2);
      if (e.target.matches("[data-gx-find]")) { clearTimeout(S.ft); S.ft = setTimeout(function () { find(e.target.value); }, 150); }
    });
    root.addEventListener("keydown", function (e) {
      if (e.target.matches("[data-gx-find]") && e.key === "Enter") { e.preventDefault(); find(e.target.value); stepHit(e.shiftKey ? -1 : 1); }
      var pathItem = e.target.closest && e.target.closest("[data-gx-path]");
      if (pathItem && (e.key === "Enter" || e.key === " ")) { e.preventDefault(); showPath(Number(pathItem.dataset.gxPath)); }
    });
    var mini = root.querySelector("[data-gx-minimap]");
    if (mini) mini.addEventListener("click", function (e) {
      if (!S.mini) return;
      var r = mini.getBoundingClientRect();
      var x = ((e.clientX - r.left) * (mini.width / r.width) - S.mini.ox) / S.mini.scale;
      var y = ((e.clientY - r.top) * (mini.height / r.height) - S.mini.oy) / S.mini.scale;
      S.cy.animate({ pan: { x: S.cy.width() / 2 - x * S.cy.zoom(), y: S.cy.height() / 2 - y * S.cy.zoom() } }, { duration: reduced() ? 0 : 200 });
    });
    if (window.matchMedia && window.matchMedia("(max-width: 900px)").matches) root.classList.add("gx-filters-closed");
    loadScript("cytoscape")
      .then(fetchGraph)
      .then(function (data) {
        if (!data.nodes.length) { state("empty", "No findings yet. The graph fills in as scans report back."); return; }
        build(data);
      })
      .catch(function (err) { state("error", "The graph could not load (" + err.message + "). The Entities tab has the same data."); });
  }

  document.addEventListener("keydown", onKey);
  window.addEventListener("resize", function () { clearTimeout(window.__gxr); window.__gxr = setTimeout(function () { fitHeight(); drawMinimap(); }, 150); });
  document.body.addEventListener("entities-changed", function () { if (S && document.contains(S.root)) refresh(); });
  document.addEventListener("unmask:graph-select", function (e) {
    if (!S || !S.cy || !document.contains(S.root)) return;
    select(S.cy.getElementById(e.detail.id), true);
  });

  window.unmaskGraph = { init: init };
  init();
})();
