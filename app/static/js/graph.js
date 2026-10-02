// unmask — case relationship graph (Cytoscape, self-hosted).
(function () {
  "use strict";
  if (window.unmaskGraph) { window.unmaskGraph.init(); return; }

  // Shape per type, so type never depends on colour alone; colours are theme tokens (--t-<type>).
  var TYPES = {
    username: { shape: "ellipse", label: "Username" },
    email: { shape: "round-rectangle", label: "Email" },
    account: { shape: "round-rectangle", label: "Account" },
    registration: { shape: "round-tag", label: "Registration" },
    breach: { shape: "octagon", label: "Breach" },
    name: { shape: "round-diamond", label: "Name" },
    domain: { shape: "round-hexagon", label: "Domain" },
    hostname: { shape: "hexagon", label: "Hostname" },
    ip: { shape: "round-pentagon", label: "IP address" },
    phone: { shape: "vee", label: "Phone" },
    web_mention: { shape: "round-triangle", label: "Web mention" },
    image: { shape: "star", label: "Image" },
    other: { shape: "barrel", label: "Other" }
  };
  function typeKey(t) { return TYPES[t] ? t : "other"; }
  // Rings from the subject outwards in the radial layout.
  var RANK = { target: 6, confirmed: 5, likely: 4, possible: 3, unlikely: 2, unchecked: 1 };
  var LABEL_ZOOM = 1.25;

  var cy = null;
  var focus = null;      // focus mode: only these node ids are shown
  var layoutName = "radial";
  var showAll = false;
  var scriptPromise = null;
  var current = document.currentScript;
  var cytoscapeSrc = (current && current.dataset.cytoscape) || "/static/js/vendor/cytoscape.min.js";

  function loadCytoscape() {
    if (window.cytoscape) return Promise.resolve();
    if (!scriptPromise) {
      scriptPromise = new Promise(function (resolve, reject) {
        var s = document.createElement("script");
        s.src = cytoscapeSrc;
        s.onload = resolve;
        s.onerror = function () { reject(new Error("could not load the graph library")); };
        document.head.appendChild(s);
      });
    }
    return scriptPromise;
  }

  function reduced() { return window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches; }

  function palette() {
    var css = getComputedStyle(document.documentElement);
    var v = function (name) { return css.getPropertyValue(name).trim(); };
    var types = {};
    Object.keys(TYPES).forEach(function (t) { types[t] = v("--t-" + t) || "#888"; });
    return { text: v("--text"), strong: v("--text-strong"), muted: v("--muted"), faint: v("--faint"),
             sunk: v("--bg-sunk"), elev: v("--bg-elev"), line: v("--border-strong"), border: v("--border"),
             accent: v("--accent"), ok: v("--ok"), warn: v("--warn"), font: v("--font") || "sans-serif", types: types };
  }

  function size(n) {
    if (n.data("seed")) return 58;
    return Math.round(20 + 28 * n.data("confidence") + 10 * n.data("centrality"));
  }

  function style() {
    var c = palette();
    var typeColor = function (n) { return c.types[typeKey(n.data("type"))]; };
    return [
      { selector: "node", style: {
        "background-color": typeColor, "shape": function (n) { return TYPES[typeKey(n.data("type"))].shape; },
        "width": size, "height": size,
        "border-width": 2, "border-color": c.sunk,
        "label": "data(short)", "font-family": c.font, "font-size": 11, "font-weight": 500, "color": c.strong,
        "text-valign": "bottom", "text-margin-y": 6, "text-wrap": "ellipsis", "text-max-width": 160,
        "text-background-color": c.elev, "text-background-opacity": 0.92, "text-background-padding": 3,
        "text-background-shape": "roundrectangle", "text-border-color": c.border, "text-border-width": 1, "text-border-opacity": 1,
        "text-opacity": 0, "text-events": "no",
        "transition-property": "opacity, border-width", "transition-duration": reduced() ? 0 : 150
      } },
      { selector: "node.labeled, node.hl, node:selected", style: { "text-opacity": 1 } },
      { selector: "node[strength = 'possible']", style: { "border-color": typeColor, "border-style": "dashed", "border-width": 2, "background-opacity": 0.85 } },
      { selector: "node[strength = 'unlikely'], node[strength = 'unchecked']", style: { "background-opacity": 0.45, "border-color": typeColor, "border-style": "dotted", "border-width": 1.5 } },
      { selector: "node[?confirmed]", style: { "border-width": 4, "border-style": "solid", "border-color": c.ok, "background-opacity": 1 } },
      { selector: "node[?seed]", style: { "border-width": 6, "border-style": "double", "border-color": c.accent, "font-size": 12.5, "font-weight": 600 } },
      { selector: "node:selected", style: { "overlay-color": c.accent, "overlay-opacity": 0.18, "overlay-padding": 6 } },
      { selector: "edge", style: {
        "width": 1, "line-color": c.line, "curve-style": "bezier", "target-arrow-shape": "none", "opacity": 0.8,
        "font-family": c.font, "font-size": 10.5, "color": c.text, "text-rotation": "autorotate",
        "text-background-color": c.elev, "text-background-opacity": 0.95, "text-background-padding": 3,
        "text-background-shape": "roundrectangle", "text-opacity": 0, "text-wrap": "ellipsis", "text-max-width": 220,
        "label": "data(tip)", "transition-property": "opacity, width, line-color", "transition-duration": reduced() ? 0 : 150
      } },
      { selector: "edge[kind = 'strong']", style: {
        "line-color": c.accent, "target-arrow-color": c.accent, "target-arrow-shape": "triangle", "arrow-scale": 0.8,
        "width": function (e) { return 1.5 + 2.5 * (e.data("confidence") || 0.5); }, "opacity": 0.9
      } },
      { selector: "edge[kind = 'suggested']", style: { "line-style": "dashed", "line-dash-pattern": [6, 4], "line-color": c.warn, "width": 1.6 } },
      { selector: "edge.hl", style: { "opacity": 1, "width": function (e) { return e.data("kind") === "strong" ? 3.5 : 2; } } },
      { selector: "edge.hover, edge:selected", style: { "text-opacity": 1, "opacity": 1, "z-index": 10 } },
      { selector: ".faded", style: { "opacity": 0.12, "text-opacity": 0 } },
      { selector: ".hidden", style: { "display": "none" } }
    ];
  }

  function layoutOptions(eles) {
    var anim = !reduced();
    if (layoutName === "force") {
      return { name: "cose", animate: anim, animationDuration: 500, nodeRepulsion: 12000, idealEdgeLength: 110,
               edgeElasticity: 120, gravity: 0.25, padding: 40, randomize: false, nodeDimensionsIncludeLabels: true,
               componentSpacing: 120, numIter: 1500, eles: eles };
    }
    // Radial: targets in the middle, findings around them in rings by strength (see radialPositions).
    var pos = radialPositions(eles.nodes());
    return { name: "preset", animate: anim, animationDuration: 450, padding: 40, fit: true, eles: eles,
             positions: function (n) { return pos[n.id()]; } };
  }

  // Every finding gets its own angle (so labels don't stack), grouped by the target it was
  // found from; its distance from the centre says how strong it is.
  function radialPositions(nodes) {
    var pos = {};
    var seeds = nodes.filter(function (n) { return n.data("seed"); });
    var rest = nodes.filter(function (n) { return !n.data("seed"); });
    var seedIndex = {};
    seeds.forEach(function (n, i) {
      seedIndex[n.id()] = i;
      var a = (2 * Math.PI * i) / Math.max(1, seeds.length) - Math.PI / 2;
      var r = seeds.length > 1 ? 45 + 12 * seeds.length : 0;
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
    var inner = seeds.length > 1 ? 190 : 150;
    var step = Math.max(80, Math.min(130, 22 * count / Math.max(1, ranks.length)));
    sorted.forEach(function (item, i) {
      var ring = ranks.indexOf(item.k);
      var a = (2 * Math.PI * i) / Math.max(1, count) - Math.PI / 2;
      // Alternate slightly in and out so neighbours on the same ring keep their labels apart.
      var r = inner + ring * step + (count > 10 ? (i % 2) * 26 : 0);
      pos[item.n.id()] = { x: r * Math.cos(a), y: r * Math.sin(a) };
    });
    return pos;
  }

  function relayout() {
    if (!cy) return;
    var visible = cy.elements().not(".hidden");
    var l = visible.layout(layoutOptions(visible));
    l.one("layoutstop", function () { if (cy.zoom() > 1.15) { cy.zoom(1.15); cy.center(visible); } updateLabels(); });
    l.run();
  }

  // Labels: always for targets, confirmed and the most central findings; others on hover, selection or zoom.
  function updateLabels() {
    if (!cy) return;
    var zoomed = cy.zoom() >= LABEL_ZOOM;
    var nodes = cy.nodes();
    var top = nodes.filter(function (n) { return !n.data("seed") && !n.data("confirmed"); })
      .sort(function (a, b) { return b.data("centrality") - a.data("centrality"); }).slice(0, 8);
    var keep = {};
    top.forEach(function (n) { keep[n.id()] = true; });
    cy.batch(function () {
      nodes.forEach(function (n) {
        n.toggleClass("labeled", zoomed || nodes.length <= 14 || n.data("seed") || n.data("confirmed") || !!keep[n.id()]);
      });
    });
  }

  function renderLegend(root) {
    var list = root.querySelector("[data-graph-legend]");
    if (!list || !cy) return;
    var present = {};
    cy.nodes().forEach(function (n) { present[typeKey(n.data("type"))] = true; });
    list.innerHTML = "";
    Object.keys(TYPES).forEach(function (t) {
      if (!present[t]) return;
      var li = document.createElement("li");
      li.className = "legend-item";
      var swatch = document.createElement("span");
      swatch.className = "legend-swatch shape-" + TYPES[t].shape;
      swatch.style.backgroundColor = "var(--t-" + t + ")";
      swatch.setAttribute("aria-hidden", "true");
      li.appendChild(swatch);
      li.appendChild(document.createTextNode(TYPES[t].label));
      list.appendChild(li);
    });
  }

  function fillSearch(root) {
    var list = root.querySelector("#graph-find-list");
    if (!list || !cy) return;
    list.innerHTML = "";
    cy.nodes().forEach(function (n) {
      var o = document.createElement("option");
      o.value = n.data("value");
      list.appendChild(o);
    });
  }

  function findNode(query) {
    var q = (query || "").trim().toLowerCase();
    if (!q || !cy) return null;
    var exact = cy.nodes().filter(function (n) { return String(n.data("value")).toLowerCase() === q; });
    if (exact.length) return exact[0];
    var part = cy.nodes().filter(function (n) {
      return String(n.data("value")).toLowerCase().indexOf(q) !== -1 || String(n.data("site") || "").toLowerCase().indexOf(q) !== -1;
    });
    return part.length ? part[0] : null;
  }

  function stats(root, data) {
    var el = root.querySelector("[data-graph-stats]");
    if (!el || !cy) return;
    var shown = cy.nodes().not(".hidden").length;
    el.textContent = shown + " of " + cy.nodes().length + " findings shown" + (focus ? " · focus: select a node to expand it" : "");
    var hidden = data && data.hidden;
    if (hidden && !showAll) {
      var more = document.createElement("button");
      more.type = "button";
      more.className = "link-btn";
      more.dataset.graphAll = "1";
      more.textContent = "Show " + hidden + " weaker finding" + (hidden === 1 ? "" : "s");
      el.appendChild(document.createTextNode(" · "));
      el.appendChild(more);
    }
    var exit = root.querySelector("[data-graph-unfocus]");
    if (exit) exit.hidden = !focus;
  }

  var lastData = null;
  function applyFilters(root, opts) {
    if (!cy) return;
    var on = function (k) { var el = root.querySelector('[data-graph-filter="' + k + '"]'); return el && el.checked; };
    cy.batch(function () {
      cy.elements().removeClass("hidden");
      if (on("confirmed")) cy.nodes().filter(function (n) { return !n.data("confirmed") && !n.data("seed"); }).addClass("hidden");
      if (on("weak")) cy.nodes().filter(function (n) { return n.data("strength") === "unlikely" || n.data("strength") === "unchecked"; }).addClass("hidden");
      if (on("pivot")) cy.nodes().filter(function (n) { return !n.data("pivot") && !n.data("seed"); }).addClass("hidden");
      if (!on("suggested")) cy.edges("[kind = 'suggested']").addClass("hidden");
      if (focus) cy.nodes().filter(function (n) { return !focus[n.id()]; }).addClass("hidden");
      cy.edges().filter(function (e) { return e.source().hasClass("hidden") || e.target().hasClass("hidden"); }).addClass("hidden");
    });
    stats(root, lastData);
    if (!opts || opts.layout !== false) relayout();
  }

  function expand(root, node) {
    if (!focus) focus = {};
    node.closedNeighborhood("node").forEach(function (n) { focus[n.id()] = true; });
    applyFilters(root);
  }

  function exportPng(root) {
    if (!cy) return;
    var bg = getComputedStyle(document.documentElement).getPropertyValue("--bg-sunk").trim() || "#ffffff";
    cy.nodes().addClass("labeled");
    var url = cy.png({ full: true, scale: 2, bg: bg, output: "base64uri" });
    updateLabels();
    var a = document.createElement("a");
    a.href = url;
    a.download = (root.dataset.caseName || "case").replace(/[^\w.-]+/g, "-").slice(0, 60) + "-graph.png";
    document.body.appendChild(a);
    a.click();
    a.remove();
  }

  function openPanel(root, node) {
    var panel = root.querySelector("[data-graph-panel]");
    panel.hidden = false;
    panel.dataset.node = node.id();
    var t = TYPES[typeKey(node.data("type"))].label;
    panel.querySelector("[data-graph-panel-title]").textContent = t + (node.data("site") ? " · " + node.data("site") : "");
    window.htmx.ajax("GET", "/cases/" + root.dataset.case + "/entities/" + node.id() + "?panel=1",
      { target: "#graph-panel-body", swap: "innerHTML" });
  }

  function selectNode(root, node) {
    if (!node) return;
    cy.nodes().unselect();
    node.removeClass("hidden").select();
    openPanel(root, node);
    // Centre it in the part of the canvas the panel leaves visible.
    var panel = root.querySelector("[data-graph-panel]");
    var cover = panel && !panel.hidden ? panel.offsetWidth + 10 : 0;
    var zoom = Math.max(cy.zoom(), 1.1);
    var p = node.position();
    cy.animate({ zoom: zoom, pan: { x: (cy.width() - cover) / 2 - p.x * zoom, y: cy.height() / 2 - p.y * zoom } },
               { duration: reduced() ? 0 : 300 });
  }

  // Hover: light up a node's neighbourhood and fade the rest.
  function highlight(node) {
    cy.batch(function () {
      cy.elements().addClass("faded");
      var hood = node.closedNeighborhood();
      hood.removeClass("faded").addClass("hl");
    });
  }
  function unhighlight() { cy.batch(function () { cy.elements().removeClass("faded hl"); }); }

  function prepare(data) {
    data.nodes.forEach(function (n) {
      var t = String(n.value).replace(/^https?:\/\/(www\.)?/i, "").replace(/\/$/, "");
      n.short = t.length > 30 ? t.slice(0, 29) + "…" : t;
    });
    data.edges.forEach(function (e) {
      var t = e.why || e.label;
      e.tip = t.length > 90 ? t.slice(0, 89) + "…" : t;
    });
    return data;
  }

  function build(root, data) {
    lastData = data;
    var container = root.querySelector("#cy");
    var elements = data.nodes.map(function (n) { return { group: "nodes", data: n }; })
      .concat(data.edges.map(function (e) { return { group: "edges", data: e }; }));
    if (cy) cy.destroy();
    cy = window.cytoscape({ container: container, elements: elements, style: style(), wheelSensitivity: 0.3,
                            minZoom: 0.15, maxZoom: 3, layout: { name: "preset" }, selectionType: "single" });
    var tip = root.querySelector("[data-graph-tip]");
    cy.on("mouseover", "node", function (e) { highlight(e.target); });
    cy.on("mouseout", "node", unhighlight);
    cy.on("mouseover", "edge", function (e) {
      e.target.addClass("hover");
      if (tip && e.target.data("why")) {
        tip.textContent = e.target.data("why");
        tip.hidden = false;
        var p = e.renderedPosition || e.target.renderedMidpoint();
        tip.style.left = Math.round(p.x + 12) + "px";
        tip.style.top = Math.round(p.y + 12) + "px";
      }
    });
    cy.on("mouseout", "edge", function (e) { e.target.removeClass("hover"); if (tip) tip.hidden = true; });
    cy.on("zoom", updateLabels);
    cy.on("tap", "node", function (e) {
      openPanel(root, e.target);
      var mode = root.querySelector("[data-graph-focus]");
      if (focus || (mode && mode.checked)) expand(root, e.target);
    });
    cy.on("tap", function (e) { if (e.target === cy) { root.querySelector("[data-graph-panel]").hidden = true; } });
    renderLegend(root);
    fillSearch(root);
    applyFilters(root);
  }

  // After a decision in the panel: refresh node states in place and reload the panel.
  function refresh(root) {
    if (!cy) return;
    load(root).then(function (data) {
      var byId = {};
      data.nodes.forEach(function (n) { byId[n.id] = n; });
      cy.batch(function () {
        cy.nodes().forEach(function (n) {
          var d = byId[n.id()];
          if (!d) { n.remove(); return; }
          n.data(d);
        });
      });
      lastData = data;
      updateLabels();
      stats(root, data);
      var panel = root.querySelector("[data-graph-panel]");
      var node = panel && !panel.hidden && cy.getElementById(panel.dataset.node);
      if (node && node.length) openPanel(root, node);
      else if (panel) panel.hidden = true;
    });
  }

  function restyle() { if (cy) cy.style(style()); }
  document.addEventListener("unmask:theme", restyle);
  if (window.matchMedia) {
    var mq = window.matchMedia("(prefers-color-scheme: dark)");
    if (mq.addEventListener) mq.addEventListener("change", restyle);
  }

  function load(root) {
    var url = root.dataset.graph + (showAll ? "?all=1" : "");
    return fetch(url, { credentials: "same-origin" })
      .then(function (r) { if (!r.ok) throw new Error("HTTP " + r.status); return r.json(); })
      .then(prepare);
  }

  function setLayout(root, name) {
    layoutName = name;
    root.querySelectorAll("[data-graph-layout]").forEach(function (b) { b.setAttribute("aria-pressed", String(b.dataset.graphLayout === name)); });
    relayout();
  }

  function init() {
    var root = document.querySelector("[data-graph]");
    focus = null;
    showAll = false;
    if (!root || root.dataset.ready) return;
    root.dataset.ready = "1";
    var statsEl = root.querySelector("[data-graph-stats]");

    root.addEventListener("change", function (e) { if (e.target.matches("[data-graph-filter]")) applyFilters(root); });
    var find = root.querySelector("[data-graph-find]");
    if (find) {
      var go = function () { var n = findNode(find.value); if (n) selectNode(root, n); else if (find.value) find.setCustomValidity("No finding matches"); };
      // Picking a suggestion from the list jumps straight to it.
      find.addEventListener("input", function () {
        find.setCustomValidity("");
        if (cy && cy.nodes().some(function (n) { return n.data("value") === find.value; })) go();
      });
      find.addEventListener("keydown", function (e) { if (e.key === "Enter") { e.preventDefault(); go(); find.reportValidity(); } });
    }
    root.addEventListener("click", function (e) {
      var lay = e.target.closest("[data-graph-layout]");
      if (lay) setLayout(root, lay.dataset.graphLayout);
      var z = e.target.closest("[data-graph-zoom]");
      if (z && cy) cy.animate({ zoom: { level: cy.zoom() * (z.dataset.graphZoom === "in" ? 1.3 : 1 / 1.3), renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } } }, { duration: reduced() ? 0 : 150 });
      if (e.target.closest("[data-graph-reset]") || e.target.closest("[data-graph-unfocus]")) {
        focus = null;
        if (e.target.closest("[data-graph-reset]")) {
          root.querySelectorAll("[data-graph-filter]").forEach(function (el) { el.checked = el.dataset.graphFilter === "suggested"; });
          var mode = root.querySelector("[data-graph-focus]");
          if (mode) mode.checked = false;
        }
        applyFilters(root);
      }
      if (e.target.closest("[data-graph-all]")) {
        showAll = true;
        load(root).then(function (data) { build(root, data); });
      }
      if (e.target.closest("[data-graph-png]")) exportPng(root);
      if (e.target.closest("[data-graph-panel-close]")) root.querySelector("[data-graph-panel]").hidden = true;
    });
    document.body.addEventListener("entities-changed", function () { if (document.contains(root)) refresh(root); });
    document.addEventListener("unmask:graph-select", function (e) {
      if (!cy || !document.contains(root)) return;
      selectNode(root, cy.getElementById(e.detail.id).length ? cy.getElementById(e.detail.id) : null);
    });
    loadCytoscape()
      .then(function () { return load(root); })
      .then(function (data) {
        if (!data.nodes.length) { statsEl.textContent = "No findings yet."; return; }
        build(root, data);
      })
      .catch(function (err) {
        statsEl.textContent = "Graph unavailable: " + err.message;
        if (window.unmaskToast) window.unmaskToast("Graph unavailable: " + err.message, "error");
      });
  }

  window.unmaskGraph = { init: init };
  init();
})();
