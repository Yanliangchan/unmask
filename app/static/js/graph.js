// unmask — case relationship graph (Cytoscape, self-hosted).
(function () {
  "use strict";
  if (window.unmaskGraph) { window.unmaskGraph.init(); return; }

  // Colour AND shape per type, so type never depends on colour alone.
  var TYPES = {
    username: { color: "#5eb1ff", shape: "ellipse", label: "Username" },
    email: { color: "#f0a35e", shape: "round-rectangle", label: "Email" },
    account: { color: "#9d8cff", shape: "rectangle", label: "Account" },
    registration: { color: "#c792ea", shape: "tag", label: "Registration" },
    breach: { color: "#ef5d5d", shape: "octagon", label: "Breach" },
    name: { color: "#3fbf7f", shape: "diamond", label: "Name" },
    domain: { color: "#e0c341", shape: "hexagon", label: "Domain" },
    hostname: { color: "#63c5b8", shape: "round-hexagon", label: "Hostname" },
    ip: { color: "#a3adbd", shape: "pentagon", label: "IP address" },
    phone: { color: "#f78fb3", shape: "vee", label: "Phone" },
    other: { color: "#b0b8c4", shape: "barrel", label: "Other" }
  };
  function typeOf(t) { return TYPES[t] || TYPES.other; }

  var cy = null;
  var scriptPromise = null;

  function loadCytoscape() {
    if (window.cytoscape) return Promise.resolve();
    if (!scriptPromise) {
      scriptPromise = new Promise(function (resolve, reject) {
        var s = document.createElement("script");
        s.src = "/static/js/vendor/cytoscape.min.js";
        s.onload = resolve;
        s.onerror = function () { reject(new Error("could not load the graph library")); };
        document.head.appendChild(s);
      });
    }
    return scriptPromise;
  }

  function style() {
    var reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    return {
      reduce: reduce,
      sheet: [
        { selector: "node", style: {
          "background-color": function (n) { return typeOf(n.data("type")).color; },
          "shape": function (n) { return typeOf(n.data("type")).shape; },
          "width": function (n) { return 18 + 42 * n.data("centrality"); },
          "height": function (n) { return 18 + 42 * n.data("centrality"); },
          "label": "data(label)", "color": "#d7dde6", "font-size": 9, "font-family": "ui-monospace, monospace",
          "text-valign": "bottom", "text-margin-y": 4, "text-outline-color": "#0b0e13", "text-outline-width": 2,
          "border-width": 1, "border-color": "#0b0e13"
        } },
        { selector: "node[?pivot]", style: { "border-width": 2, "border-style": "dashed", "border-color": "#d7dde6" } },
        { selector: "node[?seed]", style: { "border-width": 4, "border-style": "double", "border-color": "#f2f5f9" } },
        { selector: "node[?confirmed]", style: { "border-width": 4, "border-style": "solid", "border-color": "#3fbf7f" } },
        { selector: "node:selected", style: { "overlay-color": "#5eb1ff", "overlay-opacity": 0.25 } },
        { selector: "edge", style: {
          "width": 1.2, "line-color": "#2f3847", "curve-style": "bezier", "target-arrow-shape": "none",
          "font-size": 8, "color": "#8591a3", "text-rotation": "autorotate", "text-background-color": "#0b0e13",
          "text-background-opacity": 1, "text-background-padding": 2
        } },
        { selector: "edge[?suggested]", style: { "line-style": "dashed", "line-color": "#e0a43a", "width": 1.5 } },
        { selector: "edge.hover, edge:selected", style: { "label": "data(label)", "line-color": "#5eb1ff", "width": 2 } },
        { selector: ".hidden", style: { "display": "none" } }
      ]
    };
  }

  function renderLegend(root, nodes) {
    var list = root.querySelector("[data-graph-legend]");
    if (!list) return;
    var present = {};
    nodes.forEach(function (n) { present[n.data.type in TYPES ? n.data.type : "other"] = true; });
    list.innerHTML = "";
    Object.keys(TYPES).forEach(function (t) {
      if (!present[t]) return;
      var li = document.createElement("li");
      li.className = "legend-item";
      var swatch = document.createElement("span");
      swatch.className = "legend-swatch shape-" + TYPES[t].shape;
      swatch.style.backgroundColor = TYPES[t].color;
      swatch.setAttribute("aria-hidden", "true");
      li.appendChild(swatch);
      li.appendChild(document.createTextNode(TYPES[t].label));
      list.appendChild(li);
    });
  }

  function applyFilters(root) {
    if (!cy) return;
    var only = function (k) { var el = root.querySelector('[data-graph-filter="' + k + '"]'); return el && el.checked; };
    cy.batch(function () {
      cy.elements().removeClass("hidden");
      if (only("confirmed")) cy.nodes().filter(function (n) { return !n.data("confirmed") && !n.data("seed"); }).addClass("hidden");
      if (only("pivot")) cy.nodes().filter(function (n) { return !n.data("pivot"); }).addClass("hidden");
      if (!only("suggested")) cy.edges("[?suggested]").addClass("hidden");
      cy.edges().filter(function (e) { return e.source().hasClass("hidden") || e.target().hasClass("hidden"); }).addClass("hidden");
    });
    var shown = cy.nodes().not(".hidden").length;
    var stats = root.querySelector("[data-graph-stats]");
    if (stats) stats.textContent = shown + " of " + cy.nodes().length + " entities shown";
  }

  function openPanel(root, node) {
    var panel = root.querySelector("[data-graph-panel]");
    panel.hidden = false;
    panel.querySelector("[data-graph-panel-title]").textContent = node.data("value");
    window.htmx.ajax("GET", "/cases/" + root.dataset.case + "/entities/" + node.id(), { target: "#graph-panel-body", swap: "innerHTML" });
  }

  function build(root, data) {
    var container = root.querySelector("#cy");
    var elements = data.nodes.map(function (n) { return { group: "nodes", data: n }; })
      .concat(data.edges.map(function (e) { return { group: "edges", data: e }; }));
    var st = style();
    if (cy) cy.destroy();
    cy = window.cytoscape({
      container: container, elements: elements, style: st.sheet, wheelSensitivity: 0.3, minZoom: 0.1, maxZoom: 3,
      layout: { name: "cose", animate: !st.reduce, nodeRepulsion: 9000, idealEdgeLength: 90, padding: 30, randomize: false, nodeDimensionsIncludeLabels: true, componentSpacing: 60 }
    });
    // Small cases would otherwise be blown up to fill the canvas.
    cy.one("layoutstop", function () { if (cy.zoom() > 1.1) { cy.zoom(1.1); cy.center(); } });
    cy.on("mouseover", "edge", function (e) { e.target.addClass("hover"); });
    cy.on("mouseout", "edge", function (e) { e.target.removeClass("hover"); });
    cy.on("tap", "node", function (e) { openPanel(root, e.target); });
    renderLegend(root, elements.filter(function (el) { return el.group === "nodes"; }));
    applyFilters(root);
  }

  function init() {
    var root = document.querySelector("[data-graph]");
    if (!root || root.dataset.ready) return;
    root.dataset.ready = "1";
    root.addEventListener("change", function (e) { if (e.target.matches("[data-graph-filter]")) applyFilters(root); });
    root.addEventListener("click", function (e) {
      if (e.target.closest("[data-graph-reset]")) {
        root.querySelectorAll("[data-graph-filter]").forEach(function (el) { el.checked = el.dataset.graphFilter === "suggested"; });
        applyFilters(root);
        if (cy) cy.fit(undefined, 30);
      }
      if (e.target.closest("[data-graph-panel-close]")) root.querySelector("[data-graph-panel]").hidden = true;
    });
    var stats = root.querySelector("[data-graph-stats]");
    loadCytoscape()
      .then(function () { return fetch(root.dataset.graph, { credentials: "same-origin" }); })
      .then(function (r) { if (!r.ok) throw new Error("HTTP " + r.status); return r.json(); })
      .then(function (data) {
        if (!data.nodes.length) { stats.textContent = "No entities yet."; return; }
        build(root, data);
      })
      .catch(function (err) {
        stats.textContent = "Graph unavailable: " + err.message;
        if (window.unmaskToast) window.unmaskToast("Graph unavailable: " + err.message, "error");
      });
  }

  window.unmaskGraph = { init: init };
  init();
})();
