// unmask — small progressive enhancements on top of htmx.
(function () {
  "use strict";

  function qsa(root, sel) { return Array.prototype.slice.call(root.querySelectorAll(sel)); }

  // --- Tag input: comma/enter turns text into chips -------------------------
  function initTagInput(box) {
    if (box.dataset.ready) return;
    box.dataset.ready = "1";
    var hidden = box.querySelector('input[type="hidden"]');
    var entry = box.querySelector(".tag-entry");
    var tags = (hidden.value || "").split(",").map(function (t) { return t.trim(); }).filter(Boolean);

    function sync() {
      hidden.value = tags.join(",");
      qsa(box, ".chip").forEach(function (c) { c.remove(); });
      tags.forEach(function (tag, i) {
        var chip = document.createElement("span");
        chip.className = "chip";
        chip.textContent = tag;
        var x = document.createElement("button");
        x.type = "button";
        x.className = "chip-x";
        x.setAttribute("aria-label", "Remove tag " + tag);
        x.textContent = "×";
        x.addEventListener("click", function () { tags.splice(i, 1); sync(); entry.focus(); });
        chip.appendChild(x);
        box.insertBefore(chip, entry);
      });
    }

    function commit() {
      entry.value.split(",").forEach(function (raw) {
        var t = raw.trim();
        if (t && tags.map(function (x) { return x.toLowerCase(); }).indexOf(t.toLowerCase()) === -1) tags.push(t);
      });
      entry.value = "";
      sync();
    }

    entry.addEventListener("keydown", function (e) {
      if (e.key === "," || e.key === "Enter") { e.preventDefault(); commit(); }
      else if (e.key === "Backspace" && !entry.value && tags.length) { tags.pop(); sync(); }
    });
    entry.addEventListener("blur", commit);
    box.addEventListener("click", function (e) { if (e.target === box) entry.focus(); });
    sync();
  }

  // --- Case form: hard gate on authorization note + lawful basis ------------
  function initGate(form) {
    var submit = form.querySelector("[data-gated-submit]");
    var hint = form.querySelector("[data-gate-hint]");
    var gates = qsa(form, "[data-gate]");
    function check() {
      var ok = gates.every(function (el) {
        return el.type === "checkbox" ? el.checked : el.value.trim().length > 0;
      });
      submit.disabled = !ok;
      if (hint) hint.hidden = ok;
    }
    gates.forEach(function (el) { el.addEventListener("input", check); el.addEventListener("change", check); });
    form.addEventListener("submit", function (e) { check(); if (submit.disabled) e.preventDefault(); });
    check();
  }

  function initTargets(form) {
    var rows = form.querySelector("#target-rows");
    var tpl = document.getElementById("target-row-template");
    var add = form.querySelector("[data-add-target]");
    if (!rows || !tpl || !add) return;
    add.addEventListener("click", function () {
      var node = tpl.content.firstElementChild.cloneNode(true);
      rows.appendChild(node);
      qsa(node, "[data-tag-input]").forEach(initTagInput);
      node.querySelector('input[name="target_value"]').focus();
    });
    rows.addEventListener("click", function (e) {
      var btn = e.target.closest("[data-remove-target]");
      if (!btn) return;
      var all = qsa(rows, ".target-row");
      if (all.length > 1) btn.closest(".target-row").remove();
      else qsa(all[0], "input").forEach(function (i) { i.value = ""; });
    });
  }

  // --- Entity row expand ----------------------------------------------------
  function toggleRow(row) {
    var detail = document.querySelector(row.dataset.expand);
    if (!detail) return;
    var open = detail.hidden;
    detail.hidden = !open;
    row.setAttribute("aria-expanded", open ? "true" : "false");
    if (open && window.htmx) window.htmx.trigger(row, "expand");
  }

  // "Merge with…" reveals its picker row; Cancel hides it again.
  document.addEventListener("click", function (e) {
    var reveal = e.target.closest("[data-reveal]");
    if (reveal) { var r = document.querySelector(reveal.dataset.reveal); if (r) r.hidden = false; }
    var hide = e.target.closest("[data-hide]");
    if (hide) { var h = document.querySelector(hide.dataset.hide); if (h) h.hidden = true; }
  });

  document.addEventListener("click", function (e) {
    if (e.target.closest("[data-stop], a, button, input, select, label")) {
      var toast = e.target.closest("[data-dismiss-toast]");
      if (toast) toast.closest(".toast").remove();
      return;
    }
    var row = e.target.closest("[data-expand]");
    if (row) toggleRow(row);
  });
  document.addEventListener("keydown", function (e) {
    var row = e.target.closest && e.target.closest("[data-expand]");
    if (row && (e.key === "Enter" || e.key === " ") && e.target === row) { e.preventDefault(); toggleRow(row); }
  });

  // --- Tabs -----------------------------------------------------------------
  document.addEventListener("click", function (e) {
    var tab = e.target.closest("[data-tab]");
    if (!tab) return;
    qsa(tab.parentElement, "[data-tab]").forEach(function (t) { t.setAttribute("aria-selected", t === tab ? "true" : "false"); });
    var panel = document.getElementById("tab-panel");
    if (panel) panel.setAttribute("aria-labelledby", tab.id);
  });

  // --- Range outputs ----------------------------------------------------------
  document.addEventListener("input", function (e) {
    var el = e.target;
    if (el.dataset && el.dataset.output) {
      var out = document.querySelector(el.dataset.output);
      if (out) out.textContent = Number(el.value).toFixed(2);
    }
  });

  // --- Toasts for failed htmx requests ---------------------------------------
  function toast(message, kind) {
    var host = document.getElementById("toasts");
    if (!host) return;
    var el = document.createElement("div");
    el.className = "toast toast-" + (kind || "info");
    el.setAttribute("role", "status");
    var span = document.createElement("span");
    span.textContent = message;
    var close = document.createElement("button");
    close.type = "button";
    close.className = "toast-close";
    close.setAttribute("aria-label", "Dismiss");
    close.setAttribute("data-dismiss-toast", "");
    close.textContent = "×";
    el.appendChild(span);
    el.appendChild(close);
    host.appendChild(el);
    setTimeout(function () { el.remove(); }, 8000);
  }
  window.unmaskToast = toast;
  // Server-sent notices arrive as an HX-Trigger "toast" event (script is deferred, so <body> exists).
  document.body.addEventListener("toast", function (e) { toast(e.detail.message); });

  document.addEventListener("htmx:responseError", function (e) {
    var xhr = e.detail.xhr;
    toast("Request failed (" + xhr.status + "): " + (xhr.responseText || "").slice(0, 160), "error");
  });
  document.addEventListener("htmx:sendError", function () { toast("Network error — is the server reachable?", "error"); });

  function init(root) {
    qsa(root, "[data-tag-input]").forEach(initTagInput);
    qsa(root, "[data-require-gate]").forEach(function (f) {
      if (f.dataset.ready) return;
      f.dataset.ready = "1";
      initGate(f);
      initTargets(f);
    });
  }
  document.addEventListener("DOMContentLoaded", function () { init(document); });
  document.addEventListener("htmx:load", function (e) { init(e.detail.elt); });
})();
