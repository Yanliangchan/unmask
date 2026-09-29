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
      qsa(box, ".tag").forEach(function (c) { c.remove(); });
      tags.forEach(function (tag, i) {
        var chip = document.createElement("span");
        chip.className = "tag";
        chip.textContent = tag;
        var x = document.createElement("button");
        x.type = "button";
        x.className = "tag-x";
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

  // --- Range outputs ----------------------------------------------------------
  document.addEventListener("input", function (e) {
    var el = e.target;
    if (el.dataset && el.dataset.output) {
      var out = document.querySelector(el.dataset.output);
      if (out) out.textContent = Number(el.value).toFixed(2);
    }
    if (el.dataset && el.dataset.outputInt) {
      var outInt = document.querySelector(el.dataset.outputInt);
      if (outInt) outInt.textContent = String(parseInt(el.value, 10));
    }
  });

  // --- Confirmations for destructive plain forms -------------------------------
  document.addEventListener("submit", function (e) {
    var form = e.target;
    if (form.dataset && form.dataset.confirm && !window.confirm(form.dataset.confirm)) e.preventDefault();
  });

  // --- Print button (report view) -----------------------------------------------
  document.addEventListener("click", function (e) {
    if (e.target.closest("[data-print]")) window.print();
  });

  // --- Toasts for failed htmx requests ---------------------------------------
  function toast(message, kind, undoUrl) {
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
    if (undoUrl && window.htmx) {
      var undo = document.createElement("button");
      undo.type = "button";
      undo.className = "toast-undo";
      undo.textContent = "Undo";
      undo.addEventListener("click", function () {
        el.remove();
        window.htmx.ajax("POST", undoUrl, { source: document.body, swap: "none" });
      });
      el.appendChild(undo);
    }
    el.appendChild(close);
    host.appendChild(el);
    setTimeout(function () { el.remove(); }, 8000);
  }
  window.unmaskToast = toast;
  // Server-sent notices arrive as an HX-Trigger "toast" event (script is deferred, so <body> exists).
  document.body.addEventListener("toast", function (e) { toast(e.detail.message, "info", e.detail.undo); });

  document.addEventListener("htmx:responseError", function (e) {
    var xhr = e.detail.xhr;
    toast("Request failed (" + xhr.status + "): " + (xhr.responseText || "").slice(0, 160), "error");
  });
  document.addEventListener("htmx:sendError", function () { toast("Network error — is the server reachable?", "error"); });

  // Links to /cases/<id>#ent-<entity> (e.g. from Timeline) open that entity once the table loads.
  var pendingFocus = null;
  function focusPending() {
    if (!pendingFocus) return;
    var body = document.getElementById("ent-" + pendingFocus);
    if (!body) return;
    var row = body.querySelector("[data-expand]");
    body.classList.add("is-focused");
    body.scrollIntoView({ block: "center" });
    if (row && row.getAttribute("aria-expanded") !== "true") toggleRow(row);
    pendingFocus = null;
  }
  document.addEventListener("htmx:afterSettle", focusPending);
  if (location.hash.indexOf("#ent-") === 0) pendingFocus = location.hash.slice(5);

  // "Evidence" links in the case summary open that row, switching to "All findings" if it's hidden.
  document.addEventListener("click", function (e) {
    var link = e.target.closest && e.target.closest("[data-focus-entity]");
    if (!link) return;
    e.preventDefault();
    pendingFocus = link.dataset.focusEntity;
    var select = document.getElementById("entity-show");
    if (document.getElementById("ent-" + pendingFocus) || !select) { focusPending(); return; }
    select.value = "all";
    select.dispatchEvent(new Event("change", { bubbles: true }));
  });

  // --- Menus: one open at a time; close on outside click, Escape, or picking an item ------------
  function closeMenus(except) {
    qsa(document, "details.menu[open]").forEach(function (m) { if (m !== except) m.removeAttribute("open"); });
  }
  document.addEventListener("toggle", function (e) {
    if (e.target.matches && e.target.matches("details.menu") && e.target.open) closeMenus(e.target);
  }, true);
  document.addEventListener("click", function (e) {
    var menu = e.target.closest("details.menu");
    if (!menu) { closeMenus(null); return; }
    if (e.target.closest(".menu-list a, .menu-list button")) menu.removeAttribute("open");
  });
  document.addEventListener("keydown", function (e) { if (e.key === "Escape") closeMenus(null); });

  // "Show evidence" in a row's menu opens that row's detail.
  document.addEventListener("click", function (e) {
    var btn = e.target.closest("[data-open-row]");
    if (!btn) return;
    var body = document.querySelector(btn.dataset.openRow);
    var row = body && body.querySelector("[data-expand]");
    if (row && row.getAttribute("aria-expanded") !== "true") toggleRow(row);
  });

  // Whole table rows that link somewhere (the case list).
  document.addEventListener("click", function (e) {
    var tr = e.target.closest("tr[data-href]");
    if (!tr || e.target.closest("a, button, input, select, label, summary")) return;
    if (e.metaKey || e.ctrlKey) { window.open(tr.dataset.href, "_blank"); return; }
    window.location.href = tr.dataset.href;
  });

  // Plain GET forms that should apply as soon as a select changes (Timeline compare).
  document.addEventListener("change", function (e) {
    var form = e.target.closest && e.target.closest("form[data-autosubmit]");
    if (form) form.submit();
  });

  function init(root) {
    qsa(root, "[data-tag-input]").forEach(initTagInput);
    qsa(root, "[data-require-gate]").forEach(function (f) {
      if (f.dataset.ready) return;
      f.dataset.ready = "1";
      initGate(f);
      initTargets(f);
    });
  }
  // "Show all" / "View" links under the entity table switch the Show filter.
  document.addEventListener("click", function (e) {
    var btn = e.target.closest && e.target.closest("[data-show]");
    var select = document.getElementById("entity-show");
    if (!btn || !select) return;
    select.value = btn.dataset.show;
    select.dispatchEvent(new Event("change", { bubbles: true }));
  });

  // "Run scan" stays disabled while the case already has a scan in progress.
  function syncRunButton() {
    var status = document.getElementById("scan-status");
    var active = status && status.dataset.active === "1";
    qsa(document, "[data-run-scan]").forEach(function (btn) {
      btn.disabled = active;
      btn.title = active ? "A scan is already running" : "";
    });
  }

  document.addEventListener("DOMContentLoaded", function () { init(document); syncRunButton(); });
  document.addEventListener("htmx:load", function (e) { init(e.detail.elt); });
  document.addEventListener("htmx:afterSettle", syncRunButton);
})();
