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

  // Same rules as app/identifiers.py guess_type, so rows match what the server would decide.
  function guessType(v) {
    v = v.trim();
    if (/^[^@\s]+@[^@\s]+\.[a-z]{2,}$/i.test(v)) return "email";
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(v) || (/^[0-9a-f:]+$/i.test(v) && v.indexOf("::") !== -1)) return "ip";
    if (/^\+?[\d\s().\-]{7,}$/.test(v) && (v.match(/\d/g) || []).length >= 7) return "phone";
    if (/^https?:\/\//i.test(v)) return "domain";
    if (/^([a-z0-9-]+\.)+[a-z]{2,}$/i.test(v)) return "domain";
    return v.indexOf(" ") !== -1 ? "name" : "username";
  }

  function initTargets(form) {
    var rows = form.querySelector("#target-rows");
    var tpl = document.getElementById("target-row-template");
    var add = form.querySelector("[data-add-target]");
    if (!rows || !tpl || !add) return;
    function addRow(value, type) {
      var node = tpl.content.firstElementChild.cloneNode(true);
      rows.appendChild(node);
      qsa(node, "[data-tag-input]").forEach(initTagInput);
      if (type) node.querySelector('select[name="target_type"]').value = type;
      if (value) node.querySelector('input[name="target_value"]').value = value;
      return node;
    }
    add.addEventListener("click", function () {
      addRow().querySelector('input[name="target_value"]').focus();
    });

    // Pasted lines become rows; the first empty row is reused.
    var paste = form.querySelector("[data-paste-targets]");
    function takePaste() {
      if (!paste || !paste.value.trim()) return;
      var have = qsa(rows, 'input[name="target_value"]').map(function (i) { return i.value.trim().toLowerCase(); });
      paste.value.split(/[\n,;]+/).forEach(function (raw) {
        var value = raw.trim().replace(/^["']|["']$/g, "");
        if (!value || have.indexOf(value.toLowerCase()) !== -1) return;
        var type = guessType(value);
        if (type === "domain") value = value.replace(/^https?:\/\/(www\.)?/i, "").split("/")[0];
        have.push(value.toLowerCase());
        var empty = qsa(rows, ".target-row").filter(function (r) {
          return !r.querySelector('input[name="target_value"]').value.trim();
        })[0];
        if (empty) {
          empty.querySelector('input[name="target_value"]').value = value;
          empty.querySelector('select[name="target_type"]').value = type;
        } else {
          addRow(value, type);
        }
      });
      paste.value = "";
    }
    if (paste) {
      paste.addEventListener("blur", takePaste);
      paste.addEventListener("paste", function () { setTimeout(takePaste, 0); });
    }

    // Quick / Deep ticks or unticks the slow tools.
    qsa(form, "[data-depth]").forEach(function (radio) {
      radio.addEventListener("change", function () {
        var deep = radio.value === "deep";
        qsa(form, 'input[name="tools"][data-speed="slow"]').forEach(function (box) { if (!box.disabled) box.checked = deep; });
      });
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
    row.dataset.open = open ? "1" : "";
    var btn = row.querySelector("[data-row-toggle]");
    if (btn) btn.setAttribute("aria-expanded", open ? "true" : "false");
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
    var tog = e.target.closest && e.target.closest("[data-row-toggle]");
    if (tog) { toggleRow(tog.closest("[data-expand]")); return; }
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
        // Every view that lists findings reloads once the undo has landed.
        window.htmx.ajax("POST", undoUrl, { source: document.body, swap: "none" }).then(function () {
          window.htmx.trigger(document.body, "entities-changed");
        });
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
    if (row && row.dataset.open !== "1") toggleRow(row);
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
    if (row && row.dataset.open !== "1") toggleRow(row);
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

  // Buttons that change something another panel shows ask that panel to reload itself.
  document.addEventListener("htmx:afterRequest", function (e) {
    var elt = e.detail.elt;
    var target = elt && elt.dataset && elt.dataset.refresh && document.querySelector(elt.dataset.refresh);
    if (target && e.detail.successful && window.htmx) window.htmx.trigger(target, "refresh");
  });

  // Review queue: skip keeps a list of skipped ids; single keys answer the current card.
  document.addEventListener("click", function (e) {
    var skip = e.target.closest && e.target.closest("[data-skip], [data-skip-reset]");
    var input = document.getElementById("review-skip");
    if (!skip || !input || !window.htmx) return;
    input.value = skip.hasAttribute("data-skip-reset") ? "" : (input.value ? input.value + "," : "") + skip.dataset.skip;
    window.htmx.trigger("#review-card", "refresh");
  });
  document.addEventListener("keydown", function (e) {
    if (!document.getElementById("review-card") || e.metaKey || e.ctrlKey || e.altKey) return;
    if (e.target.closest && e.target.closest("input, textarea, select")) return;
    var btn = document.querySelector('#review-card [data-key="' + e.key.toLowerCase() + '"]:not([disabled])');
    if (btn) { e.preventDefault(); btn.click(); }
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

  // --- App shell: theme, mobile menu, command palette, shortcuts ----------------------------
  var THEMES = ["system", "light", "dark"];
  document.addEventListener("click", function (e) {
    var t = e.target.closest && e.target.closest("[data-theme-toggle]");
    if (!t) return;
    var root = document.documentElement;
    var next = THEMES[(THEMES.indexOf(root.dataset.theme || "system") + 1) % THEMES.length];
    root.dataset.theme = next;
    document.cookie = "theme=" + next + "; path=/; max-age=31536000; samesite=lax";
    var label = t.querySelector("[data-theme-label]");
    if (label) label.textContent = next.charAt(0).toUpperCase() + next.slice(1);
    t.setAttribute("aria-label", "Theme: " + next + ". Change theme");
    document.dispatchEvent(new CustomEvent("unmask:theme"));
  });

  var isMac = /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent);
  qsa(document, "[data-mod-key]").forEach(function (k) { if (isMac) k.textContent = "⌘K"; });

  function setNav(open) {
    document.body.classList.toggle("nav-open", open);
    qsa(document, "[data-nav-toggle]").forEach(function (b) { b.setAttribute("aria-expanded", open ? "true" : "false"); });
  }
  document.addEventListener("click", function (e) {
    if (e.target.closest && e.target.closest("[data-nav-toggle]")) { setNav(!document.body.classList.contains("nav-open")); return; }
    if (document.body.classList.contains("nav-open") && !e.target.closest(".sidebar")) setNav(false);
  });

  var COMMANDS = [
    { group: "Go to", label: "Cases", hint: "g c", url: "/" },
    { group: "Go to", label: "New case", hint: "n", url: "/cases/new" },
    { group: "Go to", label: "Tools & accuracy", hint: "g t", url: "/tools" },
    { group: "Go to", label: "Search everything", hint: "", url: "/search" },
    { group: "Actions", label: "Change theme", hint: "", action: function () { var b = document.querySelector("[data-theme-toggle]"); if (b) b.click(); } },
    { group: "Actions", label: "Keyboard shortcuts", hint: "?", action: function () { openDialog("shortcuts"); } }
  ];
  var palette = document.getElementById("palette");
  var pInput = document.getElementById("palette-q");
  var pList = document.getElementById("palette-list");
  var pItems = [], pIndex = 0, pTimer = null, pSeq = 0, lastFocus = null;

  function openDialog(id) {
    var d = document.getElementById(id);
    if (!d || d.open) return;
    lastFocus = document.activeElement;
    d.showModal();
    if (id === "palette") { pInput.value = ""; renderPalette(COMMANDS); pInput.focus(); }
  }
  document.addEventListener("close", function () { if (lastFocus && lastFocus.focus) lastFocus.focus(); }, true);
  document.addEventListener("click", function (e) {
    if (!e.target.closest) return;
    if (e.target.closest("[data-palette-open]")) { setNav(false); openDialog("palette"); }
    if (e.target.closest("[data-shortcuts-open]")) openDialog("shortcuts");
    var closer = e.target.closest("[data-dialog-close]");
    if (closer) closer.closest("dialog").close();
    if (e.target.tagName === "DIALOG") e.target.close();  // click on the backdrop
  });

  function renderPalette(items) {
    pItems = items; pIndex = 0;
    pList.textContent = "";
    if (!items.length) {
      var empty = document.createElement("li");
      empty.className = "palette-empty"; empty.textContent = "No matches";
      pList.appendChild(empty); return;
    }
    var group = null;
    items.forEach(function (item, i) {
      if (item.group !== group) {
        group = item.group;
        var g = document.createElement("li");
        g.className = "p-group"; g.setAttribute("role", "presentation"); g.textContent = group;
        pList.appendChild(g);
      }
      var li = document.createElement("li");
      li.setAttribute("role", "option"); li.id = "p-opt-" + i;
      var label = document.createElement("span"); label.className = "p-label"; label.textContent = item.label;
      var hint = document.createElement("span"); hint.className = "p-hint"; hint.textContent = item.hint || "";
      li.appendChild(label); li.appendChild(hint);
      li.addEventListener("mousemove", function () { select(i); });
      li.addEventListener("click", function () { choose(i); });
      pList.appendChild(li);
    });
    select(0);
  }
  function select(i) {
    pIndex = i;
    qsa(pList, "[role=option]").forEach(function (li) { li.setAttribute("aria-selected", li.id === "p-opt-" + i ? "true" : "false"); });
    var el = document.getElementById("p-opt-" + i);
    if (el) { el.scrollIntoView({ block: "nearest" }); pInput.setAttribute("aria-activedescendant", el.id); }
  }
  function choose(i) {
    var item = pItems[i];
    if (!item) return;
    palette.close();
    if (item.action) item.action(); else window.location.href = item.url;
  }
  if (pInput) {
    pInput.addEventListener("input", function () {
      var q = pInput.value.trim().toLowerCase();
      var local = COMMANDS.filter(function (c) { return !q || c.label.toLowerCase().indexOf(q) !== -1; });
      renderPalette(local);
      clearTimeout(pTimer);
      if (q.length < 2) return;
      var seq = ++pSeq;
      pTimer = setTimeout(function () {
        fetch("/palette.json?q=" + encodeURIComponent(q), { credentials: "same-origin" })
          .then(function (r) { return r.ok ? r.json() : { results: [] }; })
          .then(function (data) {
            if (seq !== pSeq) return;  // a newer query is on its way
            var more = [{ group: "Search", label: "Search everything for “" + pInput.value.trim() + "”", hint: "Enter",
                          url: "/search?q=" + encodeURIComponent(pInput.value.trim()) }];
            renderPalette(data.results.concat(local).concat(more));
          });
      }, 140);
    });
    pInput.addEventListener("keydown", function (e) {
      if (e.key === "ArrowDown") { e.preventDefault(); select(Math.min(pIndex + 1, pItems.length - 1)); }
      else if (e.key === "ArrowUp") { e.preventDefault(); select(Math.max(pIndex - 1, 0)); }
      else if (e.key === "Enter") { e.preventDefault(); choose(pIndex); }
    });
  }

  // Global keys. Single letters only fire outside text fields and open dialogs.
  var pendingG = false, gTimer = null;
  document.addEventListener("keydown", function (e) {
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") { e.preventDefault(); openDialog("palette"); return; }
    if (e.metaKey || e.ctrlKey || e.altKey) return;
    var typing = e.target.closest && e.target.closest("input, textarea, select, [contenteditable]");
    if (typing || document.querySelector("dialog[open]") || document.getElementById("review-card")) return;
    var key = e.key.toLowerCase();
    if (pendingG) {
      pendingG = false; clearTimeout(gTimer);
      if (key === "c") window.location.href = "/";
      else if (key === "t") window.location.href = "/tools";
      return;
    }
    if (key === "g") { pendingG = true; gTimer = setTimeout(function () { pendingG = false; }, 900); return; }
    if (key === "/") { e.preventDefault(); openDialog("palette"); }
    else if (e.key === "?") { e.preventDefault(); openDialog("shortcuts"); }
    else if (key === "n" && document.body.classList.contains("has-shell")) { window.location.href = "/cases/new"; }
    else if (key === "r") { var rv = document.querySelector("[data-review-link]"); if (rv) window.location.href = rv.getAttribute("href"); }
  });

  document.addEventListener("DOMContentLoaded", function () { init(document); syncRunButton(); });
  document.addEventListener("htmx:load", function (e) { init(e.detail.elt); });
  document.addEventListener("htmx:afterSettle", syncRunButton);
})();
