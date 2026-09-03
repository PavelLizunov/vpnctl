// admin.js — external script for the vpnctl admin UI.
//
// Why external (not inline): the admin CSP is `script-src 'self'` with
// NO 'unsafe-inline', so a `<script>…</script>` block is refused by the
// browser. Anything interactive must live in a same-origin asset like
// this one. (`connect-src 'self'` permits the same-origin EventSource.)
//
// Today it wires the SSE-streamed server re-deploy: any element with a
// `data-sse-url` attribute becomes a one-shot "stream into a log pane"
// trigger. Generic on purpose so the same wiring can drive other
// streamed actions later without new JS.
(function () {
  "use strict";

  function wireSse(btn) {
    var url = btn.getAttribute("data-sse-url");
    if (!url) return;
    var logId = btn.getAttribute("data-log") || "deploy-log";

    btn.addEventListener("click", function (e) {
      e.preventDefault();
      var log = document.getElementById(logId);
      if (log) {
        log.hidden = false;
        log.textContent = "";
      }
      var idleLabel = btn.textContent;
      btn.disabled = true;
      btn.textContent = btn.getAttribute("data-busy-label") || "working…";

      var done = false; // set once a terminal (ok|error) event arrives

      function line(text, color) {
        if (!log) return;
        var row = document.createElement("div");
        row.textContent = text;
        if (color) row.style.color = color;
        log.appendChild(row);
        log.scrollTop = log.scrollHeight;
      }

      var es = new EventSource(url);

      es.addEventListener("step", function (ev) {
        try {
          var d = JSON.parse(ev.data);
          // stderr-tagged steps (geoip runner) render red so warnings
          // stand out from progress chatter.
          var color = d.stream === "stderr" ? "var(--acc-bad, #97233f)" : null;
          line((d.phase ? "[" + d.phase + "] " : "") + d.message, color);
        } catch (_) {
          line(ev.data);
        }
      });

      es.addEventListener("ok", function (ev) {
        done = true;
        var redirect = null;
        var okMsg = null;
        try {
          var okd = JSON.parse(ev.data);
          redirect = okd.redirect;
          okMsg = okd.message;
        } catch (_) {}
        // Render the server's terminal message when it carries one —
        // the geoip runner's «new DBs load on next vpnctld restart» is
        // operator-actionable and must not be swallowed by a generic
        // «complete». The 1.2 s pre-reload pause keeps it readable;
        // it also lands in the log pane, which survives if the
        // operator cancels the reload.
        line("✓ " + (okMsg || "complete."), "var(--acc-good, #2c5f2d)");
        es.close();
        btn.textContent = "✓ done — reloading…";
        // `data-reload-self` reloads the CURRENT page (ignoring the
        // server-provided redirect) — used by the deploy-all button on a
        // user page so its "pending deploy" banner re-computes + clears,
        // rather than bouncing to /admin/servers.
        var reloadSelf = btn.getAttribute("data-reload-self");
        setTimeout(function () {
          window.location = reloadSelf ? window.location.href : redirect || window.location.href;
        }, 1200);
      });

      // One listener catches BOTH the server's named `error` event
      // (terminal, carries `.data`) AND the built-in transport error
      // (no `.data`; EventSource would otherwise auto-reconnect, which
      // we must NOT do for a one-shot deploy). After a terminal event
      // `done` is set, so the close-induced transport error is ignored.
      es.addEventListener("error", function (ev) {
        if (done) return;
        if (ev && ev.data) {
          done = true;
          var msg = "deploy failed";
          try {
            msg = JSON.parse(ev.data).message || msg;
          } catch (_) {}
          line("✗ " + msg, "var(--acc-bad, #97233f)");
        } else {
          line("✗ connection lost — please retry", "var(--acc-bad, #97233f)");
        }
        es.close();
        btn.disabled = false;
        btn.textContent = btn.getAttribute("data-retry-label") || idleLabel;
      });
    });
  }

  // ── CSP-safe confirmations ──────────────────────────────────────
  // The admin CSP is `script-src 'self'` (no 'unsafe-inline'), so an
  // inline `onsubmit="…"` handler is refused by the browser — the form
  // then submits WITHOUT the guard ever running (a destructive confirm
  // is silently skipped; a typed-confirm submits an empty field and the
  // backend rejects it). These wire the same UX from data-attributes.

  // Simple yes/no: <form data-confirm="message"> — submit proceeds
  // only if the operator accepts the confirm() dialog.
  function wireConfirm(form) {
    var msg = form.getAttribute("data-confirm");
    form.addEventListener("submit", function (e) {
      if (!window.confirm(msg)) e.preventDefault();
    });
  }

  // Typed-match: <form data-confirm-prompt="ask…" data-confirm-match="kg"
  // [data-confirm-field="confirm"]> — the operator must type the exact
  // match value; it is copied into the named hidden field (default
  // "confirm") which the backend re-checks. A mismatch or a cancelled
  // prompt blocks the submit (nothing is sent).
  function wireConfirmPrompt(form) {
    var ask = form.getAttribute("data-confirm-prompt");
    var match = form.getAttribute("data-confirm-match");
    var field = form.getAttribute("data-confirm-field") || "confirm";
    form.addEventListener("submit", function (e) {
      var v = window.prompt(ask);
      if (v !== match) {
        e.preventDefault();
        if (v !== null) window.alert("confirm did not match — nothing changed");
        return;
      }
      var target = form.elements[field];
      if (target) target.value = v;
    });
  }

  // ── auto-start SSE (design v2 6b wizard) ────────────────────────
  // A `<pre data-sse-autostart="/url" [data-redirect-on-ok]>` opens its
  // EventSource on page load (no button) and streams step/ok/error into
  // itself. Optional `[data-steps="phaseA,phaseB,…"]` container id lets
  // us light up a checklist: each `step` event with a `phase` marks the
  // row `[data-step-phase="<phase>"]` done + the earlier ones. Replaces
  // the wizard's inline <script>, which `script-src 'self'` blocked.
  function wireAutoSse(pre) {
    var url = pre.getAttribute("data-sse-autostart");
    if (!url) return;
    var stepsBox = pre.getAttribute("data-steps-box");
    var steps = stepsBox ? document.getElementById(stepsBox) : null;
    var order = [];
    if (steps) {
      var rows = steps.querySelectorAll("[data-step-phase]");
      for (var r = 0; r < rows.length; r++)
        order.push(rows[r].getAttribute("data-step-phase"));
    }
    function line(text, color) {
      var row = document.createElement("div");
      row.textContent = text;
      if (color) row.style.color = color;
      pre.appendChild(row);
      pre.scrollTop = pre.scrollHeight;
    }
    function markPhase(phase) {
      if (!steps) return;
      var idx = order.indexOf(phase);
      if (idx < 0) return;
      for (var k = 0; k <= idx; k++) {
        var el = steps.querySelector('[data-step-phase="' + order[k] + '"] .step-mark');
        if (el) {
          el.textContent = "✓";
          el.style.color = "var(--green)";
        }
      }
    }
    pre.textContent = "";
    var done = false;
    var es = new EventSource(url);
    es.addEventListener("step", function (ev) {
      try {
        var d = JSON.parse(ev.data);
        markPhase(d.phase);
        line((d.phase ? "[" + d.phase + "] " : "") + d.message);
      } catch (_) {
        line(ev.data);
      }
    });
    es.addEventListener("ok", function (ev) {
      done = true;
      var redirect = null;
      try {
        redirect = JSON.parse(ev.data).redirect;
      } catch (_) {}
      line("✓ complete.", "var(--green)");
      es.close();
      if (redirect) setTimeout(function () { window.location = redirect; }, 1400);
    });
    es.addEventListener("error", function (ev) {
      if (done) return;
      var msg = "bootstrap failed — see the log above";
      if (ev && ev.data) {
        try { msg = JSON.parse(ev.data).message || msg; } catch (_) {}
      }
      line("✗ " + msg, "var(--red)");
      es.close();
    });
  }

  // ── "/" hotkey focuses the topbar search (design v2) ────────────
  // Ignored while the operator is already typing in a field so "/" in
  // a form stays a literal slash.
  function wireSearchHotkey() {
    document.addEventListener("keydown", function (e) {
      if (e.key !== "/" || e.metaKey || e.ctrlKey || e.altKey) return;
      var t = e.target;
      var tag = t && t.tagName;
      if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT" || (t && t.isContentEditable)) return;
      var box = document.getElementById("tb-search");
      if (box) {
        e.preventDefault();
        box.focus();
      }
    });
  }

  // ── click-to-select for share-link textareas ────────────────────
  // The old inline `onclick="this.select()"` was dead under the CSP
  // (`script-src 'self'` refuses inline handlers) — the title promised
  // click-to-select but nothing happened. Delegated here instead;
  // marker attribute keeps it opt-in per textarea.
  function wireSelectOnClick() {
    document.addEventListener("click", function (e) {
      var t = e.target;
      if (t && t.tagName === "TEXTAREA" && t.hasAttribute("data-select-on-click")) t.select();
    });
  }

  // ── live user-id normalisation (NM-7 naming gate) ───────────────
  // <input data-lowercase-id>: lowercase, spaces → '-', strip anything
  // outside [a-z0-9._-], cap at 32. Replaces an inline `oninput` that
  // the CSP silently refused — `pattern=` + the server gate always
  // enforced the rule, this just restores the promised live feedback.
  function wireLowercaseId() {
    document.addEventListener("input", function (e) {
      var t = e.target;
      if (!t || t.tagName !== "INPUT" || !t.hasAttribute("data-lowercase-id")) return;
      t.value = t.value
        .toLowerCase()
        .replace(/\s+/g, "-")
        .replace(/[^a-z0-9._-]/g, "")
        .slice(0, 32);
    });
  }

  // ── form submit feedback & double-click protection ────────────
  function wireFormSubmitFeedback() {
    document.addEventListener("submit", function (e) {
      if (e.defaultPrevented) return;
      var form = e.target;
      if (!form || form.tagName !== "FORM") return;
      if (form.hasAttribute("data-submitting")) {
        e.preventDefault();
        return;
      }
      form.setAttribute("data-submitting", "true");
      var btn = e.submitter || form.querySelector("button[type='submit'], button:not([type])");
      if (btn) {
        btn.classList.add("is-loading");
      }
    });

    window.addEventListener("pageshow", function () {
      var forms = document.querySelectorAll("form[data-submitting]");
      for (var i = 0; i < forms.length; i++) {
        forms[i].removeAttribute("data-submitting");
      }
      var btns = document.querySelectorAll(".is-loading");
      for (var j = 0; j < btns.length; j++) {
        btns[j].classList.remove("is-loading");
      }
    });
  }

  document.addEventListener("DOMContentLoaded", function () {
    wireSearchHotkey();
    wireSelectOnClick();
    wireLowercaseId();
    wireFormSubmitFeedback();
    var nodes = document.querySelectorAll("[data-sse-url]");
    for (var i = 0; i < nodes.length; i++) wireSse(nodes[i]);
    var autos = document.querySelectorAll("[data-sse-autostart]");
    for (var a = 0; a < autos.length; a++) wireAutoSse(autos[a]);
    var confirms = document.querySelectorAll("[data-confirm]");
    for (var c = 0; c < confirms.length; c++) wireConfirm(confirms[c]);
    var prompts = document.querySelectorAll("[data-confirm-prompt]");
    for (var p = 0; p < prompts.length; p++) wireConfirmPrompt(prompts[p]);
  });
})();
