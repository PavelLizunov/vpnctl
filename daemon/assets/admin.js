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
          line("✗ connection lost — see vpnctld logs", "var(--acc-bad, #97233f)");
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

  document.addEventListener("DOMContentLoaded", function () {
    var nodes = document.querySelectorAll("[data-sse-url]");
    for (var i = 0; i < nodes.length; i++) wireSse(nodes[i]);
    var confirms = document.querySelectorAll("[data-confirm]");
    for (var c = 0; c < confirms.length; c++) wireConfirm(confirms[c]);
    var prompts = document.querySelectorAll("[data-confirm-prompt]");
    for (var p = 0; p < prompts.length; p++) wireConfirmPrompt(prompts[p]);
  });
})();
