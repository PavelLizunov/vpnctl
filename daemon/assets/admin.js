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
      var label = btn.querySelector("[data-icon-label]") || btn;
      var idleLabel = label.textContent;
      btn.disabled = true;
      label.textContent = btn.getAttribute("data-busy-label") || "working…";

      var done = false;

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
        line("✓ " + (okMsg || "complete."), "var(--acc-good, #2c5f2d)");
        es.close();
        label.textContent = document.documentElement.lang === "ru" ? "готово — перезагрузка…" : "done — reloading…";
        var iconUse = btn.querySelector(".ed-icon use");
        if (iconUse) iconUse.setAttribute("href", "/admin/assets/icons.svg#check");
        var reloadSelf = btn.getAttribute("data-reload-self");
        setTimeout(function () {
          window.location = reloadSelf ? window.location.href : redirect || window.location.href;
        }, 1200);
      });

      es.addEventListener("error", function (ev) {
        if (done) return;
        if (ev && ev.data) {
          done = true;
          var msg = "deploy failed";
          try {
            msg = JSON.parse(ev.data).message || msg;
          } catch (_) {}
          if (msg.indexOf("deploy already running") !== -1) {
            line("ℹ " + (document.documentElement.lang === "ru" ? "деплой уже выполняется — ожидаем завершения…" : "deploy is already in progress — waiting for completion…"), "var(--ink)");
            es.close();
            setTimeout(function () { window.location.reload(); }, 2000);
            return;
          }
          line("✗ " + msg, "var(--acc-bad, #97233f)");
        } else {
          line("✗ connection lost — please retry", "var(--acc-bad, #97233f)");
        }
        es.close();
        btn.disabled = false;
        label.textContent = btn.getAttribute("data-retry-label") || idleLabel;
      });
    });
  }


  function wireConfirm(form) {
    var msg = form.getAttribute("data-confirm");
    form.addEventListener("submit", function (e) {
      if (!window.confirm(msg)) e.preventDefault();
    });
  }

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
          var mark = el.querySelector(".ed-icon use");
          if (mark) {
            mark.setAttribute("href", "/admin/assets/icons.svg#check");
          } else {
            el.textContent = "✓";
          }
          el.setAttribute("aria-label", document.documentElement.lang === "ru" ? "Готово" : "Complete");
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
      else setTimeout(function () { window.location.reload(); }, 1400);
    });
    es.addEventListener("error", function (ev) {
      if (done) return;
      var msg = "bootstrap failed — see the log above";
      if (ev && ev.data) {
        try { msg = JSON.parse(ev.data).message || msg; } catch (_) {}
      }
      if (msg.indexOf("deploy already running") !== -1) {
        line("ℹ " + (document.documentElement.lang === "ru" ? "деплой уже выполняется — ожидаем завершения…" : "deploy is already in progress — waiting for completion…"), "var(--ink)");
        es.close();
        setTimeout(function () { window.location.reload(); }, 2000);
        return;
      }
      line("✗ " + msg, "var(--red)");
      es.close();
    });
  }

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

  function wireSelectOnClick() {
    document.addEventListener("click", function (e) {
      var t = e.target;
      if (t && t.tagName === "TEXTAREA" && t.hasAttribute("data-select-on-click")) t.select();
    });
  }

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

  function wireBoostyQuickConnect() {
    var bmlLink = document.querySelector("[data-bookmarklet-link]");
    var modal = document.getElementById("bookmarklet-help-modal");
    if (bmlLink && modal) {
      bmlLink.addEventListener("click", function (e) {
        e.preventDefault();
        modal.style.display = "flex";
      });
    }

    var closeButtons = document.querySelectorAll("[data-modal-close]");
    for (var i = 0; i < closeButtons.length; i++) {
      closeButtons[i].addEventListener("click", function () {
        var mId = this.getAttribute("data-modal-close");
        var m = document.getElementById(mId);
        if (m) m.style.display = "none";
      });
    }

    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape" && modal && modal.style.display === "flex") {
        modal.style.display = "none";
      }
    });

    var copyBtn = document.querySelector("[data-copy-bookmarklet]");
    if (copyBtn) {
      copyBtn.addEventListener("click", function () {
        var s = this.getAttribute("data-script") || "";
        function feedback() {
          var orig = copyBtn.textContent;
          copyBtn.textContent = "Скопировано!";
          setTimeout(function () { copyBtn.textContent = orig; }, 1800);
        }
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(s).then(feedback).catch(function () {
            prompt("Скопируйте скрипт:", s);
          });
        } else {
          var t = document.createElement("textarea");
          t.value = s;
          document.body.appendChild(t);
          t.select();
          try {
            document.execCommand("copy");
            feedback();
          } catch (_) {
            prompt("Скопируйте скрипт:", s);
          }
          document.body.removeChild(t);
        }
      });
    }

    var hash = window.location.hash || "";
    if (hash.indexOf("#quick_connect=") === 0) {
      var raw = hash.substring(15);
      var data = null;
      try {
        data = JSON.parse(raw);
      } catch (_) {
        try {
          data = JSON.parse(decodeURIComponent(raw));
        } catch (e) {
          console.error("Boosty quick connect error", e);
        }
      }

      try {
        history.replaceState(null, "", window.location.pathname + window.location.search);
      } catch (_) {}

      if (data && typeof data === "object") {
        if (data.blog) {
          var elBlog = document.getElementById("boosty_blog_url");
          if (elBlog) elBlog.value = data.blog;
          var info = document.getElementById("quick-connect-blog-info");
          if (info) info.textContent = "Блог: " + data.blog;
        }
        if (data.access_token) {
          var elAccess = document.getElementById("boosty_access");
          if (elAccess) elAccess.value = data.access_token;
        }
        if (data.refresh_token) {
          var elRefresh = document.getElementById("boosty_refresh");
          if (elRefresh) elRefresh.value = data.refresh_token;
        }
        if (data.device_id) {
          var elDevice = document.getElementById("boosty_device");
          if (elDevice) elDevice.value = data.device_id;
        }
        var cb = document.getElementById("boosty_enabled");
        if (cb) cb.checked = true;

        var banner = document.getElementById("quick-connect-banner");
        if (banner) {
          banner.style.display = "block";
          banner.scrollIntoView({ behavior: "smooth" });
        }
      }
    }
  }

  document.addEventListener("DOMContentLoaded", function () {
    wireSearchHotkey();
    wireSelectOnClick();
    wireLowercaseId();
    wireFormSubmitFeedback();
    wireBoostyQuickConnect();
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
