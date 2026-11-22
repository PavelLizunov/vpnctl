(function () {
  "use strict";

  var reloadTimer = null;
  var deployPollTimer = null;
  var deployPollBusy = false;

  function withTicket(url, onReady, onFail) {
    var path = url.split("?")[0];
    fetch("/admin/sse-ticket", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: "path=" + encodeURIComponent(path)
    })
      .then(function (r) {
        if (!r.ok) throw new Error("start ticket refused (HTTP " + r.status + ")");
        return r.text();
      })
      .then(function (t) {
        onReady(url + (url.indexOf("?") < 0 ? "?" : "&") + "ticket=" + encodeURIComponent(t.trim()));
      })
      .catch(function (e) {
        onFail(e && e.message ? e.message : String(e));
      });
  }

  function wireSse(btn) {
    var url = btn.getAttribute("data-sse-url");
    if (!url) return;
    var logId = btn.getAttribute("data-log") || "deploy-log";

    btn.addEventListener("click", function (e) {
      e.preventDefault();
      clearTimeout(reloadTimer);
      reloadTimer = null;
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

      withTicket(url, start, function (msg) {
        line("✗ " + msg, "var(--acc-bad, #97233f)");
        btn.disabled = false;
        label.textContent = btn.getAttribute("data-retry-label") || idleLabel;
      });

      function start(ticketedUrl) {
        var es = new EventSource(ticketedUrl);

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
            if (reloadSelf || !redirect) window.location.reload();
            else window.location = redirect;
          }, 1200);
        });

        es.addEventListener("error", function (ev) {
          if (done) return;
          done = true;
          if (ev && ev.data) {
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
            line(document.documentElement.lang === "ru"
              ? "✗ соединение потеряно — операция может ещё выполняться; перезагрузите страницу, чтобы увидеть её состояние"
              : "✗ connection lost — the operation may still be running; reload the page to see its state", "var(--acc-bad, #97233f)");
            es.close();
            label.textContent = document.documentElement.lang === "ru" ? "соединение потеряно — перезагрузите страницу" : "connection lost — reload page";
            return;
          }
          es.close();
          btn.disabled = false;
          label.textContent = btn.getAttribute("data-retry-label") || idleLabel;
        });
      }
    });
  }

  // Deploy runs in place: the URL, form drafts, focus and scroll stay put while
  // only the status fragment is refreshed. Every open tab reads the same
  // read-only panel, including a deploy started by another tab or by autodeploy.
  function deployText(en, ru) {
    return document.documentElement.lang === "ru" ? ru : en;
  }

  function deployPanel() {
    return document.getElementById("deployment-status");
  }

  function deployGeneration(panel) {
    var value = parseInt(panel.getAttribute("data-deploy-generation") || "0", 10);
    return isNaN(value) ? 0 : value;
  }

  function deployField(panel, selector, text) {
    var node = panel.querySelector(selector);
    if (node) node.textContent = text;
  }

  function deployButton() {
    return document.getElementById("deploy-button");
  }

  function syncDeployButton() {
    var panel = deployPanel();
    var btn = deployButton();
    if (!panel || !btn) return;
    var state = panel.getAttribute("data-deploy-state") || "unknown";
    var canStart = panel.getAttribute("data-deploy-can-start") === "true";
    var label = btn.querySelector("[data-icon-label]") || btn;
    var iconUse = btn.querySelector(".ed-icon use");
    function icon(name) {
      if (iconUse) iconUse.setAttribute("href", "/admin/assets/icons.svg#" + name);
    }
    btn.classList.remove("is-loading");
    if (state === "running" || state === "queued") {
      btn.disabled = true;
      btn.classList.add("is-loading");
      label.textContent = btn.getAttribute("data-label-busy") || "working…";
      icon("rotate-cw");
      return;
    }
    if (!canStart) {
      btn.disabled = true;
      label.textContent = btn.getAttribute("data-label-unknown")
        || deployText("status unknown — check status", "статус неизвестен — проверь статус");
      icon("circle-dashed");
      return;
    }
    btn.disabled = false;
    if (state === "failed") {
      label.textContent = btn.getAttribute("data-label-retry") || "retry deploy";
      icon("rotate-cw");
    } else {
      label.textContent = btn.getAttribute("data-label-idle") || "deploy";
      icon("rocket");
    }
  }

  function currentDeployState() {
    var panel = deployPanel();
    return panel ? panel.getAttribute("data-deploy-state") || "unknown" : "";
  }

  function scheduleDeployPoll(delay) {
    clearTimeout(deployPollTimer);
    if (!deployPanel()) {
      deployPollTimer = null;
      return;
    }
    if (typeof delay !== "number") {
      var state = currentDeployState();
      delay = state === "running" || state === "queued" || state === "unknown" ? 2000 : 5000;
    }
    deployPollTimer = setTimeout(function () {
      if (document.visibilityState === "hidden") {
        scheduleDeployPoll(delay);
        return;
      }
      refreshDeployStatus(function () { scheduleDeployPoll(); });
    }, delay);
  }

  function pageScroller(element) {
    const main = element.closest("main");
    return main && /^(auto|scroll)$/.test(getComputedStyle(main).overflowY)
      ? main : document.scrollingElement;
  }

  function replaceDeployPanel(panel, next) {
    const protocols = document.getElementById("enabled-protocols");
    const scroller = pageScroller(panel);
    const viewportTop = scroller === document.scrollingElement ? 0 : scroller.getBoundingClientRect().top;
    const keepList = protocols && panel.getBoundingClientRect().bottom <= viewportTop;
    const listTop = keepList ? protocols.getBoundingClientRect().top : 0;
    var active = document.activeElement;
    var focused = !!active && panel.contains(active);
    var focusKey = null;
    if (focused) {
      if (active.hasAttribute("data-deploy-retry")) focusKey = "retry";
      else if (active.hasAttribute("data-deploy-refresh")) focusKey = "refresh";
      else if (active.hasAttribute("data-deploy-audit")) focusKey = "audit";
    }
    panel.replaceWith(next);
    if (keepList) scroller.scrollTop += protocols.getBoundingClientRect().top - listTop;
    if (focused) {
      var replacement = focusKey
        ? next.querySelector("[data-deploy-" + focusKey + "]")
        : null;
      if (!replacement) {
        next.setAttribute("tabindex", "-1");
        replacement = next;
      }
      replacement.focus({ preventScroll: true });
    }
  }

  function refreshDeployStatus(onDone, uncertain) {
    var panel = deployPanel();
    if (!panel) {
      if (onDone) onDone();
      return;
    }
    var url = panel.getAttribute("data-deploy-status-url");
    if (!url || deployPollBusy) {
      if (onDone) onDone();
      return;
    }
    deployPollBusy = true;
    var controller = new AbortController();
    var timeout = setTimeout(function () { controller.abort(); }, 15000);
    fetch(url, {
      credentials: "same-origin",
      cache: "no-store",
      signal: controller.signal
    })
      .then(function (response) {
        if (!response.ok) throw new Error("status refresh failed");
        return response.text();
      })
      .then(function (text) {
        var next = new DOMParser().parseFromString(text, "text/html")
          .getElementById("deployment-status");
        if (!next) throw new Error("missing deployment status");
        var panelNow = deployPanel();
        if (!panelNow) return;
        replaceDeployPanel(panelNow, next);
        syncDeployButton();
      })
      .catch(function () {
        if (uncertain) {
          markDeployUncertain(deployText(
            "status could not be read — the operation may still be running",
            "не удалось прочитать статус — операция может ещё выполняться"
          ));
        }
      })
      .finally(function () {
        clearTimeout(timeout);
        deployPollBusy = false;
        if (onDone) onDone();
      });
  }

  function markDeployUncertain(message) {
    var panel = deployPanel();
    if (!panel) return;
    panel.setAttribute("data-deploy-state", "unknown");
    panel.setAttribute("data-deploy-can-start", "false");
    panel.setAttribute("data-deploy-uncertain", "true");
    deployField(panel, "[data-deploy-badge]", deployText("unknown", "неизвестно"));
    deployField(panel, "[data-deploy-stage-phase]", "stream");
    deployField(panel, "[data-deploy-stage-message]", message);
    deployField(panel, "[data-deploy-stage-time]", "");
    deployField(panel, "[data-deploy-note]", message);
    syncDeployButton();
    scheduleDeployPoll(2000);
  }

  function applyDeployStep(step, startedGeneration) {
    var panel = deployPanel();
    if (!panel || deployGeneration(panel) > startedGeneration) return;
    panel.setAttribute("data-deploy-state", "running");
    panel.setAttribute("data-deploy-can-start", "false");
    panel.removeAttribute("data-deploy-uncertain");
    deployField(panel, "[data-deploy-badge]", deployText("running", "выполняется"));
    deployField(panel, "[data-deploy-stage-phase]", step.phase || "deploy");
    deployField(panel, "[data-deploy-stage-message]", step.message || "");
    deployField(panel, "[data-deploy-stage-time]", deployText(" · just now", " · только что"));
    deployField(panel, "[data-deploy-note]", deployText(
      "applying; further changes will be included in a follow-up pass",
      "применяется; новые изменения войдут в следующий проход"
    ));
    syncDeployButton();
  }

  function applyDeployFailure(message, startedGeneration) {
    var panel = deployPanel();
    if (panel && deployGeneration(panel) <= startedGeneration) {
      panel.setAttribute("data-deploy-state", "failed");
      panel.setAttribute("data-deploy-can-start", "true");
      panel.removeAttribute("data-deploy-uncertain");
      deployField(panel, "[data-deploy-badge]", deployText("failed", "ошибка"));
      deployField(panel, "[data-deploy-stage-phase]", "failed");
      deployField(panel, "[data-deploy-stage-message]", message);
      deployField(panel, "[data-deploy-stage-time]", deployText(" · just now", " · только что"));
      deployField(panel, "[data-deploy-note]", deployText(
        "deployment failed — reading the authoritative status…",
        "деплой не завершён — читаю авторитетный статус…"
      ));
      var errorRow = panel.querySelector("[data-deploy-error]");
      if (errorRow) {
        errorRow.hidden = false;
        deployField(panel, "[data-deploy-error-text]", message);
      }
    }
    syncDeployButton();
  }

  function wireDeploySse(btn) {
    var url = btn.getAttribute("data-sse-url");
    if (!url) return;
    btn.addEventListener("click", function (e) {
      e.preventDefault();
      if (btn.disabled) return;
      clearTimeout(reloadTimer);
      reloadTimer = null;
      clearTimeout(deployPollTimer);
      deployPollTimer = null;
      var log = document.getElementById(btn.getAttribute("data-log") || "deploy-log");
      if (log) {
        log.hidden = false;
        log.textContent = "";
      }
      var panel = deployPanel();
      var startedGeneration = panel ? deployGeneration(panel) : 0;
      var label = btn.querySelector("[data-icon-label]") || btn;
      btn.disabled = true;
      btn.classList.add("is-loading");
      label.textContent = btn.getAttribute("data-label-busy") || "working…";
      var done = false;

      function line(text, color) {
        if (!log) return;
        var atBottom = log.scrollHeight - log.clientHeight - log.scrollTop < 3;
        var row = document.createElement("div");
        row.textContent = text;
        if (color) row.style.color = color;
        log.appendChild(row);
        if (atBottom) log.scrollTop = log.scrollHeight;
      }

      withTicket(url, start, function (msg) {
        line("✗ " + msg, "var(--acc-bad, #97233f)");
        markDeployUncertain(deployText(
          "the deploy could not be started — status is unknown",
          "не удалось запустить деплой — статус неизвестен"
        ));
        refreshDeployStatus(function () { scheduleDeployPoll(); }, true);
      });

      function start(ticketedUrl) {
        var es = new EventSource(ticketedUrl);

        es.addEventListener("step", function (ev) {
          var step = null;
          try { step = JSON.parse(ev.data); } catch (_) {}
          var panelForStep = deployPanel();
          if (panelForStep) {
            var stepGeneration = deployGeneration(panelForStep);
            var stepState = panelForStep.getAttribute("data-deploy-state");
            if (stepGeneration > startedGeneration
              && (stepState === "running" || stepState === "queued")) {
              // The first poll may already carry this operation's generation.
              startedGeneration = stepGeneration;
            }
          }
          if (step) {
            line((step.phase ? "[" + step.phase + "] " : "") + step.message,
              step.stream === "stderr" ? "var(--acc-bad, #97233f)" : null);
            applyDeployStep(step, startedGeneration);
          } else {
            line(ev.data);
          }
          scheduleDeployPoll(2000);
        });

        es.addEventListener("ok", function (ev) {
          done = true;
          var okMsg = null;
          try { okMsg = JSON.parse(ev.data).message; } catch (_) {}
          line("✓ " + (okMsg || "complete."), "var(--acc-good, #2c5f2d)");
          es.close();
          var panelNow = deployPanel();
          var currentTabOperation = panelNow && deployGeneration(panelNow) <= startedGeneration;
          if (panelNow && currentTabOperation) {
            panelNow.setAttribute("data-deploy-state", "running");
            panelNow.setAttribute("data-deploy-can-start", "false");
            deployField(panelNow, "[data-deploy-badge]", deployText("running", "выполняется"));
            deployField(panelNow, "[data-deploy-stage-phase]", "confirm");
            deployField(panelNow, "[data-deploy-stage-message]", deployText(
              "deployment complete — confirming the recorded result…",
              "деплой завершён — сверяю записанный результат…"
            ));
            deployField(panelNow, "[data-deploy-note]", deployText(
              "this page stays open; the authoritative status is being refreshed",
              "страница остаётся открытой; сверяю авторитетный статус"
            ));
          }
          syncDeployButton();
          var iconUse = btn.querySelector(".ed-icon use");
          if (iconUse) iconUse.setAttribute("href", "/admin/assets/icons.svg#check");
          refreshDeployStatus(function () { scheduleDeployPoll(); });
        });

        es.addEventListener("error", function (ev) {
          if (done) return;
          done = true;
          if (ev && ev.data) {
            var msg = deployText("deploy failed", "деплой не удался");
            try { msg = JSON.parse(ev.data).message || msg; } catch (_) {}
            if (msg.indexOf("deploy already running") !== -1) {
              line("ℹ " + deployText(
                "another deploy is running — waiting for its status…",
                "уже выполняется другой деплой — ждём его статус…"
              ), "var(--ink)");
              es.close();
              scheduleDeployPoll(2000);
              refreshDeployStatus(function () { scheduleDeployPoll(); });
              return;
            }
            line("✗ " + msg, "var(--acc-bad, #97233f)");
            es.close();
            applyDeployFailure(msg, startedGeneration);
            refreshDeployStatus(function () { scheduleDeployPoll(); });
            return;
          }
          line("✗ " + deployText(
            "connection lost — the operation may still be running; this page keeps checking its status",
            "соединение потеряно — операция может ещё выполняться; страница продолжает проверять статус"
          ), "var(--acc-bad, #97233f)");
          es.close();
          markDeployUncertain(deployText(
            "connection lost — the operation may still be running; status unknown while the page retries",
            "соединение потеряно — операция может ещё выполняться; статус неизвестен, страница повторяет проверку"
          ));
          refreshDeployStatus(function () { scheduleDeployPoll(); }, true);
        });
      }
    });
  }


  function protocolFocusTarget(section, next) {
    const active = document.activeElement;
    if (!section.contains(active)) return null;
    if (active.matches("summary")) {
      const index = Array.from(section.querySelectorAll("summary")).indexOf(active);
      return next.querySelectorAll("summary")[index] || next.querySelector("summary");
    }
    if (active.matches("a")) return [...next.querySelectorAll("a")].find(link => link.href === active.href);
    const action = active.form?.getAttribute("action");
    if (!action) return null;

    const opposite = { hide: "unhide", unhide: "hide", disable: "enable", enable: "disable" };
    const alternate = action.replace(/[^/]+$/, verb => opposite[verb] || verb);
    const match = Array.from(next.querySelectorAll("form button")).find(btn =>
      [action, alternate].includes(btn.form.getAttribute("action")));
    if (match) {
      const closed = match.closest("details:not([open])");
      return closed ? closed.querySelector("summary") : match;
    }
    // Some unsupported or legacy protocols have no control after disabling.
    // A neutral heading keeps a second key press from toggling another row.
    const heading = next.querySelector("h2");
    if (heading) heading.tabIndex = -1;
    return heading;
  }

  // Keep each native POST/redirect as the source of truth, but update the
  // protocol controls without navigating to the redirect's section anchor.
  function wireProtocolActions() {
    const section = document.getElementById("enabled-protocols");
    if (!section) return;
    const feedback = document.createElement("div");
    feedback.setAttribute("role", "status");
    feedback.className = "ed-sr-only";
    section.after(feedback);

    section.addEventListener("submit", async function (event) {
      const form = event.target;
      if (event.defaultPrevented || !form.closest(".ed-protocol")) return;
      const button = event.submitter || form.querySelector("button, input[type=submit]");
      if (!button || !form.hasAttribute("action")) return;
      event.preventDefault();
      if (section.hasAttribute("aria-busy")) return;
      section.setAttribute("aria-busy", "true");
      button.classList.add("is-loading");
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 15000);
      const unknown = deployText(
        "Could not verify the change. Refresh the page to check the saved state.",
        "Не удалось проверить результат. Обновите страницу, чтобы увидеть сохранённое состояние."
      );
      let message = unknown;
      try {
        const response = await fetch(form.action, {
          method: "POST", body: new URLSearchParams(new FormData(form)),
          mode: "same-origin", credentials: "same-origin", cache: "no-store", signal: controller.signal
        });
        if (!response.ok) {
          const plain = (response.headers.get("content-type") || "").startsWith("text/plain");
          message = "HTTP " + response.status + ". " + unknown;
          if (plain) message = (await response.text()).trim().slice(0, 500) || message;
          throw new Error("Protocol request failed");
        }
        const doc = new DOMParser().parseFromString(await response.text(), "text/html");
        const next = doc.getElementById(section.id);
        if (!next) throw new Error(unknown);

        const groups = section.querySelectorAll("details");
        next.querySelectorAll("details").forEach((group, index) => {
          group.open = !!groups[index] && groups[index].open;
        });
        const focusTarget = protocolFocusTarget(section, next);
        const main = pageScroller(section);
        const top = main.scrollTop;
        const protocol = form.closest("li").querySelector("strong")?.textContent || "";
        section.replaceChildren(...next.childNodes);
        section.querySelectorAll("form[data-confirm]").forEach(wireConfirm);
        // Only a membership change affects port diagnostics and this
        // protocol’s settings. Other forms may contain unsaved edits.
        document.querySelectorAll("[data-protocol-setting]").forEach(current => {
          if (!/\/(enable|disable)$/.test(form.action)) return;
          const key = current.dataset.protocolSetting;
          if (key !== "ports" && key !== protocol) return;
          const updated = doc.querySelector('[data-protocol-setting="' + key + '"]');
          if (updated && !current.isEqualNode(updated)) {
            current.replaceWith(updated);
            updated.querySelectorAll("form[data-confirm]").forEach(wireConfirm);
          }
        });
        if (focusTarget) focusTarget.focus({ preventScroll: true });
        main.scrollTop = top;
        feedback.className = "ed-sr-only";
        section.after(feedback);
        feedback.textContent = protocol + deployText(" — saved.", " — сохранено.");
      } catch {
        feedback.className = "ed-protocols__hint";
        const main = pageScroller(section);
        const top = button.getBoundingClientRect().top;
        form.closest("li").append(feedback);
        feedback.textContent = message;
        main.scrollTop += button.getBoundingClientRect().top - top;
      } finally {
        clearTimeout(timer);
        button.classList.remove("is-loading");
        section.removeAttribute("aria-busy");
      }
    });
  }

  function wireConfirm(form) {
    var msg = form.getAttribute("data-confirm");
    form.addEventListener("submit", function (e) {
      if (!window.confirm(msg)) e.preventDefault();
    });
  }

  function wireAutoSse(pre) {
    var url = pre.getAttribute("data-sse-autostart");
    if (!url) return;
    clearTimeout(reloadTimer);
    reloadTimer = null;
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
    function markPhase(phase, finished) {
      if (!steps) return;
      var idx = finished ? order.length : order.indexOf(phase);
      if (idx < 0) return;
      for (var k = 0; k <= idx && k < order.length; k++) {
        var complete = k < idx;
        var el = steps.querySelector('[data-step-phase="' + order[k] + '"] .step-mark');
        if (el) {
          var mark = el.querySelector(".ed-icon use");
          if (mark) {
            mark.setAttribute("href", "/admin/assets/icons.svg#" + (complete ? "check" : "clock"));
          } else {
            el.textContent = complete ? "✓" : "…";
          }
          el.setAttribute("aria-label", complete
            ? (document.documentElement.lang === "ru" ? "Готово" : "Complete")
            : (document.documentElement.lang === "ru" ? "Выполняется" : "In progress"));
          el.style.color = complete ? "var(--green)" : "var(--ink)";
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
      markPhase(null, true);
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
    if (document.getElementById("boosty-author-dashboard")) {
      function openSyncView() {
        var hash = window.location.hash;
        if (hash.indexOf("#quick_connect=") === 0) {
          window.location.replace("/admin/boosty?view=sync" + hash);
        }
      }
      openSyncView();
      window.addEventListener("hashchange", openSyncView);
      return;
    }

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

  function refreshCheckPanel(panel, url, errorSelector, apply) {
    var controller = new AbortController();
    var timeout = setTimeout(function () { controller.abort(); }, 15000);
    fetch(url, { credentials: "same-origin", cache: "no-store", signal: controller.signal })
      .then(function (response) {
        if (!response.ok) throw new Error("refresh failed");
        return response.text();
      })
      .then(function (text) {
        var next = new DOMParser().parseFromString(text, "text/html").getElementById(panel.id);
        if (!next) throw new Error("missing check state");
        apply(next);
      })
      .catch(function () {
        var error = panel.querySelector(errorSelector);
        panel.setAttribute("aria-busy", "false");
        if (error) error.hidden = false;
      })
      .finally(function () { clearTimeout(timeout); });
  }

  // The ordinary POST/redirect remains the source of truth. Poll only this
  // read-only fragment while a sweep is running; never replay a POST.
  function watchPrivateChecks() {
    var panel = document.getElementById("private-checks");
    if (!panel || panel.dataset.running !== "true") return;
    setTimeout(function () {
      refreshCheckPanel(panel, window.location.pathname, ".pc-poll-error", function (next) {
        // Avoid replacing focused controls or open details on each poll.
        if (next.dataset.running === "true") { watchPrivateChecks(); return; }
        var active = document.activeElement;
        var href = active && active.getAttribute("href");
        var summaries = Array.from(panel.querySelectorAll("summary"));
        var summaryIndex = summaries.indexOf(active);
        var focused = panel.contains(active);
        var openDetails = Array.from(panel.querySelectorAll("details")).map(function (d) { return d.open; });
        panel.replaceWith(next);
        next.querySelectorAll("details").forEach(function (d, i) { d.open = !!openDetails[i]; });
        if (focused) {
          var replacement = href ? Array.from(next.querySelectorAll("a")).find(function (a) { return a.getAttribute("href") === href; }) : null;
          if (summaryIndex >= 0) replacement = next.querySelectorAll("summary")[summaryIndex];
          if (!replacement) { replacement = next.querySelector("h1"); replacement.tabIndex = -1; }
          replacement.focus({ preventScroll: true });
        }
      });
    }, 1500);
  }

  // Refresh stored observations only. Starting a check always uses the ordinary
  // form, so a failed refresh can never replay a POST or create another run.
  function watchCheburcheckChecks() {
    var panel = document.getElementById("cheburcheck-checks");
    if (!panel || panel.dataset.refresh !== "true") return;
    setTimeout(function () {
      if (!panel.isConnected || panel.querySelector("form[data-submitting]")) return;
      refreshCheckPanel(panel, window.location.pathname + window.location.search, ".cc-poll-error", function (next) {
        if (!panel.isConnected || panel.querySelector("form[data-submitting]")) return;
        var active = document.activeElement;
        var focused = panel.contains(active);
        var activeId = focused && active.id;
        var href = focused && active.getAttribute("href");
        var detailKey = focused && active.tagName === "SUMMARY"
          ? active.parentElement.getAttribute("data-detail-key") : null;
        var details = {};
        panel.querySelectorAll("details[data-detail-key]").forEach(function (detail) {
          details[detail.getAttribute("data-detail-key")] = detail.open;
        });
        next.querySelectorAll("details[data-detail-key]").forEach(function (detail) {
          var key = detail.getAttribute("data-detail-key");
          if (Object.prototype.hasOwnProperty.call(details, key)) detail.open = details[key];
        });
        panel.replaceWith(next);
        if (focused) {
          var replacement = activeId ? Array.from(next.querySelectorAll("[id]")).find(function (item) {
            return item.id === activeId;
          }) : null;
          if (!replacement && href) replacement = Array.from(next.querySelectorAll("a")).find(function (item) {
            return item.getAttribute("href") === href;
          });
          if (!replacement && detailKey) {
            var detail = Array.from(next.querySelectorAll("details[data-detail-key]")).find(function (item) {
              return item.getAttribute("data-detail-key") === detailKey;
            });
            replacement = detail && detail.querySelector("summary");
          }
          if (!replacement || replacement.disabled) replacement = next.querySelector("h1");
          if (replacement) replacement.focus({ preventScroll: true });
        }
        watchCheburcheckChecks();
      });
    }, 2000);
  }

  // Copy confirmation for the single recommended delivery artefact. Kept
  // separate from the SSE start-ticket wiring so the two paths never share
  // listeners or transient state.
  function wireRecommendedCopy() {
    var buttons = document.querySelectorAll("[data-copy-recommended]");
    for (var i = 0; i < buttons.length; i++) {
      (function (button) {
        var resetTimer = null;
        button.addEventListener("click", function () {
          var target = document.getElementById(button.getAttribute("data-copy-recommended") || "");
          var status = document.getElementById(button.getAttribute("data-copy-status") || "");
          var value = target ? (target.value || target.textContent || "") : "";
          if (!value) return;
          var ru = document.documentElement.lang === "ru";
          function confirmCopy() {
            if (!status) return;
            status.textContent = ru ? "Скопировано" : "Copied";
            clearTimeout(resetTimer);
            resetTimer = setTimeout(function () { status.textContent = ""; }, 2200);
          }
          function fallback() {
            target.focus({ preventScroll: true });
            target.select();
            try {
              if (document.execCommand("copy")) {
                button.focus({ preventScroll: true });
                confirmCopy();
                return;
              }
            } catch (_) {}
            clearTimeout(resetTimer);
            if (status) status.textContent = ru
              ? "Ссылка выделена. Выберите «Копировать»."
              : "Link selected. Use Copy.";
          }
          if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(value).then(confirmCopy).catch(fallback);
          } else {
            fallback();
          }
        });
      })(buttons[i]);
    }
  }

  function wireDeployControls() {
    document.addEventListener("click", function (e) {
      var target = e.target;
      if (!target || !target.closest) return;
      var retry = target.closest("[data-deploy-retry]");
      if (retry) {
        e.preventDefault();
        var btn = deployButton();
        if (btn && !btn.disabled) {
          btn.click();
        } else {
          refreshDeployStatus(function () { scheduleDeployPoll(); });
        }
        return;
      }
      var refresh = target.closest("[data-deploy-refresh]");
      if (refresh) {
        e.preventDefault();
        refreshDeployStatus(function () { scheduleDeployPoll(); });
      }
    });
    document.addEventListener("visibilitychange", function () {
      if (document.visibilityState === "visible" && deployPanel()) scheduleDeployPoll(0);
    });
  }

  document.addEventListener("DOMContentLoaded", function () {
    watchPrivateChecks();
    watchCheburcheckChecks();
    wireSearchHotkey();
    wireSelectOnClick();
    wireRecommendedCopy();
    wireLowercaseId();
    wireProtocolActions();
    wireFormSubmitFeedback();
    wireBoostyQuickConnect();
    var nodes = document.querySelectorAll("[data-sse-url]");
    for (var i = 0; i < nodes.length; i++) {
      if (!nodes[i].hasAttribute("data-deploy-panel")) wireSse(nodes[i]);
    }
    var reloads = document.querySelectorAll("[data-reload-after]");
    if (reloads.length) {
      var secs = parseInt(reloads[0].getAttribute("data-reload-after"), 10) || 5;
      reloadTimer = setTimeout(function () { window.location.reload(); }, secs * 1000);
    }
    var deployButtons = document.querySelectorAll("[data-deploy-panel]");
    for (var d = 0; d < deployButtons.length; d++) wireDeploySse(deployButtons[d]);
    if (deployPanel()) {
      // Keep any unrelated status refresh unless a deploy is actually active;
      // an active deploy must not reload the page under the operator.
      var deployState = currentDeployState();
      if (deployState === "running" || deployState === "queued" || deployState === "unknown") {
        clearTimeout(reloadTimer);
        reloadTimer = null;
      }
      wireDeployControls();
      scheduleDeployPoll();
    }
    var autos = document.querySelectorAll("[data-sse-autostart]");
    for (var a = 0; a < autos.length; a++) wireAutoSse(autos[a]);
    var confirms = document.querySelectorAll("[data-confirm]");
    for (var c = 0; c < confirms.length; c++) wireConfirm(confirms[c]);
  });
})();
