(() => {
  "use strict";

  const root = document.getElementById("boosty-inbox");
  const composer = document.getElementById("boosty-inbox-compose");
  const reply = document.getElementById("boosty-inbox-reply");
  const pending = document.getElementById("boosty-inbox-pending");
  const status = document.getElementById("boosty-inbox-status");
  if (!root?.dataset.blog || !status) return;

  const { blog, dialog } = root.dataset;
  const key = "vpnctl-boosty-inbox:" + blog + ":" + (dialog || "list");
  const ru = document.documentElement.lang === "ru";
  const tr = (en, russian) => ru ? russian : en;
  let busy = false;
  let requestId = composer?.dataset.requestId || saved("request");

  function saved(field) {
    try { return sessionStorage.getItem(key + ":" + field) || ""; }
    catch (_) { return ""; }
  }

  function store(field, value) {
    try {
      if (value) sessionStorage.setItem(key + ":" + field, value);
      else sessionStorage.removeItem(key + ":" + field);
    } catch (_) {}
  }

  function message(text, tone = "") {
    status.textContent = text;
    status.dataset.tone = tone;
  }

  function syncControls() {
    const writable = composer?.dataset.writable === "1";
    if (reply) reply.readOnly = !!requestId || !writable || busy;
    if (pending) pending.hidden = !requestId;
    root.querySelectorAll("[data-inbox-operation]").forEach(button => {
      const operation = button.dataset.inboxOperation;
      button.disabled = busy || (operation === "draft" && (!writable || !!requestId || !!reply?.value.trim()));
    });
    const send = composer?.querySelector('button[type="submit"]');
    if (send) send.disabled = busy || !writable || !!requestId || !reply.value.trim() || reply.value.length > 8000;
  }

  async function call(operation, args = {}) {
    const response = await fetch("/admin/boosty/inbox/action", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ operation, blog, dialogId: dialog || null, ...args }),
      signal: AbortSignal.timeout(120_000),
    });
    if (!response.ok) return {
      result: "error",
      status: response.status,
      not_dispatched: [400, 401, 403, 404, 413, 415, 422, 429].includes(response.status),
    };
    const wire = await response.text();
    const line = wire.split(/\r?\n/).find(line => line.startsWith("data: "));
    if (!line) throw new Error("Missing inbox result");
    return JSON.parse(line.slice(6));
  }

  function errorMessage(result, fallback) {
    if (result.status === 409) return tr(
      "The account or conversation changed, or an operation is still running. Reload the conversation and check its status.",
      "Аккаунт или переписка изменились либо операция ещё выполняется. Откройте переписку заново и проверьте статус.");
    return fallback;
  }

  function reload(text, before) {
    store("notice", text);
    const url = new URL(location.href);
    if (before) url.searchParams.set("before", before);
    else url.searchParams.delete("before");
    if (url.href === location.href) location.reload();
    else location.assign(url);
  }

  function uncertain() {
    if (requestId.startsWith("auto-")) {
      message(tr("Delivery of the automatic reply is unconfirmed. Check its status before replying.",
        "Отправка автоответа не подтверждена. Проверьте её статус перед новым ответом."), "warning");
      return;
    }
    message(tr("Delivery has not been confirmed. Check its status before sending another reply.",
      "Boosty пока не подтвердил отправку. Проверьте её статус перед новым ответом."), "warning");
  }

  function applyReply(result) {
    const receipt = result.reply;
    if (result.result !== "reply" || receipt?.dialogId !== dialog || receipt.requestId !== requestId) {
      uncertain();
      return;
    }
    if (["sent", "rejected", "cancelled"].includes(receipt.status)) {
      requestId = "";
      store("request", "");
    }
    if (receipt.status === "sent") {
      reply.value = "";
      reload(tr("Reply sent.", "Ответ отправлен."));
    } else if (receipt.status === "rejected") {
      message(tr("Boosty rejected this reply. The text is ready to edit.",
        "Boosty отклонил ответ. Текст можно отредактировать."), "warning");
    } else if (receipt.status === "cancelled") {
      message(tr("The check is closed. You can edit the text and start a new reply.",
        "Проверка закрыта. Можно отредактировать текст и отправить новый ответ."));
    } else {
      uncertain();
    }
  }

  function newRequestId() {
    return Array.from(crypto.getRandomValues(new Uint8Array(16)), b => b.toString(16).padStart(2, "0")).join("");
  }

  async function run(operation, args, work) {
    if (busy) return;
    busy = true;
    syncControls();
    message(tr("Working…", "Выполняется…"));
    try { work(await call(operation, args)); }
    catch (_) {
      if (requestId) uncertain();
      else message(tr("Boosty did not return a result. Try again.", "Boosty не вернул результат. Попробуйте ещё раз."), "warning");
    } finally {
      busy = false;
      syncControls();
    }
  }

  root.addEventListener("click", event => {
    const button = event.target.closest("button[data-inbox-operation]");
    if (!button || button.disabled || busy) return;
    const { inboxOperation: operation, dialog: target, offset, generation, before } = button.dataset;
    if (operation === "refresh") {
      void run(operation, {
        dialogId: target || null, offset: offset || null,
        historyGeneration: generation === undefined ? null : Number(generation),
      }, result => {
        if (result.result === "done") reload(tr("Inbox updated.", "Переписки обновлены."), before);
        else message(errorMessage(result, tr("Could not refresh the inbox.", "Не удалось обновить переписки.")), "warning");
      });
    } else if (operation === "draft" && !requestId && reply && !reply.value.trim()) {
      const topic = document.getElementById("boosty-inbox-topic")?.value || "";
      void run(operation, { topic }, result => {
        if (result.result === "draft" && typeof result.text === "string" && result.text.trim()) {
          reply.value = result.text;
          message(tr("Draft prepared. Review it before sending.", "Черновик готов. Проверьте его перед отправкой."));
        } else message(errorMessage(result, tr("No draft was returned. Write a reply manually.",
          "Черновик не подготовлен. Можно написать ответ вручную.")), "warning");
      });
    } else if (requestId && (operation === "reconcile" || operation === "abandon")) {
      if (operation === "abandon" && !window.confirm(tr(
        "Close this check only after verifying the conversation. Close it now?",
        "Закрывайте проверку после просмотра переписки. Закрыть сейчас?"))) return;
      void run(operation, { requestId, text: reply?.value.trim() || null }, result => {
        if (result.result === "error") message(errorMessage(result, tr("The delivery status is still uncertain.",
          "Результат отправки всё ещё не подтверждён.")), "warning");
        else applyReply(result);
      });
    }
  });

  if (reply && composer) {
    if (requestId) store("request", requestId);
    reply.addEventListener("input", syncControls);
    composer.addEventListener("submit", event => {
      event.preventDefault();
      const text = reply.value.trim();
      if (busy || requestId || !text || text.length > 8000 || composer.dataset.writable !== "1") return;
      requestId = newRequestId();
      store("request", requestId);
      void run("send", { requestId, text }, result => {
        if (result.result === "error" && result.not_dispatched === true) {
          requestId = "";
          store("request", "");
          message(errorMessage(result, tr("This reply was not sent. You can edit it and try again.",
            "Ответ не отправлен. Его можно отредактировать и отправить снова.")), "warning");
        } else applyReply(result);
      });
    });
  }

  const notice = saved("notice");
  if (notice) {
    store("notice", "");
    message(notice);
  }
  if (requestId && dialog) {
    uncertain();
    void run("check", { requestId }, applyReply);
  }
  if (dialog) void call("viewed").catch(() => {});
  syncControls();
})();
