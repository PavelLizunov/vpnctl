(() => {
  "use strict";
  const root = document.getElementById("corp-diagnostics");
  if (!root) return;
  const el = (id) => document.getElementById(`diagnostics-${id}`);
  const csrf = root.dataset.csrf;
  let cursor = null;
  let active = null;
  let listGeneration = 0;
  let detailGeneration = 0;
  let locked = false;
  let reports = [];
  let deleteTarget = null;
  let deleting = false;
  let deleteDialog;
  const states = {received: "Получен", pending: "Ожидает анализа", running: "Анализ выполняется", ready: "Анализ готов", failed: "Не удалось выполнить анализ", unavailable: "Анализ недоступен"};
  const verdicts = {problem_found: "Обнаружена проблема", no_problem_evidenced: "В проверенных данных проблема не обнаружена", insufficient_data: "Недостаточно данных"};
  const times = {current: "Текущая попытка", historical: "Исторические данные", unknown: "Время неизвестно"};
  const scopes = {update_delivery: "Доставка обновления", client_runtime: "Работа приложения", tunnel_and_policy: "Подключение и правила", evidence_quality: "Полнота данных"};
  const confidence = {high: "высокая", medium: "средняя", low: "низкая"};
  function node(tag, text, className) {
    const result = document.createElement(tag);
    if (text !== undefined && text !== null) result.textContent = String(text);
    if (className) result.className = className;
    return result;
  }
  function prepareInbox() {
    const toolbar = node("div", undefined, "diagnostics-toolbar");
    const field = node("div", undefined, "field");
    const label = node("label", "Найти отчёт");
    label.htmlFor = "diagnostics-search";
    const search = node("input");
    search.id = "diagnostics-search";
    search.type = "search";
    search.placeholder = "Устройство или дата";
    search.autocomplete = "off";
    field.append(label, search);
    toolbar.append(field);
    const found = node("p", "", "muted small");
    found.id = "diagnostics-found";
    found.setAttribute("role", "status");
    found.setAttribute("aria-live", "polite");
    el("list").before(toolbar, found);
    deleteDialog = node("dialog");
    deleteDialog.id = "diagnostics-delete-dialog";
    deleteDialog.setAttribute("aria-labelledby", "diagnostics-delete-title");
    deleteDialog.setAttribute("aria-describedby", "diagnostics-delete-description");
    const title = node("h2", "Удалить диагностику?");
    title.id = "diagnostics-delete-title";
    const description = node("p", "Отчёт и ZIP-архив будут удалены с сервера и освободят место. Отменить удаление на сайте нельзя.");
    description.id = "diagnostics-delete-description";
    const actions = node("div", undefined, "dialog-actions");
    for (const [id, text, className] of [["diagnostics-delete-cancel", "Оставить отчёт", ""], ["diagnostics-delete-confirm", "Удалить отчёт и архив", "remove"]]) {
      const button = node("button", text, className);
      button.id = id;
      button.type = "button";
      actions.append(button);
    }
    deleteDialog.append(title, description, actions);
    root.append(deleteDialog);
  }
  prepareInbox();
  function timestamp(value, exact = false) {
    if (!value) return "не указано";
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? value
      : exact ? `${date.toLocaleString("ru-RU")} (${value})` : date.toLocaleString("ru-RU");
  }
  function showError(message) {
    el("error").textContent = message;
    el("error").hidden = !message;
  }
  async function request(path, method = "GET") {
    const options = {method, credentials: "same-origin", cache: "no-store", redirect: "error"};
    if (method === "POST" || method === "DELETE") {
      options.headers = {"Content-Type": "application/json", "X-Corp-CSRF": csrf};
      options.body = "{}";
    }
    let response;
    try { response = await fetch(path, options); }
    catch { throw new Error("Нет ответа от сервера. Проверьте подключение и попробуйте снова."); }
    if (response.status === 401) {
      locked = true;
      el("login").hidden = false;
      throw new Error("Срок входа истёк. Войдите снова.");
    }
    if (!response.ok) {
      const messages = {403: "Подключите корпоративный VPN и обновите страницу.", 404: "Отчёт недоступен.", 409: "Анализ уже выполняется. Обновите отчёт позже.", 503: "Диагностика сейчас недоступна. Попробуйте позже. Правила продолжают работать."};
      throw new Error(messages[response.status] || "Не удалось выполнить запрос. Обновите страницу и попробуйте снова.");
    }
    if (response.status === 303) return null;
    try { return await response.json(); }
    catch { throw new Error("Не удалось прочитать ответ. Попробуйте позже."); }
  }
  function evidence(parent, items) {
    const list = node("ul", undefined, "evidence-list");
    for (const item of items || []) {
      const text = item.kind === "log" ? `${item.file}, строка ${item.line}` : `${item.kind === "operator_fact" ? "Проверенный факт" : "Поле отчёта"}: ${item.field}`;
      list.append(node("li", text));
    }
    if (list.children.length) parent.append(list);
  }
  function findings(parent, heading, items) {
    if (!items?.length) return;
    parent.append(node("h3", heading));
    for (const item of items) {
      const block = node("div", undefined, "finding");
      block.append(node("p", item.statement));
      if (item.time_scope) block.append(node("p", times[item.time_scope] || "Время неизвестно", "muted small"));
      evidence(block, item.evidence);
      parent.append(block);
    }
  }
  function disclosure(title, className) {
    const details = node("details", undefined, className);
    details.append(node("summary", title));
    return details;
  }
  function renderList() {
    const query = el("search").value.trim().toLocaleLowerCase("ru");
    const matches = reports.filter((r) => `${r.device_label || ""} ${timestamp(r.received_utc)}`.toLocaleLowerCase("ru").includes(query));
    el("list").replaceChildren();
    for (const report of matches) {
      const item = node("li");
      const button = node("button", undefined, "report-select");
      button.type = "button";
      button.dataset.report = report.report_id;
      button.setAttribute("aria-pressed", String(report.report_id === active));
      button.append(node("strong", timestamp(report.received_utc)), node("span", `Устройство: ${report.device_label || "не указано"}`, "report-device"), node("span", states[report.analysis_state] || "Неизвестно", "muted small"));
      button.addEventListener("click", () => loadDetail(report.report_id, true));
      item.append(button);
      el("list").append(item);
    }
    el("found").textContent = query ? `Найдено в загруженных отчётах: ${matches.length}` : `Загружено отчётов: ${reports.length}`;
    if (query && !matches.length) el("list").append(node("li", "Ничего не найдено. Измените поиск или очистите поле.", "muted"));
  }
  function renderDetail(data) {
    const report = data.report;
    const body = el("detail-body");
    body.replaceChildren();
    el("detail-title").textContent = "Отчёт приложения";
    body.append(node("p", `Получен: ${timestamp(report.received_utc)}`));
    body.append(node("p", `Состояние: ${states[report.analysis_state] || "Неизвестно"}`));
    const analysis = data.analysis;
    if (analysis && report.analysis_state !== "ready") {
      body.append(node("p", ["received", "pending", "running"].includes(report.analysis_state)
        ? "Ниже — предыдущий результат. Новый анализ ещё не завершён."
        : "Ниже — предыдущий результат. Последняя попытка не дала нового заключения.", "notice"));
    }
    const answer = node("section", undefined, "diagnosis-answer");
    answer.append(node("h3", "Коротко"));
    if (report.verdict) answer.append(node("p", verdicts[report.verdict] || "Недостаточно данных", "diagnosis-verdict"));
    if (analysis) answer.append(node("p", analysis.owner_explanation));
    else if (report.summary_ru) answer.append(node("p", report.summary_ru));
    body.append(answer);
    if (analysis) {
      const action = node("section", undefined, "diagnosis-action");
      action.append(node("h3", "Что сделать сейчас"));
      if (analysis.next_steps_ru?.length) {
        const steps = node("ol");
        for (const step of analysis.next_steps_ru) steps.append(node("li", step));
        action.append(steps);
      } else {
        action.append(node("p", "В этом отчёте нет подтверждённого решения. Отправьте свежую диагностику сразу после повторения проблемы."));
      }
      action.append(node("p", "Это рекомендации. Действия не выполняются автоматически.", "muted small"));
      body.append(action);
      const reasons = disclosure("Почему такой вывод", "diagnosis-reasons");
      for (const item of analysis.assessments || []) {
        const block = node("div", undefined, "finding");
        block.append(node("h3", scopes[item.scope] || item.scope));
        block.append(node("p", verdicts[item.verdict] || "Недостаточно данных"));
        block.append(node("p", `${times[item.time_scope] || "Время неизвестно"}; уверенность: ${confidence[item.confidence] || "не указана"}`, "muted small"));
        block.append(node("p", item.explanation_ru));
        evidence(block, item.evidence);
        reasons.append(block);
      }
      findings(reasons, "Подтверждённые наблюдения", analysis.confirmed);
      findings(reasons, "Вероятные объяснения", analysis.probable);
      findings(reasons, "Что остаётся неизвестным", analysis.unknown);
      body.append(reasons);
    } else {
      body.append(node("p", "Проверенного заключения пока нет. Это не подтверждает исправность подключения.", "notice"));
    }
    const technical = disclosure("Технический отчёт", "diagnosis-technical");
    technical.append(node("p", `Устройство (сообщено приложением): ${report.device_label || "не указано"}`));
    technical.append(node("p", "Название устройства не подтверждает личность отправителя.", "muted small"));
    technical.append(node("p", `Получен: ${timestamp(report.received_utc, true)}`));
    technical.append(node("p", `Обновлён: ${timestamp(report.updated_utc, true)}`));
    technical.append(node("p", `Номер отчёта: ${report.report_id}`, "muted small"));
    if (analysis) findings(technical, "Хронология", analysis.chronology);
    const provenance = data.provenance;
    technical.append(node("h3", "Сведения об анализе"));
    const labels = {requested_model: "Запрошенная модель", returned_model: "Ответившая модель", status: "Состояние выполнения", run_id: "Номер запуска", started_utc: "Начат", completed_utc: "Завершён", prompt_version: "Версия инструкции", prompt_sha256: "Отпечаток инструкции", input_sha256: "Отпечаток входных данных"};
    if (provenance) {
      const list = node("dl", undefined, "provenance");
      for (const [key, label] of Object.entries(labels)) {
        if (provenance[key]) list.append(node("dt", label), node("dd", key.endsWith("_utc") ? timestamp(provenance[key], true) : provenance[key]));
      }
      technical.append(list);
    } else technical.append(node("p", report.model ? `Модель: ${report.model}. Другие сведения пока недоступны.` : "Сведения о выполнении пока недоступны.", "muted"));
    body.append(technical);
    const refresh = node("button", "Обновить отчёт");
    refresh.type = "button";
    refresh.addEventListener("click", () => loadDetail(report.report_id));
    const actions = node("div", undefined, "diagnostics-detail-actions");
    actions.append(refresh);
    if (!["pending", "running"].includes(report.analysis_state)) {
      const retry = node("button", "Повторить анализ");
      retry.type = "button";
      retry.disabled = locked;
      retry.addEventListener("click", async () => {
        retry.disabled = true;
        showError("");
        try {
          await request(`/api/corp/reports/${report.report_id}/retry`, "POST");
          el("status").textContent = "Повторный анализ поставлен в очередь. Предыдущий результат сохранён.";
          await loadDetail(report.report_id);
        } catch (error) { showError(error.message); retry.disabled = locked; }
      });
      actions.append(retry);
    }
    const remove = node("button", "Удалить отчёт…", "remove");
    remove.type = "button";
    remove.disabled = locked;
    remove.addEventListener("click", () => {
      deleteTarget = report.report_id;
      deleteDialog.showModal();
      el("delete-cancel").focus();
    });
    actions.append(remove);
    body.append(actions);
  }
  async function loadDetail(id, focus = false) {
    if (locked) return;
    active = id;
    for (const button of el("list").querySelectorAll(".report-select")) {
      button.setAttribute("aria-pressed", String(button.dataset.report === id));
    }
    const generation = ++detailGeneration;
    el("detail").setAttribute("aria-busy", "true");
    el("detail-title").textContent = "Загружаем отчёт…";
    el("detail-body").replaceChildren();
    showError("");
    try {
      const data = await request(`/api/corp/reports/${id}`);
      if (generation !== detailGeneration) return;
      renderDetail(data);
      if (focus) el("detail").focus();
    } catch (error) {
      if (generation !== detailGeneration) return;
      el("detail-title").textContent = "Отчёт недоступен";
      showError(error.message);
    } finally {
      if (generation === detailGeneration) el("detail").setAttribute("aria-busy", "false");
    }
  }
  async function loadList(more = false) {
    if (locked) return;
    const generation = ++listGeneration;
    el("refresh").disabled = true;
    el("more").disabled = true;
    el("status").textContent = "Загружаем отчёты…";
    showError("");
    if (!more) { cursor = null; reports = []; el("list").replaceChildren(); }
    try {
      const query = cursor ? `&cursor=${encodeURIComponent(cursor)}` : "";
      const data = await request(`/api/corp/reports?limit=50${query}`);
      if (generation !== listGeneration) return;
      for (const report of data.reports) {
        const existing = reports.findIndex((item) => item.report_id === report.report_id);
        if (existing >= 0) reports[existing] = report;
        else reports.push(report);
      }
      renderList();
      cursor = data.next_cursor;
      el("more").hidden = !cursor;
      el("status").textContent = el("list").children.length ? "Выберите отчёт для просмотра анализа." : "Отчётов пока нет. Отправьте диагностику из приложения VPNRouter.";
    } catch (error) {
      if (generation !== listGeneration) return;
      el("status").textContent = "Список отчётов не загружен.";
      showError(error.message);
    } finally {
      if (generation === listGeneration) { el("refresh").disabled = locked; el("more").disabled = locked; }
    }
  }
  el("refresh").addEventListener("click", () => { loadList(); if (active) loadDetail(active); });
  el("more").addEventListener("click", () => loadList(true));
  el("search").addEventListener("input", renderList);
  el("delete-cancel").addEventListener("click", () => deleteDialog.close());
  deleteDialog.addEventListener("cancel", (event) => { if (deleting) event.preventDefault(); });
  deleteDialog.addEventListener("close", () => { deleteTarget = null; });
  el("delete-confirm").addEventListener("click", async () => {
    const target = deleteTarget;
    if (!target || deleting || locked) return;
    deleting = true;
    el("delete-confirm").disabled = true;
    el("delete-cancel").disabled = true;
    showError("");
    try {
      const result = await request(`/api/corp/reports/${target}`, "DELETE");
      if (result?.state !== "deleted") throw new Error("Не удалось подтвердить удаление. Обновите список отчётов.");
      active = null;
      detailGeneration += 1;
      el("detail-title").textContent = "Выберите отчёт";
      el("detail-body").replaceChildren(node("p", "Отчёт и его архив удалены с сервера.", "muted"));
      deleteDialog.close();
      await loadList();
      el("status").textContent = "Отчёт и архив удалены. Место на сервере освобождено.";
      el("refresh").focus();
    } catch (error) {
      deleteDialog.close();
      showError(error.message);
    } finally {
      deleting = false;
      el("delete-confirm").disabled = false;
      el("delete-cancel").disabled = false;
    }
  });
  el("logout").addEventListener("click", async () => {
    try {
      const response = await fetch("/logout", {method: "POST", credentials: "same-origin", headers: {"X-Corp-CSRF": csrf}});
      if (response.ok) window.location.assign("/diagnostics");
      else showError("Не удалось выйти. Обновите страницу.");
    } catch { showError("Нет ответа от сервера. Попробуйте снова."); }
  });
  loadList();
})();
