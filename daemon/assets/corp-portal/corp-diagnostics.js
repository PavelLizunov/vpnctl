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
  function timestamp(value) {
    if (!value) return "не указано";
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? value : `${date.toLocaleString("ru-RU")} (${value})`;
  }
  function showError(message) {
    el("error").textContent = message;
    el("error").hidden = !message;
  }
  async function request(path, method = "GET") {
    const options = {method, credentials: "same-origin", cache: "no-store", redirect: "error"};
    if (method === "POST") {
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
  function renderDetail(data) {
    const report = data.report;
    const body = el("detail-body");
    body.replaceChildren();
    el("detail-title").textContent = "Отчёт приложения";
    body.append(node("p", `Получен: ${timestamp(report.received_utc)}`));
    body.append(node("p", `Устройство (сообщено приложением): ${report.device_label || "не указано"}`));
    body.append(node("p", `Состояние: ${states[report.analysis_state] || "Неизвестно"}`));
    if (report.verdict) body.append(node("p", verdicts[report.verdict] || "Недостаточно данных", "diagnosis-verdict"));
    if (report.summary_ru) body.append(node("p", report.summary_ru));
    body.append(node("p", `Обновлён: ${timestamp(report.updated_utc)}`, "muted small"));
    body.append(node("p", `Номер отчёта: ${report.report_id}`, "muted small"));
    const analysis = data.analysis;
    if (analysis) {
      body.append(node("h3", "Объяснение"), node("p", analysis.owner_explanation));
      for (const item of analysis.assessments || []) {
        const block = node("div", undefined, "finding");
        block.append(node("h3", scopes[item.scope] || item.scope));
        block.append(node("p", verdicts[item.verdict] || "Недостаточно данных"));
        block.append(node("p", `${times[item.time_scope] || "Время неизвестно"}; уверенность: ${confidence[item.confidence] || "не указана"}`, "muted small"));
        block.append(node("p", item.explanation_ru));
        evidence(block, item.evidence);
        body.append(block);
      }
      findings(body, "Подтверждённые наблюдения", analysis.confirmed);
      findings(body, "Вероятные объяснения", analysis.probable);
      findings(body, "Что остаётся неизвестным", analysis.unknown);
      findings(body, "Хронология", analysis.chronology);
      if (analysis.next_steps_ru?.length) {
        body.append(node("h3", "Следующий шаг"));
        const steps = node("ol");
        for (const step of analysis.next_steps_ru) steps.append(node("li", step));
        body.append(steps);
      }
      body.append(node("p", "Анализ носит рекомендательный характер. Приложение не выполняет предложенные действия автоматически.", "muted small"));
    } else {
      body.append(node("p", "Проверенного заключения пока нет. Это не подтверждает исправность подключения.", "notice"));
    }
    const provenance = data.provenance;
    body.append(node("h3", "Сведения об анализе"));
    const labels = {requested_model: "Запрошенная модель", returned_model: "Ответившая модель", status: "Состояние выполнения", run_id: "Номер запуска", started_utc: "Начат", completed_utc: "Завершён", prompt_version: "Версия инструкции", prompt_sha256: "Отпечаток инструкции", input_sha256: "Отпечаток входных данных"};
    if (provenance) {
      const list = node("dl", undefined, "provenance");
      for (const [key, label] of Object.entries(labels)) {
        if (provenance[key]) list.append(node("dt", label), node("dd", key.endsWith("_utc") ? timestamp(provenance[key]) : provenance[key]));
      }
      body.append(list);
    } else body.append(node("p", report.model ? `Модель: ${report.model}. Другие сведения пока недоступны.` : "Сведения о выполнении пока недоступны.", "muted"));
    const refresh = node("button", "Обновить отчёт");
    refresh.type = "button";
    refresh.addEventListener("click", () => loadDetail(report.report_id));
    body.append(refresh);
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
      body.append(retry);
    }
  }
  async function loadDetail(id, focus = false) {
    if (locked) return;
    active = id;
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
    if (!more) { cursor = null; el("list").replaceChildren(); }
    try {
      const query = cursor ? `&cursor=${encodeURIComponent(cursor)}` : "";
      const data = await request(`/api/corp/reports?limit=50${query}`);
      if (generation !== listGeneration) return;
      for (const report of data.reports) {
        const item = node("li");
        const button = node("button", undefined, "report-select");
        button.type = "button";
        button.append(node("strong", timestamp(report.received_utc)), node("span", `Устройство (сообщено приложением): ${report.device_label || "не указано"}`), node("span", states[report.analysis_state] || "Неизвестно", "muted small"));
        if (report.summary_ru) button.append(node("span", report.summary_ru));
        button.addEventListener("click", () => loadDetail(report.report_id, true));
        item.append(button);
        el("list").append(item);
      }
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
  el("logout").addEventListener("click", async () => {
    try {
      const response = await fetch("/logout", {method: "POST", credentials: "same-origin", headers: {"X-Corp-CSRF": csrf}});
      if (response.ok) window.location.assign("/diagnostics");
      else showError("Не удалось выйти. Обновите страницу.");
    } catch { showError("Нет ответа от сервера. Попробуйте снова."); }
  });
  loadList();
})();
