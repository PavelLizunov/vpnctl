(() => {
  "use strict";
  const root = document.getElementById("corp-phone-editor");
  if (!root) return;
  const endpoint = "/api/v1/corp/portal/telephony";
  const node = (tag, text, className) => {
    const element = document.createElement(tag);
    if (text !== undefined) element.textContent = text;
    if (className) element.className = className;
    return element;
  };
  const button = (text, action) => {
    const element = node("button", text);
    element.type = "button";
    element.addEventListener("click", action);
    return element;
  };
  const select = (values) => {
    const element = node("select");
    for (const [value, title] of values) {
      const option = node("option", title);
      option.value = value;
      element.append(option);
    }
    return element;
  };
  const field = (title, input) => {
    input.setAttribute("aria-label", title);
    const label = node("label", title, "field");
    label.append(input);
    return label;
  };
  const routes = [["direct", "Напрямую — без VPN"], ["proxy", "Через VPN"]];
  let rules = [], revision = 0, csrf = "", saved = "[]", candidate = null;
  let busy = false, ready = false, stale = false;
  const status = node("p", "Загружаем телефонию…", "notice");
  status.setAttribute("role", "status");
  status.setAttribute("aria-live", "polite");
  const error = node("p", "", "notice error");
  error.hidden = true;
  error.setAttribute("role", "alert");
  const warning = node("p", "Для редактируемой телефонии нужна Corp-версия приложения 2.50.10 или новее. Старые версии сохраняют встроенные исключения. Сохранение на сервере не подтверждает получение правил приложением или исправность звонка.", "notice warning");
  const summary = node("p", "", "muted small");
  const list = node("div", undefined, "phone-rule-list");
  const addPanel = node("details", undefined, "add-site-panel");
  addPanel.append(node("summary", "Добавить адрес телефонии"));
  const form = node("form");
  const kind = select([["domain_suffix", "Домен и поддомены"], ["ip_cidr", "IPv4-адрес или подсеть"]]);
  const address = node("input");
  address.type = "text";
  address.maxLength = 4096;
  address.autocomplete = "off";
  address.spellcheck = false;
  address.placeholder = "example.com";
  address.required = true;
  const normalize = node("button", "Проверить адрес");
  normalize.type = "submit";
  form.append(field("Тип адреса", kind), field("Адрес", address), normalize);
  const preview = node("div", undefined, "preview");
  preview.hidden = true;
  const normalized = node("strong");
  const previewText = node("p", "Будет добавлен адрес: ");
  previewText.append(normalized);
  const action = select(routes);
  const note = node("input");
  note.type = "text";
  note.maxLength = 256;
  const notes = node("details");
  notes.append(node("summary", "Заметка (необязательно)"), field("Заметка", note));
  const add = button("Добавить в список телефонии", () => {
    if (!candidate || busy || stale) return;
    if (rules.length >= 64) { fail(new Error("В телефонии уже 64 адреса. Удалите ненужный адрес.")); return; }
    if (!validComment(note.value)) { fail(new Error("Заметка: максимум 256 байт UTF-8, без управляющих символов.")); return; }
    rules.push({ type: candidate.type, value: candidate.value, action: action.value, comment: note.value });
    candidate = null;
    preview.hidden = true;
    address.value = "";
    note.value = "";
    render();
    status.textContent = "Адрес добавлен в черновик телефонии. Сохраните телефонию.";
  });
  preview.append(previewText, field("Маршрут", action), notes, add);
  addPanel.append(form, preview);
  const timing = select([["next_connection", "При следующем подключении VPN"], ["now", "Сейчас, с возможным перерывом VPN"]]);
  const interrupt = node("input");
  interrupt.type = "checkbox";
  const interruptLabel = node("label", undefined, "check-label");
  interruptLabel.append(interrupt, node("span", "Подтверждаю возможный перерыв связи у подключённых приложений"));
  interruptLabel.hidden = true;
  timing.addEventListener("change", () => { interrupt.checked = false; interruptLabel.hidden = timing.value !== "now"; update(); });
  interrupt.addEventListener("change", update);
  const save = button("Сохранить телефонию", () => run(async () => {
    const result = await api("/rules", { expected_revision: revision, apply: timing.value, confirm_interrupt: interrupt.checked, rules });
    checkRevision(result);
    revision = result.revision;
    saved = JSON.stringify(rules);
    render();
    published();
    if (history.open) await loadHistory();
  }));
  save.className = "primary";
  const reload = button("Загрузить актуальную телефонию", () => {
    if (window.corpPhoneDirty && !window.confirm("Заменить несохранённый черновик телефонии списком с сервера?")) return;
    run(load);
  });
  const history = node("details");
  history.append(node("summary", "История телефонии"));
  const historyStatus = node("p", "Откройте историю телефонии, чтобы загрузить версии.", "muted small");
  const historyList = node("ol", undefined, "history-list");
  const refreshHistory = button("Обновить историю телефонии", () => run(loadHistory));
  history.append(historyStatus, refreshHistory, historyList);
  history.addEventListener("toggle", () => { if (history.open && ready && !busy) run(loadHistory); });
  root.append(warning, status, error, summary, list, addPanel, field("Когда применить телефонию", timing), interruptLabel, save, reload, history);

  function validComment(value) {
    return new TextEncoder().encode(value).length <= 256 && !/[\u0000-\u001f\u007f-\u009f]/u.test(value);
  }
  function update() {
    window.corpPhoneDirty = JSON.stringify(rules) !== saved;
    for (const control of root.querySelectorAll("input,select,button")) control.disabled = busy || !ready || stale;
    reload.disabled = busy;
    save.disabled ||= (!window.corpPhoneDirty && revision !== 0) || (timing.value === "now" && !interrupt.checked);
    summary.textContent = `Телефония: ${rules.length} из 64 адресов · ${revision ? `версия ${revision}` : "ещё не опубликована, показаны исходные правила"}${window.corpPhoneDirty ? " · есть несохранённые изменения" : ""}`;
  }
  function render() {
    list.replaceChildren();
    rules.forEach((rule, index) => {
      const row = node("div", undefined, "phone-rule-row");
      const heading = node("div");
      heading.append(node("strong", rule.value), node("p", rule.type === "domain_suffix" ? "Домен и все его поддомены" : "IPv4-адрес или подсеть", "muted small"));
      const route = select(routes);
      route.value = rule.action;
      route.dataset.action = rule.action;
      route.className = "route-choice";
      route.addEventListener("change", () => { rule.action = route.value; route.dataset.action = route.value; update(); });
      const comment = node("input");
      comment.type = "text";
      comment.value = rule.comment;
      comment.maxLength = 256;
      comment.addEventListener("input", () => { rule.comment = comment.value; update(); });
      const details = node("details");
      details.append(node("summary", "Заметка (необязательно)"), field("Заметка", comment));
      const remove = button("Удалить адрес", () => { rules.splice(index, 1); render(); });
      remove.setAttribute("aria-label", `Удалить ${rule.value} из телефонии`);
      row.append(heading, field("Маршрут", route), details, remove);
      list.append(row);
    });
    if (!rules.length) list.append(node("p", "Телефония пуста. Сохраните пустой список, чтобы убрать прежние исключения телефонии."));
    update();
  }
  function fail(failure) {
    error.textContent = failure.message || "Не удалось выполнить действие. Проверьте подключение.";
    error.hidden = false;
  }
  async function run(task) {
    if (busy) return;
    busy = true;
    error.hidden = true;
    update();
    try { await task(); } catch (failure) { fail(failure); } finally { busy = false; update(); }
  }
  async function api(path, body) {
    let response;
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), 30000);
    try {
      response = await fetch(endpoint + path, { method: body === undefined ? "GET" : "POST", credentials: "same-origin", cache: "no-store", signal: controller.signal, headers: body === undefined ? {} : { "Content-Type": "application/json", "X-Corp-CSRF": csrf }, body: body === undefined ? undefined : JSON.stringify(body) });
    } catch {
      if (["/rules", "/restore"].includes(path)) stale = true;
      throw new Error("Нет ответа сервера. Черновик телефонии сохранён на странице; загрузите актуальную телефонию перед дальнейшим сохранением.");
    } finally { window.clearTimeout(timeout); }
    const data = await response.json().catch(() => null);
    if (["/rules", "/restore"].includes(path) && (!data || response.status >= 500)) stale = true;
    if (!response.ok) {
      if ([401, 403, 409].includes(response.status)) stale = true;
      throw new Error(data?.message || "Телефония сейчас недоступна. Попробуйте снова.");
    }
    return data;
  }
  async function load() {
    const data = await api("");
    if (!data || !Number.isSafeInteger(data.revision) || data.revision < 0 || typeof data.csrf !== "string" || !data.csrf || !Array.isArray(data.rules) || data.rules.length > 64 || data.rules.some((rule) => !rule || !["domain_suffix", "ip_cidr"].includes(rule.type) || typeof rule.value !== "string" || typeof rule.comment !== "string" || !routes.some(([value]) => value === rule.action))) throw new Error("Не удалось прочитать телефонию.");
    revision = data.revision;
    csrf = data.csrf;
    rules = data.rules.map(({ type, value, action, comment }) => ({ type, value, action, comment }));
    saved = JSON.stringify(rules);
    ready = true;
    stale = false;
    candidate = null;
    preview.hidden = true;
    render();
    status.textContent = revision ? "Телефония загружена." : "Проверьте исходные пять адресов и явно сохраните телефонию. До этого отдельный список не опубликован.";
  }
  function checkRevision(result) {
    if (!result || !Number.isSafeInteger(result.revision) || result.revision <= revision) { stale = true; throw new Error("Не удалось подтвердить сохранение телефонии. Загрузите актуальную телефонию."); }
  }
  function published() {
    status.textContent = "Телефония сохранена на сервере. " + (timing.value === "now" ? "Обновлённые приложения смогут получить её и переподключить VPN; получение ещё не подтверждено." : "Обновлённые приложения смогут использовать её при следующем подключении VPN.");
  }
  async function loadHistory() {
    const entries = await api("/history");
    if (!Array.isArray(entries) || entries.some((entry) => !entry || !Number.isSafeInteger(entry.revision) || entry.revision < 1 || !Number.isSafeInteger(entry.published_at) || entry.published_at < 1 || !Number.isSafeInteger(entry.rule_count) || entry.rule_count < 0 || entry.rule_count > 64)) throw new Error("Не удалось прочитать историю телефонии.");
    historyList.replaceChildren();
    for (const entry of entries) {
      const item = node("li");
      const restore = button("Восстановить телефонию…", () => {
        if (timing.value === "now" && !interrupt.checked) { fail(new Error("Подтвердите возможный перерыв связи.")); return; }
        if (!window.confirm(`Заменить весь список телефонии версией ${entry.revision}? Несохранённый черновик телефонии будет заменён. Правила сайтов сохранятся.`)) return;
        run(async () => {
          const result = await api("/restore", { expected_revision: revision, revision: entry.revision, apply: timing.value, confirm_interrupt: interrupt.checked });
          checkRevision(result);
          stale = true;
          await load();
          published();
          await loadHistory();
        });
      });
      item.append(node("p", `Телефония: версия ${entry.revision} · ${new Date(entry.published_at * 1000).toLocaleString("ru")} · адресов: ${entry.rule_count}`), restore);
      historyList.append(item);
    }
    historyStatus.textContent = entries.length ? "Восстановление создаёт новую версию только телефонии. Время — по вашему часовому поясу." : "Сохранённых версий телефонии пока нет.";
    update();
  }
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    run(async () => {
      candidate = null;
      preview.hidden = true;
      const result = await api("/normalize", { type: kind.value, value: address.value });
      if (!result || result.type !== kind.value || typeof result.value !== "string" || !result.value) throw new Error("Не удалось проверить адрес.");
      if (rules.some((rule) => rule.type === result.type && rule.value === result.value)) throw new Error("Этот адрес уже есть в телефонии.");
      candidate = result;
      normalized.textContent = result.value;
      preview.hidden = false;
      status.textContent = "Адрес проверен. Выберите маршрут и добавьте его в список телефонии.";
    });
  });
  for (const input of [kind, address]) input.addEventListener("input", () => { candidate = null; preview.hidden = true; });
  window.addEventListener("beforeunload", (event) => { if (window.corpPhoneDirty) { event.preventDefault(); event.returnValue = ""; } });
  run(load);
})();
