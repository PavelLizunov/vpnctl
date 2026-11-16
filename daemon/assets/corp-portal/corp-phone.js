(() => {
  "use strict";
  const root = document.getElementById("corp-phone-editor");
  if (!root) return;
  const endpoint = "/api/v1/corp/portal/telephony";
  const { node, field, routeOptions: routes, createPager, confirmAction } = window.corpPortal;
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
  let rules = [], revision = 0, csrf = "", saved = "[]", candidate = null;
  let busy = false, ready = false, stale = false, page = 0;
  const pageSize = 10;
  const status = node("p", "Загружаем телефонию…", "muted small");
  status.setAttribute("role", "status");
  status.setAttribute("aria-live", "polite");
  const error = node("p", "", "notice error");
  error.hidden = true;
  error.setAttribute("role", "alert");
  const help = node("details");
  help.append(node("summary", "Как работают правила телефонии"), node("p", "Нужна Corp-версия приложения 2.50.10 или новее. Старые версии сохраняют встроенные исключения.", "muted small"), node("p", "Сохранение на сервере не подтверждает получение правил приложением или исправность звонка.", "muted small"));
  const summary = node("p", "", "muted small");
  const heading = node("div", undefined, "section-heading");
  const title = node("div", undefined, "section-title");
  const count = node("p", "", "muted small");
  title.append(node("h2", "Адреса телефонии"), count);
  const addPanel = node("details", undefined, "add-site-panel");
  addPanel.id = "add-phone-panel";
  addPanel.append(node("summary", "Добавить адрес"));
  const openAdd = button("Добавить адрес", () => {
    addPanel.open = !addPanel.open;
    openAdd.setAttribute("aria-expanded", String(addPanel.open));
    if (addPanel.open) address.focus();
  });
  openAdd.setAttribute("aria-controls", addPanel.id);
  openAdd.setAttribute("aria-expanded", "false");
  addPanel.addEventListener("toggle", () => openAdd.setAttribute("aria-expanded", String(addPanel.open)));
  heading.append(title, openAdd);
  const toolbar = node("div", undefined, "workspace-toolbar");
  const search = node("input");
  search.type = "search";
  search.id = "phone-search";
  search.placeholder = "Адрес или заметка…";
  search.autocomplete = "off";
  const routeFilter = select([["all", "Все маршруты"], ...routes]);
  routeFilter.id = "phone-route-filter";
  const showNotes = node("input");
  showNotes.type = "checkbox";
  showNotes.id = "phone-show-notes";
  const notesText = node("span", "Заметки");
  const notesToggle = node("label", undefined, "notes-toggle");
  notesToggle.append(showNotes, notesText);
  toolbar.append(field("Поиск", search), field("Как открывать", routeFilter), notesToggle);
  const table = node("table", undefined, "rules-table");
  table.setAttribute("aria-label", "Правила телефонии");
  const thead = node("thead");
  const columns = node("tr");
  for (const title of ["Адрес", "Как открывать", "Заметка", "Действия"]) {
    const th = node("th", title);
    th.scope = "col";
    if (title === "Действия") th.replaceChildren(node("span", title, "sr-only"));
    columns.append(th);
  }
  thead.append(columns);
  const list = node("tbody", undefined, "phone-rule-list");
  table.append(thead, list);
  const pager = createPager("phone-rules", (nextPage) => { page = nextPage; render(); });
  for (const control of [search, routeFilter]) control.addEventListener("input", () => { page = 0; render(); });
  showNotes.addEventListener("change", () => table.classList.toggle("show-notes", showNotes.checked));
  const addBody = node("div", undefined, "add-site-body");
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
    search.value = "";
    routeFilter.value = "all";
    page = Math.floor((rules.length - 1) / pageSize);
    render();
    status.textContent = "Адрес добавлен в черновик телефонии. Сохраните телефонию.";
  });
  const previewFields = node("div", undefined, "preview-fields");
  previewFields.append(field("Как открывать", action), notes, add);
  preview.append(previewText, previewFields);
  addBody.append(form, preview);
  addPanel.append(addBody);
  const save = button("Сохранить изменения", () => savePolicy(false));
  save.className = "primary";
  const applyNow = button("Применить сейчас…", () => savePolicy(true));
  const reload = button("Отменить изменения", () => run(async () => {
    if (window.corpPhoneDirty && !await confirmAction({ title: "Загрузить телефонию с сервера?", description: "Несохранённый черновик телефонии будет заменён. Правила сайтов сохранятся.", confirmText: "Загрузить" })) return;
    await load();
  }));
  reload.className = "quiet";
  const saveBar = node("div", undefined, "save-bar");
  const saveMessage = node("div");
  const saveTitle = node("p", "", "save-title");
  saveMessage.append(saveTitle, node("p", "Обычное сохранение — при следующем подключении VPN.", "muted small"));
  const saveActions = node("div", undefined, "actions");
  saveActions.append(save, applyNow, reload);
  saveBar.append(saveMessage, saveActions);
  const history = node("details", undefined, "card");
  history.append(node("summary", "История телефонии"));
  const historyStatus = node("p", "Откройте историю телефонии, чтобы загрузить версии.", "muted small");
  const historyList = node("ol", undefined, "history-list");
  const refreshHistory = button("Обновить историю телефонии", () => run(loadHistory));
  history.append(historyStatus, refreshHistory, historyList);
  history.addEventListener("toggle", () => { if (history.open && ready && !busy) run(loadHistory); });
  const feedback = node("div", undefined, "section-feedback");
  const statusLine = node("div", undefined, "status-panel");
  statusLine.append(status, summary);
  feedback.append(statusLine, error);
  const panel = root.closest(".voice-rules");
  panel.before(feedback);
  help.className = "route-help";
  panel.after(help, history);
  function showSection() {
    const inactive = location.hash !== "#telephony";
    for (const element of [feedback, help, history]) element.hidden = inactive;
  }
  window.addEventListener("hashchange", showSection);
  showSection();
  root.append(heading, addPanel, toolbar, pager.element, table, saveBar);

  function validComment(value) {
    return new TextEncoder().encode(value).length <= 256 && !/[\u0000-\u001f\u007f-\u009f]/u.test(value);
  }
  function update() {
    window.corpPhoneDirty = JSON.stringify(rules) !== saved;
    root.setAttribute("aria-busy", String(busy));
    for (const control of [...root.querySelectorAll("input,select,button"), ...history.querySelectorAll("button")]) control.disabled = busy || !ready || stale || control.dataset.pageBoundary === "true";
    reload.disabled = busy;
    reload.hidden = !stale && !window.corpPhoneDirty;
    reload.textContent = stale ? "Загрузить актуальный список" : "Отменить изменения";
    save.disabled ||= !window.corpPhoneDirty && revision !== 0;
    applyNow.disabled = save.disabled;
    add.disabled ||= candidate === null;
    count.textContent = `Всего адресов: ${rules.length}`;
    const notesCount = rules.filter((rule) => rule.comment).length;
    const notesLabel = notesCount ? `Заметки (${notesCount})` : "Заметки";
    if (notesText.textContent !== notesLabel) notesText.textContent = notesLabel;
    summary.textContent = revision ? `Версия ${revision}` : "Исходные правила · ещё не опубликованы";
    saveTitle.textContent = window.corpPhoneDirty ? "Есть изменения в списке" : revision === 0 ? "Сохраните начальный список" : "Все изменения сохранены";
  }
  function render() {
    list.replaceChildren();
    const query = search.value.trim().toLocaleLowerCase("ru");
    const visible = rules.map((rule, index) => ({ rule, index })).filter(({ rule }) => (routeFilter.value === "all" || rule.action === routeFilter.value) && (!query || `${rule.value} ${rule.comment}`.toLocaleLowerCase("ru").includes(query)));
    page = Math.max(0, Math.min(page, Math.ceil(visible.length / pageSize) - 1));
    for (const { rule, index } of visible.slice(page * pageSize, (page + 1) * pageSize)) {
      const row = node("tr");
      const addressCell = node("td");
      addressCell.append(node("strong", rule.value, "site-name"), node("p", rule.type === "domain_suffix" ? "Домен и поддомены" : "IPv4-адрес или подсеть", "muted small"));
      const route = select(routes);
      route.value = rule.action;
      route.dataset.action = rule.action;
      route.className = "route-choice";
      route.setAttribute("aria-label", `Как открывать ${rule.value}`);
      route.addEventListener("change", () => {
        rule.action = route.value;
        route.dataset.action = route.value;
        if (routeFilter.value === "all") update();
        else { render(); routeFilter.focus(); }
      });
      const routeCell = node("td");
      routeCell.append(node("span", "Как открывать", "mobile-label"), route);
      const comment = node("input");
      comment.type = "text";
      comment.value = rule.comment;
      comment.maxLength = 256;
      comment.setAttribute("aria-label", `Заметка к ${rule.value}`);
      comment.addEventListener("input", () => { rule.comment = comment.value; update(); });
      const noteCell = node("td");
      noteCell.append(node("span", "Заметка (необязательно)", "mobile-label"), comment);
      const remove = button("Удалить", () => { rules.splice(index, 1); render(); });
      remove.className = "remove";
      remove.setAttribute("aria-label", `Удалить ${rule.value} из телефонии`);
      const removeCell = node("td");
      removeCell.append(remove);
      row.append(addressCell, routeCell, noteCell, removeCell);
      list.append(row);
    }
    if (!visible.length) {
      const row = node("tr");
      const cell = node("td", rules.length ? "Адреса не найдены. Измените поиск или маршрут." : "Телефония пуста. Сохраните пустой список, чтобы убрать прежние исключения телефонии.");
      cell.colSpan = 4;
      row.append(cell);
      list.append(row);
    }
    pager.update(visible.length, page, pageSize);
    update();
  }
  function savePolicy(now) {
    run(async () => {
      const timing = now ? await confirmAction({ title: "Применить телефонию сейчас?", description: "Обновлённые приложения смогут получить правила и переподключить VPN. Возможен перерыв связи.", confirmText: "Сохранить и применить", interrupt: true }) : { apply: "next_connection", confirm_interrupt: false };
      if (!timing) return;
      const result = await api("/rules", { expected_revision: revision, ...timing, rules });
      checkRevision(result);
      revision = result.revision;
      saved = JSON.stringify(rules);
      render();
      published(timing.apply);
      if (history.open) await loadHistory();
    });
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
    page = 0;
    render();
    status.textContent = revision ? "Телефония загружена." : "Проверьте исходные пять адресов и явно сохраните телефонию. До этого отдельный список не опубликован.";
  }
  function checkRevision(result) {
    if (!result || !Number.isSafeInteger(result.revision) || result.revision <= revision) { stale = true; throw new Error("Не удалось подтвердить сохранение телефонии. Загрузите актуальную телефонию."); }
  }
  function published(apply) {
    status.textContent = "Телефония сохранена на сервере. " + (apply === "now" ? "Обновлённые приложения смогут получить её и переподключить VPN; получение ещё не подтверждено." : "Обновлённые приложения смогут использовать её при следующем подключении VPN.");
  }
  async function loadHistory() {
    const entries = await api("/history");
    if (!Array.isArray(entries) || entries.some((entry) => !entry || !Number.isSafeInteger(entry.revision) || entry.revision < 1 || !Number.isSafeInteger(entry.published_at) || entry.published_at < 1 || !Number.isSafeInteger(entry.rule_count) || entry.rule_count < 0 || entry.rule_count > 64)) throw new Error("Не удалось прочитать историю телефонии.");
    historyList.replaceChildren();
    for (const entry of entries) {
      const item = node("li");
      const restore = button("Восстановить телефонию…", () => run(async () => {
        const timing = await confirmAction({ title: `Восстановить версию ${entry.revision}?`, description: "Весь список телефонии и несохранённый черновик будут заменены. Правила сайтов сохранятся.", confirmText: "Восстановить телефонию", chooseTiming: true });
        if (!timing) return;
        const result = await api("/restore", { expected_revision: revision, revision: entry.revision, ...timing });
        checkRevision(result);
        stale = true;
        await load();
        published(timing.apply);
        await loadHistory();
      }));
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
