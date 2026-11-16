(() => {
  "use strict";

  const editor = document.getElementById("corp-editor");
  if (!editor) return;

  const el = (id) => document.getElementById(id);
  const dialog = el("confirm-dialog");
  const utf8 = new TextEncoder();
  let rules = [];
  let revision = 0;
  let csrf = "";
  let savedRules = "[]";
  let initialized = false;
  let busy = false;
  let dirty = false;
  let sessionLost = false;
  let reloadRequired = false;
  let candidate = null;
  let confirmation = null;
  let historyLoaded = false;
  const narrowLayout = window.matchMedia("(max-width: 740px)");
  let pageSize = narrowLayout.matches ? 5 : 10;
  let rulePage = 0;

  const node = (tag, text, className) => {
    const result = document.createElement(tag);
    if (text !== undefined) result.textContent = text;
    if (className) result.className = className;
    return result;
  };

  function prepareWorkspace() {
    editor.querySelector(".page-header .muted").textContent = "Настройте, какие сайты открывать без VPN, а какие — через корпоративный сервер.";
    const portalNav = editor.querySelector(".portal-nav");
    const sitesLink = portalNav.querySelector('a[href="/"]');
    const sitesButton = node("button", "Правила сайтов");
    sitesButton.id = "show-site-rules";
    sitesButton.type = "button";
    sitesButton.setAttribute("aria-pressed", "true");
    const voiceButton = node("button", "Телефония (VoIP)");
    voiceButton.id = "show-voice-rules";
    voiceButton.type = "button";
    voiceButton.setAttribute("aria-pressed", "false");
    sitesLink.replaceWith(sitesButton, voiceButton);
    const guide = node("section", undefined, "workspace-guide");
    guide.setAttribute("aria-label", "Как изменить правила");
    const steps = node("ol");
    for (const [title, description] of [
      ["Найдите сайт", "Или нажмите «Добавить сайт», если его ещё нет."],
      ["Выберите маршрут", "«Без VPN» — ваш интернет. «Через VPN» — корпоративный сервер."],
      ["Сохраните изменения", "Они начнут действовать при следующем подключении VPN."],
    ]) {
      const item = node("li");
      item.append(node("strong", title), node("p", description, "muted small"));
      steps.append(item);
    }
    guide.append(steps);
    portalNav.after(guide);
    editor.querySelector('[aria-labelledby="add-title"] > .muted').textContent = "Вставьте домен или ссылку. Правило будет действовать и для поддоменов.";
    el("new-action").querySelector('[value="direct"]').textContent = "Напрямую — без VPN";
    const preview = el("site-preview");
    preview.querySelector(":scope > .muted")?.remove();
    preview.append(el("new-route-hint"));

    const card = editor.querySelector(".rules-card");
    card.id = "site-rules-panel";
    sitesButton.setAttribute("aria-controls", card.id);
    const addSection = editor.querySelector('[aria-labelledby="add-title"]');
    const addPanel = node("details", undefined, "card add-site-panel");
    addPanel.id = "add-site-panel";
    addSection.before(addPanel);
    addPanel.append(node("summary", "Добавить новый сайт"), addSection);
    addSection.classList.remove("card");
    addSection.classList.add("add-site-body");
    addSection.querySelector("h2").classList.add("sr-only");
    card.after(addPanel);
    const addButton = node("button", "Добавить сайт", "editor-control");
    addButton.id = "open-add-site";
    addButton.type = "button";
    addButton.addEventListener("click", () => {
      card.before(addPanel);
      addPanel.open = true;
      addPanel.scrollIntoView({block: "start"});
      el("site").focus({preventScroll: true});
    });
    const primaryActions = node("div", undefined, "actions rules-heading-actions");
    el("save").textContent = "Сохранить изменения";
    primaryActions.append(addButton, el("save"));
    card.querySelector(".section-heading").append(primaryActions);
    const voice = node("section", undefined, "card voice-rules");
    voice.id = "voice-rules-panel";
    voice.hidden = true;
    voiceButton.setAttribute("aria-controls", voice.id);
    voice.append(node("h2", "Телефония (VoIP) — UIS / CoMagic"));
    voice.append(node("p", "Управляйте доменами и IP-адресами телефонии отдельным списком. Изменения сохраняются отдельно от правил сайтов."));
    const phoneEditor = node("div");
    phoneEditor.id = "corp-phone-editor";
    voice.append(phoneEditor);
    card.after(voice);
    function showRules(kind) {
      const telephony = kind === "voice";
      card.hidden = telephony;
      addPanel.hidden = telephony;
      guide.hidden = telephony;
      el("history-panel").hidden = telephony;
      voice.hidden = !telephony;
      sitesButton.setAttribute("aria-pressed", String(!telephony));
      voiceButton.setAttribute("aria-pressed", String(telephony));
    }
    sitesButton.addEventListener("click", () => showRules("sites"));
    voiceButton.addEventListener("click", () => showRules("voice"));
    const help = node("details", undefined, "route-help");
    help.append(node("summary", "Как работают маршруты"), card.querySelector(".route-guide"));
    const note = card.querySelector(".route-note");
    note.textContent = "Corp VPN оставьте включённым. Маршрут определяет только путь выбранного сайта.";
    help.append(note);
    const filters = node("div", undefined, "rules-filters");
    const searchField = node("div", undefined, "field");
    searchField.append(card.querySelector('label[for="search"]'), el("search"));
    const routeField = node("div", undefined, "field");
    const label = node("label", "Маршрут");
    label.htmlFor = "route-filter";
    const select = node("select", undefined, "editor-control");
    select.id = "route-filter";
    for (const [value, title] of [["all", "Все сайты"], ["direct", "Без VPN"], ["proxy", "Через VPN"]]) {
      const option = node("option", title);
      option.value = value;
      select.append(option);
    }
    routeField.append(label, select);
    filters.append(searchField, routeField);
    const notesLabel = node("label", undefined, "notes-toggle");
    const notes = node("input");
    notes.type = "checkbox";
    notes.id = "show-rule-notes";
    notes.addEventListener("change", () => card.querySelector("table").classList.toggle("show-notes", notes.checked));
    notesLabel.append(notes, node("span", "Показать заметки к сайтам"));
    help.append(notesLabel);
    card.querySelector("th:nth-child(3)").textContent = "Заметка (необязательно)";
    searchField.querySelector("label").textContent = "Найти сайт среди всех правил";
    card.insertBefore(help, card.querySelector("table"));
    card.insertBefore(filters, card.querySelector("table"));

    const pagination = node("nav", undefined, "list-pagination");
    pagination.id = "rules-pagination";
    pagination.hidden = true;
    pagination.setAttribute("aria-label", "Страницы списка сайтов");
    const status = node("p", "", "muted small");
    status.id = "rules-page-status";
    status.setAttribute("role", "status");
    status.setAttribute("aria-live", "polite");
    const actions = node("div", undefined, "actions");
    for (const [id, title] of [["rules-previous", "Назад"], ["rules-next", "Далее"]]) {
      const button = node("button", title, "editor-control");
      button.id = id;
      button.type = "button";
      actions.append(button);
    }
    pagination.append(status, actions);
    card.insertBefore(pagination, card.querySelector(".save-bar"));
    const topPages = node("nav", undefined, "rules-page-picker");
    topPages.setAttribute("aria-label", "Все страницы правил");
    const topStatus = node("p", "Загружаем список…");
    topStatus.id = "rules-page-overview";
    topStatus.setAttribute("role", "status");
    const pageButtons = node("div", undefined, "page-number-buttons");
    pageButtons.id = "rules-page-numbers";
    topPages.append(topStatus, pageButtons);
    card.insertBefore(topPages, card.querySelector("table"));
    card.querySelector(".save-title").id = "save-summary";
    card.querySelector(".save-bar .muted").textContent = "Сохраняется весь список. Правила применятся при следующем подключении VPN.";
    el("save-now").textContent = "Сохранить и применить сейчас…";
  }

  prepareWorkspace();

  function updateControls() {
    editor.setAttribute("aria-busy", String(busy));
    for (const control of editor.querySelectorAll(".editor-control")) {
      control.disabled = busy || !initialized || sessionLost || control.dataset.pageBoundary === "true";
    }
    el("reload").disabled = busy || sessionLost;
    const cannotSave = busy || !initialized || sessionLost || reloadRequired || (!dirty && revision !== 0);
    el("save").disabled = cannotSave;
    el("save-now").disabled = cannotSave;
    el("add-site").disabled = busy || !initialized || sessionLost || candidate === null;
    for (const button of editor.querySelectorAll("[data-restore]")) {
      button.disabled = busy || sessionLost || reloadRequired || Number(button.dataset.restore) === revision;
    }
  }

  function updateDraft() {
    dirty = JSON.stringify(rules) !== savedRules;
    el("draft-status").textContent = dirty
      ? "Есть несохранённые изменения. Сохраните весь список, чтобы передать их пользователям."
      : revision === 0
        ? "Начальный список ещё не сохранён. Проверьте его и сохраните правила."
        : `Версия ${revision}. Несохранённых изменений нет.`;
    el("save-summary").textContent = dirty ? "Есть изменения в списке" : revision === 0 ? "Сохраните начальный список" : "Все изменения сохранены";
    updateControls();
  }

  function requireReload(message) {
    reloadRequired = true;
    el("reload-message").textContent = message;
    el("reload-notice").hidden = false;
  }

  function reportError(error) {
    el("error").textContent = error.message || "Не удалось выполнить действие. Попробуйте ещё раз.";
    el("error").hidden = false;
    el("status").textContent = initialized ? "Действие не завершено. Текущий список остался на странице." : "Правила не загружены.";
    if (error.status === 409) {
      requireReload("Правила уже изменились. Ваш черновик сохранён на этой странице. Загрузите актуальный список перед следующим сохранением.");
    }
    if (error.status === 401 || error.status === 403) {
      sessionLost = true;
      el("session-link").hidden = false;
    } else if (!initialized) {
      el("reload-message").textContent = "Не удалось загрузить правила. Проверьте подключение и попробуйте снова.";
      el("reload-notice").hidden = false;
    }
  }

  async function run(message, operation) {
    if (busy) return;
    busy = true;
    el("error").hidden = true;
    el("status").textContent = message;
    updateControls();
    try {
      await operation();
    } catch (error) {
      reportError(error);
    } finally {
      busy = false;
      updateControls();
    }
  }

  async function api(path, body) {
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), 30000);
    const publishing = path === "/api/corp/rules" || path === "/api/corp/restore";
    try {
      const headers = { Accept: "application/json" };
      if (body !== undefined) {
        headers["Content-Type"] = "application/json";
        headers["X-Corp-CSRF"] = csrf;
      }
      const response = await fetch(path, {
        method: body === undefined ? "GET" : "POST",
        headers,
        credentials: "same-origin",
        cache: "no-store",
        redirect: "error",
        signal: controller.signal,
        body: body === undefined ? undefined : JSON.stringify(body),
      });
      let data = null;
      try {
        data = await response.json();
      } catch {
        // A proxy may return an HTML error; never render it as page content.
      }
      if (!response.ok) {
        const error = new Error(typeof data?.message === "string" ? data.message : "Не удалось выполнить действие. Попробуйте ещё раз.");
        error.status = response.status;
        throw error;
      }
      if (data === null) throw new Error("Не удалось прочитать ответ. Попробуйте обновить список.");
      return data;
    } catch (error) {
      if (publishing && (!error.status || error.status === 408 || error.status >= 500)) {
        requireReload("Связь прервалась или ответ не получен. Правила могли сохраниться. Ваш черновик остаётся здесь; загрузите актуальный список перед новым сохранением.");
      }
      if (!error.status && (error.name === "AbortError" || error instanceof TypeError)) {
        throw new Error("Не удалось связаться с сервером. Проверьте подключение VPN и попробуйте снова.");
      }
      throw error;
    } finally {
      window.clearTimeout(timeout);
    }
  }

  function validateComment(comment) {
    return utf8.encode(comment).length <= 256 && !/[\u0000-\u001f\u007f-\u009f]/u.test(comment);
  }

  function routeConflict(domain, action, list) {
    return list.find((rule) => rule.action !== action && (
      rule.domain === domain || rule.domain.endsWith(`.${domain}`) || domain.endsWith(`.${rule.domain}`)
    ));
  }

  function validateDraft() {
    for (const rule of rules) {
      if (!validateComment(rule.comment)) {
        throw new Error(`Сократите комментарий к ${rule.domain}: до 128 русских букв или 256 латинских, без управляющих символов.`);
      }
      const conflict = routeConflict(rule.domain, rule.action, rules);
      if (conflict) throw new Error(`Для ${rule.domain} и ${conflict.domain} выбраны разные маршруты. У сайта и его поддомена должен быть один маршрут.`);
    }
  }

  function describeRoute(select, hint) {
    select.dataset.action = select.value;
    hint.textContent = select.value === "direct"
      ? "Без VPN, через ваш интернет"
      : "Через корпоративный VPN-сервер";
  }

  function ruleRow(rule) {
    const row = node("tr");
    const domainCell = node("td");
    domainCell.append(node("span", "Сайт", "mobile-label"), node("span", rule.domain, "site-name"));
    const routeCell = node("td");
    const routeLabel = node("span", "Как открывать", "mobile-label");
    const select = node("select", undefined, "editor-control route-choice");
    const hint = node("p", undefined, "route-hint");
    hint.id = `route-hint-${rule.domain}`;
    select.setAttribute("aria-label", `Как открывать ${rule.domain}`);
    select.setAttribute("aria-describedby", hint.id);
    for (const [value, label] of [["direct", "Напрямую — без VPN"], ["proxy", "Через VPN"]]) {
      const option = node("option", label);
      option.value = value;
      select.append(option);
    }
    select.value = rule.action;
    describeRoute(select, hint);
    select.addEventListener("change", () => {
      rule.action = select.value;
      describeRoute(select, hint);
      updateDraft();
      if (el("route-filter").value !== "all") {
        renderRules();
        el("route-filter").focus();
      }
    });
    routeCell.append(routeLabel, select, hint);
    const commentCell = node("td");
    const input = node("input", undefined, "editor-control");
    input.type = "text";
    input.maxLength = 256;
    input.value = rule.comment;
    input.placeholder = "Необязательно";
    input.setAttribute("aria-label", `Комментарий к ${rule.domain}`);
    input.addEventListener("input", () => { rule.comment = input.value; updateDraft(); });
    commentCell.append(node("span", "Комментарий", "mobile-label"), input);
    const actionCell = node("td");
    const remove = node("button", "Удалить", "remove editor-control");
    remove.type = "button";
    remove.setAttribute("aria-label", `Удалить ${rule.domain}`);
    remove.addEventListener("click", () => {
      rules = rules.filter((item) => item !== rule);
      renderRules();
      updateDraft();
      el("status").textContent = `${rule.domain} удалён из черновика. Сохраните список, чтобы применить изменение.`;
      el("search").focus();
    });
    actionCell.append(remove);
    row.append(domainCell, routeCell, commentCell, actionCell);
    return row;
  }

  el("new-action").addEventListener("change", () => {
    describeRoute(el("new-action"), el("new-route-hint"));
  });

  function renderRules() {
    const query = el("search").value.trim().toLocaleLowerCase("ru");
    const route = el("route-filter").value;
    const shown = rules.filter((rule) => (route === "all" || rule.action === route) && `${rule.domain} ${rule.comment}`.toLocaleLowerCase("ru").includes(query));
    const pages = Math.max(1, Math.ceil(shown.length / pageSize));
    rulePage = Math.min(rulePage, pages - 1);
    const start = rulePage * pageSize;
    const remaining = Math.max(0, shown.length - Math.min(start + pageSize, shown.length));
    const fragment = document.createDocumentFragment();
    for (const rule of shown.slice(start, start + pageSize)) fragment.append(ruleRow(rule));
    el("rules").replaceChildren(fragment);
    el("rule-count").textContent = query || route !== "all" ? `Найдено: ${shown.length} из ${rules.length}` : `Всего сайтов: ${rules.length}`;
    el("rules-pagination").hidden = shown.length <= pageSize;
    el("rules-page-status").textContent = shown.length ? `${start + 1}–${Math.min(start + pageSize, shown.length)} из ${shown.length} · Страница ${rulePage + 1} из ${pages}` : "";
    el("rules-page-overview").textContent = shown.length
      ? `Показаны сайты ${start + 1}–${Math.min(start + pageSize, shown.length)} из ${shown.length}. ${remaining ? `Дальше ещё ${remaining} — выберите страницу ниже.` : rulePage > 0 ? "Это последняя страница." : "Весь выбранный список на этой странице."}`
      : "По этому запросу сайтов нет.";
    const pageButtons = el("rules-page-numbers");
    pageButtons.replaceChildren();
    if (pages > 1) {
      const indices = pages <= 8 ? Array.from({length: pages}, (_, index) => index)
        : [...new Set([0, rulePage - 1, rulePage, rulePage + 1, pages - 1].filter((i) => i >= 0 && i < pages))].sort((a, b) => a - b);
      let prior = -1;
      for (const index of indices) {
        if (index > prior + 1) pageButtons.append(node("span", "…"));
        const button = node("button", String(index + 1), "editor-control");
        button.type = "button";
        button.setAttribute("aria-label", `Страница ${index + 1} из ${pages}`);
        if (index === rulePage) button.setAttribute("aria-current", "page");
        button.addEventListener("click", () => {
          rulePage = index;
          renderRules();
          el("rules-page-numbers").querySelector('[aria-current="page"]')?.focus();
        });
        pageButtons.append(button);
        prior = index;
      }
    }
    el("show-site-rules").textContent = `Правила сайтов (${rules.length})`;
    const routeOptions = el("route-filter").options;
    routeOptions[0].textContent = `Все сайты (${rules.length})`;
    routeOptions[1].textContent = `Без VPN (${rules.filter((r) => r.action === "direct").length})`;
    routeOptions[2].textContent = `Через VPN (${rules.filter((r) => r.action === "proxy").length})`;
    el("rules-previous").dataset.pageBoundary = String(rulePage === 0);
    el("rules-next").dataset.pageBoundary = String(rulePage + 1 === pages);
    el("empty-list").hidden = shown.length !== 0;
    el("empty-list").textContent = rules.length === 0
      ? "Список пуст. Добавьте сайт выше или сохраните пустой список, чтобы убрать все прежние правила."
      : "Ничего не найдено. Измените поиск или выберите другой маршрут.";
    updateControls();
  }

  async function loadState() {
    const data = await api("/api/corp/state");
    if (!Number.isSafeInteger(data.revision) || data.revision < 0 || typeof data.csrf !== "string" || !data.csrf || !Array.isArray(data.rules) || data.rules.some((rule) => !rule || typeof rule.domain !== "string" || typeof rule.comment !== "string" || !["direct", "proxy"].includes(rule.action))) {
      throw new Error("Не удалось прочитать список правил. Попробуйте снова.");
    }
    rules = data.rules.map(({ domain, action, comment }) => ({ domain, action, comment }));
    revision = data.revision;
    csrf = data.csrf;
    savedRules = JSON.stringify(rules);
    initialized = true;
    sessionLost = false;
    reloadRequired = false;
    candidate = null;
    rulePage = 0;
    el("site-preview").hidden = true;
    el("reload-notice").hidden = true;
    el("session-link").hidden = true;
    renderRules();
    updateDraft();
    el("status").textContent = "Правила загружены.";
  }

  function publicationMessage(apply) {
    return apply === "now"
      ? "Правила сохранены. Подключённые приложения применят их после получения обновления; связь может ненадолго прерваться. При выключенном VPN — при следующем подключении."
      : "Правила сохранены. Приложения применят их при следующем подключении VPN.";
  }

  function checkPublication(result) {
    if (!Number.isSafeInteger(result.revision) || result.revision <= revision) {
      requireReload("Не удалось подтвердить сохранение. Ваш черновик остаётся здесь. Загрузите актуальные правила.");
      throw new Error("Не удалось прочитать подтверждение сохранения.");
    }
  }

  async function publish(apply, confirmInterrupt) {
    validateDraft();
    const result = await api("/api/corp/rules", {
      expected_revision: revision,
      apply,
      confirm_interrupt: confirmInterrupt,
      rules: rules.map(({ domain, action, comment }) => ({ domain, action, comment })),
    });
    checkPublication(result);
    revision = result.revision;
    savedRules = JSON.stringify(rules);
    updateDraft();
    el("status").textContent = publicationMessage(apply);
    await refreshOpenHistory();
  }

  function formatDate(seconds) {
    const date = new Date(seconds * 1000);
    return Number.isNaN(date.getTime()) ? "Дата недоступна" : new Intl.DateTimeFormat("ru", { dateStyle: "medium", timeStyle: "short" }).format(date);
  }

  async function loadHistory() {
    el("history-status").textContent = "Загружаем историю…";
    let entries;
    try {
      entries = await api("/api/corp/history");
      if (!Array.isArray(entries) || entries.some((entry) => !entry || !Number.isSafeInteger(entry.revision) || entry.revision <= 0 || !Number.isSafeInteger(entry.published_at) || entry.published_at <= 0 || !Number.isSafeInteger(entry.rule_count) || entry.rule_count < 0 || !["next_connection", "now"].includes(entry.apply))) {
        throw new Error("Не удалось прочитать историю изменений.");
      }
    } catch (error) {
      el("history-status").textContent = "История не загрузилась. Нажмите «Обновить историю», чтобы попробовать снова.";
      throw error;
    }
    const fragment = document.createDocumentFragment();
    for (const entry of entries) {
      const item = node("li");
      const description = node("div");
      description.append(node("p", `Версия ${entry.revision} · ${formatDate(entry.published_at)}`, "history-title"));
      description.append(node("p", `Сайтов: ${entry.rule_count} · ${entry.apply === "now" ? "Применение сразу" : "При следующем подключении"}`, "muted small"));
      const button = node("button", entry.revision === revision ? "Текущая версия" : "Восстановить…", "editor-control");
      button.type = "button";
      button.dataset.restore = String(entry.revision);
      button.setAttribute("aria-label", `Восстановить версию ${entry.revision}`);
      button.addEventListener("click", () => openConfirmation({ kind: "restore", revision: entry.revision }));
      item.append(description, button);
      fragment.append(item);
    }
    el("history").replaceChildren(fragment);
    el("history-status").textContent = entries.length ? "Последние сохранённые списки. Время указано по вашему часовому поясу." : "Сохранённых списков пока нет. Проверьте список сайтов и нажмите «Сохранить правила».";
    historyLoaded = true;
    updateControls();
  }

  async function refreshOpenHistory() {
    historyLoaded = false;
    if (!el("history-panel").open) return;
    try {
      await loadHistory();
    } catch {
      el("history-status").textContent = "История не обновилась. Нажмите «Обновить историю», чтобы попробовать снова.";
    }
  }

  function updateConfirmation() {
    const interrupt = (confirmation?.kind === "save") || (confirmation?.kind === "restore" && el("confirm-timing").value === "now");
    el("interrupt-warning").hidden = !interrupt;
    el("accept-confirm").disabled = interrupt && !el("confirm-interrupt").checked;
  }

  function openConfirmation(action) {
    if (busy) return;
    confirmation = action;
    el("confirm-interrupt").checked = false;
    el("confirm-timing").value = "next_connection";
    el("restore-timing").hidden = action.kind !== "restore";
    const copy = {
      save: ["Применить правила сейчас?", "Сначала сохраним весь список, затем приложения смогут получить новые правила.", "Сохранить и применить сейчас"],
      restore: [`Восстановить версию ${action.revision}?`, "Она заменит весь текущий список и несохранённые изменения. Сохраним её как новую версию.", "Восстановить список"],
      reload: ["Загрузить актуальные правила?", "Несохранённые изменения на этой странице будут заменены списком с сервера.", "Загрузить и заменить"],
      logout: ["Выйти без сохранения?", "Несохранённые изменения будут потеряны.", "Выйти"],
    }[action.kind];
    el("confirm-title").textContent = copy[0];
    el("confirm-description").textContent = copy[1];
    el("accept-confirm").textContent = copy[2];
    updateConfirmation();
    dialog.showModal();
    el("cancel-confirm").focus();
  }

  async function restore(source, apply, confirmInterrupt) {
    const result = await api("/api/corp/restore", {
      expected_revision: revision,
      revision: source,
      apply,
      confirm_interrupt: confirmInterrupt,
    });
    checkPublication(result);
    requireReload("Список восстановлен, но пока не загружен на страницу. Загрузите актуальные правила перед дальнейшими изменениями.");
    await loadState();
    el("status").textContent = publicationMessage(apply);
    await refreshOpenHistory();
  }

  async function logout() {
    const response = await fetch("/logout", {
      method: "POST",
      credentials: "same-origin",
      headers: { "X-Corp-CSRF": csrf },
      cache: "no-store",
    });
    if (!response.ok) {
      const error = new Error("Не удалось выйти. Проверьте подключение и попробуйте снова.");
      error.status = response.status;
      throw error;
    }
    dirty = false;
    window.corpPhoneDirty = false;
    window.location.assign("/");
  }

  el("add-form").addEventListener("submit", (event) => {
    event.preventDefault();
    run("Проверяем адрес сайта…", async () => {
      candidate = null;
      el("site-preview").hidden = true;
      const result = await api("/api/corp/normalize", { site: el("site").value });
      if (typeof result.domain !== "string" || !result.domain) throw new Error("Не удалось проверить адрес сайта.");
      if (rules.some((rule) => rule.domain === result.domain)) throw new Error("Этот сайт уже есть в списке. Найдите его через поиск и измените правило.");
      candidate = result.domain;
      el("normalized-site").textContent = candidate;
      el("site-preview").hidden = false;
      el("status").textContent = "Адрес проверен. Выберите маршрут и подтвердите добавление в список.";
    }).then(() => { if (candidate) el("new-action").focus(); });
  });

  el("site").addEventListener("input", () => {
    candidate = null;
    el("site-preview").hidden = true;
    updateControls();
  });

  el("add-site").addEventListener("click", () => {
    if (!candidate || busy) return;
    el("error").hidden = true;
    const comment = el("new-comment").value;
    const action = el("new-action").value;
    let message = "";
    if (rules.length >= 512) message = "В списке уже 512 сайтов. Удалите ненужный сайт перед добавлением нового.";
    else if (!validateComment(comment)) message = "Сократите комментарий: до 128 русских букв или 256 латинских, без управляющих символов.";
    else if (routeConflict(candidate, action, rules)) message = "Для этого сайта или его поддомена уже выбран другой маршрут. Выберите одинаковый маршрут.";
    if (message) { reportError(new Error(message)); return; }
    rules.unshift({ domain: candidate, action, comment });
    el("status").textContent = `${candidate} добавлен в черновик. Сохраните список, чтобы применить изменение.`;
    candidate = null;
    el("site").value = "";
    el("new-comment").value = "";
    el("new-action").value = "direct";
    describeRoute(el("new-action"), el("new-route-hint"));
    el("search").value = "";
    el("route-filter").value = "all";
    rulePage = 0;
    el("site-preview").hidden = true;
    renderRules();
    updateDraft();
    el("site").focus();
  });

  el("search").addEventListener("input", () => { rulePage = 0; renderRules(); });
  narrowLayout.addEventListener("change", () => {
    const nextSize = narrowLayout.matches ? 5 : 10;
    if (nextSize === pageSize) return;
    rulePage = Math.floor(rulePage * pageSize / nextSize);
    pageSize = nextSize;
    if (initialized) renderRules();
  });
  el("route-filter").addEventListener("change", () => { rulePage = 0; renderRules(); });
  el("rules-previous").addEventListener("click", () => { rulePage = Math.max(0, rulePage - 1); renderRules(); });
  el("rules-next").addEventListener("click", () => { rulePage += 1; renderRules(); });
  el("save").addEventListener("click", () => run("Сохраняем правила…", () => publish("next_connection", false)));
  el("save-now").addEventListener("click", () => openConfirmation({ kind: "save" }));
  el("reload").addEventListener("click", () => {
    if (dirty) openConfirmation({ kind: "reload" });
    else run("Загружаем актуальные правила…", async () => { await loadState(); await refreshOpenHistory(); });
  });
  el("logout").addEventListener("click", () => {
    if (dirty || window.corpPhoneDirty) openConfirmation({ kind: "logout" });
    else run("Выходим…", logout);
  });
  el("refresh-history").addEventListener("click", () => run("Загружаем историю…", async () => {
    await loadHistory();
    el("status").textContent = "История обновлена. Текущий список не изменился.";
  }));
  el("history-panel").addEventListener("toggle", () => {
    if (el("history-panel").open && initialized && !busy && !historyLoaded) el("refresh-history").click();
  });
  el("confirm-timing").addEventListener("change", () => { el("confirm-interrupt").checked = false; updateConfirmation(); });
  el("confirm-interrupt").addEventListener("change", updateConfirmation);
  el("cancel-confirm").addEventListener("click", () => dialog.close());
  dialog.addEventListener("close", () => { confirmation = null; });
  el("accept-confirm").addEventListener("click", () => {
    const action = confirmation;
    if (!action || el("accept-confirm").disabled) return;
    const apply = action.kind === "save" ? "now" : el("confirm-timing").value;
    const interrupt = apply === "now" && el("confirm-interrupt").checked;
    dialog.close();
    if (action.kind === "save") run("Сохраняем правила…", () => publish(apply, interrupt));
    else if (action.kind === "restore") run("Восстанавливаем список…", () => restore(action.revision, apply, interrupt));
    else if (action.kind === "reload") run("Загружаем актуальные правила…", async () => { await loadState(); await refreshOpenHistory(); });
    else if (action.kind === "logout") run("Выходим…", logout);
  });
  window.addEventListener("beforeunload", (event) => {
    if (dirty) { event.preventDefault(); event.returnValue = ""; }
  });
  run("Загружаем правила…", async () => { await loadState(); await refreshOpenHistory(); });
})();
