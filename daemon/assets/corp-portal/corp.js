(() => {
  "use strict";

  const node = (tag, text, className) => {
    const result = document.createElement(tag);
    if (text !== undefined) result.textContent = text;
    if (className) result.className = className;
    return result;
  };
  const routeOptions = [["direct", "Напрямую — без VPN"], ["proxy", "Через VPN"]];
  function field(title, input) {
    const label = node("label", undefined, "field");
    label.append(node("span", title, "control-label"), input);
    input.setAttribute("aria-label", title);
    return label;
  }
  function createPager(id, onPage) {
    const element = node("nav", undefined, "list-pagination");
    element.id = `${id}-pagination`;
    element.setAttribute("aria-label", "Страницы списка");
    const summary = node("p", "Загружаем список…", "list-summary");
    summary.id = `${id}-page-status`;
    summary.setAttribute("role", "status");
    summary.setAttribute("aria-live", "polite");
    const buttons = node("div", undefined, "page-number-buttons");
    buttons.id = `${id}-page-numbers`;
    element.append(summary, buttons);
    return { element, update(total, page, size) {
      const pages = Math.max(1, Math.ceil(total / size));
      summary.textContent = total ? `${page * size + 1}–${Math.min((page + 1) * size, total)} из ${total}${pages > 1 ? ` · Страница ${page + 1} из ${pages}` : ""}` : "Ничего не найдено";
      buttons.replaceChildren();
      if (pages <= 1) return;
      const indices = pages <= 6 ? Array.from({length: pages}, (_, i) => i)
        : [...new Set([0, page - 1, page, page + 1, pages - 1].filter((i) => i >= 0 && i < pages))].sort((a, b) => a - b);
      function add(label, target, name, boundary = false) {
        const button = node("button", label, "editor-control");
        button.type = "button";
        button.setAttribute("aria-label", name);
        button.dataset.pageBoundary = String(boundary);
        button.disabled = boundary;
        if (typeof label === "string" && /^\d+$/.test(label) && target === page) button.setAttribute("aria-current", "page");
        button.addEventListener("click", () => {
          if (boundary) return;
          onPage(target);
          buttons.querySelector('[aria-current="page"]')?.focus();
        });
        buttons.append(button);
      }
      add("Назад", page - 1, "Предыдущая страница", page === 0);
      let prior = -1;
      for (const index of indices) {
        if (index > prior + 1) buttons.append(node("span", "…"));
        add(String(index + 1), index, `Страница ${index + 1} из ${pages}`);
        prior = index;
      }
      add("Далее", page + 1, "Следующая страница", page + 1 >= pages);
    } };
  }
  function confirmAction({title, description, confirmText = "Подтвердить", interrupt = false, chooseTiming = false}) {
    return new Promise((resolve) => {
      const modal = node("dialog", undefined, "portal-dialog");
      const heading = node("h2", title);
      heading.id = "portal-confirm-title";
      modal.setAttribute("aria-labelledby", heading.id);
      const timing = node("select");
      for (const [value, text] of [["next_connection", "При следующем подключении VPN"], ["now", "Применить сейчас"]]) {
        const option = node("option", text);
        option.value = value;
        timing.append(option);
      }
      timing.value = interrupt ? "now" : "next_connection";
      const checkbox = node("input");
      checkbox.type = "checkbox";
      const consent = node("label", undefined, "check-label");
      consent.append(checkbox, node("span", "Подтверждаю возможный перерыв VPN у подключённых пользователей"));
      const warning = node("div", undefined, "notice warning");
      warning.append(node("p", "VPN может ненадолго переподключиться. Выключенный VPN останется выключенным."), consent);
      const cancel = node("button", "Отмена");
      const confirm = node("button", confirmText, "primary");
      cancel.type = confirm.type = "button";
      cancel.autofocus = true;
      const actions = node("div", undefined, "dialog-actions");
      actions.append(cancel, confirm);
      modal.append(heading, node("p", description));
      if (chooseTiming) modal.append(field("Когда применить", timing));
      modal.append(warning, actions);
      function update() {
        warning.hidden = timing.value !== "now";
        confirm.disabled = timing.value === "now" && !checkbox.checked;
      }
      timing.addEventListener("change", () => { checkbox.checked = false; update(); });
      checkbox.addEventListener("change", update);
      let result = null;
      confirm.addEventListener("click", () => {
        if (confirm.disabled) return;
        result = {apply: timing.value, confirm_interrupt: timing.value === "now" && checkbox.checked};
        modal.close();
      });
      cancel.addEventListener("click", () => modal.close());
      modal.addEventListener("close", () => { modal.remove(); resolve(result); }, {once: true});
      document.body.append(modal);
      update();
      modal.showModal();
    });
  }
  window.corpPortal = Object.freeze({node, field, routeOptions, createPager, confirmAction});
  const main = document.querySelector("main.editor");
  const product = document.querySelector(".corp-product");
  if (product) product.textContent = "VPNRouter";
  const identity = document.querySelector(".corp-identity > :last-child");
  if (identity && identity !== product) identity.textContent = "Corp · корпоративный VPN";
  function sectionName() {
    return main?.id === "corp-diagnostics" ? "diagnostics" : location.hash === "#telephony" ? "phone" : "sites";
  }
  function updateShell() {
    if (!main) return;
    const section = sectionName();
    const headings = {sites: ["Сайты", "Выберите, какие сайты открывать напрямую, а какие — через VPN."], phone: ["Телефония (VoIP)", "Настройте маршруты доменов и IP-адресов телефонии."], diagnostics: ["Диагностика", "Отчёты из приложения: что произошло и как это исправить."]};
    main.querySelector("h1").textContent = headings[section][0];
    main.querySelector(".page-header .muted").textContent = headings[section][1];
    document.title = `${headings[section][0]} · VPNRouter Corp`;
    for (const link of main.querySelectorAll(".portal-nav a")) {
      if (link.dataset.section === section) link.setAttribute("aria-current", "page");
      else link.removeAttribute("aria-current");
    }
  }
  if (main) {
    main.querySelector(".page-header button")?.classList.add("quiet");
    const nav = main.querySelector(".portal-nav");
    nav.replaceChildren();
    for (const [section, title, href, id] of [["sites", "Сайты", "/#sites", "show-site-rules"], ["phone", "Телефония (VoIP)", "/#telephony", "show-voice-rules"], ["diagnostics", "Диагностика", "/diagnostics", "show-diagnostics"]]) {
      const link = node("a", title);
      link.href = href;
      link.id = id;
      link.dataset.section = section;
      nav.append(link);
    }
    main.id ||= "corp-main";
    const skip = node("a", "К содержимому", "skip-link");
    skip.href = `#${main.id}`;
    skip.addEventListener("click", (event) => {
      event.preventDefault();
      main.tabIndex = -1;
      main.focus();
      main.scrollIntoView({block: "start"});
    });
    document.body.prepend(skip);
    updateShell();
    window.addEventListener("hashchange", updateShell);
  }

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
  const pageSize = 10;
  let rulePage = 0;
  let rulePager;

  function prepareWorkspace() {
    const card = editor.querySelector(".rules-card");
    card.id = "site-rules-panel";
    const table = card.querySelector("table");
    const heading = card.querySelector(".section-heading");
    const feedback = node("div", undefined, "section-feedback");
    card.before(feedback);
    feedback.append(editor.querySelector(".status-panel"), el("error"), el("reload-notice"), el("session-link"));
    const title = node("div", undefined, "section-title");
    title.append(card.querySelector("h2"), el("rule-count"));
    title.querySelector("h2").textContent = "Список сайтов";
    heading.replaceChildren(title);

    const addSection = editor.querySelector('[aria-labelledby="add-title"]');
    const addPanel = node("details", undefined, "add-site-panel");
    addPanel.id = "add-site-panel";
    addPanel.append(node("summary", "Новый сайт"), addSection);
    addSection.classList.remove("card");
    addSection.classList.add("add-site-body");
    addSection.querySelector("h2").classList.add("sr-only");
    addSection.querySelector(":scope > .muted").textContent = "Вставьте домен или ссылку. Правило будет действовать и для поддоменов.";
    const addButton = node("button", "Добавить сайт", "editor-control");
    addButton.id = "open-add-site";
    addButton.type = "button";
    addButton.setAttribute("aria-controls", addPanel.id);
    addButton.setAttribute("aria-expanded", "false");
    addButton.addEventListener("click", () => {
      addPanel.open = !addPanel.open;
      if (addPanel.open) el("site").focus({preventScroll: true});
    });
    addPanel.addEventListener("toggle", () => addButton.setAttribute("aria-expanded", String(addPanel.open)));
    heading.append(addButton);
    heading.after(addPanel);
    el("new-action").querySelector('[value="direct"]').textContent = "Напрямую — без VPN";
    el("new-action").closest(".field").querySelector("label").textContent = "Как открывать";
    const preview = el("site-preview");
    preview.querySelector(":scope > .muted")?.remove();
    const noteField = el("new-comment").closest(".field");
    const noteDetails = node("details", undefined, "optional-note");
    noteDetails.append(node("summary", "Добавить заметку"));
    noteField.before(noteDetails);
    noteDetails.append(noteField);

    const filters = node("div", undefined, "workspace-toolbar rules-filters");
    const searchField = node("div", undefined, "field");
    const searchLabel = card.querySelector('label[for="search"]');
    searchLabel.textContent = "Поиск";
    el("search").placeholder = "Сайт или заметка…";
    searchField.append(searchLabel, el("search"));
    const select = node("select", undefined, "editor-control");
    select.id = "route-filter";
    for (const [value, text] of [["all", "Все маршруты"], ...routeOptions]) {
      const option = node("option", text);
      option.value = value;
      select.append(option);
    }
    const notesLabel = node("label", undefined, "notes-toggle");
    const notes = node("input", undefined, "editor-control");
    notes.type = "checkbox";
    notes.id = "show-rule-notes";
    notes.addEventListener("change", () => table.classList.toggle("show-notes", notes.checked));
    notesLabel.append(notes, node("span", "Заметки"));
    filters.append(searchField, field("Как открывать", select), notesLabel);
    table.before(filters);
    rulePager = createPager("rules", (page) => { rulePage = page; renderRules(); });
    table.before(rulePager.element);
    card.querySelector("th:nth-child(3)").textContent = "Заметка";

    const footer = card.querySelector(".save-bar");
    footer.querySelector(".save-title").id = "save-summary";
    footer.querySelector(".muted").textContent = "Обычное сохранение — при следующем подключении VPN.";
    el("save").textContent = "Сохранить изменения";
    el("save-now").textContent = "Применить сейчас…";
    footer.querySelector(".actions").append(el("save"), el("save-now"));
    const discard = node("button", "Отменить изменения", "quiet editor-control");
    discard.id = "discard-site-changes";
    discard.type = "button";
    discard.hidden = true;
    discard.addEventListener("click", () => openConfirmation({kind: "reload"}));
    footer.querySelector(".actions").append(discard);
    const help = node("details", undefined, "route-help");
    help.append(node("summary", "Как работают маршруты"), card.querySelector(".route-guide"), card.querySelector(".route-note"));
    card.after(help);

    const voice = node("section", undefined, "card voice-rules");
    voice.id = "voice-rules-panel";
    const phoneEditor = node("div");
    phoneEditor.id = "corp-phone-editor";
    voice.append(phoneEditor);
    card.after(voice);
    function showRules() {
      const telephony = sectionName() === "phone";
      card.hidden = telephony;
      help.hidden = telephony;
      feedback.hidden = telephony;
      el("history-panel").hidden = telephony;
      voice.hidden = !telephony;
    }
    window.addEventListener("hashchange", showRules);
    showRules();
  }

  prepareWorkspace();

  function updateControls() {
    editor.setAttribute("aria-busy", String(busy));
    for (const control of editor.querySelectorAll(".editor-control")) {
      if (control.closest("#corp-phone-editor")) continue;
      control.disabled = busy || !initialized || sessionLost || control.dataset.pageBoundary === "true";
    }
    el("reload").disabled = busy || sessionLost;
    const cannotSave = busy || !initialized || sessionLost || reloadRequired || (!dirty && revision !== 0);
    el("save").disabled = cannotSave;
    el("save-now").disabled = cannotSave;
    el("discard-site-changes").hidden = !dirty || reloadRequired;
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
    const fragment = document.createDocumentFragment();
    for (const rule of shown.slice(start, start + pageSize)) fragment.append(ruleRow(rule));
    el("rules").replaceChildren(fragment);
    el("rule-count").textContent = query || route !== "all" ? `Найдено: ${shown.length} из ${rules.length}` : `Всего сайтов: ${rules.length}`;
    rulePager.update(shown.length, rulePage, pageSize);
    const routeOptions = el("route-filter").options;
    routeOptions[0].textContent = `Все сайты (${rules.length})`;
    routeOptions[1].textContent = `Напрямую — без VPN (${rules.filter((r) => r.action === "direct").length})`;
    routeOptions[2].textContent = `Через VPN (${rules.filter((r) => r.action === "proxy").length})`;
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
  el("route-filter").addEventListener("change", () => { rulePage = 0; renderRules(); });
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
