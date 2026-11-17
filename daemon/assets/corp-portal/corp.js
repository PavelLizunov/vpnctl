(() => {
  "use strict";

  const node = (tag, text, className) => {
    const element = document.createElement(tag);
    if (text !== undefined) element.textContent = text;
    if (className) element.className = className;
    return element;
  };
  const field = (title, input) => {
    const label = node("label", undefined, "field");
    label.append(node("span", title, "control-label"), input);
    return label;
  };
  const button = (title, action, className = "editor-control") => {
    const element = node("button", title, className);
    element.type = "button";
    element.addEventListener("click", action);
    return element;
  };
  const select = (options) => {
    const element = node("select");
    for (const [value, title] of options) {
      const option = node("option", title);
      option.value = value;
      element.append(option);
    }
    return element;
  };
  const routeOptions = [["direct", "Без VPN"], ["proxy", "Через VPN"]];
  let dialogNumber = 0;
  function confirmAction({title, description, confirmText = "Подтвердить", interrupt = false, chooseTiming = false}) {
    return new Promise((resolve) => {
      const dialog = node("dialog", undefined, "portal-dialog");
      const heading = node("h2", title);
      heading.id = `portal-confirm-${++dialogNumber}`;
      dialog.setAttribute("aria-labelledby", heading.id);
      const timing = select([["next_connection", "При следующем подключении VPN"], ["now", "Применить сейчас"]]);
      timing.value = interrupt ? "now" : "next_connection";
      const checkbox = node("input");
      checkbox.type = "checkbox";
      const consent = node("label", undefined, "check-label");
      consent.append(checkbox, node("span", "Подтверждаю возможный перерыв VPN у подключённых пользователей"));
      const warning = node("div", undefined, "notice warning");
      warning.append(node("p", "VPN может ненадолго переподключиться. Выключенный VPN останется выключенным."), consent);
      const cancel = button("Отмена", () => dialog.close());
      cancel.autofocus = true;
      let result = null;
      const accept = button(confirmText, () => {
        if (accept.disabled) return;
        result = { apply: timing.value, confirm_interrupt: timing.value === "now" && checkbox.checked };
        dialog.close();
      }, "primary");
      const actions = node("div", undefined, "dialog-actions");
      actions.append(cancel, accept);
      dialog.append(heading, node("p", description));
      if (chooseTiming) dialog.append(field("Когда применить", timing));
      dialog.append(warning, actions);
      const update = () => {
        warning.hidden = timing.value !== "now";
        accept.disabled = timing.value === "now" && !checkbox.checked;
      };
      timing.addEventListener("change", () => { checkbox.checked = false; update(); });
      checkbox.addEventListener("change", update);
      dialog.addEventListener("close", () => { dialog.remove(); resolve(result); }, {once: true});
      document.body.append(dialog);
      update();
      dialog.showModal();
    });
  }
  window.corpPortal = Object.freeze({node, field, routeOptions, confirmAction});

  const main = document.querySelector("main.editor");
  if (!main) return;
  const diagnostics = main.id === "corp-diagnostics";
  const product = document.querySelector(".corp-product");
  if (product) product.textContent = "VPNRouter";
  const identity = document.querySelector(".corp-identity > :last-child");
  if (identity && identity !== product) identity.textContent = main.dataset.username ? `Компания: ${main.dataset.username}` : "Corp · корпоративный VPN";
  const nav = main.querySelector(".portal-nav");
  function makeNav() {
    nav?.replaceChildren();
    for (const [title, href, current] of [["Правила", "/#rules", !diagnostics], ["Диагностика", "/diagnostics", diagnostics]]) {
      const link = node("a", title);
      link.href = href;
      if (current) link.setAttribute("aria-current", "page");
      nav?.append(link);
    }
  }
  makeNav();
  document.title = `${diagnostics ? "Диагностика" : "Правила"} · VPNRouter Corp`;
  const skip = node("a", "К содержимому", "skip-link");
  skip.href = `#${main.id}`;
  skip.addEventListener("click", (event) => {
    event.preventDefault();
    main.tabIndex = -1;
    main.focus();
    main.scrollIntoView({block: "start"});
  });
  document.body.prepend(skip);
  main.querySelector(".page-header button")?.classList.add("quiet");
  if (diagnostics) return;
  if (main.id !== "corp-editor") return;

  const phoneEndpoint = "/api/v1/corp/portal/telephony";
  const feeds = {
    site: { endpoint: "/api/corp", limit: 512, title: "Сайты", revision: 0, csrf: "", rules: [], saved: "[]", stale: false },
    phone: { endpoint: phoneEndpoint, limit: 64, title: "Телефония", revision: 0, csrf: "", rules: [], saved: "[]", stale: false },
  };
  let metadata = {schema: 1, revision: 0, categories: [], assignments: []};
  let metadataStale = false, ready = false, busy = false, sessionLost = false;
  let selected = "*", page = 0, candidate = null, leaving = false;
  const pageSize = 10;
  const utf8 = new TextEncoder();
  const key = (rule) => JSON.stringify([rule.source, rule.value]);
  const records = () => [...feeds.site.rules, ...feeds.phone.rules];
  const fingerprint = (rules) => JSON.stringify(rules.map(({source, type, value, action}) => ({source, type, value, action})));
  const isDirty = (source) => fingerprint(feeds[source].rules) !== feeds[source].saved;
  const dirty = () => Object.keys(feeds).some(isDirty);
  const needsPublication = (source) => isDirty(source) || feeds[source].revision === 0;
  const pendingAssignments = new Map();
  const stale = () => metadataStale || Object.values(feeds).some((feed) => feed.stale);
  const cloneMetadata = () => ({categories: metadata.categories.map((item) => ({...item})), assignments: metadata.assignments.map((item) => ({...item}))});
  const boundedAddress = (value) => typeof value === "string" && value.length > 0 && value.length <= 4096 && /^[\x21-\x7e]+$/.test(value);
  const validName = (name) => typeof name === "string" && name === name.trim() && name.length > 0 && [...name].length <= 64 && utf8.encode(name).length <= 256 && !/[\p{Cc}\p{Cf}\p{Cs}]/u.test(name);
  const validRevision = (value) => Number.isSafeInteger(value) && value >= 0;
  const exactKeys = (item, names) => item && typeof item === "object" && !Array.isArray(item) && Object.keys(item).length === names.length && names.every((name) => Object.hasOwn(item, name));

  const header = node("header", undefined, "page-header");
  const headingText = node("div");
  headingText.append(node("h1", "Правила"), node("p", "Настройте маршруты адресов и объедините их в категории.", "muted"));
  const logoutButton = button("Выйти", () => run(logout), "quiet");
  header.append(headingText, logoutButton);
  const status = node("p", "Загружаем правила…");
  status.id = "status";
  status.setAttribute("role", "status");
  status.setAttribute("aria-live", "polite");
  const error = node("p", "", "notice error");
  error.id = "error";
  error.hidden = true;
  error.setAttribute("role", "alert");
  const reloadButton = button("Загрузить актуальные правила", () => run(reload));
  reloadButton.hidden = true;
  const login = node("a", "Войти снова", "button");
  login.href = "/";
  login.hidden = true;
  const feedback = node("div", undefined, "section-feedback");
  feedback.append(status, error, reloadButton, login);
  const workspace = node("div", undefined, "rules-workspace");
  const rail = node("aside", undefined, "category-rail");
  rail.setAttribute("aria-label", "Категории правил");
  rail.append(node("h2", "Категории"));
  const categoryList = node("div", undefined, "category-list");
  const categoryFooter = node("div", undefined, "category-footer");
  const addCategory = button("Добавить категорию", () => categoryForm());
  addCategory.id = "add-category";
  categoryFooter.append(addCategory);
  rail.append(categoryList, categoryFooter);
  const categoryPicker = select([]);
  categoryPicker.id = "category-picker";
  const pickerField = node("div", undefined, "category-picker");
  const mobileAddCategory = button("Добавить категорию", () => categoryForm());
  mobileAddCategory.id = "add-category-mobile";
  pickerField.append(field("Категория", categoryPicker), mobileAddCategory);
  categoryPicker.addEventListener("change", () => selectCategory(categoryPicker.value));
  const content = node("section", undefined, "rules-content card");
  const sectionHeading = node("header", undefined, "section-heading");
  const sectionTitle = node("div", undefined, "section-title");
  const categoryTitle = node("h2", "Все адреса");
  const count = node("p", "", "muted small");
  sectionTitle.append(categoryTitle, count);
  const headingActions = node("div", undefined, "actions category-actions");
  const renameCategory = button("Переименовать", () => categoryForm(selected));
  const removeCategory = button("Удалить категорию", () => run(deleteCategory), "quiet editor-control");
  renameCategory.id = "rename-category";
  removeCategory.id = "delete-category";
  const openAdd = button("Добавить правило", () => {
    addPanel.open = !addPanel.open;
    if (addPanel.open) address.focus();
  });
  headingActions.append(renameCategory, removeCategory, openAdd);
  sectionHeading.append(sectionTitle, headingActions);
  const addPanel = node("details", undefined, "add-site-panel");
  addPanel.id = "add-address-panel";
  addPanel.append(node("summary", "Новый адрес"));
  openAdd.id = "add-rule";
  openAdd.setAttribute("aria-controls", addPanel.id);
  openAdd.setAttribute("aria-expanded", "false");
  addPanel.addEventListener("toggle", () => openAdd.setAttribute("aria-expanded", String(addPanel.open)));
  const form = node("form", undefined, "add-site-body");
  const kind = select([["domain_suffix", "Домен и поддомены"], ["ip_cidr", "IPv4-адрес или подсеть"]]);
  const address = node("input");
  address.type = "text";
  address.id = "new-address";
  address.maxLength = 4096;
  address.required = true;
  address.autocomplete = "off";
  address.spellcheck = false;
  address.placeholder = "example.com";
  const normalize = node("button", "Проверить адрес", "editor-control");
  normalize.type = "submit";
  form.append(field("Тип адреса", kind), field("Адрес", address), normalize);
  const preview = node("div", undefined, "preview");
  preview.hidden = true;
  const normalized = node("strong");
  const previewTitle = node("p", "Будет добавлен адрес: ");
  previewTitle.append(normalized);
  const newAction = select(routeOptions);
  const addButton = button("Добавить в черновик", () => run(addAddress));
  const previewFields = node("div", undefined, "preview-fields");
  previewFields.append(field("Как открывать", newAction), addButton);
  preview.append(previewTitle, previewFields);
  addPanel.append(form, preview);
  const toolbar = node("div", undefined, "workspace-toolbar");
  const search = node("input");
  search.type = "search";
  search.id = "rules-search";
  search.placeholder = "Найти адрес";
  search.autocomplete = "off";
  const routeFilter = select([["all", "Все маршруты"], ...routeOptions]);
  routeFilter.id = "route-filter";
  toolbar.append(field("Поиск", search), field("Как открывать", routeFilter));
  const table = node("table", undefined, "rules-table unified-table");
  table.setAttribute("aria-label", "Правила маршрутизации");
  const tableHead = node("thead");
  const columns = node("tr");
  for (const title of ["Адрес", "Как открывать", "Действия"]) {
    const cell = node("th", title);
    cell.scope = "col";
    columns.append(cell);
  }
  tableHead.append(columns);
  const list = node("tbody");
  list.id = "rules";
  table.append(tableHead, list);
  const pagination = node("nav", undefined, "list-pagination");
  pagination.setAttribute("aria-label", "Страницы списка адресов");
  const range = node("p", "", "list-summary");
  pagination.id = "rules-pagination";
  const pageButtons = node("div", undefined, "page-number-buttons");
  const previous = button("Назад", () => { page--; render(); });
  const currentPage = node("span");
  currentPage.setAttribute("aria-current", "page");
  const next = button("Далее", () => { page++; render(); });
  previous.id = "previous-page";
  next.id = "next-page";
  currentPage.id = "current-page";
  pageButtons.append(previous, currentPage, next);
  pagination.append(range, pageButtons);
  const saveBar = node("div", undefined, "save-bar");
  const saveMessage = node("div");
  const saveTitle = node("p", "", "save-title");
  saveMessage.append(saveTitle, node("p", "Обычное сохранение — при следующем подключении VPN.", "muted small"));
  const saveActions = node("div", undefined, "actions");
  const saveButton = button("Сохранить изменения", () => run(() => publish({apply: "next_connection", confirm_interrupt: false})), "primary");
  const applyNow = button("Применить сейчас…", () => run(async () => {
    const timing = await confirmAction({title: "Применить изменения сейчас?", description: "Сохраним изменения маршрутов. Приложения смогут получить правила и переподключить VPN.", confirmText: "Сохранить и применить", interrupt: true});
    if (timing) await publish(timing);
  }));
  const discard = button("Отменить изменения", () => run(reload), "quiet editor-control");
  saveButton.id = "save";
  applyNow.id = "save-now";
  discard.id = "discard-changes";
  saveActions.append(saveButton, applyNow, discard);
  saveBar.append(saveMessage, saveActions);
  content.append(pickerField, sectionHeading, addPanel, toolbar, table, pagination, saveBar);
  workspace.append(rail, content);
  const historyContainer = node("div", undefined, "rules-history");
  const histories = {};
  for (const source of Object.keys(feeds)) {
    const disclosure = node("details", undefined, "history-disclosure");
    disclosure.append(node("summary", `История: ${feeds[source].title}`));
    const historyStatus = node("p", "Откройте историю, чтобы загрузить сохранённые версии.", "muted small");
    const historyList = node("ol", undefined, "history-list");
    disclosure.append(historyStatus, button("Обновить историю", () => run(() => loadHistory(source))), historyList);
    disclosure.addEventListener("toggle", () => { if (disclosure.open && ready && !busy) run(() => loadHistory(source)); });
    histories[source] = {disclosure, status: historyStatus, list: historyList};
    historyContainer.append(disclosure);
  }
  main.replaceChildren(header, nav, feedback, workspace, historyContainer);

  function categoryOf(rule, state = metadata) {
    if (state === metadata && pendingAssignments.has(key(rule))) return pendingAssignments.get(key(rule));
    const assignment = state.assignments.find((item) => key(item) === key(rule));
    if (assignment) return assignment.category;
    const fallback = rule.source === "site" ? "sites" : "telephony";
    return state.categories.some((category) => category.id === fallback) ? fallback : null;
  }
  function categoryName(id) {
    return id === "*" ? "Все адреса" : id === "" || id === null ? "Без категории" : metadata.categories.find((category) => category.id === id)?.name || "Все адреса";
  }
  function putAssignment(state, rule, category) {
    const assignment = {source: rule.source, value: rule.value, category};
    const index = state.assignments.findIndex((item) => key(item) === key(rule));
    if (index < 0) state.assignments.push(assignment);
    else state.assignments[index] = assignment;
  }
  function selectCategory(id) {
    const hash = id === "*" ? "#all" : id === "" ? "#uncategorized" : `#category/${encodeURIComponent(id)}`;
    if (location.hash === hash) { selected = id; page = 0; render(); }
    else location.hash = hash;
  }
  function readCategoryHash() {
    let id = "*";
    if (location.hash === "#sites") id = "sites";
    else if (location.hash === "#telephony") id = "telephony";
    else if (location.hash === "#uncategorized") id = "";
    else if (location.hash.startsWith("#category/")) {
      try { id = decodeURIComponent(location.hash.slice(10)); } catch { id = "*"; }
    }
    selected = id === "" || id === "*" || metadata.categories.some((category) => category.id === id) ? id : "*";
    page = 0;
    render();
  }
  function update() {
    main.setAttribute("aria-busy", String(busy));
    window.corpPhoneDirty = isDirty("phone");
    for (const control of main.querySelectorAll("button,input,select")) control.disabled = busy || !ready || sessionLost;
    for (const control of content.querySelectorAll("button,input,select")) control.disabled ||= stale();
    for (const control of rail.querySelectorAll("button")) control.disabled ||= metadataStale;
    reloadButton.hidden = ready && !stale() && !sessionLost;
    reloadButton.disabled = busy || sessionLost;
    logoutButton.disabled = busy || !feeds.site.csrf;
    login.hidden = !sessionLost;
    saveButton.disabled ||= !Object.keys(feeds).some(needsPublication);
    applyNow.disabled = saveButton.disabled;
    discard.hidden = !dirty();
    discard.disabled = busy || sessionLost;
    addButton.disabled ||= !candidate;
    previous.disabled ||= page === 0;
    next.disabled ||= Number(next.dataset.lastPage) <= page;
    renameCategory.hidden = removeCategory.hidden = selected === "*" || selected === "";
    for (const [source, history] of Object.entries(histories)) {
      for (const control of history.list.querySelectorAll("button")) control.disabled ||= feeds[source].stale || Number(control.dataset.revision) === feeds[source].revision;
    }
    saveTitle.textContent = dirty() ? "Есть несохранённые изменения маршрутов" : Object.values(feeds).some((feed) => feed.revision === 0) ? "Начальные правила ещё не опубликованы" : "Все изменения сохранены";
  }
  function render() {
    const all = records();
    const categoryOptions = [["*", "Все адреса"], ...metadata.categories.map(({id, name}) => [id, name]), ["", "Без категории"]];
    categoryList.replaceChildren();
    categoryPicker.replaceChildren();
    for (const [id, name] of categoryOptions) {
      const total = all.filter((rule) => id === "*" || categoryOf(rule) === (id || null)).length;
      const categoryButton = button("", () => selectCategory(id), "category-button");
      categoryButton.dataset.category = id;
      categoryButton.append(node("span", name, "category-name"), node("span", String(total), "category-count"));
      categoryButton.setAttribute("aria-pressed", String(selected === id));
      if (selected === id) categoryButton.setAttribute("aria-current", "true");
      categoryList.append(categoryButton);
      const option = node("option", `${name} (${total})`);
      option.value = id;
      categoryPicker.append(option);
    }
    categoryPicker.value = selected;
    categoryTitle.textContent = categoryName(selected);
    const query = search.value.trim().toLocaleLowerCase("ru");
    const inCategory = all.filter((rule) => selected === "*" || categoryOf(rule) === (selected || null));
    const visible = inCategory.filter((rule) => rule.value.toLocaleLowerCase("ru").includes(query) && (routeFilter.value === "all" || rule.action === routeFilter.value));
    const pages = Math.max(1, Math.ceil(visible.length / pageSize));
    page = Math.max(0, Math.min(page, pages - 1));
    list.replaceChildren();
    for (const rule of visible.slice(page * pageSize, (page + 1) * pageSize)) {
      const row = node("tr");
      const addressCell = node("td");
      addressCell.append(node("span", rule.value, "site-name"));
      if (selected === "*") addressCell.append(node("p", categoryName(categoryOf(rule)), "muted small rule-category"));
      const routeCell = node("td");
      routeCell.append(node("span", "Как открывать", "mobile-label"));
      const routeGroup = node("div", undefined, "route-switch");
      routeGroup.setAttribute("role", "group");
      routeGroup.setAttribute("aria-label", `Как открывать ${rule.value}`);
      for (const [action, title] of routeOptions) {
        const label = node("label", undefined, "route-option");
        const radio = node("input");
        radio.type = "radio";
        radio.name = `route-${rule.source}-${encodeURIComponent(rule.value)}`;
        radio.value = action;
        radio.checked = rule.action === action;
        label.dataset.action = action;
        radio.addEventListener("change", () => {
          if (!radio.checked) return;
          rule.action = action;
          status.textContent = "Маршрут изменён в черновике. Сохраните изменения.";
          if (routeFilter.value === "all") update();
          else { render(); routeFilter.focus(); }
        });
        label.append(radio, node("span", title));
        routeGroup.append(label);
      }
      routeCell.append(routeGroup);
      const actionCell = node("td");
      const rowActions = node("div", undefined, "row-actions");
      const move = button("Переместить", () => moveRule(rule), "quiet editor-control");
      move.setAttribute("aria-label", `Переместить ${rule.value} в категорию`);
      const remove = button("Удалить", () => {
        feeds[rule.source].rules = feeds[rule.source].rules.filter((item) => item !== rule);
        pendingAssignments.delete(key(rule));
        status.textContent = `${rule.value} удалён из черновика. Сохраните изменения.`;
        render();
      }, "remove editor-control");
      remove.setAttribute("aria-label", `Удалить ${rule.value} из правил`);
      rowActions.append(move, remove);
      actionCell.append(rowActions);
      row.append(addressCell, routeCell, actionCell);
      list.append(row);
    }
    if (!visible.length) {
      const row = node("tr");
      const cell = node("td", !ready ? "Загружаем адреса…" : query || routeFilter.value !== "all" ? "Адреса не найдены. Измените поиск или маршрут." : "В этой категории пока нет адресов. Добавьте адрес или переместите его из другой категории.", "empty-list");
      cell.colSpan = 3;
      row.append(cell);
      list.append(row);
    }
    count.textContent = query || routeFilter.value !== "all" ? `Найдено: ${visible.length} из ${inCategory.length}` : `Адресов: ${inCategory.length}`;
    range.textContent = visible.length ? `${page * pageSize + 1}–${Math.min((page + 1) * pageSize, visible.length)} из ${visible.length}` : "0 адресов";
    currentPage.textContent = `${page + 1} из ${pages}`;
    pagination.hidden = visible.length <= pageSize;
    next.dataset.lastPage = String(pages - 1);
    update();
  }

  async function request(path, body, source = "site", mutation = false) {
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), 30000);
    const markStale = () => { if (source === "metadata") metadataStale = true; else feeds[source].stale = true; };
    try {
      const response = await fetch(path, {
        method: body === undefined ? "GET" : "POST", credentials: "same-origin", cache: "no-store", redirect: "error", signal: controller.signal,
        headers: body === undefined ? {Accept: "application/json", ...(main.dataset.username ? {"X-Corp-Expected-Company": main.dataset.username} : {})} : {Accept: "application/json", ...(main.dataset.username ? {"X-Corp-Expected-Company": main.dataset.username} : {}), "Content-Type": "application/json", "X-Corp-CSRF": feeds[source === "metadata" ? "site" : source].csrf},
        body: body === undefined ? undefined : JSON.stringify(body),
      });
      const data = await response.json().catch(() => null);
      if (!response.ok) {
        if ([401, 403].includes(response.status)) sessionLost = true;
        if (mutation && (response.status === 409 || response.status === 408 || response.status >= 500)) markStale();
        const failure = new Error(typeof data?.message === "string" ? data.message : "Не удалось выполнить действие. Попробуйте снова.");
        failure.status = response.status;
        throw failure;
      }
      if (!data) {
        if (mutation) markStale();
        throw new Error("Не удалось прочитать ответ сервера.");
      }
      return data;
    } catch (failure) {
      if (mutation && !failure.status) markStale();
      if (failure.name === "AbortError" || failure instanceof TypeError) throw new Error("Нет ответа сервера. Черновик остаётся на странице.");
      throw failure;
    } finally { window.clearTimeout(timeout); }
  }
  function validateFeed(data, source) {
    const feed = feeds[source];
    if (!data || (Object.hasOwn(data, "schema") && data.schema !== 1) || !validRevision(data.revision) || typeof data.csrf !== "string" || !data.csrf || !Array.isArray(data.rules) || data.rules.length > feed.limit) throw new Error(`Не удалось прочитать правила: ${feed.title}.`);
    const seen = new Set();
    const rules = data.rules.map((rule) => {
      if (!rule || !["direct", "proxy"].includes(rule.action) || typeof rule.comment !== "string" || utf8.encode(rule.comment).length > 256 || /[\u0000-\u001f\u007f-\u009f]/u.test(rule.comment)) throw new Error(`Не удалось прочитать правило: ${feed.title}.`);
      const value = source === "site" ? rule.domain : rule.value;
      const type = source === "site" ? "domain_suffix" : rule.type;
      if (!boundedAddress(value) || !["domain_suffix", "ip_cidr"].includes(type)) throw new Error(`Не удалось прочитать адрес: ${feed.title}.`);
      const identity = JSON.stringify([type, value]);
      if (seen.has(identity)) throw new Error(`Повторяющийся адрес: ${feed.title}.`);
      seen.add(identity);
      return {source, type, value, action: rule.action, comment: rule.comment};
    });
    return {rules, revision: data.revision, csrf: data.csrf};
  }
  function validateMetadata(data) {
    if (!exactKeys(data, ["schema", "revision", "categories", "assignments"]) || data.schema !== 1 || !validRevision(data.revision) || !Array.isArray(data.categories) || data.categories.length > 32 || !Array.isArray(data.assignments) || data.assignments.length > 576) throw new Error("Не удалось прочитать категории.");
    const ids = new Set(), names = new Set(), assignments = new Set();
    for (const category of data.categories) {
      if (!exactKeys(category, ["id", "name"]) || typeof category.id !== "string" || !/^[a-z][a-z0-9-]{0,39}$/.test(category.id) || !validName(category.name) || ids.has(category.id) || names.has(category.name)) throw new Error("Не удалось прочитать категорию.");
      ids.add(category.id);
      names.add(category.name);
    }
    for (const assignment of data.assignments) {
      if (!exactKeys(assignment, ["source", "value", "category"]) || !["site", "phone"].includes(assignment.source) || !boundedAddress(assignment.value) || (assignment.category !== null && !ids.has(assignment.category)) || assignments.has(key(assignment))) throw new Error("Не удалось прочитать распределение адресов по категориям.");
      assignments.add(key(assignment));
    }
    return data;
  }
  async function loadAll() {
    const site = validateFeed(await request("/api/corp/state"), "site");
    const phone = validateFeed(await request(phoneEndpoint, undefined, "phone"), "phone");
    // Metadata authorization uses the CSRF token returned by the real state GET.
    feeds.site.csrf = site.csrf;
    const categories = validateMetadata(await request("/api/corp/categories/state", {}, "metadata"));
    for (const [source, state] of [["site", site], ["phone", phone]]) {
      Object.assign(feeds[source], state, {saved: fingerprint(state.rules), publishedKeys: new Set(state.rules.map(key)), stale: false});
    }
    metadata = categories;
    pendingAssignments.clear();
    metadataStale = sessionLost = false;
    ready = true;
    candidate = null;
    preview.hidden = true;
    addPanel.open = false;
    readCategoryHash();
    status.textContent = "Правила загружены.";
  }
  async function loadFeed(source) {
    const state = validateFeed(await request(source === "site" ? "/api/corp/state" : phoneEndpoint, undefined, source), source);
    if (state.revision < feeds[source].revision) throw new Error("Сервер вернул устаревшую версию правил. Загрузите актуальные правила.");
    Object.assign(feeds[source], state, {saved: fingerprint(state.rules), publishedKeys: new Set(state.rules.map(key)), stale: false});
    for (const pendingKey of pendingAssignments.keys()) if (JSON.parse(pendingKey)[0] === source) pendingAssignments.delete(pendingKey);
    render();
  }
  async function reload() {
    if (dirty() && !await confirmAction({title: "Загрузить актуальные правила?", description: "Несохранённые изменения маршрутов будут заменены правилами с сервера. Сохранённые категории останутся.", confirmText: "Загрузить и заменить"})) return;
    await loadAll();
  }
  async function run(operation) {
    if (busy) return;
    busy = true;
    error.hidden = true;
    update();
    try { await operation(); }
    catch (failure) {
      error.textContent = failure.message || "Не удалось выполнить действие.";
      if (stale()) error.textContent += " Черновик сохранён на странице. Загрузите актуальные правила перед следующим сохранением.";
      error.hidden = false;
    } finally { busy = false; update(); }
  }
  async function saveMetadata(nextState) {
    if (metadataStale || sessionLost) throw new Error("Сначала загрузите актуальные категории.");
    validateMetadata({schema: 1, revision: metadata.revision, ...nextState});
    const result = await request("/api/corp/categories/save", {expected_revision: metadata.revision, categories: nextState.categories, assignments: nextState.assignments}, "metadata", true);
    let accepted;
    try {
      accepted = validateMetadata(result);
      if (accepted.revision < metadata.revision || JSON.stringify(accepted.categories) !== JSON.stringify(nextState.categories) || JSON.stringify(accepted.assignments) !== JSON.stringify(nextState.assignments)) throw new Error("Категории в ответе отличаются от сохранённых.");
    } catch (failure) { metadataStale = true; throw failure; }
    metadata = accepted;
    render();
  }
  function categoryForm(id) {
    if (busy || !ready || metadataStale) return;
    const existing = id ? metadata.categories.find((category) => category.id === id) : null;
    if (!existing && metadata.categories.length >= 32) { error.textContent = "Можно создать не больше 32 категорий."; error.hidden = false; return; }
    const dialog = node("dialog", undefined, "portal-dialog category-dialog");
    const title = node("h2", existing ? "Переименовать категорию" : "Новая категория");
    title.id = `category-dialog-${++dialogNumber}`;
    dialog.setAttribute("aria-labelledby", title.id);
    const form = node("form");
    const name = node("input");
    name.type = "text";
    name.id = "category-name";
    name.required = true;
    name.value = existing?.name || "";
    name.autocomplete = "off";
    name.autofocus = true;
    const issue = node("p", "", "notice error");
    issue.hidden = true;
    issue.setAttribute("role", "alert");
    const cancel = button("Отмена", () => dialog.close());
    const accept = node("button", existing ? "Сохранить название" : "Создать категорию", "primary");
    accept.type = "submit";
    accept.id = "save-category";
    const actions = node("div", undefined, "dialog-actions");
    actions.append(cancel, accept);
    const recover = button("Загрузить актуальные категории", async () => {
      if (busy) return;
      busy = true;
      accept.disabled = cancel.disabled = recover.disabled = name.disabled = true;
      update();
      try {
        metadata = validateMetadata(await request("/api/corp/categories/state", {}, "metadata"));
        metadataStale = false;
        render();
        recover.hidden = true;
        issue.textContent = "Актуальные категории загружены. Название осталось в поле; повторите сохранение.";
      } catch (failure) { issue.textContent = failure.message; }
      finally { busy = false; update(); accept.disabled = cancel.disabled = recover.disabled = name.disabled = false; }
    }, "quiet");
    recover.hidden = true;
    form.append(field("Название", name), issue, recover, actions);
    dialog.append(title, form);
    const categoryId = existing ? id : `c-${crypto.randomUUID()}`;
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      if (busy || sessionLost) return;
      const value = name.value.trim();
      if (!validName(value) || metadata.categories.some((category) => category.id !== categoryId && category.name.toLocaleLowerCase("ru") === value.toLocaleLowerCase("ru"))) {
        issue.textContent = "Укажите уникальное название: до 64 символов и 256 байт, без управляющих символов.";
        issue.hidden = false;
        return;
      }
      const nextState = cloneMetadata();
      const current = nextState.categories.find((category) => category.id === categoryId);
      if (existing && !current) {
        issue.textContent = "Эта категория уже удалена в другом окне. Закройте форму и создайте новую.";
        issue.hidden = false;
        return;
      }
      if (current) current.name = value;
      else nextState.categories.push({id: categoryId, name: value});
      busy = true;
      accept.disabled = cancel.disabled = recover.disabled = name.disabled = true;
      issue.hidden = true;
      update();
      try {
        await saveMetadata(nextState);
        dialog.close();
        selectCategory(categoryId);
        status.textContent = "Категория сохранена. Маршруты адресов не изменились.";
      } catch (failure) {
        issue.textContent = failure.message;
        issue.hidden = false;
        recover.hidden = !metadataStale || sessionLost;
      } finally { busy = false; update(); accept.disabled = cancel.disabled = recover.disabled = name.disabled = false; }
    });
    dialog.addEventListener("cancel", (event) => { if (busy) event.preventDefault(); });
    dialog.addEventListener("close", () => dialog.remove(), {once: true});
    document.body.append(dialog);
    dialog.showModal();
  }
  async function deleteCategory() {
    const id = selected;
    if (id === "*" || id === "") return;
    if (!await confirmAction({title: `Удалить категорию «${categoryName(id)}»?`, description: "Все её адреса перейдут в «Без категории». Правила и маршруты сохранятся.", confirmText: "Удалить категорию"})) return;
    const nextState = cloneMetadata();
    for (const assignment of nextState.assignments) if (assignment.category === id) assignment.category = null;
    for (const rule of records()) if (categoryOf(rule) === id) {
      if (feeds[rule.source].publishedKeys.has(key(rule))) putAssignment(nextState, rule, null);
      else pendingAssignments.set(key(rule), null);
    }
    nextState.categories = nextState.categories.filter((category) => category.id !== id);
    await saveMetadata(nextState);
    selectCategory("");
    status.textContent = "Категория удалена. Адреса перемещены в «Без категории».";
  }
  function moveRule(rule) {
    if (busy || !ready || stale()) return;
    const dialog = node("dialog", undefined, "portal-dialog category-dialog");
    const title = node("h2", "Переместить адрес");
    title.id = `move-dialog-${++dialogNumber}`;
    dialog.setAttribute("aria-labelledby", title.id);
    const destination = select([...metadata.categories.map(({id, name}) => [id, name]), ["", "Без категории"]]);
    destination.value = categoryOf(rule) || "";
    const actions = node("div", undefined, "dialog-actions");
    actions.append(button("Отмена", () => dialog.close()), button("Переместить", () => {
      const category = destination.value || null;
      dialog.close();
      run(async () => {
        if (!feeds[rule.source].publishedKeys.has(key(rule))) {
          pendingAssignments.set(key(rule), category);
          render();
          status.textContent = "Категория черновика изменена. Сохраните правило, чтобы передать его пользователям.";
          return;
        }
        const nextState = cloneMetadata();
        putAssignment(nextState, rule, category);
        await saveMetadata(nextState);
        status.textContent = `${rule.value}: категория сохранена. Маршрут не изменился.`;
      });
    }, "primary"));
    dialog.append(title, node("p", rule.value), field("Категория", destination), actions);
    dialog.addEventListener("close", () => dialog.remove(), {once: true});
    document.body.append(dialog);
    dialog.showModal();
  }
  function recognizedPhoneDomain(input) {
    let host = input.trim().toLowerCase();
    if (host.includes("://")) {
      try { host = new URL(host).hostname; } catch { return false; }
    }
    host = host.replace(/\.$/, "");
    return ["uiscom.ru", "uiscom.co", "comagic.ru", "callbackhunter.com"].some((suffix) => host === suffix || host.endsWith(`.${suffix}`));
  }
  function duplicate(candidateRule) {
    return records().some((rule) => rule.type === candidateRule.type && rule.value === candidateRule.value);
  }
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    run(async () => {
      candidate = null;
      preview.hidden = true;
      const source = kind.value === "ip_cidr" || recognizedPhoneDomain(address.value) ? "phone" : "site";
      const result = source === "phone"
        ? await request(`${phoneEndpoint}/normalize`, {type: kind.value, value: address.value}, "phone")
        : await request("/api/corp/normalize", {site: address.value});
      const value = source === "phone" ? result.value : result.domain;
      if (!boundedAddress(value) || (source === "phone" && result.type !== kind.value)) throw new Error("Не удалось проверить адрес.");
      if (kind.value === "ip_cidr" && !/^\d{1,3}(?:\.\d{1,3}){3}\/\d{1,2}$/.test(value)) throw new Error("Укажите IPv4-адрес или подсеть.");
      const checked = {source, type: kind.value, value};
      if (duplicate(checked)) throw new Error("Этот адрес уже есть в правилах. Найдите его через поиск.");
      candidate = checked;
      normalized.textContent = value;
      preview.hidden = false;
      status.textContent = "Адрес проверен. Выберите маршрут и добавьте его в черновик.";
    });
  });
  for (const input of [kind, address]) input.addEventListener("input", () => {
    candidate = null;
    preview.hidden = true;
    address.placeholder = kind.value === "ip_cidr" ? "192.0.2.1 или 192.0.2.0/24" : "example.com";
    update();
  });
  async function addAddress() {
    if (!candidate || stale()) return;
    const rule = {...candidate, action: newAction.value, comment: ""};
    const feed = feeds[rule.source];
    if (feed.rules.length >= feed.limit) throw new Error(`Достигнут лимит: ${rule.source === "site" ? "512 сайтов" : "64 адреса телефонии"}. Удалите ненужный адрес.`);
    if (duplicate(rule)) throw new Error("Этот адрес уже есть в правилах.");
    const category = selected === "*" ? categoryOf(rule) : selected || null;
    pendingAssignments.set(key(rule), category);
    feed.rules.unshift(rule);
    candidate = null;
    preview.hidden = true;
    address.value = "";
    search.value = "";
    routeFilter.value = "all";
    page = 0;
    render();
    status.textContent = `${rule.value} добавлен в черновик. Сохраните изменения.`;
  }
  function validateRoutes() {
    for (const source of Object.keys(feeds)) {
      const rules = feeds[source].rules;
      for (let i = 0; i < rules.length; i++) {
        const left = rules[i];
        for (const right of rules.slice(i + 1)) {
          if (left.type !== "domain_suffix" || right.type !== "domain_suffix" || left.action === right.action) continue;
          if (left.value === right.value || left.value.endsWith(`.${right.value}`) || right.value.endsWith(`.${left.value}`)) throw new Error(`Для ${left.value} и ${right.value} выбраны разные маршруты. У домена и его поддомена должен быть один маршрут.`);
        }
      }
    }
  }
  function acknowledge(result, source) {
    const feed = feeds[source];
    if (!result || !validRevision(result.revision) || result.revision <= feed.revision) {
      feed.stale = true;
      throw new Error(`Не удалось подтвердить сохранение: ${feed.title}.`);
    }
    feed.revision = result.revision;
  }
  async function publish(timing) {
    if (stale() || !Object.keys(feeds).some(needsPublication)) return;
    validateRoutes();
    const accepted = [];
    for (const source of Object.keys(feeds)) {
      if (!needsPublication(source)) continue;
      const feed = feeds[source];
      const rules = feed.rules.map((rule) => source === "site" ? {domain: rule.value, action: rule.action, comment: ""} : {type: rule.type, value: rule.value, action: rule.action, comment: ""});
      try {
        const result = await request(`${feed.endpoint}/rules`, {expected_revision: feed.revision, ...timing, rules}, source, true);
        acknowledge(result, source);
        for (const rule of feed.rules) rule.comment = "";
        feed.saved = fingerprint(feed.rules);
        feed.publishedKeys = new Set(feed.rules.map(key));
        accepted.push(feed.title);
        const publishedKeys = new Set(Object.values(feeds).flatMap((item) => [...item.publishedKeys]));
        const nextMetadata = cloneMetadata();
        nextMetadata.assignments = nextMetadata.assignments.filter((item) => publishedKeys.has(key(item)));
        for (const rule of feed.rules) if (pendingAssignments.has(key(rule))) putAssignment(nextMetadata, rule, pendingAssignments.get(key(rule)));
        if (JSON.stringify(nextMetadata.assignments) !== JSON.stringify(metadata.assignments)) await saveMetadata(nextMetadata);
        for (const pendingKey of pendingAssignments.keys()) if (JSON.parse(pendingKey)[0] === source) pendingAssignments.delete(pendingKey);
        update();
      } catch (failure) {
        if (accepted.length) status.textContent = `Сохранено: ${accepted.join(", ")}. Остальные изменения остаются в черновике.`;
        throw failure;
      }
    }
    status.textContent = timing.apply === "now" ? "Изменения сохранены. Приложения смогут получить правила и переподключить VPN; получение ещё не подтверждено." : "Изменения сохранены. Приложения смогут применить их при следующем подключении VPN.";
    for (const source of Object.keys(feeds)) if (histories[source].disclosure.open) {
      try { await loadHistory(source); } catch { histories[source].status.textContent = "Правила сохранены, но история не обновилась. Попробуйте обновить историю."; }
    }
    render();
  }
  async function loadHistory(source) {
    const feed = feeds[source], history = histories[source];
    const entries = await request(`${feed.endpoint}/history`, undefined, source);
    if (!Array.isArray(entries) || entries.some((entry) => !entry || !validRevision(entry.revision) || entry.revision < 1 || !Number.isSafeInteger(entry.published_at) || entry.published_at < 1 || !Number.isSafeInteger(entry.rule_count) || entry.rule_count < 0 || entry.rule_count > feed.limit || !["next_connection", "now"].includes(entry.apply))) throw new Error(`Не удалось прочитать историю: ${feed.title}.`);
    history.list.replaceChildren();
    for (const entry of entries) {
      const item = node("li");
      const restore = button(entry.revision === feed.revision ? "Текущая версия" : "Восстановить…", () => run(async () => {
        const timing = await confirmAction({title: `Восстановить версию ${entry.revision}: ${feed.title}?`, description: `Сохранённый список заменит правила и черновик этого списка. ${source === "site" ? "Черновик телефонии" : "Черновик сайтов"} и категории сохранятся.`, confirmText: "Восстановить", chooseTiming: true});
        if (!timing) return;
        const result = await request(`${feed.endpoint}/restore`, {expected_revision: feed.revision, revision: entry.revision, ...timing}, source, true);
        acknowledge(result, source);
        feed.stale = true;
        await loadFeed(source);
        status.textContent = "Версия восстановлена и сохранена на сервере.";
        await loadHistory(source);
      }));
      restore.dataset.revision = String(entry.revision);
      item.append(node("p", `Версия ${entry.revision} · ${new Date(entry.published_at * 1000).toLocaleString("ru")} · адресов: ${entry.rule_count}`), restore);
      history.list.append(item);
    }
    history.status.textContent = entries.length ? "Восстановление создаёт новую версию выбранного списка. Время указано по вашему часовому поясу." : "Сохранённых версий пока нет.";
    update();
  }
  async function logout() {
    if (dirty() && !await confirmAction({title: "Выйти без сохранения?", description: "Несохранённые изменения маршрутов будут потеряны.", confirmText: "Выйти"})) return;
    const response = await fetch("/logout", {method: "POST", credentials: "same-origin", cache: "no-store", redirect: "error", headers: {"X-Corp-CSRF": feeds.site.csrf}});
    if (!response.ok) throw new Error("Не удалось выйти. Попробуйте снова.");
    leaving = true;
    window.corpPhoneDirty = false;
    location.assign("/");
  }
  for (const control of [search, routeFilter]) control.addEventListener("input", () => { page = 0; render(); });
  window.addEventListener("hashchange", readCategoryHash);
  window.addEventListener("beforeunload", (event) => {
    if (dirty() && !leaving) { event.preventDefault(); event.returnValue = ""; }
  });
  main.addEventListener("click", (event) => {
    const link = event.target.closest("a[href]");
    if (!link || leaving || !dirty() || event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
    const url = new URL(link.href, location.href);
    if (url.origin === location.origin && url.pathname === location.pathname && url.search === location.search) return;
    event.preventDefault();
    run(async () => {
      if (!await confirmAction({title: "Перейти без сохранения?", description: "Несохранённые изменения маршрутов будут потеряны.", confirmText: "Перейти"})) return;
      leaving = true;
      location.assign(url.href);
    });
  });
  render();
  run(loadAll);
})();
