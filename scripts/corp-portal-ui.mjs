import assert from "node:assert/strict";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { verifyOperator } from "./corp-operator-ui.mjs";
import { verifyDiagnostics } from "./corp-diagnostics-ui.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const requiredEnv = (name) => { assert.ok(process.env[name], `${name} is required`); return path.resolve(process.env[name]); };
assert.equal(process.env.CI, "true", "Run browser verification in CI only");
const fixtures = requiredEnv("CORP_UI_OUTPUT_DIR");
const screenshots = requiredEnv("CORP_UI_SCREENSHOT_DIR");
const require = createRequire(path.join(requiredEnv("CORP_UI_TOOLING_DIR"), "package.json"));
const { chromium, expect } = require("@playwright/test");
const origin = "https://admin.corp.ninitux.com";
const csrf = "synthetic-browser-csrf";
const phone = "/api/v1/corp/portal/telephony";
const pages = Object.fromEntries(await Promise.all(["editor", "login", "denied", "unavailable"].map(async (name) => {
  const body = await readFile(path.join(fixtures, `${name}.html`), "utf8");
  const metadata = JSON.parse(await readFile(path.join(fixtures, `${name}.json`), "utf8"));
  assert.ok(metadata.headers["content-security-policy"]);
  assert.equal(metadata.status, {editor: 200, login: 200, denied: 403, unavailable: 503}[name]);
  return [name, {body, ...metadata}];
})));
const username = pages.editor.body.match(/data-username="([^"]+)"/)?.[1];
assert.ok(username, "Router editor fixture must expose its synthetic username");
const assets = {};
for (const name of ["corp.css", "corp.js", "corp-phone.js"]) {
  let body = await readFile(path.join(root, "daemon/assets/corp-portal", name), "utf8");
  if (name === "corp.css") body = await readFile(path.join(root, "daemon/assets/css/theme.css"), "utf8") + body;
  assert.equal(await readFile(path.join(fixtures, "assets", name), "utf8"), body);
  assets[`/assets/${name}`] = {body, contentType: name.endsWith("css") ? "text/css" : "text/javascript"};
}
const siteRules = [{domain: "office.example.com", action: "direct", comment: "old note"}, {domain: "other.example.com", action: "proxy", comment: ""}];
const phoneRules = [{type: "domain_suffix", value: "uiscom.ru", action: "direct", comment: "old note"}];
const defaults = [{id: "sites", name: "Сайты"}, {id: "telephony", name: "Телефония"}];
await mkdir(screenshots, {recursive: true});
const browser = await chromium.launch();
const completed = [];
async function shot(page, name, width) {
  const layout = await page.evaluate(() => {
    const dialog = document.querySelector("dialog[open]");
    const box = dialog?.getBoundingClientRect();
    return {viewport: innerWidth, document: document.documentElement.scrollWidth, body: document.body.scrollWidth,
      dialog: box && {left: box.left, right: box.right, scroll: dialog.scrollWidth, width: dialog.clientWidth}};
  });
  await page.screenshot({path: path.join(screenshots, `${width}-${name}.png`), fullPage: !layout.dialog, animations: "disabled"});
  assert.ok(layout.document <= layout.viewport && layout.body <= layout.viewport, `${name}: overflow ${JSON.stringify(layout)}`);
  if (layout.dialog) assert.ok(layout.dialog.left >= 0 && layout.dialog.right <= layout.viewport && layout.dialog.scroll <= layout.dialog.width, `${name}: dialog overflow`);
}
async function harness(name, width, rules = siteRules) {
  const context = await browser.newContext({offline: true, viewport: {width, height: 900}, locale: "ru-RU", timezoneId: "UTC", reducedMotion: "reduce", serviceWorkers: "block"});
  const errors = [], calls = [];
  const state = {authenticated: name === "editor", site: {revision: 7, rules: structuredClone(rules), history: new Map([[6, [{domain: "archive.example.com", action: "proxy", comment: ""}]], [7, structuredClone(rules)]])}, phone: {revision: 3, rules: structuredClone(phoneRules), history: new Map([[3, structuredClone(phoneRules)]])}, metadata: {schema: 1, revision: 1, categories: structuredClone(defaults), assignments: []}, failure: null};
  await context.routeWebSocket("**/*", socket => { errors.push(`Unexpected WebSocket: ${socket.url()}`); socket.close(); });
  const page = await context.newPage();
  page.on("pageerror", e => errors.push(e.message));
  page.on("console", m => { if (/content security policy|refused to (?:load|execute|connect)/i.test(m.text())) errors.push(m.text()); });
  await context.route("**/*", async route => {
    try {
      const req = route.request(), url = new URL(req.url()), endpoint = url.pathname;
      assert.equal(url.origin, origin); assert.equal(url.search, "");
      if (endpoint === "/" && req.method() === "GET") return await route.fulfill(pages[state.authenticated ? "editor" : name]);
      if (assets[endpoint] && req.method() === "GET") return await route.fulfill({status: 200, ...assets[endpoint]});
      if (endpoint === "/login" && req.method() === "POST" && name === "login") {
        assert.equal(req.headers().origin, origin);
        assert.deepEqual([...new URLSearchParams(req.postData())], [["username", username], ["password", "synthetic-browser-password"]]);
        calls.push({endpoint}); state.authenticated = true; return await route.fulfill(pages.editor);
      }
      assert.ok(state.authenticated, "Unauthenticated API request");
      const post = req.method() === "POST";
      assert.ok(post || req.method() === "GET");
      assert.equal(req.headers()["x-corp-expected-company"], username, `Company assertion on ${endpoint}`);
      if (post) { assert.equal(req.headers().origin, origin); assert.equal(req.headers()["x-corp-csrf"], csrf); }
      const body = post ? req.postDataJSON() : undefined;
      calls.push({endpoint, body});
      const respond = async (status, json) => route.fulfill({status, json});
      if (state.failure === endpoint) { state.failure = null; return await respond(409, {message: "Версия изменилась"}); }
      if (endpoint === "/api/corp/categories/state") { assert.ok(post); assert.deepEqual(body, {}); return await respond(200, state.metadata); }
      if (endpoint === "/api/corp/categories/save") {
        assert.ok(post); assert.deepEqual(Object.keys(body).sort(), ["assignments", "categories", "expected_revision"]);
        assert.equal(body.expected_revision, state.metadata.revision);
        state.metadata = {schema: 1, revision: state.metadata.revision + 1, categories: structuredClone(body.categories), assignments: structuredClone(body.assignments)};
        return await respond(200, state.metadata);
      }
      const source = endpoint.startsWith(phone) ? "phone" : "site";
      const prefix = source === "phone" ? phone : "/api/corp";
      const suffix = endpoint.slice(prefix.length);
      const feed = state[source];
      if ((source === "site" && suffix === "/state") || (source === "phone" && suffix === "")) { assert.ok(!post); return await respond(200, {revision: feed.revision, rules: feed.rules, csrf, company: {username}}); }
      if (suffix === "/history") { assert.ok(!post); return await respond(200, [...feed.history].reverse().map(([revision, rules]) => ({revision, rule_count: rules.length, published_at: 1763164800 + revision, apply: "next_connection"}))); }
      if (suffix === "/normalize") { assert.ok(post); return await respond(200, source === "site" ? {domain: body.site.toLowerCase()} : {type: body.type, value: body.value.toLowerCase()}); }
      assert.ok(post && ["/rules", "/restore"].includes(suffix), `Unexpected request ${req.method()} ${endpoint}`);
      assert.deepEqual(Object.keys(body).sort(), ["apply", "confirm_interrupt", "expected_revision", suffix === "/rules" ? "rules" : "revision"].sort());
      assert.equal(body.expected_revision, feed.revision); assert.ok(["now", "next_connection"].includes(body.apply));
      assert.equal(body.confirm_interrupt, body.apply === "now");
      const next = suffix === "/rules" ? body.rules : feed.history.get(body.revision);
      assert.ok(Array.isArray(next));
      if (suffix === "/rules") for (const rule of next) assert.equal(rule.comment, "", "Notes must never be published");
      feed.rules = structuredClone(next); feed.revision++; feed.history.set(feed.revision, structuredClone(next));
      return await respond(200, {revision: feed.revision, published_at: 1763164800 + feed.revision});
    } catch (e) { errors.push(e.stack); await route.abort("blockedbyclient"); }
  });
  const response = await page.goto(`${origin}/`); assert.equal(response.status(), pages[name].status);
  await page.evaluate(() => document.fonts.ready);
  if (name === "editor") await idle(page);
  return {page, calls, state, async close() { await context.close(); assert.deepEqual(errors, [], "Browser/routing errors"); }};
}
async function idle(page) { await expect(page.locator("#corp-editor")).toHaveAttribute("aria-busy", "false"); }
const routingWrites = h => h.calls.filter(c => /\/(rules|restore)$/.test(c.endpoint));
async function choose(page, id) { await page.evaluate(id => { location.hash = id === "*" ? "#all" : `#category/${id}`; }, id); await expect(page.locator("#category-picker")).toHaveValue(id); }
async function routeChoice(page, value, action) { await page.getByRole("group", {name: `Как открывать ${value}`}).locator(`input[value="${action}"]`).check(); }
async function scenario(width) {
  const h = await harness("editor", width), p = h.page;
  try {
    await expect(p.getByRole("heading", {name: "Правила", exact: true})).toBeVisible();
    await expect(p.locator("#rules")).toContainText("office.example.com");
    await expect(p.locator('input[name*="comment"], textarea')).toHaveCount(0);
    await shot(p, "rules", width);
    const gap = await p.evaluate(() => document.documentElement.scrollHeight - document.querySelector(".rules-history").getBoundingClientRect().bottom - scrollY);
    assert.ok(gap >= 16, `Bottom gap ${gap}`);
    await p.locator(width <= 740 ? "#add-category-mobile" : "#add-category").click();
    await p.locator("#category-name").fill("Работа");
    h.state.failure = "/api/corp/categories/save";
    await p.locator("#save-category").click();
    const categoryDialog = p.getByRole("dialog");
    await expect(categoryDialog.getByRole("alert")).toBeVisible();
    await categoryDialog.getByRole("button", {name: "Загрузить актуальные категории"}).click();
    await expect(p.locator("#category-name")).toHaveValue("Работа");
    await p.locator("#save-category").click(); await idle(p);
    const category = h.state.metadata.categories.find(c => c.name === "Работа"); assert.ok(category);
    await p.locator("#rename-category").click(); await p.locator("#category-name").fill("Команда"); await p.locator("#save-category").click(); await idle(p);
    await choose(p, "*");
    await p.getByRole("button", {name: "Переместить office.example.com в категорию"}).click();
    await p.getByRole("dialog").getByLabel("Категория").selectOption(category.id);
    await p.getByRole("dialog").getByRole("button", {name: "Переместить", exact: true}).click(); await idle(p);
    assert.deepEqual(h.state.metadata.assignments, [{source: "site", value: "office.example.com", category: category.id}]);
    await choose(p, category.id); await p.locator("#delete-category").click();
    await p.getByRole("dialog").getByRole("button", {name: "Удалить категорию", exact: true}).click(); await idle(p);
    assert.equal(h.state.metadata.assignments[0].category, null); assert.equal(routingWrites(h).length, 0);
    await choose(p, "sites"); await p.locator("#add-rule").click(); await p.locator("#new-address").fill("draft.example.com");
    await p.getByRole("button", {name: "Проверить адрес"}).click(); await idle(p);
    await p.getByRole("button", {name: "Добавить в черновик"}).click(); await idle(p);
    assert.ok(!h.state.metadata.assignments.some(a => a.value === "draft.example.com"));
    await p.locator("#discard-changes").click(); await p.getByRole("dialog").getByRole("button", {name: "Загрузить и заменить"}).click(); await idle(p);
    assert.ok(!h.state.metadata.assignments.some(a => a.value === "draft.example.com"));
    await choose(p, "*"); await routeChoice(p, "office.example.com", "proxy");
    await p.getByRole("link", {name: "Диагностика"}).click(); await p.getByRole("dialog").getByRole("button", {name: "Отмена"}).click();
    await expect(p.getByRole("group", {name: "Как открывать office.example.com"}).locator('input[value="proxy"]')).toBeChecked();
    await p.locator("#save").click(); await idle(p); assert.equal(h.state.site.revision, 8); assert.equal(h.state.phone.revision, 3);
    await routeChoice(p, "uiscom.ru", "proxy"); await p.locator("#save-now").click();
    const dialog = p.getByRole("dialog"); await expect(dialog.getByRole("button", {name: "Сохранить и применить"})).toBeDisabled();
    await dialog.getByRole("checkbox").check(); await dialog.getByRole("button", {name: "Сохранить и применить"}).click(); await idle(p);
    assert.equal(h.state.phone.revision, 4); assert.equal(h.state.site.revision, 8);
    await routeChoice(p, "office.example.com", "direct"); await routeChoice(p, "uiscom.ru", "direct");
    h.state.failure = `${phone}/rules`; await p.locator("#save").click(); await idle(p);
    await expect(p.locator("#error")).toBeVisible(); await expect(p.locator("#status")).toContainText("Сохранено: Сайты");
    assert.equal(h.state.site.revision, 9); assert.equal(h.state.phone.revision, 4);
    await expect(p.getByRole("group", {name: "Как открывать uiscom.ru"}).locator('input[value="direct"]')).toBeChecked();
    await p.getByRole("button", {name: "Загрузить актуальные правила"}).click(); await p.getByRole("dialog").getByRole("button", {name: "Загрузить и заменить"}).click(); await idle(p);
    await p.getByText("История: Сайты", {exact: true}).click(); await idle(p);
    await p.locator('button[data-revision="6"]').click(); await p.getByRole("dialog").getByRole("button", {name: "Восстановить", exact: true}).click(); await idle(p);
    await expect(p.locator("#rules")).toContainText("archive.example.com");
    completed.push(`${width}/rules-categories-save-conflict-history`);
  } finally { await h.close(); }
}
async function pagination(width) {
  const rules = Array.from({length: 12}, (_, i) => ({domain: `host${i}.example.com`, action: i % 2 ? "proxy" : "direct", comment: ""}));
  const h = await harness("editor", width, rules), p = h.page;
  try {
    await expect(p.locator("#rules tr")).toHaveCount(10); await p.locator("#next-page").click(); await expect(p.locator("#rules tr")).toHaveCount(3);
    await p.locator("#rules-search").fill("host1.example"); await expect(p.locator("#rules tr")).toHaveCount(1);
    await p.locator("#route-filter").selectOption("direct"); await expect(p.locator("#rules")).toContainText("Адреса не найдены");
    await p.locator("#rules-search").fill(""); await expect(p.locator("#rules tr")).toHaveCount(7);
    await p.locator("#rules-search").focus(); await p.keyboard.press("Tab"); await expect(p.locator("#route-filter")).toBeFocused();
    completed.push(`${width}/pagination-search-filter-keyboard`);
  } finally { await h.close(); }
}
try {
  for (const width of [320, 390, 800, 1280]) { await scenario(width); await pagination(width); }
  for (const name of ["login", "denied", "unavailable"]) {
    const h = await harness(name, 320), p = h.page;
    try {
      await expect(p.getByRole("heading", {level: 1})).toBeVisible(); await shot(p, name, 320);
      if (name === "login") {
        await expect(p.locator('input[name="username"]')).toHaveAttribute("autocomplete", "username");
        await p.locator('input[name="username"]').fill(username); await p.locator('input[name="password"]').fill("synthetic-browser-password");
        await p.locator('form button[type="submit"]').click(); await idle(p); assert.equal(h.calls.filter(c => c.endpoint === "/login").length, 1);
      }
      completed.push(`320/${name}`);
    } finally { await h.close(); }
  }
  completed.push(...await verifyOperator(browser, expect, shot));
  completed.push(...await verifyDiagnostics(browser, expect, shot));
} finally { await writeFile(path.join(screenshots, "completed-scenarios.json"), `${JSON.stringify(completed, null, 2)}\n`); await browser.close(); }
