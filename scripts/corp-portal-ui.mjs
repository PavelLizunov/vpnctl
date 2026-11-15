import assert from "node:assert/strict";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { verifyOperator } from "./corp-operator-ui.mjs";
import { verifyDiagnostics } from "./corp-diagnostics-ui.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const requiredEnv = (name) => {
  assert.ok(process.env[name], `${name} must name a CI temporary directory`);
  return path.resolve(process.env[name]);
};
assert.equal(process.env.CI, "true", "Run browser verification in CI only");
const fixtures = requiredEnv("CORP_UI_OUTPUT_DIR");
const screenshots = requiredEnv("CORP_UI_SCREENSHOT_DIR");
const require = createRequire(path.join(requiredEnv("CORP_UI_TOOLING_DIR"), "package.json"));
const { chromium, expect } = require("@playwright/test");
const origin = "https://admin.corp.ninitux.com";
const csrf = "synthetic-browser-csrf";
const publishedAt = 1_763_164_800;
const initialRules = [
  { domain: "office.example.com", action: "direct", comment: "Рабочие документы" },
  { domain: "remove.example.com", action: "proxy", comment: "Старое правило" },
];
const historicalRules = [
  { domain: "archive.example.com", action: "proxy", comment: "Архивный список" },
];
const longMessage = "Не удалось завершить действие. Подключение корпоративного VPN временно прервалось. "
  + "Ваши несохранённые изменения остаются на этой странице. Проверьте подключение и загрузите "
  + "актуальный список правил, прежде чем продолжить работу. Если проблема повторяется, обратитесь к администратору.";
const pages = Object.fromEntries(await Promise.all(
  ["editor", "login", "denied", "unavailable"].map(async (name) => {
    const body = await readFile(path.join(fixtures, `${name}.html`), "utf8");
    const metadata = JSON.parse(await readFile(path.join(fixtures, `${name}.json`), "utf8"));
    assert.ok(metadata.headers["content-security-policy"], `${name}: missing real router CSP`);
    assert.equal(metadata.status, { editor: 200, login: 200, denied: 403, unavailable: 503 }[name]);
    return [name, { body, ...metadata }];
  }),
));
const assets = Object.fromEntries(await Promise.all(["css", "js"].map(async (extension) => {
  const body = await readFile(path.join(root, "daemon/assets/corp-portal", `corp.${extension}`), "utf8");
  assert.equal(await readFile(path.join(fixtures, "assets", `corp.${extension}`), "utf8"), body,
    `Router-exported corp.${extension} must match the candidate source`);
  return [`/assets/corp.${extension}`, { body, contentType: extension === "css" ? "text/css" : "text/javascript" }];
})));
await mkdir(screenshots, { recursive: true });
const browser = await chromium.launch();
const completed = [];

function writes(harness) {
  return harness.calls.filter(({ endpoint }) => ["/api/corp/rules", "/api/corp/restore"].includes(endpoint));
}

async function harness(pageName, width) {
  const context = await browser.newContext({
    offline: true,
    viewport: { width, height: 900 }, deviceScaleFactor: 1,
    locale: "ru-RU", timezoneId: "UTC", reducedMotion: "reduce", serviceWorkers: "block",
  });
  const errors = [];
  const calls = [];
  await context.routeWebSocket("**/*", (socket) => {
    errors.push(`Unexpected WebSocket request: ${socket.url()}`);
    socket.close({ code: 1008, reason: "Synthetic verification blocks network sockets" });
  });
  const page = await context.newPage();
  const state = {
    authenticated: pageName === "editor",
    revision: 7, rules: structuredClone(initialRules), failure: null,
    snapshots: new Map([[6, structuredClone(historicalRules)], [7, structuredClone(initialRules)]]),
    timings: new Map([[6, "next_connection"], [7, "next_connection"]]),
  };
  page.on("pageerror", (error) => errors.push(error.message));
  page.on("console", (message) => {
    if (/content security policy|refused to (?:load|execute|connect)/i.test(message.text())) {
      errors.push(message.text());
    }
  });
  await context.route("**/*", async (route) => {
    try {
      const request = route.request();
      const url = new URL(request.url());
      assert.equal(url.origin, origin, `Unexpected request: ${url.origin}`);
      assert.equal(url.search, "", "Unexpected request query");
      const endpoint = url.pathname;
      if (endpoint === "/" && request.method() === "GET") {
        await route.fulfill(pages[state.authenticated ? "editor" : pageName]);
        return;
      }
      if (assets[endpoint] && request.method() === "GET") {
        await route.fulfill({ status: 200, ...assets[endpoint] });
        return;
      }
      if (pageName === "login" && endpoint === "/login" && request.method() === "POST") {
        assert.equal(request.headers().origin, origin, "Native login form must retain its exact Origin");
        const form = new URLSearchParams(request.postData());
        assert.deepEqual([...form], [["password", "synthetic-browser-password"]]);
        calls.push({ endpoint });
        state.authenticated = true;
        // Chromium bypasses route interception on redirects; HTTP tests cover the server's 303.
        await route.fulfill(pages.editor);
        return;
      }
      assert.ok(state.authenticated, "Access page attempted an API call");
      assert.ok(["/api/corp/state", "/api/corp/normalize", "/api/corp/rules", "/api/corp/history", "/api/corp/restore"].includes(endpoint), `Unexpected path: ${endpoint}`);
      const post = ["/api/corp/normalize", "/api/corp/rules", "/api/corp/restore"].includes(endpoint);
      assert.equal(request.method(), post ? "POST" : "GET");
      const body = post ? request.postDataJSON() : undefined;
      calls.push({ endpoint, body });
      if (post) {
        assert.equal(request.headers()["x-corp-csrf"], csrf);
        assert.equal(request.headers().origin, origin);
      }
      const respond = (status, data) => route.fulfill({ status, json: data });
      const failure = state.failure?.endpoint === endpoint ? state.failure : null;
      if (failure) state.failure = null;
      if (failure && !failure.commit) {
        await respond(failure.status, { message: longMessage });
        return;
      }
      if (endpoint === "/api/corp/state") {
        await respond(200, { revision: state.revision, rules: state.rules, csrf });
      } else if (endpoint === "/api/corp/history") {
        await respond(200, [...state.snapshots].reverse().map(([revision, rules]) => ({
          revision, rule_count: rules.length, published_at: publishedAt + revision,
          apply: state.timings.get(revision),
        })));
      } else if (endpoint === "/api/corp/normalize") {
        assert.deepEqual(body, { site: "https://PORTAL.Example.com/documents?view=all" });
        await respond(200, { domain: "portal.example.com" });
      } else {
        const restoring = endpoint === "/api/corp/restore";
        assert.deepEqual(Object.keys(body).sort(), ["apply", "confirm_interrupt", "expected_revision", restoring ? "revision" : "rules"].sort());
        assert.equal(body.expected_revision, state.revision, "Write must use reconciled revision");
        assert.ok(["now", "next_connection"].includes(body.apply));
        assert.equal(body.confirm_interrupt, body.apply === "now");
        const nextRules = restoring ? state.snapshots.get(body.revision) : body.rules;
        assert.ok(Array.isArray(nextRules), "Publication must contain a complete list");
        state.rules = structuredClone(nextRules);
        state.revision += 1;
        state.snapshots.set(state.revision, structuredClone(state.rules));
        state.timings.set(state.revision, body.apply);
        await respond(failure?.status ?? 200, failure ? { message: longMessage } : {
          revision: state.revision, published_at: publishedAt + state.revision,
        });
      }
    } catch (error) {
      errors.push(error.stack);
      await route.abort("blockedbyclient");
    }
  });
  const result = {
    page, state, calls, errors,
    fail(endpoint, status, commit = false) { state.failure = { endpoint, status, commit }; },
    async close() { await context.close(); assert.deepEqual(errors, [], "Browser/routing errors"); },
  };
  const response = await page.goto(`${origin}/`);
  assert.equal(response.status(), pages[pageName].status);
  await page.evaluate(() => document.fonts.ready);
  if (pageName === "editor") {
    await idle(page);
    await expect(page.locator("#draft-status")).toContainText("Версия 7.");
  }
  return result;
}

async function idle(page) {
  await expect(page.locator("#corp-editor")).toHaveAttribute("aria-busy", "false");
}

async function shot(page, name, width) {
  const layout = await page.evaluate(() => {
    const dialog = document.querySelector("dialog[open]");
    const box = dialog?.getBoundingClientRect();
    return {
      viewport: innerWidth,
      document: document.documentElement.scrollWidth,
      body: document.body.scrollWidth,
      dialog: box && { left: box.left, right: box.right, scroll: dialog.scrollWidth, width: dialog.clientWidth },
    };
  });
  await page.screenshot({ path: path.join(screenshots, `${width}-${name}.png`), fullPage: !layout.dialog, animations: "disabled" });
  assert.ok(layout.document <= layout.viewport && layout.body <= layout.viewport, `${name}: horizontal page overflow ${JSON.stringify(layout)}`);
  if (layout.dialog) {
    assert.ok(layout.dialog.left >= 0 && layout.dialog.right <= layout.viewport && layout.dialog.scroll <= layout.dialog.width, `${name}: horizontal dialog overflow`);
    await expect(page.locator("#accept-confirm")).toBeInViewport();
    await expect(page.locator("#cancel-confirm")).toBeInViewport();
  }
}

async function draft(page, comment = "Несохранённый рабочий черновик") {
  await page.getByRole("textbox", { name: "Комментарий к office.example.com", exact: true }).fill(comment);
  await expect(page.locator("#draft-status")).toContainText("Есть несохранённые изменения");
}

async function readRules(page) {
  return page.locator("#rules tr").evaluateAll((rows) => rows.map((row) => ({
    domain: row.querySelector(".site-name").textContent,
    action: row.querySelector("select").value,
    comment: row.querySelector("input").value,
  })));
}

async function openHistory(page) {
  await page.locator("#history-panel summary").click();
  await expect(page.locator("#history-panel")).toHaveAttribute("open", "");
  await expect(page.locator("#history-status")).not.toContainText("Откройте историю");
  await idle(page);
}

async function reloadDraft(page) {
  await page.locator("#reload").click();
  await expect(page.locator("#confirm-title")).toHaveText("Загрузить актуальные правила?");
  await page.locator("#accept-confirm").click();
  await idle(page);
  await expect(page.locator("#reload-notice")).toBeHidden();
}

async function blockedWrites(h, expectedDraft) {
  const count = writes(h).length;
  const stateReads = h.calls.filter(({ endpoint }) => endpoint === "/api/corp/state").length;
  await expect(h.page.locator("#reload-notice")).toBeVisible();
  await expect(h.page.locator("#save")).toBeDisabled();
  await expect(h.page.locator("#save-now")).toBeDisabled();
  for (const button of await h.page.locator("[data-restore]").all()) await expect(button).toBeDisabled();
  assert.deepEqual(await readRules(h.page), expectedDraft, "An uncertain publication must retain the draft");
  // Retry timers must not turn an uncertain response into a second publication.
  await h.page.clock.runFor(60_000);
  assert.equal(writes(h).length, count, "No automatic write retry");
  assert.equal(h.calls.filter(({ endpoint }) => endpoint === "/api/corp/state").length, stateReads, "Reconciliation must be explicit");
}

async function editorFlow(width) {
  const h = await harness("editor", width);
  const { page } = h;
  try {
    await shot(page, "editor", width);
    await page.locator("#site").fill("https://PORTAL.Example.com/documents?view=all");
    await page.locator("#normalize").click();
    await expect(page.locator("#normalized-site")).toHaveText("portal.example.com");
    await idle(page);
    assert.equal((await readRules(page)).length, 2, "Normalization alone must not add a rule");
    await page.locator("#new-action").selectOption("proxy");
    await page.locator("#new-comment").fill("Корпоративный портал");
    await shot(page, "normalized-preview", width);
    await page.locator("#add-site").click();
    await page.getByRole("combobox", { name: "Маршрут для office.example.com", exact: true }).selectOption("proxy");
    await draft(page, "Обновлённый комментарий");
    await page.getByRole("button", { name: "Удалить remove.example.com", exact: true }).click();
    await page.locator("#search").fill("корпоративный портал");
    await expect(page.locator("#rules tr")).toHaveCount(1);
    await page.locator("#search").fill("");
    await page.locator("#save").click();
    await idle(page);
    assert.deepEqual(writes(h)[0].body, {
      expected_revision: 7, apply: "next_connection", confirm_interrupt: false,
      rules: [
        { domain: "portal.example.com", action: "proxy", comment: "Корпоративный портал" },
        { domain: "office.example.com", action: "proxy", comment: "Обновлённый комментарий" },
      ],
    });
    await expect(page.locator("#status")).toHaveText("Правила сохранены. Приложения применят их при следующем подключении VPN.");
    await draft(page, "Применить при текущем подключении");
    await page.locator("#save-now").click();
    await expect(page.locator("#accept-confirm")).toBeDisabled();
    await expect(page.locator("#interrupt-warning")).toContainText("Остановленный VPN останется выключенным");
    await shot(page, "apply-now-confirmation", width);
    await page.locator("#cancel-confirm").click();
    assert.equal(writes(h).length, 1, "Cancelled confirmation must not publish");
    await page.locator("#save-now").click();
    await expect(page.locator("#confirm-interrupt")).not.toBeChecked();
    await page.locator("#confirm-interrupt").check();
    await page.locator("#accept-confirm").click();
    await idle(page);
    assert.equal(writes(h)[1].body.apply, "now");
    assert.equal(writes(h)[1].body.confirm_interrupt, true);
    await expect(page.locator("#status")).toHaveText("Правила сохранены. Подключённые приложения применят их после получения обновления; связь может ненадолго прерваться. При выключенном VPN — при следующем подключении.");
    await shot(page, "long-success-status", width);
    await openHistory(page);
    await expect(page.locator('[data-restore="9"]')).toBeDisabled();
    await shot(page, "history", width);
    await page.locator('[data-restore="6"]').click();
    await expect(page.locator("#confirm-timing")).toHaveValue("next_connection");
    await page.locator("#confirm-timing").selectOption("now");
    await expect(page.locator("#accept-confirm")).toBeDisabled();
    await page.locator("#confirm-interrupt").check();
    await page.locator("#confirm-timing").selectOption("next_connection");
    await expect(page.locator("#confirm-interrupt")).not.toBeChecked();
    await shot(page, "restore-confirmation", width);
    await page.locator("#accept-confirm").click();
    await idle(page);
    assert.deepEqual(writes(h)[2].body, { expected_revision: 9, revision: 6, apply: "next_connection", confirm_interrupt: false });
    await expect(page.locator("#draft-status")).toContainText("Версия 10.");
    assert.deepEqual(await readRules(page), historicalRules);
    await page.getByRole("button", { name: "Удалить archive.example.com", exact: true }).click();
    await page.locator("#save").click();
    await idle(page);
    assert.deepEqual(writes(h)[3].body.rules, [], "Deleting all rules must publish an empty complete list");
    await expect(page.locator("#empty-list")).toContainText("Список пуст");
    await shot(page, "empty-list", width);
  } finally { await h.close(); }
}

async function errorFlow(width, status) {
  const h = await harness("editor", width);
  const { page } = h;
  try {
    await page.clock.install();
    await openHistory(page);
    await draft(page);
    const retained = await readRules(page);
    if (status === 409) {
      h.state.revision = 8;
      h.state.rules = structuredClone(historicalRules);
      h.state.snapshots.set(8, structuredClone(historicalRules));
      h.state.timings.set(8, "next_connection");
    }
    h.fail("/api/corp/rules", status);
    await page.locator("#save").click();
    await idle(page);
    await expect(page.locator("#error")).toHaveText(longMessage);
    assert.deepEqual(await readRules(page), retained);
    await shot(page, `error-${status}`, width);
    if (status === 409) {
      await blockedWrites(h, retained);
      await reloadDraft(page);
      await expect(page.locator("#draft-status")).toContainText("Версия 8.");
      assert.deepEqual(await readRules(page), historicalRules);
    } else {
      await expect(page.locator("#session-link")).toBeVisible();
      for (const control of await page.locator(".editor-control").all()) await expect(control).toBeDisabled();
      await page.clock.runFor(60_000);
      assert.equal(writes(h).length, 1, "Lost access must not trigger write retries");
    }
  } finally { await h.close(); }
}

async function historyRetry(width) {
  const h = await harness("editor", width);
  try {
    h.fail("/api/corp/history", 503);
    await openHistory(h.page);
    await expect(h.page.locator("#history-status")).toContainText("История не загрузилась");
    await expect(h.page.locator("#refresh-history")).toBeEnabled();
    await shot(h.page, "history-error", width);
    await h.page.locator("#refresh-history").click();
    await idle(h.page);
    await expect(h.page.locator("#history li")).toHaveCount(2);
    await expect(h.page.locator("#error")).toBeHidden();
    assert.equal(h.calls.filter(({ endpoint }) => endpoint === "/api/corp/history").length, 2);
    assert.equal(writes(h).length, 0);
  } finally { await h.close(); }
}

async function timeoutFlow(width, operation, committed) {
  const h = await harness("editor", width);
  const { page } = h;
  try {
    await page.clock.install();
    await openHistory(page);
    await draft(page);
    const retained = await readRules(page);
    h.fail(`/api/corp/${operation}`, 408, committed);
    if (operation === "rules") await page.locator("#save").click();
    else {
      await page.locator('[data-restore="6"]').click();
      await page.locator("#accept-confirm").click();
    }
    await idle(page);
    await expect(page.locator("#error")).toHaveText(longMessage);
    await blockedWrites(h, retained);
    await shot(page, `${operation}-408-${committed ? "committed" : "uncommitted"}`, width);
    const expectedRevision = committed ? 8 : 7;
    const expectedRules = committed ? (operation === "rules" ? retained : historicalRules) : initialRules;
    assert.equal(h.state.revision, expectedRevision);
    await reloadDraft(page);
    await expect(page.locator("#draft-status")).toContainText(`Версия ${expectedRevision}.`);
    assert.deepEqual(await readRules(page), expectedRules, "Reload must reconcile committed and uncommitted timeouts");
    assert.equal(writes(h).length, 1, "Reload must not resubmit a publication");
    await expect(page.locator('[data-restore="6"]')).toBeEnabled();
    await page.getByRole("textbox", { name: `Комментарий к ${expectedRules[0].domain}`, exact: true }).fill("После загрузки актуального списка");
    await expect(page.locator("#save")).toBeEnabled();
    await page.locator("#save").click();
    await idle(page);
    assert.equal(writes(h).length, 2);
    assert.equal(writes(h)[1].body.expected_revision, expectedRevision);
    await expect(page.locator("#draft-status")).toContainText(`Версия ${expectedRevision + 1}.`);
  } finally { await h.close(); }
}

try {
  for (const width of [320, 420]) {
    for (const [name, title] of [["login", "Вход"], ["denied", "Подключите корпоративный VPN"], ["unavailable", "Страница пока недоступна"]]) {
      const h = await harness(name, width);
      try {
        await expect(h.page.getByRole("heading", { level: 1 })).toHaveText(title);
        if (name === "login") await expect(h.page.locator("form")).toHaveAttribute("action", `${origin}/login`);
        else await expect(h.page.getByRole("link")).toHaveAttribute("href", "/");
        await shot(h.page, name, width);
        if (name === "login") {
          await h.page.getByLabel("Пароль", { exact: true }).fill("synthetic-browser-password");
          await h.page.getByRole("button", { name: "Войти", exact: true }).click();
          await expect(h.page).toHaveURL(`${origin}/login`);
          assert.equal(h.calls.filter(({ endpoint }) => endpoint === "/login").length, 1);
          await idle(h.page);
          await expect(h.page.locator("#draft-status")).toContainText("Версия 7.");
          await shot(h.page, "login-submitted", width);
        }
      } finally { await h.close(); }
      completed.push(`${width}/${name}`);
    }
    for (const [name, run] of [
      ["editor", () => editorFlow(width)],
      ["conflict", () => errorFlow(width, 409)],
      ["access-loss", () => errorFlow(width, 401)],
      ["history-retry", () => historyRetry(width)],
      ...["rules", "restore"].flatMap((operation) => [false, true].map((committed) => [
        `${operation}-408-${committed ? "committed" : "uncommitted"}`,
        () => timeoutFlow(width, operation, committed),
      ])),
    ]) {
      await run();
      completed.push(`${width}/${name}`);
      console.log(`Passed ${width}/${name}`);
    }
  }
  completed.push(...await verifyOperator(browser, expect, shot));
  completed.push(...await verifyDiagnostics(browser, expect, shot));
} finally {
  await writeFile(path.join(screenshots, "completed-scenarios.json"), `${JSON.stringify(completed, null, 2)}\n`);
  await browser.close();
}
