import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

export async function verifyDiagnostics(browser, expect, shot) {
  assert.equal(process.env.CI, "true", "Diagnostics browser verification is CI-only");
  assert.ok(process.env.CORP_DIAGNOSTICS_UI_OUTPUT_DIR);
  const fixtures = path.resolve(process.env.CORP_DIAGNOSTICS_UI_OUTPUT_DIR);
  const source = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../daemon/assets/corp-portal");
  const metadata = JSON.parse(await readFile(path.join(fixtures, "diagnostics.json"), "utf8"));
  assert.equal(metadata.status, 200);
  assert.equal(metadata.headers["cache-control"], "no-store");
  assert.ok(metadata.headers["content-security-policy"]);
  assert.equal(metadata.headers["set-cookie"], undefined);
  const fixture = { ...metadata, body: await readFile(path.join(fixtures, "diagnostics.html"), "utf8") };
  const assets = {};
  for (const name of ["corp.css", "corp.js", "corp-phone.js", "corp-diagnostics.js"]) {
    let body = await readFile(path.join(source, name), "utf8");
    if (name === "corp.css") body = await readFile(path.join(source, "../css/theme.css"), "utf8") + body;
    assert.equal(await readFile(path.join(fixtures, "assets", name), "utf8"), body,
      `Router-exported ${name} must match candidate source`);
    assets[`/assets/${name}`] = { status: 200, contentType: name.endsWith("css") ? "text/css" : "text/javascript", body };
  }
  const origin = "https://admin.corp.ninitux.com";
  const csrf = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
  const first = "a".repeat(64);
  const second = "b".repeat(64);
  const third = "c".repeat(64);
  const hostile = '<img src="https://unexpected.invalid/secret" onerror="window.diagnosticsInjected=true"><script>window.diagnosticsInjected=true</script>';
  const summary = (id, state = "ready") => ({
    report_id: id, received_utc: "2026-11-16T12:00:00Z", bytes: 1234,
    device_label: id === first ? hostile : "Синтетическое устройство",
    analysis_state: state, verdict: "insufficient_data", summary_ru: "Недостаточно свежих данных о подключении",
    model: state === "received" ? null : "synthetic-advisory-model",
    updated_utc: state === "received" ? null : "2026-11-16T12:01:00Z",
  });
  const analysis = {
    schema: "corp-diagnosis/1",
    assessments: [{scope: "client_runtime", verdict: "insufficient_data", confidence: "low", time_scope: "unknown", explanation_ru: "Старая запись не подтверждает текущее состояние", evidence: [{kind: "packet", field: "received_utc"}]}],
    confirmed: [{statement: "В архиве есть историческая запись о завершении", time_scope: "historical", evidence: [{kind: "log", file: "app-01.txt", line: 12}]}],
    probable: [{statement: "Данных текущей попытки может не хватать", time_scope: "unknown", evidence: [{kind: "operator_fact", field: "trusted_operator_facts.feed_version"}]}],
    unknown: [{statement: "Текущее состояние VPN неизвестно", time_scope: "unknown", evidence: [{kind: "packet", field: "received_utc"}]}],
    chronology: [{statement: "Получен новый отчёт со старой записью", evidence: [{kind: "packet", field: "received_utc"}]}],
    owner_explanation: `Текущую исправность подтвердить нельзя. ${hostile}`,
    next_steps_ru: ["Отправьте свежую диагностику через приложение"],
    public_analysis: {version: 1, state: "ready", message_ru: "Недостаточно свежих данных"},
  };
  const provenance = {
    requested_model: "synthetic-advisory-model", returned_model: "synthetic-advisory-model-returned",
    prompt_sha256: "d".repeat(64), input_sha256: "e".repeat(64), run_id: "synthetic-run-id",
    started_utc: "2026-11-16T12:00:30Z", completed_utc: "2026-11-16T12:01:00Z",
    prompt_version: "synthetic-v1", status: "ready",
  };
  const completed = [];

  async function harness(width, mode = "ready") {
    const context = await browser.newContext({
      offline: true, viewport: {width, height: 900}, locale: "ru-RU", timezoneId: "UTC",
      reducedMotion: "reduce", serviceWorkers: "block", deviceScaleFactor: 1,
    });
    const errors = [];
    const calls = [];
    const state = {mode, firstState: "ready", retryStatus: 202, holdRetry: false,
      deleted: new Set(), deleteStatus: 200, holdDetail: false};
    let releaseList;
    let releaseRetry;
    let releaseDetail;
    const listGate = new Promise((resolve) => { releaseList = resolve; });
    const retryGate = new Promise((resolve) => { releaseRetry = resolve; });
    const detailGate = new Promise((resolve) => { releaseDetail = resolve; });
    await context.routeWebSocket("**/*", (socket) => {
      errors.push(`Unexpected diagnostics WebSocket: ${socket.url()}`);
      socket.close({code: 1008, reason: "Synthetic verification blocks sockets"});
    });
    await context.route("**/*", async (route) => {
      try {
        const request = route.request();
        const url = new URL(request.url());
        assert.equal(url.origin, origin, "Unexpected diagnostics request origin");
        if (url.pathname === "/diagnostics" && request.method() === "GET") {
          assert.equal(url.search, "");
          await route.fulfill(fixture);
          return;
        }
        if (assets[url.pathname] && request.method() === "GET") {
          assert.equal(url.search, "");
          await route.fulfill(assets[url.pathname]);
          return;
        }
        assert.ok(url.pathname.startsWith("/api/corp/reports"), `Unexpected diagnostics path: ${url.pathname}`);
        const post = request.method() === "POST";
        const deleting = request.method() === "DELETE";
        assert.ok(post || deleting || request.method() === "GET");
        calls.push({path: url.pathname, query: url.search, method: request.method()});
        if (deleting) {
          const id = url.pathname.slice("/api/corp/reports/".length);
          assert.ok([first, second, third].includes(id));
          assert.equal(url.search, "");
          assert.equal(request.headers().origin, origin, "Delete must retain same Origin");
          assert.equal(request.headers()["x-corp-csrf"], csrf, "Delete must use session CSRF");
          assert.match(request.headers()["content-type"], /^application\/json/);
          assert.deepEqual(request.postDataJSON(), {}, "Delete accepts no destination or credential input");
          if (state.deleteStatus === 200) state.deleted.add(id);
          await route.fulfill({status: state.deleteStatus, json: state.deleteStatus === 200
            ? {schema: 1, state: "deleted", freed_bytes: 1234}
            : {message: "UNTRUSTED_DELETE_ERROR_MUST_NOT_BE_DISPLAYED"}});
          return;
        }
        if (post) {
          assert.equal(url.pathname, `/api/corp/reports/${first}/retry`);
          assert.equal(url.search, "");
          assert.equal(request.headers().origin, origin);
          assert.equal(request.headers()["x-corp-csrf"], csrf, "Retry must use real exported session CSRF");
          assert.match(request.headers()["content-type"], /^application\/json/);
          assert.deepEqual(request.postDataJSON(), {}, "Retry must not contain destination or credential input");
          if (state.holdRetry) await retryGate;
          if (state.retryStatus === 202) state.firstState = "pending";
          await route.fulfill({status: state.retryStatus, json: state.retryStatus === 202 ? {schema: 1, state: "pending"} : {message: "UNTRUSTED_UPSTREAM_ERROR_MUST_NOT_BE_DISPLAYED"}});
          return;
        }
        if (url.pathname === "/api/corp/reports") {
          assert.equal(url.searchParams.get("limit"), "50");
          assert.deepEqual([...url.searchParams.keys()], url.searchParams.has("cursor") ? ["limit", "cursor"] : ["limit"]);
          if (state.mode === "loading") await listGate;
          if (state.mode === "error") {
            await route.fulfill({status: 503, json: {message: hostile}});
          } else if (state.mode === "empty") {
            await route.fulfill({status: 200, json: {schema: 1, reports: [], next_cursor: null}});
          } else if (url.searchParams.has("cursor")) {
            assert.equal(url.searchParams.get("cursor"), second);
            await route.fulfill({status: 200, json: {schema: 1, reports: [summary(third, "running")].filter((report) => !state.deleted.has(report.report_id)), next_cursor: null}});
          } else {
            await route.fulfill({status: 200, json: {schema: 1, reports: [summary(first, state.firstState), summary(second, "received")].filter((report) => !state.deleted.has(report.report_id)), next_cursor: second}});
          }
        } else {
          assert.equal(url.search, "");
          const id = url.pathname.slice("/api/corp/reports/".length);
          assert.ok([first, second, third].includes(id));
          const detail = {
            schema: 1, report: {
              ...summary(id, id === first ? state.firstState : id === third ? "running" : "received"),
              ...(state.mode === "solution" && id === first ? {verdict: "problem_found", summary_ru: "Выбран другой маршрут"} : {}),
            },
            analysis: id === first ? (state.mode === "solution" ? {
              ...analysis,
              owner_explanation: "Для этой попытки выбран другой маршрут. Подтверждённое решение — выбрать нужный маршрут в приложении.",
              next_steps_ru: ["Выберите указанный администратором маршрут в приложении.", "Проверьте открытие нужного сайта."],
            } : analysis) : null, provenance: id === first ? provenance : null,
          };
          if (state.holdDetail && id === first) await detailGate;
          await route.fulfill({status: 200, json: detail});
        }
      } catch (error) {
        errors.push(error.stack);
        await route.abort("blockedbyclient");
      }
    });
    const page = await context.newPage();
    await page.clock.install();
    page.on("pageerror", (error) => errors.push(error.message));
    page.on("console", (message) => {
      if (/content security policy|refused to (?:load|execute|connect)/i.test(message.text())) errors.push(message.text());
    });
    await page.goto(`${origin}/diagnostics`);
    await page.evaluate(() => document.fonts.ready);
    return {
      page, calls, state, releaseList, releaseRetry, releaseDetail,
      posts: () => calls.filter((call) => call.method === "POST"),
      deletes: () => calls.filter((call) => call.method === "DELETE"),
      async close() {
        releaseList(); releaseRetry(); releaseDetail();
        await context.close();
        assert.deepEqual(errors, [], "Diagnostics browser/routing errors");
      },
    };
  }

  for (const width of [320, 420, 1280]) {
    const h = await harness(width, "loading");
    const {page} = h;
    try {
      await expect(page.locator("#diagnostics-status")).toHaveText("Загружаем отчёты…");
      await expect(page.locator("#diagnostics-refresh")).toBeDisabled();
      await shot(page, "diagnostics-loading", width);
      h.state.mode = "ready";
      h.releaseList();
      await expect(page.locator(".report-select")).toHaveCount(2);
      await expect(page.locator(".report-select").first()).toContainText(hostile);
      await expect(page.locator(".report-select img, .report-select script")).toHaveCount(0);
      assert.equal(h.posts().length, 0, "Reading inbox must not retry automatically");
      for (const row of await page.locator(".report-select").all()) {
        await expect(row).not.toContainText(summary(first).summary_ru);
      }
      await page.locator("#diagnostics-search").fill("Синтетическое устройство");
      await expect(page.locator(".report-select")).toHaveCount(1);
      await expect(page.locator(".report-select")).not.toContainText(hostile);
      await shot(page, "diagnostics-search", width);
      await page.locator("#diagnostics-search").fill("");
      await expect(page.locator(".report-select")).toHaveCount(2);
      await shot(page, "diagnostics-list-hostile-text", width);
      const rules = page.getByRole("link", {name: "Правила", exact: true});
      await expect(rules).toHaveAttribute("href", "/");
      await rules.focus();
      await page.keyboard.press("Tab");
      await expect(page.getByRole("link", {name: "Диагностика", exact: true})).toBeFocused();
      await expect(page.getByRole("link", {name: "Диагностика", exact: true})).toHaveAttribute("aria-current", "page");
      await page.locator("#diagnostics-search").focus();
      await expect(page.locator("#diagnostics-search")).toBeFocused();
      await page.locator(".report-select").first().focus();
      await expect(page.locator(".report-select").first()).toBeFocused();
      await page.keyboard.press("Enter");
      await expect(page.locator("#diagnostics-detail")).toBeFocused();
      const body = page.locator("#diagnostics-detail-body");
      await expect(page.locator(".report-select").first()).toHaveAttribute("aria-pressed", "true");
      await expect(page.locator(".report-select").nth(1)).toHaveAttribute("aria-pressed", "false");
      await expect(body.locator(".diagnosis-answer")).toBeVisible();
      await expect(body.locator(".diagnosis-action")).toBeVisible();
      await expect(body.locator(".diagnosis-action")).toContainText("Отправьте свежую диагностику");
      for (const name of ["diagnosis-reasons", "diagnosis-technical"]) {
        await expect(body.locator(`.${name}`)).not.toHaveAttribute("open");
      }
      await expect(body.locator(".provenance")).toBeHidden();
      const order = await body.evaluate((element) => [
        ...element.querySelectorAll(".diagnosis-answer, .diagnosis-action, .diagnosis-reasons, .diagnosis-technical"),
      ].map((item) => item.className));
      assert.deepEqual(order, ["diagnosis-answer", "diagnosis-action", "diagnosis-reasons", "diagnosis-technical"]);
      await shot(page, "diagnostics-short-answer-action", width);
      await body.locator(".diagnosis-reasons summary").focus();
      await page.keyboard.press("Enter");
      await expect(body.locator(".diagnosis-reasons")).toHaveAttribute("open", "");
      await body.locator(".diagnosis-technical summary").focus();
      await page.keyboard.press("Space");
      await expect(body.locator(".diagnosis-technical")).toHaveAttribute("open", "");
      await expect(body).toContainText("Недостаточно данных");
      await expect(body).toContainText("Исторические данные");
      await expect(body).toContainText("app-01.txt, строка 12");
      await expect(body).toContainText("Проверенный факт: trusted_operator_facts.feed_version");
      await expect(body).toContainText("Поле отчёта: received_utc");
      for (const heading of ["Подтверждённые наблюдения", "Вероятные объяснения", "Что остаётся неизвестным", "Хронология", "Сведения об анализе"]) await expect(body).toContainText(heading);
      await expect(body).toContainText(provenance.returned_model);
      await expect(body).toContainText(provenance.prompt_sha256);
      await expect(body).toContainText(hostile);
      await expect(body.locator("img, script, a")).toHaveCount(0);
      assert.equal(await page.evaluate(() => window.diagnosticsInjected), undefined);
      await shot(page, "diagnostics-detail-evidence-provenance", width);
      await page.locator("#diagnostics-more").click();
      await expect(page.locator(".report-select")).toHaveCount(3);
      await expect(page.locator("#diagnostics-more")).toBeHidden();
      await page.locator("#diagnostics-search").fill(third);
      await expect(page.locator(".report-select")).toHaveCount(1);
      await page.locator("#diagnostics-search").fill("");
      await expect(page.locator(".report-select")).toHaveCount(3);
      await page.locator(".report-select").nth(2).click();
      await expect(body).toContainText("Анализ выполняется");
      await expect(page.getByRole("button", {name: "Повторить анализ", exact: true})).toHaveCount(0);
      await expect(body).toContainText("Проверенного заключения пока нет");
      await shot(page, "diagnostics-running-no-retry", width);
      await page.locator(".report-select").nth(1).click();
      await expect(body.locator(".diagnosis-technical")).not.toHaveAttribute("open");
      await body.locator(".diagnosis-technical summary").click();
      await expect(body).toContainText("Сведения о выполнении пока недоступны");
      await expect(body).toContainText("Проверенного заключения пока нет");
      await shot(page, "diagnostics-received-no-analysis", width);
      await page.locator(".report-select").first().click();
      const retry = page.getByRole("button", {name: "Повторить анализ", exact: true});
      await expect(retry).toBeEnabled();
      h.state.holdRetry = true;
      await retry.click();
      await expect(retry).toBeDisabled();
      await expect.poll(() => h.posts().length).toBe(1);
      await page.clock.runFor(60_000);
      assert.equal(h.posts().length, 1, "Pending retry must not automatically resubmit");
      h.releaseRetry();
      await expect(body).toContainText("Ожидает анализа");
      await expect(body).toContainText("Ниже — предыдущий результат");
      await expect(body.locator(".diagnosis-action")).toContainText("Отправьте свежую диагностику");
      await body.locator(".diagnosis-reasons summary").click();
      await expect(body).toContainText("Старая запись не подтверждает текущее состояние");
      await expect(page.getByRole("button", {name: "Повторить анализ", exact: true})).toHaveCount(0);
      await shot(page, "diagnostics-retry-pending-retains-result", width);
      h.state.firstState = "unavailable";
      await page.locator("#diagnostics-refresh").click();
      await expect(body).toContainText("Последняя попытка не дала нового заключения");
      await expect(body).not.toContainText("Новый анализ ещё не завершён");
      await expect(body.locator(".diagnosis-action")).toContainText("Отправьте свежую диагностику");
    } finally { await h.close(); }
    completed.push(`${width}/diagnostics-list-detail-keyboard-retry`);

    const solution = await harness(width, "solution");
    try {
      await expect(solution.page.locator(".report-select")).toHaveCount(2);
      await solution.page.locator(".report-select").first().click();
      const answer = solution.page.locator(".diagnosis-answer");
      const action = solution.page.locator(".diagnosis-action");
      await expect(answer).toContainText("Подтверждённое решение");
      await expect(action.locator("li")).toHaveText([
        "Выберите указанный администратором маршрут в приложении.", "Проверьте открытие нужного сайта.",
      ]);
      assert.equal(solution.posts().length, 0, "Advice must not execute any repair or retry");
      await expect(solution.page.locator(".diagnosis-technical")).not.toHaveAttribute("open");
      await shot(solution.page, "diagnostics-available-solution", width);
    } finally { await solution.close(); }
    completed.push(`${width}/diagnostics-supported-solution-advice-only`);

    for (const mode of ["empty", "error"]) {
      const h = await harness(width, mode);
      try {
        if (mode === "empty") {
          await expect(h.page.locator("#diagnostics-status")).toContainText("Отчётов пока нет");
          await expect(h.page.locator(".report-select")).toHaveCount(0);
          await expect(h.page.locator("#diagnostics-more")).toBeHidden();
        } else {
          await expect(h.page.locator("#diagnostics-error")).toContainText("Диагностика сейчас недоступна");
          await expect(h.page.locator("#diagnostics-error")).not.toContainText(hostile);
        }
        await shot(h.page, `diagnostics-${mode}`, width);
        h.state.mode = "ready";
        await h.page.locator("#diagnostics-refresh").click();
        await expect(h.page.locator(".report-select")).toHaveCount(2);
        await expect(h.page.locator("#diagnostics-error")).toBeHidden();
        assert.equal(h.posts().length, 0);
      } finally { await h.close(); }
      completed.push(`${width}/diagnostics-${mode}-recovery`);
    }

    for (const status of [409, 401, 403]) {
      const h = await harness(width);
      try {
        await expect(h.page.locator(".report-select")).toHaveCount(2);
        await h.page.locator(".report-select").first().click();
        const retry = h.page.getByRole("button", {name: "Повторить анализ", exact: true});
        h.state.retryStatus = status;
        await retry.click();
        await expect(h.page.locator("#diagnostics-error")).toContainText({409: "Анализ уже выполняется", 401: "Срок входа истёк", 403: "Подключите корпоративный VPN"}[status]);
        await expect(h.page.locator("#diagnostics-error")).not.toContainText("UNTRUSTED_UPSTREAM_ERROR");
        if (status === 401) {
          await expect(retry).toBeDisabled();
          await expect(h.page.locator("#diagnostics-login")).toBeVisible();
          const count = h.calls.length;
          await h.page.locator("#diagnostics-refresh").click();
          assert.equal(h.calls.length, count, "Expired session must not initiate further API access");
        } else await expect(retry).toBeEnabled();
        await h.page.clock.runFor(60_000);
        assert.equal(h.posts().length, 1, "Failed or rejected retry must never resubmit automatically");
        await shot(h.page, `diagnostics-retry-${status}`, width);
      } finally { await h.close(); }
      completed.push(`${width}/diagnostics-retry-${status}`);
    }

    const deletion = await harness(width);
    try {
      const {page} = deletion;
      await expect(page.locator(".report-select")).toHaveCount(2);
      await page.locator(".report-select").first().click();
      const body = page.locator("#diagnostics-detail-body");
      await expect(body.locator(".diagnosis-answer")).toBeVisible();
      const remove = page.getByRole("button", {name: "Удалить отчёт…", exact: true});
      await remove.click();
      const dialog = page.locator("#diagnostics-delete-dialog");
      await expect(dialog).toBeVisible();
      await expect(dialog).toContainText(/отч[её]т/i);
      await expect(dialog).toContainText(/архив/i);
      await shot(page, "diagnostics-delete-confirmation", width);
      await page.locator("#diagnostics-delete-cancel").click();
      await expect(dialog).toBeHidden();
      assert.equal(deletion.deletes().length, 0, "Cancel must not delete a report");
      assert.equal(deletion.posts().length, 0, "Cancel must not issue other writes");
      await expect(page.locator(".report-select")).toHaveCount(2);
      await expect(body.locator(".diagnosis-answer")).toBeVisible();
      const listReads = deletion.calls.filter((call) => call.path === "/api/corp/reports").length;
      await remove.click();
      await page.locator("#diagnostics-delete-confirm").click();
      await expect(dialog).toBeHidden();
      await expect(page.locator(".report-select")).toHaveCount(1);
      await expect(page.locator(".report-select")).not.toContainText(hostile);
      await expect(body.locator(".diagnosis-answer")).toHaveCount(0);
      await expect(page.getByRole("button", {name: "Удалить отчёт…", exact: true})).toHaveCount(0);
      await expect(page.locator("#diagnostics-status")).toContainText(/удал[её]н/i);
      assert.equal(deletion.deletes().length, 1);
      assert.ok(deletion.calls.filter((call) => call.path === "/api/corp/reports").length > listReads, "Success must reload the report list");
      await shot(page, "diagnostics-delete-success", width);
    } finally { await deletion.close(); }
    completed.push(`${width}/diagnostics-delete-confirm-cancel-success`);

    for (const status of [503, 401]) {
      const failure = await harness(width);
      try {
        const {page} = failure;
        await expect(page.locator(".report-select")).toHaveCount(2);
        await page.locator(".report-select").first().click();
        await expect(page.locator(".diagnosis-answer")).toBeVisible();
        failure.state.deleteStatus = status;
        await page.getByRole("button", {name: "Удалить отчёт…", exact: true}).click();
        await page.locator("#diagnostics-delete-confirm").click();
        const error = page.locator("#diagnostics-error");
        await expect(error).toBeVisible();
        await expect(error).not.toContainText("UNTRUSTED_DELETE_ERROR");
        if (status === 503) {
          await expect(error).toContainText(/повтор|попроб|обнов/i);
          await expect(page.locator(".report-select")).toHaveCount(2);
          await expect(page.locator(".report-select").first()).toHaveAttribute("aria-pressed", "true");
          await expect(page.locator(".diagnosis-answer")).toBeVisible();
        } else {
          await expect(error).toContainText("Срок входа истёк");
          await expect(page.locator("#diagnostics-login")).toBeVisible();
          const count = failure.calls.length;
          await page.locator("#diagnostics-refresh").click();
          assert.equal(failure.calls.length, count, "Expired session must block further API calls");
          const remove = page.getByRole("button", {name: "Удалить отчёт…", exact: true});
          if (await remove.count()) await expect(remove).toBeDisabled();
        }
        await page.clock.runFor(60_000);
        assert.equal(failure.deletes().length, 1, "A failed delete must not resubmit automatically");
        await shot(page, `diagnostics-delete-${status}`, width);
      } finally { await failure.close(); }
      completed.push(`${width}/diagnostics-delete-${status}`);
    }

    const late = await harness(width);
    try {
      const {page} = late;
      await expect(page.locator(".report-select")).toHaveCount(2);
      late.state.holdDetail = true;
      await page.locator(".report-select").first().click();
      await expect.poll(() => late.calls.filter((call) => call.path === `/api/corp/reports/${first}`).length).toBe(1);
      await page.locator(".report-select").nth(1).click();
      await expect(page.locator("#diagnostics-detail-body")).toContainText("Проверенного заключения пока нет");
      await expect(page.locator(".report-select").nth(1)).toHaveAttribute("aria-pressed", "true");
      await page.getByRole("button", {name: "Удалить отчёт…", exact: true}).click();
      await page.locator("#diagnostics-delete-confirm").click();
      await expect(page.locator(".report-select")).toHaveCount(1);
      assert.equal(late.deletes().length, 1);
      assert.equal(late.deletes()[0].path, `/api/corp/reports/${second}`);
      const staleResponse = page.waitForResponse((response) =>
        new URL(response.url()).pathname === `/api/corp/reports/${first}`
        && response.request().method() === "GET");
      late.releaseDetail();
      await (await staleResponse).finished();
      await page.clock.runFor(1000);
      await expect(page.locator(".diagnosis-answer")).toHaveCount(0);
      await expect(page.getByRole("button", {name: "Удалить отчёт…", exact: true})).toHaveCount(0);
      await expect(page.locator('.report-select[aria-pressed="true"]')).toHaveCount(0);
      await expect(page.locator(".report-select")).toHaveCount(1);
      await expect(page.locator(".report-select")).toContainText(hostile);
      assert.ok(late.state.deleted.has(second), "The deleted report must remain absent after stale detail arrives");
      await shot(page, "diagnostics-delete-discards-late-detail", width);
    } finally { await late.close(); }
    completed.push(`${width}/diagnostics-delete-discards-late-detail`);

    console.log(`Passed ${width}/diagnostics browser scenarios`);
  }
  return completed;
}
