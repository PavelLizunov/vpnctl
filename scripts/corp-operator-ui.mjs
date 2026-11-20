import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

export async function verifyOperator(browser, expect, shot) {
  assert.equal(process.env.CI, "true", "Operator browser verification is CI-only");
  assert.ok(process.env.CORP_OPERATOR_UI_OUTPUT_DIR);
  const fixtures = path.resolve(process.env.CORP_OPERATOR_UI_OUTPUT_DIR);
  const assets = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../daemon/assets");
  const css = await readFile(path.join(assets, "corp-operator.css"), "utf8");
  assert.equal(await readFile(path.join(fixtures, "assets/operator.css"), "utf8"), css);
  const styles = new Map([
    ["/admin/corp/assets/operator.css", css],
    ["/admin/assets/css/theme.css", await readFile(path.join(assets, "css/theme.css"), "utf8")],
    ["/admin/assets/css/components.css", await readFile(path.join(assets, "css/components.css"), "utf8")],
  ]);
  const pages = {};
  for (const name of ["setup", "status", "password-result", "conflict", "egress-ready", "egress-running", "egress-failed", "egress-enabled", "company-list", "company-list-ink", "company-selected"]) {
    const metadata = JSON.parse(await readFile(path.join(fixtures, `${name}.json`), "utf8"));
    assert.equal(metadata.status, name === "conflict" ? 409 : 200);
    assert.equal(metadata.headers["cache-control"], "no-store");
    assert.ok(metadata.headers["content-security-policy"]);
    assert.equal(metadata.headers["set-cookie"], undefined);
    pages[name] = { ...metadata, body: await readFile(path.join(fixtures, `${name}.html`), "utf8") };
  }
  const resultLink = pages["password-result"].body.match(/href="(\/admin\/corp\/company\/([A-Za-z0-9_.-]+))">Продолжить<\/a>/);
  assert.ok(resultLink, "Password result fixture must identify its generated company");
  const resultCompany = resultLink[2];
  const origin = "https://operator.example.test";
  const completed = [];
  for (const width of [320, 390, 800, 1280]) {
    for (const name of Object.keys(pages)) {
      const companyList = name.startsWith("company-list");
      const pathname = companyList ? "/admin/corp/companies" : "/admin/corp";
      const context = await browser.newContext({
        offline: true,
        viewport: { width, height: 900 }, locale: "ru-RU", timezoneId: "UTC",
        colorScheme: "light", reducedMotion: "reduce", serviceWorkers: "block",
      });
      const errors = [];
      const posts = [];
      await context.routeWebSocket("**/*", (socket) => {
        errors.push("Unexpected operator WebSocket");
        socket.close({ code: 1008, reason: "Synthetic verification blocks network" });
      });
      await context.route("**/*", async (route) => {
        try {
          const request = route.request();
          const url = new URL(request.url());
          assert.equal(url.origin, origin);
          assert.equal(url.search, "");
          if (request.method() === "GET" && (url.pathname === pathname || /^\/admin\/corp\/company\/[A-Za-z0-9_.-]+$/.test(url.pathname))) {
            await route.fulfill(pages[name]);
          } else if (request.method() === "GET" && styles.has(url.pathname)) {
            await route.fulfill({ status: 200, contentType: "text/css", body: styles.get(url.pathname) });
          } else if (request.method() === "POST") {
            const action = { setup: "setup", status: "password/rotate", "egress-ready": "enabled", "egress-failed": "probe" }[name];
            assert.ok(action, `Unexpected submission from ${name}`);
            assert.equal(url.pathname, `/admin/corp/${action}`);
            assert.equal(request.headers().origin, origin);
            const form = new URLSearchParams(request.postData());
            assert.match(form.get("csrf"), /^v1\.\d+\.[A-Za-z0-9_-]{43}\.[A-Za-z0-9_-]{43}$/);
            if (action !== "probe") assert.equal(form.get(name === "setup" ? "confirm_binding" : "confirm"), "true");
            if (name === "setup") assert.equal(form.get("user_id"), "synthetic-user");
            else {
              assert.match(form.get("expected_config_version"), /^[1-9]\d*$/);
              assert.match(form.get("company_id") ?? "", /^[A-Za-z0-9_.-]{1,64}$/);
              const expected = pages[name].body.match(/name="company_id" value="([A-Za-z0-9_.-]+)"/)?.[1];
              assert.ok(expected, `${name}: fixture must identify the selected company`);
              assert.equal(form.get("company_id"), expected);
            }
            if (action === "enabled") assert.equal(form.get("enabled"), "true");
            if (action === "probe") assert.match(form.get("server_id"), /^[A-Za-z0-9_.-]{1,64}$/);
            posts.push(url.pathname);
            await route.fulfill(pages[action === "enabled" ? "egress-enabled" : action === "probe" ? "egress-running" : "password-result"]);
          } else {
            throw new Error(`Unexpected operator request: ${request.method()} ${url.pathname}`);
          }
        } catch (error) {
          errors.push(error.stack);
          await route.abort("blockedbyclient");
        }
      });
      const page = await context.newPage();
      page.on("pageerror", (error) => errors.push(error.message));
      page.on("console", (message) => {
        if (/content security policy|refused to (?:load|execute|connect)/i.test(message.text())) errors.push(message.text());
      });
      try {
        const response = await page.goto(`${origin}${pathname}`);
        assert.equal(response.status(), pages[name].status);
        await page.evaluate(() => document.fonts.ready);
        await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
        await shot(page, `operator-${name}`, width);
        if (companyList) {
          const dark = name === "company-list-ink";
          await expect(page.locator("body")).toHaveClass(dark ? /\bed-ink ed-acc-forest\b/ : /^ed corp-companies$/);
          await expect(page.locator("body")).toHaveCSS("color-scheme", dark ? "dark" : "light");
          await expect(page.getByRole("link", {name: "Панель оператора"})).toHaveAttribute("href", "/admin/");
          await expect(page.locator("script")).toHaveCount(0);
          const palette = await page.locator("body").evaluate((body) => {
            const style = getComputedStyle(body);
            return { paper: style.getPropertyValue("--paper").trim(), background: style.backgroundColor };
          });
          assert.ok(palette.paper);
          assert.equal(palette.background, palette.paper);
          assert.ok(await page.locator("body").evaluate((body) => body.getBoundingClientRect().height >= innerHeight), "Company list must fill the viewport");
          await expect(page.getByRole("table", {name: "Корпоративные клиенты"})).toBeVisible();
          await expect(page.getByRole("link", {name: "Настроить компанию"})).toHaveAttribute("href", resultLink[1]);
          await expect(page.locator("tbody")).toContainText("synthetic-user");
        }
        if (name === "company-selected") {
          await expect(page.getByRole("heading", {level: 1})).toContainText("synthetic-user");
          for (const field of await page.locator('input[name="company_id"]').all()) await expect(field).toHaveValue(resultCompany);
        }
        if (name === "status") {
          for (const action of ["enabled", "password/rotate", "sessions/revoke", "readers/add", "readers/remove", "signers/add", "signers/activate", "signers/remove", "export", "probe"]) {
            const forms = page.locator(`form[action="/admin/corp/${action}"]`);
            assert.ok(await forms.count() > 0, `Missing operator control: ${action}`);
            for (const form of await forms.all()) {
              await expect(form).toHaveAttribute("method", "post");
              await expect(form.locator('input[name="csrf"]')).toHaveAttribute("type", "hidden");
              await expect(form.locator('input[name="expected_config_version"]')).toHaveAttribute("type", "hidden");
              const company = form.locator('input[name="company_id"]');
              await expect(company).toHaveAttribute("type", "hidden");
              await expect(company).toHaveValue(resultCompany);
              await expect(form.getByRole("button")).toBeVisible();
            }
          }
          await expect(page.getByRole("button", { name: "Включить доступ", exact: true })).toBeDisabled();
          await expect(page.locator("#corp-generated-password")).toHaveCount(0);
        }
        if (name === "setup" || name === "status") {
          const action = name === "setup" ? "setup" : "password/rotate";
          const form = page.locator(`form[action="/admin/corp/${action}"]`);
          await form.getByRole("button").click();
          assert.equal(posts.length, 0, "Confirmation must prevent unconfirmed submission");
          await form.getByRole("checkbox").check();
          await form.getByRole("button").click();
          await expect(page.locator("#corp-generated-password")).toBeVisible();
          assert.deepEqual(posts, [`/admin/corp/${action}`]);
          await shot(page, `operator-${name}-confirmed`, width);
        }
        if (name === "password-result") {
          await expect(page.locator("#corp-generated-password")).toHaveText(/^[A-Za-z0-9_-]{43}$/);
          await expect(page.getByRole("link", { name: "Продолжить", exact: true })).toHaveAttribute("href", resultLink[1]);
        }
        if (name === "conflict") {
          await expect(page.getByRole("link", { name: "Загрузить текущее состояние", exact: true })).toHaveAttribute("href", /^\/admin\/corp(?:\/company\/[A-Za-z0-9_.-]+)?$/);
          assert.equal(await page.locator("form").count(), 0, "Conflict must require a state reload");
        }
        if (name.startsWith("egress-")) {
          await expect(page.getByRole("link", { name: "Обновить состояние проверки", exact: true })).toHaveAttribute("href", /^\/admin\/corp(?:\/company\/[A-Za-z0-9_.-]+)?$/);
          if (name === "egress-ready") {
            const form = page.locator('form[action="/admin/corp/enabled"]').filter({ has: page.locator('input[name="enabled"][value="true"]') });
            await expect(form.getByRole("button")).toBeEnabled();
            await form.getByRole("button").click();
            assert.equal(posts.length, 0, "Enabling access requires confirmation");
            await form.getByRole("checkbox").check();
            await form.getByRole("button").click();
            await expect(page.locator("dd").filter({ hasText: /^Включён$/ })).toBeVisible();
            assert.deepEqual(posts, ["/admin/corp/enabled"]);
            await shot(page, "operator-egress-enable-confirmed", width);
          } else if (name === "egress-failed") {
            await expect(page.getByText("Проверка не удалась.", { exact: false })).toBeVisible();
            await expect(page.getByRole("button", { name: "Включить доступ", exact: true })).toBeEnabled();
            await page.getByRole("button", { name: "Проверить выход", exact: true }).click();
            await expect(page.getByText("Проверка выполняется.", { exact: false })).toBeVisible();
            assert.deepEqual(posts, ["/admin/corp/probe"]);
            await shot(page, "operator-egress-retry-submitted", width);
          } else if (name === "egress-running") {
            await expect(page.getByText("Проверка выполняется.", { exact: false })).toBeVisible();
            await page.getByRole("link", { name: "Обновить состояние проверки", exact: true }).click();
            assert.deepEqual(posts, [], "Refreshing status must not resubmit the probe");
          } else {
            await expect(page.locator("dd").filter({ hasText: /^Включён$/ })).toBeVisible();
          }
        }
        completed.push(`${width}/operator-${name}`);
      } finally {
        await context.close();
        assert.deepEqual(errors, [], "Operator browser/routing errors");
      }
    }
  }
  return completed;
}
