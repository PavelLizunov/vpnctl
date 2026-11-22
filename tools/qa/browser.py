"""Operator journeys against a newly created QA stand. All inputs are synthetic."""
import csv
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

from playwright.sync_api import Error as BrowserError, expect, sync_playwright

from stand import stand

SUITES = ("navigation", "users", "servers", "settings")


def run_suite(suite):
    if suite not in (*SUITES, "all"):
        raise ValueError("Unknown QA suite")
    with stand() as fixture:
        cache = Path(os.environ.get("PLAYWRIGHT_BROWSERS_PATH", Path.home() / ".cache/ms-playwright")).resolve()
        mounts = ["--ro-bind", "/usr", "/usr", "--dev", "/dev", "--proc", "/proc",
                  "--tmpfs", "/tmp", "--dir", "/tmp/profile", "--dir", "/run",
                  "--ro-bind", str(cache), "/browsers", "--ro-bind", str(Path(__file__).parent), "/qa"]
        for path in map(Path, ("/bin", "/sbin", "/lib", "/lib64", "/etc/fonts", "/etc/ld.so.cache")):
            if path.is_symlink():
                mounts.extend(["--symlink", os.readlink(path), str(path)])
            elif path.exists():
                mounts.extend(["--ro-bind", str(path), str(path)])
        # Recreate the venv prefix. Its interpreter may originally traverse a user-home symlink.
        base_prefix = Path(sys.base_prefix).resolve()
        if not base_prefix.is_relative_to("/usr"):
            mounts.extend(["--ro-bind", str(base_prefix), str(base_prefix)])
        interpreter = str(Path(sys.executable).resolve())
        if Path(sys.prefix, "pyvenv.cfg").is_file():
            mounts.extend(["--dir", "/venv/bin", "--symlink", interpreter, "/venv/bin/python",
                           "--ro-bind", sys.prefix + "/lib", "/venv/lib",
                           "--ro-bind", sys.prefix + "/pyvenv.cfg", "/venv/pyvenv.cfg"])
            interpreter = "/venv/bin/python"
        worker = subprocess.run(
            ["nsenter", "--target", str(fixture.namespace_pid), "--user", "--net", "--",
             "bwrap", "--die-with-parent", "--unshare-pid", "--unshare-ipc", "--new-session",
             *mounts, "--chdir", "/qa", interpreter, "/qa/browser.py", suite],
            env={"PATH": os.defpath, "HOME": "/tmp/profile", "TMPDIR": "/tmp",
                 "PLAYWRIGHT_BROWSERS_PATH": "/browsers", "PYTHONDONTWRITEBYTECODE": "1"},
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=600, check=False,
        )
        if worker.returncode:
            raise RuntimeError("QA browser worker failed. Verify nsenter and the Playwright Chromium installation.")
        return json.loads(worker.stdout)


def browser_checks(suite):
    origin = "http://127.0.0.1:18402"
    checks = []
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(args=["--disable-background-networking",
                                                  "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1"])
        try:
            context = browser.new_context(base_url=origin, service_workers="block")
            context.route("**/*", lambda route: route.continue_()
                          if urlsplit(route.request.url).netloc == urlsplit(origin).netloc
                          and urlsplit(route.request.url).scheme == "http" else route.abort())
            page = context.new_page()
            page.set_default_timeout(4500)
            page.on("dialog", lambda dialog: dialog.accept())

            def check(name, action):
                try:
                    action()
                except (AssertionError, ValueError, TypeError, KeyError, BrowserError):
                    checks.append({"name": name, "passed": False})
                else:
                    checks.append({"name": name, "passed": True})

            groups = {"navigation": navigation, "users": users, "servers": servers, "settings": settings}
            for name in SUITES if suite == "all" else (suite,):
                groups[name](page, check)
        finally:
            browser.close()
    return {"checks": checks}


def navigation(page, check):
    for width in (1440, 390):
        page.set_viewport_size({"width": width, "height": 900})
        for section in ("", "monitoring", "servers", "users", "audit", "alerts", "settings", "boosty"):
            path = "/admin/" + section

            def open_section():
                page.goto("/admin/")
                with page.expect_response(lambda r: urlsplit(r.url).path == path
                                          and r.request.is_navigation_request()) as response:
                    page.locator(f'nav a[href="{path}"]').first.click()
                assert response.value.ok
                expect(page.locator("main h1").first).to_be_visible()
                page.wait_for_load_state("load")
                page.evaluate("document.fonts.ready.then(() => true)")
                assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")

            check(f"Menu / {section or 'dashboard'} / {width}px", open_section)
    page.set_viewport_size({"width": 1440, "height": 900})

    def search():
        page.goto("/admin/")
        page.keyboard.press("/")
        box = page.locator("#tb-search")
        expect(box).to_be_focused()
        box.fill("qa-alice")
        box.press("Enter")
        page.locator('main a[href="/admin/users/qa-alice"]').first.click()
        expect(page.locator("h1")).to_contain_text("qa-alice")

    check("Global search / shortcut, matching user and detail link", search)

    def boosty_help():
        page.goto("/admin/boosty?view=sync")
        page.locator("[data-bookmarklet-link]").click()
        modal = page.locator("#bookmarklet-help-modal")
        expect(modal).to_be_visible()
        page.keyboard.press("Escape")
        expect(modal).to_be_hidden()

    check("Boosty / open instructions and dismiss with Escape", boosty_help)

    def modal_focus():
        page.goto("/admin/boosty?view=sync")
        page.locator("[data-bookmarklet-link]").click()
        page.keyboard.press("Tab")
        assert page.locator("#bookmarklet-help-modal").evaluate("e => e.contains(document.activeElement)")

    check("Boosty / keyboard focus stays inside the open instructions", modal_focus)

    def audit_export():
        page.goto("/admin/audit")
        page.locator('main select[name=actor]').select_option("cli")
        submit(page, "/admin/audit")
        with page.expect_download() as result:
            page.locator('main a[href*="audit.csv"]').click()
        download = result.value
        assert download.failure() is None
        with Path(download.path()).open(encoding="utf-8-sig") as stream:
            rows = list(csv.DictReader(stream))
        assert rows and all(row["actor"] == "cli" for row in rows)

    check("Audit / export filtered rows to CSV", audit_export)

    def audit_snapshots():
        page.goto("/admin/audit")
        page.get_by_role("link", name="show snapshots").click()
        page.locator('main [name=action]').fill("user.")
        submit(page, "/admin/audit")
        assert "hide=none" in urlsplit(page.url).query

    check("Audit / keep show-snapshots choice when changing filters", audit_snapshots)

    def missing_page():
        response = page.goto("/admin/missing-qa-page")
        assert response.status == 404
        expect(page.locator('a[href="/admin/"]').first).to_be_visible(timeout=1500)

    check("Unknown admin page / show a way back to the dashboard", missing_page)

    def monitoring():
        page.goto("/admin/monitoring")
        with page.expect_response(lambda r: r.request.method == "POST" and r.url.endswith("/probe-all")) as sweep:
            submit(page, "/probe-all")
        assert sweep.value.status in (200, 202, 303)
        for target in ("private-checks", "cheburcheck"):
            page.goto("/admin/monitoring")
            page.locator(f'main a[href="/admin/monitoring/{target}"]').first.click()
            expect(page.locator("main h1")).to_be_visible()

    check("Monitoring / start fleet probes and open both check panels", monitoring)

    def language():
        page.goto("/admin/")
        submit(page, "/tweak/lang")
        expect(page.locator("html")).to_have_attribute("lang", "ru")
        submit(page, "/tweak/lang")
        expect(page.locator("html")).to_have_attribute("lang", "en")

    check("Language / switch to Russian and back to English", language)


def submit(page, suffix):
    page.locator(f'form[action$="{suffix}"] button[type=submit], '
                 f'form[action$="{suffix}"] button:not([type])').first.click()


def users(page, check):
    def clear_filter():
        page.goto("/admin/users")
        field = page.locator('main form[method=get] [name=q]')
        field.fill("qa-alice")
        field.press("Enter")
        expect(page.locator('main a[href="/admin/users/qa-bob"]')).to_have_count(0)
        page.get_by_role("link", name="clear", exact=True).click()
        expect(field).to_have_value("", timeout=1500)
        expect(page.locator('main a[href="/admin/users/qa-bob"]').first).to_be_visible()

    check("User search / clear restores the unfiltered list", clear_filter)

    def small_quota():
        page.goto("/admin/users/qa-bob")
        submit(page, "/traffic-limit")
        page.reload()
        value = page.locator('[name=limit_gib]').input_value()
        assert value and float(value) == 0.048828125

    check("Traffic limit / saving unchanged preserves the seeded 50 MiB quota", small_quota)

    def paused_delivery():
        page.goto("/admin/users/qa-alice")
        submit(page, "/disable")
        try:
            page.goto("/admin/users/qa-alice/delivery")
            main = page.locator("main")
            if main.locator("textarea").count():
                assert any(word in main.inner_text().lower() for word in ("disabled", "paused"))
        finally:
            page.goto("/admin/users/qa-alice")
            submit(page, "/enable")

    check("Disabled user / delivery explains that displayed links are paused", paused_delivery)

    def lifecycle():
        page.goto("/admin/users")
        form = page.locator('form[method=post][action="/admin/users"]')
        form.locator('[name=id]').fill("qa-lifecycle")
        form.locator('[name=grant_all]').uncheck()
        form.locator("button").click()
        expect(page.locator("h1")).to_have_text("qa-lifecycle")
        submit(page, "/disable")
        submit(page, "/enable")
        expect(page.locator('form[action$="/disable"]')).to_be_visible()
        page.locator('a[href$="/delete-confirm"]').click()
        page.locator('[name=confirm]').fill("qa-lifecycle")
        submit(page, "/delete")
        page.goto("/admin/users")
        expect(page.locator('a[href="/admin/users/qa-lifecycle"]')).to_have_count(0)
        expect(page.locator('a[href="/admin/users/qa-bob"]').first).to_be_visible()

    check("Users / create, disable, enable and delete only the new user", lifecycle)
    for tab in ("overview", "delivery", "access", "activity", "traffic"):
        def open_tab():
            page.goto("/admin/users/qa-alice")
            link = page.locator(f'a[href="/admin/users/qa-alice/{tab}"]').first
            link.click()
            expect(page.locator("h1")).to_have_text("qa-alice")
            assert urlsplit(page.url).path.endswith("/" + tab)
        check(f"User detail / {tab}", open_tab)

    def access():
        page.goto("/admin/users/qa-alice/access")
        submit(page, "/grants/qa-node")
        expect(page.locator('form[action$="/grants/qa-node/revoke"]').first).to_be_visible()
        submit(page, "/grants/qa-node/revoke")
        expect(page.locator('form[action$="/grants/qa-node"]').first).to_be_visible()

    check("Access / grant and revoke on the test node", access)

    def limits():
        page.goto("/admin/users/qa-bob")
        page.locator('[name=limit_gib]').fill("12")
        page.locator('[name=threshold_pct]').fill("85")
        submit(page, "/traffic-limit")
        page.reload()
        assert float(page.locator('[name=limit_gib]').input_value()) == 12
        assert page.locator('[name=threshold_pct]').input_value() == "85"

    check("Traffic limit / value persists after reload", limits)

    def rotate():
        page.goto("/admin/users/qa-bob/delivery")
        field = page.locator("main textarea").first
        old = field.input_value()
        assert old
        page.goto("/admin/users/qa-bob")
        button = page.locator('form[action$="/sub-token/regenerate"] button').first
        if not button.is_visible():
            button.locator("xpath=ancestor::details[1]/summary").click()
        button.click()
        page.goto("/admin/users/qa-bob/delivery")
        new = field.input_value()
        assert new and new != old
        field.click()
        assert field.evaluate("e => e.selectionEnd - e.selectionStart === e.value.length")

    check("Delivery / rotate subscription and select the new URL for copying", rotate)


def servers(page, check):
    for tab in ("status", "activity", "protocols", "grants", "setup", "security", "cheburcheck"):
        def open_tab():
            page.goto("/admin/servers/qa-node")
            page.locator(f'a[href="/admin/servers/qa-node/{tab}"]').first.click()
            assert urlsplit(page.url).path.endswith("/" + tab)
            expect(page.locator("main h1")).to_be_visible()
        check(f"Server detail / {tab}", open_tab)

    for server, expected in (("qa-node", "available"), ("qa-offline", "unavailable")):
        def ssh_check():
            page.goto(f"/admin/servers/{server}/status")
            submit(page, "/ssh-check")
            badge = page.locator(f'[data-ssh-route=direct] [data-ssh-state="{expected}"]')
            deadline = time.monotonic() + 25
            while time.monotonic() < deadline:
                if badge.count():
                    return
                page.wait_for_timeout(300)
                page.reload()
            expect(badge).to_be_visible()

        check(f"SSH / {server} direct route becomes {expected}", ssh_check)

    def rename():
        page.goto("/admin/servers/qa-node/setup")
        page.locator('[name=display_name]').fill("QA Browser Node")
        submit(page, "/display-name")
        page.goto("/admin/servers")
        expect(page.locator('main a[href="/admin/servers/qa-node"]').first).to_contain_text("QA Browser Node")

    check("Server name / save and verify in inventory", rename)

    def wizard():
        page.goto("/admin/servers")
        page.locator('a[href="/admin/servers/new"]').click()
        submit(page, "/servers/new")
        expect(page.locator('[name=address]')).to_be_focused()
        assert page.locator('[name=root_password]').evaluate("e => e.validity.valueMissing")

    check("Add-server wizard / required fields prevent an empty submission", wizard)

    def protocol_visibility():
        page.goto("/admin/servers/qa-node/protocols")
        submit(page, "/vless%2Breality/hide")
        page.goto("/admin/servers/qa-node/protocols")
        submit(page, "/vless%2Breality/unhide")
        page.goto("/admin/servers/qa-node/protocols")
        expect(page.locator('form[action$="/vless%2Breality/hide"]')).to_be_visible()

    check("Protocols / hide and show VLESS in subscriptions", protocol_visibility)

    def billing():
        page.goto("/admin/servers/billing")
        details = page.locator("details").filter(has=page.locator('form[action$="/qa-node/billing"]'))
        details.locator("summary").click()
        form = details.locator("form")
        form.locator('[name=due_date]').fill("2030-02-04")
        form.locator('[name=amount]').fill("12.50")
        form.locator('[name=currency]').fill("EUR")
        submit(page, "/qa-node/billing")
        page.goto("/admin/servers/billing")
        expect(form.locator('[name=due_date]')).to_have_value("2030-02-04")

    check("Billing / store a rental date and amount", billing)

    def sse_failure():
        page.goto("/admin/servers/qa-offline/status")
        button = page.locator('button[data-log="update-kernels-log"]')
        button.click()
        expect(page.locator("#update-kernels-log")).to_contain_text("✗", timeout=20000)
        expect(button).to_be_enabled()

    check("Offline node / streamed update error and retry button", sse_failure)


def settings(page, check):
    def appearance():
        page.goto("/admin/settings/appearance")
        page.locator('form[action$="/theme"] button[value=ink]').click()
        page.goto("/admin/settings/appearance")
        assert any(c['value'] == 'ink' for c in page.context.cookies())
        page.locator('select[name=tz]').select_option("UTC")
        submit(page, "/timezone")
        page.goto("/admin/settings/appearance")
        expect(page.locator('select[name=tz]')).to_have_value("UTC")

    check("Appearance / persist theme and timezone", appearance)

    def backup():
        page.goto("/admin/settings/backups")
        submit(page, "/backup/snapshot")
        expect(page.locator('a[download][href*="/admin/backup/download/"]').first).to_be_visible()
        submit(page, "/backup/self-test")
        expect(page.locator("h1")).to_contain_text("Restore self-test")
        assert page.get_by_text("overall", exact=True).locator("xpath=following-sibling::*[1]").inner_text().startswith("PASS")

    check("Backups / snapshot then restore self-test", backup)

    def deploy_key_link():
        page.goto("/admin/settings/notifications")
        page.locator('main a[href$="#deploy-ssh-key"]').click()
        expect(page.locator("#deploy-ssh-key")).to_be_in_viewport(timeout=1500)

    check("Notifications / Deploy SSH key link reaches the key", deploy_key_link)


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in (*SUITES, "all"):
        raise SystemExit("Expected one QA suite")
    # The worker is usable only inside a QA loopback namespace.
    import socket
    if [name for _, name in socket.if_nameindex()] != ["lo"]:
        raise SystemExit("Expected an isolated loopback network")
    print(json.dumps(browser_checks(sys.argv[1])))
