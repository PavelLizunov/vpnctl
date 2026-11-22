// Protocol action regression against a running vpnctl QA stand: real daemon, real
// qa-offline markup, real POST -> 303 -> GET. Serves this checkout's admin.js so the
// branch client is tested even when the stand predates it; successful actions are undone.
//   VPNCTL_PROTOCOLS_URL=http://127.0.0.1:28748 CHROME_BIN=<chromium> \
//     NODE_PATH=<directory containing playwright-core> node scripts/tests/protocols-browser.cjs
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require('playwright-core');

const origin = process.env.VPNCTL_PROTOCOLS_URL;
assert(origin, 'Set VPNCTL_PROTOCOLS_URL to a disposable seeded QA stand');
assert(['127.0.0.1', 'localhost', '[::1]'].includes(new URL(origin).hostname),
  'Use a disposable local QA stand for this mutation test');
const server = 'qa-offline';
const pagePath = `/admin/servers/${server}/protocols`;
const adminJs = fs.readFileSync(path.resolve(__dirname, '../../daemon/assets/admin.js'));

(async () => {
  assert(process.env.CHROME_BIN, 'CHROME_BIN must name a locally installed Chromium');
  const browser = await chromium.launch({ executablePath: process.env.CHROME_BIN, headless: true,
    args: ['--no-sandbox', '--disable-background-networking'] });
  const context = await browser.newContext({ viewport: { width: 1280, height: 900 }, serviceWorkers: 'block' });
  await context.route('**/admin/assets/admin.js*', route =>
    route.fulfill({ contentType: 'application/javascript', body: adminJs }));
  const page = await context.newPage();
  const requests = [];
  let dismiss = false;
  page.on('request', request => requests.push(request));
  page.on('dialog', dialog => (dismiss ? dialog.dismiss() : dialog.accept()));

  const section = page.locator('#enabled-protocols');
  const row = pid => section.locator('li.ed-protocol', { hasText: pid }).first();
  const control = (pid, operation) => row(pid).locator(`form[action$="/${operation}"] button`);
  const pidOf = async locator => (await locator.locator('strong').first().textContent()).trim();
  const posts = operation => requests.filter(request =>
    request.method() === 'POST' && request.url().endsWith(`/${operation}`));
  const navs = () => requests.filter(request => request.isNavigationRequest()).map(request => request.url());
  const openGroups = () => section.locator('details').evaluateAll(nodes => nodes.map(node => node.open));
  const focused = () => page.evaluate(() => {
    const element = document.activeElement;
    return {
      action: element?.form?.getAttribute('action') || '',
      inside: !!element?.closest('#enabled-protocols'),
    };
  });
  const measure = pid => page.evaluate(pid => {
    const main = document.querySelector('main.ed-main');
    const scroller = getComputedStyle(main).overflowY === 'visible' ? document.scrollingElement : main;
    const item = [...document.querySelectorAll('#enabled-protocols > ul > li.ed-protocol')]
      .find(node => node.querySelector('strong')?.textContent.trim() === pid);
    return { top: scroller.scrollTop, row: item?.getBoundingClientRect().top ?? null };
  }, pid);
  const assertInPlace = (label) => {
    assert.deepEqual(navs(), [], `${label}: the document must not navigate`);
    assert.equal(new URL(page.url()).pathname, pagePath, `${label}: must stay on the protocols page`);
  };
  // Keyboard activation is the operator path; keep focus on the control the refresh
  // replaces and prove the list updated in the same document.
  async function activate(button, ready, operation, label) {
    await button.scrollIntoViewIfNeeded();
    await button.focus();
    requests.length = 0;
    await page.keyboard.press('Enter');
    await ready.waitFor({ state: 'attached', timeout: 5000 });
    assertInPlace(label);
    assert.equal(posts(operation).length, 1, `${label}: exactly one POST`);
  }

  try {
    await page.goto(`${origin}${pagePath}`, { waitUntil: 'load' });
    await page.evaluate(() => document.fonts.ready);
    await section.locator('details summary').first().click();
    const openDisclosures = await openGroups();
    const enabledRow = ':scope > ul > li.ed-protocol';
    const hidePid = await pidOf(section.locator(enabledRow)
      .filter({ has: page.locator('form[action$="/hide"]') }).first());
    const disablePid = await pidOf(section.locator(enabledRow)
      .filter({ has: page.locator('form[action$="/hide"]') }).nth(1));
    const cancelPid = await pidOf(section.locator(enabledRow)
      .filter({ has: page.locator('form[action$="/hide"]') }).nth(2));
    requests.length = 0;

    // Hide below the top of the scrollable main; the row and scroller must not move.
    await control(hidePid, 'hide').scrollIntoViewIfNeeded();
    await page.evaluate(pid => {
      const main = document.querySelector('main.ed-main');
      const item = [...document.querySelectorAll('#enabled-protocols > ul > li.ed-protocol')]
        .find(node => node.querySelector('strong')?.textContent.trim() === pid);
      main.scrollTop += item.getBoundingClientRect().top - main.getBoundingClientRect().top - 250;
    }, hidePid);
    const beforeHide = await measure(hidePid);
    assert(beforeHide.top > 200, 'hide/show must run below the top of the list');
    await activate(control(hidePid, 'hide'), row(hidePid).locator('form[action$="/unhide"]'), 'hide', 'hide');
    const afterHide = await measure(hidePid);
    assert(Math.abs(afterHide.top - beforeHide.top) <= 1, `hide: scroll must stay (${beforeHide.top} -> ${afterHide.top})`);
    assert(Math.abs(afterHide.row - beforeHide.row) <= 1, 'hide: the row must stay put');
    assert((await focused()).action.endsWith('/unhide'), 'hide: focus follows the flipped control');
    assert.deepEqual(await openGroups(), openDisclosures, 'hide: open disclosures must stay open');

    await activate(control(hidePid, 'unhide'), row(hidePid).locator('form[action$="/hide"]'), 'unhide', 'show');
    const afterShow = await measure(hidePid);
    assert(Math.abs(afterShow.top - beforeHide.top) <= 1, 'show: scroll must return to the same place');
    assert((await focused()).action.endsWith('/hide'), 'show: focus follows the flipped control');

    // Disable removes the enabled row and adds it to the open available disclosure.
    await activate(control(disablePid, 'disable'),
      section.locator('details li.ed-protocol', { hasText: disablePid }).locator('form[action$="/enable"]'),
      'disable', 'disable');
    assert.equal(await section.locator(':scope > ul > li.ed-protocol', { hasText: disablePid }).count(), 0,
      'disable: the row must leave the enabled list');
    assert.equal(await section.locator('details li.ed-protocol', { hasText: disablePid }).count(), 1,
      'disable: the row must appear in the available list');
    assert.equal((await focused()).action, await control(disablePid, 'enable').evaluate(b => b.form.getAttribute('action')),
      'disable: focus follows the same protocol into the open disclosure');
    assert.deepEqual(await openGroups(), openDisclosures, 'disable: open disclosures must stay open');
    await activate(section.locator('details li.ed-protocol', { hasText: disablePid })
      .locator('form[action$="/enable"] button'),
    row(disablePid).locator('form[action$="/disable"]'), 'enable', 'enable');
    assert.equal(await section.locator('details li.ed-protocol', { hasText: disablePid }).count(), 0,
      'enable: the row must return to the enabled list');

    // Dismissing the native confirmation cancels before any request is made.
    const cancel = control(cancelPid, 'disable');
    await cancel.scrollIntoViewIfNeeded();
    await cancel.focus();
    requests.length = 0;
    dismiss = true;
    await page.keyboard.press('Enter');
    await page.waitForTimeout(300);
    dismiss = false;
    assert.equal(posts('disable').length, 0, 'cancelled disable: no POST');
    assertInPlace('cancelled disable');
    assert((await focused()).action.endsWith('/disable'), 'cancelled disable: focus stays on the control');

    // A server-side rejection must surface its reason without navigating or losing focus.
    const failed = section.locator('details li.ed-protocol', { has: page.locator('form[action$="/enable"]') }).first();
    const failedPid = await pidOf(failed);
    await context.route(`**/protocols/${encodeURIComponent(failedPid)}/enable`, route =>
      route.request().method() === 'POST'
        ? route.fulfill({ status: 400, contentType: 'text/plain',
          body: 'vpnctl admin: simulated rejection: protocol cannot be enabled\n' })
        : route.continue());
    const failedButton = failed.locator('form[action$="/enable"] button');
    await failedButton.scrollIntoViewIfNeeded();
    await failedButton.focus();
    requests.length = 0;
    await page.keyboard.press('Enter');
    await section.getByText('simulated rejection', { exact: false }).waitFor({ state: 'visible' });
    assertInPlace('rejected enable');
    assert.equal(posts('enable').length, 1, 'rejected enable: exactly one POST');
    assert((await focused()).inside, 'rejected enable: focus must stay in the protocol section');
    console.log(`PASS: hide/show ${hidePid}, disable/enable ${disablePid}, cancelled ${cancelPid}, rejected ${failedPid}; no navigation, stable scroll, focus kept.`);
  } finally {
    await browser.close();
  }
})().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
