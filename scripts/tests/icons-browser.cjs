// Offline browser regression: export icon_fixtures first; no HTTP server or live VPN.
// NODE_PATH=<directory containing playwright-core> CHROME_BIN=<chromium executable>
// VPNCTL_ICON_FIXTURES=<export directory> node scripts/tests/icons-browser.cjs
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { chromium } = require('playwright-core');
const root = path.resolve(__dirname, '../..');
const assets = path.join(root, 'daemon/assets');
const fixtures = path.resolve(process.env.VPNCTL_ICON_FIXTURES || '/tmp/vpnctl-icon-fixtures');
const manifest = JSON.parse(fs.readFileSync(path.join(fixtures, 'manifest.json')));
const ids = [...fs.readFileSync(path.join(assets, 'icons.svg'), 'utf8').matchAll(/<symbol id="([^"]+)"/g)].map(m => m[1]);
const mime = { '.css': 'text/css', '.js': 'application/javascript', '.svg': 'image/svg+xml', '.woff2': 'font/woff2' };
const home = fs.mkdtempSync(path.join(os.tmpdir(), 'vpnctl-icon-browser-'));
let browser;
let deployFragmentOverride = null;
const deployPanelCache = new Map();
function deployPanelFromFixture(file) {
  if (!deployPanelCache.has(file)) {
    const html = fs.readFileSync(path.join(fixtures, file), 'utf8');
    const match = html.match(/<section[^>]*id="deployment-status"[\s\S]*?<\/section>/);
    deployPanelCache.set(file, match ? match[0] : null);
  }
  return deployPanelCache.get(file);
}

(async function adminSseAndIconRegressions() {
  assert(process.env.CHROME_BIN, 'CHROME_BIN must name a locally installed Chromium');
  browser = await chromium.launch({ executablePath: process.env.CHROME_BIN, headless: true,
    env: { ...process.env, HOME: home, XDG_CONFIG_HOME: home, XDG_CACHE_HOME: home },
    args: ['--no-sandbox', '--disable-background-networking', '--host-resolver-rules=MAP * ~NOTFOUND'] });
  let renders = 0, transitions = 0;
  for (const width of [1440, 390]) {
    for (const javaScriptEnabled of [true, false]) {
      const context = await browser.newContext({ viewport: { width, height: 1000 }, javaScriptEnabled, serviceWorkers: 'block' });
      let current;
      const unexpected = [];
      await context.route('**/*', async route => {
        const req = route.request(), url = new URL(req.url());
        if (req.method() === 'POST' && url.origin === 'http://vpnctl.test' && url.pathname === '/admin/sse-ticket') {
          return route.fulfill({ contentType: 'text/plain', body: 'synthetic-start-ticket' });
        }
        if (req.method() === 'GET' && url.origin === 'http://vpnctl.test') {
          if (url.searchParams.get('deploy_status') === '1') {
            const body = deployFragmentOverride || (current && deployPanelFromFixture(current.file));
            if (body) return route.fulfill({ contentType: 'text/html', body });
          }
          if (req.isNavigationRequest() && url.pathname === current.route) {
            return route.fulfill({ contentType: 'text/html', body: fs.readFileSync(path.join(fixtures, current.file)) });
          }
          if (url.pathname.startsWith('/admin/assets/')) {
            const file = path.resolve(assets, decodeURIComponent(url.pathname.slice('/admin/assets/'.length)));
            if (file.startsWith(assets + path.sep) && fs.existsSync(file) && fs.statSync(file).isFile()) {
              return route.fulfill({ contentType: mime[path.extname(file)] || 'application/octet-stream', body: fs.readFileSync(file) });
            }
          }
        }
        unexpected.push(req.url());
        return route.abort();
      });
      await context.routeWebSocket('**/*', socket => { unexpected.push(socket.url()); socket.close(); });
      await context.addInitScript(() => {
        window.__sources = [];
        window.EventSource = class {
          constructor() { this.events = {}; window.__sources.push(this); }
          addEventListener(event, callback) { this.events[event] = callback; }
          close() { this.closed = true; }
          emit(event, data) { this.events[event]?.(data === undefined ? {} : { data: JSON.stringify(data) }); }
        };
        const timeout = window.setTimeout;
        const cancel = window.clearTimeout;
        window.__reloadTimers = new Set();
        window.setTimeout = (fn, ms, ...args) => {
          if (ms === 1200 || ms === 1400) return 0;
          const id = timeout(ms === 5000 ? () => {} : fn, ms, ...args);
          if (ms === 5000) window.__reloadTimers.add(id);
          return id;
        };
        window.clearTimeout = id => { window.__reloadTimers.delete(id); cancel(id); };
        document.addEventListener('DOMContentLoaded', () => {
          if (document.getElementById('deployment-status')) return;
          const marker = document.createElement('div');
          marker.setAttribute('data-reload-after', '5');
          document.body.appendChild(marker);
        });
      });
      const page = await context.newPage();
      page.on('pageerror', error => unexpected.push(error.message));
      page.on('requestfailed', request => unexpected.push(request.url()));
      for (const fixture of manifest.pages) {
        current = fixture;
        deployFragmentOverride = null;
        await page.goto('http://vpnctl.test' + current.route, { waitUntil: 'load' });
        await page.evaluate(() => document.fonts.ready);
        const icons = await page.locator('svg.ed-icon').evaluateAll(nodes => nodes.map(svg => {
          const box = svg.getBBox();
          return { id: svg.querySelector('use')?.getAttribute('href')?.split('#')[1],
            hidden: svg.getAttribute('aria-hidden'), focus: svg.getAttribute('focusable'),
            rendered: !!svg.getClientRects().length, drawn: box.width > 0 || box.height > 0 };
        }));
        assert(icons.length >= 8, `${current.file}: missing navigation icons`);
        for (const icon of icons) {
          assert(ids.includes(icon.id), `${current.file}: unknown ${icon.id}`);
          assert.equal(icon.hidden, 'true'); assert.equal(icon.focus, 'false');
          if (icon.rendered) assert(icon.drawn, `${current.file}: empty ${icon.id}`);
        }
        const fits = await page.evaluate(() => {
          const bar = document.querySelector('.ed-tb');
          return document.documentElement.scrollWidth <= innerWidth + 1 && bar.scrollWidth <= bar.clientWidth + 1;
        });
        assert(fits, `${current.file}: topbar or body overflow at ${width}px`);
        if (width === 390 && current.name === 'server-protocols') {
          const deployPanel = page.locator('#deployment-status');
          if (await deployPanel.count()) {
            const box = await deployPanel.boundingBox();
            assert(box.height <= 210,
              `idle deploy panel must stay compact at 390px (${box.height}px tall)`);
          }
          const firstEnabledTop = await page.evaluate(() => {
            const row = [...document.querySelectorAll('li.ed-protocol')]
              .find(node => node.querySelector('.ed-protocol__on'));
            return row ? row.getBoundingClientRect().top : null;
          });
          if (firstEnabledTop !== null) {
            assert(firstEnabledTop <= 900,
              `compact idle deploy panel must keep the first enabled protocol in the first screen (top ${firstEnabledTop}px)`);
          }
        }
        if (javaScriptEnabled) {
          const buttons = page.locator('[data-sse-url]');
          for (let i = 0; i < await buttons.count(); i++) {
            const button = buttons.nth(i);
            const label = button.locator('[data-icon-label]');
            const deployButton = await button.getAttribute('data-deploy-panel') !== null;
            assert.equal(await label.count(), 1);
            for (const terminal of ['error', 'transport', 'ok']) {
              deployFragmentOverride = terminal === 'transport' && deployButton
                ? '<section id="deployment-status" data-deploy-state="unknown" data-deploy-can-start="false" data-deploy-generation="98" data-deploy-status-url="/admin/servers/s0?deploy_status=1"><span data-deploy-badge>unknown</span><span data-deploy-stage-phase>stream</span><span data-deploy-stage-message>connection lost</span><span data-deploy-stage-time></span><p data-deploy-note>operation may still be running</p><div data-deploy-error hidden></div></section>'
                : null;
              await page.reload({ waitUntil: 'load' });
              const deployPage = await page.locator('#deployment-status').count() > 0;
              assert.equal(await page.evaluate(() => window.__reloadTimers.size), deployPage ? 0 : 1,
                'deploy pages must poll the status panel, not reload');
              const sources = await page.evaluate(() => window.__sources.length);
              await button.evaluate(node => node.click());
              await page.waitForFunction(count => window.__sources.length > count, sources);
              assert(await button.isDisabled());
              assert.equal(await page.evaluate(() => window.__reloadTimers.size), 0, 'R4-18: SSE start must cancel page refresh');
              assert.equal(await button.locator('.ed-icon').count(), 1);
              await page.evaluate(event => window.__sources.at(-1).emit(event === 'transport' ? 'error' : event,
                event === 'transport' ? undefined : { message: 'Synthetic browser check' }), terminal);
              assert((await label.textContent()).trim());
              assert.equal(await button.locator('.ed-icon').count(), 1);
              if (deployButton && terminal === 'ok') {
                await page.waitForFunction(() => {
                  const state = document.querySelector('#deployment-status')?.getAttribute('data-deploy-state');
                  return state && state !== 'running' && state !== 'queued';
                }, null, { timeout: 6000 });
                assert.equal(await button.isDisabled(), false, 'a settled deploy must not mask later operations');
              } else {
                assert.equal(await button.isDisabled(), terminal !== 'error', 'R4-14: transport loss must keep start disabled');
              }
              assert(await page.evaluate(() => window.__sources.at(-1).closed));
              if (terminal === 'transport') {
                const log = page.locator('#' + (await button.getAttribute('data-log') || 'deploy-log'));
                assert((await log.textContent()).includes(current.lang === 'ru' ? 'операция может ещё выполняться' : 'operation may still be running'));
                await button.evaluate(node => node.click());
                assert.equal(await page.evaluate(() => window.__sources.length), sources + 1, 'R4-14: disabled retry must not start another operation');
              }
              if (terminal === 'ok' && !deployButton) assert.equal(await button.locator('use').getAttribute('href'), '/admin/assets/icons.svg#check');
              transitions++;
            }
            deployFragmentOverride = null;
          }
          const phases = await page.locator('[data-step-phase]').evaluateAll(nodes => nodes.map(n => n.dataset.stepPhase));
          if (phases.length) {
            assert.equal(await page.evaluate(() => window.__reloadTimers.size), 0, 'R4-18: autostart must cancel page refresh');
            for (let i = 0; i < phases.length; i++) {
              const phase = phases[i];
              for (let repeat = 0; repeat < 2; repeat++) {
                await page.evaluate(phase => window.__sources.at(-1).emit('step', { phase, message: 'Synthetic phase' }), phase);
                const marks = await page.locator('.step-mark use').evaluateAll(nodes => nodes.map(n => n.getAttribute('href').split('#')[1]));
                assert.deepEqual(marks, phases.map((_, k) => k < i ? 'check' : k === i ? 'clock' : 'circle-dashed'), 'R4-19: only prior phases may be complete');
                assert.equal(await page.locator('.step-mark').nth(i).getAttribute('aria-label'), current.lang === 'ru' ? 'Выполняется' : 'In progress');
              }
            }
            await page.evaluate(() => window.__sources.at(-1).emit('ok', {}));
          }
          for (const marker of await page.locator('.step-mark').all()) {
            assert.equal(await marker.locator('use').getAttribute('href'), '/admin/assets/icons.svg#check');
            assert.equal(await marker.getAttribute('aria-label'), current.lang === 'ru' ? 'Готово' : 'Complete');
          }
          if (phases.length) {
            await page.reload({ waitUntil: 'load' });
            await page.evaluate(() => {
              const source = window.__sources.at(-1);
              source.emit('step', { phase: 'setup', message: 'Loading key' });
              source.emit('step', { phase: 'probe', message: 'Connecting' });
              source.emit('error', { phase: 'probe', message: 'Synthetic failure' });
            });
            const marks = await page.locator('.step-mark use').evaluateAll(nodes => nodes.map(n => n.getAttribute('href').split('#')[1]));
            assert.deepEqual(marks, phases.map((_, i) => i === 0 ? 'check' : i === 1 ? 'clock' : 'circle-dashed'), 'R4-19: a failed probe must not complete deployment rows');
          }
          const deployButton = page.locator('#deploy-button');
          if (await deployButton.count() && current.name === 'server-status' && current.theme === 'default') {
            await page.reload({ waitUntil: 'load' });
            const beforeUrl = page.url();
            const sources = await page.evaluate(() => window.__sources.length);
            await deployButton.evaluate(node => node.click());
            await page.waitForFunction(count => window.__sources.length > count, sources);
            await page.evaluate(() => {
              const input = document.createElement('input');
              input.id = 'deploy-draft-probe';
              const spacer = document.createElement('div');
              spacer.id = 'deploy-spacer';
              spacer.style.height = '2400px';
              document.body.appendChild(spacer);
              document.body.appendChild(input);
              input.value = 'typed draft';
              input.focus();
              window.scrollTo(0, 600);
            });
            await page.evaluate(() => window.__sources.at(-1).emit('step', { phase: 'apply', message: 'Synthetic stage' }));
            assert((await page.locator('#deployment-status [data-deploy-stage-message]').textContent()).includes('Synthetic stage'));
            await page.evaluate(() => window.__sources.at(-1).emit('ok', { message: 'Synthetic done' }));
            await page.waitForTimeout(1500);
            assert.equal(page.url(), beforeUrl, 'deploy completion must keep the current URL');
            assert.equal(await page.evaluate(() => document.activeElement.id), 'deploy-draft-probe', 'deploy completion must keep focus');
            assert.equal(await page.inputValue('#deploy-draft-probe'), 'typed draft', 'deploy completion must keep form drafts');
            assert((await page.evaluate(() => window.scrollY)) >= 100, 'deploy completion must keep scroll position');
            await page.waitForFunction(() => {
              const state = document.querySelector('#deployment-status')?.getAttribute('data-deploy-state');
              return state && state !== 'running' && state !== 'queued';
            }, null, { timeout: 6000 });
            assert.equal(await deployButton.isDisabled(), false, 'a settled deploy must not mask later operations');
          }
          if (current.name === 'server-status' && current.theme === 'default' && current.lang === 'en' && width === 1440) {
            await page.reload({ waitUntil: 'load' });
            deployFragmentOverride = '<section id="deployment-status" data-deploy-state="running" data-deploy-can-start="false" data-deploy-generation="99" data-deploy-status-url="/admin/servers/s0?deploy_status=1"><span data-deploy-badge>running</span><span data-deploy-server-label>server s0</span><span data-deploy-stage-phase>apply</span><span data-deploy-stage-message>Other tab: applying saved configuration</span><span data-deploy-stage-time></span><p data-deploy-note>applying</p><div data-deploy-error hidden></div></section>';
            await page.waitForFunction(() => document.querySelector('#deployment-status')?.getAttribute('data-deploy-state') === 'running', null, { timeout: 8000 });
            assert((await page.locator('#deployment-status [data-deploy-stage-message]').textContent()).includes('Other tab'));
            assert(await page.locator('#deploy-button').isDisabled());
            deployFragmentOverride = null;
          }
        }
        assert.deepEqual(unexpected, [], `${current.file}: unexpected network/script failure`);
        renders++;
      }
      await context.close();
    }
  }
  console.log(`PASS: ${renders} offline renders, ${transitions} SSE transitions, ${ids.length} local SVG symbols; JS on/off, 4 themes, EN/RU, desktop/mobile.`);
})().catch(error => { console.error(error); process.exitCode = 1; }).finally(async () => {
  if (browser) await browser.close();
  fs.rmSync(home, { recursive: true, force: true });
});
