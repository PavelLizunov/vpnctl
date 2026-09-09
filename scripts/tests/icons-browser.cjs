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
(async () => {
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
        if (req.method() === 'GET' && url.origin === 'http://vpnctl.test') {
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
          close() {}
          emit(event, data) { this.events[event]?.(data === undefined ? {} : { data: JSON.stringify(data) }); }
        };
        const timeout = window.setTimeout;
        window.setTimeout = (fn, ms, ...args) => ms === 1200 || ms === 1400 ? 0 : timeout(fn, ms, ...args);
      });
      const page = await context.newPage();
      page.on('pageerror', error => unexpected.push(error.message));
      page.on('requestfailed', request => unexpected.push(request.url()));
      for (const fixture of manifest.pages) {
        current = fixture;
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
        if (javaScriptEnabled) {
          const buttons = page.locator('[data-sse-url]');
          for (let i = 0; i < await buttons.count(); i++) {
            const button = buttons.nth(i);
            const label = button.locator('[data-icon-label]');
            assert.equal(await label.count(), 1);
            for (const terminal of ['error', 'transport', 'ok']) {
              await button.evaluate(node => node.click());
              assert(await button.isDisabled());
              assert.equal(await button.locator('.ed-icon').count(), 1);
              await page.evaluate(event => window.__sources.at(-1).emit(event === 'transport' ? 'error' : event,
                event === 'transport' ? undefined : { message: 'Synthetic browser check' }), terminal);
              assert((await label.textContent()).trim());
              assert.equal(await button.locator('.ed-icon').count(), 1);
              assert.equal(await button.isDisabled(), terminal === 'ok');
              if (terminal === 'ok') assert.equal(await button.locator('use').getAttribute('href'), '/admin/assets/icons.svg#check');
              transitions++;
            }
          }
          const phases = await page.locator('[data-step-phase]').evaluateAll(nodes => nodes.map(n => n.dataset.stepPhase));
          for (const phase of phases) await page.evaluate(phase => window.__sources.at(-1).emit('step', { phase, message: 'Synthetic phase' }), phase);
          for (const marker of await page.locator('.step-mark').all()) {
            assert.equal(await marker.locator('use').getAttribute('href'), '/admin/assets/icons.svg#check');
            assert.equal(await marker.getAttribute('aria-label'), current.lang === 'ru' ? 'Готово' : 'Complete');
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
