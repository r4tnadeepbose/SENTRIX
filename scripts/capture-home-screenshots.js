/**
 * Capture the 5 key SENTRIX screenshots (Home is required).
 * Requires: Node.js + Playwright.
 *   npm i -D playwright
 *   npx playwright install chromium
 *   node scripts/capture-home-screenshots.js
 * Server must be running (default http://127.0.0.1:8710, demo mode).
 */
const { chromium } = require('playwright');
const path = require('path');
const BASE = process.env.SENTRIX_URL || 'http://127.0.0.1:8710';
const USER = process.env.SENTRIX_USER || 'admin';
const PASS = process.env.SENTRIX_PASS || 'sentrix-demo';
const out = (n) => path.join(__dirname, '..', 'docs', 'screenshots', n);

(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1600, height: 1000 } });
  await page.goto(BASE + '/login', { waitUntil: 'networkidle' });
  await page.fill('#username', USER).catch(()=>{});
  await page.fill('input[type=password], #password', PASS).catch(()=>{});
  await page.click('button[type=submit], .btn-primary, #submit').catch(()=>{});
  await page.waitForTimeout(2500);

  const shots = [
    ['#/home', 'home.png'],
    ['#/findings', 'findings.png'],
    ['#/sources', 'sources.png'],
    ['#/integrations', 'integrations.png'],
    ['#/hubs', 'hubs.png'],
  ];
  for (const [hash, name] of shots) {
    await page.goto(BASE + '/' + hash, { waitUntil: 'networkidle' }).catch(()=>{});
    await page.waitForTimeout(1800);
    await page.screenshot({ path: out(name), fullPage: true });
    console.log('saved', name);
  }
  await browser.close();
})();
