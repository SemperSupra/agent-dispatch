#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const { chromium } = require('playwright');

(async () => {
  const out = '/tmp/playwright-result.json';
  const shot = '/tmp/playwright-control.png';
  const result = {
    schema: 'firecracker-playwright-control-guest/v1',
    sandbox_requested: true,
    network_used: false,
  };
  let browser;
  try {
    fs.mkdirSync('/tmp/xdg', { recursive: true, mode: 0o700 });
    process.env.XDG_RUNTIME_DIR = '/tmp/xdg';
    browser = await chromium.launch({
      headless: true,
      chromiumSandbox: true,
    });
    result.browser_version = browser.version();
    const page = await browser.newPage({ viewport: { width: 800, height: 600 } });
    await page.goto('file:///tmp/playwright-control.html');
    await page.click('#run');
    await page.waitForFunction(() => document.body.dataset.ready === '1');
    result.title = await page.title();
    result.dom_result = await page.locator('#result').textContent();
    result.ready = await page.locator('body').getAttribute('data-ready');
    await page.screenshot({ path: shot, fullPage: true });
    result.screenshot_exists = fs.existsSync(shot);
    result.ok = (
      result.title === 'Firecracker Playwright Control' &&
      result.dom_result === 'firecracker-playwright-ok:42' &&
      result.ready === '1' &&
      result.screenshot_exists
    );
  } catch (err) {
    result.ok = false;
    result.error = String(err && err.stack ? err.stack : err);
  } finally {
    if (browser) await browser.close().catch(() => {});
    fs.writeFileSync(out, JSON.stringify(result, null, 2) + '\n');
  }
  console.log('FIRECRACKER_PLAYWRIGHT_CONTROL ok=' + (result.ok ? '1' : '0') +
              ' sandbox=1 network=0' +
              (result.browser_version ? ' browser=' + result.browser_version.replace(/\s+/g, '_') : ''));
  process.exit(result.ok ? 0 : 27);
})();
