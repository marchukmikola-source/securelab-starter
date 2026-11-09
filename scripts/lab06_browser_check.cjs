// Run only against the local study API; credentials arrive through the process environment.
const assert = require('node:assert/strict');
const { chromium } = require('playwright');

(async () => {
  const browser = await chromium.launch({ channel: 'chrome', headless: true });
  try {
    const page = await browser.newPage();
    const errors = [];
    page.on('pageerror', () => errors.push('pageerror'));
    await page.goto('http://localhost:5080/auth-lab.html');
    await page.locator('#login-form input[name=userName]').fill('alice');
    await page.locator('#login-form input[name=password]').fill(process.env.SeedUsers__Password);
    await page.locator('#login-form button').click();
    await page.waitForFunction(() => document.querySelector('#session-state').textContent === 'Сеанс активний');
    await page.waitForFunction(() => document.querySelector('#profile').textContent.includes('alice'));
    await page.reload();
    await page.waitForFunction(() => document.querySelector('#session-state').textContent === 'Сеанс активний');
    await page.goto('http://localhost:5080/');
    await page.waitForFunction(() => document.querySelectorAll('#incident-list li').length === 3);
    await page.locator('#incident-list button').first().click();
    await page.waitForFunction(() => document.querySelector('#incident-details').querySelector('h3'));
    await page.locator('#load-severity-summary').click();
    await page.waitForFunction(() => document.querySelectorAll('#severity-summary-list li').length === 4);
    await page.goto('http://localhost:5080/browser-lab.html');
    await page.locator('#incident-id').fill('20000000-0000-0000-0000-000000000001');
    await page.locator('#load').click();
    await page.waitForFunction(() => document.querySelector('#status').textContent === 'GET: 200');
    await page.waitForFunction(() => document.querySelector('#comments').textContent.includes('<img'));
    assert.equal(await page.locator('#comments img').count(), 0);
    assert.equal(await page.locator('#lab05-marker-target').getAttribute('data-lab05-marker'), null);
    await page.goto('http://localhost:5080/auth-lab.html');
    await page.waitForFunction(() => document.querySelector('#session-state').textContent === 'Сеанс активний');
    await page.locator('#logout').click();
    await page.waitForFunction(() => document.querySelector('#session-state').textContent === 'Не ввійшли');
    assert.equal(errors.length, 0);
    process.stdout.write(JSON.stringify({
      browser: 'Chrome / Playwright, headless', profile: 'Development', transport: 'HTTP loopback',
      login: 'PASS', profileRead: 'PASS', reloadSession: 'PASS', incidentListCount: 3,
      details: 'PASS', severityGroups: 4, storedMarkerRenderedAsText: true,
      markerExecuted: false, logout: 'PASS', pageErrors: 0
    }));
  } finally { await browser.close(); }
})().catch(() => { process.stderr.write('Browser flow failed; credentials and page data omitted.\n'); process.exitCode = 1; });
