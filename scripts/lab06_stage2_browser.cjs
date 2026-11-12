const assert = require('node:assert/strict');
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require('playwright');

const base = 'http://localhost:5080';
const csrfHeader = 'X-CSRF-TOKEN';
const screenshots = path.resolve(process.env.LAB06_SCREENSHOT_DIRECTORY || 'docs/evidence/screenshots/lab06-stage2');
const proof = { client: 'Chrome / Playwright', transport: 'HTTP loopback', profile: 'Development' };
let phase = 'startup';
const expectedHeaders = {
  'content-security-policy': "default-src 'self'; frame-ancestors 'none'; form-action 'self'",
  'x-content-type-options': 'nosniff', 'referrer-policy': 'no-referrer'
};

async function login(page, user) {
  await page.goto(base + '/auth-lab.html');
  await page.locator('#login-form input[name=userName]').fill(user);
  await page.locator('#login-form input[name=password]').fill(process.env.SeedUsers__Password);
  await page.locator('#login-form button').click();
  await page.waitForFunction(user => document.querySelector('#profile').textContent.includes(user), user);
}

async function submitIncident(page, title) {
  await page.locator('#incident-form input[name=title]').fill(title);
  await page.locator('#incident-form textarea[name=description]').fill('A legitimate browser mutation protected with a standard antiforgery token pair.');
  const localDate = await page.evaluate(() => {
    const now = new Date(Date.now() - 120000);
    return new Date(now.getTime() - now.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
  });
  await page.locator('#incident-form input[name=occurredAtUtc]').fill(localDate);
  const pending = page.waitForResponse(r => r.url() === base + '/api/incidents' && r.request().method() === 'POST');
  await page.locator('#incident-form button').click();
  const response = await pending;
  assert.equal(response.status(), 201);
  const headers = await response.request().allHeaders();
  assert.ok(headers[csrfHeader.toLowerCase()]);
  return { status: response.status(), csrfHeaderPresent: true };
}

(async () => {
  fs.mkdirSync(screenshots, { recursive: true });
  const servers = [];
  const browser = await chromium.launch({ channel: 'chrome', headless: true });
  try {
    const context = await browser.newContext({ viewport: { width: 1440, height: 1000 }, timezoneId: 'Europe/Kyiv' });
    const page = await context.newPage();
    const pageErrors = [], violations = [];
    await context.exposeBinding('recordCspViolation', (_, directive) => violations.push(directive));
    await context.addInitScript(() => document.addEventListener('securitypolicyviolation', event => {
      window.recordCspViolation(event.effectiveDirective);
    }));
    context.on('page', p => p.on('pageerror', () => pageErrors.push('pageerror')));
    page.on('pageerror', () => pageErrors.push('pageerror'));

    phase = 'real-cookie-csrf-regression';
    // A fresh browser cookie jar first logs in without asking the UI helper for a token.
    const raw = await browser.newContext();
    const api = raw.request;
    assert.equal((await api.post(base + '/api/auth/login', {
      data: { userName: 'alice', password: process.env.SeedUsers__Password }
    })).status(), 204);
    const resourcePath = base + '/api/incidents/20000000-0000-0000-0000-000000000003';
    const initialResponse = await api.get(resourcePath);
    assert.equal(initialResponse.status(), 200);
    const initial = await initialResponse.json();
    const mutation = { title: 'REG-CSRF-01 browser ' + Date.now(), description: 'A legitimate update after successful standard token issuance and validation.' };
    const missing = await api.put(resourcePath, { data: mutation });
    assert.equal(missing.status(), 400);
    assert.equal((await missing.json()).code, 'csrf_validation_failed');
    assert.deepEqual(await (await api.get(resourcePath)).json(), initial);
    const invalid = await api.put(resourcePath, { data: mutation, headers: { [csrfHeader]: 'invalid-study-token' } });
    assert.equal(invalid.status(), 400);
    assert.deepEqual(await (await api.get(resourcePath)).json(), initial);
    const tokenResponse = await api.get(base + '/api/auth/csrf');
    assert.equal(tokenResponse.status(), 200);
    const token = (await tokenResponse.json()).requestToken;
    const allowed = await api.put(resourcePath, { data: mutation, headers: { [csrfHeader]: token } });
    assert.equal(allowed.status(), 204);
    const changed = await (await api.get(resourcePath)).json();
    assert.equal(changed.title, mutation.title);
    assert.equal(changed.description, mutation.description);
    assert.equal((await api.put(resourcePath, { data: { title: initial.title, description: initial.description }, headers: { [csrfHeader]: token } })).status(), 204);
    proof.regCsrf01 = { login: 204, allowedInitialRead: 200, missingToken: 400, invalidToken: 400,
      unchangedAfterBothDenials: true, tokenIssuance: 200, validPair: 204, intendedChangeObserved: true, values: 'omitted' };
    await raw.close();

    phase = 'normal-client-and-development-headers';
    await login(page, 'alice');
    proof.headers = [];
    for (const [route, expected] of [ ['/', 200], ['/api/incidents/20000000-0000-0000-0000-000000000001', 200],
      ['/api/incidents?status=Unknown', 400], ['/api/incidents/99999999-9999-9999-9999-999999999999', 404] ]) {
      const response = await context.request.get(base + route);
      assert.equal(response.status(), expected);
      const all = response.headers();
      for (const [name, value] of Object.entries(expectedHeaders)) assert.equal(all[name], value);
      proof.headers.push({ profile: 'Development', method: 'GET', route, status: expected, headers: expectedHeaders });
    }
    const cookies = await context.cookies(base);
    const auth = cookies.find(c => c.name === '.AspNetCore.Identity.Application');
    const anti = cookies.find(c => c.name === 'SecureLab.Antiforgery');
    assert.equal(auth.httpOnly, true); assert.equal(auth.sameSite, 'Lax');
    assert.equal(anti.httpOnly, true); assert.equal(anti.sameSite, 'Strict');
    proof.cookies = { auth: { httpOnly: auth.httpOnly, sameSite: auth.sameSite, secure: auth.secure },
      antiforgery: { httpOnly: anti.httpOnly, sameSite: anti.sameSite, secure: anti.secure }, values: 'omitted' };
    await page.goto(base + '/');
    await page.waitForFunction(() => document.querySelectorAll('#incident-list li').length === 3);
    await page.locator('#incident-list button').first().click();
    await page.waitForFunction(() => document.querySelector('#incident-details h3'));
    await page.screenshot({ path: path.join(screenshots, 'client-csp.png'), fullPage: true });

    phase = 'cors-origins';
    for (const port of [4173, 4174]) {
      const server = http.createServer((_, response) => {
        response.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        response.end('<!doctype html><html lang="uk"><title>Локальна CORS-перевірка</title><h1>Локальна CORS-перевірка</h1><pre id="result"></pre></html>');
      });
      await new Promise((resolve, reject) => { server.once('error', reject); server.listen(port, '127.0.0.1', resolve); });
      servers.push(server);
    }
    proof.cors = [];
    for (const [port, allowedOrigin] of [[4173, true], [4174, false]]) {
      const probe = await context.newPage();
      await probe.goto('http://localhost:' + port);
      const outcome = await probe.evaluate(async target => {
        try {
          const response = await fetch(target + '/api/incidents', { credentials: 'include', headers: { 'X-Lab-Cors-Probe': '1' } });
          await response.json();
          return { readable: true, status: response.status };
        } catch { return { readable: false, browserBlocked: true }; }
      }, base);
      assert.equal(outcome.readable, allowedOrigin);
      if (allowedOrigin) assert.equal(outcome.status, 200);
      await probe.locator('#result').evaluate((element, value) => { element.textContent = JSON.stringify(value, null, 2); }, outcome);
      await probe.screenshot({ path: path.join(screenshots, 'cors-' + port + '.png') });
      const tokenReadable = await probe.evaluate(async target => {
        try { await fetch(target + '/api/auth/csrf', { credentials: 'include' }).then(r => r.json()); return true; }
        catch { return false; }
      }, base);
      assert.equal(tokenReadable, false);
      proof.cors.push({ origin: 'http://localhost:' + port, ...outcome, tokenEndpointReadable: tokenReadable });
      await probe.close();
    }
    const direct = await context.request.get(base + '/api/incidents', { headers: { Origin: 'http://localhost:4174' } });
    assert.equal(direct.status(), 200);
    assert.equal(direct.headers()['access-control-allow-origin'], undefined);
    proof.corsDirectHttp = { origin: 'http://localhost:4174', status: 200, accessControlAllowOrigin: 'absent',
      boundary: 'Direct HTTP is not subject to browser CORS; authorization still required.' };

    phase = 'search-quota-partitions-and-recovery';
    const search = base + '/api/incidents/search?q=USB';
    for (let i = 0; i < 30; i++) assert.equal((await context.request.get(search)).status(), 200);
    assert.equal((await context.request.get(search)).status(), 429);
    assert.equal((await context.request.get(search + '&client=forged', { headers: { 'X-Demo-UserId': 'bob' } })).status(), 429);
    const other = await browser.newContext();
    assert.equal((await other.request.post(base + '/api/auth/login', {
      data: { userName: 'bob', password: process.env.SeedUsers__Password }
    })).status(), 204);
    assert.equal((await other.request.get(search)).status(), 200);
    assert.equal((await context.request.get(base + '/api/incidents/20000000-0000-0000-0000-000000000002')).status(), 404);
    assert.equal((await context.request.get(base + '/api/me')).status(), 200);
    await new Promise(resolve => setTimeout(resolve, 10500));
    assert.equal((await context.request.get(search)).status(), 200);
    proof.searchRateLimit = { partitionKey: 'verified NameIdentifier claim', permitLimit: 30, windowSeconds: 10,
      withinQuota: '30 x 200', overQuota: 429, forgedHeaderAndQuery: 429, secondUser: 200,
      foreignResourceStillDenied: 404, otherEndpointUnaffected: 200, afterWindow: 200 };
    await other.close();

    phase = 'all-existing-ui-mutations';
    await page.goto(base + '/auth-lab.html');
    const suffix = Date.now().toString();
    await page.locator('#register-form input[name=userName]').fill('lr06' + suffix);
    await page.locator('#register-form input[name=email]').fill('lr06' + suffix + '@example.test');
    await page.locator('#register-form input[name=displayName]').fill('Навчальний профіль ЛР 6');
    await page.locator('#register-form input[name=password]').fill(process.env.SeedUsers__Password);
    const registration = page.waitForResponse(r => r.url().endsWith('/api/auth/register') && r.request().method() === 'POST');
    await page.locator('#register-form button').click();
    assert.equal((await registration).status(), 201);
    const firstCreate = await submitIncident(page, 'UI CSRF first ' + suffix);
    await page.reload();
    await page.waitForFunction(() => document.querySelector('#profile').textContent.includes('alice'));
    const afterReload = await submitIncident(page, 'UI CSRF after F5 ' + suffix);
    await page.goto(base + '/browser-lab.html');
    await page.reload();
    await page.locator('#edit input[name=title]').fill('Browser page CSRF ' + suffix);
    await page.locator('#edit textarea[name=description]').fill('A normal creation from browser-lab after a fresh full page reload.');
    const browserCreateResponse = page.waitForResponse(r => r.url() === base + '/api/incidents' && r.request().method() === 'POST');
    await page.locator('#edit button').click();
    const created = await browserCreateResponse;
    assert.equal(created.status(), 201);
    assert.ok((await created.request().allHeaders())[csrfHeader.toLowerCase()]);
    await page.waitForFunction(() => document.querySelector('#status').textContent === 'GET: 200');
    await page.goto(base + '/session-state-demo.html');
    await page.reload();
    await page.waitForFunction(() => document.querySelector('#session-state').textContent === 'Сеанс активний');
    await page.locator('#logout').click();
    await page.waitForFunction(() => document.querySelector('#session-state').textContent === 'Не ввійшли');
    await login(page, 'bob');
    const newPrincipal = await submitIncident(page, 'Bob new principal CSRF ' + suffix);
    await page.locator('#logout').click();
    await page.waitForFunction(() => document.querySelector('#session-state').textContent === 'Не ввійшли');
    const storage = await page.evaluate(() => ({ local: localStorage.length, session: sessionStorage.length }));
    assert.deepEqual(storage, { local: 0, session: 0 });
    assert.equal(pageErrors.length, 0);
    assert.equal(violations.length, 0);
    proof.ui = { register: 201, authCreate: firstCreate, createAfterReload: afterReload,
      browserLabCreate: { status: 201, csrfHeaderPresent: true, subsequentRead: 200 },
      sessionDemoLogoutAfterReload: 204, newPrincipalCreate: newPrincipal, authLabLogout: 204,
      tokenStorage: 'memory only; localStorage/sessionStorage empty', pageErrors: 0, cspViolations: 0 };
    await context.close();
    process.stdout.write(JSON.stringify(proof));
  } finally {
    await browser.close();
    for (const server of servers) await new Promise(resolve => server.close(resolve));
  }
})().catch(error => {
  process.stderr.write('Stage 2 browser failure at ' + phase + ': ' + error.name + ' (values omitted).\n');
  process.exitCode = 1;
});
