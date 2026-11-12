const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require('playwright');
const base = 'http://localhost:5080';
const header = 'X-CSRF-TOKEN';
const revokePath = '/api/me/sessions/revoke-all';
const incident = '/api/incidents/20000000-0000-0000-0000-000000000003';
const screenshots = path.resolve(process.env.LAB06_ADVANCED_SCREENSHOT_DIRECTORY || 'docs/evidence/screenshots/lab06-stage3');
const proof = { client: 'Chrome / Playwright', profile: 'Development', logScenarios: [], advanced: {} };
let phase = 'startup';
const sensitive = new Set([process.env.SeedUsers__Password, 'WrongStudyPassword-1!', 'LOG_BODY_SENTINEL_9e261f']);
const traces = {};

async function call(context, method, route, data, token, scenario) {
  const headers = {};
  if (token) headers[header] = token;
  if (scenario) {
    traces[scenario] = crypto.randomBytes(16).toString('hex');
    headers.traceparent = `00-${traces[scenario]}-${crypto.randomBytes(8).toString('hex')}-01`;
  }
  const response = await context.request.fetch(base + route, { method, data, headers });
  for (const entry of await context.cookies(base)) sensitive.add(entry.value);
  return response;
}
async function login(context, name, scenario) {
  const response = await call(context, 'POST', '/api/auth/login',
    { userName: name, password: process.env.SeedUsers__Password }, null, scenario);
  assert.equal(response.status(), 204);
}
async function token(context) {
  const response = await call(context, 'GET', '/api/auth/csrf');
  assert.equal(response.status(), 200);
  const data = await response.json(); sensitive.add(data.requestToken); return data.requestToken;
}
async function status(context, expected) {
  assert.equal((await call(context, 'GET', '/api/me')).status(), expected);
}
function scenario(name, response, extra = {}) {
  proof.logScenarios.push({ name, traceId: traces[name], status: response.status(), ...extra });
}

(async () => {
  fs.mkdirSync(screenshots, { recursive: true });
  const browser = await chromium.launch({ channel: 'chrome', headless: true });
  const contexts = [];
  async function context() { const item = await browser.newContext({ viewport: { width: 1440, height: 1080 } }); contexts.push(item); return item; }
  try {
    phase = 'six-log-scenarios';
    const alice = await context(), alice2 = await context(), bob = await context(), analyst = await context();
    await login(alice, 'alice', 'successful-login');
    proof.logScenarios.push({ name: 'successful-login', traceId: traces['successful-login'], status: 204 });
    await login(alice2, 'alice'); await login(bob, 'bob'); await login(analyst, 'morgan');
    const failed = await call(await context(), 'POST', '/api/auth/login',
      { userName: 'alice', password: 'WrongStudyPassword-1!' }, null, 'failed-login');
    assert.equal(failed.status(), 401); scenario('failed-login', failed);
    const aliceToken = await token(alice), analystToken = await token(analyst);
    const forbiddenResource = '/api/incidents/20000000-0000-0000-0000-000000000002';
    const denied = await call(alice, 'PUT', forbiddenResource,
      { title: 'Rejected foreign update', description: 'LOG_BODY_SENTINEL_9e261f' }, aliceToken, 'denied-protected-action');
    assert.equal(denied.status(), 404);
    const bobState = await (await call(bob, 'GET', forbiddenResource)).json();
    assert.notEqual(bobState.title, 'Rejected foreign update');
    scenario('denied-protected-action', denied, { unchanged: true });
    const invalid = await call(alice, 'POST', '/api/incidents', {
      title: '', description: 'LOG_BODY_SENTINEL_9e261f', severity: 'Low', occurredAtUtc: new Date().toISOString()
    }, aliceToken, 'validation-error');
    assert.equal(invalid.status(), 400); scenario('validation-error', invalid);
    const before = await (await call(analyst, 'GET', incident)).text();
    const reporterDenied = await call(alice, 'POST', incident + '/triage', undefined, aliceToken, 'privileged-transition-denied');
    assert.equal(reporterDenied.status(), 403);
    assert.equal(await (await call(analyst, 'GET', incident)).text(), before);
    const allowed = await call(analyst, 'POST', incident + '/triage', undefined, analystToken, 'privileged-transition-allowed');
    assert.equal(allowed.status(), 204);
    const after = await (await call(analyst, 'GET', incident)).json();
    assert.equal(after.status, 'Triaged');
    scenario('privileged-transition-denied', reporterDenied, { unchanged: true });
    scenario('privileged-transition-allowed', allowed, { canonicalStatus: 'Triaged' });

    phase = 'advanced-browser';
    const page = await alice.newPage();
    const errors = [], violations = [];
    page.on('pageerror', () => errors.push('pageerror'));
    await page.exposeFunction('reportCsp', value => violations.push(value));
    await page.addInitScript(() => document.addEventListener('securitypolicyviolation', event => window.reportCsp(event.effectiveDirective)));
    await page.goto(base + '/auth-lab.html');
    await page.waitForFunction(() => document.querySelector('#profile').textContent.includes('alice'));
    await page.screenshot({ path: path.join(screenshots, '01-alice-before-revocation.png'), fullPage: true });
    const oldCookies = (await alice.cookies(base)).map(item => `${item.name}=${item.value}`).join('; ');
    const replay = await context();
    await replay.setExtraHTTPHeaders({ Cookie: oldCookies });
    await status(alice, 200); await status(alice2, 200); await status(bob, 200); await status(replay, 200);
    for (const invalidToken of [undefined, 'invalid-study-token']) {
      const rejected = await call(alice, 'POST', revokePath, { currentPassword: process.env.SeedUsers__Password }, invalidToken);
      assert.equal(rejected.status(), 400); await status(alice2, 200);
    }
    const wrongPassword = await call(alice, 'POST', revokePath, { currentPassword: 'WrongStudyPassword-1!' }, aliceToken);
    assert.equal(wrongPassword.status(), 403); await status(alice, 200); await status(alice2, 200);
    await page.locator('#revoke-sessions-form input').fill(process.env.SeedUsers__Password);
    const pending = page.waitForResponse(response => response.url() === base + revokePath && response.request().method() === 'POST');
    await page.locator('#revoke-sessions-form button').click();
    const response = await pending;
    assert.equal(response.status(), 204);
    assert.ok((await response.request().allHeaders())[header.toLowerCase()]);
    await page.waitForFunction(() => document.querySelector('#message').textContent.includes('Усі ваші сеанси завершено'));
    assert.equal(await page.locator('#revoke-sessions-form input').inputValue(), '');
    await status(alice, 401); await status(alice2, 401); await status(replay, 401); await status(bob, 200);
    await page.screenshot({ path: path.join(screenshots, '02-all-alice-sessions-revoked.png'), fullPage: true });
    await page.locator('#login-form input[name=userName]').fill('alice');
    await page.locator('#login-form input[name=password]').fill(process.env.SeedUsers__Password);
    await page.locator('#login-form button').click();
    await page.waitForFunction(() => document.querySelector('#profile').textContent.includes('alice'));
    const stale = await call(alice, 'POST', '/api/auth/logout', undefined, aliceToken);
    assert.equal(stale.status(), 400); await status(alice, 200);
    const storage = await page.evaluate(() => ({ local: localStorage.length, session: sessionStorage.length }));
    assert.deepEqual(storage, { local: 0, session: 0 });
    assert.equal(errors.length, 0); assert.equal(violations.length, 0);
    await page.screenshot({ path: path.join(screenshots, '03-alice-new-login.png'), fullPage: true });
    proof.advanced = { initial: 'Alice 2 x 200, Bob 200, replay 200', missingCsrf: 400, invalidCsrf: 400,
      wrongPassword: 403, unchangedAfterDenials: true, revoke: 204, csrfHeaderPresent: true,
      aliceSessions: '2 x 401', replay: 401, bob: 200, newLogin: 204, oldAntiforgery: 400,
      passwordFieldCleared: true, storage, pageErrors: errors.length, cspViolations: violations.length,
      screenshots: ['01-alice-before-revocation.png', '02-all-alice-sessions-revoked.png', '03-alice-new-login.png'] };

    // Raw values remain in this ignored file only until the Python driver scans the original log.
    // It is removed by the driver in finally. Never send this file to the report.
    fs.writeFileSync(path.resolve(process.env.LAB06_RUNTIME_VALUES_PATH || 'tmp/lab06/stage3/runtime-sensitive-values.json'), JSON.stringify([...sensitive].filter(Boolean)));
    process.stdout.write(JSON.stringify(proof));
  } finally {
    for (const item of contexts) await item.close();
    await browser.close();
  }
})().catch(error => {
  process.stderr.write('Stage 3 browser failure at ' + phase + ': ' + error.name + ' (values omitted).\n');
  process.exitCode = 1;
});
