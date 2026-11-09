# F-01. Відсутня standard antiforgery validation на cookie mutations

**Статус:** Fixed
**Актив:** Цілісність Incident, привілейованого переходу та cookie-сеансу.
**Компонент:** Cookie-authenticated POST/PUT/DELETE endpoints та browser fetch helper.
**Пріоритет:** P2

## Передумови і межі огляду

Review-start `ee18ff4`, власний локальний baseline 2-A, Development, штучні Alice/
Bob/Morgan, відомий seed. До етапу 2 cookie mutations не викликали IAntiforgery.
Доказ початкового стану: source цього commit та успішні state-changing тести
попереднього прогону [106/106](../evidence/lab06-stage1.json); CookieClient тоді
отримував лише authentication cookie. Реалізаційний diff етапу 2 додає control.

## Відтворення

1. У початковому source перевірити Program.cs, mutations та CookieClient:
   AddAntiforgery/ValidateRequestAsync і request token відсутні.
2. Увійти Alice на власному стенді, прочитати її SafeTextIncident.
3. Надіслати дозволений owner PUT з cookie та без request token. Початкові
   integration tests підтверджували успішну mutation без такого token.
4. На виправленому стані виконати REG-CSRF-01: без token та з invalid token
   отримати 400 і повторним GET підтвердити незмінність; після token issuance
   той самий PUT дає 204 та очікувану зміну.

Для локального повтору fixed retest: `python scripts/verify_lab06_stage2.py`
або `tests/http/lab-06-csrf.http`. Відтворення на сторонніх hosts не входить у scope.

## Вплив і ймовірність

**Статус перевірки:** первинний gap оцінено за кодом та попереднім test harness;
fixed відмову, незмінність і positive flow спостережено локально.

Сервер не відрізняв cookie mutation з request token від запиту лише з автоматичною
cookie. Для реального cross-origin browser exploitation потрібні також умови
надсилання cookie й проходження content-type/preflight/CORS. Ці передумови не
оголошено гарантовано виконаними: SameSite=Lax, JSON contract та вузький CORS
зменшують деякі paths. P2 — системний gap на п’яти sensitive mutations, який
закриває обов’язковий control; це не заява про доведений зовнішній exploit.

## Першопричина

Authentication/authorization перевіряли principal і ресурс, але не request
token. JSON/DELETE endpoints не отримують automatic form antiforgery validation.
Спільний JS helper додавав credentials, але не мав token lifecycle.

## Виправлення

Standard AddAntiforgery, authenticated same-origin GET /api/auth/csrf,
X-CSRF-TOKEN, один explicit endpoint filter перед mutation на всіх п’яти routes.
Invalid pair → точний 400 problem+json без sensitive details. Helper зберігає
token в пам’яті, підтримує F5/login/logout, не replay-ить POST після відмови.

## Retest

- REG-CSRF-01 пройшов у xUnit та Chrome HTTP context: 400 + unchanged, 400 +
  unchanged, token issuance 200, valid PUT 204 + intended changed state.
- 10 perimeter cases перевіряють missing/invalid tokens на всіх п’яти routes.
- Wrong cookie/principal/stale tokens відхиляються; fresh token дозволяє logout.
## Positive regression

- Existing create/update/delete/triage authorization tests та всі наявні UI
  mutations з valid token пройшли; всього 123/123 tests.

## Доказ

Історичний evidence: [stage2 JSON](../evidence/lab06-stage2.json),
[повний протокол](../lab-06-stage2.md), BrowserHardeningTests, адаптовані existing tests.

Після approved extension perimeter має шість cookie mutations і 12 negative
cases; CP-03 — 135/135. Актуальний повтор: `python scripts/verify_lab06_stage3.py --release`
у чистому checkout. Precise diff: `Program.cs`, `Security/AntiforgeryProtection.cs`,
`IncidentEndpoints`, `Lab02Endpoints`, `Lab03Identity`, `Client/api-fetch.js`
від review-start `ee18ff4` до робочої гілки `lab/6-hardening-review`.

## Залишковий ризик

Same-origin XSS може користуватися token та cookie; antiforgery не замінює safe
DOM/CSP. Login/register не включено до cookie-authorized perimeter: окремі
login-CSRF/account-creation risks описано в scope. Local HTTP не доводить TLS.
Ця checklist finding не зараховується третьою самостійною finding відмінного рівня.
