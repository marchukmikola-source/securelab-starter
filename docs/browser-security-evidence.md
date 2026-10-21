# Докази безпеки браузера (DEL-01)

Рівень: «Відмінно». Рівні накопичувальні; повні критерії й маршрут — на початку практичної частини методички. Заповнюються всі розділи обраного рівня й попередніх рівнів. Паролі, cookie/token values та export browser storage не записуються.

## Стенд і Git-стан (Для всіх)

ОС: Windows. Browser: Google Chrome 151. API origin: `http://localhost:5080`. Probe origins: `http://localhost:4173` і `http://localhost:4174`.

Receipt `.scaffolds/lab-05.json`: `release=lab-05-start-v1`, `base_commit=16061b56d5d1412e20fdc71993481a8cf2565b42`, `entry_parent=16061b56d5d1412e20fdc71993481a8cf2565b42`. Vulnerable commit: `7c49c5f549112866536f4eee90959b8f4b3f0312` (`lab5: install scaffold lab-05-start-v1 (vulnerable state)`). Fixed hash і тег `v0.5.0` буде внесено після server-side fix і ретесту. Робоча гілка: `lab/5-browser-xss`; передавання: commit fixed state у GitHub після перевірки.

Механізм сеансу (Application → Storage → Cookies → `http://localhost:5080`): cookie `.AspNetCore.Identity.Application`; Domain `localhost` (host-only); Path `/`; HttpOnly; SameSite=Lax; Secure=false для локального HTTP. Значення cookie не зберігається.

## Гіпотеза й REG-XSS-01 (Для всіх)

Карта `Description`: … Гіпотеза source → storage → response → sink/context: … Передумови, локальний користувач, Guid запису, marker із `resources/lab05-marker.txt`, команди reset/start і create/read: …

| Спостереження | До fix | Після fix | Посилання на доказ |
|---|---|---|---|
| Значення в БД/API | | | |
| DOM основного Description | | | |
| Дія marker | | | |
| Апостроф/лапки, 5 < 7, Unicode, HTML-like рядок | | | |
| Довжина за власними правилами ЛР 2 | | | |
| Вікно Morgan: GET і перевірка marker; контроль Bob | | | |

Finding: актив; передумови; першопричина; safe DOM diff; retest; залишковий ризик: … Повторювана REG-XSS-01, негативний контроль і очікування: …

## CORS і REG-CORS-01 (Для всіх)

Прогноз (Етап 3, крок 1), заповнити до зміни policy:

| Сценарій | Чи доходить request до API? | Чи може JavaScript прочитати response? | Чому |
|---|---|---|---|
| same-origin 5080 → API | | | |
| simple GET 4173 → API | | | |
| simple GET 4174 → API | | | |
| curl/.http → API | | не застосовується | |
| preflighted 4173 → API («Добре / Відмінно») | | | |

Команди запуску probes: … Policy — лише Development, один exact origin 4173; 4174 — контроль. Для «Задовільно» без `AllowCredentials()`.

| Клієнт / простий запит | До policy | Fixed state | Status, ACAO, Console / доказ |
|---|---|---|---|
| Same-origin 5080 | | | |
| Allowed 4173 | | | |
| Disallowed 4174 | | | |
| Direct HTTP / curl | | | |

REG-CORS-01: browser evidence і дві actual HTTP-відповіді для Origin 4173/4174: … Перевірка порядку через читання 401 без cross-origin cookie: … Пояснення різниці browser/direct HTTP: …

## Додатково для Добре та Відмінно

Другий flow `IncidentComment.Text`: … Public seed comment Guid/текст, похідні counts за потреби, DOM до/після: … Єдиний safe helper і виклики для обох полів: …

Preflight з 4173 і 4174, OPTIONS → GET / blocked GET, exact origin/header/method: … Cookie-дослід 4173/4174/без `AllowCredentials()`/401 без входу: … Кінцевий `AllowCredentials()` — лише Development policy для 4173. Review XSS/CORS/CSRF/authorization — посилання на DEL-03: …

| Директива CSP | Фактичні ресурси застосунку | Обране джерело / причина |
|---|---|---|
| default-src | | |
| script-src | | |
| style-src | | |
| connect-src | | |
| img-src | | |
| frame-ancestors | | |

Місце зміни middleware: … Enforcement: document 200 і фактичний CSP header; три сторінки flow; кероване порушення `new Image()` до 4173 — результат: … Для «Добре» докази report-only не обов’язкові.

| Header / control | Фактичне значення | Ризик і межа захисту / policy rationale |
|---|---|---|
| X-Content-Type-Options | | |
| Referrer-Policy | | |
| frame-ancestors | | |

## Додатково для Відмінно

DOM-тест: файл/команда, browser, vulnerable commit і FAIL, fixed commit і PASS: … Comments, повторний render без дублювання та позитивні рядки: … CSP report-only → enforcement: фактичні headers, flow і кероване порушення в обох режимах: … `safe-url.js` / атрибут: … Пояснення text/attribute/URL/JavaScript та ризик third-party scripts — посилання на DEL-03: …

Додаткових DEL, навчальних демо або нового журналу не подавати. Перед поданням повторити чекліст для обраного накопичувального рівня.
