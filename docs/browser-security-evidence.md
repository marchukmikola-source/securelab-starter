# Докази безпеки браузера (DEL-01)

Рівень: «Відмінно». Рівні накопичувальні; повні критерії й маршрут — на початку практичної частини методички. Заповнюються всі розділи обраного рівня й попередніх рівнів. Паролі, cookie/token values та export browser storage не записуються.

## Стенд і Git-стан (Для всіх)

ОС: Windows. Browser: Google Chrome 151. API origin: `http://localhost:5080`. Probe origins: `http://localhost:4173` і `http://localhost:4174`.

Receipt `.scaffolds/lab-05.json`: `release=lab-05-start-v1`, `base_commit=16061b56d5d1412e20fdc71993481a8cf2565b42`, `entry_parent=16061b56d5d1412e20fdc71993481a8cf2565b42`. Vulnerable commit: `7c49c5f549112866536f4eee90959b8f4b3f0312` (`lab5: install scaffold lab-05-start-v1 (vulnerable state)`). Перший fixed XSS commit: `ee57982` (`lab5: render incident text safely`). Кінцевий fixed hash і тег `v0.5.0` буде внесено після CORS/CSP fix і ретесту. Робоча гілка: `lab/5-browser-xss`; передавання: commit fixed state у GitHub після перевірки.

Механізм сеансу (Application → Storage → Cookies → `http://localhost:5080`): cookie `.AspNetCore.Identity.Application`; Domain `localhost` (host-only); Path `/`; HttpOnly; SameSite=Lax; Secure=false для локального HTTP. Значення cookie не зберігається.

## Гіпотеза й REG-XSS-01 (Для всіх)

Карта `Description` і другий flow `IncidentComment.Text`: [`docs/source-to-sink.md`](source-to-sink.md). Гіпотеза: значення з `textarea[name="description"]` у `/browser-lab.html` надсилається як JSON field `description`, зберігається як `Incident.Description` у `incidents.description`, повертається як `IncidentDetailsResponse.description` і передається у `#description.innerHTML` як HTML context. Отже, за наявності HTML-подібних символів браузер може інтерпретувати їх як markup, а не як текст. Передумови PoC: локальний вхід Alice, створений нею test incident, marker виключно з `resources/lab05-marker.txt`, Network-доказ POST і подальшого GET, Elements-доказ для `#description` та `#lab05-marker-target`. Значення cookie та паролі не фіксуються.

Vulnerable marker record: `dd114e4c-bc28-4b00-91f0-a2946f3ea193`, створений Alice через `/browser-lab.html`. POST `/api/incidents` повернув `201`; наступний GET details повернув `200` і той самий marker у response JSON. У Elements `#description` містив створений `<img>`, а `#lab05-marker-target` одержав `data-lab05-marker="executed"`; browser виконав локальний запит до `/x`. У незалежній сесії Morgan той самий GET повернув `200`, повторно утворив `<img>` і встановив marker у `executed`. Bob для того самого Guid одержав `404`, не одержав response JSON із description, а marker у новій сесії лишився `null`. Це є controlled local stored-XSS PoC: Alice створила запис, сервер його зберіг, а Morgan відобразив його окремо від сесії Alice; authorization ЛР 04 зберегла ізоляцію Bob.

Після локального reset створено новий Description marker-record для fixed retest: `47e88681-dd0e-49f9-ae70-56fcb1cb57fa`. Його не слід видаляти або повторно reset-ити до завершення fixed DOM та HTTP перевірок.

| Спостереження | До fix | Після fix | Посилання на доказ |
|---|---|---|---|
| Значення в БД/API | POST `201`, а наступний GET `200` повернув marker у `description` для record `dd114e4c-bc28-4b00-91f0-a2946f3ea193` | GET `200` для fixed record `47e88681-dd0e-49f9-ae70-56fcb1cb57fa` зберігає незмінений marker у JSON | Network POST/GET; fixed UI retest |
| DOM основного Description | `#description` містив `<img>` | Marker відображено повним буквальним рядком; дочірнього `<img>` немає | Fixed UI та DOM test `PASS` |
| Дія marker | `data-lab05-marker="executed"` для Alice та незалежної сесії Morgan | `null` для fixed Description і public comments | Console diagnostic |
| Апостроф/лапки, `<`, Unicode, HTML-like рядок | HTML-like marker був інтерпретований | Значення збережено та показано як текстовий вузол | Fixed Description і comments retest |
| Довжина за власними правилами ЛР 2 | Наявне серверне `maxlength`/DTO правило не є HTML encoding | Не змінювалася: safe rendering не послаблює серверну validation | Контракт ЛР 2 лишився чинним |
| Вікно Morgan: GET і перевірка marker; контроль Bob | Morgan GET `200` виконав marker; Bob GET `404`, marker `null` | Fixed policy відображення є однаковою для доступних users; Bob не має доступу до Alice resource | Independent-session/negative-control proof |

Finding XSS-01. Актив: `Incident.Description` і public `IncidentComment.Text`, що повертаються через existing details endpoint. Передумови: authenticated user має право створити власний incident або public comment уже збережений у seed. Першопричина: browser client передавав server-provided string у `innerHTML`, тому HTML parser утворював element та виконував локальний marker. Виправлення: один helper `renderPlainText` створює text node і замінює children для title, description і кожного comment; server contract не змінювався. Retest: Description marker для `47e88681-dd0e-49f9-ae70-56fcb1cb57fa` видимий буквально, `description-dom.js` завершився `PASS: persisted description rendered as plain text`; comments після двох reads дали `firstCount: 2`, `secondCount: 2`, `duplicateFree: true`, `marker: null`. Залишковий ризик: текстовий sink не дорівнює attribute/URL/JavaScript context; URL слід перевіряти окремо.

## CORS і REG-CORS-01 (Для всіх)

Прогноз (Етап 3, крок 1), заповнити до зміни policy:

| Сценарій | Чи доходить request до API? | Чи може JavaScript прочитати response? | Чому |
|---|---|---|---|
| same-origin 5080 → API | так | так | same-origin; CORS не потрібен |
| simple GET 4173 → API | так | ні до policy | browser надішле GET, але API не поверне `Access-Control-Allow-Origin` |
| simple GET 4174 → API | так | ні до policy і після allowlist 4173 | origin відрізняється портом і не має бути в allowlist |
| curl/.http → API | так | не застосовується | це direct HTTP client, тому browser SOP/CORS до нього не застосовується |
| preflighted 4173 → API («Добре / Відмінно») | OPTIONS доходить; actual GET не має бути надісланий без valid preflight | ні до policy | non-safelisted `X-Lab-Cors-Probe` запускає preflight |

Команди запуску probes: … Policy — лише Development, один exact origin 4173; 4174 — контроль. Для «Задовільно» без `AllowCredentials()`.

| Клієнт / простий запит | До policy | Fixed state | Status, ACAO, Console / доказ |
|---|---|---|---|
| Same-origin 5080 | CORS не потрібен | pending | pending |
| Allowed 4173 | Console: `TypeError: Failed to fetch`; Network: actual GET `/health` дійшов до API з `200`, але browser позначив `net::ERR_FAILED` | Preflight `OPTIONS`, потім `GET /health`; Console повернув `status: 200`, `body.status: "ready"` | Fixed policy повертає `Access-Control-Allow-Origin: http://localhost:4173` лише для exact origin |
| Disallowed 4174 | Console: `TypeError: Failed to fetch`; Network: actual GET `/health` дійшов до API з `200`, але browser позначив `net::ERR_FAILED` | Console: response to preflight blocked; `net::ERR_FAILED`, `TypeError: Failed to fetch` | У preflight response немає `Access-Control-Allow-Origin`; 4174 не входить до allowlist |
| Direct HTTP / curl | Н/З | Обидва GET дали `HTTP/1.1 200 OK`; з Origin 4173 є `Access-Control-Allow-Origin: http://localhost:4173`, з Origin 4174 цього header немає | Direct HTTP не виконує SOP; саме браузер не дає script прочитати відповідь для 4174 |

REG-CORS-01: browser evidence і дві actual HTTP-відповіді для Origin 4173/4174: … Перевірка порядку через читання 401 без cross-origin cookie: … Пояснення різниці browser/direct HTTP: …

## Додатково для Добре та Відмінно

Другий flow `IncidentComment.Text`: … Public seed comment Guid/текст, похідні counts за потреби, DOM до/після: … Єдиний safe helper і виклики для обох полів: …

Preflight з 4173 і 4174: до policy обидва origin були blocked; fixed 4173 виконав valid preflight і наступний GET, fixed 4174 лишився blocked. Exact policy: origin `http://localhost:4173`, method `GET`, header `X-Lab-Cors-Probe`. Cookie-дослід до `AllowCredentials()`: із 4173 request дійшов до API та мав Network `200`, але browser заблокував читання: `The value of the 'Access-Control-Allow-Credentials' header ... must be 'true' when the request's credentials mode is 'include'`. Кінцевий `AllowCredentials()` — лише Development policy для 4173. Після ретесту Alice з 4173 прочитала authenticated list: `status: 200`, `type: "cors"`, body Array(4). Та сама credential-mode спроба з 4174 отримала Network `200`, але Console показала відсутній `Access-Control-Allow-Origin` і `TypeError`; JavaScript не прочитав список. Після logout Alice запит із 4173 повернув читабельний `status: 401`, `type: "cors"` і Problem Details. CORS не є authentication/authorization і не обходить server-side authorization. Review XSS/CORS/CSRF/authorization — посилання на DEL-03: …

| Директива CSP | Фактичні ресурси застосунку | Обране джерело / причина |
|---|---|---|
| default-src | local HTML, `app.js`, `browser-lab.js`, CSS, same-origin API fetch | `'self'` як мінімальна база: блокує сторонні ресурси за замовчуванням |
| script-src | лише local deferred/module scripts | окремо не потрібен: успадковує `'self'` з `default-src` |
| style-src | `/styles.css` з того самого origin | окремо не потрібен: успадковує `'self'` |
| connect-src | same-origin `/api/*`, `/health` | окремо не потрібен: успадковує `'self'` |
| img-src | локальні зображення відсутні; контрольний зовнішній `4173/x.png` | окремо не потрібен: успадковує `'self'`; зовнішній image blocked |
| frame-ancestors | сторінки SecureLab не мають бути embedded | `'none'` забороняє framing |

Місце зміни middleware: `Program.cs`, middleware security headers перед routing/static files; Development `/scalar` виключено, щоб не ламати development API reference. Report-only: document `200` мав `Content-Security-Policy-Report-Only: default-src 'self'; frame-ancestors 'none'`. Кероване порушення `new Image().src = "http://localhost:4173/x.png"` на локальній сторінці дало Console violation, де браузер повідомив `policy is report-only, so the violation has been logged but no further action has been taken`. Enforcement: document `/browser-lab.html` повернув `Content-Security-Policy: default-src 'self'; frame-ancestors 'none'`; та сама probe команда дала Console `The action has been blocked`. Main client, `auth-lab.html` і `browser-lab.html` завантажилися після enforcement; fixed Description показав marker буквальним текстом. Для «Добре» докази report-only не обов’язкові.

| Header / control | Фактичне значення | Ризик і межа захисту / policy rationale |
|---|---|---|
| X-Content-Type-Options | `nosniff` | не дає browser визначати інший MIME type замість наданого сервером |
| Referrer-Policy | `no-referrer` | не передає URL сторінки зовнішньому destination; не замінює CSP чи authorization |
| frame-ancestors | CSP `frame-ancestors 'none'` | browser не дозволяє помістити сторінки SecureLab у frame; це anti-clickjacking control |

## Додатково для Відмінно

DOM-тест: `resources/copyable/description-dom.js` у Chrome Console, record `47e88681-dd0e-49f9-ae70-56fcb1cb57fa`. Isolated local worktree на vulnerable commit `7c49c5f` повернув `GET: 200`, створив `<img>` і завершився `Uncaught Error: Text changed`; це формальний negative result для dangerous `innerHTML`. Після повернення на fixed state (`ee57982` і наступні fixed commits) той самий тест завершився `PASS: persisted description rendered as plain text`. Comments: two reads дали `firstCount: 2`, `secondCount: 2`, `duplicateFree: true`, `marker: null`. CSP report-only → enforcement: фактичні headers і кероване порушення `new Image()` зафіксовано в обох режимах. `safe-url.js`: `https` та local `http` були прийняті; `javascript:` (включно з mixed-case/leading whitespace) і malformed URL повернули `null`; `onclick` лишився `null`. Text, HTML attribute, URL та JavaScript є різними contexts; якщо в майбутньому з’явиться third-party script, потрібні окреме рішення про source, SRI/дозвіл та review — `'self'` не робить сторонній script безпечним.

Додаткових DEL, навчальних демо або нового журналу не подавати. Перед поданням повторити чекліст для обраного накопичувального рівня.

## Фінальна локальна перевірка

Після final CSP state виконано `dotnet test tests/SecureLab.Api.Tests/SecureLab.Api.Tests.csproj --configuration Release --no-build --no-restore --logger "console;verbosity=minimal"`. Результат: `Total: 99`, `Passed: 99`, `Failed: 0`, `Skipped: 0`; test run succeeded за 13.9 s. Перед тестами застосовано локальний reset database, тому тимчасові marker records не вплинули на fixture assertions. Локальний `lab05.bundle` перевірено: complete history, refs `lab/5-browser-xss` та annotated tag `v0.5.0` присутні.
