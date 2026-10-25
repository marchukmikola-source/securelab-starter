# Докази безпеки браузера (DEL-01)

Заявлений рівень: «Відмінно». Рівні накопичувальні; повні критерії й маршрут — на початку практичної частини методички. Заповнюються всі розділи обраного рівня й попередніх рівнів. У цьому revision незбережені browser/terminal кадри наведено як required recapture, а не як виконані докази. Паролі, cookie/token values та export browser storage не записуються.

## Стенд і Git-стан (Для всіх)

ОС: Windows. Browser: Google Chrome 151. API origin: `http://localhost:5080`. Probe origins: `http://localhost:4173` і `http://localhost:4174`.

Receipt `.scaffolds/lab-05.json`: `release=lab-05-start-v1`, `base_commit=16061b56d5d1412e20fdc71993481a8cf2565b42`, `entry_parent=16061b56d5d1412e20fdc71993481a8cf2565b42`. Vulnerable commit: `7c49c5f549112866536f4eee90959b8f4b3f0312` (`lab5: install scaffold lab-05-start-v1 (vulnerable state)`). Єдиний fixed code commit у lineage тегу: `54da9a8e9048b342df1c2065e14c1f4b6c4bc6d2`; він об’єднує safe DOM rendering, CORS і CSP. Другий і останній commit містить report/evidence та позначений annotated tag `v0.5.0`; його full SHA відтворюється командою `git show --no-patch v0.5.0`. Публічна гілка `lab/5-browser-xss` і тег містять лише fixed-стан; commit з vulnerable state не є їхнім предком. Локальний `lab05.bundle` лишається окремим контрольованим навчальним артефактом. Відкритий remote для vulnerable history не використовується.

SDK policy у `global.json`: stable `10.0.100`, `rollForward: latestFeature`, `allowPrerelease: false`. Під час перевірки `dotnet --version` повернув `10.0.402`; installed SDK також містять `8.0.206`, `9.0.103`, `10.0.303` і `10.0.402`.

Механізм сеансу (Application → Storage → Cookies → `http://localhost:5080`): cookie `.AspNetCore.Identity.Application`; Domain `localhost` (host-only); Path `/`; HttpOnly; SameSite=Lax; Secure=false для локального HTTP. Значення cookie не зберігається.

## Гіпотеза й REG-XSS-01 (Для всіх)

Карта `Description` і другий flow `IncidentComment.Text`: [`docs/source-to-sink.md`](source-to-sink.md). Гіпотеза: значення з `textarea[name="description"]` у `/browser-lab.html` надсилається як JSON field `description`, зберігається як `Incident.Description` у `incidents.description`, повертається як `IncidentDetailsResponse.description` і у vulnerable client передається у `#description.innerHTML` як HTML context. Отже, за наявності HTML-подібних символів браузер може інтерпретувати їх як markup, а не як текст. Уже наявні server/header і fixed DOM докази відокремлено від необхідних screenshot capture у [`evidence/lab05-browser-capture-checklist.md`](evidence/lab05-browser-capture-checklist.md). Значення cookie та паролі не фіксуються.

Історичний vulnerable-сценарій: `dd114e4c-bc28-4b00-91f0-a2946f3ea193` Alice створила через `/browser-lab.html` в ізольованому локальному vulnerable worktree. Робочі нотатки описують POST `201`, наступний details GET `200`, створений `<img>`, виконання marker у сесіях Alice і Morgan та `404` для Bob. Сирі кадри POST/GET/Elements для цього Guid не входять до поданого image set. Цей абзац є контекстом сценарію, а не незалежним доказом приймання. CAP-01 і CAP-02 у capture checklist задають точне повторне знімання без запису cookie values чи паролів.

Після локального reset створено новий Description marker-record для fixed retest: `47e88681-dd0e-49f9-ae70-56fcb1cb57fa`. Його не слід видаляти або повторно reset-ити до завершення fixed DOM та HTTP перевірок.

| Спостереження | До fix | Після fix | Посилання на доказ |
|---|---|---|---|
| Значення в БД/API | Historical note only; raw vulnerable POST/GET capture absent | `api-render-integrity.js` requires final API Description to remain stable across load and equal rendered literal text | Final Console helper; direct API response during helper execution |
| DOM основного Description | `#description` містив `<img>` | Marker відображено повним буквальним рядком; дочірнього `<img>` немає | Fixed UI та DOM test `PASS` |
| Дія marker | Historical note only; raw vulnerable Elements frame absent | `null` for fixed Description and for every checked public comment | `description-dom.js` and `comments-dom.js` |
| Апостроф/лапки, `<`, Unicode, HTML-like рядок | HTML-like marker був інтерпретований | Позитивна регресія використовує literal `</>`, обидва види лапок і українські `ї`, `є`, `ґ`; значення має лишитися text node | [`resources/copyable/normal-text-regression.js`](../resources/copyable/normal-text-regression.js) |
| Довжина за власними правилами ЛР 2 | Наявне серверне `maximum 4000` rule не є HTML encoding | Той самий browser regression створює рівно 4000 символів і перевіряє точне значення, text node та відсутність marker | `normal-text-regression.js`; endpoint validation `Description.Length > 4000` |
| Вікно Morgan: GET і перевірка marker; контроль Bob | Morgan GET `200` виконав marker; Bob GET `404`, marker `null` | Fixed policy відображення є однаковою для доступних users; Bob не має доступу до Alice resource | Independent-session/negative-control proof |

Finding XSS-01. Актив: `Incident.Description` і public `IncidentComment.Text`, що повертаються через existing details endpoint. Передумови: authenticated user має право створити власний incident або public comment already exists in seed. Першопричина: vulnerable browser client передавав server-provided string у `innerHTML`, тому HTML parser міг утворити element. Виправлення: один helper `renderPlainText` створює text node і замінює children для title, description і кожного comment; server contract не змінювався. Fixed retest: Description marker для `47e88681-dd0e-49f9-ae70-56fcb1cb57fa` видимий буквально, `description-dom.js` завершився `PASS: persisted description rendered as plain text`; [`comments-dom.js`](../resources/copyable/comments-dom.js) після двох `load()` перевіряє кожен `comments[index].text` відносно `paragraph.textContent`, вимагає `childElementCount === 0` і збереження marker `null`. Vulnerable visual comment evidence лишається CAP-03. Залишковий ризик: текстовий sink не дорівнює attribute/URL/JavaScript context; URL слід перевіряти окремо.

## CORS і REG-CORS-01 (Для всіх)

Прогноз (Етап 3, крок 1), заповнити до зміни policy:

| Сценарій | Чи доходить request до API? | Чи може JavaScript прочитати response? | Чому |
|---|---|---|---|
| same-origin 5080 → API | так | так | same-origin; CORS не потрібен |
| simple GET 4173 → API | так | ні до policy | browser надішле GET, але API не поверне `Access-Control-Allow-Origin` |
| simple GET 4174 → API | так | ні до policy і після allowlist 4173 | origin відрізняється портом і не має бути в allowlist |
| curl/.http → API | так | не застосовується | це direct HTTP client, тому browser SOP/CORS до нього не застосовується |
| preflighted 4173 → API | OPTIONS доходить; actual GET не має бути надісланий без valid preflight | ні до policy | non-safelisted `X-Lab-Cors-Probe` запускає preflight |

Probes запускалися окремими PowerShell-вікнами з каталогів без application files:

```powershell
py -3 -m http.server 4173
py -3 -m http.server 4174
```

Policy — лише Development, один exact origin `4173`; `4174` — контроль. Для credentialed browser scenario policy містить `AllowCredentials()` і ніколи не повертає wildcard origin.

| Клієнт / простий запит | До policy | Fixed state | Status, ACAO, Console / доказ |
|---|---|---|---|
| Same-origin 5080 | CORS не потрібен | main/browser client працює з same-origin API | SOP/CORS не бере участі |
| Allowed 4173 | Console: `TypeError: Failed to fetch`; historical Network observation says actual GET `/health` reached API with `200`, but raw initial frame is not retained | Console observation after fix: `credentials: "include"` read list with `status: 200`, `type: "cors"`, `body: Array(4)` | Fixed policy emits exact ACAO/ACAC; CAP-04/CAP-05 must show Network request `Origin`/Cookie presence and response headers |
| Disallowed 4174 | Console: `TypeError: Failed to fetch`; historical Network observation says actual GET `/health` reached API with `200`, but raw initial frame is not retained | Console: response to preflight blocked; `net::ERR_FAILED`, `TypeError: Failed to fetch` | In the final preflight response no `Access-Control-Allow-Origin` exists; 4174 is not in allowlist |
| Direct HTTP / curl | Н/З | Обидва GET дали `HTTP/1.1 200 OK`; з Origin 4173 є `Access-Control-Allow-Origin: http://localhost:4173`, з Origin 4174 цього header немає | Direct HTTP не виконує SOP; саме браузер не дає script прочитати відповідь для 4174 |

REG-CORS-01: Console observations show the allowed credentialed scenario for `4173`, denied scenario for `4174`, and readable `401` after logout. Direct HTTP is retained verbatim: for `Origin: http://localhost:4173`, `/health` is `HTTP/1.1 200 OK` with exact ACAO, ACAC, `nosniff`, `Referrer-Policy`, and CSP; for `Origin: http://localhost:4174`, it is also `200` but has no `Access-Control-*`. Final preflight 25.10 for `4173` is `204 No Content` with exact ACAO, `Access-Control-Allow-Methods: GET`, `Access-Control-Allow-Headers: X-Lab-Cors-Probe`, and ACAC; control preflight `4174` is `204` with no `Access-Control-Allow-*`. This proves server headers, not a complete browser trace. CAP-04/CAP-05 must record allowed `OPTIONS` → GET, Request Headers with `Origin` and Cookie presence, and Response Headers with ACAO/ACAC. CORS does not stop direct HTTP: SOP is applied by a browser, not by API or `curl`. Full raw headers are in [`lab05-cors-direct-headers.txt`](evidence/lab05-cors-direct-headers.txt).

## Додатково для Добре та Відмінно

Другий flow `IncidentComment.Text`: public seed comment з Guid `30000000-0000-0000-0000-000000000005` містить той самий harmless local marker із `resources/lab05-marker.txt`, має `IsInternal=false` і автора Morgan. Source review identifies the pre-fix sink as `innerHTML`, but a vulnerable visual comment frame is not retained; it is CAP-03. Final [`comments-dom.js`](../resources/copyable/comments-dom.js) calls `load()` twice and validates every API comment value against its corresponding paragraph, zero element children, and marker `null`. Єдиний helper `renderPlainText` у [`browser-lab.js`](../src/SecureLab.Api/Client/browser-lab.js) використовується для title, Description і кожного `comment.text`.

Preflight із 4173 і 4174: exact final policy має origin `http://localhost:4173`, method `GET`, header `X-Lab-Cors-Probe` і `AllowCredentials()` лише у Development. Попередні Console-досліди встановлюють browser outcomes: `4173` може прочитати authenticated list після дозволу credentials; `4174` не може; після logout `4173` може прочитати `401` Problem Details. Поточні direct headers доводять дозволені/відхилені server response headers. Подані images ще не показують дозволений Network-рядок `OPTIONS` або request headers Cookie/Origin; CAP-04/CAP-05 не дають перебільшувати ці observations. CORS не є authentication/authorization і не обходить server-side authorization. Стислий review — це сам розділ DEL-03.

| Директива CSP | Фактичні ресурси застосунку | Обране джерело / причина |
|---|---|---|
| default-src | local HTML, `app.js`, `browser-lab.js`, CSS, same-origin API fetch | `'self'` як мінімальна база: блокує сторонні ресурси за замовчуванням |
| script-src | лише local deferred/module scripts | окремо не потрібен: успадковує `'self'` з `default-src` |
| style-src | `/styles.css` з того самого origin | окремо не потрібен: успадковує `'self'` |
| connect-src | same-origin `/api/*`, `/health` | окремо не потрібен: успадковує `'self'` |
| img-src | локальні зображення відсутні; контрольний зовнішній `4173/x.png` | окремо не потрібен: успадковує `'self'`; зовнішній image blocked |
| font-src | custom fonts відсутні | окремо не потрібен: успадковує `'self'` |
| frame-ancestors | сторінки SecureLab не мають бути embedded | `'none'` забороняє framing |

Місце зміни middleware: `Program.cs`, middleware security headers перед routing/static files; Development `/scalar` виключено, щоб не ламати development API reference. Report-only: document `200` мав `Content-Security-Policy-Report-Only: default-src 'self'; frame-ancestors 'none'`. Кероване порушення `new Image().src = "http://localhost:4173/x.png"` на локальній сторінці дало Console violation, де браузер повідомив `policy is report-only, so the violation has been logged but no further action has been taken`. Enforcement: document `/browser-lab.html` повернув `Content-Security-Policy: default-src 'self'; frame-ancestors 'none'`; та сама probe команда дала Console `The action has been blocked`. Console proof is retained, but the Network blocked-resource frame remains CAP-06. Main client, `auth-lab.html` і `browser-lab.html` потребують чистих Console frames CAP-07. Для «Добре» докази report-only не обов’язкові.

| Header / control | Фактичне значення | Ризик і межа захисту / policy rationale |
|---|---|---|
| X-Content-Type-Options | `nosniff` | не дає browser визначати інший MIME type замість наданого сервером |
| Referrer-Policy | `no-referrer` | не передає URL сторінки зовнішньому destination; training flow не має потрібної cross-site navigation/analytics; таке рішення переглядається, якщо потреба з’явиться |
| frame-ancestors | CSP `frame-ancestors 'none'` | browser не дозволяє помістити сторінки SecureLab у frame; це сучасний anti-clickjacking control, тому окремий `X-Frame-Options` не потрібен |

## Додатково для Відмінно

DOM-тест: [`resources/copyable/description-dom.js`](../resources/copyable/description-dom.js) у Chrome Console, record `47e88681-dd0e-49f9-ae70-56fcb1cb57fa`. Isolated local worktree на vulnerable commit `7c49c5f` produced the expected negative result `Uncaught Error: Text changed`; after returning to fixed state in lineage `v0.5.0` (`54da9a8`, combining XSS/CORS/CSP controls), the same test ended `PASS: persisted description rendered as plain text`. [`comments-dom.js`](../resources/copyable/comments-dom.js) is the structured two-load comment regression and [`api-render-integrity.js`](../resources/copyable/api-render-integrity.js) checks response/DOM equality without creating HTML. CSP report-only → enforcement: headers and controlled `new Image()` Console violations exist, while CAP-06 records the missing Network frame. [`safe-url.js`](../resources/copyable/safe-url.js): `https` and local `http` were accepted; `javascript:` (including mixed-case/leading whitespace) and malformed URL returned `null`; `onclick` remained `null`. Text, HTML attribute, URL and JavaScript are different contexts; a future third-party script requires separate source, SRI/allowance, and review — `'self'` does not make a third-party script safe.

Додаткових DEL, навчальних демо або нового журналу не подавати. Перед поданням повторити чекліст для обраного накопичувального рівня.

## Фінальна локальна перевірка

Після local reset 2026-10-26 команда `dotnet test tests/SecureLab.Api.Tests/SecureLab.Api.Tests.csproj --configuration Release --no-restore --logger "console;verbosity=minimal" --logger "trx;LogFileName=lab05-final.trx"` завершилася з `Total: 101`, `Passed: 101`, `Failed: 0`, `Skipped: 0`. Точний console output збережено у [`lab05-final-test-output.txt`](evidence/lab05-final-test-output.txt); відповідний TRX — у [`lab05-final.trx`](evidence/lab05-final.trx). Публічні `lab/5-browser-xss` і annotated tag `v0.5.0` містять fixed code; `lab05.bundle` перевірено окремо через `git bundle verify` та `git bundle list-heads` і він навмисно не містить private vulnerable commit.
