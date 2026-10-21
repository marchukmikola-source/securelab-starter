# Звіт WEB ЛР 5 — Browser security

Автор: Микола Марчук. Спільний сценарій: 2-A. Рівень: «Відмінно». Стенд: Windows, Google Chrome 151, .NET 10, API `http://localhost:5080`; probe origins `http://localhost:4173` і `http://localhost:4174`.

## DEL-01. Карта flow та browser-security evidence

Карта [`source-to-sink.md`](source-to-sink.md) описує два фактичні flow: `Incident.Description` і public `IncidentComment.Text`. Детальні докази, browser observations, HTTP status та локальні Git refs зібрані у [`browser-security-evidence.md`](browser-security-evidence.md).

### Finding XSS-01: stored markup у Description і comments

**До виправлення.** Alice створила локальний навчальний incident з marker із scaffold. POST повернув `201`, details GET повернув `200` з тим самим рядком. У browser client `#description.innerHTML = current.description` перетворив збережений рядок на `<img>` і встановив `data-lab05-marker="executed"`. Morgan у незалежній сесії міг прочитати доступний record і знову викликати marker; Bob отримав `404`, тому не мав ні response data, ні marker execution.

**Першопричина.** Серверна validation і довжина DTO не визначають, як browser інтерпретує текст. Проблемою був dangerous DOM sink `innerHTML` для data з response.

**Виправлення.** У `browser-lab.js` створено спільний helper `renderPlainText`, який створює text node і замінює children. Він застосований до title, Description і кожного comment:

```javascript
function renderPlainText(element, value) {
  element.replaceChildren(document.createTextNode(value ?? ""));
}
```

**Retest.** На isolated worktree vulnerable commit `7c49c5f` скрипт `description-dom.js` дав `Uncaught Error: Text changed` після GET `200`. На fixed state той самий fixture `47e88681-dd0e-49f9-ae70-56fcb1cb57fa` завершився `PASS: persisted description rendered as plain text`; marker був буквальним текстом, а його attribute залишився `null`. Для comments два послідовні reads дали `firstCount: 2`, `secondCount: 2`, `duplicateFree: true`, `marker: null`.

**Залишковий ризик.** Безпечний text sink не робить безпечними HTML attribute, URL або JavaScript contexts. Для URL застосовано окремий allowlist протоколів; якщо пізніше з’являться third-party scripts, потрібні source review та окреме CSP-рішення.

## DEL-02. Відтворюваність і Git-стан

Scaffold receipt: `release=lab-05-start-v1`, `base_commit=16061b56d5d1412e20fdc71993481a8cf2565b42`, `entry_parent=16061b56d5d1412e20fdc71993481a8cf2565b42`.

| Стан | Commit / ref | Призначення |
|---|---|---|
| База | `v0.4.0` / `16061b5` | перевірений результат ЛР 04 |
| Vulnerable | `7c49c5f` | scaffold із dangerous `innerHTML`; використаний лише локально для контрольованого PoC |
| XSS fixed | `ee57982` | текстове DOM-rendering рішення |
| CORS fixed | `fc41d05` | вузька Development policy та evidence |
| CSP fixed | `47ab129` | report-only → enforcement CSP та evidence |
| Final fixed | annotated tag `v0.5.0` | canonical local state перед private delivery |

Vulnerable commit не призначений для deployment і не повинен потрапити у відкритий remote. Для передавання сформовано локальний `lab05.bundle`; `git bundle verify lab05.bundle` підтвердив complete history і refs `lab/5-browser-xss` та `v0.5.0`. Тег `v0.5.0` ставиться лише на final fixed commit.

## DEL-03. Browser controls і policy decisions

### CORS

До policy simple GET із `4173` та `4174` доходив до API, але browser відхиляв читання відповіді через відсутній `Access-Control-Allow-Origin`. Preflight із `X-Lab-Cors-Probe` блокувався до actual GET. Final Development-only policy має exact allowlist:

```csharp
policy.WithOrigins("http://localhost:4173")
      .WithMethods("GET")
      .WithHeaders("X-Lab-Cors-Probe")
      .AllowCredentials();
```

Middleware виконується після routing і перед authentication/authorization. Після fix `4173` прочитав authenticated list із `status: 200`, `type: "cors"`; `4174` отримав Network `200`, але browser не передав response JavaScript через відсутній ACAO. Після logout `4173` прочитав `401` Problem Details. Отже, CORS — це browser policy читання response, а не механізм authentication чи authorization. Direct `curl` також показав: Origin `4173` одержує ACAO, `4174` — ні, хоча direct HTTP у двох випадках отримує `200`.

### CSP та security headers

Політика `default-src 'self'; frame-ancestors 'none'` спочатку була застосована через `Content-Security-Policy-Report-Only`. Контрольний `new Image().src = "http://localhost:4173/x.png"` записав Console violation без блокування. Після ретесту header змінено на `Content-Security-Policy`; та сама дія дала `The action has been blocked`.

`default-src 'self'` охоплює фактичні same-origin scripts, CSS, API fetch і зображення; тому окремі `script-src`, `style-src`, `connect-src` та `img-src` не потрібні. `frame-ancestors 'none'` захищає від embedding/clickjacking. Middleware також залишає `X-Content-Type-Options: nosniff` та `Referrer-Policy: no-referrer`. Development `/scalar` виключено з CSP, щоб не порушити API reference.

### URL та context-specific rules

Запущено `safe-url.js`: `https://example.com/a` і relative local incident URL прийняті; `javascript:alert(1)`, mixed-case/whitespace варіант та malformed URL дали `null`. Створений `<a>` мав безпечний `href`, а `onclick` був `null`. Це відрізняє дозволений URL context від text output: `textContent` не є URL validator, а CSP не є заміною server-side authorization.

## Перевірки

Після останньої зміни виконано:

```text
dotnet build SecureLab.sln --configuration Release --no-restore --disable-build-servers -m:1
Build succeeded. 0 Warning(s), 0 Error(s).

dotnet test tests/SecureLab.Api.Tests/SecureLab.Api.Tests.csproj --configuration Release --no-build --no-restore
Total: 99; Passed: 99; Failed: 0; Skipped: 0.
```

Browser evidence охоплює vulnerable/fixed XSS DOM FAIL/PASS, public comments, report-only/enforcement CSP, CORS preflight, credential-bound 4173, denied 4174, anonymous `401` і direct HTTP headers.

## Декларація використання ШІ

Використано ChatGPT Codex для аналізу методички й repository, підготовки запропонованих змін та структурування доказів. Автор власноруч запускав API, виконував local browser/Console/HTTP сценарії, переглядав code diff і отримував screenshots. Фактичні висновки спираються на наведені HTTP status, Console output, Git commits та 99 automated tests; секрети, cookie values і повний журнал діалогу до звіту не включалися.

## Межі перевірки

Перевірено локальний training environment, two browser origins, marker без зовнішнього payload, browser rendering, CORS, CSP і automated API suite. Не перевірялися production hosting, TLS, real external third-party scripts, browser extensions, distributed deployment та конкурентні сценарії. Vulnerable state зберігається тільки як локальний навчальний commit.
