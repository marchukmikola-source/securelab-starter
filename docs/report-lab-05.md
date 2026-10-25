# Звіт WEB ЛР 5 — Browser security

Автор: Микола Марчук. Спільний сценарій: 2-A. Рівень: «Відмінно». Стенд: Windows, Google Chrome 151, .NET 10, API `http://localhost:5080`; probe origins `http://localhost:4173` і `http://localhost:4174`.

## DEL-01. Карта flow та browser-security evidence

Карта [`source-to-sink.md`](source-to-sink.md) описує два фактичні flow: `Incident.Description` і public `IncidentComment.Text`. Детальні докази, browser observations, HTTP status та локальні Git refs зібрані у [`browser-security-evidence.md`](browser-security-evidence.md). Межа між уже збереженими доказами та кадрами, які ще треба зняти в DevTools, наведена у [`evidence/lab05-browser-capture-checklist.md`](evidence/lab05-browser-capture-checklist.md).

### Finding XSS-01: stored markup у Description і comments

**До виправлення.** Контрольований сценарій виконувався тільки в ізольованому local worktree на vulnerable commit `7c49c5f549112866536f4eee90959b8f4b3f0312`: dangerous sink `#description.innerHTML = current.description` перетворював збережений marker на `<img>`. У робочих нотатках зафіксовано POST `201`, details GET `200`, marker execution у сесіях Alice/Morgan та `404` для Bob, але сирі Network/Elements кадри для цього стану не входять до поданого набору. Тому ця частина описує відтворений historical scenario, а не самостійний скриншотний доказ; точний список необхідних кадрів — CAP-01--CAP-03 у checklist.

**Першопричина.** Серверна validation і довжина DTO не визначають, як browser інтерпретує текст. Проблемою був dangerous DOM sink `innerHTML` для data з response.

**Виправлення.** У `browser-lab.js` створено спільний helper `renderPlainText`, який створює text node і замінює children. Він застосований до title, Description і кожного comment:

```javascript
function renderPlainText(element, value) {
  element.replaceChildren(document.createTextNode(value ?? ""));
}
```

**Retest.** На isolated worktree vulnerable commit `7c49c5f549112866536f4eee90959b8f4b3f0312` скрипт `description-dom.js` дав очікуваний negative result `Uncaught Error: Text changed` після GET `200`. На fixed state fixture `47e88681-dd0e-49f9-ae70-56fcb1cb57fa` завершився `PASS: persisted description rendered as plain text`; marker був буквальним текстом, а його attribute залишився `null`. Новий [`comments-dom.js`](../resources/copyable/comments-dom.js) посилює REG-XSS-02: після двох `load()` він для кожного `comments[index]` вимагає точну рівність `paragraph.textContent === comment.text`, відсутність HTML children і незмінний marker `null`. [`api-render-integrity.js`](../resources/copyable/api-render-integrity.js) перевіряє сталість API Description і його рівність із plain-text DOM. Вразливий visual comment PoC ще потребує CAP-03, а не замінюється цим fixed-state тестом.

| REG-XSS-01 поле | Відтворювана перевірка |
|---|---|
| Передумови | Private vulnerable commit `7c49c5f549112866536f4eee90959b8f4b3f0312` для negative control; fixed code commit `54da9a8e9048b342df1c2065e14c1f4b6c4bc6d2`; API у Development; після reset deterministic fixture `47e88681-dd0e-49f9-ae70-56fcb1cb57fa`; authenticated Alice і origin `http://localhost:5080`. |
| Кроки | Виконати `description-dom.js` для fixture; після `load()` перевірити API response, `#description.textContent`, `#description.childElementCount` і marker attribute. Для comments виконати `comments-dom.js`, який робить два `load()` і перевіряє кожний paragraph. |
| Очікувано на fixed state | API Description не змінюється, DOM показує literal text, `childElementCount === 0`, marker `null`; кожен comment paragraph має рівний API text і не має HTML children. |
| Негативний контроль | Той самий description helper на isolated vulnerable commit дає очікуваний `Text changed`, бо `innerHTML` формує DOM; Bob не повинен одержати Alice resource. |
| Доказ і межа | Fixed Description PASS already retained; `comments-dom.js` і `api-render-integrity.js` додані в repository. Raw vulnerable Alice/Morgan/Bob POST/GET/Elements frames, visual vulnerable comment та normal-text Console capture ще треба відзняти як CAP-01--CAP-03 і CAP-09. |

**Залишковий ризик.** Безпечний text sink не робить безпечними HTML attribute, URL або JavaScript contexts. Для URL застосовано окремий allowlist протоколів; якщо пізніше з’являться third-party scripts, потрібні source review та окреме CSP-рішення.

## DEL-02. Відтворюваність і Git-стан

Scaffold receipt: `release=lab-05-start-v1`, `base_commit=16061b56d5d1412e20fdc71993481a8cf2565b42`, `entry_parent=16061b56d5d1412e20fdc71993481a8cf2565b42`.

| Стан | Commit / ref | Призначення |
|---|---|---|
| База | `v0.4.0` / `16061b5` | перевірений результат ЛР 04 |
| Vulnerable | `7c49c5f549112866536f4eee90959b8f4b3f0312` | scaffold із dangerous `innerHTML`; використаний лише локально для контрольованого PoC |
| Security controls | `54da9a8e9048b342df1c2065e14c1f4b6c4bc6d2` | XSS plain-text renderer, exact CORS policy, CSP і response hardening |
| Verified evidence / release | annotated tag `v0.5.0` | Word report і browser evidence; exact commit перевіряється `git show --no-patch v0.5.0` |

Vulnerable commit не призначений для deployment і не потрапляє у відкритий remote. На GitHub публікуються лише fixed-гілка `lab/5-browser-xss` та annotated tag `v0.5.0`, побудовані від `v0.4.0`; vulnerable commit не є їхнім предком. Попередник release commit `54da9a8e9048b342df1c2065e14c1f4b6c4bc6d2` містить усі code controls ЛР5, а другий і останній commit містить звіт та evidence й позначений тегом `v0.5.0`. Його exact full SHA визначається тільки після створення commit командою `git show --no-patch v0.5.0`, тому текст commit не містить власного майбутнього SHA. `lab05.bundle` містить лише публічний fixed lineage; private vulnerable commit до нього навмисно не включено. Повні фактичні виводи `git show`, `git bundle verify`, `git bundle list-heads` та fast-forward merge збережено у [`evidence/lab05-release-verification.txt`](evidence/lab05-release-verification.txt). Публічна історія була скорочена до двох commit на пряме прохання автора; це не слід подавати як методичний сценарій збереження непереписаної історії.

## DEL-03. Browser controls і policy decisions

### CORS

До policy simple GET із `4173` та `4174` доходив до API, але browser відхиляв читання відповіді через відсутній `Access-Control-Allow-Origin`. Preflight із `X-Lab-Cors-Probe` блокувався до actual GET. Final Development-only policy має exact allowlist:

```csharp
policy.WithOrigins("http://localhost:4173")
      .WithMethods("GET")
      .WithHeaders("X-Lab-Cors-Probe")
      .AllowCredentials();
```

Middleware виконується після routing і перед authentication/authorization. Console observations показують allowed credentialed read для `4173`, denied flow для `4174` і читабельний `401` після logout. Final direct headers окремо доводять, що Origin `4173` одержує ACAO/ACAC, а `4174` — ні, хоча direct HTTP у двох випадках отримує `200`. Для повного browser proof ще потрібні CAP-04 і CAP-05: саме вони покажуть allowed `OPTIONS` → GET, request `Origin`/Cookie presence та response ACAO/ACAC в одному Network trace. Отже, CORS — це browser policy читання response, а не механізм authentication чи authorization.



### Direct HTTP headers retained verbatim

Повний сирий вивід команд збережено у [`evidence/lab05-cors-direct-headers.txt`](evidence/lab05-cors-direct-headers.txt). Усі заголовки перезнято 25.10 на final fixed state: обидва direct GET мають `HTTP/1.1 200 OK`, `nosniff`, `Referrer-Policy` і enforcement CSP; `Access-Control-Allow-Origin: http://localhost:4173` та credentials є лише для allowed origin. Окремо final preflight для `4173` повернув `204 No Content` з exact `Access-Control-Allow-Origin`, `Access-Control-Allow-Methods: GET`, `Access-Control-Allow-Headers: X-Lab-Cors-Probe` і `Access-Control-Allow-Credentials: true`. Контрольний `OPTIONS` із `4174` також має transport-level `204`, але не містить жодного `Access-Control-Allow-*`; отже браузер відхиляє preflight і не повинен надсилати actual cross-origin GET. Це доказ server headers; browser-visible SOP/CORS результат окремо підтверджується Console і Network.

### Межі XSS, CORS, CSRF та authorization

XSS у цьому flow виникав, коли browser інтерпретував збережене сервером поле як HTML; його усунуто у DOM sink через text node. CORS визначає, чи надасть browser cross-origin response JavaScript, і не дає API права доступу. CSRF — інша загроза: browser може надсилати cookie за власними правилами, тому state-changing request потребує окремого server-side antiforgery/CSRF control; це тема ЛР 6 і її не підмінено CORS-policy. Authorization лишається server-side рішенням для authenticated principal і конкретного incident: саме воно дало Morgan доступ до дозволеного record, а Bob — `404`. CSP, CORS і safe rendering не замінюють це рішення.

### CSP та security headers

Політика `default-src 'self'; frame-ancestors 'none'` спочатку була застосована через `Content-Security-Policy-Report-Only`. Контрольний `new Image().src = "http://localhost:4173/x.png"` записав Console violation без блокування. Після ретесту header змінено на `Content-Security-Policy`; та сама дія дала `The action has been blocked`. Console proof already exists; CAP-06 still requires a matching Network blocked-resource frame.

`default-src 'self'` є fallback для фактичних same-origin scripts, CSS, API fetch, images і fonts, бо окремі `script-src`, `style-src`, `connect-src`, `img-src` і `font-src` не задані. `frame-ancestors 'none'` є сучасним anti-clickjacking control, тому окремий `X-Frame-Options` не потрібен. `X-Content-Type-Options: nosniff` обмежує MIME sniffing; `Referrer-Policy: no-referrer` не передає URL сторінки назовні. Це допустимо тут, бо flow не має потрібної cross-site navigation/analytics; така потреба вимагала б окремого перегляду policy. Development `/scalar` виключено з CSP, щоб не порушити API reference. У дослідженому flow third-party scripts відсутні: браузер завантажує лише same-origin HTML, JavaScript, CSS та API. Для майбутніх CDN, analytics або widget потрібно окремо перевірити постачальника й мету script, звузити `script-src`, застосувати SRI там, де це можливо, і повторити CSP evidence. Додавання URL до CSP не робить third-party script trusted само по собі.

| Ресурс | Фактичне джерело | Директива / причина |
|---|---|---|
| Document | `localhost:5080` | `frame-ancestors 'none'` забороняє embedding |
| Scripts | same-origin `browser-lab.js`, `auth-lab.js` | fallback `default-src 'self'` |
| Styles | same-origin CSS | fallback `default-src 'self'` |
| API | same-origin `/api/*`, `/health` | fallback `default-src 'self'` для `connect-src` |
| Images | application images відсутні; `4173/x.png` є контрольний probe | fallback блокує external image |
| Fonts | custom fonts відсутні | fallback `default-src 'self'` |

### URL та context-specific rules

Запущено `safe-url.js`: `https://example.com/a` і relative local incident URL прийняті; `javascript:alert(1)`, mixed-case/whitespace варіант та malformed URL дали `null`. Створений `<a>` мав безпечний `href`, а `onclick` був `null`. Це відрізняє дозволений URL context від text output: `textContent` не є URL validator, а CSP не є заміною server-side authorization.



### Чотири output contexts

Text context у ЛР5 обробляється `textContent`/text node. HTML attribute context потребує attribute-specific encoding або property assignment і allowlist; untrusted значення не додаються до `on*` attributes. URL context проходить `URL` parser і allowlist `http`/`https`. JavaScript context не приймає untrusted text як код: його не конкатенують у expression, а передають тільки як data values. ЛР5 не має feature з formatted HTML або untrusted JavaScript expression; це зафіксована межа, а не пропущений sink.

## Перевірки

Команди для відтворюваної фінальної перевірки:

```text
dotnet build SecureLab.sln --configuration Release --no-restore --disable-build-servers -m:1
Build succeeded. 0 Warning(s), 0 Error(s).

dotnet test tests/SecureLab.Api.Tests/SecureLab.Api.Tests.csproj --configuration Release --no-build --no-restore --logger "trx;LogFileName=lab05-final.trx"
```

Після local reset 2026-10-26 команда завершилася `101 passed, 0 failed, 0 skipped`. Повний console output збережено у [`evidence/lab05-final-test-output.txt`](evidence/lab05-final-test-output.txt), а TRX — у [`evidence/lab05-final.trx`](evidence/lab05-final.trx). Наявні browser/server докази — fixed Description DOM PASS, Console CSP, denied 4174 та direct HTTP headers; прогалини Network/visual capture перелічені у checklist.

## Короткі відповіді для захисту

1. Дані з БД можуть походити від користувача, старого коду або зовнішнього import, тому не стають trusted лише через storage.
2. Source — введення або seed, transformations — JSON, validation, mapping і storage, sink — конкретна browser-операція відображення.
3. Stored XSS зберігається й виконується при наступному читанні; reflected приходить у поточній відповіді; DOM-based виникає в client-side DOM flow.
4. Заборона `<script>` не враховує інші HTML/attribute contexts та event handlers, тому не прибирає першопричину unsafe sink.
5. Для звичайного тексту обирають `textContent`/text node; sanitizer потрібний лише за окремої вимоги приймати обмежений formatted HTML.
6. Regular expression не може коректно й повно обробити HTML, attributes і URL protocols; у цій роботі sanitizer не потрібний.
7. Origin складається зі scheme, host і port.
8. Preflight — автоматичний `OPTIONS`, у якому browser передає origin, запланований method і non-safelisted headers.
9. API оголошує headers CORS-policy, а browser застосовує SOP/CORS і вирішує, чи віддати response JavaScript.
10. `curl` не реалізує browser SOP, тому читає HTTP response незалежно від ACAO; browser script без ACAO не може його прочитати.
11. CORS не перевіряє права користувача та не зупиняє надсилання cookie; authorization і CSRF controls виконуються server-side.
12. `Access-Control-Allow-Origin: *` заборонено поєднувати з credentialed response, бо credentials потребують exact allowed origin.
13. CSP обмежує дозволені browser resources/contexts, але не перетворює unsafe `innerHTML` на безпечний текстовий sink.
14. `nosniff` зменшує MIME-sniffing, `Referrer-Policy` обмежує витік URL, а `frame-ancestors` забороняє небажане embedding/clickjacking.

## Декларація використання ШІ

Використано OpenAI ChatGPT Codex для аналізу методички й repository, підготовки запропонованих змін та структурування доказів. Автор власноруч запускав API, виконував local browser/Console/HTTP сценарії, переглядав code diff і отримував screenshots. Висновки спираються на збережені HTTP status, Console output, Git refs і фінальний log/TRX 101/101. Секрети, cookie values і повний журнал діалогу до звіту не включалися.

## Межі перевірки

Перевірено локальний training environment, two browser origins, marker без зовнішнього payload, browser rendering, CORS, CSP і automated API suite. Не перевірялися production hosting, TLS, real external third-party scripts, browser extensions, distributed deployment та конкурентні сценарії. Vulnerable state зберігається тільки як локальний навчальний commit.
