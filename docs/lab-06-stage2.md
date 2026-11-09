# ЛР 6 — етап 2: browser controls, CSRF, rate limiting

Дата: 05.11.2026. Рівень: відмінний. **CP-02 виконано** у наведених межах.
Етапи 3–4, третя самостійна finding та погоджений advanced variant ще попереду.

## Середовище та повтор

Власний local Development API: `http://localhost:5080`, PostgreSQL
`127.0.0.1:54329/securelab`; Production використано для контрольованої 500 та
cookie-aware TestServer. Базовий review-start commit лишається
`ee18ff404459584030df429c6a2c899c64cda89d`; зміни етапів 1–2 поки в робочому дереві,
тому цей прогін не оголошено фінальним verified release commit.

```powershell
docker compose --env-file infra/.env.example -f infra/compose.yaml up -d --wait
python scripts/verify_lab06_stage2.py
```

Потрібні .NET 10, Python 3, Node, Playwright і Chrome. Runner використовує
наявний локальний seed-пароль з env або ignored `tmp/lab06/local.runsettings`.
**Скидає лише відомі таблиці локальної навчальної БД** до/після тестів та після
браузерних mutation-сценаріїв. Значення credentials/token/cookies не друкуються.
Raw logs/TRX — лише в ignored `tmp/lab06/stage2`. API і локальні probe-сервери
перевірки завершуються, правильний DB target та known seed відновлюються.

Фактичний результат: [lab06-stage2.json](evidence/lab06-stage2.json), статус PASS,
123/123 tests, failed=0, skipped=0; Release build без warnings/errors.

## 1. Заголовки та cookie profile

На кожній із п’яти перевірених відповідей:

```text
Content-Security-Policy: default-src 'self'; frame-ancestors 'none'
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
```

| Клас | Profile, client/session | Method + route | Status | Evidence |
|---|---|---|---|---|
| Статична сторінка | Development, Chrome context Alice | GET `/` | 200 text/html | `checks.browser.headers[0]` |
| Дозволений API | Development, той самий Alice context | GET `/api/incidents/20000000-0000-0000-0000-000000000001` | 200 JSON | `headers[1]` |
| Validation | Development, той самий Alice context | GET `/api/incidents?status=Unknown` | 400 problem+json | `headers[2]` |
| Unknown resource | Development, той самий Alice context | GET `/api/incidents/99999999-9999-9999-9999-999999999999` | 404 problem+json | `headers[3]` |
| Unexpected error | Production/no-launch-profile, anonymous HTTP login, недоступна loopback БД 54399 | POST `/api/auth/login` | 500 problem+json | `checks.production-500-headers` |

На етапі 1 headers зникали на 500. Тепер middleware реєструє Response.OnStarting
перед UseExceptionHandler: потрібні headers встановлюються після очищення
error response. Спільний AddProblemDetails/UseExceptionHandler збережено,
другий catch-all не додано. Finding: [F-02](findings/F-02-error-path-headers.md).

CSP збережено без wildcard/unsafe-inline. Development Scalar лишився окремим
локальним винятком, як раніше. Chrome перевірив actual page scripts, форми,
навігацію і F5: pageErrors=0, CSP violations=0. Safe DOM лишився незмінним.

| Cookie | Development HTTP (Chrome) | Production (HTTPS-addressed TestServer) |
|---|---|---|
| Identity application | HttpOnly=true, SameSite=Lax, Secure=false | HttpOnly, SameSite=Lax, Secure |
| Antiforgery | HttpOnly=true, SameSite=Strict, Secure=false | HttpOnly, SameSite=Strict, Secure |

Secure=false в Development відповідає наявному HTTP profile. Production cookie
policy не послаблено. Окремий final targeted test Production cookie пройшов
після додавання перевірок antiforgery cookie. Values у evidence відсутні.

## 2. REG-CORS-01

Policy `Lab05BrowserProbe`: лише Development, exact origin
`http://localhost:4173`, method GET, request header X-Lab-Cors-Probe,
AllowCredentials. Production не має дозволених cross-origin policies.
Cors middleware присутній у двох profiles, щоб endpoint metadata оброблялася
коректно; це не додає Production allowed origins.

| Сценарій | Фактичний результат у Chrome |
|---|---|
| Origin `http://localhost:4173`, credentialed GET `/api/incidents`, X-Lab-Cors-Probe | Preflight/GET успішні; JS читає 200 JSON |
| Origin `http://localhost:4174`, той самий flow | Fetch відхилено браузером, JS response не читає |
| Token endpoint `/api/auth/csrf` з 4173 або 4174 | JS не читає token response; DisableCors metadata |
| Direct HTTP із Origin 4174, чинна cookie | 200, Access-Control-Allow-Origin відсутній; direct HTTP не підкоряється browser CORS |

Два localhost ports — різні origins, але не доказ cross-site SameSite behavior.
CORS не замінює authentication, authorization або antiforgery. Прямий HTTP 200
за чинної cookie не є обходом authorization.

Скріншоти фактичного Chrome:
[дозволений origin](evidence/screenshots/lab06-stage2/cors-4173.png),
[заборонений origin](evidence/screenshots/lab06-stage2/cors-4174.png).

## 3. Повний mutation perimeter та узгодження джерел

Джерела: поточні MapPost/MapPut/MapDelete, client calls, фактичний OpenAPI JSON
Development та накопичена access matrix ЛР 4. OpenAPI містить рівно сім unsafe
routes нижче. PATCH, batch, administrative mutation чи mutating GET не виявлено.
GET token issuance не змінює бізнес-дані; GET/HEAD/OPTIONS не редагують Incident.

| ID | Method + route | Зміна state | Cookie authorizes? | Browser-accessible? | Validation / regression |
|---|---|---|---|---|---|
| SC-01 | POST `/api/incidents` | Створення Incident | Так | Так | explicit AntiforgeryFilter; missing/invalid → 400; existing positive creation tests; Chrome auth/browser forms → 201 |
| SC-02 | PUT `/api/incidents/{id}` | title/description | Так | Так | explicit filter; REG-CSRF-01; existing owner/foreign tests |
| SC-03 | DELETE `/api/incidents/{id}` | Видалення | Так | Так | explicit filter; perimeter negative theory; existing owner-delete positive regression |
| SC-04 | POST `/api/incidents/{id}/triage` | New → Triaged + history | Так | Так | explicit filter; perimeter negative theory; existing Analyst transition regression |
| SC-05 | POST `/api/auth/logout` | Завершення session | Так | Так | RequireAuthorization + explicit filter перед SignOut; deny зберігає session, valid pair → 204 |
| SC-06 | POST `/api/auth/login` | Новий cookie principal | Ні, перевіряються подані credentials | Так | absent, окреме scope-рішення нижче; valid login → 204; failure/limiter tests збережено |
| SC-07 | POST `/api/auth/register` | Новий account | Ні, публічна реєстрація з фіксованою server role | Так | absent, окреме scope-рішення нижче; existing registration tests та Chrome → 201 |

DISCREPANCY між source/OpenAPI і client: PUT, DELETE та triage опубліковані API,
але окремих кнопок у наявному Client немає. Це явно задокументовані API-only
операції: відсутність UI не є виключенням із CSRF perimeter. Вони покриті
integration tests, PUT має також HTTP/Chrome regression. Нові UI-функції для
видимості цих routes не вигадувалися. Застарілий опис login success=200 в
OpenAPI виправлено на 204; додано відсутні 403 для create/triage та CSRF 400.

Login/register не довіряють уже виданій auth cookie як дозволу на дію. Для цього
етапу обрано authenticated-only token issuance без анонімного bootstrap; ці два
routes не оголошено CSRF-protected. Login-CSRF та небажане створення accounts
залишено явними residual risks. JSON-only contract і вузький CORS зменшують
окремі browser paths, але не зараховуються заміною antiforgery.

## 4. Standard antiforgery flow

1. AddAntiforgery реєструє standard ASP.NET Core service; header — **X-CSRF-TOKEN**.
2. Authenticated GET `/api/auth/csrf` викликає GetAndStoreTokens. DTO містить
   requestToken і headerName; cookie частину ставить framework. Cache-Control
   забороняє зберігання token response; endpoint CORS-вимкнений.
3. Один `AntiforgeryFilter` викликає ValidateRequestAsync перед mutation handler.
   AntiforgeryValidationException перетворюється на точний **400 problem+json**,
   `code=csrf_validation_failed`; exception/token details не повертаються.
4. Filter застосовано явно до всіх п’яти cookie mutations, а не до read group.
   JSON/DELETE не покладаються на автоматичний form-data middleware.
5. `Client/api-fetch.js` тримає token лише в пам’яті module, одержує після login
   або lazy після F5, додає header для unsafe cookie calls, очищує після logout,
   нового login, 401 або CSRF denial. localStorage/sessionStorage порожні.
6. Після CSRF denial helper не повторює mutation автоматично. Нову дію запускає
   користувач. Token старого principal або іншої cookie-пари сервер відхиляє.

Auth-lab та session-state-demo вже імпортували api-fetch; browser-lab тепер
також module та використовує цей helper. На index є лише GET, тому його
read-only fetch не потребує token flow. Cross-origin URL helper відхиляє.

## 5. REG-CSRF-01 та всі легітимні UI mutations

Повний flow виконано і в xUnit через реальний Identity cookie login, і через
новий Chrome cookie context / HTTP APIRequestContext. Не підроблявся principal
та не вимикався antiforgery в tests/production code.

| Крок REG-CSRF-01 | Фактичний результат |
|---|---|
| Login Alice → початковий дозволений GET SafeTextIncident | 204 → 200 |
| PUT без request token | 400, csrf_validation_failed |
| Повторний GET | Повний resource DTO збігається з початковим |
| PUT із невалідним token | Такий самий 400; DTO знову незмінний |
| Видача token тим самим cookie client | 200 |
| Той самий PUT із валідною парою | 204 |
| Повторний GET | Саме очікувані title/description змінено |

`EveryCookieMutation_RejectsMissingOrInvalidTokenWithoutChangingState` має
10 cases: обидві відмови на кожному з п’яти routes. Порівнюється stored Incident
state/history, а для logout додатково підтверджується активний session-check.
Окремо перевірено wrong cookie pair, token іншого principal, stale token після
logout/new login та успіх із новим token. Positive create/update/delete/triage
tests адаптовано через спільний CookieClient.AddAntiforgeryTokenAsync;
authorization assertions збережено. Публічні login/register tests не обходять controls.

Фактичні UI дії Chrome:

- register — 201; login Alice — успіх;
- create з auth-lab — 201 із CSRF header;
- F5 на auth-lab → ще один create — 201 із новим token flow;
- перехід та F5 на browser-lab → create 201 → details GET 200;
- перехід та F5 на session-state-demo → logout 204;
- новий login Bob → create 201 із token нового principal → auth-lab logout 204.

Чутливі values не записуються. Ручний REST Client flow:
[lab-06-csrf.http](../tests/http/lab-06-csrf.http). Старі Python PoC ЛР 4 та
fixed access .http адаптовано до token flow, збережено їхні попередні scenario IDs.

## 6. HTTPS/HSTS: межа огляду

У launchSettings лише `http://localhost:5080`. UseHttpsRedirection/UseHsts
не додавалися; reverse proxy/TLS termination відсутні. Реальний HTTPS transport,
redirect і production HSTS не перевірялися. Loopback-виключення HSTS не
змінювалися, довільну локальну HSTS policy не вмикали. HTTPS BaseAddress
TestServer підтверджує cookie/application behavior, а не реальний TLS.

## 7. Rate limiting

Search: наявний GET `/api/incidents/search?q=...`, standard ASP.NET Core
fixed-window limiter, **30 запитів / 10 секунд**, queue=0. Параметри в
`RateLimiting:Search` appsettings, конфігурація валідована при старті. Partition —
verified NameIdentifier claim. Authentication і authorization виконуються до
UseRateLimiter. Client header, q або client query не задають partition.

| Фактична HTTP перевірка | Результат |
|---|---|
| Alice: 30 пошуків USB у межах квоти | 30 × 200 |
| Наступний Alice search | 429 problem+json |
| Підміна X-Demo-UserId / client query | 429, не створює нову квоту |
| Bob одразу після exhausted Alice | 200, інший partition |
| Alice звертається до чужого Incident, не search | 404; authorization збережено |
| Alice GET /api/me під час search throttling | 200; інший flow не заблоковано |
| Alice search після вікна | 200 |

Окремий integration test виконує той самий flow із quota=2/window=2 seconds
для швидкого boundary/recovery test; actual Chrome run перевіряє production
defaults 30/10. Anonymous search лишається 401.

Наявний login limiter збережено: 5 failed attempts / 2 minutes за IP. Existing
integration та unit tests підтверджують quota/429/recovery, partition expiration
та безпечний зовнішній failure contract. Відновлення тестується наявним
керованим TimeProvider; це не твердження про очікування двох хвилин у браузері.
Обидва лічильники in-memory; shared state між instances не заявляється.

## CP-02 та відкриті пункти

Виконано всі вимоги етапу 2: actual headers/cookies на потрібних responses,
CSP без поломки клієнта, REG-CORS-01, узгоджений perimeter, standard token flow,
negative/positive/state CSRF regression, HTTPS/HSTS boundary та search/login
limiting checks. Залишаються dependency/full log/audit review, фінальна регресія
етапів 3–4, третя finding поза checklist та погодження advanced variant.
Redis не додано без погодженого сценарію. `v1.0.0` не створювався.

Actual screenshot клієнта: [client-csp.png](evidence/screenshots/lab06-stage2/client-csp.png).
