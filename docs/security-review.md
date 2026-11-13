# Security review SecureLab, ЛР 6

Рівень: **відмінний («Відмінно»)**. Дата етапу 1: 02.11.2026.
Статус вихідних документів: **CP-01–CP-03 PASS; огляд і пакет CP-04 підготовлено**.
Фактичні final commit, результат регресії прийнятого merge та tag додаються
до експорту поза Git після перевірки. Порядок — [CP-04](lab-06-stage4.md).

## 1. Executive summary

Огляд локального SecureLab охопив етапи 1–3: модель загроз, configuration/secret
review, Production error/trace та browser controls. Виправлено відсутність standard
CSRF validation, зникнення security headers на error path та конкурентне
дублювання triage history (F-03 поза checklist). Усі шість cookie
mutations захищено; повний REG-CSRF-01 підтвердив відмови без зміни стану та
успішну дозволену зміну. Перевірено CORS, CSP без поломки клієнта, cookie flags,
search quota/partition isolation/recovery і збережений login limiter. Повний
прогін етапу 3: 135/135 tests; фактичні Chrome UI/CORS/rate-limit сценарії пройшли.
Dependency advisory audit не виявив відомих вразливих пакетів; виконано source
secret inventory та шість класів log/audit scenarios з trace correlation.
Погоджений self-only revoke-all реалізовано з password rate limit, SecurityStamp,
stamp-bound antiforgery і виміром DB/Set-Cookie ціни. Підсумковий статус CP-03 —
[lab06-stage3.json](evidence/lab06-stage3.json); final verified release належить CP-04.

## 2. Scope та exclusions

Детальний scope, subjects, endpoints, assets та схема:
[threat-model.md](threat-model.md).

У межах: Client, API, локальна PostgreSQL, Compose, Git/configuration, build,
наявні security tests та діагностика контрольованої unexpected error.
Виключено зовнішні системи, реальні персональні дані, production host/TLS,
Redis, binary documents, unrelated untracked content та всю історію Git, окрім явно
переглянутих configuration inputs. CP-03 source scan додатково охоплює явно
визначені planned-release untracked source/docs ЛР 6, окремо від tracked файлів.

## 3. System overview і trust boundaries

Трирівневий моноліт: Vanilla JS → ASP.NET Core/Identity → EF Core/PostgreSQL.
Матриця ролей: [access-matrix.md](access-matrix.md). Власник Incident і ролі
визначаються сервером; Analyst transition не надається Reporter через ownership.
Зв’язок asset → threat → control → verification та результати конкретних тестів
наведено в моделі загроз. Standard antiforgery запроваджено на етапі 2;
повний perimeter і token lifecycle описано у [протоколі](lab-06-stage2.md).

## 4. Methodology та test environment

- Review-start commit: `ee18ff404459584030df429c6a2c899c64cda89d`.
- Гілка: `lab/6-hardening-review`; `v0.5.0` збережено без переміщення.
- Початкове дерево містило 8 tracked modifications і 15 untracked entries.
  Збережено поточний cumulative HEAD та всі попередні локальні зміни.
  На review-start Production source/config мали той самий вміст, що у `v0.5.0`;
  етап 2 тепер додає описані нижче зміни.
- SDK: стабільна `10.0.403`; locked restore успішний; Release build: 0 warnings/errors.
- PostgreSQL healthy, target `127.0.0.1:54329/securelab`; штатний Development
  reset/seed виконано перед тестами й повторено після тестів.
- Seed-пароль передано через process environment, без значення у доказах.
  Локальний повтор використовує ignored `tmp/lab06/local.runsettings`.
- Real-process profiles: Development та Production через `--no-launch-profile`,
  HTTP `localhost:5080`. У Production connection string задавався process env.
- Protected Production checks: WebApplicationFactory з фактичним
  `IHostEnvironment=Production`, cookie-aware client з HTTPS BaseAddress.
  Це перевірка application/cookie behavior без реального TLS.
- Browser: headless Chrome через Playwright; Development, HTTP localhost.
- Unexpected error: публічний login, вигадані credentials, тимчасовий
  недоступний loopback DB port `54399`; Console scopes увімкнено.

Повтор поточного етапу 2 з кореня проєкту (Python 3, Node, Playwright і Chrome доступні):

```powershell
docker compose --env-file infra/.env.example -f infra/compose.yaml up -d --wait
dotnet restore SecureLab.sln --locked-mode
python scripts/verify_lab06_stage2.py
```

Команда скидає відомі таблиці локальної навчальної БД. Якщо env seed-пароль
не заданий, повторно використовує локальні ignored runsettings; при першому
запуску генерує новий навчальний пароль. Значення не друкується.
Для bundled Node `NODE_PATH` визначається зі встановленого runtime; у звичайному
оточенні встановлений Playwright має бути доступний Node через NODE_PATH або node_modules.
Raw logs/TRX етапу 2 залишаються у `tmp/lab06/stage2`, поза tracked state. JSON evidence містить
лише безпечний excerpt і підсумки. Кожен API-процес перевірки завершується.

## 5. Findings summary

| ID | Finding | Priority | Status | Retest |
|---|---|---|---|---|
| F-01 | Відсутній standard antiforgery на cookie mutations | P2 | Fixed | REG-CSRF-01, 12 negative perimeter cases, valid UI/API mutations |
| F-02 | Headers губилися на unexpected error response | P3 | Fixed | Actual headers на static/API/400/404/500, CSP browser flow |
| F-03 | Concurrent triage дублював один перехід у history | P2 | Fixed | До 204+204/2 history; після 204+409/1 history з тим самим scheduling barrier |

F-01/F-02 стосуються checklist. F-03 — окрема business-logic finding поза
checklist, підтверджена негативним тестом до виправлення. Рівень відмінно також
потребує погодженого розширення, повної регресії та завершення CP-04.

## 6. Detailed findings

Детальні картки з scope, reproduction, impact/likelihood, root cause, fix,
retest, positive regression і residual risk:

- [F-01-cookie-csrf.md](findings/F-01-cookie-csrf.md).
- [F-02-error-path-headers.md](findings/F-02-error-path-headers.md).
- [F-03-concurrent-triage.md](findings/F-03-concurrent-triage.md).

P2 для системного CSRF gap має вищий пріоритет за P3 browser-header inconsistency.
Порядок виправлення обґрунтовано окремо:

| Порядок | Finding / актив | Impact | Likelihood / передумови | Рішення |
|---|---|---|---|---|
| 1 | F-01 / цілісність Incident та cookie-сеансу | Потенційна небажана mutation у широкому perimeter | Потрібні authenticated browser, надсилання cookie і відповідний request path; SameSite/JSON/CORS обмежують exploitation | Закрити standard antiforgery до mutation на всіх routes; стан і legitimate success перевірити |
| 2 | F-03 / canonical status і достовірність history | Дублювання одного привілейованого переходу спотворює аудит | Потрібні Analyst, New incident і два одночасні запити; локально відтворено | Conditional atomic update + transactional history; 204/409 та один запис |
| 3 | F-02 / узгоджена browser response policy | Втрата defense-in-depth на exception response | Потрібна unexpected error; JSON Content-Type і safe ProblemDetails вже працювали, окремий exploit не доведений | OnStarting перед exception handler; п'ять класів відповідей та CSP regression |

Усі три findings виправлені. Тимчасово прийнятих невиправлених findings немає.
Residual boundaries (local HTTP, single-process quotas, anonymous login/register)
мають compensating controls у розділах 8/10. Відповідальний за перегляд — автор
проєкту; тригер follow-up — зміна scope, новий deployment або advisory.
Передумови browser exploit не підмінені фактом відсутнього control; самостійний
XSS exploit через headers не заявляється.

## 7. Regression results

Фінальний pack запускається командою `python scripts/verify_lab06_stage3.py --release`
на чистому candidate і потім на прийнятому merge commit у main. Усі outputs цього
режиму лишаються в ignored `tmp/lab06/release`; історичні докази CP-01–CP-03 не
переписуються. Повні фактичні final counters, commit і час містяться в експорті
`release-verification.json` разом із PDF; це усуває самопосилання commit hash.

Історичний прогін етапу 1 (02.11.2026): [lab06-stage1.json](evidence/lab06-stage1.json).

| Перевірка | Результат | Доказ |
|---|---|---|
| Locked restore | PASS, exit 0 | Виконано перед build; lockfiles не змінено |
| Release build | PASS, 0 warnings/errors | `checks.build` |
| Наявний harness + нові Production тести | PASS: 106/106, failed=0, skipped=0 | `checks.tests`; raw TRX лише локально |
| Фактичний Production profile | PASS: console environment/listening, health 200 | `checks.production-profile` |
| Development migrations/reset не активні в Production | PASS: flags false, reset відхилено, study rows не змінилися | Два ProductionProfileTests та `production-reset-refusal` |
| Protected allowed GET, validation 400, missing resource 404 | PASS через Production TestServer; login тим самим cookie client | `Production_UsesExplicitConfigurationAndPreservesProtectedErrorContracts` |
| Production auth cookie | PASS: Secure, HttpOnly, SameSite=Lax; session 204 | `Production_AuthenticationCookieRetainsSecureHttpOnlyAndSameSiteFlags` |
| Контрольована unexpected error | PASS: 500 problem+json, без SQL/stack/path/credentials | `checks.unexpected-error`, відповідний integration test |
| Зв’язок HTTP → diagnostic log | PASS: середній сегмент response traceId = log TraceId | `traceMatches=true`, оригінальний очищений excerpt |
| Normal browser flow до помилки | PASS | `checks.browser-before` |
| Відновлення після помилки | PASS: Development health 200; login/profile/F5/list/details/summary/marker/logout | `checks.browser-restored`, `checks.restoration` |

Поточний прогін етапу 2 (05.11.2026): [lab06-stage2.json](evidence/lab06-stage2.json).

| Додаткова перевірка | Фактичний результат |
|---|---|
| Release build / full tests | 0 warnings/errors; 123/123 PASS, failed=0, skipped=0 |
| REG-CSRF-01, xUnit та Chrome HTTP context | Login → missing/invalid 400 → unchanged GET → token 200 → valid PUT 204 → intended change |
| Увесь cookie mutation perimeter | 5 routes × missing/invalid; незмінний stored state; logout denial зберігає session |
| Cookie/principal binding | Wrong cookie/principal/stale token → 400; fresh pair → success |
| CSP/headers | 5 actual response classes; pageErrors=0; CSP violations=0 |
| CORS | 4173 browser GET readable 200; 4174 JS blocked; token endpoint не читається з обох origins |
| UI | Register, auth/browser create, F5, logout на обох сторінках, новий principal — PASS |
| Search limiter | Actual defaults 30/10; 31st → 429; Bob isolated; forged key не обходить; recovery → 200 |
| Login limiter | Existing integration/unit quota/429/recovery/partition tests PASS |
| OpenAPI / Production cookies | Final response declarations звірено; targeted Secure/HttpOnly/SameSite test 1/1 PASS |
| Restoration | Known seed, правильний target, Development health 200 та normal browser PASS |

Це історичний прогін етапу 2. Повний протокол і межі
доказів: [lab-06-stage2.md](lab-06-stage2.md).

## 8. Hardening controls

| Control | Risk | Verification | Boundary |
|---|---|---|---|
| Identity + resource authorization | Identity forgery / IDOR | Auth/ownership/triage tests з валідним token, 135/135 PASS у CP-03 | Не замінює CSRF |
| Standard antiforgery, explicit filter | Cookie CSRF на mutation | REG-CSRF-01, 6-route perimeter, cookie/principal/stamp binding | Login/register окремо виключені; не зупиняє same-origin XSS |
| Token helper / memory lifecycle | Неправильна пара після F5/login/logout | Actual Chrome форми на всіх сторінках, новий principal | Немає automatic mutation retry; stale request може вимагати ручної повторної дії |
| OnStarting headers + enforced CSP | Browser policy gaps | Static/API/400/404/Production 500, CSP browser flow | Development Scalar — наявний виняток; safe DOM збережено |
| Narrow CORS | Cross-origin response disclosure | REG-CORS-01, два origins + direct HTTP boundary | Не authentication/authorization/CSRF replacement |
| Secure/HttpOnly/SameSite cookies | Частина session/token risks | Chrome Development flags; Production TestServer flags | Не реальний TLS доказ |
| Search fixed-window limiter | Search abuse | Verified subject partitions, quota/429/recovery | In-memory, не shared для instances |
| Existing login limiter | Password guessing abuse | Existing TimeProvider/unit/integration tests | IP може бути спільним; не authorization |
| Safe errors + trace | Internal info leakage / діагностична кореляція | Production 500 safe ProblemDetails + matching ExceptionHandlerMiddleware trace; original six-class log review | Перевірені конкретні runtime values/patterns, без claim абсолютної відсутності витоків |
| Self-only session revocation | Старі cookie/token після sign-out everywhere | 2 Alice + replay 401; Bob 200; fresh login; old token before/after 204/400; password quota 429 без revoke | In-flight requests не скасовуються; local in-memory limiter; додаткові DB reads |
| Atomic workflow update | Concurrent дублювання triage history | F-03 retest, 204+409/1 history | Інші concurrent business operations потребують окремого рішення |
| Reset guard | Production data reset | Етап 1: refusal before mutation + unchanged rows | Потребує контролю env/configuration |

Production OpenAPI/Scalar boundary, AllowedHosts=* та local HTTP/HSTS
limitations з етапу 1 збережено. Реального deployment/TLS/HSTS evidence немає.
Точний perimeter, actual header values, CORS policy, token contract і limiter
parameters: [lab-06-stage2.md](lab-06-stage2.md).

## 9. Dependency and secret audit

### Secrets/configuration: етап 1

Команда snapshot до додавання нових файлів етапу:

```powershell
git grep -n -I -i -E 'password|passwd|secret|api.?key' -- .
git ls-files '*appsettings*.json' '*.env*' '*compose*.yml' '*compose*.yaml' '*.config'
git check-ignore -v infra/.env appsettings.Local.json tmp/lab06/local.runsettings
```

514 збігів у 46 tracked текстових файлах; кожен має окремий рядок рішення у
[CSV](evidence/lab06-secret-matches.csv). Кількість не є кількістю секретів.
Підсумок і межі: [lab06-secret-review.json](evidence/lab06-secret-review.json).

| Вхід | Огляд і рішення | Межа |
|---|---|---|
| `appsettings.Development.json` | Connection string: accepted, study-only | Узгоджений локальний PostgreSQL; не копіювати в інші середовища |
| `infra/compose.yaml` | Відомі навчальні credentials; publish тільки 127.0.0.1 | Loopback binding не є захистом реального deployment |
| `SecureLabDesignTimeDbContextFactory.cs` | Той самий навчальний fallback; env має пріоритет | Три конфігураційні входи збережено узгодженими |
| `appsettings.json` | Без credentials; migration/reset false, AllowedHosts=* | Host filtering виключений з позитивного висновку |
| `infra/.env.example` | Тільки non-secret `POSTGRES_PORT=54329` | Не свідчить про вміст untracked .env |
| `.gitignore` | .env/.env.*, local JSON, keys, logs, tmp виключено; .env.example дозволено | Gitignore не видаляє вже tracked секрети |
| README | Навчальні credentials явно обмежено локальним стендом; реальний connection string через env | Не просить додати реальний credential у Git |
| Скрипти/тести/контракти | Ключі env, назви Password/PasswordHash, синтетичні inputs | Не справжні credentials; повні input/body не копіювалися до evidence |
| Lockfile | Назва UserSecrets package | Ідентифікатор залежності, не secret value |
| CI | Tracked CI definitions не знайдено | Зовнішні CI та їхні secrets не перевірялися |
| Configuration history | `git log --all --follow` і patch history трьох навчальних PostgreSQL inputs: лише initial commit d7efe1f | Не вся history, не stash/clones/CI |

Серед 514 збігів: 3 accepted study-only, 339 назв/службових записів,
172 документаційних/тестових/скриптових згадок без real credential.
Справжнього credential у перевіреному контексті не виявлено. Keyword search
не доводить абсолютної відсутності секретів; binary DOCX і untracked content не сканувалися.
Для реального витоку одного видалення з latest commit недостатньо: потрібні
revocation/rotation та оцінка history/clones/cache/logs; історію тут не переписували.

### Dependency audit

09.11.2026 виконано locked restore та direct/transitive audit у text/JSON,
exit 0. Джерела NuGet не повернули відомих advisory для API/Tests.
Reachability для конкретної advisory — N/A; версії збережено, suppression і
сліпі upgrades не застосовано. [Повний вивід](evidence/lab06-dependency-audit.txt)
та [таблиця рішень CP-03](lab-06-stage3.md). Це point-in-time результат,
а не доказ відсутності невідомих вразливостей чи проблем ОС/контейнера.

### Secrets і журнали: етап 3

Актуальний [scope, manifest і підсумок](evidence/lab06-stage3-secret-review.json)
та [per-match CSV](evidence/lab06-stage3-secret-matches.csv) охоплюють tracked text
і окремо визначені planned-release untracked файли. Точні runtime secrets
перевіряються без публікації значень. Публічні negative-test markers явно
класифіковано synthetic; у повних журналах вони також мають бути відсутні.
Шість класів сценаріїв: successful/failed login, protected denial, validation,
Production unexpected error, privileged allowed/denied transition. Перевірено
original logs, їх SHA-256 та matching trace; safe excerpts і zero-match counts
збережено в CP-03. Canonical triage success та failed session password checks
мають мінімальні audit events. Повний опис меж — у протоколі етапу 3.

## 10. Residual risks

- Same-origin XSS може користуватися cookie/token; safe DOM/CSP лишаються потрібними.
- Login/register не мають anonymous antiforgery bootstrap; login-CSRF/account-creation risks явно описано у scope.
- Лічильники in-memory не забезпечують shared quota для кількох API instances; login IP partition може бути спільним.
- Local HTTP та AllowedHosts=* не підтверджують production transport/host safety.
- Keyword/signature secret review має явно обмежений scope; binary docs, full history та external CI/clones не перевірені. Dependency advisory result обмежений датою і джерелами.
- Початкове робоче дерево містило попередні матеріали ЛР 4–5. Їх збережено поза commit ЛР6; release перевіряється в окремому чистому worktree. Існуючий позитивний `IncidentDecTests` включено незміненим до cumulative regression pack.
- F-03 та погоджений advanced variant реалізовані; in-flight requests не скасовуються, ValidationInterval=0 збільшує DB/Set-Cookie cost. Redis не потрібний для цього локального design.

## 11. Conclusion

CP-01 та CP-02 виконано в описаному локальному scope. Standard CSRF perimeter
і legitimate UI flow працюють; error headers gap виправлено; CORS/CSP/cookie
та rate-limit властивості перевірено фактично. Після mutation/controlled-error
експериментів відновлено seed, правильний DB target і normal Development flow.
CP-03 додає dependency/secret/log audit, повний regression pack, F-03 та
погоджений advanced variant. Його фактичний статус — в JSON evidence.
CP-04 описує послідовність clean merge → fresh regression → annotated tag →
export. Вихідні docs не містять майбутнього hash або непідтвердженого PASS.
Факт завершення release та його ідентичність підтверджуються обкладинкою PDF,
окремим verification JSON і hashes локального tag/ZIP після виконання процедури.

## 12. Evidence appendix

Актуальні результати етапу 3: [протокол](lab-06-stage3.md),
[JSON перевірок](evidence/lab06-stage3.json), [regression pack](lab-06-regression-pack.md),
[погодження](evidence/lab06-advanced-approval.md),
[до виправлення F-03](evidence/lab06-triage-race-before.json),
[Chrome screenshots](evidence/screenshots/lab06-stage3).
Для CP-04: [процедура та DEL-01–03](lab-06-stage4.md),
[короткий live defense](lab-06-defense.md). Фінальні outputs додаються тільки
до зовнішньої папки submission, не до tracked docs після tag.

| ID | Артефакт | Що підтверджує |
|---|---|---|
| EV-06-START | [lab06-start-state.json](evidence/lab06-start-state.json) | Review-start, branch, відмінність від tag, наявні локальні зміни |
| EV-06-TM | [threat-model.md](threat-model.md) | Scope, схема, assets/threats/controls/tests |
| EV-06-SECRETS | [lab06-secret-review.json](evidence/lab06-secret-review.json), [CSV](evidence/lab06-secret-matches.csv) | Команда, кількість, scope, рішення для кожного match |
| EV-06-RUN | [lab06-stage1.json](evidence/lab06-stage1.json) | Фактичні build/tests/profile/error/trace/browser/restoration результати |
| EV-06-TEST | `tests/SecureLab.Api.Tests/ProductionProfileTests.cs` | Повторювані Production checks у наявному harness |
| EV-06-CMD | `scripts/verify_lab06_stage1.py`, `scripts/lab06_browser_check.cjs` | Повтор етапу без друку credentials |

Додаткові докази етапу 2:

- [Повний протокол CP-02](lab-06-stage2.md).
- [Фактичний JSON прогону](evidence/lab06-stage2.json).
- [Chrome screenshots](evidence/screenshots/lab06-stage2/client-csp.png): normal client/CSP; поруч cors-4173.png і cors-4174.png.
- BrowserHardeningTests, SearchRateLimitTests; `scripts/verify_lab06_stage2.py`.
- [Ручний REG-CSRF-01](../tests/http/lab-06-csrf.http).

### Декларація та журнал ШІ

Використано OpenAI Codex для аналізу наданої методички й коду, підготовки
моделі загроз, automation scripts, integration tests та документування результатів.
Код адаптовано до фактичних routes, ролей, cookie profile та наявного harness.

| Дата | Допомога ШІ | Перевірка / авторська робота |
|---|---|---|
| 02.11.2026 | Scope, tests, scripts, secret classification, review етапу 1 | Фактично виконано restore/build, 106 tests, Chrome flow і Production error experiment; студент має перевірити зміст, пояснити рішення та підготуватися до захисту |
| 05.11.2026 | Standard CSRF, headers, rate limiting, адаптація tests/client, CORS/CSP/browser proof, finding cards | Full run 123/123, actual Chrome сценарії та Production headers; targeted cookie test 1/1; студент має перевірити й пояснити рішення |
| 09.11.2026 | Погоджений revoke-all, stamp-bound antiforgery, audit/dependency/secret review, concurrency finding і runner | 135/135 tests, контроль до/після provider та triage; actual Chrome і original logs; остаточні counts/status у CP-03. Студент має перевірити й самостійно пояснити рішення |
| 09.11.2026 | Пріоритизація, finding cards за шаблоном, README, clean release runner і PDF/ZIP export | Final regression перевіряється на прийнятому merge; actual counts/hash додаються лише до зовнішнього експорту. Авторська інтерпретація й особистий захист студента не підмінені автоматизацією |

Самостійне пояснення студентом і live defense ще не перевірялися; їх не
підмінено автоматизованим прогоном. Цей запис не є твердженням, що ШІ не використовувався.
