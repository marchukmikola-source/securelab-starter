# ЛР 6 — етап 3: залежності, секрети, журнали та regression pack

Дата: 09.11.2026. Рівень: **відмінний**. **CP-03 виконано**.
Фактичний результат: `status=PASS` у [lab06-stage3.json](evidence/lab06-stage3.json).
Погоджене розширення входить у цей прогін; CP-04 release оформлюється окремо.

## Середовище та повторення

Гілка `lab/6-hardening-review`, SDK **10.0.403**, Release/net10.0,
існуюча PostgreSQL `127.0.0.1:54329/securelab`. HEAD — review-start
`ee18ff404459584030df429c6a2c899c64cda89d`; зміни етапів 1–3 локальні.
Це доказ перевірки робочого дерева, а не фінального release commit.

```powershell
docker compose --env-file infra/.env.example -f infra/compose.yaml up -d --wait
python scripts/verify_lab06_stage3.py
```

Потрібні .NET 10, Python, Node, Playwright та Chrome. Runner використовує
існуючий пароль із env або ignored `tmp/lab06/local.runsettings`, не друкує його.
Відомі таблиці **локальної навчальної** БД скидаються між незалежними наборами
та після завершення. API-процеси й probe-сервери завершуються.
Оригінальні logs/TRX зберігаються тільки в ignored `tmp/lab06/stage3`.

Повтор після проблеми тільки в automation: `--resume-after-tests` звіряє
SHA-256 усіх build inputs із успішним прогоном; зміна коду/тестів/settings
змушує виконати повний прогін. Це не заміна фінальної регресії CP-04.

## 1. Аудит залежностей

Фактично виконано locked restore та `dotnet package list --vulnerable
--include-transitive --no-restore` у text і JSON форматах. Exit codes — 0.
[Повний вивід з датою та SDK](evidence/lab06-dependency-audit.txt).

| Результат / рішення | Обґрунтування та межі |
|---|---|
| Direct і transitive advisory: **0** | У відповідях налаштованих NuGet sources для API й Tests відомих advisory немає |
| Reachability: advisory-specific N/A | Немає повідомленої advisory, для якої можна було б чесно аналізувати вразливий call path |
| Залишити locked versions | Немає підстав для сліпого оновлення, suppression чи позначення warning як виправленої finding |
| Обмеження | Point-in-time NuGet результат; не доводить відсутність zero-day, проблем Docker/ОС чи зовнішнього CI |

Lockfiles узгоджені зі restore. Джерела та фактичні exit codes —
`checks.dependencies`. Старий пріоритетний package override не вилучено.

## 2. Систематичний огляд секретів

[JSON scope/manifest](evidence/lab06-stage3-secret-review.json) та
[класифікація кожного keyword match](evidence/lab06-stage3-secret-matches.csv)
генеруються `scripts/review_lab06_secrets.py`.

Охоплено current tracked text та окремо визначені planned-release untracked
файли ЛР 6. Untracked не названі tracked. Кожен перевірений файл має SHA-256.
Keyword inventory охоплює password/passwd/secret/API key/SecurityStamp/
connection string/cookie/token, додатково перевіряються signature patterns
та точні поточні runtime значення seed-пароля, cookie, antiforgery і stamp.
Відомі synthetic negative-test markers дозволені у source, але також
перевірені на відсутність в оригінальних журналах.

Класифікація в CSV базується на описаних правилах; додатково переглянуті local
fixtures, runtime secret flow і підозрілі signature matches. Навчальний
DB fallback явно лишається study-only. `.env`, local runsettings, dumps і
logs ignored. Binary Word/PDF, сторонні untracked resources, stash, clones,
зовнішній CI та повна history виключені. Limited configuration-history review
етапу 1 збережено. Відсутність збігів не є абсолютною гарантією відсутності секретів.

## 3. Шість класів log/audit-сценаріїв

| Клас | Фактичний запит / результат | Доказ у початковому журналі |
|---|---|---|
| Успішний login | Alice POST login → 204 | Safe authentication outcome + той самий request TraceId |
| Невдалий login | Неправильний synthetic пароль → 401 | Generic failure, без username/password/body dump |
| Заборонена protected дія | Alice PUT чужого Bob incident → 404 | Request completion status + TraceId; Bob resource не змінено |
| Validation error | POST incident із порожнім title → 400 | Request completion + TraceId; body sentinel відсутній у журналі |
| Unexpected error | Production, тимчасово недоступна loopback БД → 500 | Safe ProblemDetails, response traceId пов’язаний з ExceptionHandlerMiddleware TraceId |
| Привілейований перехід | Reporter triage → 403 без зміни; Analyst → 204, canonical `Triaged` | `incident.triage.denied` та `incident.triage.allowed`: actor/action/resource/result/time/trace |

Для normal log run у дочірньому процесі ввімкнено тільки звичайні request
completion metadata (без body/header logging). Production unexpected run
використовує штатний profile. Перевірено **повні оригінальні console logs**,
включно з exception details, а не лише очищені excerpts. У доказах — SHA-256
джерел, кількість перевірених значень і нульові sensitive-match counts.
Значення паролів, cookie, CSRF-токенів, SecurityStamp та connection string
у звіт і screenshots не потрапляють. Безпечні excerpts і trace correlation —
`checks.log-audit-normal` та `checks.log-audit-unexpected`.

Для успішного triage додано мінімальний audit після commit; наявний denial
audit збережено. Не логуються user input, incident title/description чи model.
Додатково ревокація сеансів пише `success`, `failure`, `rate_limited` без пароля.

## 4. Повна регресія

Актуальний CSRF-периметр (SC-01–SC-07 збережені з етапу 2):

| ID | Method + route | Cookie authorizes? | CSRF / перевірка |
|---|---|---|---|
| SC-01 | POST `/api/incidents` | Так | Standard filter; missing/invalid 400 без зміни, valid 201 |
| SC-02 | PUT `/api/incidents/{id}` | Так | Standard filter; REG-CSRF-01: 400 unchanged → valid 204 changed |
| SC-03 | DELETE `/api/incidents/{id}` | Так | Standard filter; deny не видаляє, owner valid 204 |
| SC-04 | POST `/api/incidents/{id}/triage` | Так | Standard filter; Reporter denied, Analyst valid 204; atomic transition |
| SC-05 | POST `/api/auth/logout` | Так | Standard filter перед SignOut; 400 зберігає сеанс, valid 204 |
| SC-06 | POST `/api/auth/login` | Ні, подані credentials | Anonymous antiforgery exception зі scope-рішенням та residual risk етапу 2 |
| SC-07 | POST `/api/auth/register` | Ні, публічна реєстрація | Те саме scope-рішення етапу 2; fixed server role та strict DTO |
| SC-08 | POST `/api/me/sessions/revoke-all` | Так | Standard filter + repeated password + limiter; 400/403/429 без revoke, valid 204 |

Усі доступні browser cookie mutations охоплено; GET revocation, PATCH/batch
та target-user administration endpoint не додавалися. OpenAPI фактично
звірено: 8 unsafe operations, із них 6 authenticated cookie mutations.

Release build: **0 warnings, 0 errors**. Повний xUnit run: **135/135 passed**,
failed=0, skipped=0. У JSON наведені всі точні test names/outcomes.
[Regression pack з ID та executable selectors](lab-06-regression-pack.md)
охоплює validation, SQLi/query semantics, authentication, authz/IDOR,
REG-XSS-01, REG-CORS-01, REG-CSRF-01, обидва старі limiter та новий password limiter.

Chrome повторює повний REG-CSRF-01 і UI mutations після F5, 4173/4174 CORS,
CSP, cookies та quota isolation/recovery. Оригінальні LR4 scripts виконані
на відновленому seed. При `ValidationInterval=0` PoC порівнює verified subject
замість незмінності байтів cookie; назви старих access-сценаріїв збережені.
Після controlled-error run відновлено нормальний seed, health та browser flow.

## 5. Третя знахідка поза checklist

[F-03](findings/F-03-concurrent-triage.md): два одночасні triage раніше давали
2 × 204 та 2 history records. [Негативний доказ до fix](evidence/lab06-triage-race-before.json)
збережено окремо. Умовне atomic UPDATE + history в одній транзакції дає
204 + 409, один history та canonical `Triaged`. Той самий test-only scheduling
barrier використано до/після; production bypass відсутній.

## 6. Погоджений advanced variant

[Текст відповіді викладача](evidence/lab06-advanced-approval.md) та
[остаточний design/limits](advanced-variant-proposal.md).

POST `/api/me/sessions/revoke-all` захищений authentication, standard CSRF,
повторним `CheckPasswordAsync` і subject-keyed атомарним лімітом 5/2 хв.
Успіх оновлює SecurityStamp та завершує поточний сеанс. Старі cookie Alice
відхиляються на наступному protected GET; Bob не зачіпається. Bob self-revoke
відкликає тільки Bob. Wrong/missing CSRF, wrong password та 429 не відкликають сеанси.

Global additional-data provider бере userId/stamp із claims без додаткового
DB lookup, явно підтримує anonymous; стандартний anonymous issue/validate
round-trip перевірений. Контроль same-user old-token: **без custom provider 204,
з provider 400**, новий token → 204. Ресурс перевірки тут — поточний cookie-сеанс:
при відмові він залишається чинним; звичайний REG-CSRF-01 окремо перевіряє
незмінність incident перед дозволеним PUT.

Вимір 10 warm Production TestServer GET `/api/me`:

| ValidationInterval | SQL commands | Відповіді з поновленим auth cookie | Flags |
|---|---|---|---|
| 30 хв | 10 | 0/10 | Штатні flags перевірено окремим Production cookie test |
| 0 | 60 | 10/10 | На кожному поновленні Secure, HttpOnly, SameSite=Lax |

Фактичні mean/max latency — в `checks.advanced-integration` (`validation-cost`).
Це локальний послідовний warm вимір, не load benchmark. Додаткові 5 SQL reads
на запит пов’язані з Identity validation/rebuilding principal. Ціну прийнято
для погодженого навчального стенда. In-flight запити не скасовуються;
реальний deployment/TLS та multi-instance quotas не перевірялися.

## 7. Знімки та межа завершення

Actual Chrome screenshots — [папка етапу 3](evidence/screenshots/lab06-stage3):
Alice до відкликання, повідомлення після виходу з усіх пристроїв і новий вхід.
Окремо збережені regression/CORS screenshots. Поля паролів на знімках порожні.
Це знімки автоматизованого Chrome, не захоплення Windows Terminal.

Для читабельного показу доказів у терміналі без raw logs:
`powershell -NoProfile -ExecutionPolicy Bypass -File scripts/Show-Lab06Stage3Evidence.ps1 -Section Advanced`.
Доступні також `Tests`, `Dependencies`, `Secrets`, `Logs`, `Triage` та `All`.

CP-04 ще має оформити фінальний review/report, перевірку release state,
merge/tag і спосіб передачі за методичкою. Цей етап не створює `v1.0.0`.
