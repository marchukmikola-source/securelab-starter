# Звіт до лабораторної роботи № 03 — SecureLab

**Тема:** безпечна реєстрація, cookie-автентифікація та серверний owner

## 1. Ідентифікація стану

- **Студент:** Марчук Микола Васильович, КБ-41 [23].
- **Варіант:** 2-A «Трекер інцидентів».
- **Базовий стан:** тег `v0.2.0`, commit `f52d1bb149044e2e83ebf0cad5c94a0767ef5d3a`.
- **Стартовий scaffold:** `lab-03-start-v1`.
- **Змінені ділянки:** Identity-модель і міграція, auth endpoint-и, DTO,
  захищене створення інциденту, browser demo, інтеграційні тести й докази.

Секрет для локальних навчальних акаунтів передається тільки змінною середовища
`SeedUsers__Password`. Його значення не записується в Git, у тестові дані,
відповіді, логи або цей звіт.

### Відтворюваність попередньої лабораторної

ЛР-02 завершена на базовому тегу `v0.2.0`. Щоб відтворити її локальний стан,
потрібно підняти навчальну PostgreSQL командою `docker compose --env-file
infra/.env.example -f infra/compose.yaml up -d --wait`, передати локальний
`SeedUsers__Password` лише в поточний процес PowerShell та виконати
`dotnet run --project src/SecureLab.Api -- --reset-database`. ЛР-03 зберігає
цей доменний стан і додає Identity, cookie-автентифікацію та захист owner.

## 2. Реалізація

### Реєстрація

`POST /api/auth/register` приймає окремий `RegisterUserRequest`: `userName`,
`email`, `displayName`, `password`. До створення облікового запису сервер
перевіряє обов'язковість, довжини, допустимі символи і формат email. Пароль
передається незміненим у `UserManager.CreateAsync(user, password)`; власний
алгоритм хешування не реалізовується.

Успішний результат — `201 Created` з `RegisteredUserResponse`:

```json
{ "id": "<server-generated-guid>", "userName": "…", "displayName": "…" }
```

У response навмисно немає `password`, `passwordHash`, `securityStamp`, email,
ролей, cookie або токенів. Невалідний contract повертає `400`, а дубльоване
ім'я чи email — послідовний `409` з `ValidationProblemDetails` без внутрішніх
кодів Identity. Новому користувачеві сервер призначає фіксовану роль `Reporter`.
Як перше обране поглиблення, contract реєстрації відхиляє невідомі JSON-поля,
зокрема client-supplied `role` або `id`, з `400` до створення облікового запису;
ця політика застосована лише до register DTO, а не глобально.

### Вхід, cookie, profile і logout

`POST /api/auth/login` викликає `SignInManager.PasswordSignInAsync`. Для
відомого користувача з неправильним паролем і для невідомого імені повертається
однакова відмова `401`, тому API не підтверджує існування акаунта через статус
або форму помилки.

Identity створює application cookie. Вона має `HttpOnly` і `SameSite=Lax`; у
Production діє `Secure=Always`, а в Development — `SameAsRequest`, щоб
локальний навчальний HTTP-стенд міг працювати. Для API unauthorized/forbidden
cookie handler повертає JSON `401`/`403 Problem Details`, а не redirect чи
bearer challenge.

`GET /api/me` вимагає авторизацію. Сервер бере лише `NameIdentifier` з
перевіреного `HttpContext.User`, шукає відповідний профіль і повертає лише
`id`, `userName`, `displayName`. Довільні заголовки, наприклад
`X-Demo-UserId`, не впливають на principal. `POST /api/auth/logout` робить
`SignOutAsync`; наступний `/api/me` повертає `401`.

### Захищена операція і owner

`POST /api/incidents` має `.RequireAuthorization()`. Після DTO validation
server-side код читає `ClaimTypes.NameIdentifier`, перетворює його на `Guid` і
сам встановлює `Incident.OwnerUserId`. Request DTO не дозволяє передавати
`ownerUserId`, role, status, internal id або timestamp створення. Додаткове
клієнтське JSON-поле owner і довільні headers ігноруються, тому Bob не може
створити інцидент від імені Alice.

### Rate limit і безпечні auth-події

Для `POST /api/auth/login` реалізовано локальний in-memory ліміт: максимум
5 невдалих спроб у ковзному вікні 2 хвилини на IP-розділ. Шоста спроба повертає
`429 application/problem+json`. Ключ не містить user name; отже ліміт не
створює окремого каналу для перевірки існування акаунта.

Логуються лише фіксовані outcome-події: `login succeeded`, `login failed`,
`login rate limited`, `logout completed`. Не логуються password, cookie, token,
user name або їхні хеші. IP-поділ є навчальним компромісом: він стримує спроби
з одного клієнта, але може зачепити користувачів за NAT і не зупиняє розподілену
атаку. За reverse proxy потрібно окремо налаштувати trusted forwarded headers.

## 3. Маршрути довіри

### Register

`JSON request` → `RegisterUserRequest` → server validation →
`UserManager.CreateAsync` → Identity store → `RegisteredUserResponse`.

Пароль присутній тільки в request та в виклику `UserManager`; він не стає
полем response. Identity зберігає службовий `PasswordHash`, але хеш не
обчислюється вручну, не читається для API й не показується в доказах.

### Login і owner

`JSON login request` → `PasswordSignInAsync` → Identity password verification
→ cookie з атрибутами → браузер автоматично надсилає cookie лише за правилами
browser policy → authentication middleware → claims у `HttpContext.User` →
`NameIdentifier` → `Incident.OwnerUserId` на сервері.

Тому значення з форми, JavaScript, hidden input або заголовка не є джерелом
ідентичності. У browser demo застосовано same-origin `fetch` з credentials,
`textContent` для UI і відсутній запис облікових даних або principal у
`localStorage`, `sessionStorage` чи Console.

## 4. Матриця перевірок

| ID | Перевірка | Очікуваний безпечний результат | Фактично (2026-10-11) | Автоматичний доказ |
|---|---|---|---|---|
| T-01 | Коректний register | `201`, лише `id`, `userName`, `displayName` | Пройшло у full regression; browser flow повідомив лише про завершену реєстрацію. | `RegistrationContractTests` |
| T-02 | Невалідний та повторний register | `400`; для duplicates — `409` з однаковим контрактом | Пройшло у full regression `56/56`. | `RegistrationContractTests` |
| T-03 | Зберігання password | немає plaintext-поля чи password/hash у response | Перевірено contract-тестом і CP-01; чутливі поля не повертаються. | код Identity + CP-01 |
| A-01 | Анонімний create | `401 problem+json`, без redirect/challenge | Пройшло у full regression `56/56`. | `IncidentOwnershipSecurityTests` |
| A-02 | login → `/api/me` | principal тільки з cookie; safe profile | Пройшло у full regression; вручну показано лише safe profile. | `CurrentUserEndpointTests` |
| A-03 | Чужий `X-Demo-UserId` | ігнорується | Пройшло у full regression `56/56`. | `CurrentUserEndpointTests` |
| A-04 | Bob без owner | owner = Bob | Пройшло у full regression `56/56`. | `IncidentOwnershipSecurityTests` |
| A-05 | Bob передає owner Alice | owner усе одно Bob | Пройшло у full regression `56/56`. | `IncidentOwnershipSecurityTests` |
| A-06 | logout → `/api/me` | `204`, потім `401` | Пройшло у full regression; вручну після logout — «Не ввійшли». | `CurrentUserEndpointTests` |
| A-07 | wrong password / unknown user | однаковий безпечний `401`-контракт | Пройшло у full regression `56/56`. | `CurrentUserEndpointTests` |
| S-01 | Лімітер і auth-події | 5×`401`, 6-та `429`, recovery; лише safe outcomes | Пройшло у full regression `56/56`. | `AuthenticationProtectionTests` |

Докази контрольних точок: [CP-01](lab-03-cp-01-evidence.md),
[CP-02](lab-03-cp-02-evidence.md), [CP-03](lab-03-cp-03-evidence.md) і
[rate limit / auth events](lab-03-rate-limit-evidence.md). Вони містять лише
статуси та безпечні структури результатів.

## 5. Ризики та обрані компроміси

- **User enumeration.** Login умисно не відрізняє unknown user від wrong
  password. Register повертає поле duplicate (`409`), бо це кращий UX для
  створення акаунта, але воно розкриває зайнятість name/email. У production це
  рішення варто переглянути для публічного register і доповнити захистами.
- **CSRF.** `SameSite=Lax` зменшує ризик міжсайтового надсилання cookie, але не
  є повноцінним захистом усіх state-changing сценаріїв. Для наступної роботи
  лишається explicit CSRF-захист: antiforgery token та/або перевірка Origin для
  cookie-authenticated write endpoint-ів.
- **Локальний rate limit.** Він навмисно простий і достатній для одного
  навчального інстанса. Для кількох інстансів потрібен спільний storage та
  policy для proxy/NAT.

### Поглиблення 2: короткий threat analysis

| Елемент | Аналіз |
|---|---|
| Активи | Облікові дані, application cookie, профіль поточного користувача та ownership інцидентів. |
| Entry points | `POST /api/auth/register`, `POST /api/auth/login`, `GET /api/me`, `POST /api/incidents`, browser forms. |
| Межі довіри | Браузер → API; JSON DTO → серверна доменна модель; Identity cookie → claims; API → PostgreSQL. |
| Реалістична загроза | Авторизований Bob додає в create JSON `ownerUserId` Alice, щоб підмінити власника ресурсу. |
| Контрзахід | Owner не входить до DTO: сервер встановлює його тільки з `NameIdentifier` перевіреного cookie principal; A-05 перевіряє це регресійно. |
| Залишковий ризик | Cookie write endpoint-и до ЛР-06 ще потребують explicit CSRF-захисту; IP rate limit не захищає від розподілених спроб. |

## 6. Фінальна перевірка перед поданням

У поточному PowerShell, де локальна `SeedUsers__Password` була задана лише для
процесів застосунку й тестів, виконано:

```powershell
docker compose --env-file infra/.env.example `
  -f infra/compose.yaml up -d --wait
dotnet run --project src/SecureLab.Api -- --reset-database
dotnet build tests/SecureLab.Api.Tests -c Release
dotnet test tests\SecureLab.Api.Tests\SecureLab.Api.Tests.csproj -c Release --no-build
```

PostgreSQL-контейнер був healthy. Два послідовні `--reset-database` завершилися
успішно з однаковим повідомленням про очищення й повторний seed; після
ручного сценарію виконано ще один final reset, тому в локальній БД лишився
лише відтворюваний seed-стан. Build завершився з `0 Warning(s), 0 Error(s)`.
Фінальний повний інтеграційний прогін: **56 passed, 0 failed, 0 skipped**.

Ручний same-origin browser flow на локальному стенді підтвердив п'ять
спостережень: (1) до входу — «Не ввійшли»; (2) register завершився успішно;
(3) після login — активний сеанс і лише safe поля `/api/me`; (4) створено
інцидент без client-supplied owner; (5) після logout — «Не ввійшли» і профіль
очищено. У доказ не внесено password, cookie, hash, token, database dump або
їх значення.

## 7. Чекліст перед поданням

### Для всіх рівнів

- [x] У звіті явно описано завершений стан ЛР-02 і команди його відтворення.
- [x] Використано стандартні Identity + EF Core + application cookie; немає
  власного hash, JWT або другого user store.
- [x] `ApplicationUser : IdentityUser<Guid>` є єдиним поточним user store;
  доменні FK лишилися `Guid` і посилаються на `ApplicationUser`.
- [x] Seeder визначає Alice, Bob, Morgan і Admin; Alice/Bob мають власні
  навчальні інциденти, а Admin має привілейовану роль.
- [x] Два послідовні `--reset-database` фактично виконано й підтверджено.
- [x] Register/login response не містять password, hash, cookie, token або
  службові поля Identity.
- [x] `/api/me` і create endpoint беруть користувача лише з verified principal.
- [x] Request DTO не приймають owner, role, id, status або інший server-managed
  стан; register additionally відхиляє невідомі JSON-поля.
- [x] A-01, A-02 і A-05 автоматизовано; A-05 виконується від Bob із forged
  owner Alice.
- [x] T-01, T-02, T-03 та S-01 мають тести й безпечні CP-докази.
- [x] У звіті описано CSRF teaching debt та межі `SameSite=Lax`.
- [x] Повний build та інтеграційні тести після останньої зміни успішно
  виконано й внесено фактичний результат.
- [x] Перевірка Git diff і звіту не виявила переданого локального seed-secret,
  cookie value, token, dump або diagnostic log із credentials.
- [x] Перевірений підсумковий commit і анотований тег `v0.3.0` створено.
- [x] Додано декларацію або журнал використання ШІ.

### Додатково для «Добре» та «Відмінно»

- [x] A-03, A-04, A-06 і A-07 автоматизовано; duplicate-контракт має
  регресійні тести.
- [x] Cookie flags перевіряються HTTPS-тестом без збереження cookie value.
- [x] 429, відновлення після вікна, IP partition key і safe auth-події
  реалізовано та покрито тестами.
- [x] Власний browser flow фактично пройдено вручну; п'ять спостережень
  зафіксовано в DEL-02.

### Додатково для «Відмінно»

- [x] Обрано й описано два поглиблення: strict register JSON contract і
  threat analysis із активами, межами довіри, контролем та residual risk.

## 8. Декларація використання ШІ

Під час ЛР-03 використано Codex як інструмент для аналізу вимог, перевірки
реалізації, підготовки тестів і структурування звіту. Власник роботи виконав
локальні команди, переглянув безпечні результати browser flow і відповідає за
подану реалізацію та наведені фактичні результати.
