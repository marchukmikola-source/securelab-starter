# Звіт до лабораторної роботи № 2

**Дисципліна:** Прикладні технології програмування в інформаційній безпеці  
**Тема:** Контракт API, серверна валідація та захист від SQL injection  
**Варіант:** 2-A «Трекер інцидентів»  
**Студент:** Марчук Микола Васильович, група КБ-41  
**Викладач:** Бабенко Юрій Михайлович  
**Рік:** 2026

## 1. Ідентифікація виконаного стану

| Параметр | Значення |
|---|---|
| Репозиторій | `https://github.com/marchukmikola-source/securelab-starter.git` |
| Робоча гілка | `lab/2-input-sqli` |
| Базовий тег | `v0.1.0` |
| Наданий стартовий стан | `lab-02-start-v1` |
| Vulnerable commit | `3b96592f258cd82edb3a98031dc61eb1f8fc28e6` |
| Fixed commit | `0816f92926105420dfc11ce7fb721b311b2c976a` |
| Поточний commit із доповненими тестами | `760ac9446803f9fdf2fa163d61566eb3eb051ee6` |
| Локальний стенд | Development, PostgreSQL у Docker, штучні seed-дані |
| Фінальний тег | `v0.2.0` ще не створено; його потрібно поставити на commit зі звітом після фінальної перевірки |

Мета роботи - реалізувати безпечний контракт створення інциденту, відтворити в контрольованому локальному середовищі дефект SQL injection у пошуку, усунути його першопричину та перевірити регресії.

## 2. Контракт створення інциденту і серверна валідація

`POST /api/incidents` приймає окремий `CreateIncidentRequest` з полями `Title`, `Description`, `Severity` і `OccurredAtUtc`. Поля, якими керує сервер (`Id`, `OwnerUserId`, `Status`, `CreatedAtUtc`, `UpdatedAtUtc`), у request DTO відсутні. Після перевірки сервер створює entity, встановлює `Status = New` і повертає обмежений `CreatedIncidentResponse` зі статусом `201 Created`.

| Правило | Реалізація та результат |
|---|---|
| `title` | Обов'язковий, не довший за 160 символів; перед збереженням нормалізується через `Trim()`. |
| `description` | Обов'язковий, не довший за 4000 символів; нормалізується через `Trim()`. |
| `severity` | `Enum.TryParse` разом із `Enum.IsDefined`; приймаються лише `Low`, `Medium`, `High`, `Critical`. |
| `occurredAtUtc` | Обов'язкове значення; не допускається час більш ніж на 5 хвилин у майбутньому від UTC-часу сервера. |
| Cross-field правило 2-A | Для `High` і `Critical` нормалізований опис має містити щонайменше 40 символів. |
| Предметний конфлікт | Однаковий нормалізований `title` блокується для інцидентів у станах `New`, `Triaged`, `InProgress`, `Resolved`; відповідь - `409 Problem Details`. |
| Додаткове правило T-10 | `description` після `Trim()` не може повністю дублювати `title`; порушення повертає `400` з ключем `errors.description`. |

**CP-01.** Перевірка `severity = "7"` повертає `400 application/problem+json` із ключем `errors.severity`. Це підтверджує, що форматна й доменна перевірки виконуються на сервері, а не покладаються на HTML-клієнт. Успішна відповідь не містить `ownerUserId`, `description` або audit-полів.

Докази: `tests/SecureLab.Api.Tests/IncidentCreationContractTests.cs`, `tests/http/incidents.http`.

## 3. Security-сценарій SQL injection

### Контекст і гіпотеза

Endpoint `GET /api/incidents/search` отримує недовірені параметри `q` і `sortBy`. У vulnerable стані існував ризик, що значення `q` потрапить до структури SQL-запиту, а не буде передане як параметр.

### Стан до виправлення

На commit `3b96592f258cd82edb3a98031dc61eb1f8fc28e6` у `Scaffolding/Lab02Endpoints.cs` параметр `q` приєднувався до рядка SQL, який передавався у `FromSqlRaw`. Це створювало шлях: HTTP query parameter -> конкатенація SQL -> `FromSqlRaw` -> PostgreSQL.

### Мінімальний контрольний сценарій і спостереження

Було використано лише власний локальний read-only сценарій S-01 з `tests/http/lab-02-search.http`; його повний рядок у звіт не включено. На vulnerable commit сценарій повернув `200 OK` і небажано розширену вибірку з п'яти seed-записів замість порожнього результату. Звичайний пошук `USB` повернув один запис із ідентифікатором, що закінчується на `...0005`. Легітимний пошук зі звичайним апострофом на vulnerable стані повертав `500`, що також вказувало на некоректну обробку значення в SQL-тексті.

**CP-02.** Першопричину локалізовано у поєднанні значення `q` з SQL-текстом до виконання запиту. Контрольний сценарій не містив команд зміни даних, DDL або stacked statements.

### Виправлення

У fixed commit пошук переписано на LINQ і `EF.Functions.ILike`. Значення `q` перетворюється тільки на значення шаблону пошуку, а EF Core передає його параметром. Метасимволи LIKE (`%`, `_`, `\\`) екрануються, тому клієнт не керує wildcard-структурою запиту.

Для `sortBy` реалізовано allowlist: `createdAtUtc`, `severity`, `status`. Значення поза списком відхиляється до доступу до даних з відповіддю `400 application/problem+json` і `errors.sortBy`.

### Retest і позитивна регресія

Після виправлення той самий контрольний read-only сценарій S-02 повернув `200 OK` і точну порожню множину `[]`. Звичайний пошук `USB` повертає тільки seed-інцидент `...0005`, а легітимний апостроф - тільки seed-інцидент `...0003`, без `500`. Додатково перевірено, що знак `%` трактується як буквальний символ, а не клієнтський wildcard.

**CP-03.** Виправлення усуває саме механічну причину дефекту: користувацьке значення більше не стає SQL-синтаксисом. Allowlist окремо закриває ризик динамічного вибору структури сортування.

Докази: `tests/SecureLab.Api.Tests/SearchMechanicsTests.cs`, `tests/http/lab-02-search.http`, `docs/lab-02-vulnerable-observations.md`, `docs/lab-02-security-audit.md`.

### Залишковий ризик

Ця перевірка не замінює авторизацію, обмеження ресурсу, пагінацію, аудит інших endpoint або production-політику журналювання. Вона доводить лише безпечну обробку контрольованого входу для реалізованого маршруту пошуку.

## 4. Матриця фактичних перевірок

| ID | Сценарій | Фактично | Доказ |
|---|---|---|---|
| T-01 | Коректне створення | `201 Created`; відповідь містить server-assigned `status = New` і не повертає `ownerUserId`. | `IncidentCreationContractTests`, `incidents.http` |
| T-02 | Некоректний DTO | Обов'язкові поля, надмірна довжина, `severity = "7"`, відсутня або надто майбутня дата повертають `400 application/problem+json` з відповідним ключем у `errors`. | `IncidentCreationContractTests`, `incidents.http` |
| T-03 | Предметний конфлікт | Повторне створення активного інциденту з тим самим нормалізованим `title` повертає `409 Problem Details`. | `IncidentCreationContractTests`, `incidents.http` |
| S-01 | SQLi до fix | Локальний read-only контрольний сценарій на vulnerable commit повернув `200` і 5 seed-записів замість порожньої вибірки. | `lab-02-vulnerable-observations.md` |
| S-02 | Retest SQLi | Той самий сценарій на fixed стані повернув `200` і `[]`; автоматизований тест перевіряє точну порожню множину ID. | `Search_WithControlledReadOnlyInput_ReturnsNoMatches` |
| T-04 | Позитивна регресія | `USB` -> тільки `...0005`; пошук з апострофом -> тільки `...0003`; обидва запити повертають `200`. | `SearchMechanicsTests`, `lab-02-search.http` |
| T-05 | Невідоме сортування | `sortBy=unknown` повертає `400 application/problem+json`, `errors.sortBy`; SQL, stack trace і connection string у body відсутні. | `Search_WithUnsupportedSortBy_Returns400ProblemDetails` |
| T-06 | Ресурс не знайдено | Коректний відсутній GUID повертає `404 Problem Details` без внутрішніх деталей. | `IncidentEndpointTests` |
| T-09 | Cross-field правило | `High`/`Critical` з 39 символами після `Trim()` -> `400 errors.description`; 40 символів -> `201 Created`. | `IncidentCreationContractTests`, `incidents.http` |
| T-10 | Додаткове правило | Однакові після `Trim()` `title` і `description` -> `400 errors.description`; опис із додатковими фактами -> `201 Created`. | `IncidentCreationContractTests`, `incidents.http` |

## 5. A-01 Огляд точок доступу до даних

| Місце | Категорія | Висновок |
|---|---|---|
| `Application/Incidents/IncidentQueries.cs` | EF Core LINQ | `Where`, `Select`, `GroupBy` працюють із параметризованими значеннями; конкатенації SQL немає. |
| `Scaffolding/Lab02Endpoints.cs`, пошук | LINQ + `EF.Functions.ILike` | `q` є лише значенням параметра; LIKE-метасимволи екрануються; `sortBy` обмежений allowlist. |
| `Scaffolding/Lab02Endpoints.cs`, створення | EF Core `AnyAsync`, `Add`, `SaveChangesAsync` | Нормалізований `title` використовується як значення предиката, а не SQL-текст. |
| `Data/DbSeeder.cs`, `Scaffolding/Lab02Seed.cs` | Seed через EF Core | Використовуються статичні навчальні дані; HTTP-ввід відсутній. |
| `Data/DatabaseBootstrap.cs` | Константний raw SQL | `TRUNCATE` застосовується лише для дозволеного Development reset, а текст не формується з клієнтського вводу. |
| EF migrations | Згенеровані команди | Runtime HTTP-ввід не потрапляє до raw SQL. |

Пошук `FromSqlRaw`, `ExecuteSqlRaw`, `$"SELECT`, `+ query` і `ORDER BY` у `src` та `tests` підтвердив відсутність runtime-місця, де HTTP input формується як SQL-структура. Єдиний raw-SQL виклик є константним Development-only reset.

## 6. A-02 Захист від mass assignment

Ризик mass assignment заблоковано контрактом. `CreateIncidentRequest` не містить `Id`, `OwnerUserId`, `Status` або audit-полів. Навіть якщо клієнт передає зайві JSON-поля, сервер не читає їх із DTO: сам генерує ідентифікатор, встановлює власника, `Status = New` і часові поля.

Тест `Create_HighWith40CharactersAfterTrim_Returns201AndUsesServerFields` надсилає `ownerUserId` і `status = Closed`, але перевіряє, що відповідь має `status = New` і не містить `ownerUserId`. Отже, клієнт не може призначити собі власника або закритий статус через endpoint створення.

## 7. Висновок

У лабораторній роботі реалізовано окремий контракт створення інциденту з server-side валідацією, бізнес-правилами та безпечними Problem Details. Контрольований дефект SQL injection було локалізовано у поєднанні `q` із SQL-текстом на vulnerable commit. Після переходу до LINQ, параметризованого `ILike`, екранування LIKE-метасимволів і allowlist для `sortBy` той самий сценарій перестав змінювати логіку пошуку, а легітимні сценарії залишилися працездатними. Окремо перевірено захист від mass assignment і всі точки runtime-доступу до даних.

## 8. Декларація використання ШІ

Під час оформлення звіту використано Codex. Завданням було структурувати звіт за методичними рекомендаціями, зіставити розділи з наявною реалізацією, Git-історією, тестами та зафіксованими локальними спостереженнями. Текст адаптовано до фактичного стану проєкту: вказано наявні commits, поточну гілку, результати контрольних сценаріїв і відсутність фінального тегу. Перед оформленням перевірено код маршрутів, тестові сценарії, документи A-01/A-02/CP-03 та Git-стан репозиторію.
