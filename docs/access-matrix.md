# Матриця контролю доступу SecureLab для ЛР 4

## Призначення та джерела

Це цільовий контракт авторизації спільного baseline 2-A для рівня «Відмінно»,
включно з вимогами нижчих рівнів. Головна protected action -
`GET /api/incidents/{id}` (details/read). Вхідний read-контракт ЛР 5:
власник читає свій інцидент, інший Reporter отримує відмову,
Morgan/Analyst читає інцидент для аналізу.

Джерела: «Методичні рекомендації ЛР 04», теоретичні відомості, §6
«Привілейована дія й контекст рішення» (с. 25-27), практичні кроки 2-3
(с. 37-39), матриця перевірок (с. 52-53), фіксований сценарій (с. 54);
[картка baseline 2-A](variant-02-a.md).

Дата фінального огляду коду: 18.10.2026. Матриця визначає правила, які
реалізовані в endpoint/query-коді; фактичні результати наведено в останній
колонці та [звіті](report-lab-04.md). Позначення A-01 ... A-12 належать до
ЛР 4. Вразливий PoC збережено окремо, а fixed PoC підтверджує контракт.

## Суб'єкт і контекст рішення

- Ідентифікатор користувача береться тільки з verified `HttpContext.User`,
  claim `NameIdentifier`; ролі - із server-issued role claims Identity.
  Header, JSON, query, browser storage та приховані поля форми не є
  джерелом identity або дозволу.
- Власник Incident - `Incident.OwnerUserId`. Для коментаря перевіряється
  власник його батьківського Incident, а не `IncidentComment.AuthorUserId`.
- Таблиця описує кожну роль окремо, як у чотирьох навчальних акаунтів.
  `Administrator` сам по собі не включає права Reporter чи Analyst і не
  має автоматичного обходу ownership. За кількох ролей застосовуються
  лише явно надані ними права, з усіма умовами відповідної операції.
- Рішення використовує verified subject, operation, ресурс із БД та його
  поточний context. Дозвіл читання не дає права змінювати ресурс.
- Reporter читає лише `OwnerUserId == currentUserId`; Analyst читає всю
  множину для аналізу. Окремих tenant або призначення аналітика поточна
  модель не має, тому такі обмеження не вигадуються.

## Матриця прав

`allow` означає конкретний дозвіл за вказаних умов. Успішні status codes
наведено для коректного запиту; валідація, відсутність ресурсу та конфлікт
назви обробляються окремо.

| Дія | Рівень | Анонім | Reporter | Analyst | Administrator | Власник ресурсу має значення? | Стан реалізації |
|---|---|---|---|---|---|---|---|
| Список: `GET /api/incidents` | Добрий | deny, `401`, без redirect | allow, `200`, лише власні інциденти | allow, `200`, усі інциденти для аналізу | deny, `403`; окремого права читання не надано | Так для Reporter; ні для Analyst | Реалізовано через `IncidentAccessRules` і scoped query. Fixed PoC: Alice count=3, `containsBob=false`; tests пройшли. |
| Пошук: `GET /api/incidents/search` | Відмінний | deny, `401`, без redirect | allow, `200`, пошук лише серед власних інцидентів | allow, `200`, пошук серед усіх інцидентів для аналізу | deny, `403` | Так для Reporter; ні для Analyst | Реалізовано в `Lab02Endpoints` зі scope до sort/take/projection. Fixed PoC Alice за назвою Bob: `200`, порожній масив. |
| Зведення: `GET /api/incidents/severity-summary` | Відмінний | deny, `401`, без redirect | allow, `200`, кількості лише за власними інцидентами | allow, `200`, кількості за всіма інцидентами для аналізу | deny, `403` | Так для Reporter; ні для Analyst | Реалізовано зі scope до `GroupBy`. Fixed PoC Alice: Critical=0, High=0, Medium=1, Low=2. |
| Деталі: `GET /api/incidents/{id}` | Достатній; головна action та entry-контракт ЛР 5 | deny, `401`, без redirect | owner: allow, `200`, без internal comments; non-owner: deny, `404` | allow, `200`, будь-який наявний інцидент; internal comments лише після дозволу на parent | deny, `403` | Так для Reporter; ні для Analyst | Реалізовано. Fixed PoC підтвердив Alice own `200`, Alice/Bob foreign і missing однакові `404`, Analyst `200`, anonymous `401`. |
| Створення: `POST /api/incidents` | Успадкований baseline ЛР 3 | deny, `401`, без redirect | allow, `201`, лише від власного імені | allow, `201`, лише від власного імені | deny, `403`; окремого права створення для цієї ролі не надано | Нового owner визначає сервер із principal | Реалізовано server-side owner і явну рольову перевірку; Admin deny покрито regression test. |
| Зміна content: `PUT /api/incidents/{id}`; лише `title`, `description` | Добрий; окрема mutating operation | deny, `401`, без redirect | owner: allow, `204`, лише content; non-owner: deny, `404` | deny, `403`, навіть для власного інциденту; роль аналізу не дає content update | deny, `403` | Так для Reporter; для Analyst ownership не надає цього права | Реалізовано. Fixed PoC: foreign `404` без зміни Bob, owner update пройшов, protected fields `400` без зміни стану. |
| Видалення: `DELETE /api/incidents/{id}` | Добрий; mutation perimeter | deny, `401`, без redirect | owner: deny, `403`; non-owner: deny, `404` | deny, `403` | deny, `403` | Ownership визначає видимість parent, але не дає права delete | Реалізований deny endpoint. Fixed PoC підтвердив owner `403`, foreign Reporter `404`, без mutation. |
| Зміна стану: `POST /api/incidents/{id}/triage` | Добрий; privileged action | deny, `401`, без redirect | власний інцидент: deny, `403`, навіть у `New`; чужий: deny, `404` | allow, `204`, тільки якщо поточний status із БД - `New`; сервер встановлює лише `Triaged`; інший status: deny, `403` | deny, `403`, навіть для `New` | Для Reporter - видимість parent; для дозволу Analyst ownership не потрібне, потрібен `New` | Реалізовано. Fixed PoC: Reporter `403`, Analyst `New -> Triaged`; denied audit з корельованим traceId пройшов. |
| Звичайний коментар: `GET /api/incident-comments/{id}`, `IsInternal == false` | Добрий; child resource | deny, `401`, без redirect | власний parent: allow, `200`; чужий parent: deny, `404` | allow, `200`, тільки після дозволу на читання parent | deny, `403` | Так, за власником parent, не за автором коментаря | Реалізовано через parent access decision; fixed child PoC пройшов. |
| Internal comment: той самий child endpoint або comments у details, `IsInternal == true` | Добрий | deny, `401`, без redirect | direct child власного parent: deny, `403`; чужого parent: deny, `404`; у дозволених details internal comment не включається в response | allow, `200`, після дозволу на parent; однаково для details-проєкції та direct child | deny, `403` | Для видимості parent - так; ownership не дає Reporter права на internal text | Реалізовано в details і direct child: Reporter не бачить internal text, Analyst бачить після parent decision; fixed child PoC пройшов. |

### Обґрунтування обраних правил

Reporter редагує Title і Description власного інциденту. Додаткової заборони
за статусом тут немає: канонічне правило Incident її не встановлює.
Умови бібліотечного прикладу щодо активного/поверненого замовлення на
Incident не переносяться. Analyst має читання та лише `New -> Triaged`,
а не право довільно змінювати content чи видаляти.

Delete заборонено всім, оскільки явного права не опубліковано. DELETE endpoint
існує лише для єдиної, перевірюваної HTTP-відмови; він не замінює позитивну
перевірку дозволеного owner update.

Export/audit-read flow у матрицю не додається: відповідних маршрутів або
опублікованих прав у застосунку немає. Створювати такий flow заради
матриці не потрібно. Це **не скасовує** structured audit denied triage.
Назва Administrator не є дозволом на читання журналів.

## Політика HTTP-відмов

Для головної action `GET /api/incidents/{id}` обрано **404**, якщо
authenticated Reporter не є власником запитаного інциденту. Наприклад,
Alice з чинною cookie при зверненні до інциденту Bob має одержати ту саму
безпечну відповідь, що й для неіснуючого коректного GUID. На відміну від
`403`, такий контракт не підтверджує клієнтові існування чужого ресурсу.
Це правило для non-owner **без права читати чужі ресурси**, а не заборона
всім non-owner: Morgan/Analyst має явно надане право читання для аналізу
та одержує `200` для наявного інциденту незалежно від ownership.

1. **401 Unauthorized** - немає чинного authentication principal.
   Захищений API не повертає `302` або HTML-сторінку входу.
2. **404 Not Found** - коректно сформований запит Reporter до чужого
   incident або його child; така сама відповідь, як для неіснуючого
   incident/child. Це зменшує disclosure існування чужого ресурсу.
   Політика однакова для details, update, delete, child та triage.
   Відмова не містить чужий owner, title, description, текст коментаря
   або окрему причину «чужий ресурс».
3. **403 Forbidden** - parent доступний, але operation не дозволена:
   Reporter-owner виконує triage; Analyst змінює content або намагається
   перевести не-New інцидент; Reporter-owner читає internal child.
   Для суб'єкта лише з Administrator відмова через відсутність права
   не має залежати від існування ID.
4. **400 Bad Request** - некоректний контракт. Для regular update
   обрано **A-08b**: невідомі JSON-поля, зокрема `ownerUserId`, `role`,
   `status`, `severity`, `id` і службовий час, явно відхиляються з `400`.
   Захищений state не змінюється. Синтаксична валідація не замінює
   перевірку ownership.
5. У A-10 чужий та неіснуючий коректні GUID дають однакові `404`,
   `application/problem+json` і стабільне тіло після вилучення `traceId`
   та `requestId`. Кореляційні поля між запитами можуть відрізнятися.
   Ідентифікатор чужого owner та захищені дані не потрапляють у відповідь.
6. Список, пошук і зведення за дозволеної ролі повертають `200` навіть
   без доступних записів: порожня дозволена множина або нульові counts.
   Owner scope застосовується в БД **до** сортування, `Take`, проєкції
   та `GroupBy`; чужі інциденти не включаються навіть у лічильники.
   Пошук Reporter за текстом, який є лише в чужому інциденті, повертає
   `200` з порожнім масивом, а не `404`. Severity-summary містить кількості
   лише власних записів Reporter. Для Analyst обидві операції охоплюють
   усі дозволені йому інциденти. Це окремі перевірки A-11.

Узгодженість для рівня «Відмінно»: однакове приховування чужого ресурсу
застосовується до details, update, delete та direct child (за власником
parent); список, search і severity-summary не розкривають його через
результати чи агрегати. Самого коду `404` недостатньо: потрібні серверне
рішення доступу, однаковий безпечний response і відсутність mutation після
відмови. Контракт не гарантує однакового часу виконання запитів.

**Стан пункту 3:** політику застосовано в endpoint/query-коді. Fixed PoC
підтвердив A-10/A-11, а [звіт](report-lab-04.md) зберігає окремі vulnerable і
fixed докази. `404` для foreign перевіряється разом з таким самим `404` для
missing та відсутністю mutation.

## Межі mutation та privileged action

- Create зберігає чотири поля baseline: `title`, `description`, `severity`
  як текстове ім'я enum і `occurredAtUtc` типу `DateTimeOffset?` з UTC
  нормалізацією. Id, owner, `Status = New` та службовий час визначає сервер.
  Початковий вибір severity не дає права змінювати severity наявного запису.
- Для create зберігається контракт ЛР 3: зайвий `ownerUserId` ігнорується
  та не впливає на фактичного власника. A-08b для update не застосовується
  глобально до всіх request DTO.
- Update дозволяє лише Title і Description; owner, severity, status та
  ідентифікатор не змінюються. Службовий час оновлює тільки сервер.
  Зберігаються правила content-валідації ЛР 2 з використанням поточної
  severity та інших потрібних полів із БД.
- Triage - окрема операція `POST /api/incidents/{id}/triage`.
  Дозвіл: роль Analyst із principal та поточний status New із БД.
  Наступний status встановлює сервер: тільки Triaged. Reporter не отримує
  цього права навіть як owner. Жодні role, owner, protected status або
  `isTransitionAllowed` із request не є аргументом надання дозволу.
- Авторизація передує mutation tracked entity та `SaveChangesAsync`.
  У негативних mutation-тестах порівнюється стан до/після: content,
  owner, severity, status і пов'язані записи history. У A-08b стан має
  залишитися незмінним; A-08a як альтернативний контракт не обирається.
- Role claims фіксуються під час login. У тесті роль призначається до
  входу; зміна ролі в БД зі старою cookie не доводить нових прав.

## Дочірній ресурс та internal comments

Child resource - `IncidentComment`, parent - `Incident` через
`IncidentComment.IncidentId`. Канонічний маршрут -
`GET /api/incident-comments/{id}`.

Порядок рішення: authentication -> parent read scope -> право бачити вид
коментаря -> safe response. Вибір child лише за його id без parent scope
неприпустимий. Для Reporter дозволені details не включають internal text;
для Analyst internal comments дозволені після перевірки parent. Правило
однакове у details-проєкції й direct child endpoint, а не тільки в UI.

Контрольні синтетичні ресурси:

- incident Alice: `20000000-0000-0000-0000-000000000001`;
- incident Bob: `20000000-0000-0000-0000-000000000002`;
- звичайний коментар Morgan до incident Bob:
  `30000000-0000-0000-0000-000000000002` - A-12. Це не коментар,
  написаний Bob; доступ визначається через incident Bob;
- потрібний internal comment до incident Alice:
  `30000000-0000-0000-0000-000000000003`, автор Morgan, `IsInternal = true`.
  Запис визначено в `DbSeeder.AliceInternalCommentId`. Його зв'язки та
  `IsInternal` перевіряє `Seed_IncludesFixedInternalCommentByMorganForAliceIncident`.
  Наявність у БД, endpoint і role-aware проєкцію підтверджують regression
  tests та [fixed PoC](evidence/lab04-fixed.txt) від 18.10.2026.

## Audit denied triage

Для authenticated deny privileged action потрібна structured подія
`authorization.denied`: verified `SubjectId`, фіксована `Action =
Incident.Triage`, `ResourceId`, `Result = denied`, серверний `OccurredAtUtc`
та `TraceId`. ResourceId є посиланням на ресурс, а не доказом права.

TraceId береться з `Activity.Current?.Id ?? httpContext.TraceIdentifier`
і збігається з traceId безпечної відповіді цього самого запиту. Подія не
містить password, cookie, token, повного body, stack trace або тексту
інциденту. Role/resource decision для такого audit має бути доступний
  усередині операції, а не тільки в декларативній role policy, яка не
  запускає код endpoint. Реалізація логує подію і fixed PoC підтвердив
  кореляцію traceId для A-09.

## Межі поточного кроку

Матриця підтверджена fixed PoC і 97 regression tests. Контрольований
вразливий PoC збережено окремо, щоб показати початковий дефект. Позитивні
mutation-тести створюють власні тимчасові записи та прибирають їх, не
змінюючи сталі seed-ресурси.

CSRF teaching debt cookie-authentication із ЛР 3 залишається:
SameSite=Lax не є повним CSRF-захистом. Ownership і role authorization
цього боргу не усувають.
