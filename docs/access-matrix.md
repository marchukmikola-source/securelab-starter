# Матриця контролю доступу SecureLab для ЛР 04

Дата фінального огляду: 18.10.2026. Матриця охоплює лише маршрути, що були в
cumulative state на vulnerable commit `390bc04`. Нових endpoint-ів для ЛР 04
не створено.

## Контекст рішення

- Subject береться тільки з verified `HttpContext.User` claim
  `NameIdentifier`; ролі — з server-issued role claims Identity.
- Власник Incident — `Incident.OwnerUserId`. Ідентифікатор із URL визначає
  ресурс для завантаження, але ніколи не є доказом права доступу.
- Reporter має owner-only read і update. Analyst читає всі Incident для
  аналізу, але не змінює content. Administrator не має автоматичних прав.
- Для рядків list/search/summary owner scope накладається в SQL до
  сортування, `Take`, проєкції та `GroupBy`.

## Матриця прав

| Дія | Рівень | Анонім | Reporter | Analyst | Administrator | Owner має значення? | Стан реалізації та доказ |
|---|---|---|---|---|---|---|---|
| Список: `GET /api/incidents` | Добрий | `401`, без redirect | `200`, лише власні Incident | `200`, усі Incident для аналізу | `403` | Так для Reporter | Реалізовано через `IncidentAccessRules` і scoped query. Fixed PoC: Alice count=3, Bob відсутній. |
| Пошук: `GET /api/incidents/search` | Відмінний | `401`, без redirect | `200`, пошук серед власних Incident | `200`, пошук серед усіх Incident | `403` | Так для Reporter | Реалізовано в SQL до sort/take/projection. Fixed PoC Alice за назвою Bob повернув порожній масив. |
| Зведення: `GET /api/incidents/severity-summary` | Відмінний | `401`, без redirect | `200`, counts лише власних Incident | `200`, counts усіх Incident | `403` | Так для Reporter | Реалізовано в SQL до `GroupBy`. Fixed PoC Alice: Critical=0, High=0, Medium=1, Low=2. |
| Деталі: `GET /api/incidents/{id}` | Достатній, головна protected action | `401`, без redirect | owner `200`; чужий `404`; internal comments не повертаються | `200` для наявного Incident, internal comments повертаються | `403` | Так для Reporter | Centralized resource decision. Fixed PoC: Alice own `200`, foreign/missing однакові `404`, Morgan `200`. |
| Створення: `POST /api/incidents` | Успадкований ЛР 03 | `401`, без redirect | `201`, owner визначає сервер | `201`, owner визначає сервер | `403` | Новий owner визначається сервером | Існуючий маршрут отримав явну рольову перевірку; Administrator deny покрито regression test. |
| Зміна content: `PUT /api/incidents/{id}` | Добрий | `401`, без redirect | owner `204`; чужий `404`; лише title/description | `403`, навіть для доступного Incident | `403` | Так для Reporter | Centralized resource decision перед validation, tracked mutation і `SaveChanges`. Fixed PoC: foreign `404` без зміни Bob; owner update та `400` для protected fields пройшли. |
| Comments у details response | Добрий | Відповідь details недоступна | Власний details без `IsInternal` comments | Дозволений details містить internal comments | `403` разом з details | Так для доступу до parent | Role-aware проєкція в наявному details route; owner і Analyst поведінка покрита regression test. |

## HTTP-відмови

1. `401 Unauthorized` — немає authenticated principal; API не повертає `302`.
2. `404 Not Found` — authenticated Reporter звертається до чужого Incident
   або до відсутнього коректного GUID. Обидві гілки використовують один helper
   і мають однакове тіло після вилучення `traceId` / `requestId`.
3. `403 Forbidden` — ресурс доступний, але operation не надано цій ролі:
   Analyst update або Administrator читання.
4. `400 Bad Request` — update містить невідомі/protected JSON-поля, наприклад
   `ownerUserId` чи `status`; стан ресурсу не змінюється.

## Додатковий finding: непряме розкриття через колекції й агрегати

Первинний дефект існував не лише у details: list, search і severity-summary
обробляли всі рядки без owner scope. Тому навіть після захисту details чужий
Incident міг бути розкритий через назву у search або count у summary. Виправлення
додає SQL-умову за owner/роллю з principal безпосередньо до запиту: до
`OrderBy`/`Take` у search і до `GroupBy` у summary. Це не завантажує повну
множину в пам'ять.

## Межі mutation

`PUT` приймає лише `title` і `description`; id, owner, severity, status та
службовий час визначає сервер. Рішення доступу виконується до будь-якої зміни
tracked entity. Відсутні у vulnerable state delete, triage та direct child
endpoint не були додані в ЛР 04; їх не можна зараховувати як authorization
coverage наявних маршрутів.

Fixed результат, vulnerable PoC і hashes двох станів наведені у
[звітi](report-lab-04.md).
