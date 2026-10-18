# Матриця контролю доступу SecureLab для ЛР 04

Дата огляду: 18.10.2026. Матриця охоплює fixed cumulative state ЛР 04,
включно зі спільною privileged action `triage`. Її контрольований vulnerable
endpoint з п. 10 зберігається лише в приватній локальній гілці та не є
частиною цього безпечного стану.

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
| Видалення Incident | Добрий | deny; delete HTTP-flow відсутній | deny; права delete не надано | deny; права delete не надано | deny; права delete не надано | Було б так для видимості parent | У cumulative state немає DELETE endpoint; за правилом «нових endpoint-ів не створюйте» операцію не додано. Це явний deny, а не неперевірений allow. |
| Privileged transition: `POST /api/incidents/{id}/triage` | Добрий | `401`, без redirect | owner `403`; чужий Incident `404`; owner не має винятку | `204` лише для `New → Triaged`; інший status `409` | `403` | Лише для concealment чужого ресурсу від Reporter; ownership не надає transition | Реалізовано у `IncidentAccessRules.Triage` до mutation; server сам встановлює `Triaged`. Deny створює structured `incident.triage.denied` без title/body. A-06/A-07 та audit traceId покриті integration tests і fixed PoC. |
| Internal comment | Добрий | `401` через details | owner details `200`, internal comment не включається | дозволений details `200`, internal comment включається | `403` разом з details | Так для parent read; internal rule не залежить від автора comment | `IncidentComment` — child resource. У cumulative state його єдиний HTTP-шлях — проєкція details; direct child identifier endpoint не створювався. Регресійний тест перевіряє обидві проєкції. |
| Export/audit | Відмінний лише якщо flow існує | deny; HTTP-flow відсутній | deny; права не надано | deny; права не надано | deny; права не надано | Не застосовується без ресурсу | Export/audit endpoint у cumulative state відсутній, тому не вигадувався для ЛР 04. |

## HTTP-відмови

1. `401 Unauthorized` — немає authenticated principal; API не повертає `302`.
2. `404 Not Found` — authenticated Reporter звертається до чужого Incident
   або до відсутнього коректного GUID у details чи existing update. Обидві
   гілки використовують один helper і мають однакове тіло після вилучення
   `traceId` / `requestId`.
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
tracked entity. Окремі delete, direct-child та export endpoints у vulnerable
state були відсутні; за вимогою ЛР 04 їх не створено. У матриці для них
зафіксовано явний deny або відсутність HTTP-flow, щоб їх не видавали за
реалізоване authorization coverage.

## Privileged action: triage (п. 9)

Для `POST /api/incidents/{id}/triage` policy формується сервером із verified
principal і стану завантаженого ресурсу. Право має тільки `Analyst`; додатковий
context — поточний `Incident.Status`, який має бути `New`. Модель не містить
tenant, а ownership не є підставою для переходу: власний Reporter так само
одержує `403`. Інший Reporter одержує `404`, щоб не підтверджувати існування
чужого Incident. Administrator не набуває цього права автоматично і одержує
`403`. Для Analyst на доступному Incident із status, відмінним від `New`,
повертається `409 Conflict`, бо право є, але перехід недійсний.

Після deny сервер залишає audit event `incident.triage.denied` з
`operation=Incident.Triage`, verified `actorUserId`, `incidentId`, рішенням і
UTC-часом. До нього не потрапляють title, description, JSON-body, підставлена
role та розрізнення чужого й відсутнього ресурсу в зовнішній відповіді. Це
дає достатній слід для розслідування без нового розкриття даних.

Fixed результат, vulnerable PoC і hashes двох станів наведені у
[звіті](report-lab-04.md).
