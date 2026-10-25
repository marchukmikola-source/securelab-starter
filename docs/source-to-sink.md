# Карта source-to-sink: Incident.Description та IncidentComment.Text

Стан коду: scaffold `lab-05-start-v1`, vulnerable commit `7c49c5f549112866536f4eee90959b8f4b3f0312`. API працює на `http://localhost:5080`; запит виконується після входу користувача, який має право створювати та читати власний інцидент. Значення cookie і пароль не фіксуються.

## Основний потік: Incident.Description

Передумови для Network-доказу: увійти як `alice`, відкрити `/browser-lab.html`, створити інцидент через форму «Створити й прочитати» або прочитати власний запис за Guid. У DevTools потрібно зберегти POST та наступний GET: POST передає поле `description`, а GET повертає його для відображення.

| Крок | Файл та функція/DTO | Конкретне поле/значення | Доказ і довіра |
|---|---|---|---|
| Source | `Client/browser-lab.html`, `<textarea name="description">` | Текст, який вводить користувач у форму створення інциденту | Контрольоване користувачем значення. Форма не змінює його категорію довіри. |
| Request | `Client/browser-lab.js`, submit handler | `fetch("/api/incidents", { method: "POST", body: JSON.stringify({ ..., description: event.currentTarget.elements.description.value, ... }) })` | У Network це JSON field `description`. Значення все ще контролює користувач. |
| Validation/mapping | `Scaffolding/Lab02Endpoints.cs`, `CreateIncidentRequest.Description` | Перевірка required і maximum 4000; `request.Description?.Trim()` → `description` | Validation обмежує довжину й прибирає крайні пробіли, але не робить HTML-текст trusted і не визначає безпечний DOM-контекст. |
| Storage | `Data/Entities/Incident.cs`, `Incident.Description`; `Data/SecureLabDbContext.cs` | `description` → таблиця `incidents`, колонка `description`, maximum 4000 | Це збережене значення користувача. Запис у PostgreSQL не перетворює його на безпечний HTML. |
| Response | `Application/Incidents/IncidentQueries.cs`, `GetDetailsAsync`; `Presentation/Contracts/IncidentResponses.cs` | `Incident.Description` → `IncidentDetailsResponse.Description` → response JSON field `description` у GET `/api/incidents/{id}` | JSON escaping не є HTML-санітизацією. Значення лишається недовіреним для браузерного відображення. |
| Client transform | `Client/browser-lab.js`, `load()` | `current = await response.json()`; `current.description` | Дані з API передаються до відображення без перетворення контексту. |
| Sink/context | `Client/browser-lab.js`, `load()`; елемент `#description` | `document.querySelector("#description").innerHTML = current.description` | Небезпечний HTML-parser context: рядок може бути інтерпретований браузером як markup, а не як текст. |

Гіпотеза: значення з `textarea[name="description"]` зберігається в `incidents.description`, повертається як `IncidentDetailsResponse.description` і передається у `#description.innerHTML` як HTML; тому за умови, що опис містить HTML-подібні символи, браузер може інтерпретувати їх як markup замість звичайного тексту.

## Другий потік: IncidentComment.Text

Для контрольованої перевірки використовується public seed comment інциденту Alice: Guid `30000000-0000-0000-0000-000000000005`, text marker із `resources/lab05-marker.txt`, заданий як `lab05Marker` у `DbSeeder.SeedAsync`. Internal comment не є доказом для Reporter, тому що details response для нього його не повертає.

| Крок | Файл та функція/DTO | Конкретне поле/значення | Доказ і довіра |
|---|---|---|---|
| Source | `Data/DbSeeder.cs`, `lab05Marker` і `IncidentComment.Text` | Точний local-only marker із `resources/lab05-marker.txt` | Це code-owned synthetic fixture для відтворюваного PoC. Sink не повинен покладатися на це: для коментаря, створеного користувачем у реальному flow, категорія буде «збережене значення користувача». |
| Storage | `Data/Entities/IncidentComment.cs`, `Text`; `Data/SecureLabDbContext.cs` | Таблиця `incident_comments`, колонка `text`, maximum 2000 | Збереження не робить текст безпечним для HTML parser. |
| Response | `Application/Incidents/IncidentQueries.cs`, `GetDetailsAsync` | `comment.Text` → `IncidentCommentResponse.Text` → `comments[].text` у details JSON | Для Analyst internal comments також можуть увійти до response; для Reporter вони відфільтровані до projection. |
| Client transform | `Client/browser-lab.js`, цикл `for (const comment of current.comments ?? [])` | `comment.text` | Значення надходить із details response. |
| Sink/context | `Client/browser-lab.js`, елемент `p` | `paragraph.innerHTML = comment.text` | Небезпечний HTML-parser context, такий самий за класом ризику як для Description. |

## Інвентаризація DOM sinks у власному browser client

| Місце | Дані в sink | Категорія даних | Контекст | Рішення у fixed state |
|---|---|---|---|---|
| `browser-lab.js`: `#title.textContent = current.title` | `current.title` | Збережене значення користувача / API value | Text node | Лишити `textContent`. |
| `browser-lab.js`: `#description.innerHTML = current.description` | `current.description` | Збережене значення користувача | HTML parser | Замінити на безпечний text rendering. |
| `browser-lab.js`: `paragraph.innerHTML = comment.text` | `comment.text` | Збережене значення користувача для звичайного comment flow | HTML parser | Використати той самий безпечний helper, що й для Description. |
| `browser-lab.js`: `status.textContent = ...` | Статус, сформований із `response.status` | Server-generated number плюс code-owned literal | Text node | Лишити `textContent`. |

Перевірка CP-01 перед payload: є форма-джерело, точне JSON field `description`, server/storage/response mapping і конкретні sinks `#description.innerHTML` та `paragraph.innerHTML`. Наступний етап — normal text і контрольований marker тільки на локальних синтетичних даних.
