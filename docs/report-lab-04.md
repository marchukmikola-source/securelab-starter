# ЛР 04: контроль доступу до Incident

Дата перевірки: 17.10.2026. Поточний обсяг: перевірка пунктів 2-3 та
виконання пункту 4, включно з додатковим mutation PoC для доброго/відмінного
рівня. Це звіт про **вразливий стан**, а не про завершену ЛР 4.

## Перевірка пунктів 2-3

[Матриця доступу](access-matrix.md) містить одну таблицю з вісьмома колонками,
правила Reporter/Analyst/Administrator, ownership, конкретні HTTP-відмови,
internal comments, triage та наявні search/severity-summary. Незаповнених
`conditional`, `TODO`, «Визначте» та «за предметним правилом» немає.

Для authenticated Reporter чужий incident має давати `404`, як і відсутній
incident; для аноніма - `401`; відсутність права на операцію над доступним
ресурсом - `403`. Analyst читає інциденти для аналізу й має лише перехід
`New -> Triaged`; Administrator не має автоматичного обходу ownership.
Матриця й політика заповнені, але застосування цих правил у коді є наступним
етапом. Фактичні порушення нижче не позначаються як успішна авторизація.

## Передумови та відтворення

- Гілка: `lab/4-authorization`.
- Базовий commit перед змінами пункту 4:
  `73901c423e7dc16ef0b19d9f3cbe96e1c710b856`.
- Головна action: `GET /api/incidents/{id}`; додатковий mutation PoC:
  `PUT /api/incidents/{id}`, тільки `title` і `description`.
- Incident Alice: `20000000-0000-0000-0000-000000000001`.
- Incident Bob: `20000000-0000-0000-0000-000000000002`.
- Alice/Bob мають роль Reporter, Morgan - Analyst; ролі призначені seed до login.
- Використано локальний PostgreSQL у `secure-lab-postgres-1`, окрему
  тимчасову БД `securelab_lr04_poc_<random>` та API `http://localhost:5084`.
  Звичайний API на 5080 вже працював, тому обрано інший порт.
- Пароль згенеровано лише в пам'яті процесу та передано через
  `SeedUsers__Password`. Кожний клієнт має окремий cookie jar у пам'яті.
  У файлах і доказах немає password/cookie/token/Set-Cookie values.

Повторити з кореня проєкту в PowerShell 7, коли Docker уже працює:

```powershell
.\scripts\verify_lab04_poc.ps1 -Port 5084 -Python python
```

Якщо команда `python` недоступна, параметр `-Python` приймає повний шлях до
Python 3. Скрипт створює тільки власну тимчасову БД, збирає проєкт в окремому
`tmp`-каталозі, запускає suite та API, виконує сценарій, зупиняє власний API
і видаляє тимчасову БД. Значення змінних середовища після запуску відновлюються.

Для вже запущеного локального API із відомим seed-паролем у середовищі:

```powershell
python scripts/lab04_access.py --host http://localhost:5080 --expect vulnerable --perimeter --mutation
```

Альтернативний ручний шлях - послідовні запити у
[tests/http/lab-04-access.http](../tests/http/lab-04-access.http) через VS Code
REST Client. У файлі описано login, читання до/після та відновлення seed-content.
Для довільного початкового тексту безпечніше використати helper: він відновлює
саме прочитані `title`/`description`, а не припускає seed-значення.

## Фактичні докази пункту 4

[Збережений HTTP-доказ](evidence/lab04-poc.txt) отримано під час реального
запуску. Build: **0 warnings, 0 errors**. Regression suite: **91 passed,
0 failed, 0 skipped**. Перед PoC: 4 users, 5 incidents, 3 comments.

Для Alice виконано login `204` та перевірено `/api/me` з subject
`10000000-0000-0000-0000-000000000001`. Запити Alice до власного й чужого
incident використовують той самий HTTP-клієнт, cookie, метод і заголовки;
змінюється тільки GUID у URL. Helper окремо перевіряє незмінність cookie
та повторно перевіряє principal Alice.

| ID | Рівень | Сценарій | Передумови | Дія | Очікувано за матрицею | Фактично у вразливому стані | Доказ |
|---|---|---|---|---|---|---|---|
| A-01 | Добрий | Анонімний details | Окремий клієнт без cookie; `/api/me` дає 401 | GET Bob | 401, без redirect | 200 із даними Bob; маршрут не вимагає входу | `A-01 Anonymous -> Bob` у lab04-poc.txt |
| A-02 | Усі | Alice читає власний incident | Login 204, verified subject Alice | GET Alice | 200, id Alice | 200, правильний id і ownerDisplayName | `A-02 Alice -> Alice` |
| A-03 | Усі | Alice читає Bob | Та сама cookie Alice, тільки інший id | GET Bob | 404 | 200, title Bob і ownerDisplayName «Боб Мельник»; IDOR відтворено | `A-03 Alice -> Bob`, `alice_same_cookie_for_own_and_foreign=true` |
| A-03R | Усі, entry ЛР 5 | Morgan читає Alice | Окремий login Morgan 204 | GET Alice | 200 для аналізу | 200; окреме role-based рішення ще відсутнє | `A-03R Morgan -> Alice` |
| A-04 | Добрий | Alice змінює content Bob | Bob читає до; Alice має власну cookie | PUT Bob, потім Bob GET | 404, стан Bob без змін | 204; Bob бачить нові title/description; mutation IDOR відтворено | `A-04 Alice updates Bob`, `foreign_content_changed=true` |
| A-05 | Добрий | Alice list | Login Alice | GET list | Лише власні incident | 200, усі 5, включно з Bob | `A-05 Alice list` |
| A-06 | Добрий | Заборонений triage | Endpoint ще відсутній | Не виконувалось | 403/404 за видимістю parent, без mutation | Не перевірено; наступні кроки ЛР | Огляд маршрутів |
| A-07 | Добрий | Analyst New -> Triaged | Endpoint ще відсутній | Не виконувалось | 204, тільки дозволений перехід | Не перевірено; наступні кроки ЛР | Огляд маршрутів |
| A-08b | Добрий | Зайві protected fields у update | Alice; поточний Bob content збережено | PUT із ownerUserId/status/role | 400, без зміни стану | 400; повторне читання Bob збігається з попереднім | `forged_fields_status=400; rejected_request_state_unchanged=true` |
| A-09 | Добрий | Audit denied triage | Triage ще відсутній | Не виконувалось | Безпечна audit-подія зі спільним traceId | Не перевірено; наступні кроки ЛР | Огляд маршрутів |
| A-10 | Добрий | Чужий та відсутній incident | Та сама Alice | GET Bob, GET missing | Однакові 404 і безпечні тіла без correlation fields | Чужий 200, відсутній 404: політика ще не реалізована | `A-03 Alice -> Bob`, `A-10 Alice -> missing` |
| A-11 | Відмінний | Search і summary | Alice, незмінений seed до mutation | Пошук назви Bob та summary | Порожній пошук; counts лише Alice | Пошук повернув Bob; summary: High=1, Medium=1, Low=3, Critical=0, тобто всі 5 замість 3 власних | Рядки `A-11 Alice search Bob title` і `A-11 Alice summary` |
| A-12 | Добрий | Direct child/internal comment | Child endpoint ще відсутній | Не виконувалось | Parent decision та internal rule | Direct child не перевірено; наявна details-проєкція приховує internal для всіх ролей | Огляд маршрутів/проєкції |

Додатково Bob читає свій incident із `200`, Bob читає Alice із `200`
(симетричний дефект), Morgan читає Bob із `200`. Анонімний `PUT` повертає
`401`: login-захист mutation збережено, але authentication не усуває IDOR.

### Mutation: до, зміна, після, відновлення

1. Bob читає власний incident: title = `Невідома спроба входу`, status = `InProgress`.
2. Alice надсилає `PUT` до цього id з title = `LR04 controlled update by Alice`
   та description = `Контрольована навчальна зміна чужого інциденту для PoC ЛР 4.`.
3. Сервер повертає `204`. Bob повторно читає ресурс і бачить обидва нові поля.
4. Helper перевіряє незмінність `id`, `severity`, `status`, `ownerDisplayName`,
   `occurredAtUtc`, `createdAtUtc` та comments у response. Код update присвоює
   лише title/description і server-side UpdatedAtUtc; owner/history не змінює.
5. Bob відновлює початкові title/description. Повторний details response
   повністю збігається з початковим. `UpdatedAtUtc` не входить до details DTO
   і закономірно оновлюється сервером під час запису та відновлення.
6. Створений для PoC API зупинено, тимчасову БД видалено.

Ці «до/після» стосуються **ефекту вразливої mutation**. HTTP-доказу після
виправлення авторизації ще немає; його потрібно отримати на наступному етапі.

## Першопричина та межі стану

`IncidentQueries.GetDetailsAsync` шукає тільки за id, без subject/owner scope.
Details endpoint також не вимагає authentication. Це дві окремі проблеми:
чужий ресурс доступний authenticated Alice, а також доступний аноніму.

Доданий навчальний `IncidentEndpoints.UpdateContentAsync` вимагає login,
використовує вузький DTO та tracked entity, але завантажує Incident тільки
за id і зберігає content без ресурсного рішення. Саме пропущена перевірка
власника є контрольованим дефектом. UI не змінювався.

## Що належить до наступних кроків

Пункт 4 виконано: сценарій та реальні докази read/mutation IDOR збережені.
Delete, triage та direct child у поточному cumulative state ще відсутні;
відсутність маршруту не видається за перевірену authorization-відмову.

За пунктом 5 потрібно зафіксувати окремий vulnerable commit із цими файлами
та записати його hash. За пунктом 6 та наступними - реалізувати ресурсні
рішення, повний perimeter рівня «Відмінно», повторити PoC у fixed-режимі,
додати authorization regression tests, fixed commit і фінальний тег.
Наявний baseline hash вище не є hash нового vulnerable commit. Git commits,
fixed state та тег цим виконанням пункту 4 не створювалися.

## Використання ШІ

Codex використано для звірення вимог, підготовки сценарію, контрольованого
endpoint, запуску перевірок та оформлення фактичних результатів. Автору
роботи потрібно переглянути код і вміти пояснити різницю між authentication,
ownership та дозволом на конкретну операцію.
