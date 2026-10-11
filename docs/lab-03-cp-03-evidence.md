# CP-03 — захищене створення інциденту та regression

Дата фінальної перевірки: 2026-10-11.

## Автоматична перевірка

Сценарії `IncidentCreationContractTests` і
`IncidentOwnershipSecurityTests` увійшли до фінального повного
інтеграційного прогону. Результат: **56 успішно, 0 помилок, 0 пропущено**.

- Анонімний `POST /api/incidents` повертає `401 application/problem+json` без redirect і без `WWW-Authenticate`.
- Попередні create-контрактні перевірки виконуються cookie-aware клієнтом, тому продовжують перевіряти функціональні `201`, `400` і `409`.
- Створення від Bob без поля owner зберігає `Incident.OwnerUserId` Bob.
- Створення від Bob із доданим у JSON чужим `ownerUserId` Alice також зберігає власником Bob. Безпечна response DTO не містить `ownerUserId`.

## Два запити для демонстрації

1. Анонімний `POST /api/incidents` із коректними `title`, `description`, `severity`, `occurredAtUtc` → `401`.
2. Після входу Bob у тому самому cookie-aware клієнті `POST /api/incidents` із тими самими чотирма DTO-полями та додатковим JSON-полем `ownerUserId` Alice → `201`; перевірка тестової БД підтверджує owner Bob.

Значення пароля, cookie, хешів і повних запитів у доказі не зберігаються.

## Джерело owner

Маршрут має `.RequireAuthorization()`. Після DTO validation сервер бере лише `ClaimTypes.NameIdentifier` з перевіреного `HttpContext.User`, перетворює його на `Guid` і призначає `Incident.OwnerUserId` під час створення entity. Request DTO не має owner, ролі, статусу, id або дат створення. Приховане поле форми чи довільний header надходять від клієнта, тому не є access control і не беруть участі у визначенні власника.

## Браузерний сценарій

`/auth-lab.html` реалізує register → login → `/api/me` → create → logout. Він надсилає cookie лише на той самий origin, не записує credentials/principal у browser storage або Console, очищує password inputs і відмальовує дозволені поля профілю через `textContent`. Після logout сценарій очищує профіль і форму та повторно викликає `/api/me`, що повертає `401`.

2026-10-11 цей маршрут вручну пройдено на локальному стенді: анонімний стан,
успішна реєстрація, активний сеанс із safe profile, створення інциденту та
logout із поверненням до анонімного стану. У доказ не додавалися значення
пароля або cookie.
