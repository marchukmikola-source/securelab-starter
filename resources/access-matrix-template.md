# Каркас матриці контролю доступу Incident — ЛР 04

> Скопіюйте таблицю до `docs/access-matrix.md` і замініть **кожен** `TODO`
> конкретним правилом. `allow` означає право на конкретну дію і ресурс, а не
> лише успішний login. Для deny зазначайте узгоджений HTTP status. Не надавайте
> Administrator автоматичних прав: право має випливати з предметного правила.

| Дія | Рівень | Анонім | Reporter | Analyst | Administrator | Власник ресурсу має значення? | Стан реалізації |
|---|---|---|---|---|---|---|---|
| Перегляд списку: `GET /api/incidents` | Добрий | deny, `TODO` | `TODO: дозволена множина / scope` | `TODO: дозволена множина / scope` | `TODO: allow/deny + status` | `TODO` | `TODO: query/handler і A-05` |
| Пошук: `GET /api/incidents/search` | Відмінний (A-11) | deny, `TODO` | `TODO: owner scope` | `TODO: scope` | `TODO: allow/deny + status` | `TODO` | `TODO: scope до sort/take; A-11` |
| Зведення: `GET /api/incidents/severity-summary` | Відмінний (A-11) | deny, `TODO` | `TODO: owner scope` | `TODO: scope` | `TODO: allow/deny + status` | `TODO` | `TODO: scope до GroupBy; A-11` |
| Перегляд деталей: `GET /api/incidents/{id}` | Достатній; entry-контракт ЛР 5 | deny, `TODO` | owner — allow; non-owner — deny, `TODO` | allow для аналізу Incident, `TODO` | `TODO: allow/deny + status` | Так, `TODO: конкретна умова` | `TODO: resource decision і A-02/A-03/A-03R` |
| Створення: `POST /api/incidents` | Успадкований baseline | deny, `TODO` | allow для себе, `TODO` | `TODO` | `TODO` | Сервер призначає owner | `TODO: перевірка baseline` |
| Update content: `PUT /api/incidents/{id}` | Достатній, якщо головна action; повний perimeter — добрий | deny, `TODO` | `TODO: owner/non-owner, дозволені поля` | `TODO: умова або deny` | `TODO: allow/deny + status` | Так, `TODO: конкретна умова` | `TODO: DTO, decision, A-04/A-08a або A-08b` |
| Delete: `DELETE /api/incidents/{id}` | Добрий | deny, `TODO` | `TODO: owner/non-owner` | `TODO` | `TODO` | `TODO` | `TODO: реалізувати й перевірити або явний відсутній flow` |
| Зміна severity/status: `TODO: маршрут` | Добрий | deny, `TODO` | `TODO: deny/limited` | `TODO: лише конкретний transition + context` | `TODO` | `TODO` | `TODO: server-chosen next status, A-06/A-07/A-09` |
| Перегляд internal comment: `TODO: details-projection або child route` | Добрий | deny, `TODO` | `TODO: parent rule + internal visibility` | `TODO: після authorizing parent` | `TODO` | `TODO: parent ownership / internal rule` | `TODO: child path і A-12` |
| Export/audit: `TODO: route`, лише якщо flow існує | Відмінний, якщо flow існує | deny, `TODO` | `TODO` | `TODO` | `TODO` | `TODO` | `TODO: перевірити тільки наявний flow` |

## Політика HTTP-відмов

- `TODO`: зафіксуйте `401` для anonymous, а також узгоджене `403` або `404`
  для authenticated non-owner.
- `TODO`: поясніть, як policy застосовується до details, mutation і child path.
- Для кожної mutation запишіть, як доказується незмінність state після deny.

## Нотатки до заповнення

- Замініть усі `TODO` конкретним allow/deny/умовою та HTTP status.
- У останній колонці назвіть місце коду й тест або HTTP-доказ (`A-02`, `A-03`, …).
- Не створюйте endpoint лише заради рядка; якщо flow відсутній, зафіксуйте це явно.
