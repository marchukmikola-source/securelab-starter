# F-03. Два паралельні triage створювали два записи одного переходу

**Статус:** Fixed
**Пріоритет:** P2. **Поза прямим checklist:** цілісність business workflow при конкуренції.
**Актив:** канонічний `Incident.Status` та достовірність `IncidentStatusHistory`.
**Компонент:** `IncidentEndpoints.TriageAsync`, PostgreSQL.

## Передумови і межі огляду

Потрібні два чинні cookie-сеанси Analyst Morgan зі стандартними CSRF-парами
та один доступний інцидент зі статусом `New`. Відтворення проводиться тільки
на одноразовому synthetic інциденті; тест видаляє його у `finally`.

Перед запуском full release runner відновлює тільки local study seed у Development.
Поза scope: інші business transitions, зовнішні системи та production deployment.

## Відтворення

1. Два незалежні клієнти одночасно виконують `POST /api/incidents/{id}/triage`.
2. Test-only `DbCommandInterceptor` затримує продовження першого SELECT до
   завершення другого SELECT. Обидва handlers отримують початковий `New`.
   Тест явно перевіряє досягнення бар’єра двома читачами; production hooks відсутні.
3. До виправлення обидві відповіді — `204`; історія містить **два** переходи
   `New → Triaged`. Канонічний статус — `Triaged`, тому звичайна послідовна
   перевірка статусу приховувала дублювання.

Фактичний негативний доказ: [lab06-triage-race-before.json](../evidence/lab06-triage-race-before.json).
Regression test тоді завершився exit 1 саме через очікування `[204, 409]`
замість спостережених `[204, 204]`. Це кероване відтворення scheduling race,
а не вимірювання частоти помилки під реальним навантаженням.

## Вплив і ймовірність

**Статус перевірки:** спостережено локально до/після на реальній PostgreSQL.

Подвійний клік, повтор мережевого запиту або два Analyst можуть записати
суперечливу історію виконання однієї операції. Це спотворює подальший аудит
і дані звітування. Ймовірність залежить від одночасності; потрібна привілейована
роль. P2 обґрунтовано відтворюваною втратою цілісності workflow в локальному scope.

## Першопричина

Причина — перевірка `Status == New` тільки на прочитаній EF-сутності.
Дві окремі операції read/check та save не забезпечували взаємного виключення.

## Виправлення

Після незміненої перевірки authorization виконується умовний атомарний
`UPDATE ... WHERE id = ... AND status = 'New'`. Зміна статусу та додавання
історії охоплені однією транзакцією. Лише `affectedRows == 1` дозволяє
додати history й повернути `204`; конкурент отримує `409`. При помилці
history транзакція відкочується. Успішна мінімальна audit-подія записується
після commit з actor/action/resource/result/time/trace.

## Retest

`ConcurrentTriageTests.SimultaneousTriage_ExactlyOneTransitionAndOneHistoryRecord`
повторює той самий бар’єр після виправлення: **один 204, один 409, один history**.
## Positive regression

Інші `IncidentTriageAuthorizationTests` зберігають дозволений Analyst transition,
відмову Reporter/anonymous, scope правил ЛР 4 та audit denial.
Новий endpoint відкликання сеансів є окремим розширенням, а F-03 виправляє triage workflow.

## Доказ

Негативне спостереження — `docs/evidence/lab06-triage-race-before.json`,
fixed retest — `checks.triage-concurrency-after` у CP-03 і release JSON.
Команда: `dotnet test SecureLab.sln -c Release --settings tmp/lab06/local.runsettings --filter FullyQualifiedName~ConcurrentTriageTests`.
Full command із reset/positive regression: `python scripts/verify_lab06_stage3.py --release`.
Precise diff: `IncidentEndpoints.TriageAsync` — conditional ExecuteUpdateAsync,
transaction та history; `IncidentTriageAudit.Allowed` після commit.

## Залишковий ризик

Виправлено саме перехід `New → Triaged`. Паралельне редагування content,
видалення та нові майбутні workflow потребують окремого рішення щодо
конкуренції. Інтеграційний тест не є розподіленим load test. Уже прийняті
in-flight запити не скасовуються відкликанням сеансу.
