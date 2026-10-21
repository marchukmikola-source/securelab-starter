# ЛР 04: контроль доступу до Incident

Дата останньої fixed-перевірки: 21.10.2026. Виконано пункти 2–13: матрицю доступу,
відтворювані vulnerable states, серверне виправлення для read/update/delete і
direct child comment, regression tests, HTTP PoC та контрольований PoC
privileged action `triage`. Фінальний fixed state збережено в гілці
`lab/4-authorization` і позначено анотованим тегом `v0.4.0`.

Git-ланцюжок пояснює позначки у ранніх доказах: `64889c11` вносить fixed
policy triage, `93d15b10` є його нащадком і вже містить цю зміну. Повний
implementation fixed hash `d3c398d930c7d3ccd97882f38519a3cb02b59338` додає
`DELETE` та direct child comment; це саме code commit, на якому закрито
відсутні routes. Тег `v0.4.0` позначає пізніший verified final state з доказами;
control run 21.10.2026 завершився з `101 passed, 0 failed, 0 skipped`.

Публічний fixed ref: https://github.com/marchukmikola-source/securelab-starter/tree/lab/4-authorization . Передавання виконано прямим `git push` гілки `lab/4-authorization` і анотованого тегу `v0.4.0`. Merge request не створювався, а `main` не зливався: лабораторна подається й перевіряється в ізольованій гілці; це не є твердженням про deployment у main.

## Пункти 2–3: контракт доступу

[Матриця доступу](access-matrix.md) визначає окремі права Reporter, Analyst
та Administrator. Reporter читає й оновлює лише власний Incident; Analyst
читає всі Incident для аналізу; Administrator не отримує автоматичних прав.
Для authenticated Reporter чужий ресурс і відсутній GUID повертають однакову
безпечну `404`; анонімний запит — `401`; дозволений ресурс із відсутнім
правом на операцію — `403`.

### Вихідні дані та правило прийняття рішення

У системі є чотири навчальні principal: Alice і Bob мають роль `Reporter`,
Morgan — `Analyst`, Administrator — `Administrator`. Ідентифікатор ресурсу
передається в URL лише для пошуку Incident. Право визначається тільки після
того, як сервер отримав verified principal із cookie Identity та завантажив
власника ресурсу з БД. Reporter читає, оновлює та видаляє лише власний
Incident; child comment успадковує рішення для свого parent Incident.

Централізований контекст формується в
`Application/Incidents/IncidentAccessRules.cs`:

```csharp
public IncidentAccessContext From(ClaimsPrincipal principal)
{
    var subject = principal.FindFirstValue(ClaimTypes.NameIdentifier);
    return Guid.TryParse(subject, out var subjectId)
        ? new IncidentAccessContext(
            subjectId,
            principal.IsInRole("Reporter"),
            principal.IsInRole("Analyst"),
            principal.IsInRole("Administrator"))
        : default;
}
```

Отже, поле `role` у JSON, `OwnerUserId` у body або прихована кнопка браузера
не впливають на авторизацію. Основна матриця має вісім колонок; для кожного
реалізованого read або mutation flow правило ухвалюється на сервері до response
чи зміни persistence.

| Операція | Рівень | Анонім | Reporter | Analyst | Administrator | Owner має значення? | Стан реалізації та доказ |
|---|---|---|---|---|---|---|---|
| `GET /api/incidents` | Добрий | `401` | `200`, лише власна множина | `200`, усі | `403` | Так для Reporter | scoped SQL query; A-05 |
| `GET /api/incidents/search` | Відмінний | `401` | `200`, лише власний scope | `200`, усі | `403` | Так для Reporter | scope до sort/take; A-11 |
| `GET /api/incidents/severity-summary` | Відмінний | `401` | `200`, лише власні counts | `200`, усі counts | `403` | Так для Reporter | scope до `GroupBy`; A-11 |
| `GET /api/incidents/{id}` | Достатній | `401` | owner `200`, foreign `404` | `200` | `403` | Так для Reporter | `IncidentAccessRules.Read`; A-02/A-03/A-03R/A-10 |
| `PUT /api/incidents/{id}` | Добрий | `401` | owner `204`, foreign `404`; A-08b extra JSON fields `400` | `403` | `403` | Так для Reporter | `IncidentAccessRules.Update`; A-04/A-08b |
| `DELETE /api/incidents/{id}` | Добрий | `401` | owner `204`, foreign `404` без зміни | `403` | `403` | Так для Reporter | `IncidentAccessRules.Delete`; A-04 та positive owner delete |
| `POST /api/incidents/{id}/triage` | Добрий | `401` | owner `403`, foreign `404` | `204` лише `New → Triaged` | `403` | Лише для concealment foreign Reporter | `IncidentAccessRules.Triage`; A-06/A-07/A-09 |
| `GET /api/incident-comments/{id}` | Добрий | `401` | own public `200`; foreign-parent або internal `404` | public/internal доступного parent `200` | `403` | Так для parent details | `IncidentAccessRules.Read` для parent + `IsInternal`; A-12 |
| Export/audit | Відмінний, якщо flow існує | deny; endpoint відсутній | deny; endpoint відсутній | deny; endpoint відсутній | deny; endpoint відсутній | Ні | Новий endpoint не створювався |

Для details decision є resource-based, а не URL-based:

```csharp
public IncidentAccessDecision Read(IncidentAccessContext context, Guid ownerUserId) =>
    context switch
    {
        { HasSubject: true, IsAnalyst: true } => IncidentAccessDecision.Allow,
        { HasSubject: true, IsReporter: true, SubjectId: var id } when id == ownerUserId
            => IncidentAccessDecision.Allow,
        { HasSubject: true, IsReporter: true } => IncidentAccessDecision.NotFound,
        _ => IncidentAccessDecision.Forbidden
    };
```

`404` для чужого Reporter є свідомою політикою concealment: зовнішній клієнт
не може відрізнити чужий наявний GUID від випадкового відсутнього GUID. Це
не означає, що server не знає ресурс: він спочатку читає owner і лише потім
ухвалює нейтральну відповідь.

## Пункт 4–5: контрольований vulnerable state

- Базовий commit: `73901c423e7dc16ef0b19d9f3cbe96e1c710b856`.
- Vulnerable commit: `390bc0421e33d8815444cb0c37d5398b54d5d6c8`
  (`Reproduce controlled incident access vulnerability`).

У вразливому стані details шукав Incident тільки за id і не вимагав входу.
`PUT` вимагав login, але завантажував entity лише за id і не порівнював
`OwnerUserId` із verified principal. URL-id був звичайним способом вибору
ресурсу; дефектом була відсутність server-side resource decision.

Тому за однакових методу, cookie та заголовків Alice могла змінити тільки GUID
і прочитати або змінити Incident Bob. HTTP-доказ зберігається лише у приватній
локальній гілці `lab/4-idor-vulnerable` за цим commit у
`docs/evidence/lab04-poc.txt`; він містить фактичні результати: anonymous details `200`, Alice -> Bob details
`200`, Alice -> Bob update `204`, `foreign_content_changed=true`. Mutation
відбувалася тільки в ізольованій тимчасовій БД, а первісний content Bob був
відновлений.

| Суб'єкт | Action | Identifier | Очікування за матрицею | Фактичний status у vulnerable state | Відповідь | Ефект | Артефакт |
|---|---|---|---|---|---|---|---|
| Anonymous | details | Bob `…0002` | `401` | `200` | Дані Bob | Disclosure без входу | private `lab04-poc.txt`, A-01 |
| Alice / Reporter | details | Alice `…0001` | `200` | `200` | Власні дані Alice | baseline allow | private `lab04-poc.txt`, A-02 |
| Alice / Reporter | details | Bob `…0002` | `404` | `200` | Дані Bob | Horizontal disclosure | private `lab04-poc.txt`, A-03 |
| Alice / Reporter | update | Bob `…0002` | `404`, без зміни | `204` | No Content | `foreign_content_changed=true` | private `lab04-poc.txt`, A-04 |

**CP-01.** Однакова роль `Reporter` визначає лише клас дозволених дій, але не
додає право на конкретний Incident. Alice і Bob мають однакову роль, проте
`OwnerUserId` Bob не збігається з verified `NameIdentifier` Alice. Місце
server-side рішення у fixed state —
`IncidentAccessRules.Read(context, target.OwnerUserId)` після
`queries.GetAccessTargetAsync(id, ...)`, до формування response.

Мінімальна форма дефекту в vulnerable commit була такою:

```csharp
var incident = await db.Incidents.SingleOrDefaultAsync(item => item.Id == id, ct);
if (incident is null) return NotFound();

// Порівняння incident.OwnerUserId із verified principal відсутнє.
incident.Title = request.Title!.Trim();
incident.Description = request.Description!.Trim();
await db.SaveChangesAsync(ct);
```

Контрольований PoC використовував однакові cookie Alice, метод і body. Змінювався
лише GUID після `/api/incidents/`:

```http
GET /api/incidents/20000000-0000-0000-0000-000000000001  # Alice -> Alice
GET /api/incidents/20000000-0000-0000-0000-000000000002  # Alice -> Bob

PUT /api/incidents/20000000-0000-0000-0000-000000000002
Content-Type: application/json

{ "title": "LR04 controlled update by Alice", "description": "..." }
```

Часові мітки скріншотів відображають момент фіксації доказів. Fixed кадри
створено раніше 19.10, а vulnerable PoC навмисно повторено пізніше того самого
дня в приватній гілці лише для порівняльної частини звіту. Архівний network
кадр від 18.10 підтверджує той самий fixed контракт `404` і не позначає дату
внесення виправлення.

У vulnerable state другий `GET` повертав `200`, а `PUT` — `204`: це і є
IDOR/BOLA, бо Alice не змінювала principal, а змінила тільки selector ресурсу.

Vulnerable commit лишається лише у приватній навчальній історії. Він не
використовується для deployment і не має фінального тегу.

## Пункт 6: серверне виправлення

`IncidentAccessRules` є централізованою точкою прийняття рішення для details,
update, delete і child read. Вона приймає verified subject та role claims, а
endpoint передає owner ресурсу, завантаженого з БД. Тому request body, browser
client і id у URL не можуть надати право доступу.

Для list, search та severity-summary scope з principal застосовується в SQL
до сортування, `Take`, проєкції і `GroupBy`. Update приймає вузький DTO лише
з `title` і `description`; protected JSON-поля відхиляються з `400` до будь-
якої mutation. Delete викликає `Remove` тільки після `Delete` decision. Direct
child route завантажує `IncidentComment` разом із owner його parent, застосовує
`Read` decision, а потім приховує internal comment від Reporter. Analyst після
дозволеного parent decision читає public та internal comments.

Фіксація details виконує всі необхідні кроки в server endpoint:

```csharp
var context = accessRules.From(httpContext.User);
if (accessRules.ReadScope(context) == IncidentReadScope.Forbidden) return Forbidden();

var target = await queries.GetAccessTargetAsync(id, cancellationToken);
if (target is null) return NotFound();
var decision = accessRules.Read(context, target.OwnerUserId);
if (decision != IncidentAccessDecision.Allow) return Denied(decision);

var incident = await queries.GetDetailsAsync(id, context.IsAnalyst, cancellationToken);
return incident is null ? NotFound() : Results.Ok(incident);
```

Для update той самий principal проходить окреме `Update`-рішення до validation
і до зміни tracked entity. DTO обмежений content-полями:

```csharp
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record UpdateIncidentContentRequest(string? Title, string? Description);
```

Тому `ownerUserId`, `status`, `severity`, `id` та role не можуть потрапити до
mutation. Незнайомі або protected JSON-поля дають `400 Bad Request`; чужий
Incident для Reporter дає `404` ще до validation і `SaveChangesAsync`.

## Пункт 7: повторний PoC та позитивна регресія

Повторити з кореня проєкту в PowerShell 7, коли Docker працює:

```powershell
.\scripts\verify_lab04_poc.ps1 -Port 5084 -ExpectedState fixed -Python python
```

Скрипт створює тільки власну БД `securelab_lr04_poc_<random>`, запускає API
на окремому порту, зупиняє створений API, видаляє тимчасову БД та відновлює
змінні оточення. Пароль існує лише в пам'яті процесу; докази не містять
password, cookie, token або `Set-Cookie` values.

Фактичний isolated run 21.10.2026 завершився з `0` warnings, `0` errors та
`101 passed, 0 failed, 0 skipped`; test duration — 14 s. Команда скрипта створила
`docs/evidence/test-results/lab04-latest.trx` (101 executed/passed, 0 failed), а
знеособлений console/HTTP output — `docs/evidence/lab04-fixed.txt`; обидва
артефакти мають час запису 21.10.2026 близько 14:01. Цей запуск містить
`DELETE` і direct child A-12, тому не змішується зі старим run на 99 тестів.

| Перевірка | Результат fixed PoC |
|---|---|
| A-01 anonymous -> Bob | `401` Problem Details |
| A-02 Alice -> Alice | `200` |
| A-02b Alice update own Incident | `204`; content змінюється, baseline відновлено |
| A-03 / A-10 Alice -> Bob і missing | той самий client: `404`, `application/problem+json`, нормалізовані JSON тотожні |
| A-03R Morgan/Analyst -> Alice/Bob | `200` |
| A-04 Alice update/delete Bob | обидва `404`; content Bob не змінився |
| A-05 / A-11 list, search, summary Reporter | лише власна множина; `search?q=O'Brien` → `200 []`; Critical=0, High=0, Medium=1, Low=2 |
| A-08b protected fields update | `400`, стан не змінився |
| A-12 direct child endpoint | Alice → `comment-2` Bob `404`; Alice → own internal `404`; Morgan → `comment-2` та internal `200` |

Для negative mutation proof скрипт спочатку читає baseline Bob, виконує запит
Alice, а потім читає Bob повторно. У fixed state він перевіряє
`foreign_content_changed=false`. Для positive regression Alice оновлює власний
content, підтверджує нові `title` і `description`, а потім відновлює baseline.
Таким чином успішна operation не стала побічним ефектом deny-перевірки.

Для A-10 обидва запити зроблено тією самою cookie Alice; з відповідей вилучено
лише кореляційні поля `traceId` / `requestId`. Збережені нормалізовані JSON
мають однакові status, content type і body:

```json
{"detail":"Запитаний інцидент відсутній.","status":404,"title":"Інцидент не знайдено","type":"https://tools.ietf.org/html/rfc9110#section-15.5.5"}
```

Перший екземпляр — Alice → Bob, другий — Alice → non-existent GUID;
`normalized_bodies_equal=true`. Отже, `404` не видає факт існування чужого
Incident. У тому самому фактичному прогоні A-11 для `search?q=O'Brien` повернув
`200`, `count=0`, `containsOBrien=false` для Alice.

Реальний ізольований прогін після фінального виправлення наведено у
[evidence/lab04-fixed.txt](evidence/lab04-fixed.txt). Regression tests у
`tests/SecureLab.Api.Tests/IncidentAuthorizationTests.cs` перевіряють details,
scope колекцій/агрегатів, update, delete, protected fields, direct comments і deny
Administrator. Успадковані анонімні `IncidentEndpointTests`
`GetList_ReturnsSeededIncidents`, `GetDetails_ForUnknownId_ReturnsProblemDetails404`
і `GetDetails_DoesNotExposeInternalOwnerFields` переведені на client після
login; очікування старого list замінене A-05. `SearchMechanicsTests` також
виконується authenticated client, бо search бере owner scope з principal.
Export/audit лишився єдиним відсутнім flow, бо він не був частиною cumulative
state; delete та direct-child route реалізовано для обов'язкового perimeter
доброго/відмінного рівня.

## Пункт 8: browser client

У тій самій browser-вкладці Alice відкрила власний Incident, а потім probe
`loadIncidentDetails("20000000-0000-0000-0000-000000000002")` запросив Bob.
Клієнт відобразив `Помилка: Інцидент не знайдено` через
`detailsElement.textContent`; рішення залишилося server-side. Обидва стани
зафіксовано у [evidence/lab04-browser.txt](evidence/lab04-browser.txt). Для
симетричної перевірки Bob побачив тільки два власні Incident і успішно відкрив
`Невідома спроба входу`; Bob -> Alice вже зафіксовано у fixed HTTP PoC як `404`.

Код browser client не інтерпретує API-дані як HTML. Для дозволеного Incident
він створює текстові DOM-вузли, а у гілці відмови записує тільки текст
Problem Details:

```javascript
function createTextElement(tagName, text, className) {
  const element = document.createElement(tagName);
  element.textContent = text;
  if (className) element.className = className;
  return element;
}

async function loadIncidentDetails(id) {
  detailsElement.textContent = "Завантаження…";
  try {
    renderIncidentDetails(await apiFetch(`/api/incidents/${encodeURIComponent(id)}`));
  } catch (error) {
    detailsElement.textContent = `Помилка: ${error.message}`;
  }
}
```

Отже, client не містить role/owner перевірки і не приховує факт відмови штучно:
він лише відображає server response. Відсутність `innerHTML` також не дозволяє
даним Incident або error message стати HTML-кодом.

## Пункти 9–10: privileged action і вертикальне підвищення

Цільовий contract для `POST /api/incidents/{id}/triage` описано в
[матриці](access-matrix.md): лише Analyst може виконати `New → Triaged`.
Ownership не є винятком для Reporter; owner Reporter має одержати `403`,
foreign Reporter — concealment `404`, Administrator — `403`, а Analyst для
status, відмінного від `New`, — `409`. Після deny fixed state має записувати
безпечну структуровану audit event `incident.triage.denied` тільки з verified
actor, operation, incident id, рішенням і UTC-часом.

Рішення для цієї action централізоване й не має client-supplied параметрів:

```csharp
public IncidentAccessDecision Triage(IncidentAccessContext context, Guid ownerUserId) =>
    context switch
    {
        { HasSubject: true, IsAnalyst: true } => IncidentAccessDecision.Allow,
        { HasSubject: true, IsReporter: true, SubjectId: var id } when id != ownerUserId
            => IncidentAccessDecision.NotFound,
        _ => IncidentAccessDecision.Forbidden
    };
```

Тут ownership впливає тільки на concealment для іншого Reporter. Власний
Reporter також потрапляє в `Forbidden`, тому ownership не перетворюється на
право triage.

Контрольований vulnerable commit п. 10:
`c010d2d9aae4fd0ec18668c3875df04c9c6f90d0`
(`test(lab04): reproduce triage privilege escalation`). Він існує тільки у
локальній private гілці `lab/4-triage-vulnerable`, не має тегу і не є
deployment state.

У його ізольованому HTTP PoC Alice спочатку виконала дозволений own-content
`PUT` із `204`. Потім цей самий verified Reporter виконав `POST .../triage`
для власного Incident у status `New`, одержав `204`, а наступні details
підтвердили `status=Triaged`. Повтор на іншому власному `New` Incident із JSON
`{"role":"Administrator"}` також повернув `204`. Це не робить body-role
джерелом права: порожній request тієї самої дії вже виконав transition.
Фактична першопричина — endpoint завантажує Incident і перевіряє тільки його
status, але не виконує server-side role/policy decision для `Incident.Triage`
до mutation. Повний безпечний доказ наведено у
[lab04-triage-vulnerable.txt](evidence/lab04-triage-vulnerable.txt).

Скорочено, vulnerable logic мала тільки state-check і mutation:

```csharp
var incident = await db.Incidents.SingleOrDefaultAsync(item => item.Id == id, ct);
if (incident is null) return NotFound();
if (incident.Status != IncidentStatus.New) return Results.Problem(statusCode: 409);

incident.Status = IncidentStatus.Triaged;
await db.SaveChangesAsync(ct); // role/policy decision відсутнє
```

Підставлення `role=Administrator` не було причиною успіху: порожній `POST`
як Alice давав той самий `204`. Значення body просто ігнорувалося, а дефектом
була відсутність обов'язкового рішення сервера.

Відтворення виконується з приватної гілки vulnerable state; воно запускає
старі fixed checks і цей окремий PoC лише в новій тимчасовій БД:

```powershell
git switch lab/4-triage-vulnerable
.\scripts\verify_lab04_poc.ps1 -Port 5084 -ExpectedState fixed -TriagePoC
git switch lab/4-authorization
```

## Пункти 11–12: fixed triage policy та audit deny

Fixed commit: `64889c11d27f7b1b1d13f9c2ae0494134bdb5e60`
(`fix(authz): enforce incident triage policy`). Він не містить vulnerable
поведінки з п. 10. `TriageAsync` завантажує tracked Incident, викликає
`IncidentAccessRules.Triage` із verified principal і `OwnerUserId` ресурсу,
записує audit при deny, лише тоді перевіряє `Status == New`, сам призначає
`Triaged` і викликає `SaveChangesAsync`. Endpoint не має DTO для role, owner
або status: ці JSON-поля не є input для authorization чи transition.

Власне endpoint дотримується порядку: tracked entity → decision → deny audit
і response → state-check → server-selected next status → `SaveChangesAsync`.

```csharp
var actor = accessRules.From(httpContext.User);
var incident = await db.Incidents.SingleOrDefaultAsync(item => item.Id == id, ct);
if (incident is null) return NotFound();

var decision = accessRules.Triage(actor, incident.OwnerUserId);
if (decision != IncidentAccessDecision.Allow)
{
    IncidentTriageAudit.Denied(loggerFactory, actor.SubjectId, incident.Id,
        DateTimeOffset.UtcNow, Activity.Current?.Id ?? httpContext.TraceIdentifier);
    return Denied(decision);
}
if (incident.Status != IncidentStatus.New) return Results.Problem(statusCode: 409);

var nextStatus = IncidentStatus.Triaged;
incident.Status = nextStatus;
await db.SaveChangesAsync(ct);
```

`AsNoTracking()` тут не використовується: EF Core відстежує entity, тому
успішна transition зберігається разом із `IncidentStatusHistory`. При deny
зміна status і запис history не створюються.

Audit пишеться через structured logger `SecureLab.Api.Audit.IncidentTriage`:
`EventName=incident.triage.denied`, `Operation=Incident.Triage`, verified
`ActorUserId`, `IncidentId`, `Result=Denied`, server-generated
`OccurredAtUtc` та request `TraceId`. Назва події описує доменну дію і її
наслідок: відмовлено саме у transition `Incident.Triage`. Загальна
`authorization.denied` втратила б контекст Incident і конкретної privileged
операції; сам authorization outcome однозначно зберігається у полі
`Result=Denied`. Пароль, cookie, token, body, title, description і stack trace
не записуються. Реальний HTTP-доказ містить `403`,
незмінний `New`, `204` Analyst, `409` повторної transition та рівний trace id
у response й audit: [lab04-triage-fixed.txt](evidence/lab04-triage-fixed.txt).

Виділений метод аудиту формує структуровані поля, а не конкатенує request body
або виняток у текст повідомлення:

```csharp
loggerFactory.CreateLogger(LogCategory).LogWarning(DeniedEvent,
    "{EventName} {Operation} {ActorUserId} {IncidentId} {Result} {OccurredAtUtc} {TraceId}",
    "incident.triage.denied", "Incident.Triage", actorUserId, incidentId,
    "Denied", occurredAtUtc, traceId);
```

У доказі є рівно ті дані, які дозволені контрактом. Наприклад, audit line
містить event name, verified GUID actor/Incident, `Denied`, UTC-час і traceId;
у ньому немає `role=Analyst` із forged JSON, `ownerUserId`, password або cookie.

## Пункт 13: authorization test matrix

Новий [IncidentTriageAuthorizationTests.cs](../tests/SecureLab.Api.Tests/IncidentTriageAuthorizationTests.cs)
створює temporary Incident, працює через login/cookie власної Identity
реалізації та прибирає Incident і його history у `finally`.

Negative test навмисно надсилає захищені fields, після чого читає ресурс ще
раз. Це перевіряє не лише HTTP status, а й відсутність mutation:

```csharp
using var reporterDenied = await alice.PostAsJsonAsync($"/api/incidents/{id}/triage", new
{
    role = "Analyst", ownerUserId = DbSeeder.MorganId,
    status = "Triaged", isTransitionAllowed = true
});
Assert.Equal(HttpStatusCode.Forbidden, reporterDenied.StatusCode);
await AssertStatusAsync(alice, id, "New");
```

Окремий audit test має in-memory `ILoggerProvider`, читає Problem Details і
перевіряє equality traceId, тип часу та allowlist ключів structured event:

```csharp
Assert.Equal(responseTraceId, entry.Fields["TraceId"]);
Assert.IsType<DateTimeOffset>(entry.Fields["OccurredAtUtc"]);
Assert.All(entry.Fields.Keys, key => Assert.Contains(key, allowedKeys));
```

| Рядок | Рівень | HTTP-boundary сценарій | Очікувано | Фактично та доказ |
|---|---|---|---|---|
| A-01 | Усі | Anonymous → Bob details | `401`, без redirect | `401 application/problem+json`; fixed PoC |
| A-02 | Усі | Alice → Alice details | `200` | `200`; fixed PoC |
| A-03 | Усі | Alice → Bob details | `404` | `404`; тіло нормалізовано збігається з A-10 |
| A-03R | Усі | Morgan/Analyst → Alice і Bob details | `200` | `200` для обох; fixed PoC |
| A-04 | Добрий | Alice `PUT` і `DELETE` Bob | обидва `404`, без mutation | Bob before/after однакові; `Update_AsNonOwner...` і `Delete_EnforcesOwnerRuleAndPreservesForeignResourceAfterDeny` |
| A-05 | Добрий | list як Alice | лише own set | `count=3`, Bob відсутній |
| A-06 | Добрий | owner Reporter triage з forged `role`, `ownerUserId`, `status`, `isTransitionAllowed` | `403`, `New` без зміни | `403`; повторні details `New` |
| A-06R/A-06A | Добрий | foreign Reporter / Administrator triage | `404` / `403`, без зміни | owner повторно читає `New` |
| A-07 | Добрий | Morgan/Analyst triage | `204`, `New → Triaged` | `204`; details `Triaged`, один history record |
| A-08b | Добрий | owner update з extra `ownerUserId`, `status`, `severity`, `role` | `400`, повний state без зміни | `400`; повторні details збігаються |
| A-09 | Добрий | Reporter denied triage | safe audit з response trace | allowlist structured fields; audit `TraceId` = Problem Details `traceId` |
| A-10 | Усі | одна cookie Alice: Bob details і missing GUID | `404/404`, рівні нормалізовані JSON | два збережені JSON у `lab04-fixed.txt`; `normalized_bodies_equal=true` |
| A-11 | Відмінний | Alice search і severity-summary | тільки own scope | `O'Brien` → `200 []`; summary Critical=0, High=0, Medium=1, Low=2 |
| A-12 | Добрий | Alice direct GET `comment-2` Bob | child не оминає parent decision | `404`; Morgan читає `comment-2` і internal comment з `200`; `ChildComment_EnforcesParentReadAndInternalVisibilityRules` |

Повний відтворюваний fixed прогін з кореня проєкту:

```powershell
.\scripts\verify_lab04_poc.ps1 -Port 5084 -ExpectedState fixed -TriageFixedPoC
```

## Використання ШІ та перевірка матеріалу

Codex використано для звірення вимог, підготовки контрольованого сценарію,
реалізації серверної авторизації, запуску перевірок і оформлення доказів.
Матеріал, запропонований ШІ, не приймався як доказ сам по собі: автор звірив
контракти з методичкою, переглянув `git diff`, перевірив server-side decision
у `IncidentAccessRules` та endpoint-ах, а твердження звіту прийняв лише після
HTTP/Browser/PowerShell запусків і TRX. Кожен суттєвий висновок у звіті має
відтворювану команду, status code, test або файл evidence; секрети не
передавались у Git чи до звіту. Автору роботи потрібно вміти пояснити
відмінність між authentication, ownership та дозволом на конкретну операцію.
