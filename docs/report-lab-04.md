# ЛР 04: контроль доступу до Incident

Дата перевірки: 18.10.2026. Виконано пункти 2–13: матрицю доступу,
відтворювані vulnerable states, серверне виправлення для read/update,
regression tests, HTTP PoC та контрольований PoC privileged action `triage`.

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
власника ресурсу з БД.

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
не впливають на авторизацію. Матриця фіксує такий контракт:

| Операція | Reporter | Analyst | Administrator |
|---|---|---|---|
| `GET details` | власний `200`, чужий `404` | `200` для наявного | `403` |
| `PUT content` | лише власний `204` | `403` | `403` |
| list/search/summary | тільки власна множина | вся множина для аналізу | `403` |
| `POST triage` | власний `403`, чужий `404` | `204` тільки `New → Triaged` | `403` |

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
і прочитати або змінити Incident Bob. [HTTP-доказ](evidence/lab04-poc.txt)
зберігає фактичні результати: anonymous details `200`, Alice -> Bob details
`200`, Alice -> Bob update `204`, `foreign_content_changed=true`. Mutation
відбувалася тільки в ізольованій тимчасовій БД, а первісний content Bob був
відновлений.

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

У vulnerable state другий `GET` повертав `200`, а `PUT` — `204`: це і є
IDOR/BOLA, бо Alice не змінювала principal, а змінила тільки selector ресурсу.

Vulnerable commit лишається лише у приватній навчальній історії. Він не
використовується для deployment і не має фінального тегу.

## Пункт 6: серверне виправлення

`IncidentAccessRules` є централізованою точкою прийняття рішення для details
і update. Вона приймає verified subject та role claims, а endpoint передає
owner ресурсу, завантаженого з БД. Тому request body, browser client і id у
URL не можуть надати право доступу.

Для list, search та severity-summary scope з principal застосовується в SQL
до сортування, `Take`, проєкції і `GroupBy`. Update приймає вузький DTO лише
з `title` і `description`; protected JSON-поля відхиляються з `400` до будь-
якої mutation. Comments як частина наявної details response role-aware:
Reporter не бачить internal comments, Analyst бачить їх після дозволеного
parent details. Нових endpoint-ів у fixed state не додано.

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

| Перевірка | Результат fixed PoC |
|---|---|
| A-01 anonymous -> Bob | `401` Problem Details |
| A-02 Alice -> Alice | `200` |
| A-02b Alice update own Incident | `204`; content змінюється, baseline відновлено |
| A-03 / A-10 Alice -> Bob і missing | однакові безпечні `404` |
| A-03R Morgan/Analyst -> Alice/Bob | `200` |
| A-04 Alice update Bob | `404`; content Bob не змінився |
| A-05 / A-11 list, search, summary Reporter | лише власна множина |
| A-08b protected fields update | `400`, стан не змінився |
| Details comments | Reporter не бачить internal, Analyst бачить |

Для negative mutation proof скрипт спочатку читає baseline Bob, виконує запит
Alice, а потім читає Bob повторно. У fixed state він перевіряє
`foreign_content_changed=false`. Для positive regression Alice оновлює власний
content, підтверджує нові `title` і `description`, а потім відновлює baseline.
Таким чином успішна operation не стала побічним ефектом deny-перевірки.

Реальний ізольований прогін після фінального виправлення наведено у
[evidence/lab04-fixed.txt](evidence/lab04-fixed.txt). Regression tests у
`tests/SecureLab.Api.Tests/IncidentAuthorizationTests.cs` перевіряють details,
scope колекцій/агрегатів, update, protected fields, comments і deny
Administrator. Для відсутніх у cumulative state delete, transition, direct
child та export/audit flows матриця містить конкретний deny/відсутність маршруту;
їх не створено лише для штучного розширення ЛР 04.

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
`5a1d657e86ec50c89630c7a60a52a0d9de057abd`
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

Fixed commit: `27b2ec6e94fbae95c2683ad46400f912570b696b`
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
`OccurredAtUtc` та request `TraceId`. Пароль, cookie, token, body, title,
description і stack trace не записуються. Реальний HTTP-доказ містить `403`,
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

| Рядок | Автоматична перевірка | Результат |
|---|---|---|
| A-06 | Reporter triage з підставленими `role`, `ownerUserId`, `status`, `isTransitionAllowed` | `403`; повторні details показують `New` |
| A-06R | Інший Reporter triage | `404`; owner повторно читає `New` |
| A-06A | Administrator triage | `403`; owner повторно читає `New` |
| A-07 | Analyst triage | `204`; details показують `Triaged`; history містить `New → Triaged` і verified Analyst |
| A-07S | Analyst повторює triage | `409`; history не має нового запису |
| Audit deny | Reporter `403` | structured event має allowlist полів і `TraceId`, рівний Problem Details `traceId` |

Повний відтворюваний fixed прогін з кореня проєкту:

```powershell
.\scripts\verify_lab04_poc.ps1 -Port 5084 -ExpectedState fixed -TriageFixedPoC
```

## Використання ШІ

Codex використано для звірення вимог, підготовки контрольованого сценарію,
реалізації серверної авторизації, запуску перевірок і оформлення доказів.
Автору роботи потрібно вміти пояснити відмінність між authentication,
ownership та дозволом на конкретну операцію.
