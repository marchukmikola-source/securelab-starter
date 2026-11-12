# F-02. Security headers губилися на unexpected error response

**Статус:** Fixed
**Актив:** Browser defense in depth та цілісність узгодженої response policy.
**Компонент:** Program.cs middleware / UseExceptionHandler pipeline.
**Пріоритет:** P3

## Передумови і межі огляду

Локальний Production/no-launch-profile, навчальний API 5080, тимчасово
недоступна loopback PostgreSQL на 54399. Публічний login із вигаданими даними,
без cookie. Новий debug endpoint не додавався. Початковий доказ з етапу 1
збережено в [lab06-stage1.json](../evidence/lab06-stage1.json):
`checks.unexpected-error.headers={}` при 500 problem+json.

## Відтворення

1. Перевірити security headers звичайного static/API response.
2. У Production тимчасово запустити наданий local-only unreachable DB scenario.
3. Публічний POST login доходить до сховища та повертає unexpected 500.
4. Порівняти actual response headers: у початковому записі потрібні CSP,
   nosniff, Referrer-Policy відсутні, хоча безпечний ProblemDetails/trace працює.
5. Після виправлення повторити той самий сценарій; runner також відновлює
   правильний DB target і normal browser flow.

## Вплив і ймовірність

**Статус перевірки:** спостережено локально до й після виправлення.

Error responses не мали узгодженого browser defense in depth. P3: на
перевіреному шляху залишалися коректні JSON Content-Type і safe ProblemDetails;
самостійний XSS/витік credentials через цей gap не демонструвався. Unexpected
error можна відтворити локально, але вплив вужчий за unauthorized mutation.

## Першопричина

Headers встановлювалися до виконання downstream handler. Під час обробки
exception response очищувалася, і попередньо встановлені headers губилися.

## Виправлення

Headers middleware стоїть перед UseExceptionHandler та реєструє OnStarting.
CSP/nosniff/Referrer-Policy встановлюються перед фактичним надсиланням відповіді,
також на error path. Спільний exception handler збережено; CSP не послаблено.

## Retest

- Actual Production POST login за недоступної БД → 500 problem+json із трьома
  потрібними headers; response traceId зіставлено з ExceptionHandlerMiddleware.
## Positive regression

- Static 200, API 200, validation 400 та unknown-resource 404 мають ту саму policy.
- Chrome Client/forms/F5 працюють; pageErrors=0, CSP violations=0.
- Production integration error test додатково перевіряє headers на 500.

## Доказ

Evidence: [stage2 JSON](../evidence/lab06-stage2.json),
`checks.production-500-headers` і `checks.browser.headers`;
[протокол](../lab-06-stage2.md). Повтор: `python scripts/verify_lab06_stage2.py`.

Для актуального release: `python scripts/verify_lab06_stage3.py --release`.
Precise diff: security-header middleware в `src/SecureLab.Api/Program.cs`
між review-start `ee18ff4` та `lab/6-hardening-review`: Response.OnStarting
реєструється перед UseExceptionHandler; values policy не послаблені.

## Залишковий ризик

Headers не замінюють safe DOM, authentication/authorization або validation.
Перевірено п’ять указаних класів відповідей локального стенда, а не кожен
можливий deployment/proxy path. Методичка прямо підказує цей gap; він не
зараховується третьою самостійною finding відмінного рівня.
