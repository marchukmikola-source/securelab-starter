# Advanced variant: відкликання всіх cookie-сеансів користувача

Статус: **погоджено користувачем через надану відповідь викладача 09.11.2026; реалізовано**.
Дослівна відповідь та прийняті уточнення збережені в
[доказі погодження](evidence/lab06-advanced-approval.md). Результат повної
перевірки визначається статусом [CP-03](evidence/lab06-stage3.json).

## Мета

Дати користувачу можливість негайно відкликати всі попередні сеанси після
підозри на компрометацію cookie. Використати стандартний ASP.NET Core Identity
SecurityStamp, зберегти cookie profile, CSRF та server-side authorization.

## Реалізація та межі

- Лише власний localhost SecureLab зі штучними accounts.
- Authenticated POST `/api/me/sessions/revoke-all`: повторна перевірка пароля,
  стандартний antiforgery token, оновлення SecurityStamp та завершення поточного сеансу.
- Перевірка stamp на наступному protected request усіх попередніх сеансів.
- Жодного Redis, нового контейнера чи primary business data поза PostgreSQL.
- У логах лише мінімальна подія, без пароля, cookie, токена, stamp value чи model dump.
- Чесна межа: негайна перевірка stamp збільшує DB reads; це локальний навчальний
  profile, а не заява про оптимальний production session architecture.

## Контракт та вибір механізму

JSON містить тільки `currentPassword`; невідомі поля, включно з `userId`,
відхиляються. Subject походить із перевіреного principal. Для всіх ролей
це self-only операція: Bob відкликає сеанси Bob, сеанси Alice залишаються чинними.
GET-маршруту відкликання та адміністративного target-user endpoint немає.

`CheckPasswordAsync` + окремий атомарний limiter: **5 спроб / 2 хвилини**
на authenticated userId. У квоту входять усі допущені до handler спроби;
паралельні запити не обходять ліміт. Відсутній/невалідний CSRF відхиляється
раніше й не запускає password check. Після перевищення — `429` без відкликання.
Постійного lockout немає: невдале підтвердження не блокує новий вхід до account.
Ліміт у пам’яті одного процесу достатній для погодженого локального стенда;
він не є розподіленим захистом для deployment із кількома репліками.

Успіх: `UpdateSecurityStampAsync` → `SignOutAsync` → `204`.
`ValidationInterval = TimeSpan.Zero` відхиляє старі cookie на наступному
захищеному запиті. Поточний сеанс також завершується. Клієнт очищує CSRF-кеш,
поле пароля і профіль, показує потребу нового входу; автоматичного повтору POST немає.

`StampBoundAntiforgeryData` реалізує стандартний `IAntiforgeryAdditionalDataProvider`.
Додаткові дані — versioned SHA-256 binding userId + SecurityStamp **із claims**,
без окремого запиту до БД. Для anonymous principal — явний `anonymous:v1`;
authenticated principal без потрібних claims відхиляється. Framework захищає
ці дані всередині свого токена. Відсутність/помилка перевірки дає `400`.

Audit містить тільки `EventName, Subject, Action, Resource, Result, Time, TraceId`.
Результати: `success`, `failure` та `rate_limited`. Пароль, cookie, токен,
SecurityStamp і його digest не записуються. `failure` також фіксується для
неправильного або відсутнього повторного пароля.

## Відтворювана перевірка

1. Два незалежні cookie clients Alice та окремий client Bob успішно читають свої ресурси.
2. Запит відкликання без CSRF/з невалідним token відхилено; обидва сеанси Alice чинні.
3. Неправильний повторний пароль відхилено; стан сеансів не змінився.
4. Правильний пароль + valid token відкликає поточний та другий сеанси Alice.
5. Старі cookie Alice на наступному protected request дають 401; Bob лишається authorized.
6. Новий правильний login Alice знову дозволяє легітимний flow.
7. Перевірити відсутність sensitive values у diagnostic/audit logs.
8. Bob self-revoke: Bob 2 × 401, Alice 2 × 200; anonymous POST → 401.
9. П’ять неправильних паролів → 5 × 403, шоста спроба іншого сеансу того самого
   subject → 429 без відкликання. Bob має окрему квоту; після вікна дія працює.
10. Контроль «до/після» у test-only host: стандартний default provider без
    stamp binding допускає старий токен того самого user після нового входу (`204`);
    власний provider відхиляє його (`400`), зберігаючи чинний сеанс; новий токен працює.
    У production немає перемикача вимкнення provider.
11. Anonymous standard antiforgery issue/validate round-trip проходить у тесті.
12. Production TestServer: 10 warm GET `/api/me` при 30 хв та при 0; записуються
    DB command count, mean/max latency, кількість Set-Cookie та перевірка flags.
    Це локальний послідовний вимір, а не load benchmark чи перевірка реального TLS.

## Докази та залишковий ризик

Тести: `SessionRevocationTests`; протокол — `checks.advanced-integration`
та `checks.browser-advanced` у CP-03. Знімки actual Chrome збережено в
`docs/evidence/screenshots/lab06-stage3`. Значення cookie, token, stamp та пароля
не публікуються. Сеанс перевіряється на кожному запиті ціною додаткових DB reads
і частого перевипуску cookie; прапорці Secure/HttpOnly/SameSite=Lax перевіряються
саме на поновлених відповідях. In-flight запити не скасовуються, викрадений пароль
дозволить новий вхід; компрометація Data Protection keys поза scope.

## Офіційні джерела механізмів

- [ValidationInterval, стандартні 30 хвилин](https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.identity.securitystampvalidatoroptions.validationinterval?view=aspnetcore-10.0).
- [Стандартне розширення antiforgery](https://learn.microsoft.com/en-us/aspnet/core/security/anti-request-forgery?view=aspnetcore-10.0#extend-antiforgery).
