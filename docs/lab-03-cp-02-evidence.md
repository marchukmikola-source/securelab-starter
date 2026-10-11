# CP-02 — безпечний login, cookie, `/api/me` і logout

Дата фінальної перевірки: 2026-10-11.

## Автоматична перевірка

Сценарії `CurrentUserEndpointTests` увійшли до фінального повного
інтеграційного прогону. Результат: **56 успішно, 0 помилок, 0 пропущено**.

- Успішний login повертає `204 No Content` і встановлює application cookie лише з атрибутами `HttpOnly`, `SameSite=Lax`; у HTTPS-тесті також є `Secure`. Значення cookie не зберігається в доказі.
- Два login-відмови — для невідомого користувача та неправильного пароля — мають однакові статус, тип відповіді і текст `ProblemDetails`; відповідь не містить пароля.
- Анонімний `GET /api/me` повертає `401`, `application/problem+json`, без redirect, `Location` і `WWW-Authenticate: Bearer`.
- Після входу як `alice`, навіть з заголовком `X-Demo-UserId` іншого користувача, `GET /api/me` повертає лише профіль поточного автентифікованого користувача: `id`, `userName`, `displayName`.
- `POST /api/auth/logout` повертає `204`, надсилає видалення application cookie, а наступний `GET /api/me` повертає `401`.

## Маршрут даних

`POST /api/auth/login` передає request у `SignInManager.PasswordSignInAsync`. Identity перевіряє облікові дані у своєму сховищі та, у разі успіху, видає application cookie. На захищеному `/api/me` middleware відновлює перевірений `HttpContext.User`; сервер бере ID лише з claim `NameIdentifier`, читає профіль з БД і повертає обмежений `CurrentUserResponse`. Клієнтські заголовки не визначають користувача.

## Налаштування cookie

`HttpOnly` забороняє доступ JavaScript до cookie, `SameSite=Lax` обмежує надсилання cookie в міжсайтових сценаріях. У Development використано `SameAsRequest`, тож локальний HTTP можливий для навчання; поза Development застосовано `Secure=Always`, тобто cookie передається лише через HTTPS.
