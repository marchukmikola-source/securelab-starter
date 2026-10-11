# Контракт безпечної реєстрації (ЛР 03)

`POST /api/auth/register` приймає лише `userName`, `email`, `displayName` і
`password`. Ідентифікатор, роль, хеш пароля, security stamp та інші поля, якими
керує сервер, не входять до request DTO і не впливають на створений акаунт.

## Нормалізація і валідація

Перед перевіркою сервер прибирає пробіли на початку й у кінці `userName`,
`email` та `displayName`. Пароль не нормалізується, не логується і передається
без змін у `UserManager.CreateAsync`.

| Поле | Правило |
|---|---|
| `userName` | Обов’язкове; до 256 символів; лише латинські літери, цифри та `-._@+`. |
| `email` | Обов’язкове; до 256 символів; коректний email-формат. |
| `displayName` | Обов’язкове; до 120 символів. |
| `password` | Обов’язковий; політику складності застосовує ASP.NET Core Identity. |

## Відповіді

| Умова | HTTP | Тіло |
|---|---:|---|
| Реєстрація успішна | `201 Created` | Лише `id`, `userName`, `displayName`. |
| Помилка контракту або policy пароля | `400 Bad Request` | Validation Problem без чутливих даних. |
| Дубль userName або email | `409 Conflict` | Validation Problem з полем, яке конфліктує. |

Після успішного `UserManager.CreateAsync` сервер самостійно призначає незмінну
роль `Reporter`. У `identity_users` Identity зберігає `PasswordHash`, а не
відкритий пароль; перевірка виконується через `PasswordSignInAsync`.

Регресійні тести `RegistrationContractTests` перевіряють успішну реєстрацію,
відсутність чутливих полів у response, ігнорування server-managed полів,
призначення ролі `Reporter`, а також безпечний `409` для дубліката.
