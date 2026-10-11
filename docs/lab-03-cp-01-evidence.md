# CP-01 — доказ безпечної реєстрації

Перевірка виконана інтеграційними тестами в локальному Development-середовищі.
Пароль передавався тестовому процесу лише через `SeedUsers__Password`; його
значення не збережено в цьому файлі, в тестах або в response.

## T-01: коректна реєстрація

Тест: `RegistrationContractTests.Register_WithValidInput_ReturnsSafeResponseAndAssignsReporterRole`.

Результат: `201 Created`, `Content-Type: application/json`.

Безпечна структура response (ідентифікатор генерує сервер):

```json
{
  "id": "<server-generated-guid>",
  "userName": "reg<unique-suffix>",
  "displayName": "Тестовий користувач"
}
```

Тест підтверджує, що сервер генерує `id` та призначає лише роль `Reporter`.
Окремий
`RegistrationContractTests.Register_WithUnexpectedServerManagedField_Returns400WithoutCreatingAccount`
підтверджує strict contract: client-supplied `role` завершується `400` без
створення account. У response відсутні `password`, `passwordHash`,
`securityStamp`, cookie і token.

## T-02: безпечна відмова для дубліката

Тести:

- `RegistrationContractTests.Register_WithDuplicateUserName_Returns409ValidationProblem`;
- `RegistrationContractTests.Register_WithDuplicateEmail_Returns409ValidationProblem`.

Результат: `409 Conflict`, `Content-Type: application/problem+json`.

Безпечна структура response для дубльованого імені:

```json
{
  "status": 409,
  "errors": {
    "userName": ["Це ім’я користувача вже зайняте."]
  }
}
```

Відповідь не розкриває пароль, хеш, security stamp або внутрішні коди Identity.
Окремі тести також підтверджують `400 Bad Request` для невалідного contract,
пароля, що не відповідає policy Identity, і невідомого server-managed JSON-поля.

## T-03: зберігання пароля

Модель `ApplicationUser` відображається на таблицю `identity_users`. Identity
зберігає в ній лише `PasswordHash` типу `text`; поля для відкритого пароля
немає. Створення й перевірка облікових даних виконуються через
`UserManager.CreateAsync(user, password)` і `PasswordSignInAsync`, тобто хеш
вручну не обчислюється й не повертається клієнту.

## Підсумок перевірки

Сценарії CP-01 автоматизовані. 2026-10-11 на локальній PostgreSQL виконано
фінальний повний інтеграційний прогін: **56 passed, 0 failed, 0 skipped**.
Збережено лише безпечні статуси та форму response; значення секретів у доказі
відсутні.
