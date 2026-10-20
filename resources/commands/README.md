# Допоміжні команди для локальної перевірки

Це локальна копія лише тих helpers із комплекту ЛР, які потрібні цьому
репозиторію. Вона не замінює повний комплект, що постачається поруч із PDF та
Word. Сценарій тут не змінює код SecureLab, не записує налаштування до Git і
не виводить пароль чи connection string у консоль.

## Зовнішній файл test settings

Перед запуском у тому самому вікні PowerShell задайте локальний пароль seed
користувачів. Значення не додавайте до файлів проєкту, звіту або скриншотів.
Щоб не показувати його в історії консолі, можна ввести значення приховано:

```powershell
$seedSecret = Read-Host 'Локальний пароль' -AsSecureString
$env:SeedUsers__Password = [Net.NetworkCredential]::new('', $seedSecret).Password
Remove-Variable seedSecret
$localSettings = Join-Path $HOME 'securelab-local.runsettings'
pwsh -NoProfile -File .\resources\commands\New-LocalTestSettings.ps1 `
    -OutputPath $localSettings
```

Якщо `pwsh` відсутній, замініть його на `powershell`. Файл створюється тільки
за абсолютним шляхом **поза** репозиторієм і не перезаписується. За потреби
сценарій додасть `ConnectionStrings__SecureLab`, якщо ця змінна вже задана у
поточному процесі.

Запустіть перевірку з цими налаштуваннями:

```powershell
dotnet test .\tests\SecureLab.Api.Tests\SecureLab.Api.Tests.csproj `
    --settings $localSettings
```

У Visual Studio виберіть **Test → Configure Run Settings → Select Solution
Wide runsettings File** і вкажіть цей зовнішній файл. У Rider додайте ті самі
змінні середовища до конфігурації Test Runner. `runsettings` налаштовує тести,
але не налаштовує запущений API: для API передайте змінні в його локальну
конфігурацію запуску або той самий термінал.

## ЛР 04: локальна перевірка

З кореня проєкту перевірте фіксований стан:

```powershell
dotnet build .\SecureLab.sln
dotnet test .\tests\SecureLab.Api.Tests\SecureLab.Api.Tests.csproj
```

Для локальної БД за потреби спочатку підніміть PostgreSQL:

```powershell
docker compose --env-file .\infra\.env.example -f .\infra\compose.yaml up -d --wait
```

Ручні сценарії містяться у `tests/http/lab-04-access.http`. Спочатку надішліть
login-запит, потім `GET /api/me`; лише відповідь `200` для потрібного
користувача підтверджує, що HTTP Client зберіг cookie-сеанс. Не додавайте до
звіту або Git відповідь login із заголовком `Set-Cookie`.

Для сценарію стану «до» працюйте лише в окремому локальному worktree та на
іншому порту й ізольованій БД. Не публікуйте уразливий commit у відкритому
remote і не використовуйте його для deployment.

## Діагностика

- `401` після успішного login у `.http` означає, що клієнт не надіслав cookie:
  перевірте один і той самий host (`localhost` або `127.0.0.1`) і збереження
  cookies у вашому HTTP Client.
- `address already in use` означає, що API вже запущений на обраному порту;
  зупиніть саме той локальний процес через `Ctrl+C` або задайте інший порт.
- Для запуску API потрібні Docker PostgreSQL, .NET SDK із `global.json` і
  `ASPNETCORE_ENVIRONMENT=Development`.
- Якщо виконання PowerShell-скрипта блокує політика, не змінюйте системну
  policy: задайте змінні середовища в налаштуваннях Test Runner вручну.

Перед commit перевіряйте `git status` і `git diff --staged`. Не додавайте
`.runsettings`, cookies, tokens, паролі, логи з headers або дампи БД.
