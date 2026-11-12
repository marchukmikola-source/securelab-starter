# SecureLab - трекер інцидентів, ЛР6

Автор: Микола Марчук. Baseline 2-A, цільовий рівень - відмінний.
ASP.NET Core / Identity cookie / EF Core / PostgreSQL / Vanilla JS.
Це cumulative fixed state ЛР1-6. Історичні протоколи збережено в docs.

[Матеріали публікації ЛР №6, звіти PDF/Word і локальний CSP-probe](docs/lab-06-publication.md).

## Передумови

- .NET 10: перевірено SDK 10.0.403; global.json задає 10.0.100 + latestFeature, без prerelease.
- Docker Desktop / docker compose; Git.
- Для повної автоматизації: Python 3, Node.js, JS package playwright та встановлений Chrome.
- Playwright має бути доступний через NODE_PATH або node_modules; у Codex bundled runtime runner знаходить NODE_PATH автоматично.
- Для PDF export: Python reportlab; для перевірки PDF - pypdf та Poppler.
- Вільні loopback порти: API 5080, CORS probes 4173/4174, error experiment 54399; PostgreSQL 54329.

## Відтворюваний повний прогін

Запускати тільки на власній локальній synthetic БД. Runner скидає відомі навчальні таблиці
перед/між наборами й після завершення. Зовнішні DB/hosts не входять у scope.

```powershell
docker compose --env-file infra/.env.example -f infra/compose.yaml up -d --wait
python scripts/verify_lab06_stage3.py
```

Звичайний режим записує поточний CP-03 у docs/evidence/lab06-stage3.json.
Для фінальної перевірки committed release використовуйте **чистий checkout**:

```powershell
python scripts/verify_lab06_stage3.py --release
```

Release mode перевіряє чисте дерево до/після, виконує fresh locked restore, audit,
Release build, весь test pack, Chrome/CORS/CSP/CSRF, advanced revoke-all, log/secret review,
Production normal/error та відновлює seed. Усі результати й raw logs залишає тільки
в ignored tmp/lab06/release. Final proof: verification.json, dependency-audit.txt,
secret-review.json та screenshots у цій папці. Raw logs не включаються до submission.

SeedUsers__Password читається з env або ignored tmp/lab06/local.runsettings;
за відсутності обох runner створює випадковий локальний пароль і runsettings.
Значення не друкуються. Початкові alice/bob/morgan/admin використовують цей seed-пароль.
DB credentials у Development/Compose/design-time - відкрита study-only fixture для
loopback; їх не можна повторно використовувати для іншого середовища.

## Ручний запуск після автоматичного seed

```powershell
$localSettings = [xml](Get-Content ./tmp/lab06/local.runsettings -Raw)
$env:SeedUsers__Password = $localSettings.RunSettings.RunConfiguration.EnvironmentVariables.SeedUsers__Password
$env:ASPNETCORE_ENVIRONMENT = 'Development'
dotnet run --project src/SecureLab.Api -c Release --no-launch-profile --urls http://localhost:5080
```

Відкрити http://localhost:5080/ та /auth-lab.html; readiness - /health.
Development OpenAPI JSON - /openapi/v1.json, Scalar - /scalar/v1.
У Production OpenAPI/Scalar endpoints не реєструються: /scalar/v1 може повернути
HTML index fallback з 200; перевіряйте Content-Type і тіло. Production потребує
явного ConnectionStrings__SecureLab поза Git; migrations/reset defaults false,
cookie Secure/HttpOnly/SameSite flags перевірені HTTPS-addressed TestServer.
Реальний TLS deployment не перевірявся.

## Окремі build / tests

```powershell
dotnet restore SecureLab.sln --locked-mode
dotnet build SecureLab.sln -c Release --no-restore
dotnet test SecureLab.sln -c Release --no-build --no-restore --settings tmp/lab06/local.runsettings
```

Окремі tests очікують initialized known seed; для гарантованого reset використовуйте
full runner. Reset дозволений лише у Development з Database:AllowReset=true:
`dotnet run --project src/SecureLab.Api -- --reset-database` (той самий локальний seed env).

## Контролі й перевірки

Після login client одержує standard antiforgery request token; після F5 відновлює
його перед mutation. GET /api/auth/csrf вимагає auth, no-store/no-CORS; token тільки
в пам'яті. X-CSRF-TOKEN потрібний для create/update/delete/triage/logout/revoke-all.
Login/register мають окреме anonymous scope-рішення з residual risk у review.
POST /api/me/sessions/revoke-all приймає лише currentPassword; self-only,
standard CSRF + CheckPasswordAsync + 5 спроб/2 хв на verified subject.
SecurityStamp rotation відкликає старі cookie на наступному protected request;
поточний сеанс також завершується. ValidationInterval=0 збільшує DB/Set-Cookie cost.
Search quota - 30/10 секунд на principal; login limiter збережено окремо.

- [Security review](docs/security-review.md), [threat model](docs/threat-model.md).
- [Finding cards](docs/findings/README.md), [regression pack](docs/lab-06-regression-pack.md).
- [Approved variant](docs/advanced-variant-proposal.md), [approval evidence](docs/evidence/lab06-advanced-approval.md).
- [CP-04 / delivery](docs/lab-06-stage4.md), [live defense](docs/lab-06-defense.md).
- [Manual CSRF flow](tests/http/lab-06-csrf.http).

## Final release / submission

Committed docs -> чистий candidate run -> no-ff merge в main -> full --release на
прийнятому merge -> annotated v1.0.0 -> export поза репозиторієм.
Не пересувайте existing tag. Exporter перевіряє HEAD == tag commit == verified run,
чистий Git state та створює PDF/ZIP/hash без зміни tracked docs:

```powershell
python scripts/export_lab06_submission.py --output-dir ../lr06-submission --verification tmp/lab06/release/verification.json
```

Private remote visibility не підтверджена; fallback - локальний ZIP і hashes tag.
Не публікуйте repository чи logs. Moodle upload та особистий захист виконує автор.
