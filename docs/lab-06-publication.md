# ЛР №6: публікація та додатковий CSP-експеримент

Гілка GitHub: `lab/6-hardening-review`.

## Склад

- Виправлений код ЛР №6, тести й сценарії перевірок.
- [Огляд безпеки](security-review.md), [модель загроз](threat-model.md), [findings](findings/README.md), [regression pack](lab-06-regression-pack.md).
- Докази етапів у `docs/evidence/lab06-*` і підготовлені скриншоти.
- Детальний звіт: [PDF](reports/lab06/security-review.pdf) та [Word](reports/lab06/security-review.docx).
- Локальний приймач синтетичних POST у `scripts/lab06-probe`.

Публікацію побудовано поверх GitHub `main` (`6deee13`), щоб не переносити локальну історію навчальних вразливих версій. SHA попередніх локальних запусків у збережених доказах є історичними ідентифікаторами; вони не є ідентифікатором нового публічного коміту. Попередні теги не переміщувалися.

PDF і Word зберігають раніше оформлений звіт про етапи ЛР №6. Вони не є новим протоколом додаткового ручного CSP-експерименту. Збережені докази не переписані під нову policy. Нова перевірка публікації зберігається окремо у `docs/evidence/lab06-github-verification.json`.

## Додаткова зміна CSP

У `src/SecureLab.Api/Program.cs` додано тільки `form-action 'self'`:

```text
default-src 'self'; frame-ancestors 'none'; form-action 'self'
```

Fetch залишається обмеженим через fallback до `default-src 'self'`. `frame-ancestors 'none'` збережено. Очікування заголовків у тестах та актуальних автоматизованих сценаріях узгоджено з цією policy.

Користувач вручну зафіксував повідомлення браузера про блокування зовнішньої форми через `form-action 'self'` та fetch через fallback до `default-src 'self'`. Це не є доказом блокування `location.assign`, усунення XSS або відсутності доставки без окремого огляду приймача.

## Приймач POST

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\lab06-probe\Start-CorsProbes.ps1
```

Потрібен Node.js у PATH або явний параметр `-NodePath`. На навчальному пристрої launcher також перевіряє доступний bundled runtime.

- `http://localhost:4173/events.html` — перегляд подій.
- `http://localhost:4173/events` — безпечний JSON подій.
- `POST /collect?via=form` — рівно одне form-urlencoded поле `marker=FAKE-CSP-1`.
- `POST /reset` — очистити тимчасові події цього локального probe.
- `http://localhost:4174/csp-demo` — окремий навчальний fixture із початковою policy; це не policy власного API.

Приймач не зберігає cookie, Authorization, довільні значення або повні тіла запитів. Усі події тимчасові та зберігаються в пам'яті. `verify-form-probe.cjs` перевіряє сам probe в Chrome/Playwright на окремих випадкових loopback-портах; цей тест не замінює ручний actual власного застосунку.

У новій публікації немає локальних runsettings, паролів, сирих журналів, Word lock-файлів або приватного `lab05.bundle`.
