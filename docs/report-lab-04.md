# ЛР 04: контроль доступу до Incident

Дата фінальної перевірки: 18.10.2026. Виконано пункти 2–6 для рівня
«Відмінно»: матрицю доступу, відтворюваний вразливий стан, серверне
виправлення, регресійні тести та повторний HTTP PoC.

## Пункти 2–3: контракт доступу

[Матриця доступу](access-matrix.md) встановлює такі правила: Reporter читає
й змінює лише власні Incident; Analyst читає всі Incident для аналізу, бачить
internal comments і переводить лише `New -> Triaged`; Administrator не має
автоматичних прав. Анонімний запит отримує `401`, Reporter до чужого ресурсу
— таку саму безпечну `404`, як і для відсутнього id, а доступний ресурс із
забороненою операцією дає `403`.

## Вразливий і виправлений стани

- Базовий commit: `73901c423e7dc16ef0b19d9f3cbe96e1c710b856`.
- Вразливий commit: `390bc0421e33d8815444cb0c37d5398b54d5d6c8`
  (`Reproduce controlled incident access vulnerability`).
- Виправлений стан цього звіту буде зафіксований окремим commit і тегом
  `v0.4.0`.

У вразливому стані details не вимагав входу, а `PUT` перевіряв лише login.
Тому Alice з незмінним authenticated client могла прочитати й змінити Incident
Bob, змінивши тільки GUID у URL. [Початковий HTTP-доказ](evidence/lab04-poc.txt)
зберігає фактичні результати: anonymous details `200`, Alice -> Bob details
`200`, Alice -> Bob update `204` і `foreign_content_changed=true`. Після
mutation початковий content Bob був відновлений у тимчасовій БД.

## Реалізоване виправлення

`IncidentAccessRules` приймає рішення з verified subject і role claims,
операції та завантаженого сервером ресурсу. Endpoint не довіряє id, owner,
role чи status із request body. Фільтр ownership застосовується до списку,
пошуку та severity-summary ще до сортування, проєкції й агрегації.

Додано захищені маршрути details, update, delete-deny, triage та direct child
comment. Update приймає тільки title/description і відхиляє protected JSON
fields із `400`. Triage доступний тільки Analyst для поточного `New`; відмова
Reporter фіксує structured `authorization.denied` з тим самим traceId, що й
Problem Details response. UI не змінювався.

## Фінальна перевірка

Команда для повторення з кореня проєкту в PowerShell 7 (Docker має працювати):

```powershell
.\scripts\verify_lab04_poc.ps1 -Port 5084 -ExpectedState fixed -Python python
```

Скрипт створює лише власну БД `securelab_lr04_poc_<random>`, запускає API на
окремому порту, прибирає створений API й тимчасову БД та відновлює змінні
оточення. Пароль існує лише в пам'яті процесу; у доказах немає значень
password, cookie, token або `Set-Cookie`.

Фактичний запуск 18.10.2026: build — **0 warnings, 0 errors**; тестів —
**97 passed, 0 failed, 0 skipped**. Повний безпечний витяг зберігається у
[evidence/lab04-fixed.txt](evidence/lab04-fixed.txt).

| Перевірка | Результат fixed PoC |
|---|---|
| A-01 anonymous -> Bob | `401` Problem Details |
| A-02 Alice -> Alice | `200` |
| A-03 / A-10 Alice -> Bob і missing | однакові безпечні `404` |
| A-03R Morgan/Analyst -> Alice/Bob | `200` |
| A-04 Alice update Bob | `404`; content Bob не змінився |
| A-05 / A-11 list, search, summary Reporter | лише власна множина |
| A-08b protected fields update | `400`, стан не змінився |
| A-12 direct child/internal | parent та internal rules пройдені |
| A-06 / A-07 triage | Reporter `403`; Analyst `New -> Triaged` пройшов |
| A-09 audit deny | traceId відповіді збігається з `authorization.denied` |

`tests/SecureLab.Api.Tests/IncidentAuthorizationTests.cs` додає регресійне
покриття для цих рольових, ownership, mutation, child і audit сценаріїв.

## Використання ШІ

Codex використано для звірення вимог, підготовки контрольованого сценарію,
реалізації серверної авторизації, запуску перевірок і оформлення доказів.
Автору роботи потрібно вміти пояснити відмінність між authentication,
ownership та дозволом на конкретну операцію.
