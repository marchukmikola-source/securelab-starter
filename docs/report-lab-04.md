# ЛР 04: контроль доступу до Incident

Дата фінальної перевірки: 18.10.2026. Виконано пункти 2–6 для існуючих
маршрутів cumulative state: матрицю доступу, відтворюваний vulnerable state,
серверне виправлення, regression tests і повторний HTTP PoC.

## Пункти 2–3: контракт доступу

[Матриця доступу](access-matrix.md) визначає окремі права Reporter, Analyst
та Administrator. Reporter читає й оновлює лише власний Incident; Analyst
читає всі Incident для аналізу; Administrator не отримує автоматичних прав.
Для authenticated Reporter чужий ресурс і відсутній GUID повертають однакову
безпечну `404`; анонімний запит — `401`; дозволений ресурс із відсутнім
правом на операцію — `403`.

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

## Фінальна перевірка

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

## Використання ШІ

Codex використано для звірення вимог, підготовки контрольованого сценарію,
реалізації серверної авторизації, запуску перевірок і оформлення доказів.
Автору роботи потрібно вміти пояснити відмінність між authentication,
ownership та дозволом на конкретну операцію.
