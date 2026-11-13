# ЛР6: CP-04, підсумковий огляд і release

Автор: Микола Марчук. Baseline 2-A. Обраний рівень: відмінний.
Дата підготовки вихідних документів: 09.11.2026.

## DEL-01: межі й модель загроз

`docs/threat-model.md`: assets, subjects, entry points, trust boundaries,
diagram, exclusions і reproducible start. Зв'язок asset → threat → control →
verification збережено; local HTTP і реальний production deployment не ототожнені.

## DEL-02: review і findings

`docs/security-review.md` містить 12 розділів, hardening controls, dependency
decision, source secret review, original-log audit, trace linkage, CSRF perimeter,
regression summary, AI declaration. F-01/F-02/F-03 — три виправлені finding cards;
F-03 поза прямим checklist, з власним негативним concurrency proof до fix.
Порядок пріоритетів: F-01 → F-03 → F-02 через impact/likelihood/preconditions.
Погодження advanced variant збережене дослівно з наданої користувачем відповіді.

## DEL-03: regression і Git state

1. Завершити source/docs та переглянути staged diff проти review-start ee18ff4.
2. Зберегти початкові сторонні зміни ЛР4–5; не включати їх механічно через git add .
3. Commit ЛР6; перевірити кандидат у чистому detached worktree.
4. У чистому main worktree виконати `git merge --no-ff --no-edit lab/6-hardening-review`.
5. На прийнятому merge виконати `python scripts/verify_lab06_stage3.py --release`.
6. Лише після PASS створити annotated `v1.0.0`; existing tag не пересувати.
7. Експортувати PDF і ZIP за tag у папку поза Git; tracked docs після tag не змінювати.

Release mode повторює locked restore, audit, Release build, усі xUnit tests,
повний REG-CSRF-01, Chrome forms/F5/CSP/CORS, search quota/isolation/recovery,
оригінальні access/triage PoC, approved revoke-all, шість log classes,
Production normal/error профілі, source secret review та відновлення seed.
Перевіряються чистий Git state до/після і actual HEAD. Усі generated outputs
лишаються під ignored `tmp/lab06/release`; історичні CP-01–03 не переписуються.

Production Scalar-like URL окремо перевіряється за Content-Type і тілом:
`/scalar/v1` може дати 200 text/html як index fallback, це не зареєстрований Scalar.
OpenAPI JSON у Production — 404; migrations/reset guards і cookie flags перевірені tests.
Контрольована помилка використовує тільки child-process loopback DB override;
production throw/debug endpoint не додається.

## Пакет подання

Експорт містить security-review.pdf (review, threat model, finding cards,
approved variant, cleaned evidence, actual final hash/run), release-verification.json,
security-review-source.zip і SHA256SUMS.txt з hash annotated tag та його commit.
Git remote існує, але його private visibility/дозвіл на delivery не підтверджені;
замість push готується приватний локальний ZIP. Автоматичне завантаження у Moodle
або повідомлення викладачу не виконується.

Попередні сторонні dirty/untracked матеріали залишаються в початковому worktree;
main release worktree має бути чистим. Незмінений успадкований IncidentDecTests
включено свідомо: він уже входив до 135-test CP-03 pack і зберігає owner-positive regression.
Фінальні hashes і counters додаються тільки під час експорту, без самопосилання у commit.

## Захист

`docs/lab-06-defense.md` дає коротку live modification і пояснення контролю.
Особистий захист/авторське розуміння студента автоматизацією не підтверджуються.
