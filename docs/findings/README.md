# Знахідки ЛР 6

На етапі 2 виправлено й перевірено:

- [F-01 — відсутній standard CSRF control](F-01-cookie-csrf.md), P2.
- [F-02 — заголовки губилися на error path](F-02-error-path-headers.md), P3.

- [F-03 — гонка двох triage та дублювання історії](F-03-concurrent-triage.md), P2.

F-01/F-02 стосуються checklist. F-03 — окрема відтворена business-logic
finding поза checklist; негативний доказ збережено до виправлення,
той самий concurrency test після виправлення перевіряє позитивний перехід
та відмову конкурента. Остаточний release оформлюється в CP-04.
