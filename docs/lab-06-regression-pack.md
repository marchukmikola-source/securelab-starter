# Regression pack ЛР 6

Повтор: `python scripts/verify_lab06_stage3.py`. Власна локальна synthetic БД
скидається до відомого seed між незалежними наборами та після завершення.
Статус кожного фактичного тесту — у `checks.tests.scenarios` файлу
[lab06-stage3.json](evidence/lab06-stage3.json). Історичні ID ЛР 4–5 збережені;
назви класів/методів нижче — точні executable selectors, а не нові номери старих сценаріїв.

| Група / ID | Автоматизована перевірка | Негативна та позитивна умови |
|---|---|---|
| Validation | `IncidentCreationContractTests`, `RegistrationContractTests`, `RegistrationRequestSerializationTests` | 400/409 та незмінність при порушенні DTO/довжин/форматів; дозволені boundary values створюються |
| SQLi / query semantics | `SearchMechanicsTests` | Controlled read-only input не розширює вибірку; apostrophe/percent зберігають визначену семантику; лише allowlisted sort; normal USB search працює |
| Authentication | `AuthenticationMechanicsTests`, `CurrentUserEndpointTests`, `AuthenticationProtectionTests`, `LoginAttemptLimiterTests` | Anonymous/forged cookie → 401, generic failed login, quota → 429; справжній login/profile/logout та recovery |
| Authorization / IDOR | `IncidentAuthorizationTests`, `IncidentTriageAuthorizationTests`; оригінальні `lab04_access.py --expect fixed --perimeter --mutation`, `lab04_triage_fixed.py` | A-01/A-02/A-03/A-03R/A-05/A-10/A-11/A-12 та mutation/triage як у старих scripts; owner/Analyst дозволені, non-owner/Reporter/admin відхиляються за матрицею |
| REG-XSS-01 / safe DOM | `lab06_browser_check.cjs`, `lab06_stage2_browser.cjs` | Збережений навчальний marker показано текстом, код не виконується; normal list/details/forms/F5 працюють; pageErrors/CSP violations = 0 |
| REG-CORS-01 | `BrowserHardeningTests.Cors_OnlyPermitsTheExactDevelopmentReadOrigin`, actual Chrome probe на 4173/4174 | Тільки exact origin читає дозволений GET; token endpoint не читається cross-origin; direct HTTP не видається за browser enforcement |
| REG-CSRF-01 | `BrowserHardeningTests.RegCsrf01_RealCookieDenialPreservesStateThenTokenAllowsMutation`, Chrome raw cookie context | Login → missing/invalid token 400 → unchanged GET → token 200 → valid PUT 204 → intended change |
| CSRF весь perimeter | `EveryCookieMutation_RejectsMissingOrInvalidTokenWithoutChangingState`, `SessionRevocationTests` | 6 cookie mutations × missing/invalid token; incident/history або sessions незмінні. Видача вимагає auth, no-store/no-CORS; legitimate forms працюють після F5 |
| Search rate limiting | `SearchRateLimitTests`, actual Chrome quota 30/10 | Over-limit 429, forged header/query не вибирає partition, Bob незалежний, IDOR не надається, recovery працює |
| Production errors / headers | `ProductionProfileTests`, actual isolated unreachable loopback DB | 500 safe ProblemDetails, matching log TraceId, headers на static/API/400/404/500; Production cookie flags та reset refusal |
| ADV-SESSION-01 (новий) | `SessionRevocationTests`, `lab06_stage3_browser.cjs` | Два Alice + replay → 401 після revoke; Bob → 200; fresh login працює; old token 400 без завершення нового сеансу; fresh token 204 |
| ADV-SESSION-02 (новий) | `BobSelfRevocation_CannotTargetAlice`, `PasswordChecks_AreBoundedBySubject_429DoesNotRevoke_RecoversAfterWindow` | Bob відкликає лише Bob; 5 × wrong password 403, shared-subject sixth attempt 429 без revoke; інша quota та recovery; failure audit |
| ADV-SESSION-03 (новий) | `SameUserOldAntiforgery_AfterStampRotationAndRelogin_BeforeAfterProvider`, anonymous round-trip, `ValidationCost_...` | Default provider old token 204 / stamp-bound 400; anonymous підтримується; 30 хв vs 0: SQL commands, latency, Set-Cookie та flags |
| F-03 поза checklist | `ConcurrentTriageTests.SimultaneousTriage_ExactlyOneTransitionAndOneHistoryRecord` | Два підтверджені одночасні читання: до 2 × 204 / 2 history; після 204 + 409 / 1 history; canonical status Triaged |

При поновленні cookie порівнюється verified subject, а не рівність байтів
cookie: `ValidationInterval=0` закономірно змінює захищений ticket. Це не зміна
матриці доступу ЛР 4. Сценарій A-11 виконується на відновленому seed, бо його
контракт передбачає точні початкові summary counts.

`--resume-after-tests` дозволено лише для продовження доказів при точному збігу
збереженого SHA-256 усіх build inputs та вже успішних тестах. При зміні source,
tests, contracts, packages або settings runner вимагає повний прогін.
CP-04 має виконати фінальну перевірку прийнятого release state окремо.
