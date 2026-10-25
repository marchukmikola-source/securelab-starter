# Lab 05 browser capture checklist

Цей checklist відокремлює фінальні browser-докази, які ще треба зняти, від server-side headers і source review, уже збережених у repository. Він не дозволяє текстовому твердженню підміняти DevTools observation.

Before every capture: start the final fixed API, sign in with the relevant training account, open DevTools, enable **Preserve log**, clear Console and Network, and hide cookie values and passwords.

| ID | Required frame | Exact observation to retain | Status in the current evidence set |
|---|---|---|---|
| CAP-01 | Vulnerable Description PoC | Alice POST `201`, details GET `200`, Elements shows generated `img`, then marker `executed` for `dd114e4c-bc28-4b00-91f0-a2946f3ea193` | Recreate in the isolated vulnerable worktree; no raw screenshot is retained |
| CAP-02 | Cross-user authorization | Morgan reads CAP-01 record; Bob receives `404` and no description response | Recreate in the isolated vulnerable worktree; no raw screenshot is retained |
| CAP-03 | Vulnerable public comment | Elements shows the generated element before the safe renderer | Recreate in the isolated vulnerable worktree; no raw screenshot is retained |
| CAP-04 | Allowed CORS preflight | `OPTIONS` from `http://localhost:4173`, then GET; Request Headers include `Origin` and Cookie presence; Response Headers include ACAO, ACAC, methods and headers | Must be captured on final fixed state |
| CAP-05 | Credential transition | Before `AllowCredentials`, browser rejects credentialed read; after it, `4173` reads `200`; after logout it reads `401` | Must be captured on final fixed state |
| CAP-06 | CSP enforcement | Network row for external `http://localhost:4173/x.png` blocked by CSP, plus matching Console message | Must be captured on final fixed state |
| CAP-07 | Clean smoke frames | Empty-error Console after loading `/`, `/browser-lab.html`, and `/auth-lab.html` | Must be captured on final fixed state |
| CAP-08 | Automated suite | Complete terminal output and `.trx` from the fixed release source after reset | Done 2026-10-26: `101 passed, 0 failed, 0 skipped`; see `lab05-final-test-output.txt` and `lab05-final.trx` |
| CAP-09 | Normal-text regression | Console result for exact 4000-character, quote, `</>` and Ukrainian text check | Must be captured on final fixed state; a copied Console view must not be used to judge character encoding |

Direct curl header transcript у `lab05-cors-direct-headers.txt` перевіряє, що саме повернув server. Він не замінює CAP-04/CAP-05, бо лише DevTools показує, як browser застосував CORS до credentialed request.
