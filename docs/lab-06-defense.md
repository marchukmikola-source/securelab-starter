# Підготовка до live defense ЛР6

Автор пояснює реалізацію самостійно. Нижче — підготовлений сценарій на 2–3 хв;
факт особистого захисту ще не перевірено. Працювати тільки на локальному synthetic стенді.

## Коротка зміна: search quota

1. Зробити окрему робочу гілку від перевіреного v1.0.0. Сам tag не змінювати.
2. У `src/SecureLab.Api/appsettings.json` змінити `RateLimiting:Search:PermitLimit`
   з 30 на 2; window залишити 10 секунд. Перезапустити Development API.
3. Увійти Alice на auth-lab.html; у browser console виконати:

```javascript
for (let i = 0; i < 3; i++) {
  const response = await fetch('/api/incidents/search?q=USB', { credentials: 'same-origin' });
  console.log(response.status);
}
```

Очікування нового вікна: 200, 200, 429. Bob у незалежному browser profile має
окрему квоту. Після 10 секунд Alice знову отримує 200. У screenshots показувати
тільки status, без cookie/token/пароля чи повних headers.

## Пояснення

Partition походить із NameIdentifier перевіреного principal; підставлений
userId/header не змінює її. Quota обмежує частоту, authorization і owner scope
залишаються окремими контролями. `SearchRateLimitTests` перевіряє quota,
subject isolation, spoof rejection, foreign resource denial та recovery.

## Резервний доказ

REG-CSRF-01: authenticated owner PUT без token → 400, повторний GET без зміни;
valid pair → 204 та intended change. Увесь сценарій повторює
`BrowserHardeningTests.RegCsrf01_RealCookieDenialPreservesStateThenTokenAllowsMutation`.
Для F-03 пояснити, чому read-then-save не замінює conditional atomic UPDATE.
Для approved variant пояснити 60 проти 10 SQL commands та Set-Cookie renewal.
