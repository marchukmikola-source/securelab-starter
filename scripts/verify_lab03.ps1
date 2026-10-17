param([switch]$ResetTwice)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path 'global.json')) { throw 'Run from the SecureLab root.' }
if (-not $env:SeedUsers__Password) { throw 'Set SeedUsers__Password outside Git.' }
if (-not $ResetTwice) { throw 'Use -ResetTwice only for the local synthetic database.' }

# Retained from LR03 and adapted to the LR04 seed (three comments, one internal).
# Store only counts and a checksum of non-secret logical data. Identity hashes,
# security stamps, tokens and connection strings never enter this evidence.
$stateQuery = @'
WITH logical_state AS (
  SELECT jsonb_build_object(
    'users', (SELECT jsonb_agg(jsonb_build_array("Id", "UserName", "DisplayName") ORDER BY "Id") FROM identity_users),
    'roles', (SELECT jsonb_agg(jsonb_build_array("Id", "Name") ORDER BY "Id") FROM identity_roles),
    'memberships', (SELECT jsonb_agg(jsonb_build_array("UserId", "RoleId") ORDER BY "UserId", "RoleId") FROM identity_user_roles),
    'incidents', (SELECT jsonb_agg(to_jsonb(i) ORDER BY id) FROM incidents i),
    'comments', (SELECT jsonb_agg(to_jsonb(c) ORDER BY id) FROM incident_comments c),
    'history', (SELECT jsonb_agg(to_jsonb(h) ORDER BY id) FROM incident_status_history h)
  )::text AS value
)
SELECT json_build_object(
  'users', (SELECT count(*) FROM identity_users),
  'roles', (SELECT count(*) FROM identity_roles),
  'memberships', (SELECT count(*) FROM identity_user_roles),
  'incidents', (SELECT count(*) FROM incidents),
  'comments', (SELECT count(*) FROM incident_comments),
  'internalComments', (SELECT count(*) FROM incident_comments WHERE is_internal),
  'fixedInternalComment', EXISTS (SELECT 1 FROM incident_comments WHERE id = '30000000-0000-0000-0000-000000000003' AND incident_id = '20000000-0000-0000-0000-000000000001' AND author_user_id = '10000000-0000-0000-0000-000000000003' AND is_internal),
  'history', (SELECT count(*) FROM incident_status_history),
  'authAuxiliaryRows', (SELECT (SELECT count(*) FROM identity_user_claims) + (SELECT count(*) FROM identity_role_claims) + (SELECT count(*) FROM identity_user_logins) + (SELECT count(*) FROM identity_user_tokens)),
  'legacyAbsent', to_regclass('public.study_users') IS NULL,
  'fixedAccountsAndRoles', (SELECT count(*) = 4 FROM identity_users u JOIN identity_user_roles ur ON ur."UserId" = u."Id" JOIN identity_roles r ON r."Id" = ur."RoleId" WHERE
    (u."Id" = '10000000-0000-0000-0000-000000000001' AND u."UserName" = 'alice' AND r."Name" = 'Reporter') OR
    (u."Id" = '10000000-0000-0000-0000-000000000002' AND u."UserName" = 'bob' AND r."Name" = 'Reporter') OR
    (u."Id" = '10000000-0000-0000-0000-000000000003' AND u."UserName" = 'morgan' AND r."Name" = 'Analyst') OR
    (u."Id" = '10000000-0000-0000-0000-000000000004' AND u."UserName" = 'admin' AND r."Name" = 'Administrator')),
  'fixedOwners', (SELECT count(*) = 2 FROM incidents WHERE (id = '20000000-0000-0000-0000-000000000001' AND owner_user_id = '10000000-0000-0000-0000-000000000001') OR (id = '20000000-0000-0000-0000-000000000002' AND owner_user_id = '10000000-0000-0000-0000-000000000002')),
  'logicalChecksum', (SELECT md5(value) FROM logical_state)
);
'@

$snapshots = @()
$env:Logging__LogLevel__Microsoft = 'Warning'
foreach ($round in 1..2) {
    & dotnet run --project src/SecureLab.Api -- --reset-database --Logging:LogLevel:Microsoft.EntityFrameworkCore.Database.Command=Warning
    if ($LASTEXITCODE -ne 0) { throw "Reset $round failed." }

    # Send SQL through stdin: Windows PowerShell's native argument quoting can
    # strip the double quotes required by case-sensitive Identity column names.
    $safeState = $stateQuery | & docker compose --env-file infra/.env.example -f infra/compose.yaml exec -T postgres psql -X -v ON_ERROR_STOP=1 -U securelab -d securelab -At -f -
    if ($LASTEXITCODE -ne 0) { throw 'Logical seed verification failed.' }
    $snapshot = ($safeState -join '') | ConvertFrom-Json
    if ($snapshot.users -ne 4 -or $snapshot.roles -ne 3 -or $snapshot.memberships -ne 4 -or $snapshot.incidents -ne 5 -or $snapshot.comments -ne 3 -or $snapshot.internalComments -ne 1 -or -not $snapshot.fixedInternalComment -or $snapshot.history -ne 1 -or $snapshot.authAuxiliaryRows -ne 0 -or -not $snapshot.fixedAccountsAndRoles -or -not $snapshot.fixedOwners -or -not $snapshot.legacyAbsent) {
        throw 'Seed invariant failed (sensitive values omitted).'
    }
    $snapshots += $snapshot
    Write-Output "Reset ${round}: users=4 roles=3 memberships=4 incidents=5 comments=3 internalComments=1 history=1; fixed GUIDs/roles/owners/internal comment=True; auxiliary auth tables empty=True; legacy store absent=True."

    & dotnet test tests/SecureLab.Api.Tests -c Release --logger 'console;verbosity=quiet'
    if ($LASTEXITCODE -ne 0) { throw "Tests after reset $round failed." }
}
if ($snapshots[0].logicalChecksum -ne $snapshots[1].logicalChecksum) { throw 'Two resets differ in logical state.' }
Write-Output 'Two-reset logical state equality: True. Registration regression passed after each reset.'
