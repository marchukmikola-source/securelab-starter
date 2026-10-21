param(
    [string]$Python = 'python',
    [string]$Container = 'secure-lab-postgres-1',
    [ValidateRange(1024, 65535)][int]$Port = 5080,
    [ValidateSet('vulnerable', 'fixed')][string]$ExpectedState = 'vulnerable',
    [switch]$TriageFixedPoC
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$runDirectory = Join-Path $repo ('tmp\lab04-poc-' + [Guid]::NewGuid().ToString('N'))
$artifacts = Join-Path $runDirectory 'artifacts'
$database = 'securelab_lr04_poc_' + [Guid]::NewGuid().ToString('N')
$apiHost = "http://localhost:$Port"
$api = $null
$databaseCreated = $false
$savedEnvironment = @{}
$environmentNames = @('SeedUsers__Password', 'ConnectionStrings__SecureLab',
    'ASPNETCORE_ENVIRONMENT', 'Logging__LogLevel__Default',
    'Logging__LogLevel__Microsoft.AspNetCore', 'DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE')
foreach ($name in $environmentNames) {
    $savedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}

function Assert-Exit([string]$Step) {
    if ($LASTEXITCODE -ne 0) { throw "$Step failed; inspect the local result." }
}

Push-Location $repo
try {
    # Refuse to reuse another process's API. Nothing in the normal securelab DB is reset.
    $probe = [Net.Sockets.TcpClient]::new()
    try {
        try { $probe.Connect('127.0.0.1', $Port) } catch [Net.Sockets.SocketException] { }
        if ($probe.Connected) { throw "Port $Port is busy; choose a free -Port for the isolated PoC." }
    } finally { $probe.Dispose() }
    New-Item -ItemType Directory -Path $runDirectory | Out-Null
    & docker exec $Container createdb -U securelab $database
    Assert-Exit 'Create isolated database'
    $databaseCreated = $true

    $env:SeedUsers__Password = 'Aa1!' + [Convert]::ToHexString(
        [Security.Cryptography.RandomNumberGenerator]::GetBytes(24))
    # This is the repository's published, local-only Docker connection baseline.
    $env:ConnectionStrings__SecureLab = "Host=127.0.0.1;Port=54329;Database=$database;Username=securelab;Password=local-study-password;Include Error Detail=false"
    $env:ASPNETCORE_ENVIRONMENT = 'Development'
    $env:Logging__LogLevel__Default = 'Information'
    [Environment]::SetEnvironmentVariable('Logging__LogLevel__Microsoft.AspNetCore', 'Warning', 'Process')
    $env:DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE = 'true'

    # Isolated outputs also avoid locking binaries of an already running normal API.
    & dotnet build SecureLab.sln -c Release --artifacts-path $artifacts -p:RestoreLockedMode=true
    Assert-Exit 'Build'
    $testResultsDirectory = Join-Path $repo 'docs\evidence\test-results'
    New-Item -ItemType Directory -Force -Path $testResultsDirectory | Out-Null
    $testOutput = & dotnet test tests/SecureLab.Api.Tests/SecureLab.Api.Tests.csproj -c Release --no-build --artifacts-path $artifacts `
        --logger 'trx;LogFileName=lab04-latest.trx' --results-directory $testResultsDirectory 2>&1
    $testExit = $LASTEXITCODE
    $testOutput | Write-Output
    if ($testExit -ne 0) { throw 'Existing regression suite failed; inspect the local result.' }
    $env:Logging__LogLevel__Default = 'Warning'

    # Test fixtures clean their own data; record the remaining synthetic seed counts.
    & docker exec $Container psql -U securelab -d $database -At -c 'SELECT (SELECT count(*) FROM identity_users) AS users, (SELECT count(*) FROM incidents) AS incidents, (SELECT count(*) FROM incident_comments) AS comments;'
    Assert-Exit 'Seed counts'
    $apiDll = Join-Path $artifacts 'bin\SecureLab.Api\release\SecureLab.Api.dll'
    $api = Start-Process -FilePath 'dotnet' -ArgumentList @(
        ('"' + $apiDll + '"'), '--urls', $apiHost) `
        -WorkingDirectory (Join-Path $repo 'src\SecureLab.Api') -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput (Join-Path $runDirectory 'api.stdout.log') `
        -RedirectStandardError (Join-Path $runDirectory 'api.stderr.log')
    $ready = $false
    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        if ($api.HasExited) { throw 'Local API exited before becoming ready.' }
        try {
            $health = Invoke-WebRequest "$apiHost/health" -TimeoutSec 2
            if ($health.StatusCode -eq 200) { $ready = $true; break }
        } catch { }
        Start-Sleep -Milliseconds 500
    }
    if (-not $ready) { throw 'Local API did not become ready.' }
    $environmentOutput = & $Python -X utf8 scripts/lab04_access.py --host $apiHost --expect $ExpectedState --check 2>&1
    $environmentExit = $LASTEXITCODE
    $environmentOutput | Write-Output
    if ($environmentExit -ne 0) { throw 'Environment check failed; inspect the local result.' }
    $httpPocOutput = & $Python -X utf8 scripts/lab04_access.py --host $apiHost --expect $ExpectedState --perimeter --mutation 2>&1
    $httpPocExit = $LASTEXITCODE
    $httpPocOutput | Write-Output
    if ($httpPocExit -ne 0) { throw 'HTTP PoC failed; inspect the local result.' }
    if ($ExpectedState -eq 'fixed') {
        $fixedEvidence = @(
            'SecureLab LR04: fixed authorization HTTP evidence.'
            "API: $apiHost; isolated synthetic PostgreSQL database."
            'Credentials, cookies, tokens, request bodies and stack traces are omitted.'
            ''
            'Regression suite:'
        )
        $fixedEvidence += $testOutput
        $fixedEvidence += ''
        $fixedEvidence += 'Environment and HTTP PoC:'
        $fixedEvidence += $environmentOutput
        $fixedEvidence += $httpPocOutput
        $fixedEvidence | Set-Content -Encoding utf8 (Join-Path $repo 'docs\evidence\lab04-fixed.txt')
        $fixedEvidence | Set-Content -Encoding utf8 (Join-Path $repo 'docs\evidence\lab04-verification-latest.txt')
        $a12Evidence = [ordered]@{
            source = 'verify_lab04_poc.ps1 isolated fixed HTTP PoC'
            endpoint = 'GET /api/incident-comments/{id}'
            assertions = @(
                [ordered]@{ actor = 'Anonymous'; target = 'Bob public comment'; status = 401 }
                [ordered]@{ actor = 'Alice / Reporter'; target = 'own public comment'; status = 200 }
                [ordered]@{ actor = 'Alice / Reporter'; target = 'Bob public comment'; status = 404 }
                [ordered]@{ actor = 'Alice / Reporter'; target = 'own internal comment'; status = 404 }
                [ordered]@{ actor = 'Morgan / Analyst'; target = 'Bob public comment'; status = 200 }
                [ordered]@{ actor = 'Morgan / Analyst'; target = 'Alice internal comment'; status = 200 }
            )
            result = 'passed; parent ownership and internal visibility are enforced by the direct child endpoint'
        }
        $a12Evidence | ConvertTo-Json -Depth 4 | Set-Content -Encoding utf8 (Join-Path $repo 'docs\evidence\lab04-a12-responses-latest.json')
    }
    if ($TriageFixedPoC) {
        $triageOutput = & $Python -X utf8 scripts/lab04_triage_fixed.py --host $apiHost 2>&1
        $triageExit = $LASTEXITCODE
        $traceLine = @($triageOutput | Where-Object { $_ -like 'denied_trace_id=*' } | Select-Object -Last 1)
        $traceId = if ($traceLine.Count -eq 1) {
            $traceLine[0].ToString().Substring('denied_trace_id='.Length)
        } else {
            '<missing>'
        }
        $auditLine = @(Get-Content (Join-Path $runDirectory 'api.stdout.log') |
            Where-Object { $_ -like '*incident.triage.denied*' } |
            Select-Object -Last 1)
        $auditEvent = if ($auditLine.Count -eq 1) { $auditLine[0].ToString() } else { '<missing>' }
        $auditTraceMatchesResponse = $traceId -ne '<missing>' -and $auditEvent -like "*$traceId*"
        $auditEventLine = 'audit_log_event=' + $auditEvent
        $auditTraceLine = 'audit_trace_matches_response=' + $auditTraceMatchesResponse.ToString().ToLowerInvariant()
        $evidence = @(
            'SecureLab LR04 points 11-12: fixed triage HTTP and audit evidence.'
            "API: $apiHost; isolated synthetic PostgreSQL database."
            'Credentials, cookies, tokens, request body and stack traces are omitted.'
            ''
        )
        $evidence += $triageOutput
        $evidence += ''
        $evidence += $auditEventLine
        $evidence += $auditTraceLine
        $evidence | Set-Content -Encoding utf8 (Join-Path $repo 'docs\evidence\lab04-triage-fixed.txt')
        if ($triageExit -ne 0) { throw 'Fixed triage PoC failed; inspect the local result.' }
        if ($traceLine.Count -ne 1 -or $auditLine.Count -ne 1 -or -not $auditTraceMatchesResponse) {
            throw 'Audit event does not contain the denial response trace id.'
        }
    }
} finally {
    if ($null -ne $api -and -not $api.HasExited) {
        # Kill only the process tree created above, including dotnet run's child API.
        $api.Kill($true)
        $api.WaitForExit()
    }
    if ($databaseCreated -and $database -match '^securelab_lr04_poc_[0-9a-f]{32}$') {
        & docker exec $Container dropdb -U securelab --force $database
        if ($LASTEXITCODE -ne 0) { Write-Warning "Temporary database cleanup failed: $database" }
        else { Write-Output 'isolated_database_removed=true' }
    }
    foreach ($name in $environmentNames) {
        [Environment]::SetEnvironmentVariable($name, $savedEnvironment[$name], 'Process')
    }
    Pop-Location
}
