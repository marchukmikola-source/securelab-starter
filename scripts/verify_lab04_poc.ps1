param(
    [string]$Python = 'python',
    [string]$Container = 'secure-lab-postgres-1',
    [ValidateRange(1024, 65535)][int]$Port = 5080,
    [ValidateSet('vulnerable', 'fixed')][string]$ExpectedState = 'vulnerable'
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
    & dotnet test tests/SecureLab.Api.Tests/SecureLab.Api.Tests.csproj -c Release --no-build --artifacts-path $artifacts
    Assert-Exit 'Existing regression suite'
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
    & $Python -X utf8 scripts/lab04_access.py --host $apiHost --expect $ExpectedState --check
    Assert-Exit 'Environment check'
    $pocOutput = & $Python -X utf8 scripts/lab04_access.py --host $apiHost --expect $ExpectedState --perimeter --mutation
    $pocOutput
    Assert-Exit 'HTTP PoC'
    if ($ExpectedState -eq 'fixed') {
        $traceLine = $pocOutput | Where-Object { $_ -like 'triage_denied_trace_id=*' } | Select-Object -Last 1
        if (-not $traceLine) { throw 'Fixed scenario did not return a triage deny trace id.' }
        $traceId = $traceLine.Substring('triage_denied_trace_id='.Length)
        $auditLine = Get-Content -LiteralPath (Join-Path $runDirectory 'api.stdout.log') |
            Where-Object { $_ -match 'authorization\.denied' -and $_ -like "*$traceId*" } |
            Select-Object -Last 1
        if (-not $auditLine) { throw 'Missing correlated authorization.denied audit event.' }
        if ($auditLine -match '(?i)password|cookie|token|authorization:') {
            throw 'Audit event contains a prohibited secret-related field.'
        }
        Write-Output 'triage_audit_trace_correlation=passed'
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
