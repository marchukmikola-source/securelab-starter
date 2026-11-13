[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('2', '3', '4', '5a', '5b', '5c', '6', '7', '8', '9')]
    [string]$Section
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$projectRoot = Split-Path -Parent $PSScriptRoot
$evidencePath = Join-Path $projectRoot 'docs\evidence\lab06-stage2.json'
if (-not (Test-Path -LiteralPath $evidencePath -PathType Leaf)) {
    throw "Evidence file not found: $evidencePath"
}
$proof = Get-Content -LiteralPath $evidencePath -Encoding UTF8 -Raw | ConvertFrom-Json
if ($null -eq $proof.checks -or $null -eq $proof.checks.browser) {
    throw 'The evidence file has no checks.browser section.'
}
$browser = $proof.checks.browser
$timestamp = ([datetimeoffset]$proof.startedAtUtc).UtcDateTime.ToString('yyyy-MM-dd HH:mm:ss')
Write-Output 'SecureLab LR06 - recorded stage 2 evidence'
Write-Output "Run started: $timestamp UTC; overall result: $($proof.status)"
Write-Output "Source: $evidencePath"
Write-Output "Section: $Section"

switch ($Section) {
    '2' {
        if (@($proof.checks.'openapi-mutation-perimeter').Count -eq 0) {
            throw 'The recorded mutation perimeter is empty.'
        }
        $proof.checks.'openapi-mutation-perimeter' |
            Format-Table method, route -AutoSize
        $proof.checks.'final-contract-verification' |
            Select-Object openapiDeclaredStatusesVerified, protectedMutationCount, publicAuthMutationCount |
            Format-List
    }
    '3' { $browser.regCsrf01 | Format-List }
    '4' { $browser.ui | ConvertTo-Json -Depth 6 }
    '5a' {
        $responses = @($browser.headers) + @($proof.checks.'production-500-headers')
        $responses | Select-Object profile, status, method, route | Format-Table -AutoSize -Wrap
    }
    '5b' {
        $responses = @($browser.headers) + @($proof.checks.'production-500-headers')
        $responses | ForEach-Object {
            [pscustomobject]@{
                Profile = $_.profile
                Status = $_.status
                CSP = $_.headers.'content-security-policy'
                NoSniff = $_.headers.'x-content-type-options'
                Referrer = $_.headers.'referrer-policy'
            }
        } | Format-Table -AutoSize -Wrap
    }
    '5c' {
        $failure = $proof.checks.'production-500-headers'
        $failure | Select-Object profile, method, route, status, contentType, traceMatches | Format-List
        $failure.headers | Format-List
    }
    '6' {
        $browser.cors |
            Format-Table origin, readable, status, browserBlocked, tokenEndpointReadable -AutoSize -Wrap
        $browser.corsDirectHttp | Format-List
    }
    '7' {
        $browser.cookies | ConvertTo-Json -Depth 4
        $proof.checks.'final-contract-verification' |
            Select-Object targetedProductionCookieTestPassed, antiforgeryCookieProductionFlags |
            ConvertTo-Json -Depth 4
    }
    '8' { $browser.searchRateLimit | Format-List }
    '9' {
        $limiterPath = Join-Path $projectRoot 'src\SecureLab.Api\Application\Authentication\LoginAttemptLimiter.cs'
        Get-Content -LiteralPath $limiterPath -Encoding UTF8 |
            Where-Object { $_ -match 'MaximumFailedAttempts =|Window =' }
        $scenarios = @($proof.checks.tests.securityScenarios | Where-Object {
            $_.test -match 'Login_AfterMaximumFailedAttempts|FailedAttempts_ArePartitionedAndExpire'
        })
        if ($scenarios.Count -eq 0) { throw 'No login limiter test results found in the evidence file.' }
        $scenarios | Format-List test, outcome
    }
}
