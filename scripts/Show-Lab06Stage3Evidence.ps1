param(
    [ValidateSet('All', 'Tests', 'Dependencies', 'Secrets', 'Logs', 'Advanced', 'Triage')]
    [string]$Section = 'All'
)
$ErrorActionPreference = 'Stop'
$rootPath = Split-Path -Parent $PSScriptRoot
$evidencePath = Join-Path $rootPath 'docs/evidence/lab06-stage3.json'
$evidence = Get-Content -LiteralPath $evidencePath -Raw -Encoding UTF8 | ConvertFrom-Json
Write-Output ("LR06 CP-03: {0}; finished UTC: {1}" -f $evidence.status, $evidence.finishedAtUtc)
Write-Output ("Branch: {0}; SDK: {1}; scope: working tree" -f $evidence.checks.environment.branch, $evidence.checks.environment.sdk)
function Show-Proof([string]$title, $value) {
    Write-Output ""
    Write-Output $title
    $value | ConvertTo-Json -Depth 15
}
if ($Section -in @('All', 'Tests')) {
    Show-Proof 'Release build' $evidence.checks.build
    $evidence.checks.tests | Select-Object total, passed, failed, notExecuted | Format-List
}
if ($Section -in @('All', 'Dependencies')) { Show-Proof 'Direct and transitive NuGet audit' $evidence.checks.dependencies }
if ($Section -in @('All', 'Secrets')) { Show-Proof 'Secret review (values omitted)' $evidence.checks.'secret-review' }
if ($Section -in @('All', 'Logs')) {
    Show-Proof 'Normal original log review' $evidence.checks.'log-audit-normal'
    Show-Proof 'Production original exception log review' $evidence.checks.'log-audit-unexpected'
}
if ($Section -in @('All', 'Advanced')) {
    Show-Proof 'Advanced integration proofs (values omitted)' $evidence.checks.'advanced-integration'
    Show-Proof 'Actual Chrome revocation flow' $evidence.checks.'browser-advanced'.advanced
}
if ($Section -in @('All', 'Triage')) {
    $beforePath = Join-Path $rootPath 'docs/evidence/lab06-triage-race-before.json'
    Show-Proof 'F-03 before fix' (Get-Content -LiteralPath $beforePath -Raw -Encoding UTF8 | ConvertFrom-Json)
    Show-Proof 'F-03 same test after fix' $evidence.checks.'triage-concurrency-after'
}
