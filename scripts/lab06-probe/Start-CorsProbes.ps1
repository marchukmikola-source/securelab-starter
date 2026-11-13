param([string]$NodePath)

$ErrorActionPreference = 'Stop'
if (-not $NodePath) {
    $nodeCommand = Get-Command node -CommandType Application -ErrorAction SilentlyContinue
    if ($nodeCommand) { $NodePath = $nodeCommand.Source }
}
if (-not $NodePath) {
    $runtimeDirectory = Join-Path $env:ProgramFiles 'WindowsApps'
    $runtimes = Get-ChildItem -LiteralPath $runtimeDirectory -Filter 'OpenAI.CodexPrimaryRuntime*' -Directory -ErrorAction SilentlyContinue |
        Sort-Object Name -Descending
    foreach ($runtime in $runtimes) {
        $candidate = Join-Path $runtime.FullName 'dependencies/node/bin/node.exe'
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { $NodePath = $candidate; break }
    }
}
if (-not $NodePath -or -not (Test-Path -LiteralPath $NodePath -PathType Leaf)) {
    throw 'Install Node.js or provide -NodePath with the full path to node.exe.'
}
& $NodePath (Join-Path $PSScriptRoot 'cors-probes.cjs')
exit $LASTEXITCODE
