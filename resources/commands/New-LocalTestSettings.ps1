[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($env:SeedUsers__Password)) {
    throw 'Задайте SeedUsers__Password у цьому PowerShell перед створенням runsettings.'
}

$fullPath = [System.IO.Path]::GetFullPath($OutputPath)
$directory = [System.IO.Path]::GetDirectoryName($fullPath)
if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
    throw "Каталог призначення не існує: $directory"
}

if (Test-Path -LiteralPath $fullPath) {
    throw "Файл уже існує; оберіть нове ім’я або видаліть власний старий файл."
}

$variables = [ordered]@{ SeedUsers__Password = $env:SeedUsers__Password }
if (-not [string]::IsNullOrWhiteSpace($env:ConnectionStrings__SecureLab)) {
    $variables['ConnectionStrings__SecureLab'] = $env:ConnectionStrings__SecureLab
}

# XmlWriter safely XML-escapes values. UTF-8 with BOM is readable by Windows
# PowerShell 5.1, pwsh and Visual Studio Test Explorer.
$encoding = New-Object System.Text.UTF8Encoding($true)
$settings = New-Object System.Xml.XmlWriterSettings
$settings.Encoding = $encoding
$settings.Indent = $true
$settings.OmitXmlDeclaration = $false
$settings.CloseOutput = $true
$stream = [System.IO.File]::Open(
    $fullPath,
    [System.IO.FileMode]::CreateNew,
    [System.IO.FileAccess]::Write,
    [System.IO.FileShare]::None)
$writer = $null
try {
    $writer = [System.Xml.XmlWriter]::Create($stream, $settings)
    $writer.WriteStartDocument()
    $writer.WriteStartElement('RunSettings')
    $writer.WriteStartElement('RunConfiguration')
    $writer.WriteStartElement('EnvironmentVariables')
    foreach ($entry in $variables.GetEnumerator()) {
        $writer.WriteElementString([string]$entry.Key, [string]$entry.Value)
    }
    $writer.WriteEndElement()
    $writer.WriteEndElement()
    $writer.WriteEndElement()
    $writer.WriteEndDocument()
}
finally {
    if ($null -ne $writer) { $writer.Dispose() }
    else { $stream.Dispose() }
}

Write-Output "Локальні налаштування тестів створено: $fullPath. Значення не виводяться."
