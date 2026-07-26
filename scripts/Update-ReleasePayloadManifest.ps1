[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $PayloadPath
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath $PayloadPath).Path
$manifestPath = Join-Path $root 'release-payload.manifest.json'
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
    throw "Release payload manifest is missing: $manifestPath"
}

$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if ($manifest.schemaVersion -ne 1 -or $null -eq $manifest.files) {
    throw 'Release payload manifest has an unsupported schema.'
}

# This script may refresh hashes after SignPath changes executable bytes, but it must never discover or add paths.
# Test-ReleasePayload.ps1 validates exact tree purity before this runs and again afterwards.
foreach ($entry in $manifest.files) {
    $relative = [string]$entry.path
    if ([string]::IsNullOrWhiteSpace($relative) -or [IO.Path]::IsPathRooted($relative) -or
        ($relative -split '[\\/]') -contains '..') {
        throw "Release payload manifest contains an unsafe path: '$relative'"
    }
    $full = Join-Path $root ($relative.Replace('/', '\'))
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) {
        throw "Cannot refresh manifest hash for missing declared file: $relative"
    }
    $entry.sha256 = (Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash.ToLowerInvariant()
}

$manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
Write-Host "Refreshed hashes for $($manifest.files.Count) pre-declared release payload files."
