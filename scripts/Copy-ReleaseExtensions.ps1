[CmdletBinding()]
param(
    [string] $RepositoryRoot,

    [Parameter(Mandatory = $true)]
    [string] $PayloadPath
)

$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) {
    $RepositoryRoot = Split-Path -Parent $PSScriptRoot
}
$repo = (Resolve-Path -LiteralPath $RepositoryRoot).Path
$payload = if (Test-Path -LiteralPath $PayloadPath) {
    (Resolve-Path -LiteralPath $PayloadPath).Path
} else {
    New-Item -ItemType Directory -Path $PayloadPath -Force | Select-Object -ExpandProperty FullName
}
$destinationRoot = Join-Path $payload 'extensions'

if (Test-Path -LiteralPath $destinationRoot) {
    Remove-Item -LiteralPath $destinationRoot -Recurse -Force
}

$packages = @(
    @{ Source = 'extension'; Destination = 'foreman' },
    @{ Source = 'extension-liveweave'; Destination = 'liveweave' }
)
$manifestPaths = [Collections.Generic.List[string]]::new()

foreach ($package in $packages) {
    $source = Join-Path $repo $package.Source
    if (-not (Test-Path -LiteralPath (Join-Path $source 'manifest.json') -PathType Leaf)) {
        throw "Browser extension source is missing manifest.json: $source"
    }

    $destination = Join-Path $destinationRoot $package.Destination
    foreach ($file in Get-ChildItem -LiteralPath $source -Recurse -File -Force) {
        if (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Refusing to package browser-extension reparse point: $($file.FullName)"
        }

        $relative = $file.FullName.Substring($source.TrimEnd('\', '/').Length).TrimStart('\', '/')
        $segments = $relative -split '[\\/]'
        if ($segments[0] -eq 'tests') {
            continue
        }

        $target = Join-Path $destination $relative
        $targetDirectory = Split-Path -Parent $target
        New-Item -ItemType Directory -Path $targetDirectory -Force | Out-Null
        Copy-Item -LiteralPath $file.FullName -Destination $target -Force
        $manifestPaths.Add($target.Substring($payload.TrimEnd('\', '/').Length).TrimStart('\', '/'))
    }
}

$requiredExecutables = @(
    'TraceBrake.exe',
    'sidecar\Foreman.EtwSidecar.exe',
    'guardian\Foreman.Guardian.exe',
    'cu-sidecar\Foreman.CuSidecar.exe',
    'cu-pilot\Foreman.CuPilot.exe'
)
foreach ($relative in $requiredExecutables) {
    $full = Join-Path $payload $relative
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) {
        throw "Cannot create release manifest; required executable is missing: $relative"
    }
    $manifestPaths.Add($relative)
}

$entries = @($manifestPaths |
    ForEach-Object { $_.Replace('/', '\') } |
    Sort-Object -Unique |
    ForEach-Object {
        $full = Join-Path $payload $_
        [ordered]@{
            path = $_.Replace('\', '/')
            sha256 = (Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    })
$manifest = [ordered]@{
    schemaVersion = 1
    files = $entries
}
$manifestPath = Join-Path $payload 'release-payload.manifest.json'
$manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $manifestPath -Encoding UTF8

Write-Host "Packaged both browser extensions and wrote $($entries.Count)-file release manifest."
