[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $PayloadPath,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^\d+\.\d+\.\d+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?(?:\+[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$')]
    [string] $ExpectedVersion,

    [switch] $RequireValidSignatures,

    [switch] $SkipManifestHashValidation
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath $PayloadPath).Path

function Get-RelativeChildPath([string] $BasePath, [string] $ChildPath) {
    $base = [IO.Path]::GetFullPath($BasePath).TrimEnd('\', '/')
    $child = [IO.Path]::GetFullPath($ChildPath)
    $prefix = $base + [IO.Path]::DirectorySeparatorChar
    if (-not $child.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Path '$child' is not under release payload '$base'."
    }
    return $child.Substring($prefix.Length)
}
$required = @(
    'Foreman.exe',
    'sidecar\Foreman.EtwSidecar.exe',
    'guardian\Foreman.Guardian.exe',
    'cu-sidecar\Foreman.CuSidecar.exe',
    'cu-pilot\Foreman.CuPilot.exe'
)

$missing = @($required | Where-Object { -not (Test-Path -LiteralPath (Join-Path $root $_) -PathType Leaf) })
if ($missing.Count -gt 0) {
    throw "Release payload is missing required executable(s): $($missing -join ', ')"
}

$wrongVersion = @()
$badSignature = @()
foreach ($relative in $required) {
    $full = Join-Path $root $relative
    $productVersion = [Diagnostics.FileVersionInfo]::GetVersionInfo($full).ProductVersion
    $versionMatches = -not [string]::IsNullOrWhiteSpace($productVersion) -and (
        $productVersion.Equals($ExpectedVersion, [StringComparison]::OrdinalIgnoreCase) -or
        $productVersion.StartsWith("$ExpectedVersion+", [StringComparison]::OrdinalIgnoreCase) -or
        ($ExpectedVersion.Contains('+') -and
         $productVersion.StartsWith("$ExpectedVersion.", [StringComparison]::OrdinalIgnoreCase))
    )
    if (-not $versionMatches) {
        $wrongVersion += "$relative=$productVersion"
    }

    if ($RequireValidSignatures -and (Get-AuthenticodeSignature -LiteralPath $full).Status -ne 'Valid') {
        $badSignature += $relative
    }
}

if ($wrongVersion.Count -gt 0) {
    throw "Release payload version mismatch; expected '$ExpectedVersion': $($wrongVersion -join ', ')"
}
if ($badSignature.Count -gt 0) {
    throw "Release payload contains unsigned or invalid executable(s): $($badSignature -join ', ')"
}

$manifestPath = Join-Path $root 'release-payload.manifest.json'
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
    throw 'Release payload is missing release-payload.manifest.json.'
}
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if ($manifest.schemaVersion -ne 1 -or $null -eq $manifest.files) {
    throw 'Release payload manifest has an unsupported schema.'
}

$allowedRootFiles = @('Foreman.exe', 'release-payload.manifest.json')
$actualRootFiles = @(Get-ChildItem -LiteralPath $root -File -Force | ForEach-Object Name)
$unexpectedRootFiles = @($actualRootFiles | Where-Object { $_ -notin $allowedRootFiles })
$missingRootFiles = @($allowedRootFiles | Where-Object { $_ -notin $actualRootFiles })
if ($unexpectedRootFiles.Count -gt 0 -or $missingRootFiles.Count -gt 0) {
    throw "Release payload root purity failed; unexpected=[$($unexpectedRootFiles -join ', ')], missing=[$($missingRootFiles -join ', ')]."
}

$allowedRootDirectories = @('sidecar', 'guardian', 'cu-sidecar', 'cu-pilot', 'extensions')
$actualRootDirectories = @(Get-ChildItem -LiteralPath $root -Directory -Force | ForEach-Object Name)
$unexpectedRootDirectories = @($actualRootDirectories | Where-Object { $_ -notin $allowedRootDirectories })
$missingRootDirectories = @($allowedRootDirectories | Where-Object { $_ -notin $actualRootDirectories })
if ($unexpectedRootDirectories.Count -gt 0 -or $missingRootDirectories.Count -gt 0) {
    throw "Release payload directory purity failed; unexpected=[$($unexpectedRootDirectories -join ', ')], missing=[$($missingRootDirectories -join ', ')]."
}

$declared = [Collections.Generic.Dictionary[string, string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($entry in $manifest.files) {
    $manifestRelative = [string]$entry.path
    if ([string]::IsNullOrWhiteSpace($manifestRelative) -or [IO.Path]::IsPathRooted($manifestRelative) -or
        ($manifestRelative -split '[\\/]') -contains '..') {
        throw "Release payload manifest contains an unsafe path: '$manifestRelative'"
    }
    $normal = $manifestRelative.Replace('/', '\')
    if ($declared.ContainsKey($normal)) {
        throw "Release payload manifest contains duplicate path: $manifestRelative"
    }
    $declared.Add($normal, [string]$entry.sha256)
}

$expectedFiles = @($declared.Keys) + 'release-payload.manifest.json'
$actualFiles = @(Get-ChildItem -LiteralPath $root -File -Recurse -Force | ForEach-Object {
    Get-RelativeChildPath $root $_.FullName
})
$undeclaredFiles = @($actualFiles | Where-Object { $_ -notin $expectedFiles })
$missingDeclaredFiles = @($expectedFiles | Where-Object { $_ -notin $actualFiles })
if ($undeclaredFiles.Count -gt 0 -or $missingDeclaredFiles.Count -gt 0) {
    throw "Release payload tree differs from its manifest; undeclared=[$($undeclaredFiles -join ', ')], missing=[$($missingDeclaredFiles -join ', ')]."
}

$reparsePoints = @(Get-ChildItem -LiteralPath $root -Recurse -Force | Where-Object {
    ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
})
if ($reparsePoints.Count -gt 0) {
    throw "Release payload contains reparse point(s): $($reparsePoints.FullName -join ', ')"
}

if (-not $SkipManifestHashValidation) {
    $hashMismatches = @()
    foreach ($entry in $declared.GetEnumerator()) {
        $actualHash = (Get-FileHash -LiteralPath (Join-Path $root $entry.Key) -Algorithm SHA256).Hash
        if (-not $actualHash.Equals($entry.Value, [StringComparison]::OrdinalIgnoreCase)) {
            $hashMismatches += $entry.Key
        }
    }
    if ($hashMismatches.Count -gt 0) {
        throw "Release payload hash mismatch for declared file(s): $($hashMismatches -join ', ')"
    }
}

$extensionRequirements = @(
    'extensions\foreman\manifest.json',
    'extensions\foreman\background.js',
    'extensions\liveweave\manifest.json',
    'extensions\liveweave\background.js'
)
$missingExtensions = @($extensionRequirements | Where-Object {
    -not (Test-Path -LiteralPath (Join-Path $root $_) -PathType Leaf)
})
if ($missingExtensions.Count -gt 0) {
    throw "Release payload is missing browser-extension file(s): $($missingExtensions -join ', ')"
}

foreach ($manifestRelative in @('extensions\foreman\manifest.json', 'extensions\liveweave\manifest.json')) {
    $manifest = Get-Content -LiteralPath (Join-Path $root $manifestRelative) -Raw | ConvertFrom-Json
    if ($manifest.manifest_version -ne 3 -or [string]::IsNullOrWhiteSpace($manifest.version)) {
        throw "Packaged browser extension has an invalid MV3 manifest: $manifestRelative"
    }
}

$packagedTests = @(Get-ChildItem -LiteralPath (Join-Path $root 'extensions') -Directory -Recurse -Force |
    Where-Object { $_.Name -eq 'tests' })
if ($packagedTests.Count -gt 0) {
    throw "Release payload contains browser-extension test directories: $($packagedTests.FullName -join ', ')"
}

$signatureNote = if ($RequireValidSignatures) { ', valid Authenticode signatures' } else { '' }
$hashNote = if ($SkipManifestHashValidation) { ', hashes deferred for signed overlay' } else { ', manifest hashes' }
Write-Host "Release payload verified: exact $($declared.Count)-file tree, $($required.Count) executables, two MV3 extensions, version $ExpectedVersion$signatureNote$hashNote."
