[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $PayloadPath,

    [Parameter(Mandatory = $true)]
    [string] $ExpectedVersion
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath $PayloadPath).Path
$validator = Join-Path $PSScriptRoot 'Test-ReleasePayload.ps1'
if (-not (Test-Path -LiteralPath $validator -PathType Leaf)) {
    throw "Release payload validator is missing: $validator"
}

function Assert-UnderPayload([string] $Path) {
    $full = [IO.Path]::GetFullPath($Path)
    $prefix = $root.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
    if (-not $full.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to mutate a bypass-test path outside the payload: $full"
    }
}

function Expect-ValidatorRejection([string] $Name, [string] $MessagePattern) {
    $failure = $null
    try {
        & $validator -PayloadPath $root -ExpectedVersion $ExpectedVersion | Out-Null
    } catch {
        $failure = $_
    }

    if ($null -eq $failure) {
        throw "Release payload validator accepted bypass fixture '$Name'."
    }
    if ($failure.Exception.Message -notmatch $MessagePattern) {
        throw "Bypass fixture '$Name' failed for the wrong reason: $($failure.Exception.Message)"
    }
    Write-Host "Release payload bypass rejected: $Name."
}

# Whole-tree purity: no root DLL, unknown directory, hidden root file, or undeclared extension file may be
# laundered through signing and attestation.
$rootDll = Join-Path $root 'version.dll'
Assert-UnderPayload $rootDll
try {
    Copy-Item -LiteralPath (Join-Path $root 'extensions\foreman\manifest.json') -Destination $rootDll
    Expect-ValidatorRejection 'root version.dll' 'root purity'
} finally {
    if (Test-Path -LiteralPath $rootDll) {
        Remove-Item -LiteralPath $rootDll -Force
    }
}

$unknownDirectory = Join-Path $root 'amd64'
Assert-UnderPayload $unknownDirectory
try {
    New-Item -ItemType Directory -Path $unknownDirectory -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $root 'extensions\foreman\manifest.json') `
        -Destination (Join-Path $unknownDirectory 'x.dll')
    Expect-ValidatorRejection 'unknown root directory' 'directory purity'
} finally {
    if (Test-Path -LiteralPath $unknownDirectory) {
        Remove-Item -LiteralPath $unknownDirectory -Recurse -Force
    }
}

$hiddenRoot = Join-Path $root '.foreman-hidden-root'
Assert-UnderPayload $hiddenRoot
try {
    Copy-Item -LiteralPath (Join-Path $root 'extensions\foreman\manifest.json') -Destination $hiddenRoot
    (Get-Item -LiteralPath $hiddenRoot -Force).Attributes = [IO.FileAttributes]::Hidden
    Expect-ValidatorRejection 'hidden root file' 'root purity'
} finally {
    if (Test-Path -LiteralPath $hiddenRoot) {
        Remove-Item -LiteralPath $hiddenRoot -Force
    }
}

$extraExtensionFile = Join-Path $root 'extensions\foreman\undeclared.js'
Assert-UnderPayload $extraExtensionFile
try {
    Copy-Item -LiteralPath (Join-Path $root 'extensions\foreman\background.js') -Destination $extraExtensionFile
    Expect-ValidatorRejection 'undeclared extension file' 'differs from its manifest'
} finally {
    if (Test-Path -LiteralPath $extraExtensionFile) {
        Remove-Item -LiteralPath $extraExtensionFile -Force
    }
}

# Round-two sibling bypass: -Force must expose a hidden neighbouring file in every helper directory, not only
# the originally reported ETW sidecar directory.
$hiddenSibling = Join-Path $root 'cu-pilot\.foreman-hidden-sibling.dll'
Assert-UnderPayload $hiddenSibling
try {
    Copy-Item -LiteralPath (Join-Path $root 'extensions\foreman\manifest.json') -Destination $hiddenSibling
    (Get-Item -LiteralPath $hiddenSibling -Force).Attributes = [IO.FileAttributes]::Hidden
    Expect-ValidatorRejection 'hidden CU Pilot sibling' 'differs from its manifest'
} finally {
    if (Test-Path -LiteralPath $hiddenSibling) {
        Remove-Item -LiteralPath $hiddenSibling -Force
    }
}

# Packaging bypass: tests/ and its fixtures must never ride into an unpacked extension installed for users.
$packagedTests = Join-Path $root 'extensions\liveweave\tests'
Assert-UnderPayload $packagedTests
try {
    New-Item -ItemType Directory -Path $packagedTests -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $root 'extensions\liveweave\manifest.json') `
        -Destination (Join-Path $packagedTests 'fixture.json')
    Expect-ValidatorRejection 'packaged extension tests' 'differs from its manifest'
} finally {
    if (Test-Path -LiteralPath $packagedTests) {
        Remove-Item -LiteralPath $packagedTests -Recurse -Force
    }
}

& $validator -PayloadPath $root -ExpectedVersion $ExpectedVersion
Write-Host 'Release payload bypass regression tests passed.'
