[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$guard = Join-Path $PSScriptRoot 'Assert-ReleaseSource.ps1'
$tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\', '/')
$repo = Join-Path $tempRoot ("foreman-release-source-test-" + [Guid]::NewGuid().ToString('N'))

function Run-Git {
    $Arguments = @($args)
    & git -C $repo @Arguments | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Test repository git command failed: git $($Arguments -join ' ')"
    }
}

function Expect-Rejection([string] $Name, [scriptblock] $Action, [string] $Pattern) {
    $failure = $null
    try { & $Action } catch { $failure = $_ }
    if ($null -eq $failure) { throw "Release-source guard accepted bypass '$Name'." }
    if ($failure.Exception.Message -notmatch $Pattern) {
        throw "Release-source bypass '$Name' failed for the wrong reason: $($failure.Exception.Message)"
    }
    Write-Host "Release-source bypass rejected: $Name."
}

try {
    New-Item -ItemType Directory -Path $repo -Force | Out-Null
    & git -C $repo init -b main | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not initialise release-source test repository.' }
    Run-Git config user.email 'release-policy@example.invalid'
    Run-Git config user.name 'Release Policy Test'

    Set-Content -LiteralPath (Join-Path $repo 'baseline.txt') -Value 'baseline' -Encoding ASCII
    Run-Git add baseline.txt
    Run-Git commit -m baseline
    $mainCommit = (& git -C $repo rev-parse HEAD).Trim()
    Run-Git tag -a v-main -m 'annotated main release' $mainCommit
    Run-Git tag v-light $mainCommit

    Run-Git switch -c side
    Set-Content -LiteralPath (Join-Path $repo 'side.txt') -Value 'side' -Encoding ASCII
    Run-Git add side.txt
    Run-Git commit -m side
    $sideCommit = (& git -C $repo rev-parse HEAD).Trim()
    Run-Git tag -a v-side -m 'annotated side release' $sideCommit

    Expect-Rejection 'annotated tag on side branch' {
        & $guard -RepositoryPath $repo -CommitSha $sideCommit -MainRef main `
            -TagRef refs/tags/v-side -RequireAnnotatedTag
    } 'not an ancestor'

    Expect-Rejection 'lightweight tag on main' {
        & $guard -RepositoryPath $repo -CommitSha $mainCommit -MainRef main `
            -TagRef refs/tags/v-light -RequireAnnotatedTag
    } 'not an annotated tag'

    & $guard -RepositoryPath $repo -CommitSha $mainCommit -MainRef main `
        -TagRef refs/tags/v-main -RequireAnnotatedTag
    Write-Host 'Release-source guard regression tests passed.'
} finally {
    $resolved = if (Test-Path -LiteralPath $repo) { (Resolve-Path -LiteralPath $repo).Path } else { $repo }
    $prefix = $tempRoot + [IO.Path]::DirectorySeparatorChar + 'foreman-release-source-test-'
    if ($resolved.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        Remove-Item -LiteralPath $resolved -Recurse -Force -ErrorAction SilentlyContinue
    }
}
