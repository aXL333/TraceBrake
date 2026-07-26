[CmdletBinding()]
param(
    [string] $RepositoryPath = '.',

    [Parameter(Mandatory = $true)]
    [string] $CommitSha,

    [string] $MainRef = 'origin/main',

    [string] $TagRef,

    [switch] $RequireAnnotatedTag
)

$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path -LiteralPath $RepositoryPath).Path

git -C $repo cat-file -e "$CommitSha^{commit}" 2>$null
if ($LASTEXITCODE -ne 0) {
    throw "Release commit does not exist: $CommitSha"
}
$canonicalCommit = ([string](& git -C $repo rev-parse "$CommitSha^{commit}")).Trim()
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($canonicalCommit)) {
    throw "Release commit could not be canonicalised: $CommitSha"
}

git -C $repo merge-base --is-ancestor $canonicalCommit $MainRef
if ($LASTEXITCODE -ne 0) {
    throw "Release commit '$canonicalCommit' is not an ancestor of '$MainRef'."
}

if ($RequireAnnotatedTag) {
    if ([string]::IsNullOrWhiteSpace($TagRef) -or $TagRef -notmatch '^refs/tags/v') {
        throw "Publishing requires an annotated v* tag; got '$TagRef'."
    }

    $objectOutput = @(& git -C $repo cat-file -t $TagRef 2>$null)
    $objectExit = $LASTEXITCODE
    $objectType = if ($objectOutput.Count -gt 0) { ([string]$objectOutput[0]).Trim() } else { '' }
    if ($objectExit -ne 0 -or $objectType -ne 'tag') {
        throw "Publishing requires an annotated or signed tag; '$TagRef' is not an annotated tag object."
    }

    $commitOutput = @(& git -C $repo rev-list -n 1 $TagRef)
    $commitExit = $LASTEXITCODE
    $tagCommit = if ($commitOutput.Count -gt 0) { ([string]$commitOutput[0]).Trim() } else { '' }
    if ($commitExit -ne 0 -or
        -not $tagCommit.Equals($canonicalCommit, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Tag '$TagRef' resolves to '$tagCommit', not release commit '$canonicalCommit'."
    }
}

Write-Host "Release source verified: $canonicalCommit is on $MainRef$(if ($RequireAnnotatedTag) { " via $TagRef" })."
