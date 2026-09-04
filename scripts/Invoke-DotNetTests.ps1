[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string] $Configuration = 'Release',

    [switch] $NoBuild,

    [switch] $NoRestore,

    [string[]] $ProjectName = @()
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptRoot = Split-Path -Parent $PSCommandPath
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $scriptRoot '..')).Path
$testsRoot = Join-Path $repositoryRoot 'tests'

# A VSTest invocation may exit 0 while reporting "No test is available". Keep a
# per-project floor so losing a whole assembly, adapter, or parser route fails CI.
$minimumExecutedByProject = [ordered]@{
    'Foreman.Core.Tests' = 1167
    'Foreman.Guardian.Tests' = 28
    'Foreman.McpServer.Tests' = 238
    'Foreman.Monitor.Tests' = 100
    'Foreman.Platform.Linux.Tests' = 7
    'Foreman.Vault.Tests' = 53
}

$discoveredProjects = @(
    Get-ChildItem -LiteralPath $testsRoot -Recurse -File -Filter '*.Tests.csproj' |
        Sort-Object FullName
)

if ($discoveredProjects.Count -eq 0) {
    throw "No test projects were discovered below '$testsRoot'."
}

$discoveredByName = @{}
foreach ($project in $discoveredProjects) {
    if ($discoveredByName.ContainsKey($project.BaseName)) {
        throw "Duplicate test project name '$($project.BaseName)' makes result attribution ambiguous."
    }

    $discoveredByName[$project.BaseName] = $project
}

foreach ($requiredProjectName in $minimumExecutedByProject.Keys) {
    if (-not $discoveredByName.ContainsKey($requiredProjectName)) {
        throw "Required test project '$requiredProjectName' was not discovered."
    }
}

$selectedProjects = @(
    if ($ProjectName.Count -eq 0) {
        $discoveredProjects
    }
    else {
        foreach ($requestedProjectName in $ProjectName) {
            if (-not $discoveredByName.ContainsKey($requestedProjectName)) {
                throw "Requested test project '$requestedProjectName' was not discovered."
            }

            $discoveredByName[$requestedProjectName]
        }
    }
)

$runId = '{0}-{1}' -f [DateTimeOffset]::UtcNow.ToString('yyyyMMddTHHmmssfffZ'), [Guid]::NewGuid().ToString('N')
$resultsRoot = Join-Path $repositoryRoot ".artifacts\test-results\$runId"
New-Item -ItemType Directory -Path $resultsRoot -Force | Out-Null

$totalExecuted = 0
foreach ($project in $selectedProjects) {
    # Deliberately NOT named after the $ProjectName parameter above. PowerShell variable
    # names are case-insensitive, so reusing that name inherits its [string[]] type
    # constraint and silently coerces this string into a one-element String[]. Join-Path
    # then fails with an opaque "cannot convert System.String[] ... ChildPath" error
    # before a single test runs, with or without the parameter being supplied.
    $projectBaseName = $project.BaseName
    $projectResults = Join-Path $resultsRoot $projectBaseName
    New-Item -ItemType Directory -Path $projectResults -Force | Out-Null

    $trxName = "$projectBaseName.trx"
    $dotnetArguments = [System.Collections.Generic.List[string]]::new()
    $dotnetArguments.Add('test')
    # .NET 10's VSTest parser has produced false-green no-op runs for relative
    # solution/project tokens. An absolute project path removes that ambiguity.
    $dotnetArguments.Add($project.FullName)
    $dotnetArguments.Add('-c')
    $dotnetArguments.Add($Configuration)
    $dotnetArguments.Add('-m:1')
    $dotnetArguments.Add('-p:UseSharedCompilation=false')
    $dotnetArguments.Add('--results-directory')
    $dotnetArguments.Add($projectResults)
    $dotnetArguments.Add('--logger')
    $dotnetArguments.Add("trx;LogFileName=$trxName")
    $dotnetArguments.Add('--verbosity')
    $dotnetArguments.Add('minimal')

    if ($NoBuild) {
        $dotnetArguments.Add('--no-build')
    }
    elseif ($NoRestore) {
        $dotnetArguments.Add('--no-restore')
    }

    Write-Host "Testing $projectBaseName"
    & dotnet @dotnetArguments
    if ($LASTEXITCODE -ne 0) {
        throw "dotnet test failed for '$projectBaseName' with exit code $LASTEXITCODE."
    }

    $trxFiles = @(Get-ChildItem -LiteralPath $projectResults -File -Filter '*.trx')
    if ($trxFiles.Count -ne 1) {
        throw "Expected exactly one TRX result for '$projectBaseName'; found $($trxFiles.Count)."
    }

    [xml] $trx = Get-Content -LiteralPath $trxFiles[0].FullName -Raw
    $counters = $trx.SelectSingleNode("//*[local-name()='Counters']")
    if ($null -eq $counters) {
        throw "TRX result for '$projectBaseName' has no Counters element."
    }

    $executed = [int]::Parse($counters.GetAttribute('executed'), [Globalization.CultureInfo]::InvariantCulture)
    $failed = [int]::Parse($counters.GetAttribute('failed'), [Globalization.CultureInfo]::InvariantCulture)
    $minimumExecuted = if ($minimumExecutedByProject.Contains($projectBaseName)) {
        [int] $minimumExecutedByProject[$projectBaseName]
    }
    else {
        1
    }

    if ($failed -ne 0) {
        throw "TRX result for '$projectBaseName' records $failed failed test(s)."
    }

    if ($executed -lt $minimumExecuted) {
        throw "Test discovery floor failed for '$projectBaseName': executed $executed, required at least $minimumExecuted."
    }

    $totalExecuted += $executed
    Write-Host "Validated ${projectBaseName}: $executed test(s), 0 failed."
}

Write-Host "Validated $totalExecuted test(s) across $($selectedProjects.Count) project(s)."
Write-Host "TRX evidence: $resultsRoot"
