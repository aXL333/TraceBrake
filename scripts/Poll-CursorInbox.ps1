#Requires -Version 5.1
<#
.SYNOPSIS
  Cheap guard for Cursor inbox wake loops. Zero agent tokens when idle.

.DESCRIPTION
  Checks (in order):
    1. File inbox: T:\TOOLS\.cursor-inbox\*.md|*.txt|*.msg (excludes README/processed)
    2. Foreman mailbox: dotnet Foreman.TestHarness --harness cursor --probe

  When work exists, prints an AGENT_LOOP_WAKE sentinel on stdout (for monitored-shell /loop).
  Exit codes: 0 idle, 1 work pending, 2 Foreman unreachable (file inbox still checked first).
#>
[CmdletBinding()]
param(
    [string]$InboxRoot = '',
    [string]$ForemanRoot = '',
    [int]$Port = 54321,
    [string]$IntervalHint = '',
    [switch]$NoSentinel
)

$ErrorActionPreference = 'Stop'

$scriptDir = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($scriptDir)) {
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
}
if (-not $ForemanRoot) {
    $ForemanRoot = Split-Path -Parent $scriptDir
}
if (-not $InboxRoot) {
    $toolsRoot = Split-Path -Parent $ForemanRoot
    $InboxRoot = Join-Path $toolsRoot '.cursor-inbox'
}

function Get-InboxFiles {
    param([string]$Root)
    if (-not (Test-Path -LiteralPath $Root)) { return @() }
    Get-ChildItem -LiteralPath $Root -File -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Name -notmatch '^(README|\.gitkeep)' -and
            $_.Extension -match '^\.(md|txt|msg)$'
        }
}

$fileHits = @(Get-InboxFiles -Root $InboxRoot)
$fileCount = $fileHits.Count

$foremanPending = 0
$foremanStatus = 'skipped'
$probeJson = $null

if ($fileCount -eq 0) {
    $proj = Join-Path $ForemanRoot 'src\Foreman.TestHarness\Foreman.TestHarness.csproj'
    if (Test-Path -LiteralPath $proj) {
        try {
            $probeLine = & dotnet run --project $proj -c Release -- --harness cursor --probe --port $Port 2>&1 |
                Where-Object { $_ -match '^\s*\{' } |
                Select-Object -Last 1
            if ($probeLine) {
                $probeJson = $probeLine | ConvertFrom-Json
                $foremanStatus = [string]$probeJson.status
                $foremanPending = [int]$probeJson.pendingCount
            }
        }
        catch {
            $foremanStatus = 'unreachable'
        }
    }
    else {
        $foremanStatus = 'unreachable'
    }
}

$hasWork = ($fileCount -gt 0) -or ($foremanPending -gt 0)

$result = [ordered]@{
    status         = if ($hasWork) { 'pending' } else { 'idle' }
    fileCount      = $fileCount
    fileNames      = @($fileHits | ForEach-Object { $_.Name })
    foremanStatus  = $foremanStatus
    foremanPending = $foremanPending
    checkedAt      = (Get-Date).ToString('o')
}
$result | ConvertTo-Json -Compress | Write-Output

if ($hasWork -and -not $NoSentinel) {
    $prompt = @'
Inbox wake — act only if work exists.
1. If .cursor-inbox/ has *.md|*.txt|*.msg (not README/processed): read each, do the request, move to .cursor-inbox/processed/.
2. Else call Foreman list_ask_harness_requests (harness cursor). For each pending item, act and reply_to_ask_harness_request.
3. If nothing after both checks: reply IDLE and stop. Do not explore the repo.
'@
    $payload = @{
        prompt   = $prompt.Trim()
        source   = if ($fileCount -gt 0) { 'file' } else { 'foreman' }
        files    = $result.fileNames
        foreman  = $foremanPending
        interval = $IntervalHint
    } | ConvertTo-Json -Compress
    Write-Output "AGENT_LOOP_WAKE_CURSOR_INBOX $payload"
}

if ($hasWork) { exit 1 }
if ($foremanStatus -eq 'unreachable' -and $fileCount -eq 0) { exit 2 }
exit 0
