<#
    Regression checks for bounded Sysmon collection without inferred finality.
    This file is intentionally ASCII-only for Windows PowerShell 5.1.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "..\r1-incremental-sysmon-producer-common.ps1")

$script:Failures = 0
$script:Total = 0

function Assert-True {
    param([string]$Name, [bool]$Condition)
    $script:Total++
    if ($Condition) {
        Write-Host "[PASS] $Name" -ForegroundColor Green
    } else {
        $script:Failures++
        Write-Host "[FAIL] $Name" -ForegroundColor Red
    }
}

function Assert-ThrowsLike {
    param([string]$Name, [scriptblock]$Action, [string]$Pattern)
    $thrown = $false
    try {
        & $Action
    } catch {
        $thrown = $_.Exception.Message -like $Pattern
    }
    Assert-True $Name $thrown
}

function New-TestEvent {
    param([long]$RecordId, [int]$EventId, [string]$TimeCreated)
    [pscustomobject]@{
        RecordId = $RecordId
        Id = $EventId
        TimeCreated = [DateTime]::Parse($TimeCreated).ToUniversalTime()
    }
}

$identityConverter = {
    param($Event)
    [ordered]@{ RecordId = [long]$Event.RecordId; EventId = [int]$Event.Id }
}

$producerText = Get-Content -LiteralPath (
    Join-Path $PSScriptRoot "..\r1-incremental-sysmon-producer.ps1") -Raw
$commonText = Get-Content -LiteralPath (
    Join-Path $PSScriptRoot "..\r1-incremental-sysmon-producer-common.ps1") -Raw
Assert-True "the live producer uses bounded snapshots and publishes no inferred finality" (
    $producerText -match '\$R1_INCREMENTAL_SYSMON_QUERY' -and
    $producerText -notmatch 'Get-R1FinalWatermarkDecision' -and
    $producerText -notmatch '"publish-watermark"' -and
    $producerText -notmatch '"publish-close"' -and
    $producerText -notmatch 'source_upper_utc' -and
    $producerText -notmatch '\$records\.Count\s*-eq\s*0' -and
    $producerText -notmatch '\[Math\]::Max\(\$boundaryUtc\.Ticks')

# The cursor is captured at 10. Event 11 arrives during the first target query,
# remains outside the fixed upper bound, and is collected by the next poll.
$script:Events = @(New-TestEvent 10 1 "2030-01-01T00:00:10Z")
$script:TargetQueries = 0
$queryCursor = { $script:Events[-1] }
$queryTargetsWithArrival = {
    param($Start, $AfterRecordId, $ThroughRecordId)
    $script:TargetQueries++
    if ($script:TargetQueries -eq 1) {
        $script:Events += New-TestEvent 11 3 "2030-01-01T00:00:05Z"
    }
    @($script:Events | Where-Object {
            $_.RecordId -gt $AfterRecordId -and $_.RecordId -le $ThroughRecordId
        } | Sort-Object RecordId)
}
$first = & $R1_INCREMENTAL_SYSMON_QUERY 0 "2030-01-01T00:00:00Z" `
    $queryCursor $queryTargetsWithArrival $identityConverter
$second = & $R1_INCREMENTAL_SYSMON_QUERY 10 "2030-01-01T00:00:00Z" `
    $queryCursor $queryTargetsWithArrival $identityConverter
Assert-True "a later RecordId with an older timestamp is collected on the next poll" (
    [bool]$first.snapshot_consistent -and $first.records.Count -eq 1 -and
    [long]$first.records[0].RecordId -eq 10 -and [long]$first.source_upper_record_id -eq 10 -and
    [bool]$second.snapshot_consistent -and $second.records.Count -eq 1 -and
    [long]$second.records[0].RecordId -eq 11)

# An empty first query cannot prove drain if the bounded verification finds an
# event. No record from an inconsistent snapshot is returned for persistence.
$script:InconsistentQueries = 0
$queryCursorTwenty = { New-TestEvent 20 3 "2030-01-01T00:00:20Z" }
$queryTargetsZeroThenEvent = {
    param($Start, $AfterRecordId, $ThroughRecordId)
    $script:InconsistentQueries++
    if ($script:InconsistentQueries -eq 1) { return @() }
    @(New-TestEvent 20 3 "2030-01-01T00:00:20Z")
}
$inconsistent = & $R1_INCREMENTAL_SYSMON_QUERY 10 "2030-01-01T00:00:00Z" `
    $queryCursorTwenty $queryTargetsZeroThenEvent $identityConverter
Assert-True "zero results do not close over an event found by bounded verification" (
    -not [bool]$inconsistent.snapshot_consistent -and $inconsistent.records.Count -eq 0)

# A non-target channel event may advance RecordId and TimeCreated, but the
# bounded target snapshot contains no target event and grants no finality.
$queryNonTargetCursor = { New-TestEvent 30 22 "2030-01-01T01:00:00Z" }
$queryNoTargets = { param($Start, $AfterRecordId, $ThroughRecordId) @() }
$nonTargetOnly = & $R1_INCREMENTAL_SYSMON_QUERY 20 "2030-01-01T00:00:00Z" `
    $queryNonTargetCursor $queryNoTargets $identityConverter
Assert-True "a non-target timestamp advance provides no source finality" (
    [bool]$nonTargetOnly.snapshot_consistent -and $nonTargetOnly.records.Count -eq 0 -and
    [long]$nonTargetOnly.source_upper_record_id -eq 30 -and
    [long]$nonTargetOnly.target_high_water_record_id -eq 20 -and
    $producerText -notmatch 'TimeCreated.*AllowedLatenessMs')

$stableCursor = { New-TestEvent 40 3 "2030-01-01T00:00:40Z" }
$stableTargets = {
    param($Start, $AfterRecordId, $ThroughRecordId)
    @(New-TestEvent 40 3 "2030-01-01T00:00:40Z")
}
$stable = & $R1_INCREMENTAL_SYSMON_QUERY 30 "2030-01-01T00:00:00Z" `
    $stableCursor $stableTargets $identityConverter
Assert-True "a consistent bounded snapshot still does not authorize watermark or close" (
    [bool]$stable.snapshot_consistent -and $stable.records.Count -eq 1 -and
    [long]$stable.target_high_water_record_id -eq 40 -and
    $commonText -notmatch 'watermark_at|AllowedLateness')

# A restart does not consume or export finality emitted by the removed inferred
# path. The immutable state file is left untouched for operator inspection.
$tempRoot = Join-Path ([IO.Path]::GetTempPath()) ("r1-finality-guard-" + [Guid]::NewGuid().ToString("N"))
$spoolRoot = Join-Path $tempRoot "spool"
$controlRoot = Join-Path $tempRoot "control"
$runId = "RUN-20300101-001"
$runSpool = Join-Path $spoolRoot $runId
New-Item -ItemType Directory -Path $runSpool -Force | Out-Null
$statePath = Join-Path $runSpool "producer-state.json"
$stateText = '{"last_record_id":40,"segment_no":1,"chunk_sequence":1,"watermark_sequence":1,"message_ordinal":2,"last_watermark_at":"2030-01-01T00:00:40.000Z"}'
[IO.File]::WriteAllText($statePath, $stateText, (New-Object System.Text.UTF8Encoding($false)))
$secure = ConvertTo-SecureString "not-used" -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential("not-used", $secure)
Assert-ThrowsLike "restart refuses previously inferred finality before opening a session" {
    & (Join-Path $PSScriptRoot "..\r1-incremental-sysmon-producer.ps1") `
        -RunId $runId -TargetHost "Target-A" -TargetAddress "192.0.2.1" `
        -WinRmPort 5985 -Credential $credential -ContextStartUtc "2030-01-01T00:00:00Z" `
        -SpoolRoot $spoolRoot -ControlRoot $controlRoot `
        -RequiredPartitionContract (Join-Path $tempRoot "contract.json") `
        -PollIntervalSec 1 -ChunkMaxEvents 10 -AllowedLatenessMs 2000
} "*unverified source watermark*"
Assert-True "restart leaves the prior producer state unchanged" (
    [IO.File]::ReadAllText($statePath) -ceq $stateText)
Remove-Item -LiteralPath $tempRoot -Recurse -Force

if ($script:Failures -eq 0) {
    Write-Host "ALL $($script:Total) CHECKS PASSED" -ForegroundColor Green
    exit 0
}
Write-Host "$($script:Failures) of $($script:Total) CHECKS FAILED" -ForegroundColor Red
exit 1
