<#
    Regression checks for the bounded Sysmon snapshot and final watermark.
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
Assert-True "the live producer uses bounded snapshots and the shared finality decision" (
    $producerText -match '\$R1_INCREMENTAL_SYSMON_QUERY' -and
    $producerText -match 'Get-R1FinalWatermarkDecision' -and
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
        $script:Events += New-TestEvent 11 3 "2030-01-01T00:00:11Z"
    }
    @($script:Events | Where-Object {
            $_.RecordId -gt $AfterRecordId -and $_.RecordId -le $ThroughRecordId
        } | Sort-Object RecordId)
}
$first = & $R1_INCREMENTAL_SYSMON_QUERY 0 "2030-01-01T00:00:00Z" `
    $queryCursor $queryTargetsWithArrival $identityConverter
$second = & $R1_INCREMENTAL_SYSMON_QUERY 10 "2030-01-01T00:00:00Z" `
    $queryCursor $queryTargetsWithArrival $identityConverter
Assert-True "an event arriving after cursor capture is collected on the next poll" (
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
$inconsistentDecision = Get-R1FinalWatermarkDecision `
    -SnapshotConsistent ([bool]$inconsistent.snapshot_consistent) `
    -PersistedTargetRecordId 10 -TargetHighWaterRecordId 10 `
    -SourceCursorUtc ([DateTime]"2030-01-01T00:00:20Z") `
    -CandidateBoundaryUtc ([DateTime]"2030-01-01T00:00:15Z") `
    -AllowedLatenessMs 2000 -PreviousWatermarkUtc $null
Assert-True "zero results do not close over an event found by bounded verification" (
    -not [bool]$inconsistent.snapshot_consistent -and $inconsistent.records.Count -eq 0 -and
    -not [bool]$inconsistentDecision.ready -and
    $inconsistentDecision.reason -ceq "snapshot_inconsistent")

$notLateEnough = Get-R1FinalWatermarkDecision `
    -SnapshotConsistent $true -PersistedTargetRecordId 20 -TargetHighWaterRecordId 20 `
    -SourceCursorUtc ([DateTime]"2030-01-01T00:00:16Z") `
    -CandidateBoundaryUtc ([DateTime]"2030-01-01T00:00:15Z") `
    -AllowedLatenessMs 2000 -PreviousWatermarkUtc $null
Assert-True "allowed lateness must be satisfied before close" (
    -not [bool]$notLateEnough.ready -and
    $notLateEnough.reason -ceq "allowed_lateness_not_satisfied" -and
    $null -eq $notLateEnough.watermark_at)

$notPersisted = Get-R1FinalWatermarkDecision `
    -SnapshotConsistent $true -PersistedTargetRecordId 19 -TargetHighWaterRecordId 20 `
    -SourceCursorUtc ([DateTime]"2030-01-01T00:00:18Z") `
    -CandidateBoundaryUtc ([DateTime]"2030-01-01T00:00:15Z") `
    -AllowedLatenessMs 2000 -PreviousWatermarkUtc $null
Assert-True "a target event through the upper bound must be persisted before close" (
    -not [bool]$notPersisted.ready -and $notPersisted.reason -ceq "target_events_not_persisted")

$ready = Get-R1FinalWatermarkDecision `
    -SnapshotConsistent $true -PersistedTargetRecordId 20 -TargetHighWaterRecordId 20 `
    -SourceCursorUtc ([DateTime]"2030-01-01T00:00:18Z") `
    -CandidateBoundaryUtc ([DateTime]"2030-01-01T00:00:15Z") `
    -AllowedLatenessMs 2000 -PreviousWatermarkUtc ([DateTime]"2030-01-01T00:00:14Z")
Assert-True "a complete snapshot uses the real lateness-adjusted final watermark" (
    [bool]$ready.ready -and $ready.reason -ceq "ready" -and
    ([DateTime]$ready.watermark_at) -eq
        ([DateTime]::Parse("2030-01-01T00:00:16Z").ToUniversalTime()))

if ($script:Failures -eq 0) {
    Write-Host "ALL $($script:Total) CHECKS PASSED" -ForegroundColor Green
    exit 0
}
Write-Host "$($script:Failures) of $($script:Total) CHECKS FAILED" -ForegroundColor Red
exit 1
