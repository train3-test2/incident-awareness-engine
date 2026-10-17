<#
    Shared, testable finality helpers for the R1 Sysmon sidecar.

    This file is intentionally ASCII-only for Windows PowerShell 5.1.
#>

$R1_INCREMENTAL_SYSMON_QUERY = {
    param(
        [long]$LastRecordId,
        [string]$ContextStart,
        [scriptblock]$QueryCursor = $null,
        [scriptblock]$QueryTargets = $null,
        [scriptblock]$ConvertTarget = $null
    )

    if ($null -eq $QueryCursor) {
        $QueryCursor = {
            Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 1 `
                -ErrorAction SilentlyContinue
        }
    }
    if ($null -eq $QueryTargets) {
        $QueryTargets = {
            param($Start, $AfterRecordId, $ThroughRecordId)
            @(Get-WinEvent -FilterHashtable @{
                LogName = "Microsoft-Windows-Sysmon/Operational"
                Id = @(1, 3)
                StartTime = [DateTime]::Parse($Start)
            } -ErrorAction Stop | Where-Object {
                $_.RecordId -gt $AfterRecordId -and $_.RecordId -le $ThroughRecordId
            } | Sort-Object RecordId)
        }
    }
    if ($null -eq $ConvertTarget) {
        $ConvertTarget = {
            param($Event)
            $xml = [xml]$Event.ToXml()
            $eventData = [ordered]@{}
            foreach ($item in $xml.Event.EventData.Data) {
                $eventData[$item.Name] = $item."#text"
            }
            [ordered]@{
                RecordId = [long]$Event.RecordId
                EventId = [int]$Event.Id
                Computer = [string]$Event.MachineName
                TimeCreated = $Event.TimeCreated.ToUniversalTime().ToString("o")
                Provider = [string]$Event.ProviderName
                EventData = $eventData
            }
        }
    }

    # Capture the all-channel upper bound before querying target EIDs. Events
    # arriving afterwards have a larger RecordId and belong to the next poll.
    $upper = & $QueryCursor
    if ($null -eq $upper) {
        return [ordered]@{
            target_queried_at_utc = [DateTime]::UtcNow.ToString("o")
            source_upper_record_id = 0
            source_upper_utc = $null
            target_high_water_record_id = $LastRecordId
            snapshot_consistent = $true
            records = @()
        }
    }

    $upperRecordId = [long]$upper.RecordId
    $first = @(& $QueryTargets $ContextStart $LastRecordId $upperRecordId)
    $verification = @(& $QueryTargets $ContextStart $LastRecordId $upperRecordId)
    $firstKeys = @($first | ForEach-Object { "{0}:{1}" -f ([long]$_.RecordId), ([int]$_.Id) })
    $verificationKeys = @(
        $verification | ForEach-Object { "{0}:{1}" -f ([long]$_.RecordId), ([int]$_.Id) }
    )
    $snapshotConsistent = ($firstKeys.Count -eq $verificationKeys.Count)
    if ($snapshotConsistent) {
        for ($index = 0; $index -lt $firstKeys.Count; $index++) {
            if ($firstKeys[$index] -cne $verificationKeys[$index]) {
                $snapshotConsistent = $false
                break
            }
        }
    }

    $converted = @()
    $targetHighWaterRecordId = $LastRecordId
    if ($snapshotConsistent) {
        $converted = @($verification | ForEach-Object { & $ConvertTarget $_ })
        if ($verification.Count -gt 0) {
            $targetHighWaterRecordId = [long]$verification[-1].RecordId
        }
    }

    [ordered]@{
        target_queried_at_utc = [DateTime]::UtcNow.ToString("o")
        source_upper_record_id = $upperRecordId
        source_upper_utc = $upper.TimeCreated.ToUniversalTime().ToString("o")
        target_high_water_record_id = $targetHighWaterRecordId
        snapshot_consistent = $snapshotConsistent
        records = @($converted)
    }
}

function Get-R1FinalWatermarkDecision {
    param(
        [Parameter(Mandatory = $true)][bool]$SnapshotConsistent,
        [Parameter(Mandatory = $true)][long]$PersistedTargetRecordId,
        [Parameter(Mandatory = $true)][long]$TargetHighWaterRecordId,
        [Parameter(Mandatory = $true)][DateTime]$SourceCursorUtc,
        [Parameter(Mandatory = $true)][DateTime]$CandidateBoundaryUtc,
        [Parameter(Mandatory = $true)][int]$AllowedLatenessMs,
        [AllowNull()][Nullable[DateTime]]$PreviousWatermarkUtc
    )

    if (-not $SnapshotConsistent) {
        return [pscustomobject]@{ ready = $false; reason = "snapshot_inconsistent"; watermark_at = $null }
    }
    if ($PersistedTargetRecordId -lt $TargetHighWaterRecordId) {
        return [pscustomobject]@{ ready = $false; reason = "target_events_not_persisted"; watermark_at = $null }
    }

    $frontier = $SourceCursorUtc.ToUniversalTime().AddMilliseconds(-$AllowedLatenessMs)
    if ($null -ne $PreviousWatermarkUtc) {
        $previousUtc = ([DateTime]$PreviousWatermarkUtc).ToUniversalTime()
        if ($frontier -lt $previousUtc) {
            return [pscustomobject]@{ ready = $false; reason = "watermark_regression"; watermark_at = $null }
        }
    }
    if ($frontier -lt $CandidateBoundaryUtc.ToUniversalTime()) {
        return [pscustomobject]@{
            ready = $false
            reason = "allowed_lateness_not_satisfied"
            watermark_at = $null
        }
    }

    [pscustomobject]@{ ready = $true; reason = "ready"; watermark_at = $frontier }
}
