<#
    Shared, testable bounded-query helper for the R1 Sysmon sidecar.

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
        target_high_water_record_id = $targetHighWaterRecordId
        snapshot_consistent = $snapshotConsistent
        records = @($converted)
    }
}
