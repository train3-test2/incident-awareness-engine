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
                Channel = [string]$Event.LogName
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

# Freeze snapshot of the RecordId position-finality path
# (docs/schema/r1-sysmon-record-position-finality-v0.md). The producer runs it on
# Target-A once it has read the runner's freeze request. It fixes one all-channel
# upper RecordId, takes the lower RecordId from the same context start the live
# polls use, reads the closed bound [lower, upper] of EID 1/3 twice and reads the
# channel generation. It issues nothing itself: the Controller publishes the rest
# of the bound, compares it with what it published and only then asks the Python
# tool for the freeze ack. A non-empty "failures" list means no ack may be written.
#
# Identity lines are host, channel, RecordId, EventId and the SHA-256 of the raw
# XML plus LF, the same lines as scenarios/R1/host/Test-R1RecordBoundedFinality.ps1.
$R1_POSITION_FREEZE_SNAPSHOT = {
    param(
        [long]$LastRecordId,
        [string]$ContextStart,
        [long]$ExpectedLowerRecordId,
        [string]$ExpectedHost,
        [scriptblock]$QueryUpper = $null,
        [scriptblock]$QuerySeed = $null,
        [scriptblock]$QueryBound = $null,
        [scriptblock]$ReadChannelState = $null,
        [scriptblock]$ConvertTarget = $null
    )

    $channel = "Microsoft-Windows-Sysmon/Operational"
    $sha256Text = {
        param([string[]]$Lines)
        $bytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes((($Lines -join "`n") + "`n"))
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try {
            return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace("-", "").ToLowerInvariant()
        } finally {
            $sha.Dispose()
        }
    }
    $identityLine = {
        param($Event)
        "{0}`t{1}`t{2}`t{3}`t{4}" -f [string]$Event.MachineName, [string]$Event.LogName,
            ([long]$Event.RecordId), ([int]$Event.Id), (& $sha256Text @([string]$Event.ToXml()))
    }
    if ($null -eq $QueryUpper) {
        $QueryUpper = { Get-WinEvent -LogName $channel -MaxEvents 1 -ErrorAction Stop }
    }
    if ($null -eq $QuerySeed) {
        $QuerySeed = {
            param($Start, $ThroughRecordId)
            try {
                @(Get-WinEvent -FilterHashtable @{
                    LogName = $channel
                    Id = @(1, 3)
                    StartTime = [DateTime]::Parse($Start)
                } -ErrorAction Stop | Where-Object { $_.RecordId -le $ThroughRecordId } |
                    Sort-Object RecordId | Select-Object -First 1)
            } catch {
                if ($_.FullyQualifiedErrorId -like "NoMatchingEventsFound*") { return @() }
                throw
            }
        }
    }
    if ($null -eq $QueryBound) {
        $QueryBound = {
            param($Lower, $Upper)
            $xpath = "*[System[(EventID=1 or EventID=3) and EventRecordID >= $Lower and EventRecordID <= $Upper]]"
            try {
                @(Get-WinEvent -LogName $channel -FilterXPath $xpath -ErrorAction Stop | Sort-Object RecordId)
            } catch {
                if ($_.FullyQualifiedErrorId -like "NoMatchingEventsFound*") { return @() }
                throw
            }
        }
    }
    if ($null -eq $ReadChannelState) {
        $ReadChannelState = {
            $info = [System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.GetLogInformation(
                $channel, [System.Diagnostics.Eventing.Reader.PathType]::LogName)
            $created = $null
            if ($null -ne $info.CreationTime) {
                $created = ([DateTime]$info.CreationTime).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
            }
            $oldest = $null
            if ($null -ne $info.OldestRecordNumber) { $oldest = [long]$info.OldestRecordNumber }
            [ordered]@{ oldest_record_number = $oldest; log_creation_time_utc = $created }
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
                Channel = [string]$Event.LogName
                TimeCreated = $Event.TimeCreated.ToUniversalTime().ToString("o")
                Provider = [string]$Event.ProviderName
                EventData = $eventData
            }
        }
    }

    $failures = New-Object System.Collections.Generic.List[string]
    $answer = [ordered]@{
        target_queried_at_utc = [DateTime]::UtcNow.ToString("o")
        source_lower_record_id = 0
        source_upper_record_id = 0
        lower_anchor_raw_xml_sha256 = $null
        upper_anchor_raw_xml_sha256 = $null
        oldest_record_number = $null
        log_creation_time_utc = $null
        target_event_count = 0
        target_identity_sha256 = $null
        bound_keys = @()
        failures = $failures
        records = @()
    }

    # The upper bound is the newest record of the channel, of any Event ID.
    $upperEvent = & $QueryUpper
    if ($null -eq $upperEvent) {
        $failures.Add("empty_channel")
        return $answer
    }
    $upper = [long]$upperEvent.RecordId
    if ($upper -lt $LastRecordId) { $failures.Add("upper_below_published_records") }

    # Time is used once, as the live polls use it, to choose the lower RecordId.
    $seed = @(& $QuerySeed $ContextStart $upper)
    if ($seed.Count -eq 0) {
        $failures.Add("empty_bound")
        return $answer
    }
    $lowerEvent = $seed[0]
    $lower = [long]$lowerEvent.RecordId
    if ($ExpectedLowerRecordId -gt 0 -and $lower -ne $ExpectedLowerRecordId) {
        $failures.Add("lower_differs_from_first_published_record")
    }
    $state = & $ReadChannelState

    $first = @(& $QueryBound $lower $upper)
    $second = @(& $QueryBound $lower $upper)
    $firstLines = @($first | ForEach-Object { & $identityLine $_ })
    $secondLines = @($second | ForEach-Object { & $identityLine $_ })
    if ($firstLines.Count -eq 0) { $failures.Add("empty_bound") }
    $consistent = ($firstLines.Count -eq $secondLines.Count)
    for ($index = 0; $consistent -and $index -lt $firstLines.Count; $index++) {
        if ($firstLines[$index] -cne $secondLines[$index]) { $consistent = $false }
    }
    if (-not $consistent) { $failures.Add("view_mismatch") }
    foreach ($item in @(@($upperEvent, $lowerEvent) + $first + $second)) {
        if (-not ([string]$item.MachineName -ceq $ExpectedHost) -or -not ([string]$item.LogName -ceq $channel)) {
            $failures.Add("host_or_channel_mismatch")
            break
        }
    }
    $lowerLine = & $identityLine $lowerEvent
    if ($firstLines.Count -eq 0 -or $firstLines[0] -cne $lowerLine) { $failures.Add("lower_anchor_not_in_bound") }
    $oldest = $state.oldest_record_number
    if ($null -eq $oldest -or [long]$oldest -gt $lower) { $failures.Add("bound_not_retained") }
    if ([string]::IsNullOrEmpty([string]$state.log_creation_time_utc)) { $failures.Add("channel_state_unreadable") }

    $answer.source_lower_record_id = $lower
    $answer.source_upper_record_id = $upper
    $answer.lower_anchor_raw_xml_sha256 = (& $sha256Text @([string]$lowerEvent.ToXml()))
    $answer.upper_anchor_raw_xml_sha256 = (& $sha256Text @([string]$upperEvent.ToXml()))
    $answer.oldest_record_number = $oldest
    $answer.log_creation_time_utc = $state.log_creation_time_utc
    $answer.target_event_count = $firstLines.Count
    $answer.target_identity_sha256 = (& $sha256Text $firstLines)
    $answer.bound_keys = @($first | ForEach-Object { "{0}:{1}" -f ([long]$_.RecordId), ([int]$_.Id) })
    if ($failures.Count -eq 0) {
        $answer.records = @($first | Where-Object { [long]$_.RecordId -gt $LastRecordId } |
            ForEach-Object { & $ConvertTarget $_ })
    }
    $answer
}
