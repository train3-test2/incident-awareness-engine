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

# ---------------------------------------------------------------------------
# Controller side of the sidecar. r1-incremental-sysmon-producer.ps1 dot-sources
# this file, and so do the guard tests: the functions below run in the caller's
# scope and read its $state, $rawRoot, $runSpool, $statePath, $ChunkMaxEvents,
# $RequiredPartitionContract, $TargetHost, $RunId, $ContextStartUtc,
# $AllowedLatenessMs, $freezeRequestPath, $freezeGenerationPath, $freezeAckPath,
# $freezeFailurePath and $producerBindingPath, and call its Invoke-Wiring and
# Invoke-FreezeTool. The guard tests replace those two and Invoke-Command.
# ---------------------------------------------------------------------------

$R1_SIDECAR_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
$R1_SIDECAR_FAILURE_SCHEMA = "r1-sysmon-collection-freeze-failure"
$R1_SIDECAR_BINDING_SCHEMA = "r1-sysmon-collection-producer-binding"
# Stable reason codes of collection-freeze-failed.json.
$R1_SIDECAR_FAILURE_CODES = @(
    "request_unreadable", "request_binding_mismatch", "live_key_invalid", "live_segment_missing",
    "freeze_snapshot_rejected", "bound_key_invalid", "delivery_failed", "segment_chunk_mismatch",
    "live_bound_mismatch", "freeze_tool_failed", "unexpected_error")

function Write-AtomicText([string]$Path, [string]$Text) {
    $encoding = New-Object System.Text.UTF8Encoding($false)
    $temp = $Path + "." + [Guid]::NewGuid().ToString("N") + ".tmp"
    [IO.File]::WriteAllText($temp, $Text, $encoding)
    if (Test-Path -LiteralPath $Path) {
        $same = ([IO.File]::ReadAllText($Path) -ceq $Text)
        Remove-Item -LiteralPath $temp -Force
        if (-not $same) { throw "immutable path conflict: $Path" }
        return
    }
    [IO.File]::Move($temp, $Path)
}

# A property of parsed JSON, or $null when it is missing (StrictMode would throw).
function Get-PositionField($Object, [string]$Name) {
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) { return $Object[$Name] }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function Get-PositionSha256Bytes([byte[]]$Bytes) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace("-", "").ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

function Save-ProducerState {
    $encoding = New-Object System.Text.UTF8Encoding($false)
    $stateTemp = $statePath + "." + [Guid]::NewGuid().ToString("N") + ".next"
    [IO.File]::WriteAllText($stateTemp, (($state | ConvertTo-Json -Compress) + "`n"), $encoding)
    Move-Item -LiteralPath $stateTemp -Destination $statePath -Force
}

# Write the records of one answer as raw segments, one chunk per segment.
function Publish-Records([object[]]$Records, [string]$TargetQueriedAtUtc, [string]$ControllerReceivedAtUtc) {
    for ($offset = 0; $offset -lt $Records.Count; $offset += $ChunkMaxEvents) {
        $end = [Math]::Min($offset + $ChunkMaxEvents - 1, $Records.Count - 1)
        $slice = @($Records[$offset..$end])
        $state.segment_no++
        $state.chunk_sequence++
        $state.message_ordinal++
        $rawPath = Join-Path $rawRoot ("sysmon-{0:D8}.jsonl" -f $state.segment_no)
        $metaPath = $rawPath + ".capture.json"
        $lines = @($slice | ForEach-Object { $_ | ConvertTo-Json -Compress -Depth 8 })
        if (-not (Test-Path -LiteralPath $metaPath)) {
            Write-AtomicText $metaPath (([ordered]@{
                target_queried_at_utc = $TargetQueriedAtUtc
                controller_received_at_utc = $ControllerReceivedAtUtc
                observed_at_utc = $ControllerReceivedAtUtc
            } | ConvertTo-Json -Compress) + "`n")
        }
        Write-AtomicText $rawPath (($lines -join "`n") + "`n")
        $capture = Get-Content -LiteralPath $metaPath -Raw -Encoding UTF8 | ConvertFrom-Json
        Invoke-Wiring @("publish-segment", "--spool-root", $runSpool,
            "--required-partition-contract", $RequiredPartitionContract,
            "--target-host", $TargetHost, "--run-id", $RunId,
            "--raw-jsonl", $rawPath, "--raw-log-id", ("R1-INCREMENTAL-" + $RunId + "-SYSMON"),
            "--segment-no", [string]$state.segment_no,
            "--chunk-sequence", [string]$state.chunk_sequence,
            "--message-ordinal", [string]$state.message_ordinal,
            "--observed-at", [string]$capture.observed_at_utc)
        $state.last_record_id = [long]$slice[-1].RecordId
    }
}

# Throw a freeze error whose message starts with its stable reason code, so that
# collection-freeze-failed.json can name the code without the message.
function Stop-PositionFreeze([string]$ReasonCode, [string]$Message, [string[]]$Details = @()) {
    $suffix = ""
    if (@($Details).Count -gt 0) { $suffix = ":" + (@($Details) -join ",") }
    throw ("[" + $ReasonCode + $suffix + "] " + $Message)
}

# "RecordId:EventId" keys: a positive decimal RecordId and Sysmon EID 1 or 3, each
# RecordId once and in ascending order.
function Assert-PositionKeys([string[]]$Keys, [string]$ReasonCode, [string]$Label) {
    $previous = [long]0
    foreach ($key in @($Keys)) {
        if (-not ([string]$key -cmatch '^[1-9][0-9]{0,18}:(1|3)$')) {
            Stop-PositionFreeze $ReasonCode ($Label + " key is not RecordId:EventId of EID 1 or 3: '" + [string]$key + "'")
        }
        $recordId = [long]([string]$key).Split(":")[0]
        if ($recordId -le $previous) {
            Stop-PositionFreeze $ReasonCode ($Label + " keys repeat a RecordId or are not in ascending order")
        }
        $previous = $recordId
    }
}

# "RecordId:EventId" of every published raw record, in segment order, as a flat
# string array.
function Get-PublishedLiveKeys {
    $keys = New-Object System.Collections.Generic.List[string]
    for ($segment = 1; $segment -le [int64]$state.segment_no; $segment++) {
        $rawPath = Join-Path $rawRoot ("sysmon-{0:D8}.jsonl" -f $segment)
        if (-not (Test-Path -LiteralPath $rawPath)) {
            Stop-PositionFreeze "live_segment_missing" ("published raw segment is missing: " + $rawPath)
        }
        foreach ($line in @(Get-Content -LiteralPath $rawPath -Encoding UTF8)) {
            if ([string]::IsNullOrWhiteSpace($line)) { continue }
            try {
                $record = $line | ConvertFrom-Json
            } catch {
                Stop-PositionFreeze "live_key_invalid" ("a published raw record is not JSON in " + $rawPath)
            }
            $recordId = Get-PositionField $record "RecordId"
            $eventId = Get-PositionField $record "EventId"
            if (($recordId -isnot [int] -and $recordId -isnot [long]) -or
                ($eventId -isnot [int] -and $eventId -isnot [long])) {
                Stop-PositionFreeze "live_key_invalid" ("a published raw record has no integer RecordId and EventId in " + $rawPath)
            }
            $keys.Add(("{0}:{1}" -f ([long]$recordId), ([long]$eventId)))
        }
    }
    $flat = [string[]]$keys.ToArray()
    Assert-PositionKeys -Keys $flat -ReasonCode "live_key_invalid" -Label "published raw record"
    return $flat
}

# The request the runner wrote, bound to this sidecar's Run, host and partition.
function Read-PositionFreezeRequest {
    try {
        $bytes = [IO.File]::ReadAllBytes($freezeRequestPath)
        $request = (New-Object System.Text.UTF8Encoding($false)).GetString($bytes) | ConvertFrom-Json
    } catch {
        Stop-PositionFreeze "request_unreadable" ("the freeze request cannot be read: " + $freezeRequestPath)
    }
    $partition = Get-PositionField $request "partition"
    if ([string](Get-PositionField $request "schema") -cne "r1-sysmon-collection-freeze-request" -or
        [string](Get-PositionField $partition "run_id") -cne $RunId -or
        [string](Get-PositionField $partition "host_id") -cne $TargetHost -or
        [string](Get-PositionField $partition "source") -cne "sysmon" -or
        [string](Get-PositionField $partition "source_channel") -cne $R1_SIDECAR_CHANNEL) {
        Stop-PositionFreeze "request_binding_mismatch" "the freeze request is not bound to this sidecar's Run, host and partition"
    }
    return [ordered]@{
        request_id = [string](Get-PositionField $request "request_id"); request_sha256 = (Get-PositionSha256Bytes $bytes) }
}

# The producer side of one collection freeze. Nothing is written to the control
# directory unless every bound record is published, delivered and acked. The
# Python output of the wiring and of the freeze tool goes to the host, so the
# only output of this function is the upper RecordId.
function Invoke-PositionFreeze($Session) {
    $null = Read-PositionFreezeRequest
    $published = @(Get-PublishedLiveKeys)
    $expectedLower = [long]0
    if ($published.Count -gt 0) { $expectedLower = [long]($published[0].Split(":")[0]) }
    $snapshot = Invoke-Command -Session $Session -ScriptBlock $R1_POSITION_FREEZE_SNAPSHOT `
        -ArgumentList @([long]$state.last_record_id, $ContextStartUtc, $expectedLower, $TargetHost)
    $observedAt = [DateTime]::UtcNow
    $failures = @($snapshot.failures | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_ })
    if ($failures.Count -gt 0) {
        Stop-PositionFreeze "freeze_snapshot_rejected" ("position freeze snapshot failed: " + ($failures -join ", ")) $failures
    }
    $bound = [string[]]@($snapshot.bound_keys | ForEach-Object { [string]$_ })
    Assert-PositionKeys -Keys $bound -ReasonCode "bound_key_invalid" -Label "RecordId bound"
    if ([long]$snapshot.target_event_count -ne $bound.Count) {
        Stop-PositionFreeze "bound_key_invalid" "the bound Event count is not the number of bound keys"
    }

    $lower = [long]$snapshot.source_lower_record_id
    $upper = [long]$snapshot.source_upper_record_id
    try {
        Publish-Records -Records @($snapshot.records) -TargetQueriedAtUtc ([string]$snapshot.target_queried_at_utc) `
            -ControllerReceivedAtUtc $observedAt.ToString("o") | Out-Host
        $state.last_record_id = $upper
        Save-ProducerState
        Invoke-Wiring @("consume", "--spool-root", $runSpool,
            "--required-partition-contract", $RequiredPartitionContract,
            "--target-host", $TargetHost) | Out-Host
    } catch {
        Stop-PositionFreeze "delivery_failed" ("publishing or delivering the bound records failed: " + $_.Exception.Message)
    }

    if ([int64]$state.segment_no -ne [int64]$state.chunk_sequence) {
        Stop-PositionFreeze "segment_chunk_mismatch" "raw segment and chunk sequence numbers differ; the freeze ack cannot name its covered chunks"
    }
    $live = @(Get-PublishedLiveKeys)
    if (($live -join ",") -cne ($bound -join ",")) {
        Stop-PositionFreeze "live_bound_mismatch" "the published live records are not exactly the EID 1/3 records of the RecordId bound"
    }

    $common = @("--request", $freezeRequestPath, "--run-id", $RunId, "--target-host", $TargetHost,
        "--required-partition-contract", $RequiredPartitionContract,
        "--lower", [string]$lower, "--upper", [string]$upper)
    try {
        Invoke-FreezeTool (@("write-generation-observation") + $common + @(
            "--output", $freezeGenerationPath, "--phase", "freeze_ack",
            "--lower-anchor-raw-xml-sha256", [string]$snapshot.lower_anchor_raw_xml_sha256,
            "--upper-anchor-raw-xml-sha256", [string]$snapshot.upper_anchor_raw_xml_sha256,
            "--oldest-record-number", [string]$snapshot.oldest_record_number,
            "--log-creation-time-utc", [string]$snapshot.log_creation_time_utc,
            "--observed-at", $observedAt.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"))) | Out-Host
        Invoke-FreezeTool (@("write-freeze-ack") + $common + @(
            "--output", $freezeAckPath, "--run-spool-root", $runSpool,
            "--target-event-count", [string]$bound.Count,
            "--target-identity-sha256", [string]$snapshot.target_identity_sha256,
            "--covered-through-chunk-sequence", [string]$state.chunk_sequence,
            "--allowed-lateness-ms", [string]$AllowedLatenessMs)) | Out-Host
    } catch {
        Stop-PositionFreeze "freeze_tool_failed" ("the freeze tool refused the generation or the ack: " + $_.Exception.Message)
    }
    return $upper
}

# collection-freeze-failed.json: the machine-readable reason a freeze stopped,
# bound to the request bytes so that the runner never reads it as the failure
# of another request. It holds no message, path, credential or stack trace.
function Write-PositionFreezeFailure([string]$ErrorMessage) {
    $code = "unexpected_error"
    $details = @()
    if ([string]$ErrorMessage -cmatch '^\[([a-z_]+)(?::([a-z_,]+))?\] ') {
        if ($R1_SIDECAR_FAILURE_CODES -ccontains $Matches[1]) {
            $code = $Matches[1]
            if ($Matches.ContainsKey(2) -and -not [string]::IsNullOrEmpty($Matches[2])) { $details = @($Matches[2].Split(",")) }
        }
    }
    $requestId = $null
    $requestSha256 = $null
    try {
        $bytes = [IO.File]::ReadAllBytes($freezeRequestPath)
        $requestSha256 = Get-PositionSha256Bytes $bytes
        $requestId = [string](Get-PositionField ((New-Object System.Text.UTF8Encoding($false)).GetString($bytes) |
                ConvertFrom-Json) "request_id")
    } catch {
        $requestId = $null
    }
    $failure = [ordered]@{
        schema            = $R1_SIDECAR_FAILURE_SCHEMA
        contract_version  = "v0.1"
        run_id            = $RunId
        host_id           = $TargetHost
        request_id        = $requestId
        request_sha256    = $requestSha256
        partition         = [ordered]@{ run_id = $RunId; host_id = $TargetHost; source = "sysmon"; source_channel = $R1_SIDECAR_CHANNEL }
        failed_at         = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        reason_code       = $code
        snapshot_failures = @($details)
    }
    Write-AtomicText $freezeFailurePath (($failure | ConvertTo-Json -Depth 4 -Compress) + "`n")
    return $code
}

# collection-producer-binding.json: what this sidecar collects, written before
# the runner starts so that the runner can refuse a host, partition or contract
# that is not its own before any action. Its content has no time, so a restart
# with the same arguments writes the same bytes.
function Write-PositionProducerBinding {
    $contractPath = (Resolve-Path -LiteralPath $RequiredPartitionContract).Path
    $bytes = [IO.File]::ReadAllBytes($contractPath)
    $contract = (New-Object System.Text.UTF8Encoding($false)).GetString($bytes) | ConvertFrom-Json
    $parts = @(Get-PositionField $contract "required_partitions")
    if ([string](Get-PositionField $contract "schema") -cne "r1-required-partitions" -or
        [string](Get-PositionField $contract "contract_version") -cne "v0.1" -or
        [string](Get-PositionField $contract "target_host") -cne $TargetHost) {
        throw "the required-partition contract is not a v0.1 contract of this TargetHost"
    }
    if ($parts.Count -ne 1 -or [string](Get-PositionField $parts[0] "source") -cne "sysmon" -or
        [string](Get-PositionField $parts[0] "source_channel") -cne $R1_SIDECAR_CHANNEL) {
        throw "the required-partition contract does not name exactly the Sysmon partition"
    }
    $binding = [ordered]@{
        schema                      = $R1_SIDECAR_BINDING_SCHEMA
        contract_version            = "v0.1"
        run_id                      = $RunId
        host_id                     = $TargetHost
        partition                   = [ordered]@{ run_id = $RunId; host_id = $TargetHost; source = "sysmon"; source_channel = $R1_SIDECAR_CHANNEL }
        required_partition_contract = [ordered]@{
            path = $contractPath; sha256 = (Get-PositionSha256Bytes $bytes); target_host = $TargetHost }
        context_start_utc           = $ContextStartUtc
    }
    Write-AtomicText $producerBindingPath (($binding | ConvertTo-Json -Depth 4 -Compress) + "`n")
}
