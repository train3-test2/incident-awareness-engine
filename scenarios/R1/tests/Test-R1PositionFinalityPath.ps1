<#
    Regression checks for the VM path of the R1 RecordId position finality.

    Runs on the host with no VM, no WinRM, no Sysmon and no Python: Target-A
    queries, the export, the clock and the producer are fakes, and every case
    works on temporary directories. No real Run or Pair identity is used.

    Covered:

    1. the producer's freeze snapshot ($R1_POSITION_FREEZE_SNAPSHOT): the closed
       bound, the lower and upper records inside it, the records still to
       publish, the identity digest, and each failure that forbids an ack,
    2. the producer script: no freeze without consuming, no resume of an
       interrupted freeze, and the ack only after delivery and comparison,
    3. the runner's freeze request, the check of the producer's ack and
       generation, and the wait for them,
    4. the RecordId-bounded export step and the snapshot it completes: the
       XPath is the RecordId bound, the digest is the producer's, and export
       drift, generation change, JSONL drift and later file drift fail closed,
    5. that nothing here issues or reads an event-time watermark or run_closed.

        powershell -ExecutionPolicy Bypass -File scenarios\R1\tests\Test-R1PositionFinalityPath.ps1

    NOTE: this file is intentionally ASCII only, like the rest of scenarios/R1.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "..\run-common.ps1")
. (Join-Path $PSScriptRoot "..\r1-incremental-sysmon-producer-common.ps1")

$script:Failures = 0
$script:Total = 0
$script:TempRoots = New-Object System.Collections.Generic.List[string]

function Assert-True {
    param([Parameter(Mandatory = $true)][string]$Name, [Parameter(Mandatory = $true)][bool]$Condition)
    $script:Total++
    if ($Condition) {
        Write-Host "[PASS] $Name" -ForegroundColor Green
    } else {
        $script:Failures++
        Write-Host "[FAIL] $Name" -ForegroundColor Red
    }
}

function Assert-Throws {
    param([Parameter(Mandatory = $true)][string]$Name, [Parameter(Mandatory = $true)][scriptblock]$Action,
        [string]$MessageLike)
    $script:Total++
    try {
        & $Action | Out-Null
        $script:Failures++
        Write-Host "[FAIL] $Name (no error was raised)" -ForegroundColor Red
    } catch {
        $message = $_.Exception.Message
        if ($MessageLike -and ($message -notlike $MessageLike)) {
            $script:Failures++
            Write-Host "[FAIL] $Name (message was: $message)" -ForegroundColor Red
            return
        }
        Write-Host "[PASS] $Name" -ForegroundColor Green
    }
}

function New-TempRoot {
    $path = Join-Path ([System.IO.Path]::GetTempPath()) ("r1-position-" + [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $path -Force | Out-Null
    $script:TempRoots.Add($path)
    return $path
}

# Computed here, independently of the code under test.
function Get-TestSha256Text {
    param([AllowEmptyCollection()][string[]]$Lines)
    $bytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes((($Lines -join "`n") + "`n"))
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace("-", "").ToLowerInvariant() }
    finally { $sha.Dispose() }
}

$RUN_ID = "RUN-20300101-901"
$HOST_A = "TARGET-A"
$CHANNEL = "Microsoft-Windows-Sysmon/Operational"
$CONTEXT_START = "2030-01-01T00:00:01.000Z"
$CREATED = "2029-12-31T23:50:00.000Z"

function New-FakeEvent {
    <# A Sysmon record the way Get-WinEvent hands it back, with its raw XML. #>
    param([long]$RecordId, [int]$EventId, [int]$Second, [string]$MachineName = $HOST_A,
        [string]$LogName = $CHANNEL, [string]$Image = "C:\Windows\System32\cmd.exe")
    $xml = ("<Event><System><EventID>{0}</EventID><EventRecordID>{1}</EventRecordID><Computer>{2}</Computer>" +
        "</System><EventData><Data Name='UtcTime'>2030-01-01 00:00:{3:D2}.000</Data><Data Name='Image'>{4}</Data>" +
        "</EventData></Event>") -f $EventId, $RecordId, $MachineName, $Second, $Image
    $event = [pscustomobject]@{
        RecordId     = $RecordId
        Id           = $EventId
        MachineName  = $MachineName
        LogName      = $LogName
        ProviderName = "Microsoft-Windows-Sysmon"
        TimeCreated  = [datetime]::new(2030, 1, 1, 0, 0, $Second, [System.DateTimeKind]::Utc)
        Xml          = $xml
    }
    $event | Add-Member -MemberType ScriptMethod -Name ToXml -Value { $this.Xml }
    return $event
}

function Get-TestIdentityLine {
    param($Event)
    return ("{0}`t{1}`t{2}`t{3}`t{4}" -f $Event.MachineName, $Event.LogName, $Event.RecordId, $Event.Id,
        (Get-TestSha256Text @($Event.ToXml())))
}

# Target-A: 1000 is before the context start, 1003 is not EID 1 or 3, and the
# newest record of the channel (1006, EID 22) is the all-channel upper bound.
function New-ChannelEvents {
    return @(
        (New-FakeEvent 1000 1 0),
        (New-FakeEvent 1001 1 2),
        (New-FakeEvent 1002 1 3 -Image "C:\Windows\System32\wscript.exe"),
        (New-FakeEvent 1003 11 4),
        (New-FakeEvent 1004 3 5),
        (New-FakeEvent 1005 1 6),
        (New-FakeEvent 1006 22 7))
}

function New-FreezeSeams {
    param([object[]]$Events, [hashtable]$State = @{ oldest_record_number = 900; log_creation_time_utc = $CREATED })
    $script:SeamEvents = $Events
    $script:SeamState = $State
    $script:BoundReads = 0
    return @{
        QueryUpper       = { if ($script:SeamEvents.Count -eq 0) { return $null }; $script:SeamEvents[-1] }
        QuerySeed        = {
            param($Start, $ThroughRecordId)
            $startTime = (ConvertFrom-R1UtcStamp $Start "start")
            @($script:SeamEvents | Where-Object {
                    @(1, 3) -contains $_.Id -and $_.TimeCreated -ge $startTime -and
                    $_.RecordId -le $ThroughRecordId } | Sort-Object RecordId | Select-Object -First 1)
        }
        QueryBound       = {
            param($Lower, $Upper)
            $script:BoundReads++
            @($script:SeamEvents | Where-Object {
                    @(1, 3) -contains $_.Id -and $_.RecordId -ge $Lower -and $_.RecordId -le $Upper } |
                Sort-Object RecordId)
        }
        ReadChannelState = { $script:SeamState }
    }
}

function Invoke-FreezeSnapshot {
    param([long]$LastRecordId, [long]$ExpectedLower, [hashtable]$Seams, [scriptblock]$QueryBound)
    if ($null -eq $QueryBound) { $QueryBound = $Seams.QueryBound }
    return (& $R1_POSITION_FREEZE_SNAPSHOT $LastRecordId $CONTEXT_START $ExpectedLower $HOST_A `
        $Seams.QueryUpper $Seams.QuerySeed $QueryBound $Seams.ReadChannelState $null)
}

 # --- 1. the producer's freeze snapshot ----------------------------------------------

$channelEvents = New-ChannelEvents
$boundEvents = @($channelEvents | Where-Object { @(1001, 1002, 1004, 1005) -contains $_.RecordId })
$expectedIdentity = Get-TestSha256Text @($boundEvents | ForEach-Object { Get-TestIdentityLine $_ })
$snapshot = Invoke-FreezeSnapshot -LastRecordId 1002 -ExpectedLower 1001 -Seams (New-FreezeSeams $channelEvents)

Assert-True "freeze: a consistent bound has no failure" (@($snapshot.failures).Count -eq 0)
Assert-True "freeze: the upper bound is the newest record of any Event ID and the lower the first since the context" (
    $snapshot.source_lower_record_id -eq 1001 -and $snapshot.source_upper_record_id -eq 1006)
Assert-True "freeze: the bound holds exactly the EID 1/3 records of the closed interval, read twice" (
    $snapshot.target_event_count -eq 4 -and (@($snapshot.bound_keys) -join ",") -ceq "1001:1,1002:1,1004:3,1005:1" -and
    $script:BoundReads -eq 2)
Assert-True "freeze: the identity digest is the host/channel/RecordId/EventId/raw-XML digest" (
    $snapshot.target_identity_sha256 -ceq $expectedIdentity)
Assert-True "freeze: only the records after the published ones are left to publish, with their channel" (
    (@($snapshot.records | ForEach-Object { [string]$_.RecordId }) -join ",") -ceq "1004,1005" -and
    @($snapshot.records | Where-Object { $_.Channel -cne $CHANNEL -or $_.Computer -cne $HOST_A }).Count -eq 0)
Assert-True "freeze: the generation anchors are the raw XML digests of the two bound records" (
    $snapshot.lower_anchor_raw_xml_sha256 -ceq (Get-TestSha256Text @($channelEvents[1].ToXml())) -and
    $snapshot.upper_anchor_raw_xml_sha256 -ceq (Get-TestSha256Text @($channelEvents[6].ToXml())) -and
    $snapshot.oldest_record_number -eq 900 -and $snapshot.log_creation_time_utc -ceq $CREATED)

$edgeEvents = @((New-FakeEvent 1001 1 2), (New-FakeEvent 1002 11 3), (New-FakeEvent 1003 3 4))
$edge = Invoke-FreezeSnapshot -LastRecordId 0 -ExpectedLower 0 -Seams (New-FreezeSeams $edgeEvents)
Assert-True "freeze: the lower and the upper RecordId are both inside the bound" (
    @($edge.failures).Count -eq 0 -and $edge.source_lower_record_id -eq 1001 -and $edge.source_upper_record_id -eq 1003 -and
    (@($edge.bound_keys) -join ",") -ceq "1001:1,1003:3" -and @($edge.records).Count -eq 2)

$seams = New-FreezeSeams (New-ChannelEvents)
$changing = {
    param($Lower, $Upper)
    $script:BoundReads++
    $read = @($script:SeamEvents | Where-Object { @(1, 3) -contains $_.Id -and $_.RecordId -ge $Lower -and $_.RecordId -le $Upper })
    if ($script:BoundReads -eq 2) { $read = @($read | Where-Object { $_.RecordId -ne 1004 }) }
    $read
}
$unstable = Invoke-FreezeSnapshot -LastRecordId 1002 -ExpectedLower 1001 -Seams $seams -QueryBound $changing
Assert-True "freeze: a bound event missing from the second read forbids the ack and publishes nothing" (
    @($unstable.failures) -contains "view_mismatch" -and @($unstable.records).Count -eq 0)

foreach ($case in @(
        @{ name = "a record of another host"; failure = "host_or_channel_mismatch"
           events = { $e = New-ChannelEvents; $e[4] = New-FakeEvent 1004 3 5 -MachineName "TARGET-B"; $e } },
        @{ name = "a record of another channel"; failure = "host_or_channel_mismatch"
           events = { $e = New-ChannelEvents; $e[2] = New-FakeEvent 1002 1 3 -LogName "Microsoft-Windows-PowerShell/Operational"; $e } })) {
    $result = Invoke-FreezeSnapshot -LastRecordId 1002 -ExpectedLower 1001 -Seams (New-FreezeSeams (& $case.events))
    Assert-True ("freeze: " + $case.name + " forbids the ack") (
        @($result.failures) -contains $case.failure -and @($result.records).Count -eq 0)
}

$otherLower = Invoke-FreezeSnapshot -LastRecordId 1002 -ExpectedLower 999 -Seams (New-FreezeSeams (New-ChannelEvents))
Assert-True "freeze: a lower bound that is not the first published record forbids the ack" (
    @($otherLower.failures) -contains "lower_differs_from_first_published_record")
$behind = Invoke-FreezeSnapshot -LastRecordId 2000 -ExpectedLower 1001 -Seams (New-FreezeSeams (New-ChannelEvents))
Assert-True "freeze: a channel whose newest record is below the published ones forbids the ack" (
    @($behind.failures) -contains "upper_below_published_records")
$lost = Invoke-FreezeSnapshot -LastRecordId 1002 -ExpectedLower 1001 `
    -Seams (New-FreezeSeams (New-ChannelEvents) @{ oldest_record_number = 1002; log_creation_time_utc = $CREATED })
Assert-True "freeze: a channel that no longer retains the lower record forbids the ack" (
    @($lost.failures) -contains "bound_not_retained")
$empty = Invoke-FreezeSnapshot -LastRecordId 0 -ExpectedLower 0 -Seams (New-FreezeSeams @())
Assert-True "freeze: an empty channel forbids the ack" (@($empty.failures) -contains "empty_channel")
$noTarget = Invoke-FreezeSnapshot -LastRecordId 0 -ExpectedLower 0 -Seams (New-FreezeSeams @((New-FakeEvent 1001 11 2)))
Assert-True "freeze: a bound without EID 1/3 forbids the ack" (@($noTarget.failures) -contains "empty_bound")

$defaultRecord = & {
    $seamsWithConverter = New-FreezeSeams (New-ChannelEvents)
    $result = & $R1_POSITION_FREEZE_SNAPSHOT 1004 $CONTEXT_START 1001 $HOST_A $seamsWithConverter.QueryUpper `
        $seamsWithConverter.QuerySeed $seamsWithConverter.QueryBound $seamsWithConverter.ReadChannelState
    @($result.records)[0]
}
Assert-True "freeze: the default converter writes the channel the Python finalizer requires" (
    [string]$defaultRecord.Channel -ceq $CHANNEL -and [long]$defaultRecord.RecordId -eq 1005 -and
    [string]$defaultRecord.EventData.Image -ceq "C:\Windows\System32\cmd.exe")

 # --- 2. the producer's Controller side, executed -----------------------------------------
 # The production functions of r1-incremental-sysmon-producer-common.ps1 run here
 # against a temporary spool. Only Target-A (Invoke-Command), the Python wiring
 # and the Python freeze tool are fakes; their stdout is emulated too, so that a
 # function that leaked it into its return value would show.

function Invoke-Wiring([string[]]$Arguments) {
    $script:ProducerCalls.Add("wiring:" + $Arguments[0])
    if ($script:WiringFails -ceq $Arguments[0]) { throw ("synthetic wiring failure in " + $Arguments[0]) }
    Write-Output ("python stdout of " + $Arguments[0])
}
function Invoke-FreezeTool([string[]]$Arguments) {
    $script:ProducerCalls.Add("freeze:" + $Arguments[0])
    $script:FreezeToolArguments.Add([string[]]@($Arguments))
    if ($script:FreezeToolFails) { throw "synthetic freeze tool failure" }
    Write-Output ("python stdout of " + $Arguments[0])
}
function Invoke-Command {
    param($Session, $ScriptBlock, $ArgumentList)
    $script:ProducerCalls.Add("target:freeze_snapshot")
    $script:FreezeInvokeArguments = @($ArgumentList)
    return $script:FakeSnapshot
}

function New-LiveRecord([long]$RecordId, [int]$EventId) {
    return [ordered]@{
        RecordId = $RecordId; EventId = $EventId; Computer = $HOST_A; Channel = $CHANNEL
        TimeCreated = "2030-01-01T00:00:02.0000000Z"; Provider = "Microsoft-Windows-Sysmon"
        EventData = [ordered]@{ Image = "C:\Windows\System32\cmd.exe" }
    }
}

function New-FakeFreezeSnapshot([string[]]$BoundKeys, [object[]]$Remaining = @(), [string[]]$Failures = @(), $Count = $null) {
    if ($null -eq $Count) { $Count = @($BoundKeys).Count }
    # The shape a WinRM answer arrives in: a hashtable with list members.
    return @{
        target_queried_at_utc = "2030-01-01T00:13:01.0000000Z"; source_lower_record_id = [long]1001
        source_upper_record_id = [long]1006; lower_anchor_raw_xml_sha256 = ("1" * 64)
        upper_anchor_raw_xml_sha256 = ("2" * 64); oldest_record_number = [long]900
        log_creation_time_utc = $CREATED; target_event_count = $Count; target_identity_sha256 = ("a" * 64)
        bound_keys = [System.Collections.ArrayList]@($BoundKeys); failures = [System.Collections.ArrayList]@($Failures)
        records = [System.Collections.ArrayList]@($Remaining)
    }
}

function New-ProducerFixture {
    param([object[]]$PrePublished = @(), [string]$RequestHost = $HOST_A, [switch]$NoRequest)
    $root = New-TempRoot
    $script:runSpool = Join-Path $root ("spool\" + $RUN_ID)
    $script:rawRoot = Join-Path $script:runSpool "raw-segments"
    New-Item -ItemType Directory -Path $script:rawRoot -Force | Out-Null
    $script:statePath = Join-Path $script:runSpool "producer-state.json"
    $control = Join-Path $root ("control\" + $RUN_ID)
    New-Item -ItemType Directory -Path $control -Force | Out-Null
    $script:RunId = $RUN_ID
    $script:TargetHost = $HOST_A
    $script:ContextStartUtc = $CONTEXT_START
    $script:ChunkMaxEvents = 200
    $script:AllowedLatenessMs = 2000
    $script:RequiredPartitionContract = Join-Path $root "contract.json"
    $script:freezeRequestPath = Join-Path $control $R1_FREEZE_REQUEST_FILE
    $script:freezeGenerationPath = Join-Path $control $R1_FREEZE_GENERATION_FILE
    $script:freezeAckPath = Join-Path $control $R1_FREEZE_ACK_FILE
    $script:freezeFailurePath = Join-Path $control $R1_FREEZE_FAILURE_FILE
    $script:producerBindingPath = Join-Path $control $R1_PRODUCER_BINDING_FILE
    $script:state = [ordered]@{ last_record_id = 0; segment_no = 0; chunk_sequence = 0; message_ordinal = 0 }
    $script:ProducerCalls = New-Object System.Collections.Generic.List[string]
    $script:FreezeToolArguments = New-Object System.Collections.Generic.List[object]
    $script:FreezeInvokeArguments = $null
    $script:WiringFails = ""
    $script:FreezeToolFails = $false
    $t = [datetime]::new(2030, 1, 1, 0, 0, 0, [System.DateTimeKind]::Utc)
    $fixtureRequest = New-R1FreezeRequest -RunId $RUN_ID -TargetHost $RequestHost -Channel $CHANNEL `
        -CandidateBoundaryAt $t.AddSeconds(720) -ObservationBoundaryAt $t.AddSeconds(780) -RequestedAt $t.AddSeconds(781)
    if (-not $NoRequest) { Write-R1PositionJson -Path $script:freezeRequestPath -Value $fixtureRequest | Out-Null }
    if (@($PrePublished).Count -gt 0) {
        Publish-Records -Records $PrePublished -TargetQueriedAtUtc "2030-01-01T00:01:00.0000000Z" `
            -ControllerReceivedAtUtc "2030-01-01T00:01:00.0000000Z" | Out-Null
    }
    $script:ProducerCalls.Clear()
    return [ordered]@{ root = $root; control = $control; request = $fixtureRequest }
}

function Invoke-FreezeCase {
    <# Invoke-PositionFreeze, as the producer's loop does: a failure leaves its artifact. #>
    try {
        return [ordered]@{ upper = @(Invoke-PositionFreeze "fake-session"); error = $null; code = $null }
    } catch {
        $message = [string]$_.Exception.Message
        return [ordered]@{ upper = $null; error = $message; code = (Write-PositionFreezeFailure $message) }
    }
}

function Get-FreezeToolArguments([string]$Command) {
    return @($script:FreezeToolArguments | Where-Object { $_[0] -ceq $Command } | Select-Object -First 1)
}

function Get-ArgumentValue([string[]]$Arguments, [string]$Name) {
    if ($null -eq $Arguments) { return $null }
    $index = [array]::IndexOf($Arguments, $Name)
    if ($index -lt 0) { return $null }
    return $Arguments[$index + 1]
}

Assert-True "producer: the sidecar and the runner name the same artifacts, schemas and reason codes" (
    $R1_SIDECAR_FAILURE_SCHEMA -ceq $R1_FREEZE_FAILURE_SCHEMA -and
    $R1_SIDECAR_BINDING_SCHEMA -ceq $R1_PRODUCER_BINDING_SCHEMA -and
    ($R1_SIDECAR_FAILURE_CODES -join ",") -ceq ($R1_FREEZE_FAILURE_CODES -join ",") -and
    $R1_SIDECAR_CHANNEL -ceq $CHANNEL)

# Several published keys, all of them the bound records.
$fixture = New-ProducerFixture -PrePublished @((New-LiveRecord 1001 1), (New-LiveRecord 1002 1))
$publishedBefore = @(Get-PublishedLiveKeys)
$script:FakeSnapshot = New-FakeFreezeSnapshot @("1001:1", "1002:1", "1004:3", "1005:1") `
    @((New-LiveRecord 1004 3), (New-LiveRecord 1005 1))
$case = Invoke-FreezeCase
$ackArguments = [string[]](Get-FreezeToolArguments "write-freeze-ack")
$liveAfter = @(Get-PublishedLiveKeys)
Assert-True "producer: published keys come back as a flat array of RecordId:EventId strings" (
    $publishedBefore.Count -eq 2 -and $publishedBefore[0] -is [string] -and
    ($publishedBefore -join ",") -ceq "1001:1,1002:1" -and
    ($liveAfter -join ",") -ceq "1001:1,1002:1,1004:3,1005:1" -and
    ($liveAfter -join ",") -notmatch 'System\.')
Assert-True "producer: the freeze asks Target-A with the first published record as the lower bound" (
    $null -eq $case.error -and [long]$script:FreezeInvokeArguments[2] -eq 1001 -and
    [long]$script:FreezeInvokeArguments[0] -eq 1002 -and [string]$script:FreezeInvokeArguments[3] -ceq $HOST_A)
Assert-True "producer: the only output of the freeze is the upper RecordId, not the Python stdout" (
    @($case.upper).Count -eq 1 -and [long]@($case.upper)[0] -eq 1006 -and [long]$script:state.last_record_id -eq 1006)
Assert-True "producer: publish, delivery, comparison, generation and ack run in that order" (
    ($script:ProducerCalls -join ",") -ceq
        "target:freeze_snapshot,wiring:publish-segment,wiring:consume,freeze:write-generation-observation,freeze:write-freeze-ack")
Assert-True "producer: the ack names the bound, its Event count and the covered chunks, with no array text" (
    (Get-ArgumentValue $ackArguments "--lower") -ceq "1001" -and (Get-ArgumentValue $ackArguments "--upper") -ceq "1006" -and
    (Get-ArgumentValue $ackArguments "--target-event-count") -ceq "4" -and
    (Get-ArgumentValue $ackArguments "--covered-through-chunk-sequence") -ceq "2" -and
    (Get-ArgumentValue $ackArguments "--allowed-lateness-ms") -ceq "2000" -and
    (Get-ArgumentValue $ackArguments "--run-id") -ceq $RUN_ID -and
    (@($script:FreezeToolArguments | ForEach-Object { $_ -join " " }) -join " ") -notmatch 'System\.' -and
    -not (Test-Path -LiteralPath $script:freezeFailurePath))

# Nothing published before the freeze.
$fixture = New-ProducerFixture
$script:FakeSnapshot = New-FakeFreezeSnapshot @("1001:1", "1004:3") @((New-LiveRecord 1001 1), (New-LiveRecord 1004 3))
$empty = @(Get-PublishedLiveKeys)
$case = Invoke-FreezeCase
$ackArguments = [string[]](Get-FreezeToolArguments "write-freeze-ack")
Assert-True "producer: with nothing published before, the lower bound is unknown and every bound record is published" (
    $empty.Count -eq 0 -and $null -eq $case.error -and [long]$script:FreezeInvokeArguments[2] -eq 0 -and
    (Get-ArgumentValue $ackArguments "--target-event-count") -ceq "2" -and
    (Get-ArgumentValue $ackArguments "--covered-through-chunk-sequence") -ceq "1")

function Get-FailureRecord { return (Get-Content -LiteralPath $script:freezeFailurePath -Raw -Encoding UTF8 | ConvertFrom-Json) }

# A bound record the live polls skipped.
$fixture = New-ProducerFixture -PrePublished @((New-LiveRecord 1001 1), (New-LiveRecord 1004 3))
$script:FakeSnapshot = New-FakeFreezeSnapshot @("1001:1", "1002:1", "1004:3")
$case = Invoke-FreezeCase
$failure = Get-FailureRecord
$failureText = Get-Content -LiteralPath $script:freezeFailurePath -Raw
Assert-True "producer: a bound record missing from the live records fails closed before the freeze tool" (
    $case.error -clike "``[live_bound_mismatch``]*" -and $case.code -ceq "live_bound_mismatch" -and
    @($script:ProducerCalls | Where-Object { $_ -like "freeze:*" }).Count -eq 0)
Assert-True "producer: the failure artifact binds the Run, host, request bytes and partition and holds only a code" (
    $failure.schema -ceq $R1_FREEZE_FAILURE_SCHEMA -and $failure.run_id -ceq $RUN_ID -and $failure.host_id -ceq $HOST_A -and
    $failure.request_id -ceq ($RUN_ID + "-freeze-0001") -and
    $failure.request_sha256 -ceq (Get-R1FileSha256 -Path $script:freezeRequestPath) -and
    $failure.partition.source_channel -ceq $CHANNEL -and $failure.reason_code -ceq "live_bound_mismatch" -and
    @($failure.snapshot_failures).Count -eq 0 -and $failure.failed_at -cmatch $R1_UTC_MS_PATTERN -and
    (@($failure.PSObject.Properties.Name) -join ",") -ceq
        "schema,contract_version,run_id,host_id,request_id,request_sha256,partition,failed_at,reason_code,snapshot_failures" -and
    $failureText -notmatch 'published live records|Exception|\\\\|password|postgres')
Assert-Throws "producer: the runner stops on this failure with its reason code" {
    Test-R1FreezeFailure -Request $fixture.request -RequestSha256 (Get-R1FileSha256 -Path $script:freezeRequestPath) `
        -Failure (Get-FailureRecord)
} "*collection freeze failure: live_bound_mismatch"
Assert-Throws "producer: a failure artifact is written once; another failure does not replace it" {
    Write-PositionFreezeFailure "[freeze_tool_failed] another failure"
} "*immutable path conflict*"
Assert-True "  ... and the first failure is kept" ((Get-FailureRecord).reason_code -ceq "live_bound_mismatch")

# Duplicate and malformed keys.
$fixture = New-ProducerFixture
$segment = Join-Path $script:rawRoot "sysmon-00000001.jsonl"
foreach ($bad in @(
        @{ name = "a RecordId published twice"; lines = @('{"RecordId":1001,"EventId":1}', '{"RecordId":1001,"EventId":1}') },
        @{ name = "a RecordId that is a string"; lines = @('{"RecordId":"1001","EventId":1}') },
        @{ name = "an Event ID other than 1 or 3"; lines = @('{"RecordId":1001,"EventId":11}') },
        @{ name = "a record without an Event ID"; lines = @('{"RecordId":1001}') },
        @{ name = "a line that is not JSON"; lines = @('{"RecordId":') })) {
    [System.IO.File]::WriteAllText($segment, (($bad.lines -join "`n") + "`n"))
    $script:state.segment_no = 1
    Assert-Throws ("producer: " + $bad.name + " is an invalid live key") { @(Get-PublishedLiveKeys) } "``[live_key_invalid``]*"
}
$script:state.segment_no = 2
[System.IO.File]::WriteAllText($segment, ('{"RecordId":1001,"EventId":1}' + "`n"))
Assert-Throws "producer: a published segment that is gone is reported as such" { @(Get-PublishedLiveKeys) } "``[live_segment_missing``]*"
foreach ($bad in @(
        @{ name = "a bound key without its Event ID"; keys = @("1001-1"); count = 1 },
        @{ name = "a bound key of another Event ID"; keys = @("1001:11"); count = 1 },
        @{ name = "a bound key repeated"; keys = @("1001:1", "1001:1"); count = 2 },
        @{ name = "bound keys out of order"; keys = @("1004:3", "1001:1"); count = 2 },
        @{ name = "a bound Event count that is not the number of keys"; keys = @("1001:1"); count = 2 })) {
    $fixture = New-ProducerFixture
    $script:FakeSnapshot = New-FakeFreezeSnapshot $bad.keys @() @() $bad.count
    $case = Invoke-FreezeCase
    Assert-True ("producer: " + $bad.name + " fails closed before anything is published") (
        $case.code -ceq "bound_key_invalid" -and @($script:ProducerCalls | Where-Object { $_ -like "wiring:*" }).Count -eq 0)
}

# Target-A's snapshot refused the bound.
$fixture = New-ProducerFixture -PrePublished @((New-LiveRecord 1001 1))
$script:FakeSnapshot = New-FakeFreezeSnapshot @("1001:1") @() @("view_mismatch", "host_or_channel_mismatch")
$case = Invoke-FreezeCase
Assert-True "producer: a refused snapshot publishes nothing and names Target-A's own failure codes" (
    $case.code -ceq "freeze_snapshot_rejected" -and
    (@((Get-FailureRecord).snapshot_failures) -join ",") -ceq "view_mismatch,host_or_channel_mismatch" -and
    ($script:ProducerCalls -join ",") -ceq "target:freeze_snapshot")
Assert-Throws "  ... and the runner reports them" {
    Test-R1FreezeFailure -Request $fixture.request -RequestSha256 (Get-R1FileSha256 -Path $script:freezeRequestPath) `
        -Failure (Get-FailureRecord)
} "*freeze_snapshot_rejected (view_mismatch, host_or_channel_mismatch)"

# Delivery and the freeze tool.
$fixture = New-ProducerFixture -PrePublished @((New-LiveRecord 1001 1))
$script:FakeSnapshot = New-FakeFreezeSnapshot @("1001:1", "1004:3") @((New-LiveRecord 1004 3))
$script:WiringFails = "consume"
$case = Invoke-FreezeCase
Assert-True "producer: a delivery to Role3 that fails stops the freeze before the freeze tool" (
    $case.code -ceq "delivery_failed" -and @($script:ProducerCalls | Where-Object { $_ -like "freeze:*" }).Count -eq 0)
$fixture = New-ProducerFixture -PrePublished @((New-LiveRecord 1001 1))
$script:FakeSnapshot = New-FakeFreezeSnapshot @("1001:1")
$script:FreezeToolFails = $true
$case = Invoke-FreezeCase
Assert-True "producer: a freeze tool that refuses is a failure with its own code" (
    $case.code -ceq "freeze_tool_failed" -and (Get-FailureRecord).reason_code -ceq "freeze_tool_failed")

# The request.
$fixture = New-ProducerFixture -PrePublished @((New-LiveRecord 1001 1)) -RequestHost "TARGET-B"
$script:FakeSnapshot = New-FakeFreezeSnapshot @("1001:1")
$case = Invoke-FreezeCase
Assert-True "producer: a request of another host is refused before Target-A is asked" (
    $case.code -ceq "request_binding_mismatch" -and $script:ProducerCalls.Count -eq 0)
$fixture = New-ProducerFixture -NoRequest
[System.IO.File]::WriteAllText($script:freezeRequestPath, "{not json")
$case = Invoke-FreezeCase
Assert-True "producer: an unreadable request is its own failure, with no request binding" (
    $case.code -ceq "request_unreadable" -and $script:ProducerCalls.Count -eq 0 -and
    -not [string]::IsNullOrEmpty((Get-FailureRecord).request_sha256))

# Stable reason codes.
foreach ($message in @("boom", "[not_a_code] boom", "[live_bound_mismatch boom")) {
    $fixture = New-ProducerFixture
    Assert-True ("producer: the message '" + $message + "' is reported as unexpected_error") (
        (Write-PositionFreezeFailure $message) -ceq "unexpected_error" -and (Get-FailureRecord).reason_code -ceq "unexpected_error")
}

# The binding the runner checks before its first action.
$fixture = New-ProducerFixture
$contract = [ordered]@{ schema = "r1-required-partitions"; contract_version = "v0.1"; target_host = $HOST_A
    required_partitions = @([ordered]@{ source = "sysmon"; source_channel = $CHANNEL }) }
[System.IO.File]::WriteAllText($script:RequiredPartitionContract, ($contract | ConvertTo-Json -Depth 4))
Write-PositionProducerBinding
$bindingBytes = [System.IO.File]::ReadAllBytes($script:producerBindingPath)
Write-PositionProducerBinding
$binding = Get-Content -LiteralPath $script:producerBindingPath -Raw -Encoding UTF8 | ConvertFrom-Json
$bindingPaths = Get-R1PositionPaths -ControlDir $fixture.control
Assert-True "producer: the binding names the Run, host, partition and the contract by digest, the same on a restart" (
    $binding.schema -ceq $R1_PRODUCER_BINDING_SCHEMA -and $binding.run_id -ceq $RUN_ID -and $binding.host_id -ceq $HOST_A -and
    $binding.partition.source_channel -ceq $CHANNEL -and
    $binding.required_partition_contract.sha256 -ceq (Get-R1FileSha256 -Path $script:RequiredPartitionContract) -and
    [Convert]::ToBase64String($bindingBytes) -ceq [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($script:producerBindingPath)))
Assert-R1PositionPreflight -Paths $bindingPaths -RunId $RUN_ID -TargetHost $HOST_A -Channel $CHANNEL -ExpectedContextStartUtc $CONTEXT_START -Scenario $null
Assert-True "preflight: the runner accepts the binding of its own producer" $true
$bindingMismatch = (New-Object System.Text.UTF8Encoding($false)).GetString($bindingBytes) | ConvertFrom-Json
$bindingMismatch.context_start_utc = Get-UtcStamp ((ConvertFrom-R1UtcStamp $CONTEXT_START "test context start").AddSeconds(1))
[System.IO.File]::WriteAllText($script:producerBindingPath, ($bindingMismatch | ConvertTo-Json -Depth 4))
Assert-Throws "preflight: a producer context start after Target-A boot is refused" {
    Assert-R1PositionPreflight -Paths $bindingPaths -RunId $RUN_ID -TargetHost $HOST_A -Channel $CHANNEL `
        -ExpectedContextStartUtc $CONTEXT_START -Scenario $null
} "*producer context start*does not match the Target-A boot UTC*"
[System.IO.File]::WriteAllBytes($script:producerBindingPath, $bindingBytes)
$bindingInvalid = (New-Object System.Text.UTF8Encoding($false)).GetString($bindingBytes) | ConvertFrom-Json
$bindingInvalid.context_start_utc = "not-a-utc-stamp"
[System.IO.File]::WriteAllText($script:producerBindingPath, ($bindingInvalid | ConvertTo-Json -Depth 4))
Assert-Throws "preflight: a malformed producer context start is refused" {
    Assert-R1PositionPreflight -Paths $bindingPaths -RunId $RUN_ID -TargetHost $HOST_A -Channel $CHANNEL `
        -ExpectedContextStartUtc $CONTEXT_START -Scenario $null
} "*producer binding context_start_utc is not a UTC millisecond stamp*"
[System.IO.File]::WriteAllBytes($script:producerBindingPath, $bindingBytes)
$bindingMissing = (New-Object System.Text.UTF8Encoding($false)).GetString($bindingBytes) | ConvertFrom-Json
$bindingMissing.PSObject.Properties.Remove("context_start_utc")
[System.IO.File]::WriteAllText($script:producerBindingPath, ($bindingMissing | ConvertTo-Json -Depth 4))
Assert-Throws "preflight: a missing producer context start is refused" {
    Assert-R1PositionPreflight -Paths $bindingPaths -RunId $RUN_ID -TargetHost $HOST_A -Channel $CHANNEL `
        -ExpectedContextStartUtc $CONTEXT_START -Scenario $null
} "*producer binding context_start_utc is not a UTC millisecond stamp*"
[System.IO.File]::WriteAllBytes($script:producerBindingPath, $bindingBytes)
Assert-Throws "preflight: a runner on another host refuses the binding" {
    Assert-R1PositionPreflight -Paths $bindingPaths -RunId $RUN_ID -TargetHost "TARGET-B" -Channel $CHANNEL -ExpectedContextStartUtc $CONTEXT_START -Scenario $null
} "*collects another Run, host or partition*"
Assert-Throws "preflight: a runner of another Run refuses the binding" {
    Assert-R1PositionPreflight -Paths $bindingPaths -RunId "RUN-20300101-902" -TargetHost $HOST_A -Channel $CHANNEL -ExpectedContextStartUtc $CONTEXT_START -Scenario $null
} "*collects another Run, host or partition*"
Assert-Throws "preflight: a scenario that states another host is refused" {
    Assert-R1PositionPreflight -Paths $bindingPaths -RunId $RUN_ID -TargetHost $HOST_A -Channel $CHANNEL -ExpectedContextStartUtc $CONTEXT_START `
        -Scenario ([pscustomobject]@{ run_metadata = [pscustomobject]@{ target_host = "TARGET-B" } })
} "*scenario states the target host TARGET-B*"
$contract.target_host = "TARGET-B"
[System.IO.File]::WriteAllText($script:RequiredPartitionContract, ($contract | ConvertTo-Json -Depth 4))
Assert-Throws "preflight: a contract changed after the producer started is refused" {
    Assert-R1PositionPreflight -Paths $bindingPaths -RunId $RUN_ID -TargetHost $HOST_A -Channel $CHANNEL -ExpectedContextStartUtc $CONTEXT_START -Scenario $null
} "*not the one the producer was started with*"
$fixture = New-ProducerFixture
[System.IO.File]::WriteAllText($script:RequiredPartitionContract, ($contract | ConvertTo-Json -Depth 4))
Assert-Throws "producer: a contract of another host is refused at start" { Write-PositionProducerBinding } "*not a v0.1 contract of this TargetHost*"
$contract.target_host = $HOST_A
$contract.required_partitions = @(
    [ordered]@{ source = "sysmon"; source_channel = $CHANNEL },
    [ordered]@{ source = "security"; source_channel = "Security" })
[System.IO.File]::WriteAllText($script:RequiredPartitionContract, ($contract | ConvertTo-Json -Depth 4))
Assert-Throws "producer: a contract with another partition is refused at start" { Write-PositionProducerBinding } "*exactly the Sysmon partition*"
$noBinding = Get-R1PositionPaths -ControlDir (New-TempRoot)
Assert-Throws "preflight: a run without a producer binding does not start" {
    Assert-R1PositionPreflight -Paths $noBinding -RunId $RUN_ID -TargetHost $HOST_A -Channel $CHANNEL -ExpectedContextStartUtc $CONTEXT_START -Scenario $null
} "*no producer binding*"

Remove-Item -LiteralPath function:Invoke-Command, function:Invoke-Wiring, function:Invoke-FreezeTool

 # --- 2b. the producer script ----------------------------------------------------------------

$producerPath = Join-Path $PSScriptRoot "..\r1-incremental-sysmon-producer.ps1"
$producerText = Get-Content -LiteralPath $producerPath -Raw
$producerCommonText = Get-Content -LiteralPath (Join-Path $PSScriptRoot "..\r1-incremental-sysmon-producer-common.ps1") -Raw
Assert-True "producer: the freeze publishes no watermark, no close and no stream control message" (
    ($producerText + $producerCommonText) -notmatch '"publish-watermark"|"publish-close"|issue-position-close|"watermark_at"' -and
    $producerText -match 'Invoke-PositionFreeze \$session' -and $producerText -match 'Write-PositionFreezeFailure')

$producerRoot = New-TempRoot
$secure = ConvertTo-SecureString "not-used" -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential("not-used", $secure)
$producerArguments = @{
    RunId = $RUN_ID; TargetHost = $HOST_A; TargetAddress = "192.0.2.1"; WinRmPort = 5985; Credential = $credential
    ContextStartUtc = $CONTEXT_START; SpoolRoot = (Join-Path $producerRoot "spool")
    ControlRoot = (Join-Path $producerRoot "control"); RequiredPartitionContract = (Join-Path $producerRoot "contract.json")
    PollIntervalSec = 1; ChunkMaxEvents = 10; AllowedLatenessMs = 2000; PositionFinality = $true
}
Assert-Throws "producer: position finality without consuming is refused before anything starts" {
    & $producerPath @producerArguments -NoConsume
} "*NoConsume cannot be used*"
$producerControl = Join-Path (Join-Path $producerRoot "control") $RUN_ID
New-Item -ItemType Directory -Path $producerControl -Force | Out-Null
[System.IO.File]::WriteAllText((Join-Path $producerControl $R1_FREEZE_FAILURE_FILE), "{}")
Assert-Throws "producer: a failed freeze is not resumed and no session is opened" {
    & $producerPath @producerArguments
} "*failed collection freeze cannot be resumed*"
Remove-Item -LiteralPath (Join-Path $producerControl $R1_FREEZE_FAILURE_FILE) -Force
[System.IO.File]::WriteAllText((Join-Path $producerControl $R1_FREEZE_GENERATION_FILE), "{}")
Assert-Throws "producer: an interrupted freeze is not resumed and no session is opened" {
    & $producerPath @producerArguments
} "*interrupted collection freeze*"
Remove-Item -LiteralPath (Join-Path $producerControl $R1_FREEZE_GENERATION_FILE) -Force
[System.IO.File]::WriteAllText((Join-Path $producerControl $R1_RUN_FINALIZED_FILE), "{}")
Assert-Throws "producer: run-finalized without its freeze ack is refused" {
    & $producerPath @producerArguments
} "*run-finalized exists without*"

 # --- 3. the runner's request and the producer's ack -------------------------------------

$t0 = [datetime]::new(2030, 1, 1, 0, 0, 0, [System.DateTimeKind]::Utc)
$request = New-R1FreezeRequest -RunId $RUN_ID -TargetHost $HOST_A -Channel $CHANNEL `
    -CandidateBoundaryAt $t0.AddSeconds(720) -ObservationBoundaryAt $t0.AddSeconds(780) -RequestedAt $t0.AddSeconds(781)
Assert-True "request: it carries the partition and the two boundaries, and no watermark" (
    $request.schema -ceq "r1-sysmon-collection-freeze-request" -and $request.request_id -ceq ($RUN_ID + "-freeze-0001") -and
    $request.partition.host_id -ceq $HOST_A -and $request.partition.source_channel -ceq $CHANNEL -and
    $request.candidate_boundary_at -ceq "2030-01-01T00:12:00.000Z" -and
    $request.observation_boundary_at -ceq "2030-01-01T00:13:00.000Z" -and
    (@($request.Keys) -join ",") -ceq "schema,contract_version,request_id,partition,candidate_boundary_at,observation_boundary_at,requested_at")
Assert-Throws "request: a candidate boundary after the observation boundary is refused" {
    New-R1FreezeRequest -RunId $RUN_ID -TargetHost $HOST_A -Channel $CHANNEL -CandidateBoundaryAt $t0.AddSeconds(790) `
        -ObservationBoundaryAt $t0.AddSeconds(780) -RequestedAt $t0.AddSeconds(800)
} "*later than the observation boundary*"
Assert-Throws "request: a request before the observation boundary is refused" {
    New-R1FreezeRequest -RunId $RUN_ID -TargetHost $HOST_A -Channel $CHANNEL -CandidateBoundaryAt $t0.AddSeconds(720) `
        -ObservationBoundaryAt $t0.AddSeconds(780) -RequestedAt $t0.AddSeconds(779)
} "*before the observation boundary*"

Assert-True "stamps: the forms the Python tools write are read as the same instant" (
    (Get-UtcStamp (ConvertFrom-R1UtcStamp "2030-01-01T00:13:05.905000Z" "t")) -ceq "2030-01-01T00:13:05.905Z" -and
    (Get-UtcStamp (ConvertFrom-R1UtcStamp "2030-01-01T00:13:05Z" "t")) -ceq "2030-01-01T00:13:05.000Z" -and
    (ConvertFrom-R1UtcStamp "2030-01-01T00:13:05.905Z" "t").Kind -eq [System.DateTimeKind]::Utc)
foreach ($stamp in @("2030-01-01T00:13:05.905001Z", "2030-01-01T09:13:05.905+09:00", "2030-01-01 00:13:05.905Z", "")) {
    Assert-Throws ("stamps: '" + $stamp + "' is not read as a UTC millisecond stamp") {
        ConvertFrom-R1UtcStamp $stamp "t"
    } "*not a UTC millisecond stamp*"
}

$IDENTITY = "a" * 64
function New-AckJson {
    param([hashtable]$Set = @{}, [hashtable]$Partition = @{})
    $ackPartition = [ordered]@{ run_id = $RUN_ID; host_id = $HOST_A; source = "sysmon"; source_channel = $CHANNEL }
    foreach ($key in $Partition.Keys) { $ackPartition[$key] = $Partition[$key] }
    $ack = [ordered]@{
        schema = "r1-sysmon-collection-freeze-ack"; contract_version = "v0.1"; request_id = ($RUN_ID + "-freeze-0001")
        partition = $ackPartition; source_lower_record_id = 1001; source_upper_record_id = 1006
        target_event_ids = @(1, 3); target_event_count = 4; target_identity_sha256 = $IDENTITY
        covered_through_chunk_sequence = 2; allowed_lateness_ms = 2000; raw_segment_inventory_sha256 = ("b" * 64)
        acked_at = "2030-01-01T00:13:05.000Z"
    }
    foreach ($key in $Set.Keys) { $ack[$key] = $Set[$key] }
    return (($ack | ConvertTo-Json -Depth 8) | ConvertFrom-Json)
}
function New-GenerationJson {
    param([hashtable]$Set = @{})
    $generation = [ordered]@{
        schema = "r1-sysmon-channel-generation-observation"; contract_version = "v0.1"; phase = "freeze_ack"
        request_id = ($RUN_ID + "-freeze-0001")
        partition = [ordered]@{ run_id = $RUN_ID; host_id = $HOST_A; source = "sysmon"; source_channel = $CHANNEL }
        source_lower_record_id = 1001; source_upper_record_id = 1006
        lower_anchor_raw_xml_sha256 = ("1" * 64); upper_anchor_raw_xml_sha256 = ("2" * 64)
        oldest_record_number = 900; log_creation_time_utc = $CREATED; observed_at = "2030-01-01T00:13:03.000Z"
    }
    foreach ($key in $Set.Keys) { $generation[$key] = $Set[$key] }
    return (($generation | ConvertTo-Json -Depth 8) | ConvertFrom-Json)
}

$frozen = Test-R1FreezeAck -Request $request -Ack (New-AckJson) -Generation (New-GenerationJson)
Assert-True "ack: a matching ack and generation give the bound and the producer's digest" (
    $frozen.lower -eq 1001 -and $frozen.upper -eq 1006 -and $frozen.target_event_count -eq 4 -and
    $frozen.target_identity_sha256 -ceq $IDENTITY -and $frozen.log_creation_time_utc -ceq $CREATED)
$pythonForm = Test-R1FreezeAck -Request $request -Ack (New-AckJson -Set @{ acked_at = "2030-01-01T00:13:05Z" }) `
    -Generation (New-GenerationJson -Set @{ observed_at = "2030-01-01T00:13:03.000000Z"; log_creation_time_utc = "2029-12-31T23:50:00Z" })
Assert-True "ack: an ack and generation in the datetime form of the Python tool are accepted" (
    $pythonForm.acked_at -eq $t0.AddSeconds(785) -and $pythonForm.log_creation_time_utc -ceq $CREATED)
foreach ($case in @(
        @{ name = "for another request"; ack = @{ request_id = "RUN-20300101-901-freeze-0002" }; like = "*another request*" },
        @{ name = "for another host"; partition = @{ host_id = "TARGET-B" }; like = "*another request, Run, host*" },
        @{ name = "for another channel"; partition = @{ source_channel = "Security" }; like = "*another request, Run, host*" },
        @{ name = "for another Run"; partition = @{ run_id = "RUN-20300101-902" }; like = "*another request, Run, host*" },
        @{ name = "with a reversed bound"; ack = @{ source_lower_record_id = 1007 }; like = "*1 <= lower <= upper*" },
        @{ name = "with other Event IDs"; ack = @{ target_event_ids = @(1) }; like = "*exactly Sysmon EID 1 and 3*" },
        @{ name = "with no Event"; ack = @{ target_event_count = 0 }; like = "*covers no Event*" },
        @{ name = "with a digest that is not a SHA-256"; ack = @{ target_identity_sha256 = "A" * 64 }; like = "*not a SHA-256*" },
        @{ name = "before the request"; ack = @{ acked_at = "2030-01-01T00:13:00.500Z" }; like = "*precedes its request*" },
        @{ name = "with a generation of the export phase"; generation = @{ phase = "after_canonical_export" }; like = "*freeze_ack channel generation*" },
        @{ name = "with a generation of another bound"; generation = @{ source_upper_record_id = 1005 }; like = "*another request, host or RecordId bound*" },
        @{ name = "with a generation that lost the lower record"; generation = @{ oldest_record_number = 1002 }; like = "*no longer retains*" },
        @{ name = "with a generation observed after the ack"; generation = @{ observed_at = "2030-01-01T00:13:06.000Z" }; like = "*between the request and the ack*" })) {
    $ackSet = @{}; if ($case.ContainsKey("ack")) { $ackSet = $case.ack }
    $partitionSet = @{}; if ($case.ContainsKey("partition")) { $partitionSet = $case.partition }
    $generationSet = @{}; if ($case.ContainsKey("generation")) { $generationSet = $case.generation }
    Assert-Throws ("ack: an ack " + $case.name + " fails closed") {
        Test-R1FreezeAck -Request $request -Ack (New-AckJson -Set $ackSet -Partition $partitionSet) `
            -Generation (New-GenerationJson -Set $generationSet)
    } $case.like
}

$waitRoot = New-TempRoot
$waitPaths = Get-R1PositionPaths -ControlDir $waitRoot
Write-R1PositionJson -Path $waitPaths.request -Value $request | Out-Null
$requestSha256 = Get-R1FileSha256 -Path $waitPaths.request
$script:WaitNow = $t0.AddSeconds(781)
$waitClock = { $script:WaitNow }
$plainSleeper = { param($Seconds) $script:WaitNow = $script:WaitNow.AddSeconds($Seconds) }
Assert-Throws "wait: no ack and no failure within the timeout fails the run" {
    Wait-R1FreezeAck -Paths $waitPaths -Request $request -RequestSha256 $requestSha256 -TimeoutSec 30 `
        -NowProvider $waitClock -Sleeper $plainSleeper
} "*no collection freeze ack within 30 s*"
[System.IO.File]::WriteAllText($waitPaths.ack, ((New-AckJson) | ConvertTo-Json -Depth 8))
Assert-Throws "wait: an ack without its generation fails the run" {
    Wait-R1FreezeAck -Paths $waitPaths -Request $request -RequestSha256 $requestSha256 -TimeoutSec 30 `
        -NowProvider $waitClock -Sleeper $plainSleeper
} "*without its freeze generation*"
Remove-Item -LiteralPath $waitPaths.ack -Force
$script:WaitNow = $t0.AddSeconds(781)
$script:Sleeps = 0
$producingSleeper = {
    param($Seconds)
    $script:WaitNow = $script:WaitNow.AddSeconds($Seconds)
    $script:Sleeps++
    if ($script:Sleeps -eq 3) {
        [System.IO.File]::WriteAllText($waitPaths.freeze_generation, ((New-GenerationJson) | ConvertTo-Json -Depth 8))
        [System.IO.File]::WriteAllText($waitPaths.ack, ((New-AckJson) | ConvertTo-Json -Depth 8))
    }
}
$waited = Wait-R1FreezeAck -Paths $waitPaths -Request $request -RequestSha256 $requestSha256 -TimeoutSec 60 `
    -NowProvider $waitClock -Sleeper $producingSleeper
Assert-True "wait: the run goes on once the producer's ack and generation arrive" (
    $waited.upper -eq 1006 -and $script:Sleeps -eq 3)

function New-FailureJson {
    param([hashtable]$Set = @{}, [hashtable]$Partition = @{})
    $failurePartition = [ordered]@{ run_id = $RUN_ID; host_id = $HOST_A; source = "sysmon"; source_channel = $CHANNEL }
    foreach ($key in $Partition.Keys) { $failurePartition[$key] = $Partition[$key] }
    $failure = [ordered]@{
        schema = $R1_FREEZE_FAILURE_SCHEMA; contract_version = "v0.1"; run_id = $RUN_ID; host_id = $HOST_A
        request_id = ($RUN_ID + "-freeze-0001"); request_sha256 = $requestSha256; partition = $failurePartition
        failed_at = "2030-01-01T00:13:04.000Z"; reason_code = "live_bound_mismatch"; snapshot_failures = @()
    }
    foreach ($key in $Set.Keys) { $failure[$key] = $Set[$key] }
    return ($failure | ConvertTo-Json -Depth 6)
}

function New-WaitDirectory {
    $paths = Get-R1PositionPaths -ControlDir (New-TempRoot)
    Write-R1PositionJson -Path $paths.request -Value $request | Out-Null
    return $paths
}

# A failure that appears while the run waits ends the wait at once.
$failPaths = New-WaitDirectory
$script:WaitNow = $t0.AddSeconds(781)
$script:Sleeps = 0
$failingSleeper = {
    param($Seconds)
    $script:WaitNow = $script:WaitNow.AddSeconds($Seconds)
    $script:Sleeps++
    if ($script:Sleeps -eq 2) { [System.IO.File]::WriteAllText($failPaths.freeze_failure, (New-FailureJson)) }
}
Assert-Throws "wait: the producer's failure ends the wait with its reason code" {
    Wait-R1FreezeAck -Paths $failPaths -Request $request -RequestSha256 $requestSha256 -TimeoutSec 900 `
        -NowProvider $waitClock -Sleeper $failingSleeper
} "*collection freeze failure: live_bound_mismatch"
Assert-True "  ... after two polls, not after the 900 s timeout" ($script:Sleeps -eq 2)

foreach ($case in @(
        @{ name = "of another Run"; set = @{ run_id = "RUN-20300101-902" } },
        @{ name = "of another host"; set = @{ host_id = "TARGET-B" } },
        @{ name = "of another request"; set = @{ request_id = ($RUN_ID + "-freeze-0002") } },
        @{ name = "of an earlier request of this Run"; set = @{ request_sha256 = ("e" * 64) } },
        @{ name = "of another partition"; partition = @{ source_channel = "Security" } },
        @{ name = "of another schema"; set = @{ schema = "r1-sysmon-collection-freeze-ack" } })) {
    $otherPaths = New-WaitDirectory
    $set = @{}; if ($case.ContainsKey("set")) { $set = $case.set }
    $partitionSet = @{}; if ($case.ContainsKey("partition")) { $partitionSet = $case.partition }
    [System.IO.File]::WriteAllText($otherPaths.freeze_failure, (New-FailureJson -Set $set -Partition $partitionSet))
    Assert-Throws ("wait: a failure " + $case.name + " is not consumed and the run stops") {
        Wait-R1FreezeAck -Paths $otherPaths -Request $request -RequestSha256 $requestSha256 -TimeoutSec 900 `
            -NowProvider $waitClock -Sleeper $plainSleeper
    } "*a collection freeze failure of another Run, request, host or partition*"
}
$unknownPaths = New-WaitDirectory
[System.IO.File]::WriteAllText($unknownPaths.freeze_failure, (New-FailureJson -Set @{ reason_code = "made_up" }))
Assert-Throws "wait: a failure with an unknown reason code still stops the run" {
    Wait-R1FreezeAck -Paths $unknownPaths -Request $request -RequestSha256 $requestSha256 -TimeoutSec 900 `
        -NowProvider $waitClock -Sleeper $plainSleeper
} "*unknown reason code 'made_up'*"
$bothPaths = New-WaitDirectory
[System.IO.File]::WriteAllText($bothPaths.freeze_generation, ((New-GenerationJson) | ConvertTo-Json -Depth 8))
[System.IO.File]::WriteAllText($bothPaths.ack, ((New-AckJson) | ConvertTo-Json -Depth 8))
[System.IO.File]::WriteAllText($bothPaths.freeze_failure, (New-FailureJson))
Assert-Throws "wait: an ack next to a failure fails the run" {
    Wait-R1FreezeAck -Paths $bothPaths -Request $request -RequestSha256 $requestSha256 -TimeoutSec 900 `
        -NowProvider $waitClock -Sleeper $plainSleeper
} "*both a collection freeze ack and a collection freeze failure*"
$stalePaths = Get-R1PositionPaths -ControlDir (New-TempRoot)
[System.IO.File]::WriteAllText($stalePaths.freeze_failure, (New-FailureJson))
Assert-Throws "wait: a failure left from an earlier attempt keeps the run from starting" {
    Assert-R1PositionControlFree -Paths $stalePaths
} "*position-finality artifact of this run already exists*"

 # --- 3b. the candidate boundary attestation -----------------------------------------------

$runEndResult = [ordered]@{
    completed_utc = "2030-01-01T00:12:00.000Z"
    ended         = @(
        @{ process_id = 4100; image = "cmd.exe"; outcome = "stopped" },
        @{ process_id = 4200; image = "powershell.exe"; outcome = "already_exited" })
}
$lineageRecords = @(
    [ordered]@{ role = "final_tool"; process_guid = "{00000000-0000-0000-0000-000000004200}"
        image = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" },
    [ordered]@{ role = "intermediate"; process_guid = "{00000000-0000-0000-0000-000000004100}"
        image = "C:\Windows\System32\cmd.exe" },
    [ordered]@{ role = "root"; process_guid = "{00000000-0000-0000-0000-000000000900}"
        image = "C:\Windows\System32\wbem\WmiPrvSE.exe" })
$boundaryAction = [pscustomobject]@{ action_id = "A04"; offset_sec = 720; step = "run_end"; action_type = "run_end"
    description = "synthetic" }
$attestationArguments = @{
    BoundaryAction = $boundaryAction; CompletedUtc = "2030-01-01T00:12:00.000Z"
    RequestCandidateBoundaryAt = $request.candidate_boundary_at; RunEnd = $runEndResult
    IntermediatePid = 4100; FinalPid = 4200; LineageRecords = $lineageRecords
}
$attestation = New-R1BoundaryAttestation @attestationArguments
Assert-True "attestation: it holds exactly the fields of R1CandidateBoundaryAttestation" (
    (@($attestation.Keys) -join ",") -ceq "action_id,step,action_type,completed_at,no_actions_after_boundary,owned_processes" -and
    (@($attestation.owned_processes[0].Keys) -join ",") -ceq "role,image,process_guid,terminal_state")
Assert-True "attestation: the final scenario action, the run_end completion and both Run-owned processes" (
    $attestation.action_id -ceq "A04" -and $attestation.completed_at -ceq "2030-01-01T00:12:00.000Z" -and
    $attestation.no_actions_after_boundary -eq $true -and
    $attestation.owned_processes[0].role -ceq "intermediate" -and $attestation.owned_processes[0].image -ceq "cmd.exe" -and
    $attestation.owned_processes[0].process_guid -ceq "{00000000-0000-0000-0000-000000004100}" -and
    $attestation.owned_processes[0].terminal_state -ceq "stopped" -and
    $attestation.owned_processes[1].role -ceq "final_tool" -and $attestation.owned_processes[1].image -ceq "powershell.exe" -and
    $attestation.owned_processes[1].terminal_state -ceq "already_exited")
foreach ($case in @(
        @{ name = "a completion that is not the freeze request boundary"; set = @{ CompletedUtc = "2030-01-01T00:12:01.000Z" }
           like = "*not the candidate boundary of the freeze request*" },
        @{ name = "a final action that is not run_end"; set = @{ BoundaryAction = [pscustomobject]@{
                action_id = "A03"; step = "connect"; action_type = "network_connection" } }; like = "*not the run_end boundary*" },
        @{ name = "a run_end result without the final tool"; set = @{ FinalPid = 4300 }; like = "*does not account once for the final_tool*" },
        @{ name = "an owned process that is still running"; set = @{ RunEnd = [ordered]@{ ended = @(
                @{ process_id = 4100; outcome = "stopped" }, @{ process_id = 4200; outcome = "running" }) } }
           like = "*not an accepted terminal state*" },
        @{ name = "a lineage without the intermediate"; set = @{ LineageRecords = @($lineageRecords[0]) }
           like = "*no single intermediate with a ProcessGuid*" })) {
    $arguments = $attestationArguments.Clone()
    foreach ($key in $case.set.Keys) { $arguments[$key] = $case.set[$key] }
    Assert-Throws ("attestation: " + $case.name + " is not attested") { New-R1BoundaryAttestation @arguments } $case.like
}
$attestationPath = Join-Path (New-TempRoot) "candidate-boundary-attestation.json"
Write-R1PositionJsonOnce -Path $attestationPath -Value $attestation | Out-Null
$attestationBytes = [System.IO.File]::ReadAllBytes($attestationPath)
Write-R1PositionJsonOnce -Path $attestationPath -Value $attestation | Out-Null
Assert-True "attestation: writing the same attestation again keeps the bytes" (
    [Convert]::ToBase64String($attestationBytes) -ceq [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($attestationPath)))
$otherAttestation = New-R1BoundaryAttestation @attestationArguments
$otherAttestation.owned_processes[0].terminal_state = "exited_by_itself"
Assert-Throws "attestation: another attestation at the same path fails closed" {
    Write-R1PositionJsonOnce -Path $attestationPath -Value $otherAttestation
} "*immutable control artifact conflict*"
Assert-True "  ... and the first attestation is kept" (
    [Convert]::ToBase64String($attestationBytes) -ceq [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($attestationPath)))

 # --- 4. the RecordId-bounded export and the snapshot ------------------------------------

$exportRoot = New-TempRoot
$script:ExportQuery = $null
$exportSeams = @{
    Export           = {
        param($LogName, $Query, $Path)
        $script:ExportQuery = $Query
        [System.IO.File]::WriteAllText($Path, "synthetic record-bounded evtx")
    }
    ReadExported     = { param($Path) @($boundEvents) }
    QueryRecord      = { param($LogName, $RecordId) @($channelEvents | Where-Object { $_.RecordId -eq $RecordId }) }
    ReadChannelState = { param($LogName) @{ oldest_record_number = 950; log_creation_time_utc = $CREATED } }
}
$stepArguments = @{ log_name = $CHANNEL; lower = 1001; upper = 1006; expected_host = $HOST_A
    export_path = (Join-Path $exportRoot "r1_sysmon_record_bounded.evtx") }
$exportAnswer = & $R1_RECORD_BOUNDED_EXPORT_STEP $stepArguments $exportSeams.Export $exportSeams.ReadExported `
    $exportSeams.QueryRecord $exportSeams.ReadChannelState
Assert-True "export: the XPath is the closed RecordId bound of EID 1/3, never a time window" (
    $script:ExportQuery -ceq "*[System[(EventID=1 or EventID=3) and EventRecordID >= 1001 and EventRecordID <= 1006]]" -and
    $script:ExportQuery -notmatch "timediff|TimeCreated")
Assert-True "export: the export digest is the digest the producer's freeze snapshot gives for the same records" (
    $exportAnswer.identity_sha256 -ceq $snapshot.target_identity_sha256 -and $exportAnswer.event_count -eq 4 -and
    (@($exportAnswer.record_keys) -join ",") -ceq (@($snapshot.bound_keys) -join ","))
Assert-True "export: the two bound records are read again from the channel after the export" (
    $exportAnswer.lower_anchor_raw_xml_sha256 -ceq $snapshot.lower_anchor_raw_xml_sha256 -and
    $exportAnswer.upper_anchor_raw_xml_sha256 -ceq $snapshot.upper_anchor_raw_xml_sha256 -and
    $exportAnswer.host_channel_bound -and
    $exportAnswer.evtx_sha256 -ceq (Get-FileHash -LiteralPath $stepArguments.export_path -Algorithm SHA256).Hash.ToLower())
Assert-Throws "export: a reversed bound is refused before anything is exported" {
    & $R1_RECORD_BOUNDED_EXPORT_STEP @{ log_name = $CHANNEL; lower = 1006; upper = 1001; expected_host = $HOST_A
        export_path = $stepArguments.export_path } $exportSeams.Export
} "*1 <= lower <= upper*"
$foreignExport = & $R1_RECORD_BOUNDED_EXPORT_STEP $stepArguments $exportSeams.Export `
    { param($Path) @($boundEvents) + @(New-FakeEvent 1005 1 6 -MachineName "TARGET-B") } `
    $exportSeams.QueryRecord $exportSeams.ReadChannelState
Assert-True "export: a record of another host is reported" (-not $foreignExport.host_channel_bound)

$freezeFrozen = Test-R1FreezeAck -Request $request `
    -Ack (New-AckJson -Set @{ target_identity_sha256 = $snapshot.target_identity_sha256 }) `
    -Generation (New-GenerationJson -Set @{
        lower_anchor_raw_xml_sha256 = $snapshot.lower_anchor_raw_xml_sha256
        upper_anchor_raw_xml_sha256 = $snapshot.upper_anchor_raw_xml_sha256 })
Test-R1RecordBoundedExport -Export $exportAnswer -Frozen $freezeFrozen
Assert-True "export: an export of the acked record set and generation passes" $true
foreach ($case in @(
        @{ name = "with one Event fewer"; set = @{ event_count = 3 }; like = "*canonical export drift*" },
        @{ name = "with another identity digest"; set = @{ identity_sha256 = ("c" * 64) }; like = "*canonical export drift*" },
        @{ name = "with a record of another host"; set = @{ host_channel_bound = $false }; like = "*another host or channel*" },
        @{ name = "after the upper record changed"; set = @{ upper_anchor_raw_xml_sha256 = ("3" * 64) }; like = "*generation changed*bound record*" },
        @{ name = "after the lower record disappeared"; set = @{ lower_anchor_raw_xml_sha256 = $null }; like = "*generation changed*bound record*" },
        @{ name = "after the channel was recreated"; set = @{ log_creation_time_utc = "2030-01-01T00:13:10.000Z" }; like = "*log recreated*" },
        @{ name = "after the oldest record moved backwards"; set = @{ oldest_record_number = 800 }; like = "*moved backwards*" },
        @{ name = "after the lower record left the channel"; set = @{ oldest_record_number = 1002 }; like = "*no longer retains*" })) {
    $changed = @{}
    foreach ($key in $exportAnswer.Keys) { $changed[$key] = $exportAnswer[$key] }
    foreach ($key in $case.set.Keys) { $changed[$key] = $case.set[$key] }
    Assert-Throws ("export: an export " + $case.name + " fails closed") {
        Test-R1RecordBoundedExport -Export $changed -Frozen $freezeFrozen
    } $case.like
}

function New-SnapshotFixture {
    <# A control directory whose fetched EVTX is the exported file. #>
    $root = New-TempRoot
    $paths = Get-R1PositionPaths -ControlDir $root
    New-Item -ItemType Directory -Path $paths.telemetry_dir -Force | Out-Null
    Copy-Item -LiteralPath $stepArguments.export_path -Destination $paths.evtx
    return $paths
}
$writeJsonl = {
    param($EvtxPath, $JsonlPath)
    $lines = @($boundEvents | ForEach-Object {
            ([ordered]@{ RecordId = $_.RecordId; EventId = $_.Id; TimeCreated = "2030-01-01T00:00:00.000Z"
                Channel = $_.LogName; Computer = $_.MachineName; Provider = "Microsoft-Windows-Sysmon"
                EventData = @{ Image = "C:\Windows\System32\cmd.exe" } } | ConvertTo-Json -Compress) })
    [System.IO.File]::WriteAllLines($JsonlPath, [string[]]$lines, (New-Object System.Text.UTF8Encoding($false)))
    return $lines.Count
}
$script:SnapshotNow = $t0.AddSeconds(800)
$snapshotClock = { $script:SnapshotNow }
$completeArguments = @{ Request = $request; Frozen = $freezeFrozen; Export = $exportAnswer
    ExportObservedAt = $t0.AddSeconds(795); RunId = $RUN_ID; TargetHost = $HOST_A; Channel = $CHANNEL
    NowProvider = $snapshotClock }

$goodPaths = New-SnapshotFixture
$completed = Complete-R1PositionSnapshot -Paths $goodPaths -Convert $writeJsonl @completeArguments
$manifest = Get-Content -LiteralPath $goodPaths.manifest -Raw -Encoding UTF8 | ConvertFrom-Json
$exportGeneration = Get-Content -LiteralPath $goodPaths.export_generation -Raw -Encoding UTF8 | ConvertFrom-Json
Assert-True "snapshot: the manifest names one Sysmon EVTX and the JSONL derived from it, with their digests" (
    $manifest.run_id -ceq $RUN_ID -and @($manifest.items).Count -eq 2 -and
    (Split-Path -Leaf $manifest.items[0].path) -ceq "sysmon-0001.evtx" -and
    (Split-Path -Leaf $manifest.items[1].path) -ceq "sysmon-0001.jsonl" -and
    $manifest.items[1].derived_from -ceq $manifest.items[0].path -and
    $manifest.items[0].sha256 -ceq (Get-FileHash -LiteralPath $goodPaths.evtx -Algorithm SHA256).Hash.ToLower() -and
    $manifest.items[1].sha256 -ceq (Get-FileHash -LiteralPath $goodPaths.jsonl -Algorithm SHA256).Hash.ToLower())
Assert-True "snapshot: the export generation is observed after the ack with the freeze anchors" (
    $exportGeneration.phase -ceq "after_canonical_export" -and $exportGeneration.observed_at -ceq "2030-01-01T00:13:15.000Z" -and
    $exportGeneration.source_lower_record_id -eq 1001 -and $exportGeneration.source_upper_record_id -eq 1006 -and
    $exportGeneration.upper_anchor_raw_xml_sha256 -ceq $freezeFrozen.upper_anchor_raw_xml_sha256 -and
    $exportGeneration.oldest_record_number -eq 950 -and
    $completed.canonical_event_count -eq 4 -and $completed.canonical_identity_sha256 -ceq $snapshot.target_identity_sha256)

$driftPaths = New-SnapshotFixture
[System.IO.File]::AppendAllText($driftPaths.evtx, "x")
Assert-Throws "snapshot: a fetched EVTX that is not the exported file fails closed" {
    Complete-R1PositionSnapshot -Paths $driftPaths -Convert $writeJsonl @completeArguments
} "*fetched snapshot EVTX*"
Assert-True "  ... and neither the manifest nor the export generation is written" (
    -not (Test-Path -LiteralPath $driftPaths.manifest) -and -not (Test-Path -LiteralPath $driftPaths.export_generation))
foreach ($case in @(
        @{ name = "holds a record outside the bound"; change = { param($l) $l -replace '"RecordId":1005', '"RecordId":1007' }; like = "*outside the RecordId bound*" },
        @{ name = "misses a record of the export"; change = { param($l) $l | Where-Object { $_ -notmatch '"RecordId":1004' } }; like = "*canonical export drift*" },
        @{ name = "holds a record of another host"; change = { param($l) $l -replace ('"Computer":"' + $HOST_A + '"'), '"Computer":"TARGET-B"' }; like = "*another host or channel*" },
        @{ name = "holds a RecordId twice"; change = { param($l) @($l) + @($l[-1]) }; like = "*twice*" })) {
    $jsonlPaths = New-SnapshotFixture
    $change = $case.change
    $convert = {
        param($EvtxPath, $JsonlPath)
        & $writeJsonl $EvtxPath $JsonlPath | Out-Null
        $lines = @(& $change @(Get-Content -LiteralPath $JsonlPath))
        [System.IO.File]::WriteAllLines($JsonlPath, [string[]]$lines, (New-Object System.Text.UTF8Encoding($false)))
    }.GetNewClosure()
    Assert-Throws ("snapshot: a JSONL that " + $case.name + " fails closed") {
        Complete-R1PositionSnapshot -Paths $jsonlPaths -Convert $convert @completeArguments
    } $case.like
}
$earlyPaths = New-SnapshotFixture
$earlyArguments = $completeArguments.Clone()
$earlyArguments.ExportObservedAt = $t0.AddSeconds(784)
Assert-Throws "snapshot: an export generation before the freeze ack fails closed" {
    Complete-R1PositionSnapshot -Paths $earlyPaths -Convert $writeJsonl @earlyArguments
} "*cannot precede the freeze ack*"

$finalizedPath = Write-R1RunFinalized -Paths $goodPaths -Request $request -Frozen $freezeFrozen -Snapshot $completed `
    -FinalizedAt $t0.AddSeconds(810)
$finalizedRecord = Get-Content -LiteralPath $finalizedPath -Raw -Encoding UTF8 | ConvertFrom-Json
Assert-True "finalized: run-finalized binds the bound, the Event set and the three file digests" (
    $finalizedRecord.schema -ceq "r1-sysmon-run-finalized" -and $finalizedRecord.source_lower_record_id -eq 1001 -and
    $finalizedRecord.source_upper_record_id -eq 1006 -and (@($finalizedRecord.target_event_ids) -join ",") -ceq "1,3" -and
    $finalizedRecord.canonical_event_count -eq 4 -and
    $finalizedRecord.canonical_identity_sha256 -ceq $snapshot.target_identity_sha256 -and
    $finalizedRecord.canonical_evtx_sha256 -ceq (Get-FileHash -LiteralPath $goodPaths.evtx -Algorithm SHA256).Hash.ToLower() -and
    $finalizedRecord.canonical_jsonl_sha256 -ceq (Get-FileHash -LiteralPath $goodPaths.jsonl -Algorithm SHA256).Hash.ToLower() -and
    $finalizedRecord.manifest_sha256 -ceq (Get-FileHash -LiteralPath $goodPaths.manifest -Algorithm SHA256).Hash.ToLower() -and
    $finalizedRecord.finalized_at -ceq "2030-01-01T00:13:30.000Z")
Assert-Throws "finalized: run-finalized is written once" {
    Write-R1RunFinalized -Paths $goodPaths -Request $request -Frozen $freezeFrozen -Snapshot $completed -FinalizedAt $t0.AddSeconds(811)
} "*already exists*"

foreach ($case in @(
        @{ name = "EVTX"; file = "evtx" }, @{ name = "JSONL"; file = "jsonl" }, @{ name = "manifest"; file = "manifest" })) {
    $laterPaths = New-SnapshotFixture
    $laterSnapshot = Complete-R1PositionSnapshot -Paths $laterPaths -Convert $writeJsonl @completeArguments
    [System.IO.File]::AppendAllText($laterPaths[$case.file], " ")
    Assert-Throws ("finalized: a snapshot " + $case.name + " changed after the export fails closed") {
        Write-R1RunFinalized -Paths $laterPaths -Request $request -Frozen $freezeFrozen -Snapshot $laterSnapshot `
            -FinalizedAt $t0.AddSeconds(810)
    } ("*snapshot " + $case.name + " changed after the export*")
    Assert-True ("  ... and no run-finalized is written (" + $case.name + ")") (-not (Test-Path -LiteralPath $laterPaths.run_finalized))
}
$earlyFinalPaths = New-SnapshotFixture
$earlyFinalSnapshot = Complete-R1PositionSnapshot -Paths $earlyFinalPaths -Convert $writeJsonl @completeArguments
Assert-Throws "finalized: run-finalized before the export generation fails closed" {
    Write-R1RunFinalized -Paths $earlyFinalPaths -Request $request -Frozen $freezeFrozen -Snapshot $earlyFinalSnapshot `
        -FinalizedAt $t0.AddSeconds(790)
} "*cannot precede the export generation*"

 # --- 5. no event-time finality --------------------------------------------------------

$moduleText = Get-Content -LiteralPath (Join-Path $PSScriptRoot "..\r1-position-finality-common.ps1") -Raw
$runnerText = Get-Content -LiteralPath (Join-Path $PSScriptRoot "..\run-common.ps1") -Raw
Assert-True "no file of this path writes a watermark, a run_closed or an event-time frontier" (
    $moduleText -notmatch 'watermark_at' -and $moduleText -notmatch 'message_type\s*=' -and
    $moduleText -notmatch '"r1-incremental-stream"' -and $moduleText -notmatch 'run_closed"' -and
    $runnerText -notmatch '"(source_watermark|run_closed)"')
Assert-True "the time-window export of the Run is kept and the snapshot is exported next to it" (
    $runnerText -match 'TimeCreated\[timediff\(@SystemTime\) <= \$windowMs\]' -and
    $runnerText.IndexOf('$session "export_record_bounded"') -gt $runnerText.IndexOf('& $Transport.invoke $session "export" @{'))
Assert-True "the export step is registered as a remote step of the runner" (
    $R1_REMOTE_STEPS.ContainsKey("export_record_bounded") -and
    [object]::ReferenceEquals($R1_REMOTE_STEPS["export_record_bounded"], $R1_RECORD_BOUNDED_EXPORT_STEP))

Write-Host ""
if ($script:Failures -eq 0) {
    foreach ($path in $script:TempRoots) {
        if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Recurse -Force }
    }
    Write-Host "ALL $($script:Total) CHECKS PASSED" -ForegroundColor Green
    exit 0
}
Write-Host "$($script:Failures) of $($script:Total) CHECKS FAILED" -ForegroundColor Red
Write-Host ("temporary output kept for inspection under " + [System.IO.Path]::GetTempPath() + "r1-position-*")
exit 1
