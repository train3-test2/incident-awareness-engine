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

 # --- 2. the producer script ------------------------------------------------------------

$producerPath = Join-Path $PSScriptRoot "..\r1-incremental-sysmon-producer.ps1"
$producerText = Get-Content -LiteralPath $producerPath -Raw
$freezeBody = $producerText.Substring($producerText.IndexOf("function Invoke-PositionFreeze"))
$freezeBody = $freezeBody.Substring(0, $freezeBody.IndexOf("`$runControlDir = "))
Assert-True "producer: the ack is written only after delivery to Role3 and the comparison with the bound" (
    $freezeBody.IndexOf('Invoke-Wiring @("consume"') -gt 0 -and
    $freezeBody.IndexOf('Invoke-Wiring @("consume"') -lt $freezeBody.IndexOf('the published live records are not exactly') -and
    $freezeBody.IndexOf('the published live records are not exactly') -lt $freezeBody.IndexOf('"write-generation-observation"') -and
    $freezeBody.IndexOf('"write-generation-observation"') -lt $freezeBody.IndexOf('"write-freeze-ack"'))
Assert-True "producer: the freeze publishes no watermark, no close and no stream control message" (
    $producerText -notmatch '"publish-watermark"' -and $producerText -notmatch '"publish-close"' -and
    $producerText -notmatch 'issue-position-close' -and $freezeBody -notmatch 'watermark')

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
$script:WaitNow = $t0.AddSeconds(781)
$waitClock = { $script:WaitNow }
$plainSleeper = { param($Seconds) $script:WaitNow = $script:WaitNow.AddSeconds($Seconds) }
Assert-Throws "wait: no ack within the timeout fails the run" {
    Wait-R1FreezeAck -Paths $waitPaths -Request $request -TimeoutSec 30 -NowProvider $waitClock -Sleeper $plainSleeper
} "*no collection freeze ack within 30 s*"
[System.IO.File]::WriteAllText($waitPaths.ack, ((New-AckJson) | ConvertTo-Json -Depth 8))
Assert-Throws "wait: an ack without its generation fails the run" {
    Wait-R1FreezeAck -Paths $waitPaths -Request $request -TimeoutSec 30 -NowProvider $waitClock -Sleeper $plainSleeper
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
$waited = Wait-R1FreezeAck -Paths $waitPaths -Request $request -TimeoutSec 60 -NowProvider $waitClock -Sleeper $producingSleeper
Assert-True "wait: the run goes on once the producer's ack and generation arrive" (
    $waited.upper -eq 1006 -and $script:Sleeps -eq 3)

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
