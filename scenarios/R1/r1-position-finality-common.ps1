<#
    Runner side of the R1 Sysmon RecordId position-finality path.

    Contracts: docs/schema/r1-sysmon-record-bounded-finality-v0.md (v0.1 snapshot
    artifacts) and docs/schema/r1-sysmon-record-position-finality-v0.md. The
    runner owns three of the snapshot artifacts, all under
    <IncrementalStreamControlRoot>/<run_id>/:

        collection-freeze-requested.json   after the observation boundary
        canonical-export-generation.json   after the RecordId-bounded export
        position-finality/candidate-boundary-attestation.json
                                           the A04 run_end result, as R1CandidateBoundaryAttestation
        run-finalized.json                 after the Run and the snapshot are complete

    It reads two files of the producer in the same directory:

        collection-producer-binding.json   before the first action: the producer's
                                           Run, host, partition and contract
        collection-freeze-failed.json      while it waits for the ack: a freeze the
                                           producer gave up, with a stable reason code

    The canonical snapshot itself is a separate export of the closed RecordId
    bound of the producer's freeze ack, under position-finality/ in the same
    directory. The time-window export of the Run is not changed, is not used in
    place of the snapshot and the snapshot is not used in place of it.

    None of these files is a source watermark or run_closed.
    observation_boundary_at is the observation boundary of the run, not an
    event-time frontier. Nothing here claims Sysmon provider queue drain,
    raw-source completeness outside the bound or TTSD/online eligibility.

    Every check fails closed: a function throws, the run fails and run-finalized
    is not written.

    NOTE: this file is intentionally ASCII only, like the rest of scenarios/R1.
#>

$R1_POSITION_CONTRACT_VERSION = "v0.1"
$R1_POSITION_SOURCE = "sysmon"
$R1_POSITION_TARGET_EVENT_IDS = @(1, 3)
$R1_FREEZE_REQUEST_FILE = "collection-freeze-requested.json"
$R1_FREEZE_ACK_FILE = "collection-freeze-ack.json"
$R1_FREEZE_GENERATION_FILE = "collection-freeze-generation.json"
$R1_EXPORT_GENERATION_FILE = "canonical-export-generation.json"
$R1_RUN_FINALIZED_FILE = "run-finalized.json"
$R1_FREEZE_FAILURE_FILE = "collection-freeze-failed.json"
$R1_PRODUCER_BINDING_FILE = "collection-producer-binding.json"
$R1_BOUNDARY_ATTESTATION_FILE = "candidate-boundary-attestation.json"
$R1_FREEZE_FAILURE_SCHEMA = "r1-sysmon-collection-freeze-failure"
$R1_PRODUCER_BINDING_SCHEMA = "r1-sysmon-collection-producer-binding"
$R1_FREEZE_FAILURE_CODES = @(
    "request_unreadable", "request_binding_mismatch", "live_key_invalid", "live_segment_missing",
    "freeze_snapshot_rejected", "bound_key_invalid", "delivery_failed", "segment_chunk_mismatch",
    "live_bound_mismatch", "freeze_tool_failed", "unexpected_error")
$R1_ACCEPTED_TERMINAL_STATES = @("stopped", "exited_by_itself", "already_exited")
$R1_POSITION_SNAPSHOT_DIR = "position-finality"
$R1_POSITION_EXPORT_FILE = "r1_sysmon_record_bounded.evtx"
$R1_POSITION_ACK_POLL_SEC = 5
$R1_SHA256_PATTERN = '^[0-9a-f]{64}$'
# UTC with at most millisecond precision. The Python tools write the same instant
# as ".fff000Z", or without a fraction when it is zero.
$R1_UTC_MS_PATTERN = '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3}(000)?)?Z$'
$R1_UTC_MS_FORMATS = [string[]]@("yyyy-MM-dd'T'HH:mm:ss'Z'", "yyyy-MM-dd'T'HH:mm:ss.fff'Z'",
    "yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'")

function Get-R1PositionPaths {
    <# Where the snapshot artifacts of one run live. #>
    param([Parameter(Mandatory = $true)][string]$ControlDir)

    $snapshotDir = Join-Path $ControlDir $R1_POSITION_SNAPSHOT_DIR
    $telemetry = Join-Path $snapshotDir "telemetry"
    return [ordered]@{
        control_dir       = $ControlDir
        request           = (Join-Path $ControlDir $R1_FREEZE_REQUEST_FILE)
        ack               = (Join-Path $ControlDir $R1_FREEZE_ACK_FILE)
        freeze_generation = (Join-Path $ControlDir $R1_FREEZE_GENERATION_FILE)
        export_generation = (Join-Path $ControlDir $R1_EXPORT_GENERATION_FILE)
        run_finalized     = (Join-Path $ControlDir $R1_RUN_FINALIZED_FILE)
        freeze_failure    = (Join-Path $ControlDir $R1_FREEZE_FAILURE_FILE)
        producer_binding  = (Join-Path $ControlDir $R1_PRODUCER_BINDING_FILE)
        snapshot_dir      = $snapshotDir
        boundary_attestation = (Join-Path $snapshotDir $R1_BOUNDARY_ATTESTATION_FILE)
        telemetry_dir     = $telemetry
        evtx              = (Join-Path $telemetry "sysmon-0001.evtx")
        jsonl             = (Join-Path $telemetry "sysmon-0001.jsonl")
        manifest          = (Join-Path $snapshotDir "manifest.json")
    }
}

function Assert-R1PositionControlFree {
    <# A run starts no freeze while any snapshot artifact of its run_id exists. #>
    param([Parameter(Mandatory = $true)]$Paths)

    foreach ($name in @("request", "ack", "freeze_generation", "export_generation", "run_finalized",
            "freeze_failure", "snapshot_dir")) {
        if (Test-Path -LiteralPath $Paths[$name]) {
            throw ("a position-finality artifact of this run already exists: " + $Paths[$name])
        }
    }
}

function Get-R1FileSha256 {
    <# Lowercase SHA-256 of a file named by its literal path. #>
    param([Parameter(Mandatory = $true)][string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Write-R1PositionJsonOnce {
    <# Write a control artifact once; the same bytes again are accepted, other bytes fail. #>
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)]$Value)

    $bytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes((($Value | ConvertTo-Json -Depth 8 -Compress) + "`n"))
    if (Test-Path -LiteralPath $Path) {
        $existing = [System.IO.File]::ReadAllBytes($Path)
        if ([Convert]::ToBase64String($existing) -ceq [Convert]::ToBase64String($bytes)) {
            return $Path
        }
        throw ("immutable control artifact conflict: " + $Path)
    }
    Write-R1AtomicNewFile -Path $Path -Bytes $bytes
    return $Path
}

function Assert-R1PositionPreflight {
    <#
        Before the first action: the producer of this Run is running for the
        same Run, host and Sysmon partition, against a required-partition
        contract of this host. A missing or different binding fails the run
        before anything starts on Target-A.
    #>
    param(
        [Parameter(Mandatory = $true)]$Paths,
        [Parameter(Mandatory = $true)][string]$RunId,
        [Parameter(Mandatory = $true)][string]$TargetHost,
        [Parameter(Mandatory = $true)][string]$Channel,
        [Parameter(Mandatory = $true)]$ExpectedContextStartUtc,
        [AllowNull()]$Scenario
    )

    if (-not (Test-Path -LiteralPath $Paths.producer_binding -PathType Leaf)) {
        throw ("no producer binding at " + $Paths.producer_binding +
            ": start r1-incremental-sysmon-producer.ps1 -PositionFinality for this Run before the runner")
    }
    $binding = Read-R1PositionJson $Paths.producer_binding
    $expected = New-R1PositionPartition -RunId $RunId -TargetHost $TargetHost -Channel $Channel
    if ([string](Get-R1Value $binding "schema") -cne $R1_PRODUCER_BINDING_SCHEMA -or
        [string](Get-R1Value $binding "contract_version") -cne $R1_POSITION_CONTRACT_VERSION) {
        throw "the producer binding is not an r1-sysmon-collection-producer-binding v0.1"
    }
    if ([string](Get-R1Value $binding "run_id") -cne $RunId -or [string](Get-R1Value $binding "host_id") -cne $TargetHost -or
        -not (Test-R1SamePartition (Get-R1Value $binding "partition") $expected)) {
        throw ("the producer collects another Run, host or partition than this run (" + $RunId + " on " +
            $TargetHost + ")")
    }
    $bindingContextStart = ConvertFrom-R1UtcStamp (Get-R1Value $binding "context_start_utc") `
        "producer binding context_start_utc"
    $expectedContextStart = ConvertFrom-R1UtcStamp $ExpectedContextStartUtc "Target-A boot UTC"
    if ($bindingContextStart -ne $expectedContextStart) {
        throw ("the producer context start " + (Get-UtcStamp $bindingContextStart) +
            " does not match the Target-A boot UTC " + (Get-UtcStamp $expectedContextStart))
    }
    $contractBinding = Get-R1Value $binding "required_partition_contract"
    $contractPath = [string](Get-R1Value $contractBinding "path")
    if ([string]::IsNullOrEmpty($contractPath) -or -not (Test-Path -LiteralPath $contractPath -PathType Leaf)) {
        throw "the producer binding names no readable required-partition contract"
    }
    if ((Get-R1FileSha256 -Path $contractPath) -cne [string](Get-R1Value $contractBinding "sha256") -or
        [string](Get-R1Value $contractBinding "target_host") -cne $TargetHost) {
        throw "the required-partition contract is not the one the producer was started with"
    }
    $contract = Read-R1PositionJson $contractPath
    $parts = @(Get-R1Value $contract "required_partitions")
    if ([string](Get-R1Value $contract "schema") -cne "r1-required-partitions" -or
        [string](Get-R1Value $contract "contract_version") -cne $R1_POSITION_CONTRACT_VERSION -or
        [string](Get-R1Value $contract "target_host") -cne $TargetHost -or $parts.Count -ne 1 -or
        [string](Get-R1Value $parts[0] "source") -cne $R1_POSITION_SOURCE -or
        [string](Get-R1Value $parts[0] "source_channel") -cne $Channel) {
        throw ("the required-partition contract does not bind exactly the Sysmon partition of " + $TargetHost)
    }
    $statedHost = Get-R1Value (Get-R1Value $Scenario "run_metadata") "target_host"
    if (-not [string]::IsNullOrEmpty([string]$statedHost) -and [string]$statedHost -cne $TargetHost) {
        throw ("the scenario states the target host " + [string]$statedHost + ", not " + $TargetHost)
    }
}

function Test-R1FreezeFailure {
    <#
        A collection-freeze-failed.json found while the run waits. Bound to this
        request it stops the run with the producer's reason code; bound to any
        other Run, request, host or partition it is not consumed and the run
        fails closed on the inconsistent control directory. Either way it throws.
    #>
    param(
        [Parameter(Mandatory = $true)]$Request,
        [Parameter(Mandatory = $true)][string]$RequestSha256,
        [Parameter(Mandatory = $true)]$Failure
    )

    $partition = $Request.partition
    $bound = (
        [string](Get-R1Value $Failure "schema") -ceq $R1_FREEZE_FAILURE_SCHEMA -and
        [string](Get-R1Value $Failure "contract_version") -ceq $R1_POSITION_CONTRACT_VERSION -and
        [string](Get-R1Value $Failure "run_id") -ceq [string]$partition.run_id -and
        [string](Get-R1Value $Failure "host_id") -ceq [string]$partition.host_id -and
        [string](Get-R1Value $Failure "request_id") -ceq [string]$Request.request_id -and
        [string](Get-R1Value $Failure "request_sha256") -ceq $RequestSha256 -and
        (Test-R1SamePartition (Get-R1Value $Failure "partition") $partition))
    if (-not $bound) {
        throw ("a collection freeze failure of another Run, request, host or partition is in the control " +
            "directory; it is not this run's failure and the run stops")
    }
    $code = [string](Get-R1Value $Failure "reason_code")
    if ($R1_FREEZE_FAILURE_CODES -cnotcontains $code) {
        throw ("the producer reported a collection freeze failure with an unknown reason code '" + $code + "'")
    }
    $details = @(Get-R1Value $Failure "snapshot_failures" | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_ })
    $suffix = ""
    if ($details.Count -gt 0) { $suffix = " (" + ($details -join ", ") + ")" }
    throw ("the producer reported a collection freeze failure: " + $code + $suffix)
}

function ConvertFrom-R1UtcStamp {
    <# A UTC millisecond stamp of a snapshot artifact as a UTC datetime; anything else throws. #>
    param([AllowNull()]$Value, [Parameter(Mandatory = $true)][string]$Name)

    if ($Value -is [datetime]) { $Value = Get-UtcStamp $Value }
    if (-not ([string]$Value -cmatch $R1_UTC_MS_PATTERN)) {
        throw ($Name + " is not a UTC millisecond stamp: " + [string]$Value)
    }
    return [datetime]::ParseExact([string]$Value, $R1_UTC_MS_FORMATS,
        [System.Globalization.CultureInfo]::InvariantCulture,
        ([System.Globalization.DateTimeStyles]::AssumeUniversal -bor
            [System.Globalization.DateTimeStyles]::AdjustToUniversal))
}

function Read-R1PositionJson {
    <# Read one control artifact; a missing or unreadable file throws. #>
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw ("missing control artifact: " + $Path) }
    try {
        return (Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json)
    } catch {
        throw ("control artifact is not valid JSON: " + $Path)
    }
}

function Write-R1PositionJson {
    <# Publish one control artifact once; an existing path throws. #>
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)]$Value)

    $utf8 = New-Object System.Text.UTF8Encoding($false)
    $text = ($Value | ConvertTo-Json -Depth 8 -Compress) + "`n"
    Write-R1AtomicNewFile -Path $Path -Bytes $utf8.GetBytes($text)
    return $Path
}

function New-R1PositionPartition {
    param(
        [Parameter(Mandatory = $true)][string]$RunId,
        [Parameter(Mandatory = $true)][string]$TargetHost,
        [Parameter(Mandatory = $true)][string]$Channel
    )
    return [ordered]@{
        run_id         = $RunId
        host_id        = $TargetHost
        source         = $R1_POSITION_SOURCE
        source_channel = $Channel
    }
}

function Test-R1SamePartition {
    param($Actual, $Expected)
    if ($null -eq $Actual) { return $false }
    $names = @($Actual.PSObject.Properties.Name | Sort-Object)
    if (($names -join ",") -cne "host_id,run_id,source,source_channel") { return $false }
    foreach ($name in @("run_id", "host_id", "source", "source_channel")) {
        if ([string]$Actual.$name -cne [string]$Expected[$name]) { return $false }
    }
    return $true
}

function Read-R1CandidateBoundary {
    <# The A04 completion the runner itself wrote to candidate-boundary-completed.json. #>
    param(
        [Parameter(Mandatory = $true)][string]$ControlDir,
        [Parameter(Mandatory = $true)][string]$RunId,
        [Parameter(Mandatory = $true)][string]$TargetHost
    )

    $control = Read-R1PositionJson -Path (Join-Path $ControlDir "candidate-boundary-completed.json")
    if ([string]$control.message_type -cne "candidate_boundary_completed" -or
        [string]$control.run_id -cne $RunId -or [string]$control.target_host -cne $TargetHost) {
        throw "candidate-boundary-completed.json is not the boundary of this run and host"
    }
    return (ConvertFrom-R1UtcStamp $control.candidate_boundary_at "candidate_boundary_at")
}

function New-R1FreezeRequest {
    <#
        The freeze request of one run. candidate_boundary_at <= observation_boundary_at
        <= requested_at, or nothing is written. observation_boundary_at is the
        observation boundary and is never written as a watermark.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$RunId,
        [Parameter(Mandatory = $true)][string]$TargetHost,
        [Parameter(Mandatory = $true)][string]$Channel,
        [Parameter(Mandatory = $true)][datetime]$CandidateBoundaryAt,
        [Parameter(Mandatory = $true)][datetime]$ObservationBoundaryAt,
        [Parameter(Mandatory = $true)][datetime]$RequestedAt
    )

    $candidate = ConvertFrom-R1UtcStamp (Get-UtcStamp $CandidateBoundaryAt) "candidate_boundary_at"
    $observation = ConvertFrom-R1UtcStamp (Get-UtcStamp $ObservationBoundaryAt) "observation_boundary_at"
    $requested = ConvertFrom-R1UtcStamp (Get-UtcStamp $RequestedAt) "requested_at"
    if ($observation -lt $candidate) {
        throw ("the candidate boundary " + (Get-UtcStamp $candidate) + " is later than the observation boundary " +
            (Get-UtcStamp $observation))
    }
    if ($requested -lt $observation) {
        throw ("a freeze cannot be requested at " + (Get-UtcStamp $requested) + ", before the observation boundary " +
            (Get-UtcStamp $observation))
    }
    return [ordered]@{
        schema                  = "r1-sysmon-collection-freeze-request"
        contract_version        = $R1_POSITION_CONTRACT_VERSION
        request_id              = ($RunId + "-freeze-0001")
        partition               = (New-R1PositionPartition -RunId $RunId -TargetHost $TargetHost -Channel $Channel)
        candidate_boundary_at   = (Get-UtcStamp $candidate)
        observation_boundary_at = (Get-UtcStamp $observation)
        requested_at            = (Get-UtcStamp $requested)
    }
}

function Test-R1FreezeAck {
    <#
        The producer's freeze ack and freeze generation, checked against the
        request before the runner exports anything. Python checks them again,
        strictly, before a position close. Returns the bound and its digests.
    #>
    param(
        [Parameter(Mandatory = $true)]$Request,
        [Parameter(Mandatory = $true)]$Ack,
        [Parameter(Mandatory = $true)]$Generation
    )

    $requestedAt = ConvertFrom-R1UtcStamp $Request.requested_at "requested_at"
    if ([string]$Ack.schema -cne "r1-sysmon-collection-freeze-ack" -or
        [string]$Ack.contract_version -cne $R1_POSITION_CONTRACT_VERSION) {
        throw "the freeze ack is not an r1-sysmon-collection-freeze-ack v0.1"
    }
    if ([string]$Ack.request_id -cne [string]$Request.request_id -or
        -not (Test-R1SamePartition $Ack.partition $Request.partition)) {
        throw "the freeze ack is bound to another request, Run, host or channel"
    }
    $lower = [long]$Ack.source_lower_record_id
    $upper = [long]$Ack.source_upper_record_id
    if ($lower -lt 1 -or $lower -gt $upper) { throw "the freeze ack RecordId bound is not 1 <= lower <= upper" }
    if ((@($Ack.target_event_ids) -join ",") -cne ($R1_POSITION_TARGET_EVENT_IDS -join ",")) {
        throw "the freeze ack does not bind exactly Sysmon EID 1 and 3"
    }
    if ([long]$Ack.target_event_count -lt 1 -or [long]$Ack.covered_through_chunk_sequence -lt 1) {
        throw "the freeze ack covers no Event or no chunk"
    }
    foreach ($name in @("target_identity_sha256", "raw_segment_inventory_sha256")) {
        if (-not ([string]$Ack.$name -cmatch $R1_SHA256_PATTERN)) { throw ("the freeze ack " + $name + " is not a SHA-256") }
    }
    $ackedAt = ConvertFrom-R1UtcStamp $Ack.acked_at "acked_at"
    if ($ackedAt -lt $requestedAt) { throw "the freeze ack precedes its request" }

    if ([string]$Generation.schema -cne "r1-sysmon-channel-generation-observation" -or
        [string]$Generation.contract_version -cne $R1_POSITION_CONTRACT_VERSION -or
        [string]$Generation.phase -cne "freeze_ack") {
        throw "the freeze generation is not a freeze_ack channel generation observation v0.1"
    }
    if ([string]$Generation.request_id -cne [string]$Request.request_id -or
        -not (Test-R1SamePartition $Generation.partition $Request.partition) -or
        [long]$Generation.source_lower_record_id -ne $lower -or [long]$Generation.source_upper_record_id -ne $upper) {
        throw "the freeze generation is bound to another request, host or RecordId bound"
    }
    foreach ($name in @("lower_anchor_raw_xml_sha256", "upper_anchor_raw_xml_sha256")) {
        if (-not ([string]$Generation.$name -cmatch $R1_SHA256_PATTERN)) {
            throw ("the freeze generation " + $name + " is not a SHA-256")
        }
    }
    if ([long]$Generation.oldest_record_number -lt 1 -or [long]$Generation.oldest_record_number -gt $lower) {
        throw "the freeze generation no longer retains the lower bound record"
    }
    $observedAt = ConvertFrom-R1UtcStamp $Generation.observed_at "freeze generation observed_at"
    if ($observedAt -lt $requestedAt -or $observedAt -gt $ackedAt) {
        throw "the freeze generation was not observed between the request and the ack"
    }

    return [ordered]@{
        request_id                  = [string]$Request.request_id
        lower                       = $lower
        upper                       = $upper
        target_event_count          = [long]$Ack.target_event_count
        target_identity_sha256      = [string]$Ack.target_identity_sha256
        acked_at                    = $ackedAt
        lower_anchor_raw_xml_sha256 = [string]$Generation.lower_anchor_raw_xml_sha256
        upper_anchor_raw_xml_sha256 = [string]$Generation.upper_anchor_raw_xml_sha256
        oldest_record_number        = [long]$Generation.oldest_record_number
        log_creation_time_utc       = (Get-UtcStamp (ConvertFrom-R1UtcStamp $Generation.log_creation_time_utc "log_creation_time_utc"))
    }
}

function Wait-R1FreezeAck {
    <#
        Wait on the injected clock for the producer's ack and freeze generation,
        and watch for the producer's failure at the same time. A failure ends
        the wait at once; an ack and a failure together, or an ack that does not
        match the request, fail the run. TimeoutSec applies only while neither
        file is there.
    #>
    param(
        [Parameter(Mandatory = $true)]$Paths,
        [Parameter(Mandatory = $true)]$Request,
        [Parameter(Mandatory = $true)][string]$RequestSha256,
        [Parameter(Mandatory = $true)][int]$TimeoutSec,
        [Parameter(Mandatory = $true)][scriptblock]$NowProvider,
        [Parameter(Mandatory = $true)][scriptblock]$Sleeper
    )

    if ($TimeoutSec -lt 1) { throw "the freeze ack timeout must be at least 1 s" }
    $deadline = (& $NowProvider).ToUniversalTime().AddSeconds($TimeoutSec)
    while ($true) {
        $hasAck = Test-Path -LiteralPath $Paths.ack
        $hasFailure = Test-Path -LiteralPath $Paths.freeze_failure
        if ($hasAck -and $hasFailure) {
            throw "the producer left both a collection freeze ack and a collection freeze failure"
        }
        if ($hasFailure) {
            Test-R1FreezeFailure -Request $Request -RequestSha256 $RequestSha256 `
                -Failure (Read-R1PositionJson $Paths.freeze_failure)
        }
        if ($hasAck) { break }
        if (Test-Path -LiteralPath (Join-Path $Paths.control_dir "run-aborted.json")) {
            throw "the run was aborted while it waited for the collection freeze ack"
        }
        if ((& $NowProvider).ToUniversalTime() -ge $deadline) {
            throw ("no collection freeze ack within " + $TimeoutSec + " s of the request")
        }
        Wait-R1Until -Due ((& $NowProvider).ToUniversalTime().AddSeconds($R1_POSITION_ACK_POLL_SEC)) `
            -NowProvider $NowProvider -Sleeper $Sleeper
    }
    if (-not (Test-Path -LiteralPath $Paths.freeze_generation)) {
        throw "the collection freeze ack exists without its freeze generation observation"
    }
    $frozen = Test-R1FreezeAck -Request $Request -Ack (Read-R1PositionJson $Paths.ack) `
        -Generation (Read-R1PositionJson $Paths.freeze_generation)
    if (Test-Path -LiteralPath $Paths.freeze_failure) {
        throw "the producer left both a collection freeze ack and a collection freeze failure"
    }
    return $frozen
}

function New-R1BoundaryAttestation {
    <#
        The A04 run_end result of a WMI run as R1CandidateBoundaryAttestation:
        the final action of the scenario, the completion the run_end step
        reported (the candidate boundary of the freeze request) and the two
        Run-owned processes it ended, by the ProcessGuid of the run's lineage.
        Only what that model holds is written. Built only after the run has
        succeeded; anything missing or unaccepted throws.
    #>
    param(
        [Parameter(Mandatory = $true)]$BoundaryAction,
        [Parameter(Mandatory = $true)][string]$CompletedUtc,
        [Parameter(Mandatory = $true)][string]$RequestCandidateBoundaryAt,
        [Parameter(Mandatory = $true)]$RunEnd,
        [Parameter(Mandatory = $true)][int]$IntermediatePid,
        [Parameter(Mandatory = $true)][int]$FinalPid,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$LineageRecords
    )

    $actionId = [string](Get-R1Value $BoundaryAction "action_id")
    $step = [string](Get-R1Value $BoundaryAction "step")
    $actionType = [string](Get-R1Value $BoundaryAction "action_type")
    if ([string]::IsNullOrEmpty($actionId) -or $step -cne "run_end" -or $actionType -cne "run_end") {
        throw "the final action of the scenario is not the run_end boundary of a run through WMI"
    }
    $completed = Get-UtcStamp (ConvertFrom-R1UtcStamp $CompletedUtc "run_end completed_utc")
    if ($completed -cne (Get-UtcStamp (ConvertFrom-R1UtcStamp $RequestCandidateBoundaryAt "candidate_boundary_at"))) {
        throw "the run_end completion is not the candidate boundary of the freeze request"
    }
    $ended = @(Get-R1Value $RunEnd "ended" | Where-Object { $null -ne $_ })
    $owned = New-Object System.Collections.Generic.List[object]
    foreach ($process in @(@{ role = "intermediate"; pid = $IntermediatePid }, @{ role = "final_tool"; pid = $FinalPid })) {
        $result = @($ended | Where-Object { [string](Get-R1Value $_ "process_id") -ceq [string]$process.pid })
        if ($result.Count -ne 1) {
            throw ("the run_end result does not account once for the " + $process.role + " (process id " + $process.pid + ")")
        }
        $state = [string](Get-R1Value $result[0] "outcome")
        if ($R1_ACCEPTED_TERMINAL_STATES -cnotcontains $state) {
            throw ("the " + $process.role + " ended with the outcome '" + $state + "', which is not an accepted terminal state")
        }
        $record = @($LineageRecords | Where-Object { [string](Get-R1Value $_ "role") -ceq $process.role })
        if ($record.Count -ne 1 -or [string]::IsNullOrEmpty([string](Get-R1Value $record[0] "process_guid"))) {
            throw ("the lineage of the run has no single " + $process.role + " with a ProcessGuid")
        }
        $owned.Add([ordered]@{
            role           = $process.role
            image          = [System.IO.Path]::GetFileName([string](Get-R1Value $record[0] "image"))
            process_guid   = [string](Get-R1Value $record[0] "process_guid")
            terminal_state = $state
        })
    }
    return [ordered]@{
        action_id                 = $actionId
        step                      = $step
        action_type               = $actionType
        completed_at              = $completed
        no_actions_after_boundary = $true
        owned_processes           = [object[]]$owned.ToArray()
    }
}

# The canonical export of the freeze ack's closed RecordId bound, run on
# Target-A by the transport. The XPath is the RecordId bound, never a time
# window. It reads the export back, takes the identity lines of every record
# (host, channel, RecordId, EventId, SHA-256 of raw XML plus LF - the lines the
# producer's freeze ack digest is made of) and then reads the two bound records
# and the channel state again, so that a clear, rollover or regenerated channel
# between the freeze and the export shows. The seams are for the guard tests;
# the transport passes only the arguments.
$R1_RECORD_BOUNDED_EXPORT_STEP = {
    param(
        $Arguments,
        [scriptblock]$Export = $null,
        [scriptblock]$ReadExported = $null,
        [scriptblock]$QueryRecord = $null,
        [scriptblock]$ReadChannelState = $null
    )
    Set-StrictMode -Version Latest
    $ErrorActionPreference = "Stop"

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
    if ($null -eq $Export) {
        $Export = {
            param($LogName, $Query, $Path)
            if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Force }
            & wevtutil epl $LogName $Path "/q:$Query" /ow:true | Out-Null
            if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $Path)) {
                throw ("wevtutil epl failed for " + $LogName)
            }
        }
    }
    if ($null -eq $ReadExported) {
        $ReadExported = {
            param($Path)
            try {
                @(Get-WinEvent -Path $Path -ErrorAction Stop | Sort-Object RecordId)
            } catch {
                if ($_.FullyQualifiedErrorId -like "NoMatchingEventsFound*") { return @() }
                throw
            }
        }
    }
    if ($null -eq $QueryRecord) {
        $QueryRecord = {
            param($LogName, $RecordId)
            try {
                @(Get-WinEvent -LogName $LogName -FilterXPath "*[System[EventRecordID=$RecordId]]" `
                    -MaxEvents 1 -ErrorAction Stop)
            } catch {
                if ($_.FullyQualifiedErrorId -like "NoMatchingEventsFound*") { return @() }
                throw
            }
        }
    }
    if ($null -eq $ReadChannelState) {
        $ReadChannelState = {
            param($LogName)
            $info = [System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.GetLogInformation(
                $LogName, [System.Diagnostics.Eventing.Reader.PathType]::LogName)
            $created = $null
            if ($null -ne $info.CreationTime) {
                $created = ([DateTime]$info.CreationTime).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
            }
            $oldest = $null
            if ($null -ne $info.OldestRecordNumber) { $oldest = [long]$info.OldestRecordNumber }
            @{ oldest_record_number = $oldest; log_creation_time_utc = $created }
        }
    }

    $lower = [long]$Arguments.lower
    $upper = [long]$Arguments.upper
    if ($lower -lt 1 -or $lower -gt $upper) { throw "the RecordId bound must satisfy 1 <= lower <= upper" }
    $logName = [string]$Arguments.log_name
    $query = "*[System[(EventID=1 or EventID=3) and EventRecordID >= $lower and EventRecordID <= $upper]]"
    & $Export $logName $query ([string]$Arguments.export_path)

    $exported = @(& $ReadExported ([string]$Arguments.export_path))
    $lines = @($exported | ForEach-Object {
        "{0}`t{1}`t{2}`t{3}`t{4}" -f [string]$_.MachineName, [string]$_.LogName, ([long]$_.RecordId),
            ([int]$_.Id), (& $sha256Text @([string]$_.ToXml()))
    })
    $hostChannelBound = $true
    foreach ($item in $exported) {
        if (-not ([string]$item.MachineName -ceq [string]$Arguments.expected_host) -or
            -not ([string]$item.LogName -ceq $logName)) {
            $hostChannelBound = $false
            break
        }
    }

    $anchors = @{}
    foreach ($bound in @(@{ name = "lower"; id = $lower }, @{ name = "upper"; id = $upper })) {
        $found = @(& $QueryRecord $logName $bound.id)
        $anchors[$bound.name] = $null
        if ($found.Count -eq 1) { $anchors[$bound.name] = (& $sha256Text @([string]$found[0].ToXml())) }
    }
    $state = & $ReadChannelState $logName
    $fileSha = (Get-FileHash -LiteralPath ([string]$Arguments.export_path) -Algorithm SHA256).Hash.ToLowerInvariant()

    return @{
        utc                         = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        evtx_path                   = [string]$Arguments.export_path
        evtx_sha256                 = $fileSha
        event_count                 = $lines.Count
        identity_sha256             = (& $sha256Text $lines)
        record_keys                 = @($exported | ForEach-Object { "{0}:{1}" -f ([long]$_.RecordId), ([int]$_.Id) })
        host_channel_bound          = $hostChannelBound
        lower_anchor_raw_xml_sha256 = $anchors["lower"]
        upper_anchor_raw_xml_sha256 = $anchors["upper"]
        oldest_record_number        = $state.oldest_record_number
        log_creation_time_utc       = $state.log_creation_time_utc
    }
}

function Test-R1RecordBoundedExport {
    <#
        The answer of the export step, against the freeze ack and freeze
        generation. A different Event set, a host or channel that is not the
        partition's, or a changed channel generation is canonical export drift.
    #>
    param(
        [Parameter(Mandatory = $true)]$Export,
        [Parameter(Mandatory = $true)]$Frozen
    )

    if (-not [bool]$Export.host_channel_bound) {
        throw "the RecordId-bounded export holds a record of another host or channel"
    }
    if ([long]$Export.event_count -ne [long]$Frozen.target_event_count -or
        [string]$Export.identity_sha256 -cne [string]$Frozen.target_identity_sha256) {
        throw ("canonical export drift: the export holds " + $Export.event_count + " Event(s) with identity " +
            $Export.identity_sha256 + ", the freeze ack " + $Frozen.target_event_count + " with " +
            $Frozen.target_identity_sha256)
    }
    if (-not ([string]$Export.evtx_sha256 -cmatch $R1_SHA256_PATTERN)) { throw "the export step returned no EVTX SHA-256" }
    if ([string]$Export.lower_anchor_raw_xml_sha256 -cne [string]$Frozen.lower_anchor_raw_xml_sha256 -or
        [string]$Export.upper_anchor_raw_xml_sha256 -cne [string]$Frozen.upper_anchor_raw_xml_sha256) {
        throw "the Sysmon channel generation changed between the freeze ack and the export (bound record changed)"
    }
    $created = Get-UtcStamp (ConvertFrom-R1UtcStamp $Export.log_creation_time_utc "export log_creation_time_utc")
    if ($created -cne [string]$Frozen.log_creation_time_utc) {
        throw "the Sysmon channel generation changed between the freeze ack and the export (log recreated)"
    }
    $oldest = $Export.oldest_record_number
    if ($null -eq $oldest -or [long]$oldest -lt [long]$Frozen.oldest_record_number -or [long]$oldest -gt [long]$Frozen.lower) {
        throw "the Sysmon channel no longer retains the bound, or its oldest record moved backwards"
    }
}

function Test-R1BoundedJsonl {
    <#
        The JSONL rendered from the fetched snapshot EVTX: every record is EID 1
        or 3 of the partition host and channel inside the bound, once, and in the
        order and number of the export.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$JsonlPath,
        [Parameter(Mandatory = $true)]$Frozen,
        [Parameter(Mandatory = $true)][string]$TargetHost,
        [Parameter(Mandatory = $true)][string]$Channel,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$ExpectedKeys
    )

    $keys = New-Object System.Collections.Generic.List[string]
    $seen = @{}
    foreach ($line in @(Get-Content -LiteralPath $JsonlPath -Encoding UTF8)) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $record = $line | ConvertFrom-Json
        $recordId = [long]$record.RecordId
        $eventId = [int]$record.EventId
        if (@($R1_POSITION_TARGET_EVENT_IDS) -notcontains $eventId) { throw "the snapshot JSONL holds a record that is not EID 1 or 3" }
        if ([string]$record.Computer -cne $TargetHost -or [string]$record.Channel -cne $Channel) {
            throw "the snapshot JSONL holds a record of another host or channel"
        }
        if ($recordId -lt [long]$Frozen.lower -or $recordId -gt [long]$Frozen.upper) {
            throw "the snapshot JSONL holds a record outside the RecordId bound"
        }
        if ($seen.ContainsKey($recordId)) { throw "the snapshot JSONL holds a RecordId twice" }
        $seen[$recordId] = $true
        $keys.Add(("{0}:{1}" -f $recordId, $eventId))
    }
    if (($keys.ToArray() -join ",") -cne ($ExpectedKeys -join ",")) {
        throw "canonical export drift: the snapshot JSONL is not the record set of the EVTX export"
    }
    return $keys.Count
}

function Write-R1PositionSnapshotManifest {
    <# The manifest of the snapshot: one Sysmon EVTX and the JSONL derived from it. #>
    param(
        [Parameter(Mandatory = $true)]$Paths,
        [Parameter(Mandatory = $true)][string]$RunId,
        [Parameter(Mandatory = $true)][datetime]$GeneratedAt
    )

    $evtxPath = (Resolve-Path -LiteralPath $Paths.evtx).Path
    $manifest = [ordered]@{
        run_id       = $RunId
        generated_at = (Get-UtcStamp $GeneratedAt)
        items        = @(
            [ordered]@{
                raw_log_id = "RAW-001"; path = $evtxPath; sha256 = (Get-R1FileSha256 -Path $Paths.evtx)
                layer = "raw_telemetry"; source = $R1_POSITION_SOURCE },
            [ordered]@{
                raw_log_id = "RAW-002"; path = (Resolve-Path -LiteralPath $Paths.jsonl).Path
                sha256 = (Get-R1FileSha256 -Path $Paths.jsonl); layer = "raw_telemetry"; source = $R1_POSITION_SOURCE
                derived_from = $evtxPath })
    }
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    Write-R1AtomicNewFile -Path $Paths.manifest -Bytes $utf8.GetBytes((($manifest | ConvertTo-Json -Depth 6) + "`n"))
    return $Paths.manifest
}

function Complete-R1PositionSnapshot {
    <#
        After the export step and the fetch: the fetched EVTX is the exported
        one, its JSONL is the export's record set, the manifest names both, and
        the channel generation is observed unchanged. Writes the manifest and
        canonical-export-generation.json and returns the digests run-finalized
        binds.
    #>
    param(
        [Parameter(Mandatory = $true)]$Paths,
        [Parameter(Mandatory = $true)]$Request,
        [Parameter(Mandatory = $true)]$Frozen,
        [Parameter(Mandatory = $true)]$Export,
        [Parameter(Mandatory = $true)][datetime]$ExportObservedAt,
        [Parameter(Mandatory = $true)][string]$RunId,
        [Parameter(Mandatory = $true)][string]$TargetHost,
        [Parameter(Mandatory = $true)][string]$Channel,
        [Parameter(Mandatory = $true)][scriptblock]$Convert,
        [Parameter(Mandatory = $true)][scriptblock]$NowProvider
    )

    Test-R1RecordBoundedExport -Export $Export -Frozen $Frozen
    if ((Get-R1FileSha256 -Path $Paths.evtx) -cne [string]$Export.evtx_sha256) {
        throw "canonical export drift: the fetched snapshot EVTX is not the file Target-A exported"
    }
    & $Convert $Paths.evtx $Paths.jsonl | Out-Null
    $count = Test-R1BoundedJsonl -JsonlPath $Paths.jsonl -Frozen $Frozen -TargetHost $TargetHost -Channel $Channel `
        -ExpectedKeys ([string[]]@($Export.record_keys))
    if ($count -ne [long]$Frozen.target_event_count) {
        throw "canonical export drift: the snapshot JSONL Event count differs from the freeze ack"
    }

    $observed = ConvertFrom-R1UtcStamp (Get-UtcStamp $ExportObservedAt) "export generation observed_at"
    if ($observed -lt $Frozen.acked_at) { throw "the export generation cannot precede the freeze ack" }
    Write-R1PositionSnapshotManifest -Paths $Paths -RunId $RunId -GeneratedAt (& $NowProvider) | Out-Null
    $generation = [ordered]@{
        schema                      = "r1-sysmon-channel-generation-observation"
        contract_version            = $R1_POSITION_CONTRACT_VERSION
        phase                       = "after_canonical_export"
        request_id                  = [string]$Request.request_id
        partition                   = $Request.partition
        source_lower_record_id      = [long]$Frozen.lower
        source_upper_record_id      = [long]$Frozen.upper
        lower_anchor_raw_xml_sha256 = [string]$Export.lower_anchor_raw_xml_sha256
        upper_anchor_raw_xml_sha256 = [string]$Export.upper_anchor_raw_xml_sha256
        oldest_record_number        = [long]$Export.oldest_record_number
        log_creation_time_utc       = [string]$Frozen.log_creation_time_utc
        observed_at                 = (Get-UtcStamp $observed)
    }
    Write-R1PositionJson -Path $Paths.export_generation -Value $generation | Out-Null

    return [ordered]@{
        canonical_event_count     = [long]$count
        canonical_identity_sha256 = [string]$Export.identity_sha256
        canonical_evtx_sha256     = (Get-R1FileSha256 -Path $Paths.evtx)
        canonical_jsonl_sha256    = (Get-R1FileSha256 -Path $Paths.jsonl)
        manifest_sha256           = (Get-R1FileSha256 -Path $Paths.manifest)
        export_observed_at        = $observed
    }
}

function Write-R1RunFinalized {
    <#
        run-finalized.json, written once the Run's own artifacts and the snapshot
        are complete. The snapshot files are hashed again first: a file that
        changed after the export generation is canonical export drift.
    #>
    param(
        [Parameter(Mandatory = $true)]$Paths,
        [Parameter(Mandatory = $true)]$Request,
        [Parameter(Mandatory = $true)]$Frozen,
        [Parameter(Mandatory = $true)]$Snapshot,
        [Parameter(Mandatory = $true)][datetime]$FinalizedAt
    )

    foreach ($pair in @(
            @{ path = $Paths.evtx; sha = $Snapshot.canonical_evtx_sha256; name = "EVTX" },
            @{ path = $Paths.jsonl; sha = $Snapshot.canonical_jsonl_sha256; name = "JSONL" },
            @{ path = $Paths.manifest; sha = $Snapshot.manifest_sha256; name = "manifest" })) {
        if (-not (Test-Path -LiteralPath $pair.path -PathType Leaf) -or (Get-R1FileSha256 -Path $pair.path) -cne [string]$pair.sha) {
            throw ("canonical export drift: the snapshot " + $pair.name + " changed after the export")
        }
    }
    if ([long]$Snapshot.canonical_event_count -ne [long]$Frozen.target_event_count -or
        [string]$Snapshot.canonical_identity_sha256 -cne [string]$Frozen.target_identity_sha256) {
        throw "the canonical snapshot and the freeze ack hold different Event sets"
    }
    $finalized = ConvertFrom-R1UtcStamp (Get-UtcStamp $FinalizedAt) "finalized_at"
    if ($finalized -lt $Snapshot.export_observed_at -or $finalized -lt $Frozen.acked_at) {
        throw "run-finalized cannot precede the export generation or the freeze ack"
    }
    $record = [ordered]@{
        schema                    = "r1-sysmon-run-finalized"
        contract_version          = $R1_POSITION_CONTRACT_VERSION
        request_id                = [string]$Request.request_id
        partition                 = $Request.partition
        source_lower_record_id    = [long]$Frozen.lower
        source_upper_record_id    = [long]$Frozen.upper
        target_event_ids          = @($R1_POSITION_TARGET_EVENT_IDS)
        canonical_event_count     = [long]$Snapshot.canonical_event_count
        canonical_identity_sha256 = [string]$Snapshot.canonical_identity_sha256
        canonical_evtx_sha256     = [string]$Snapshot.canonical_evtx_sha256
        canonical_jsonl_sha256    = [string]$Snapshot.canonical_jsonl_sha256
        manifest_sha256           = [string]$Snapshot.manifest_sha256
        finalized_at              = (Get-UtcStamp $finalized)
    }
    return (Write-R1PositionJson -Path $Paths.run_finalized -Value $record)
}
