<#
    Live WMI development Sysmon producer for the R1 v0.1 stream.

    Start this sidecar before Invoke-R1PilotRun.  It polls the live Sysmon
    channel through the same WinRM trust boundary, writes immutable raw JSONL
    segments, invokes the canonical Python normalizer/chunk publisher, and can
    immediately deliver the spool to Role3's PostgreSQL ledger. No approved
    Sysmon source-completeness proof exists, so this sidecar does not publish a
    source watermark or run_closed.

    -PositionFinality adds the producer side of the RecordId position-finality
    path (docs/schema/r1-sysmon-record-position-finality-v0.md). Once the runner
    writes <ControlRoot>/<RunId>/collection-freeze-requested.json, the sidecar
    fixes one all-channel upper RecordId on Target-A, publishes every EID 1/3 of
    the closed bound as chunks, delivers them to Role3 and checks their
    post-commit acks, and only then writes collection-freeze-generation.json and
    collection-freeze-ack.json through
    incident_awareness.pipeline.r1_record_bounded_freeze. Later polls publish only
    records above the bound (post-bound chunks), and the sidecar stops once the
    runner writes run-finalized.json. At start it writes
    collection-producer-binding.json (Run, host, partition, contract) for the
    runner's check before any action, and a freeze that fails leaves
    collection-freeze-failed.json with a stable reason code so the runner stops
    waiting at once. Neither file is a source watermark or
    run_closed, and neither claims Sysmon provider queue drain or completeness
    outside the bound.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$RunId,
    [Parameter(Mandatory = $true)][string]$TargetHost,
    [Parameter(Mandatory = $true)][string]$TargetAddress,
    [Parameter(Mandatory = $true)][int]$WinRmPort,
    [Parameter(Mandatory = $true)][System.Management.Automation.PSCredential]$Credential,
    [Parameter(Mandatory = $true)][string]$ContextStartUtc,
    [Parameter(Mandatory = $true)][string]$SpoolRoot,
    [Parameter(Mandatory = $true)][string]$ControlRoot,
    [Parameter(Mandatory = $true)][string]$RequiredPartitionContract,
    [Parameter(Mandatory = $true)][int]$PollIntervalSec,
    [Parameter(Mandatory = $true)][int]$ChunkMaxEvents,
    [Parameter(Mandatory = $true)][int]$AllowedLatenessMs,
    [switch]$UseSsl,
    [switch]$NoConsume,
    [switch]$PositionFinality
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
if ($PositionFinality -and $NoConsume) {
    throw "PositionFinality checks the post-commit acks this sidecar writes when it consumes; NoConsume cannot be used with it"
}
if ($PollIntervalSec -lt 1) { throw "PollIntervalSec must be at least 1" }
if ($ChunkMaxEvents -lt 1) { throw "ChunkMaxEvents must be at least 1" }
if ($AllowedLatenessMs -lt 0) { throw "AllowedLatenessMs must not be negative" }
$null = [DateTime]::Parse($ContextStartUtc).ToUniversalTime()

$runSpool = Join-Path $SpoolRoot $RunId
$rawRoot = Join-Path $runSpool "raw-segments"
$statePath = Join-Path $runSpool "producer-state.json"
New-Item -ItemType Directory -Path $rawRoot -Force | Out-Null
$utf8 = New-Object System.Text.UTF8Encoding($false)
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$env:PYTHONPATH = Join-Path $projectRoot "src"
. (Join-Path $PSScriptRoot "r1-incremental-sysmon-producer-common.ps1")

function Invoke-Wiring([string[]]$Arguments) {
    Push-Location $projectRoot
    try {
        & uv run python -m incident_awareness.pipeline.r1_stream_wiring @Arguments
    } finally {
        Pop-Location
    }
    if ($LASTEXITCODE -ne 0) { throw "r1_stream_wiring failed with exit code $LASTEXITCODE" }
}

function Invoke-FreezeTool([string[]]$Arguments) {
    Push-Location $projectRoot
    try {
        & uv run python -m incident_awareness.pipeline.r1_record_bounded_freeze @Arguments
    } finally {
        Pop-Location
    }
    if ($LASTEXITCODE -ne 0) { throw "r1_record_bounded_freeze failed with exit code $LASTEXITCODE" }
}

$runControlDir = Join-Path $ControlRoot $RunId
$failedControlPath = Join-Path $runControlDir "run-failed.json"
$abortedControlPath = Join-Path $runControlDir "run-aborted.json"
$freezeRequestPath = Join-Path $runControlDir "collection-freeze-requested.json"
$freezeAckPath = Join-Path $runControlDir "collection-freeze-ack.json"
$freezeGenerationPath = Join-Path $runControlDir "collection-freeze-generation.json"
$runFinalizedPath = Join-Path $runControlDir "run-finalized.json"
$freezeFailurePath = Join-Path $runControlDir "collection-freeze-failed.json"
$producerBindingPath = Join-Path $runControlDir "collection-producer-binding.json"
if (Test-Path -LiteralPath $failedControlPath) {
    throw "runner failed before completion (found $failedControlPath)"
}
if (Test-Path -LiteralPath $abortedControlPath) {
    throw "runner was aborted before completion (found $abortedControlPath)"
}

$state = [ordered]@{
    last_record_id = 0
    segment_no = 0
    chunk_sequence = 0
    message_ordinal = 0
}
if (Test-Path -LiteralPath $statePath) {
    $loaded = Get-Content -LiteralPath $statePath -Raw -Encoding UTF8 | ConvertFrom-Json
    $loadedNames = @($loaded.PSObject.Properties.Name)
    if ((($loadedNames -contains "watermark_sequence") -and
            [int64]$loaded.watermark_sequence -gt 0) -or
        (($loadedNames -contains "last_watermark_at") -and
            -not [string]::IsNullOrWhiteSpace([string]$loaded.last_watermark_at))) {
        throw "existing producer state contains an unverified source watermark; automatic finality is disabled"
    }
    foreach ($name in @($state.Keys)) {
        $state[$name] = [int64]$loaded.$name
    }
}

# Refuse to resume artifacts produced by the former TimeCreated-derived
# finality path. They remain immutable, but are not accepted as proof.
$existingWatermark = Get-ChildItem (Join-Path $runSpool "outbox") `
    -Filter "*-source_watermark.json" -ErrorAction SilentlyContinue | Select-Object -First 1
$existingClose = Get-ChildItem (Join-Path $runSpool "outbox") `
    -Filter "*-run_closed.json" -ErrorAction SilentlyContinue | Select-Object -First 1
$existingExport = Join-Path (Join-Path $runSpool "exports") (Join-Path $RunId "accepted-run-closed.json")
if ($null -ne $existingWatermark -or $null -ne $existingClose -or
    (Test-Path -LiteralPath $existingExport)) {
    throw "existing unverified finality artifact cannot be resumed by the Sysmon chunk producer"
}

# Clean up orphan raw/capture pairs before recovery
foreach ($rawFile in @(Get-ChildItem -LiteralPath $rawRoot -Filter "sysmon-*.jsonl" -ErrorAction SilentlyContinue)) {
    $metaPath = $rawFile.FullName + ".capture.json"
    if (-not (Test-Path -LiteralPath $metaPath)) {
        Remove-Item -LiteralPath $rawFile.FullName -Force
    }
}
foreach ($metaFile in @(Get-ChildItem -LiteralPath $rawRoot -Filter "sysmon-*.jsonl.capture.json" -ErrorAction SilentlyContinue)) {
    $rawPath = $metaFile.FullName.Substring(0, $metaFile.FullName.Length - ".capture.json".Length)
    if (-not (Test-Path -LiteralPath $rawPath)) {
        Remove-Item -LiteralPath $metaFile.FullName -Force
    }
}

# Recover counters from immutable source/output files. This closes the crash
# gap where publication succeeded before producer-state.json was replaced.
foreach ($rawFile in @(Get-ChildItem -LiteralPath $rawRoot -Filter "sysmon-*.jsonl" -ErrorAction SilentlyContinue)) {
    $segmentNumber = [int64]([IO.Path]::GetFileNameWithoutExtension($rawFile.Name).Substring(7))
    if ($segmentNumber -gt $state.segment_no) { $state.segment_no = $segmentNumber }
    foreach ($line in @(Get-Content -LiteralPath $rawFile.FullName -Encoding UTF8)) {
        $record = $line | ConvertFrom-Json
        if ([int64]$record.RecordId -gt $state.last_record_id) {
            $state.last_record_id = [int64]$record.RecordId
        }
    }
}
foreach ($messageFile in @(Get-ChildItem (Join-Path $runSpool "outbox") -Filter "*.json" -ErrorAction SilentlyContinue)) {
    $ordinal = [int64]($messageFile.Name.Split("-")[0])
    if ($ordinal -gt $state.message_ordinal) { $state.message_ordinal = $ordinal }
    $message = Get-Content -LiteralPath $messageFile.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($message.message_type -cne "event_chunk") {
        throw "unverified finality control message exists in the chunk producer outbox"
    }
    if ($message.message_type -ceq "event_chunk" -and [int64]$message.chunk_sequence -gt $state.chunk_sequence) {
        $state.chunk_sequence = [int64]$message.chunk_sequence
    }
}
while ($state.chunk_sequence -lt $state.segment_no) {
    $nextSequence = [int64]$state.chunk_sequence + 1
    $rawPath = Join-Path $rawRoot ("sysmon-{0:D8}.jsonl" -f $nextSequence)
    $metaPath = $rawPath + ".capture.json"
    if (-not (Test-Path -LiteralPath $rawPath) -or -not (Test-Path -LiteralPath $metaPath)) {
        throw "incomplete raw segment recovery state for sequence $nextSequence"
    }
    $capture = Get-Content -LiteralPath $metaPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $state.chunk_sequence = $nextSequence
    $state.message_ordinal++
    Invoke-Wiring @("publish-segment", "--spool-root", $runSpool,
        "--required-partition-contract", $RequiredPartitionContract,
        "--target-host", $TargetHost, "--run-id", $RunId,
        "--raw-jsonl", $rawPath, "--raw-log-id", ("R1-INCREMENTAL-" + $RunId + "-SYSMON"),
        "--segment-no", [string]$nextSequence,
        "--chunk-sequence", [string]$nextSequence,
        "--message-ordinal", [string]$state.message_ordinal,
        "--observed-at", [string]$capture.observed_at_utc)
}

# A freeze is resumed only when its ack is complete; the ack's upper bound is
# then where the post-bound polls start. A generation observation without its
# ack is an interrupted freeze and is not repaired here.
$frozenUpper = $null
if ($PositionFinality) {
    if (Test-Path -LiteralPath $freezeAckPath) {
        $existingAck = Get-Content -LiteralPath $freezeAckPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $frozenUpper = [long]$existingAck.source_upper_record_id
        if ([long]$state.last_record_id -lt $frozenUpper) { $state.last_record_id = $frozenUpper }
    } elseif (Test-Path -LiteralPath $freezeFailurePath) {
        throw "a failed collection freeze cannot be resumed (found $freezeFailurePath)"
    } elseif (Test-Path -LiteralPath $freezeGenerationPath) {
        throw "an interrupted collection freeze cannot be resumed (found $freezeGenerationPath without its ack)"
    } elseif (Test-Path -LiteralPath $runFinalizedPath) {
        throw "run-finalized exists without a collection freeze ack of this sidecar"
    }
    # The runner checks this before its first action: the same Run, host,
    # partition and required-partition contract as this sidecar.
    New-Item -ItemType Directory -Path $runControlDir -Force | Out-Null
    Write-PositionProducerBinding
}

$sessionOptions = New-PSSessionOption
$sessionArgs = @{ ComputerName = $TargetAddress; Port = $WinRmPort; Credential = $Credential; SessionOption = $sessionOptions }
if ($UseSsl) { $sessionArgs.UseSSL = $true }
$session = New-PSSession @sessionArgs
try {
    while ($true) {
        if (Test-Path -LiteralPath $failedControlPath) {
            throw "runner failed during polling (found $failedControlPath)"
        }
        if (Test-Path -LiteralPath $abortedControlPath) {
            throw "runner was aborted during polling (found $abortedControlPath)"
        }
        if ($PositionFinality) {
            if ($null -ne $frozenUpper -and (Test-Path -LiteralPath $runFinalizedPath)) {
                Write-Host "run-finalized found: the RecordId-bounded snapshot is sealed and the sidecar stops"
                break
            }
            if ($null -eq $frozenUpper) {
                if (Test-Path -LiteralPath $runFinalizedPath) {
                    throw "run-finalized was written before the collection freeze ack of this sidecar"
                }
                if (Test-Path -LiteralPath $freezeRequestPath) {
                    try {
                        $frozenUpper = Invoke-PositionFreeze $session
                    } catch {
                        # The runner stops waiting as soon as this file appears.
                        $freezeError = $_
                        try {
                            $reasonCode = Write-PositionFreezeFailure ([string]$freezeError.Exception.Message)
                            Write-Host ("collection freeze failed: " + $reasonCode)
                        } catch {
                            Write-Host ("writing the collection freeze failure failed: " + $_.Exception.Message)
                        }
                        throw $freezeError
                    }
                    Write-Host ("collection freeze ack written; the RecordId bound ends at " + $frozenUpper)
                    Start-Sleep -Seconds $PollIntervalSec
                    continue
                }
            }
        }

        $answer = Invoke-Command -Session $session -ScriptBlock $R1_INCREMENTAL_SYSMON_QUERY `
            -ArgumentList @([long]$state.last_record_id, $ContextStartUtc)

        $controllerReceivedAtUtc = [DateTime]::UtcNow.ToString("o")
        Publish-Records -Records @($answer.records) -TargetQueriedAtUtc ([string]$answer.target_queried_at_utc) `
            -ControllerReceivedAtUtc $controllerReceivedAtUtc

        if ([bool]$answer.snapshot_consistent -and
            [long]$state.last_record_id -lt [long]$answer.target_high_water_record_id) {
            throw "bounded Sysmon target events were not durably persisted"
        }

        Save-ProducerState
        if (-not $NoConsume) {
            Invoke-Wiring @("consume", "--spool-root", $runSpool,
                "--required-partition-contract", $RequiredPartitionContract,
                "--target-host", $TargetHost)
        }

        Start-Sleep -Seconds $PollIntervalSec
    }
} finally {
    Remove-PSSession $session
}
