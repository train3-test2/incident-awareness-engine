<#
    Live WMI development Sysmon producer for the R1 v0.1 stream.

    Start this sidecar before Invoke-R1PilotRun.  It polls the live Sysmon
    channel through the same WinRM trust boundary, writes immutable raw JSONL
    segments, invokes the canonical Python normalizer/chunk publisher, and can
    immediately deliver the spool to Role3's PostgreSQL ledger. No approved
    Sysmon source-completeness proof exists, so this sidecar does not publish a
    source watermark or run_closed.
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
    [switch]$NoConsume
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
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

function Write-AtomicText([string]$Path, [string]$Text) {
    $temp = $Path + "." + [Guid]::NewGuid().ToString("N") + ".tmp"
    [IO.File]::WriteAllText($temp, $Text, $utf8)
    if (Test-Path -LiteralPath $Path) {
        if ([IO.File]::ReadAllText($Path) -cne $Text) { throw "immutable path conflict: $Path" }
        Remove-Item -LiteralPath $temp -Force
        return
    }
    [IO.File]::Move($temp, $Path)
}

function Invoke-Wiring([string[]]$Arguments) {
    Push-Location $projectRoot
    try {
        & uv run python -m incident_awareness.pipeline.r1_stream_wiring @Arguments
    } finally {
        Pop-Location
    }
    if ($LASTEXITCODE -ne 0) { throw "r1_stream_wiring failed with exit code $LASTEXITCODE" }
}

$runControlDir = Join-Path $ControlRoot $RunId
$failedControlPath = Join-Path $runControlDir "run-failed.json"
$abortedControlPath = Join-Path $runControlDir "run-aborted.json"
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

        $answer = Invoke-Command -Session $session -ScriptBlock $R1_INCREMENTAL_SYSMON_QUERY `
            -ArgumentList @([long]$state.last_record_id, $ContextStartUtc)

        $controllerReceivedAtUtc = [DateTime]::UtcNow.ToString("o")
        $records = @($answer.records)
        for ($offset = 0; $offset -lt $records.Count; $offset += $ChunkMaxEvents) {
            $end = [Math]::Min($offset + $ChunkMaxEvents - 1, $records.Count - 1)
            $slice = @($records[$offset..$end])
            $state.segment_no++
            $state.chunk_sequence++
            $state.message_ordinal++
            $rawPath = Join-Path $rawRoot ("sysmon-{0:D8}.jsonl" -f $state.segment_no)
            $metaPath = $rawPath + ".capture.json"
            $lines = @($slice | ForEach-Object { $_ | ConvertTo-Json -Compress -Depth 8 })
            if (-not (Test-Path -LiteralPath $metaPath)) {
                Write-AtomicText $metaPath (([ordered]@{
                    target_queried_at_utc = [string]$answer.target_queried_at_utc
                    controller_received_at_utc = $controllerReceivedAtUtc
                    observed_at_utc = $controllerReceivedAtUtc
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

        if ([bool]$answer.snapshot_consistent -and
            [long]$state.last_record_id -lt [long]$answer.target_high_water_record_id) {
            throw "bounded Sysmon target events were not durably persisted"
        }

        $stateTemp = $statePath + "." + [Guid]::NewGuid().ToString("N") + ".next"
        [IO.File]::WriteAllText($stateTemp, (($state | ConvertTo-Json -Compress) + "`n"), $utf8)
        Move-Item -LiteralPath $stateTemp -Destination $statePath -Force
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
