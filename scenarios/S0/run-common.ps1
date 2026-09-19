<#
    .SYNOPSIS
        Shared helpers for the S0 scenario runs (normal and attack).

    .DESCRIPTION
        Dot-source this file from normal/run.ps1 or attack/run.ps1. It does not
        execute scenario actions and it makes no network connections; it only
        issues the run context and writes the four artifacts described in
        docs/scenarios/s0.md section 9.

            data/raw/<run_id>/telemetry/       sysmon EVTX and JSONL
            data/raw/<run_id>/manifest.json    path / sha256 / layer / source
            data/ground_truth/<run_id>/execution_record.csv
            data/ground_truth/<run_id>/run_metadata.json

        Scenario values are read from a JSON rendering of scenario.yaml.
        Windows PowerShell 5.1 has no YAML reader, so the host converts
        scenario.yaml before copying the scripts to the VM.

        run_id is supplied by the caller. The sequence number must come from
        outside the VM: a snapshot restore would roll back any counter kept
        inside it and the same run_id could be issued twice
        (docs/schema/run-id.md sections 3 and 10).

        NOTE: this file is intentionally ASCII only. Windows PowerShell 5.1
        misreads UTF-8 source files without a BOM, and a lost BOM corrupts
        string literals.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$SYSMON_LOG = "Microsoft-Windows-Sysmon/Operational"
$SYSMON_EVENT_IDS = @(1, 3)
$EVTX_WINDOW_MARGIN_MS = 10000
$RUN_ID_PATTERN = '^RUN-(?<date>[0-9]{8})-(?<sequence>[0-9]{3})$'

# Captured while this file is dot-sourced so a worker process can load the same
# helpers (Invoke-ApprovedTcpAttempt) the runner uses.
$RUN_COMMON_PATH = $PSCommandPath

function Write-Step { param([string]$Message) Write-Host "[*] $Message" -ForegroundColor Cyan }
function Write-Ok { param([string]$Message) Write-Host "[+] $Message" -ForegroundColor Green }
function Write-Fail { param([string]$Message) Write-Host "[!] $Message" -ForegroundColor Red }

function Get-UtcStamp {
    <# UTC ISO 8601 with milliseconds. "fff" truncates, it does not round. #>
    param([datetime]$Value)
    return $Value.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
}

function Get-Sha256 {
    param([string]$Path)
    return (Get-FileHash -Path $Path -Algorithm SHA256).Hash.ToLower()
}

function Test-RunId {
    <# Format and calendar validity, the same rule RunMetadata applies. #>
    param([string]$RunId)

    $match = [regex]::Match($RunId, $RUN_ID_PATTERN)
    if (-not $match.Success) {
        return $false
    }

    try {
        [datetime]::ParseExact($match.Groups["date"].Value, "yyyyMMdd", $null) | Out-Null
    } catch {
        return $false
    }

    return $true
}

function Get-SysmonConfigState {
    <# Config hash and HashingAlgorithms as reported by Sysmon64 -c. #>
    param([string]$SysmonBinary)

    $state = [ordered]@{
        config_file        = $null
        config_hash        = $null
        hashing_algorithms = $null
    }

    $output = & $SysmonBinary -c | Out-String
    foreach ($line in ($output -split "`r?`n")) {
        if ($line -match '^\s*-?\s*Config file:\s*(.+?)\s*$') { $state.config_file = $Matches[1] }
        if ($line -match '^\s*-?\s*Config hash:\s*(.+?)\s*$') { $state.config_hash = $Matches[1] }
        if ($line -match '^\s*-?\s*HashingAlgorithms:\s*(.+?)\s*$') { $state.hashing_algorithms = $Matches[1] }
    }

    return $state
}

function Test-SysmonConfigApplied {
    <#
        Compare the config file on disk with the config Sysmon reports as applied.

        "Config hash" from Sysmon64 -c is the hash of the configuration actually in
        force, so a difference means the file was edited, re-encoded or copied with
        different line endings after it was applied. The run would then record a
        sysmon_config_version that does not describe what was monitoring
        (samples/raw/README.md section 4).

        A collection run also stops when the two cannot be compared at all - no
        hash reported, or an algorithm other than SHA-256 - because an applied
        config that cannot be verified is not a valid collection. Rehearsal warns
        and continues in every one of these cases.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$ConfigSha256,
        [Parameter(Mandatory = $true)]$ConfigState,
        [switch]$Rehearsal
    )

    $reported = [string]$ConfigState.config_hash
    if ([string]::IsNullOrWhiteSpace($reported)) {
        $message = "Sysmon reported no config hash; the applied config cannot be compared."
        if (-not $Rehearsal) { throw $message }
        Write-Fail $message
        return
    }

    $algorithm = "SHA256"
    $value = $reported.Trim()
    if ($value -match '^(?<algorithm>[A-Za-z0-9]+)=(?<value>[0-9A-Fa-f]+)$') {
        $algorithm = $Matches["algorithm"].ToUpper()
        $value = $Matches["value"]
    }

    if ($algorithm -ne "SHA256") {
        $message = ("Sysmon reports the config hash as " + $algorithm +
            "; it cannot be compared with the SHA-256 of the file.")
        if (-not $Rehearsal) { throw $message }
        Write-Fail $message
        return
    }

    if ($value.ToLower() -eq $ConfigSha256.ToLower()) {
        Write-Ok "applied Sysmon config matches the config file"
        return
    }

    $message = ("Sysmon applied config differs from the config file. file=" + $ConfigSha256.ToLower() +
        " applied=" + $value.ToLower() + ". Copy the file again without changing its line endings, " +
        "or re-apply it with -c.")
    if ($Rehearsal) {
        Write-Fail $message
        return
    }
    throw $message
}

function Get-EffectiveDataRoot {
    <#
        The directory a run actually writes under.

        A rehearsal is pushed one level down so its artifacts can never be read as
        data/raw or data/ground_truth. The same run_id therefore lives in two
        separate namespaces, and a rehearsal never collides with a collection run.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$DataRoot,
        [switch]$Rehearsal
    )

    if ($Rehearsal) { return (Join-Path $DataRoot "_rehearsal") }
    return $DataRoot
}

function Get-ExistingRunDirectory {
    <#
        Return the run directories that already exist under a root.

        The run_id directory itself is checked, not the telemetry subfolder: a
        half finished run leaves ground_truth behind without any telemetry, and
        that is exactly the state a rerun must not write into.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$EffectiveRoot,
        [Parameter(Mandatory = $true)][string]$RunId
    )

    $existing = New-Object System.Collections.Generic.List[string]
    foreach ($layer in @("raw", "ground_truth")) {
        $candidate = Join-Path (Join-Path $EffectiveRoot $layer) $RunId
        if (Test-Path -LiteralPath $candidate) { $existing.Add($candidate) }
    }

    return $existing.ToArray()
}

function Assert-RunDirectoryAvailable {
    <#
        Refuse to start when this run_id already produced output.

        Reusing a run_id would overwrite the EVTX, the execution_record and the
        metadata of the earlier run, and a failure part way through would leave the
        old manifest beside new telemetry. The check runs before anything is
        created or written, so a refused run leaves the earlier artifacts byte for
        byte as they were.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$EffectiveRoot,
        [Parameter(Mandatory = $true)][string]$RunId
    )

    $existing = @(Get-ExistingRunDirectory -EffectiveRoot $EffectiveRoot -RunId $RunId)
    if ($existing.Count -eq 0) { return }

    throw ("run_id " + $RunId + " already has output at " + ($existing -join " and ") +
        ". Issue a new run_id: this run would overwrite the existing artifacts.")
}

function Test-AnchorEventBoundary {
    <#
        True when a Sysmon EID 1 record may stand for the anchor action.

        Both conditions are required: the record belongs to the process that was
        started, and it was created at or after the moment the action started.
        Get-WinEvent's StartTime is only a query hint, so the boundary is checked
        again here in UTC. Without it a reused ProcessId would let the previous
        owner's EID 1 become reference_time, and reference_time together with
        reference_source_event_id would no longer describe A01.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowNull()][object]$RecordedProcessId,
        [Parameter(Mandatory = $true)][int]$ProcessId,
        [Parameter(Mandatory = $true)][datetime]$TimeCreated,
        [Parameter(Mandatory = $true)][datetime]$Since
    )

    if ([string]$RecordedProcessId -ne [string]$ProcessId) { return $false }

    return ($TimeCreated.ToUniversalTime() -ge $Since.ToUniversalTime())
}

function New-RunContext {
    <#
        Validate the inputs and lay out the run directories.

        A run that performs an external connection requires a non-null
        external_connection.target in the scenario file. Collection runs stay
        blocked until the network isolation decision is recorded.

        A run_id that already produced output is refused before any side effect,
        so a rerun cannot overwrite an earlier run's artifacts.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$RunId,
        [Parameter(Mandatory = $true)][ValidateSet("normal", "attack")][string]$RunType,
        [Parameter(Mandatory = $true)][string]$ScenarioJsonPath,
        [Parameter(Mandatory = $true)][string]$DataRoot,
        [Parameter(Mandatory = $true)][string]$VmSnapshot,
        [Parameter(Mandatory = $true)][string]$SysmonBinary,
        [Parameter(Mandatory = $true)][string]$SysmonConfigPath,
        [string]$ExpectedSysmonConfigSha256,
        [switch]$Rehearsal
    )

    if (-not (Test-RunId -RunId $RunId)) {
        throw "run_id must match RUN-YYYYMMDD-NNN with a real date: $RunId"
    }

     # The date part is the UTC date the run_id was issued for (docs/schema/run-id.md
     # section 3). Contract validation stops at the calendar check, so a stale run_id
     # only shows up here.
    $runIdDate = [regex]::Match($RunId, $RUN_ID_PATTERN).Groups["date"].Value
    $todayUtc = (Get-Date).ToUniversalTime().ToString("yyyyMMdd")
    if ($runIdDate -ne $todayUtc) {
        Write-Fail ("run_id date " + $runIdDate + " is not the current UTC date " + $todayUtc +
            "; check that the run_id was issued for this run.")
    }
    foreach ($path in @($ScenarioJsonPath, $SysmonConfigPath, $SysmonBinary)) {
        if (-not (Test-Path $path)) { throw "File not found: $path" }
    }

    $scenario = Get-Content -Path $ScenarioJsonPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $run = $scenario.runs.$RunType

    $externalActions = @($run.actions | Where-Object {
        $_.PSObject.Properties.Name -contains "uses_external_connection" -and $_.uses_external_connection
    })
    $externalTargetSet = -not [string]::IsNullOrWhiteSpace($scenario.external_connection.target)
    if ($externalActions.Count -gt 0 -and -not $externalTargetSet) {
        if (-not $Rehearsal) {
            throw ("external_connection.target is null. The destination is decided in " +
                $scenario.external_connection.decision_reference + " before a collection run.")
        }
        Write-Fail ("external_connection.target is null; the external action is skipped. " +
            "Rehearsal artifacts are not a valid S0 run.")
    }

     # Refuse a reused run_id before anything happens: no Sysmon probe, no marker,
     # no directory, no artifact. A rejected run must leave the earlier run
     # untouched, so this is the last check that can still be free of side effects.
    $effectiveRoot = Get-EffectiveDataRoot -DataRoot $DataRoot -Rehearsal:$Rehearsal
    Assert-RunDirectoryAvailable -EffectiveRoot $effectiveRoot -RunId $RunId

    $configSha256 = Get-Sha256 -Path $SysmonConfigPath
    if ($ExpectedSysmonConfigSha256 -and $configSha256 -ne $ExpectedSysmonConfigSha256.ToLower()) {
        throw "Sysmon config sha256 mismatch. expected=$ExpectedSysmonConfigSha256 actual=$configSha256"
    }

     # Query Sysmon before start_time is stamped: "Sysmon64 -c" starts a process of its
     # own, and the export window is measured from start_time, so leaving this call in
     # the context literal below put the runner's own probe inside the collected window.
    $configState = Get-SysmonConfigState -SysmonBinary $SysmonBinary
    Test-SysmonConfigApplied -ConfigSha256 $configSha256 -ConfigState $configState -Rehearsal:$Rehearsal

    # Rehearsal artifacts are not a valid S0 collection. The output root above
    # already points one level down so they are never mistaken for data/raw or
    # data/ground_truth; this drops a marker that says so. The run_id and the
    # RunMetadata contract are unchanged.
    if ($Rehearsal) {
        New-Item -ItemType Directory -Path $effectiveRoot -Force | Out-Null
        $markerPath = Join-Path $effectiveRoot "REHEARSAL.txt"
        $markerText = "Rehearsal output. NOT a valid S0 collection. Do not use as data/raw or data/ground_truth."
        $utf8NoBomMarker = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($markerPath, $markerText, $utf8NoBomMarker)
    }

    $telemetryDir = Join-Path $effectiveRoot "raw\$RunId\telemetry"
    $groundTruthDir = Join-Path $effectiveRoot "ground_truth\$RunId"
    foreach ($dir in @($telemetryDir, $groundTruthDir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }

    $startTime = Get-Date
    Write-Ok "run context ready: $RunId ($RunType) start $(Get-UtcStamp $startTime)"

    return [ordered]@{
        run_id               = $RunId
        run_type             = $RunType
        rehearsal            = [bool]$Rehearsal
        external_target_set  = $externalTargetSet
        scenario             = $scenario
        run                  = $run
        start_time           = $startTime
        telemetry_dir        = $telemetryDir
        ground_truth_dir     = $groundTruthDir
        vm_snapshot          = $VmSnapshot
        sysmon_binary        = $SysmonBinary
        sysmon_config_path   = $SysmonConfigPath
        sysmon_config_sha256 = $configSha256
        sysmon_config_state  = $configState
        execution_records    = New-Object System.Collections.Generic.List[object]
        artifacts            = New-Object System.Collections.Generic.List[object]
    }
}

function Add-ExecutionRecord {
    <#
        Record one executed action. The timestamp is the real execution time,
        not the design offset kept in scenario.yaml.
    #>
    param(
        [Parameter(Mandatory = $true)]$Context,
        [Parameter(Mandatory = $true)][string]$ActionId,
        [Parameter(Mandatory = $true)][datetime]$Timestamp
    )

    $action = $Context.run.actions | Where-Object { $_.action_id -eq $ActionId }
    if (-not $action) { throw "action_id not present in the scenario file: $ActionId" }

    $Context.execution_records.Add([ordered]@{
        run_id      = $Context.run_id
        action_id   = $ActionId
        timestamp   = (Get-UtcStamp $Timestamp)
        action_type = $action.action_type
        description = $action.description
    })
    Write-Ok "$ActionId recorded at $(Get-UtcStamp $Timestamp)"
}

function Initialize-WorkDir {
    <#
        Create the shared working directory and the helper scripts. Both runs use
        the same directory and the same s0_ prefix so the path and the file names
        cannot separate normal from attack.
    #>
    param([string]$Path)

    New-Item -ItemType Directory -Path $Path -Force | Out-Null
    $docs = Join-Path $Path "s0_docs"
    New-Item -ItemType Directory -Path $docs -Force | Out-Null
    1..3 | ForEach-Object {
        $file = Join-Path $docs ("s0_note_{0:D2}.txt" -f $_)
        Set-Content -Path $file -Value "S0 sample document $_" -Encoding Ascii
    }

    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)

    $inventory = @'
$ErrorActionPreference = "Stop"
$target = Join-Path $PSScriptRoot "s0_inventory.txt"
Get-Volume | Select-Object DriveLetter, FileSystemLabel, SizeRemaining |
    Out-File -FilePath $target -Encoding ascii
'@
    [System.IO.File]::WriteAllText((Join-Path $Path "s0_inventory.ps1"), $inventory, $utf8NoBom)

    $archive = @'
$ErrorActionPreference = "Stop"
$source = Join-Path $PSScriptRoot "s0_docs"
$staging = Join-Path $PSScriptRoot "s0_staging"
New-Item -ItemType Directory -Path $staging -Force | Out-Null
Copy-Item -Path (Join-Path $source "*") -Destination $staging -Force
$zip = Join-Path $PSScriptRoot "s0_archive.zip"
if (Test-Path $zip) { Remove-Item $zip -Force }
Compress-Archive -Path (Join-Path $staging "*") -DestinationPath $zip
'@
    [System.IO.File]::WriteAllText((Join-Path $Path "s0_archive.ps1"), $archive, $utf8NoBom)

    $cleanup = @'
$ErrorActionPreference = "Stop"
$staging = Join-Path $PSScriptRoot "s0_staging"
if (Test-Path $staging) { Remove-Item $staging -Recurse -Force }
$log = Join-Path $PSScriptRoot "s0_cleanup.log"
Add-Content -Path $log -Value ("cleanup " + (Get-Date).ToUniversalTime().ToString("o")) -Encoding Ascii
'@
    [System.IO.File]::WriteAllText((Join-Path $Path "s0_cleanup.ps1"), $cleanup, $utf8NoBom)

    Write-Ok "work directory ready: $Path"
}

function Start-ScenarioScript {
    <#
        Start one helper script as its own process so Sysmon records EID 1, and
        return the process together with the moment it was started. The returned
        time is what goes into execution_record.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$ScriptPath
    )

    $startedAt = Get-Date
    $process = Start-Process -FilePath "powershell.exe" `
        -ArgumentList @("-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
            "-File", $ScriptPath) `
        -WindowStyle Hidden -PassThru
    $process.WaitForExit()

    if ($process.ExitCode -ne 0) {
        throw "helper script failed with exit code $($process.ExitCode): $ScriptPath"
    }

    return [ordered]@{ process = $process; started_at = $startedAt }
}

function Wait-ForOffset {
    param(
        [Parameter(Mandatory = $true)]$Context,
        [Parameter(Mandatory = $true)][int]$OffsetSec,
        [switch]$Rehearsal
    )

    if ($Rehearsal) { return }

    $due = $Context.start_time.AddSeconds($OffsetSec)
    $remaining = ($due - (Get-Date)).TotalSeconds
    if ($remaining -gt 0) {
        Write-Step ("waiting {0:N0}s for offset {1}s" -f $remaining, $OffsetSec)
        Start-Sleep -Seconds ([int][Math]::Ceiling($remaining))
    }
}

function Get-ActionOffset {
    param([Parameter(Mandatory = $true)]$Context, [Parameter(Mandatory = $true)][string]$ActionId)
    $action = $Context.run.actions | Where-Object { $_.action_id -eq $ActionId }
    if (-not $action) { throw "action_id not present in the scenario file: $ActionId" }
    return [int]$action.offset_sec
}

function Export-SysmonRunWindow {
    <#
        Export Sysmon EID 1 and 3 for this run only.

        The window is measured backwards from the moment the query runs with the
        timediff() XPath function, because XPath 1.0 cannot compare @SystemTime
        against an ISO 8601 string. Keeping the window tight is what excludes the
        pre-run checks already present in the snapshot.
    #>
    param([Parameter(Mandatory = $true)]$Context)

    $windowMs = [int]((Get-Date) - $Context.start_time).TotalMilliseconds + $EVTX_WINDOW_MARGIN_MS
    $idClause = ($SYSMON_EVENT_IDS | ForEach-Object { "EventID=$_" }) -join " or "
    $query = "*[System[($idClause) and TimeCreated[timediff(@SystemTime) <= $windowMs]]]"

    $evtxPath = Join-Path $Context.telemetry_dir "sysmon-0001.evtx"
    if (Test-Path $evtxPath) { Remove-Item $evtxPath -Force }

     # Do not redirect stderr. In Windows PowerShell 5.1 "2>&1" on a native command
     # wraps stderr lines in ErrorRecord objects, which raises NativeCommandError
     # under $ErrorActionPreference = "Stop" before the exit code can be inspected.
    & wevtutil epl $SYSMON_LOG $evtxPath "/q:$query" /ow:true | Out-Null
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $evtxPath)) {
        throw "wevtutil epl failed for $SYSMON_LOG"
    }

    $events = @(Get-WinEvent -Path $evtxPath -ErrorAction SilentlyContinue | Sort-Object RecordId)
    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($event in $events) {
        $xml = [xml]$event.ToXml()
        $eventData = [ordered]@{}
        foreach ($item in $xml.Event.EventData.Data) { $eventData[$item.Name] = $item."#text" }

        $record = [ordered]@{
            RecordId    = $event.RecordId
            EventId     = $event.Id
            TimeCreated = (Get-UtcStamp $event.TimeCreated)
            Channel     = $event.LogName
            Computer    = $event.MachineName
            Provider    = $event.ProviderName
            EventData   = $eventData
        }
        $lines.Add(($record | ConvertTo-Json -Compress -Depth 5))
    }

    $jsonlPath = Join-Path $Context.telemetry_dir "sysmon-0001.jsonl"
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllLines($jsonlPath, $lines, $utf8NoBom)

    $Context.artifacts.Add([ordered]@{
        path = $evtxPath; source = "sysmon"; layer = "raw_telemetry"
    })
    $Context.artifacts.Add([ordered]@{
        path = $jsonlPath; source = "sysmon"; layer = "raw_telemetry"; derived_from = $evtxPath
    })

    Write-Ok "sysmon window exported: $($events.Count) events"
    return $events
}

function Get-AnchorTelemetry {
    <#
        Find the first Sysmon EID 1 record produced by the anchor process while the
        run is still going.

        reference_time cannot wait for the EVTX export: the export happens after the
        observation window, and the window end is computed from reference_time
        (docs/scenarios/s0.md sections 6 and 9). So this reads the live channel
        instead, and the export later carries the same record.

        The search never looks before $Since. Windows reuses ProcessIds, so an
        earlier process could hold the same id; an EID 1 from before the action
        started must never become reference_time. Sysmon may write the record late,
        which only delays the poll, but the record's own TimeCreated decides.
    #>
    param(
        [Parameter(Mandatory = $true)][int]$ProcessId,
        [Parameter(Mandatory = $true)][datetime]$Since,
        [int]$TimeoutSec = 60,
        [int]$PollIntervalSec = 2
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    $filter = @{ LogName = $SYSMON_LOG; Id = 1; StartTime = $Since }

    while ($true) {
        $events = @(Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue |
            Sort-Object RecordId)
        foreach ($event in $events) {
            $xml = [xml]$event.ToXml()
            $recordedPid = ($xml.Event.EventData.Data |
                Where-Object { $_.Name -eq "ProcessId" })."#text"
            if (-not (Test-AnchorEventBoundary -RecordedProcessId $recordedPid -ProcessId $ProcessId `
                -TimeCreated $event.TimeCreated -Since $Since)) {
                continue
            }

            return [ordered]@{
                reference_time            = (Get-UtcStamp $event.TimeCreated)
                reference_source_event_id = [string]$event.RecordId
                process_guid              = ($xml.Event.EventData.Data |
                    Where-Object { $_.Name -eq "ProcessGuid" })."#text"
                observed_at               = $event.TimeCreated
            }
        }

        if ((Get-Date) -ge $deadline) {
            throw "no Sysmon EID 1 record for ProcessId $ProcessId within $TimeoutSec s"
        }
        Start-Sleep -Seconds $PollIntervalSec
    }
}

function Wait-ForObservationEnd {
    <#
        Hold the run open until the observation window closes.

        The anchor is reference_time for an attack run and run start for a normal
        run, so both runs are observed for the same span (docs/scenarios/s0.md
        sections 7 and 9).
    #>
    param(
        [Parameter(Mandatory = $true)]$Context,
        [Parameter(Mandatory = $true)][datetime]$AnchorTime,
        [switch]$Rehearsal
    )

    $observationSec = [int]$Context.scenario.run_length.evaluation_horizon_sec +
        [int]$Context.scenario.run_length.post_reference_margin_sec
    $due = $AnchorTime.AddSeconds($observationSec)

    if ($Rehearsal) {
        Write-Fail ("observation window skipped (rehearsal); a real run would end at " +
            (Get-UtcStamp $due))
        return
    }

    $remaining = ($due - (Get-Date)).TotalSeconds
    if ($remaining -gt 0) {
        Write-Step ("observing for {0:N0}s more" -f $remaining)
        Start-Sleep -Seconds ([int][Math]::Ceiling($remaining))
    }
}

function Test-ActionCausality {
    <#
        Check that the child action ran inside the anchor process
        (docs/scenarios/s0.md section 4-2: same ProcessGuid).

        The destination and the start time are part of the match so a connection
        the anchor process made earlier cannot be mistaken for the child action.

        Returns status "matched", "mismatched" or "not_verified". While the child
        action is unimplemented, "not_verified" is the expected result.
    #>
    param(
        [Parameter(Mandatory = $true)]$Events,
        [object]$AnchorProcessGuid,
        [object]$ChildStartedAt,
        [object]$ExpectedDestination,
        [object]$ExpectedPort,
        [int]$ToleranceSec = 30,
        [int]$ChildEventId = 3
    )

    if ([string]::IsNullOrWhiteSpace([string]$AnchorProcessGuid)) {
        return [ordered]@{ status = "not_verified"; record_id = $null; reason = "anchor ProcessGuid unknown" }
    }
    if ($null -eq $ChildStartedAt) {
        return [ordered]@{ status = "not_verified"; record_id = $null; reason = "child action was not executed" }
    }

    $notBefore = ([datetime]$ChildStartedAt).AddSeconds(-$ToleranceSec)
    $candidates = @($Events | Where-Object { $_.Id -eq $ChildEventId -and $_.TimeCreated -ge $notBefore })
    if ($candidates.Count -eq 0) {
        return [ordered]@{ status = "not_verified"; record_id = $null; reason = "no candidate event after the child action started" }
    }

    foreach ($event in ($candidates | Sort-Object RecordId)) {
        $xml = [xml]$event.ToXml()
        $data = $xml.Event.EventData.Data
        $guid = ($data | Where-Object { $_.Name -eq "ProcessGuid" })."#text"
        if ($guid -ne [string]$AnchorProcessGuid) { continue }

        if (-not [string]::IsNullOrWhiteSpace([string]$ExpectedDestination)) {
            $destination = ($data | Where-Object { $_.Name -eq "DestinationIp" })."#text"
            if ($destination -ne [string]$ExpectedDestination) { continue }
        }
        if ($null -ne $ExpectedPort -and -not [string]::IsNullOrWhiteSpace([string]$ExpectedPort)) {
            $port = ($data | Where-Object { $_.Name -eq "DestinationPort" })."#text"
            if ($port -ne [string]$ExpectedPort) { continue }
        }

        return [ordered]@{ status = "matched"; record_id = [string]$event.RecordId; reason = "same ProcessGuid as the anchor" }
    }

    return [ordered]@{ status = "mismatched"; record_id = $null; reason = "no event with the anchor ProcessGuid matched the expected destination" }
}

function Get-ReferenceFromTelemetry {
    <#
        reference_time is the first telemetry the anchor action produced and
        reference_source_event_id is the Sysmon RecordId of that event
        (docs/scenarios/s0.md section 6). A normal run has no anchor.
    #>
    param(
        [Parameter(Mandatory = $true)]$Events,
        [Parameter(Mandatory = $true)][int]$AnchorProcessId
    )

    $anchor = $Events |
        Where-Object { $_.Id -eq 1 } |
        Where-Object {
            $xml = [xml]$_.ToXml()
            $recordedPid = ($xml.Event.EventData.Data |
                Where-Object { $_.Name -eq "ProcessId" })."#text"
            $recordedPid -eq [string]$AnchorProcessId
        } |
        Sort-Object RecordId |
        Select-Object -First 1

    if (-not $anchor) {
        throw "no Sysmon EID 1 record found for the anchor ProcessId $AnchorProcessId"
    }

    $xml = [xml]$anchor.ToXml()
    return [ordered]@{
        reference_time            = (Get-UtcStamp $anchor.TimeCreated)
        reference_source_event_id = [string]$anchor.RecordId
        process_guid              = ($xml.Event.EventData.Data |
            Where-Object { $_.Name -eq "ProcessGuid" })."#text"
    }
}

function Write-RunMetadata {
    param(
        [Parameter(Mandatory = $true)]$Context,
        [Parameter(Mandatory = $true)][datetime]$EndTime,
        [object]$ReferenceTime,
        [object]$ReferenceActionId,
        [object]$ReferenceSourceEventId
    )

     # A [string] parameter converts $null to an empty string, and the empty string
     # would be written as "" instead of null. RunMetadata rejects a normal run whose
     # reference_time is not null, so the three fields are normalised here.
    $referenceTimeValue = if ([string]::IsNullOrEmpty([string]$ReferenceTime)) { $null } else { [string]$ReferenceTime }
    $referenceActionValue = if ([string]::IsNullOrEmpty([string]$ReferenceActionId)) { $null } else { [string]$ReferenceActionId }
    $referenceEventValue = if ([string]::IsNullOrEmpty([string]$ReferenceSourceEventId)) { $null } else { [string]$ReferenceSourceEventId }

    $scenario = $Context.scenario
    $meta = [ordered]@{
        run_id                    = $Context.run_id
        scenario_id               = $scenario.scenario_id
        run_type                  = $Context.run_type
        target_host               = $scenario.run_metadata.target_host
        start_time                = (Get-UtcStamp $Context.start_time)
        end_time                  = (Get-UtcStamp $EndTime)
        family_id                 = $scenario.family_id
        variation_id              = $scenario.variation_id
        repetition                = 1
        reference_time            = $referenceTimeValue
        reference_action_id       = $referenceActionValue
        reference_source_event_id = $referenceEventValue
        vm_snapshot               = $Context.vm_snapshot
        sysmon_config_version     = $scenario.run_metadata.sysmon_config_version
        detector_set_version      = $null
        scenario_version          = $scenario.scenario_version
        schema_versions           = $scenario.run_metadata.schema_versions
        reference_policy_version  = $scenario.run_metadata.reference_policy_version
    }

    $path = Join-Path $Context.ground_truth_dir "run_metadata.json"
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($path, ($meta | ConvertTo-Json -Depth 5), $utf8NoBom)
    Write-Ok "run_metadata written: $path"
    return $path
}

function Write-ExecutionRecord {
    param([Parameter(Mandatory = $true)]$Context)

    $expected = $Context.scenario.shortcut_controls.actions_per_run
    if ($Context.execution_records.Count -ne $expected) {
        $message = ("execution_record has " + $Context.execution_records.Count +
            " rows, the scenario expects " + $expected)
        if (-not $Context.rehearsal) { throw $message }
        Write-Fail ($message + " (rehearsal: the skipped action is not recorded)")
    }

     # Export-Csv -Encoding UTF8 writes a BOM in Windows PowerShell 5.1, and a reader
     # that opens the file as plain UTF-8 then sees the BOM inside the first column
     # name. The rows are rendered first and written without one.
    $path = Join-Path $Context.ground_truth_dir "execution_record.csv"
    $lines = @($Context.execution_records |
        ForEach-Object { New-Object psobject -Property $_ } |
        Select-Object run_id, action_id, timestamp, action_type, description |
        ConvertTo-Csv -NoTypeInformation)
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllLines($path, $lines, $utf8NoBom)
    Write-Ok "execution_record written: $path"
    return $path
}

function Write-RunManifest {
    <#
        Manifest item fields follow docs/data-contract-v0.2.md section 5-2:
        path / sha256 / layer / source plus the optional derived_from.

        raw_log_id uses the provisional RAW-NNN scheme shown in
        docs/schema/run-id.md section 12 until the generation rule is decided.
        config_version stays null until the run config artifact exists
        (docs/data-contract-v0.2.md section 8-1).
    #>
    param([Parameter(Mandatory = $true)]$Context)

    $items = New-Object System.Collections.Generic.List[object]
    $index = 0
    foreach ($artifact in $Context.artifacts) {
        $index++
        $item = [ordered]@{
            raw_log_id = ("RAW-{0:D3}" -f $index)
            path       = (Resolve-Path $artifact.path).Path
            sha256     = (Get-Sha256 -Path $artifact.path)
            layer      = $artifact.layer
            source     = $artifact.source
        }
        if ($artifact.Keys -contains "derived_from") {
            $item.derived_from = (Resolve-Path $artifact.derived_from).Path
        }
        $items.Add($item)
    }

    $manifest = [ordered]@{
        run_id         = $Context.run_id
        generated_at   = (Get-UtcStamp (Get-Date))
        config_version = $null
        sysmon         = [ordered]@{
            config_version     = $Context.scenario.run_metadata.sysmon_config_version
            config_sha256      = $Context.sysmon_config_sha256
            config_hash        = $Context.sysmon_config_state.config_hash
            hashing_algorithms = $Context.sysmon_config_state.hashing_algorithms
        }
        items          = $items
    }

    $path = Join-Path (Split-Path $Context.telemetry_dir -Parent) "manifest.json"
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($path, ($manifest | ConvertTo-Json -Depth 6), $utf8NoBom)
    Write-Ok "manifest written: $path"
    return $path
}

# ---------------------------------------------------------------------------
# Formal external connection - safety gate, worker and single TCP primitive
#
# These helpers are used only by a formal (non-rehearsal) run. Rehearsal never
# calls them, makes no network connection and needs none of the approval inputs.
# ---------------------------------------------------------------------------

function Test-ApprovedGlobalIPv4 {
    <#
        True only for a canonical, globally routable IPv4 literal.

        This mirrors tools/scenario_to_json.py: the destination the renderer
        injected is checked again on the VM before any socket is created, so a
        hand-edited scenario.json cannot slip a private, documentation or
        non-canonical address into a formal run. IPv6 and hostnames are refused.
    #>
    param([string]$Address)

    if ([string]::IsNullOrEmpty($Address)) { return $false }
    if ($Address -ne $Address.Trim()) { return $false }
    if ($Address.Contains(":")) { return $false }

    $parsed = [System.Net.IPAddress]::Any
    if (-not [System.Net.IPAddress]::TryParse($Address, [ref]$parsed)) { return $false }
    if ($parsed.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { return $false }

    # TryParse accepts "1.1" and shortened forms; require the four dotted octets
    # to round-trip so only the canonical spelling passes.
    if ($parsed.ToString() -ne $Address) { return $false }

    $octet = $parsed.GetAddressBytes()

    # 192.0.0.9 and 192.0.0.10 are the only globally reachable hosts in 192.0.0.0/24
    if ($octet[0] -eq 192 -and $octet[1] -eq 0 -and $octet[2] -eq 0) {
        return ($octet[3] -eq 9 -or $octet[3] -eq 10)
    }
    if ($octet[0] -eq 0) { return $false }                                   # 0.0.0.0/8
    if ($octet[0] -eq 10) { return $false }                                  # 10.0.0.0/8 private
    if ($octet[0] -eq 127) { return $false }                                 # 127.0.0.0/8 loopback
    if ($octet[0] -eq 100 -and $octet[1] -ge 64 -and $octet[1] -le 127) { return $false }  # CGNAT
    if ($octet[0] -eq 169 -and $octet[1] -eq 254) { return $false }          # link-local
    if ($octet[0] -eq 172 -and $octet[1] -ge 16 -and $octet[1] -le 31) { return $false }   # private
    if ($octet[0] -eq 192 -and $octet[1] -eq 0 -and $octet[2] -eq 2) { return $false }      # TEST-NET-1
    if ($octet[0] -eq 192 -and $octet[1] -eq 88 -and $octet[2] -eq 99) { return $false }    # 6to4 relay
    if ($octet[0] -eq 192 -and $octet[1] -eq 168) { return $false }          # private
    if ($octet[0] -eq 198 -and ($octet[1] -eq 18 -or $octet[1] -eq 19)) { return $false }   # benchmark
    if ($octet[0] -eq 198 -and $octet[1] -eq 51 -and $octet[2] -eq 100) { return $false }    # TEST-NET-2
    if ($octet[0] -eq 203 -and $octet[1] -eq 0 -and $octet[2] -eq 113) { return $false }     # TEST-NET-3
    if ($octet[0] -ge 224) { return $false }                                 # multicast and reserved

    return $true
}

function Assert-FormalConnectionApproval {
    <#
        Validate every approval input before a formal external connection.

        The check runs once at the start of a run and again immediately before
        the connection, so an approval window that closed mid-run stops the
        connection. It creates no network object; a failure throws before any
        socket exists.

        Rehearsal never calls this: the caller skips the external action and no
        approval input is required.

        -VmSnapshot on the run is an attestation recorded in the artifacts. It is
        not verified here: a guest cannot confirm the hypervisor snapshot state,
        and a snapshot restore can roll back any attempt counter kept in the VM,
        so the single-attempt guarantee is enforced per run, not across runs.
    #>
    param(
        [Parameter(Mandatory = $true)]$Context,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$ApprovedStartUtc,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$ApprovedEndUtc,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$ApprovedComputerName,
        [Parameter(Mandatory = $true)][int]$MaxConnectionAttempts,
        [datetime]$NowUtc = (Get-Date).ToUniversalTime()
    )

    $external = $Context.scenario.external_connection
    $target = [string]$external.target
    if (-not (Test-ApprovedGlobalIPv4 $target)) {
        throw ("external_connection.target is not an approved global IPv4 literal: '" + $target +
            "'. Render scenario.json with tools/scenario_to_json.py --external-target.")
    }

    $port = 0
    if (-not [int]::TryParse([string]$external.port, [ref]$port) -or $port -lt 1 -or $port -gt 65535) {
        throw ("external_connection.port must be an integer in 1..65535, found '" +
            [string]$external.port + "'")
    }

    $protocol = "TCP"
    if ($external.PSObject.Properties.Name -contains "protocol") {
        $protocol = ([string]$external.protocol).ToUpper()
    }
    if ($protocol -ne "TCP") {
        throw ("external_connection.protocol must be TCP, found '" + $protocol + "'")
    }

    if ([string]::IsNullOrWhiteSpace($ApprovedComputerName)) {
        throw "ApprovedComputerName is required for a formal run"
    }
    if ($env:COMPUTERNAME -ne $ApprovedComputerName) {
        # -ne on strings is case-insensitive by default, which is the intended
        # exact-but-case-insensitive match for a Windows computer name.
        throw ("computer name mismatch: this host is '" + $env:COMPUTERNAME +
            "', approval is for '" + $ApprovedComputerName + "'")
    }

    # Same strict UTC parser as the worker (ConvertTo-ApprovedUtc): only ISO 8601
    # with a capital Z. A locale dependent or offset bearing value is refused
    # here, before a worker or a socket exists.
    $parsedStart = ConvertTo-ApprovedUtc -Value $ApprovedStartUtc -Label "ApprovedStartUtc"
    if (-not $parsedStart.ok) { throw $parsedStart.reason }
    $parsedEnd = ConvertTo-ApprovedUtc -Value $ApprovedEndUtc -Label "ApprovedEndUtc"
    if (-not $parsedEnd.ok) { throw $parsedEnd.reason }

    $start = $parsedStart.value
    $end = $parsedEnd.value
    if ($start -ge $end) {
        throw ("approved window is empty: start " + (Get-UtcStamp $start) +
            " is not before end " + (Get-UtcStamp $end))
    }

    $now = $NowUtc.ToUniversalTime()
    if ($now -lt $start -or $now -ge $end) {
        throw ("current UTC " + (Get-UtcStamp $now) + " is outside the approved window " +
            (Get-UtcStamp $start) + " .. " + (Get-UtcStamp $end))
    }

    if ($MaxConnectionAttempts -ne 1) {
        throw ("formal MaxConnectionAttempts must be exactly 1, found " + $MaxConnectionAttempts)
    }

    return [ordered]@{
        target       = $target
        port         = $port
        protocol     = $protocol
        computer     = $ApprovedComputerName
        window_start = $start
        window_end   = $end
        max_attempts = $MaxConnectionAttempts
    }
}

# The only accepted spellings of an approved time: ISO 8601 UTC with a capital
# Z, with or without fractional seconds. "T" and "Z" are quoted so they are
# literals, and AssumeUniversal + AdjustToUniversal then read the value as UTC.
# There is deliberately no locale fallback and no offset form: "+00:00" and a
# value with no offset at all are both refused, so the parent and the worker
# can never disagree about what an input means.
$APPROVED_UTC_FORMATS = [string[]]@(
    "yyyy-MM-dd'T'HH:mm:ss'Z'",
    "yyyy-MM-dd'T'HH:mm:ss.FFFFFFF'Z'"
)

function ConvertTo-ApprovedUtc {
    <#
        Parse one approved time string as strict ISO 8601 UTC.

        This is the single parser for approved times. The parent gate and the
        worker both call it - the worker dot-sources this file - so an input can
        never be accepted in one place and refused in the other.

        Returns ok, the UTC value, and a reason when it is refused.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][AllowNull()][string]$Value,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $parsed = [datetime]::MinValue
    $ok = [datetime]::TryParseExact(
        [string]$Value,
        $APPROVED_UTC_FORMATS,
        [System.Globalization.CultureInfo]::InvariantCulture,
        ([System.Globalization.DateTimeStyles]::AssumeUniversal -bor
            [System.Globalization.DateTimeStyles]::AdjustToUniversal),
        [ref]$parsed)

    if (-not $ok) {
        return [ordered]@{
            ok     = $false
            value  = $null
            reason = ($Label + " must be ISO 8601 UTC ending in 'Z' " +
                "(yyyy-MM-ddTHH:mm:ss[.fffffff]Z), found '" + [string]$Value + "'")
        }
    }

    return [ordered]@{ ok = $true; value = $parsed; reason = $null }
}

function Test-ApprovalWindowNow {
    <#
        Decide whether a moment falls inside the approved UTC window.

        Both bounds are parsed with InvariantCulture and AssumeUniversal +
        AdjustToUniversal, so a value without an offset is read as UTC and never
        as local time. The window is half open: approved_start <= now < approved_end.

        Returns allowed, a reason for a refusal, and the UTC moment that was
        checked. The reasons are the error_kind values the worker status records.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$ApprovedStartUtc,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$ApprovedEndUtc,
        [Parameter(Mandatory = $true)][datetime]$NowUtc
    )

    $now = $NowUtc.ToUniversalTime()

    # The same strict parser the parent gate uses, so an input the parent
    # accepted cannot be read differently here.
    $parsedStart = ConvertTo-ApprovedUtc -Value $ApprovedStartUtc -Label "ApprovedStartUtc"
    $parsedEnd = ConvertTo-ApprovedUtc -Value $ApprovedEndUtc -Label "ApprovedEndUtc"
    if (-not $parsedStart.ok -or -not $parsedEnd.ok) {
        return [ordered]@{ allowed = $false; reason = "approval_window_malformed"; now = $now }
    }

    $start = $parsedStart.value
    $end = $parsedEnd.value

    if ($start -ge $end) {
        return [ordered]@{ allowed = $false; reason = "approval_window_invalid_range"; now = $now }
    }
    if ($now -lt $start) {
        return [ordered]@{ allowed = $false; reason = "approval_window_not_started"; now = $now }
    }
    if ($now -ge $end) {
        return [ordered]@{ allowed = $false; reason = "approval_window_expired"; now = $now }
    }

    return [ordered]@{ allowed = $true; reason = $null; now = $now }
}

function Get-WorkerLaunch {
    <#
        Build the executable and argument list that starts the worker.

        This is the single place a worker command line is produced: the runner
        starts the process with exactly what this returns, and the tests check
        the same values without starting a process.

        Two launch modes, chosen explicitly by the caller, never by a default:

          EncodedCommand  Attack A01. PowerShell is launched with
                          -EncodedCommand so the process command line carries the
                          option the S0 Attack contract requires and the Evidence
                          extractor looks for. The encoded text is a fixed
                          bootstrap this function builds; it only invokes the
                          worker script this repository wrote, with the channel
                          directory as a parameter. No user supplied command
                          string is ever encoded or executed, and the worker
                          still reads nothing executable from the trigger.

          File            Normal N02. The worker is started with -File, so the
                          normal run's command line has no encoded option and
                          produces no encoded_powershell_command Evidence.

        -EncodedCommand takes UTF-16LE text encoded as Base64, which is what
        PowerShell expects. Paths are embedded as single quoted PowerShell
        literals with any quote doubled, so a path cannot break out of the
        literal.
    #>
    param(
        [Parameter(Mandatory = $true)][ValidateSet("EncodedCommand", "File")][string]$LaunchMode,
        [Parameter(Mandatory = $true)][string]$WorkerPath,
        [Parameter(Mandatory = $true)][string]$ChannelDir
    )

    if ($LaunchMode -eq "EncodedCommand") {
        $bootstrap = "& '" + $WorkerPath.Replace("'", "''") + "' -ChannelDir '" +
            $ChannelDir.Replace("'", "''") + "'"
        $encoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($bootstrap))

        # -File must not appear here: the Evidence extractor stops at a -File or
        # -Command token before it reaches -EncodedCommand.
        return [ordered]@{
            launch_mode = $LaunchMode
            executable  = "powershell.exe"
            arguments   = @("-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                "-EncodedCommand", $encoded)
            bootstrap   = $bootstrap
        }
    }

    return [ordered]@{
        launch_mode = $LaunchMode
        executable  = "powershell.exe"
        arguments   = @("-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
            "-File", $WorkerPath, "-ChannelDir", $ChannelDir)
        bootstrap   = $null
    }
}

function Invoke-ApprovedTcpAttempt {
    <#
        The worker side of the safety gate, followed by at most one TCP connect.

        The parent already checked the approval before starting the worker and
        again before writing the trigger. This runs inside the worker process
        immediately before a socket would exist, so an approval window that
        closed between the parent's check and this moment still stops the
        connection.

        Order: re-validate the approved target, port, protocol and attempt count
        from the config, then parse the approved UTC window, take the current
        UTC, and only if the moment is inside the window create the client. On
        any refusal no client is created, attempts_made stays 0 and the status
        carries the reason and the moment that was checked.

        NowUtcProvider and ClientFactory are the only seams: production uses the
        real clock and a real TcpClient, and the tests pass a fake clock and a
        fake client factory so no socket is ever created. There is no way to
        skip the approval check.
    #>
    param(
        [Parameter(Mandatory = $true)]$Config,
        [scriptblock]$NowUtcProvider = { (Get-Date).ToUniversalTime() },
        [scriptblock]$ClientFactory = { New-Object System.Net.Sockets.TcpClient }
    )

    $target = [string]$Config.target
    $port = 0
    $protocol = ([string]$Config.protocol).ToUpper()
    $attempts = 0
    $timeoutMs = [int]$Config.timeout_ms

    $checkedUtc = (& $NowUtcProvider).ToUniversalTime()

    $refusal = $null
    if (-not (Test-ApprovedGlobalIPv4 $target)) {
        $refusal = "target_not_approved"
    } elseif (-not [int]::TryParse([string]$Config.port, [ref]$port) -or
        $port -lt 1 -or $port -gt 65535) {
        $refusal = "port_not_approved"
    } elseif ($protocol -ne "TCP") {
        $refusal = "protocol_not_approved"
    } elseif (-not [int]::TryParse([string]$Config.max_attempts, [ref]$attempts) -or $attempts -ne 1) {
        $refusal = "attempts_not_approved"
    }

    if ($null -eq $refusal) {
        $window = Test-ApprovalWindowNow -ApprovedStartUtc ([string]$Config.approved_start_utc) `
            -ApprovedEndUtc ([string]$Config.approved_end_utc) -NowUtc $checkedUtc
        if (-not $window.allowed) { $refusal = [string]$window.reason }
    }

    if ($null -ne $refusal) {
        # No socket object is created on this path.
        return [ordered]@{
            pid           = $PID
            target        = $target
            port          = [int]$Config.port
            protocol      = $protocol
            checked_utc   = (Get-UtcStamp $checkedUtc)
            started_utc   = $null
            ended_utc     = $null
            success       = $false
            timed_out     = $false
            error_kind    = $refusal
            attempts_made = 0
        }
    }

    $startedUtc = (& $NowUtcProvider).ToUniversalTime()
    $success = $false
    $timedOut = $false
    $errorKind = $null
    $client = $null
    try {
        $client = & $ClientFactory
        $async = $client.BeginConnect($target, $port, $null, $null)
        if ($async.AsyncWaitHandle.WaitOne($timeoutMs, $false) -and $client.Connected) {
            $client.EndConnect($async)
            $success = $true
        } else {
            $timedOut = $true
            $errorKind = "timeout"
        }
    } catch {
        $errorKind = $_.Exception.GetType().Name
    } finally {
        if ($null -ne $client) { $client.Close() }
    }
    $endedUtc = (& $NowUtcProvider).ToUniversalTime()

    return [ordered]@{
        pid           = $PID
        target        = $target
        port          = $port
        protocol      = $protocol
        checked_utc   = (Get-UtcStamp $checkedUtc)
        started_utc   = (Get-UtcStamp $startedUtc)
        ended_utc     = (Get-UtcStamp $endedUtc)
        success       = $success
        timed_out     = $timedOut
        error_kind    = $errorKind
        attempts_made = 1
    }
}

function New-ConnectionWorker {
    <#
        Start a harmless PowerShell worker whose own process makes the approved
        connection, so the Sysmon EID 3 ProcessGuid equals this process's EID 1
        ProcessGuid (docs/scenarios/s0.md section 4-2).

        The worker reads only approved values from a JSON config in a
        run-specific channel directory: the target, port, protocol, attempt count
        and the approved UTC window. It never reads a command string from the
        trigger and never uses Invoke-Expression. The channel directory must not
        already exist, so a trigger or status file from an earlier run cannot be
        reused.

        -LaunchMode is mandatory and decides the process command line
        (Get-WorkerLaunch): the attack run asks for EncodedCommand, the normal
        run asks for File. Nothing falls back to a default, so the two runs
        cannot silently produce the same Evidence.

        The process is returned WITHOUT waiting for it to exit; it stays alive so
        the connection happens inside it and is stopped by Stop-ConnectionWorker
        after the run.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$WorkDir,
        [Parameter(Mandatory = $true)][string]$RunId,
        [Parameter(Mandatory = $true)]$Approval,
        [Parameter(Mandatory = $true)][ValidateSet("EncodedCommand", "File")][string]$LaunchMode,
        [int]$ConnectTimeoutMs = 3000,
        [int]$IdleSeconds = 3600
    )

    $channelDir = Join-Path $WorkDir ("s0_conn_" + $RunId)
    if (Test-Path -LiteralPath $channelDir) {
        throw ("connection channel already exists for this run: " + $channelDir +
            ". A previous run's trigger/status must not be reused.")
    }
    New-Item -ItemType Directory -Path $channelDir -Force | Out-Null

    $config = [ordered]@{
        target             = $Approval.target
        port               = $Approval.port
        protocol           = $Approval.protocol
        max_attempts       = $Approval.max_attempts
        approved_start_utc = (Get-UtcStamp $Approval.window_start)
        approved_end_utc   = (Get-UtcStamp $Approval.window_end)
        timeout_ms         = $ConnectTimeoutMs
        idle_sec           = $IdleSeconds
        run_common_path    = $RUN_COMMON_PATH
    }
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText((Join-Path $channelDir "s0_conn_config.json"),
        ($config | ConvertTo-Json), $utf8NoBom)

    # The worker script is fixed text. It waits for the trigger, then hands the
    # config to Invoke-ApprovedTcpAttempt, which re-checks the approval before a
    # socket can exist. It does no DNS, no TLS, no retry and sends zero
    # application bytes.
    $worker = @'
param([Parameter(Mandatory = $true)][string]$ChannelDir)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$config = Get-Content -LiteralPath (Join-Path $ChannelDir "s0_conn_config.json") -Raw -Encoding UTF8 |
    ConvertFrom-Json

# The gate and the single connect live in run-common.ps1 so the worker and the
# tests exercise exactly the same code.
. ([string]$config.run_common_path)

$triggerPath = Join-Path $ChannelDir "s0_conn_trigger"
$statusPath = Join-Path $ChannelDir "s0_conn_status.json"
$statusTmp = $statusPath + ".tmp"
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)

$deadline = (Get-Date).AddSeconds([int]$config.idle_sec)
while (-not (Test-Path -LiteralPath $triggerPath)) {
    if ((Get-Date) -ge $deadline) { return }
    Start-Sleep -Milliseconds 200
}

$status = Invoke-ApprovedTcpAttempt -Config $config

[System.IO.File]::WriteAllText($statusTmp, ($status | ConvertTo-Json), $utf8NoBom)
[System.IO.File]::Move($statusTmp, $statusPath)

# Stay alive so the ProcessGuid persists through the observation window; the
# orchestrator stops this process during cleanup.
Start-Sleep -Seconds ([int]$config.idle_sec)
'@
    $workerPath = Join-Path $channelDir "s0_worker.ps1"
    [System.IO.File]::WriteAllText($workerPath, $worker, $utf8NoBom)

    $launch = Get-WorkerLaunch -LaunchMode $LaunchMode -WorkerPath $workerPath -ChannelDir $channelDir
    $startedAt = Get-Date
    $process = Start-Process -FilePath $launch.executable -ArgumentList $launch.arguments `
        -WindowStyle Hidden -PassThru

    return [ordered]@{
        process     = $process
        started_at  = $startedAt
        channel_dir = $channelDir
        launch      = $launch
        trigger     = (Join-Path $channelDir "s0_conn_trigger")
        status      = (Join-Path $channelDir "s0_conn_status.json")
    }
}

function Invoke-WorkerConnection {
    <#
        Trigger the worker's single approved connection and wait for its status.

        The status carries the moment the worker actually attempted the
        connection; execution_record uses that time, not the moment the trigger
        was written. A timeout, a connection failure, a target or port mismatch,
        a refusal by the worker's own approval re-check (error_kind
        approval_window_not_started / approval_window_expired and the other
        approval_* reasons), or a missing status is a formal run failure.
    #>
    param(
        [Parameter(Mandatory = $true)]$Worker,
        [Parameter(Mandatory = $true)]$Approval,
        [int]$WaitTimeoutSec = 60,
        [int]$PollIntervalMs = 200
    )

    $triggerText = "connect " + (Get-Date).ToUniversalTime().ToString("o")
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Worker.trigger, $triggerText, $utf8NoBom)

    $deadline = (Get-Date).AddSeconds($WaitTimeoutSec)
    while (-not (Test-Path -LiteralPath $Worker.status)) {
        if ((Get-Date) -ge $deadline) {
            throw ("worker wrote no connection status within " + $WaitTimeoutSec + "s")
        }
        Start-Sleep -Milliseconds $PollIntervalMs
    }

    $status = Get-Content -LiteralPath $Worker.status -Raw -Encoding UTF8 | ConvertFrom-Json
    if (-not $status.success) {
        throw ("approved connection did not succeed: timed_out=" + $status.timed_out +
            " error_kind=" + [string]$status.error_kind +
            " checked_utc=" + [string]$status.checked_utc +
            " attempts_made=" + [string]$status.attempts_made)
    }
    if ([string]$status.target -ne [string]$Approval.target) {
        throw ("worker connected to '" + [string]$status.target + "', approved '" + $Approval.target + "'")
    }
    if ([int]$status.port -ne [int]$Approval.port) {
        throw ("worker connected to port " + [string]$status.port + ", approved " + $Approval.port)
    }
    if ([int]$status.attempts_made -ne 1) {
        throw ("worker reported " + [string]$status.attempts_made + " connection attempts, approved 1")
    }

    # The worker stamps its times with Get-UtcStamp, which is the same ISO 8601
    # UTC spelling the approved times use, so the same parser reads it back.
    $startedUtc = ConvertTo-ApprovedUtc -Value ([string]$status.started_utc) -Label "worker started_utc"
    if (-not $startedUtc.ok) { throw $startedUtc.reason }

    return [ordered]@{
        pid          = [int]$status.pid
        started_utc  = $startedUtc.value
        target       = [string]$status.target
        port         = [int]$status.port
        protocol     = [string]$status.protocol
    }
}

function Stop-ConnectionWorker {
    <#
        Stop the worker and remove its run-specific channel directory.

        Called during cleanup after the status has been read and the causality
        checked, so a formal failure never leaves a stray worker process or a
        reusable trigger/status behind.
    #>
    param([object]$Worker)

    if ($null -eq $Worker) { return }
    $process = $Worker.process
    if ($null -ne $process -and -not $process.HasExited) {
        $process.Kill()
        $process.WaitForExit()
    }
    if (-not [string]::IsNullOrEmpty([string]$Worker.channel_dir) -and
        (Test-Path -LiteralPath $Worker.channel_dir)) {
        Remove-Item -LiteralPath $Worker.channel_dir -Recurse -Force
    }
    Write-Ok "connection worker stopped and channel removed"
}

function Assert-FormalCausalityMatched {
    <#
        In a formal run the A01->A02 (or N02) causality must be "matched": the
        EID 3 ProcessGuid equals the worker's anchor ProcessGuid and the
        destination and port match. Anything else fails the run before any
        success artifact is written. Rehearsal keeps the not_verified result.
    #>
    param([Parameter(Mandatory = $true)]$Causality)

    if ($Causality.status -ne "matched") {
        throw ("formal causality check failed: " + $Causality.status + " (" + $Causality.reason + ")")
    }
}
