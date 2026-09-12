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

function New-RunContext {
    <#
        Validate the inputs and lay out the run directories.

        A run that performs an external connection requires a non-null
        external_connection.target in the scenario file. Collection runs stay
        blocked until the network isolation decision is recorded.
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

    $configSha256 = Get-Sha256 -Path $SysmonConfigPath
    if ($ExpectedSysmonConfigSha256 -and $configSha256 -ne $ExpectedSysmonConfigSha256.ToLower()) {
        throw "Sysmon config sha256 mismatch. expected=$ExpectedSysmonConfigSha256 actual=$configSha256"
    }

    # Rehearsal artifacts are not a valid S0 collection. Force them under a
    # separate output root so they are never mistaken for data/raw or
    # data/ground_truth, and drop a marker that says so. The run_id and the
    # RunMetadata contract are unchanged.
    $effectiveRoot = $DataRoot
    if ($Rehearsal) {
        $effectiveRoot = Join-Path $DataRoot "_rehearsal"
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
        sysmon_config_state  = (Get-SysmonConfigState -SysmonBinary $SysmonBinary)
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
    #>
    param(
        [Parameter(Mandatory = $true)][int]$ProcessId,
        [Parameter(Mandatory = $true)][datetime]$Since,
        [int]$TimeoutSec = 60,
        [int]$PollIntervalSec = 2
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    $filter = @{ LogName = $SYSMON_LOG; Id = 1; StartTime = $Since.AddSeconds(-5) }

    while ($true) {
        $events = @(Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue |
            Sort-Object RecordId)
        foreach ($event in $events) {
            $xml = [xml]$event.ToXml()
            $recordedPid = ($xml.Event.EventData.Data |
                Where-Object { $_.Name -eq "ProcessId" })."#text"
            if ($recordedPid -ne [string]$ProcessId) { continue }

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
        Write-Fail ("execution_record has " + $Context.execution_records.Count +
            " rows, the scenario expects " + $expected)
    }

    $path = Join-Path $Context.ground_truth_dir "execution_record.csv"
    $Context.execution_records |
        ForEach-Object { New-Object psobject -Property $_ } |
        Select-Object run_id, action_id, timestamp, action_type, description |
        Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
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
