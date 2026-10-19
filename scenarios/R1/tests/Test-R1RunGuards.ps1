<#
    .SYNOPSIS
        Regression checks for the R1-V02 Pilot runner in scenarios/R1.

    .DESCRIPTION
        Runs on the host. It needs no VM, no WinRM, no Sysmon and no Administrator
        rights, and it starts no scenario process and opens no socket: the
        transport, the clock, the sleeper and the TCP client are fakes, and every
        case works on temporary directories. The one program it starts is a
        stand-in for Sysmon64 - a .cmd file that writes prepared bytes - for the
        probe step (7), which runs in a background job.

        Covered:

        1. the destination gate (Test-R1InternalDestination) and the task's single
           TCP attempt (Invoke-R1InternalTcpAttempt) with a fake client factory,
        2. the launch plan (Get-R1LaunchPlan): both lineages, the same final tool
           and depth, only the intermediate differing, no encoded command option
           and no run type in anything Target-A would record,
        3. the fail-closed input checks of Invoke-R1PilotRun: a refused run opens
           no session and starts nothing,
        4. a complete run against the fake transport: call order and counts, the
           observation window on the fake clock, the four artifacts and their
           run_id, and the deterministic execution record,
        5. the lineage check (Test-R1RunLineage) and that a failure leaves no
           execution_record, run_metadata or manifest behind,
        6. the identity of a Pair (Get-R1PairIdentity): family, variation and
           repetition are read from the scenario, refused when missing, malformed
           or named after a run type, and written to RunMetadata unchanged by
           both runs,
        7. the probe step's query of Sysmon64, the one remote step executed here:
           UTF-16 and code-page stdout are read whether or not stderr carried
           anything, and a non-zero exit code, an empty or unreadable stdout, a
           missing config hash and a hash that is not the file's still stop the
           run,
        8. the dataset tier of a Pair: read from the scenario like the identity,
           refused when it is missing or unknown, never taken from a caller, and
           written to the operator trace of both runs unchanged,
        9. the reference of an attack run: which record is selected, when none
           is, and that its time and the two bounds of its window are UTC,
       10. the collection profile a scenario may state: an entry through WMI
           and its launch step, the boot-to-end raw window, the readiness
           record a run is given instead of connecting from the target, the
           collection provenance and its context records, and that a run of
           the session entry is planned, launched and exported as before,
       11. a run through WMI with -PositionFinality: the freeze request after
           the observation boundary, the wait for the producer's ack, the
           RecordId-bounded export next to the unchanged time-window export,
           run-finalized last, and the failures that leave no completed run.

        The repository has no PowerShell test harness, so this script is a plain
        runner: it prints one line per case and exits non-zero when any case fails.

            powershell -ExecutionPolicy Bypass -File scenarios\R1\tests\Test-R1RunGuards.ps1

        By default the cases use the small scenario below. -BaseScenarioJson runs
        the same cases against a rendered scenarios/R1/scenario.yaml:

            python tools/r1_scenario_to_json.py scenarios/R1/scenario.yaml --out build/R1/scenario.json `
                --repetition 1 --dataset-tier pilot
            powershell -ExecutionPolicy Bypass -File scenarios\R1\tests\Test-R1RunGuards.ps1 `
                -BaseScenarioJson build\R1\scenario.json

        NOTE: this file is intentionally ASCII only, for the same reason as the
        rest of scenarios/R1 - Windows PowerShell 5.1 misreads UTF-8 source files
        without a BOM.
#>

[CmdletBinding()]
param([string]$BaseScenarioJson)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "..\run-common.ps1")

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
        return
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
    $path = Join-Path ([System.IO.Path]::GetTempPath()) ("r1-guard-" + [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $path -Force | Out-Null
    $script:TempRoots.Add($path)
    return $path
}

 # ---------------------------------------------------------------------------
 # Scenario fixture
 # ---------------------------------------------------------------------------

 # The shape tools/r1_scenario_to_json.py renders from scenarios/R1/scenario.yaml,
 # with synthetic descriptions. Destination, lab network and host are filled in
 # per case; none of them is a real value.
$script:BaseScenarioText = @'
{
  "scenario_version": "v1",
  "scenario_id": "R1",
  "family_id": "remote_management",
  "variation_id": "V02",
  "repetition": 1,
  "dataset_tier": "pilot",
  "run_metadata": {
    "target_host": null,
    "sysmon_config_version": "sysmonconfig-sample-v0.1",
    "detector_set_version": null,
    "reference_policy_version": "r1-ref-v0.1",
    "schema_versions": {
      "run_metadata": "v0.2", "event": "v0.3", "evidence": "v0.2", "fast_hit": "v0.2",
      "detection_result": "v0.2", "fusion_result": "v0.3", "decision_result": "v0.2",
      "execution_record": "v0.1", "evaluation_input": "v0.1"
    }
  },
  "run_length": { "observation_sec": null, "evaluation_horizon_sec": 600 },
  "internal_connection": {
    "required": true, "target": null, "port": null, "protocol": "TCP",
    "lab_cidr": null, "max_attempts": 1
  },
  "planned_lineage": {
    "session_host": { "image": "wsmprovhost.exe" },
    "final_tool": {
      "image": "powershell.exe",
      "arguments": ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                    "-File", "{task_script}", "-ChannelDir", "{channel_dir}"]
    },
    "intermediate": {
      "normal": { "image": "cmd.exe", "launcher_kind": "batch", "launcher_file": "r1_launch.cmd",
                  "arguments": ["/d", "/c", "{launcher}"] },
      "attack": { "image": "cscript.exe", "launcher_kind": "jscript", "launcher_file": "r1_launch.js",
                  "arguments": ["//NoLogo", "//B", "{launcher}"] }
    }
  },
  "shortcut_controls": { "actions_per_run": 5 },
  "runs": {
    "normal": {
      "run_type": "normal", "reference_action_id": null,
      "actions": [
        { "action_id": "N01", "offset_sec": 0, "step": "session_begin", "action_type": "remote_session", "description": "open the remote session" },
        { "action_id": "N02", "offset_sec": 120, "step": "prepare", "action_type": "file_operation", "description": "common preparation" },
        { "action_id": "N03", "offset_sec": 300, "step": "launch", "action_type": "process_create", "description": "approved wrapper starts the final tool" },
        { "action_id": "N04", "offset_sec": 480, "step": "connect", "action_type": "network_connection", "description": "final tool connects internally" },
        { "action_id": "N05", "offset_sec": 600, "step": "session_end", "action_type": "remote_session", "description": "close the remote session" }
      ]
    },
    "attack": {
      "run_type": "attack", "reference_action_id": "A01",
      "actions": [
        { "action_id": "A01", "offset_sec": 0, "step": "session_begin", "action_type": "remote_session", "description": "open the remote session" },
        { "action_id": "A02", "offset_sec": 120, "step": "prepare", "action_type": "file_operation", "description": "common preparation" },
        { "action_id": "A03", "offset_sec": 300, "step": "launch", "action_type": "process_create", "description": "other intermediate starts the same final tool" },
        { "action_id": "A04", "offset_sec": 480, "step": "connect", "action_type": "network_connection", "description": "final tool connects internally" },
        { "action_id": "A05", "offset_sec": 600, "step": "session_end", "action_type": "remote_session", "description": "close the remote session" }
      ]
    }
  }
}
'@
if (-not [string]::IsNullOrEmpty($BaseScenarioJson)) {
    $script:BaseScenarioText = Get-Content -LiteralPath $BaseScenarioJson -Raw -Encoding UTF8
    Write-Host "scenario under test: $BaseScenarioJson" -ForegroundColor Cyan
}

$TEST_HOST = "TARGET-A"
$TEST_TARGET = "10.20.30.20"
$TEST_PORT = 8443
$TEST_LAB = "10.20.30.0/24"
$TEST_WORK = "C:\R1\work"
$TEST_CONFIG_SHA = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
$TEST_FAMILY = "remote_management"
$TEST_VARIATION = "V02"
$TEST_REPETITION = 1

function New-ScenarioObject {
    <# The fixture with the run inputs a renderer would inject. A $null value leaves the field null. #>
    param(
        [AllowNull()][string]$TargetHost = $TEST_HOST,
        [AllowNull()][string]$Target = $TEST_TARGET,
        [AllowNull()]$Port = $TEST_PORT,
        [AllowNull()][string]$LabCidr = $TEST_LAB,
        [string]$FamilyId = $TEST_FAMILY,
        [string]$VariationId = $TEST_VARIATION,
        [int]$Repetition = $TEST_REPETITION,
        # The tier a renderer would write for the Pair. The cases that are not
        # about the tier are rendered as pilot; the runner itself has no default.
        [string]$DatasetTier = "pilot"
    )

    $scenario = $script:BaseScenarioText | ConvertFrom-Json
    $scenario.family_id = $FamilyId
    $scenario.variation_id = $VariationId
    $scenario.repetition = $Repetition
    $scenario | Add-Member -NotePropertyName "dataset_tier" -NotePropertyValue $DatasetTier -Force
    $scenario.run_metadata.target_host = $null
    if (-not [string]::IsNullOrEmpty($TargetHost)) { $scenario.run_metadata.target_host = $TargetHost }
    $scenario.internal_connection.target = $null
    $scenario.internal_connection.port = $null
    $scenario.internal_connection.lab_cidr = $null
    if (-not [string]::IsNullOrEmpty($Target)) {
        $scenario.internal_connection.target = $Target
        $scenario.internal_connection.port = $Port
        $scenario.internal_connection.lab_cidr = $LabCidr
    }
    return $scenario
}

function Save-Scenario {
    param([Parameter(Mandatory = $true)]$Scenario)

    $path = Join-Path (New-TempRoot) "scenario.json"
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($path, ($Scenario | ConvertTo-Json -Depth 10), $utf8NoBom)
    return $path
}

 # ---------------------------------------------------------------------------
 # Fakes: clock, sleeper, transport
 # ---------------------------------------------------------------------------

$script:FakeNowProvider = { $script:FakeNow }
$script:FakeSleeper = {
    param($Seconds)
    $script:SleepCalls.Add([int]$Seconds)
    $script:FakeNow = $script:FakeNow.AddSeconds($Seconds)
}

function Reset-Fakes {
    param([hashtable]$Options = @{})

    $script:FakeNow = [datetime]::new(2030, 1, 1, 0, 0, 0, [System.DateTimeKind]::Utc)
    $script:SleepCalls = New-Object System.Collections.Generic.List[int]
    $script:FakeCalls = New-Object System.Collections.Generic.List[string]
    $script:FakeArguments = @{}
    $script:FakeOptions = $Options
    # When the session host of the scenario session was created on the fake
    # target, in the form Sysmon writes a time. Set when that session answers.
    $script:FakeSessionUtc = "2030-01-01 00:00:00.000"
}

function Get-FakeOption {
    param([string]$Name, $Default)
    if ($script:FakeOptions.ContainsKey($Name)) { return $script:FakeOptions[$Name] }
    return $Default
}

$SESSION_GUID = "{00000000-0000-0000-0000-000000004000}"
$INTERMEDIATE_GUID = "{00000000-0000-0000-0000-000000004100}"
$FINAL_GUID = "{00000000-0000-0000-0000-000000004200}"
$OUTSIDE_GUID = "{00000000-0000-0000-0000-000000000700}"

function New-SyntheticRecord {
    param([int]$RecordId, [int]$EventId, [string]$Computer, $EventData)

    return [ordered]@{
        RecordId    = $RecordId
        EventId     = $EventId
        TimeCreated = "2030-01-01T00:00:00.000Z"
        Channel     = "Microsoft-Windows-Sysmon/Operational"
        Computer    = $Computer
        Provider    = "Microsoft-Windows-Sysmon"
        EventData   = $EventData
    }
}

function New-SyntheticRecords {
    <#
        What Target-A's Sysmon would hold after a run: the session host, the
        intermediate, the final tool and, optionally, the final tool's connection.
        Every value is synthetic.

        -Protocol replaces the Protocol Sysmon wrote on the connection ($null is
        written as a JSON null) and -OmitProtocol leaves the field out.
    #>
    param(
        [string]$Computer = $TEST_HOST,
        [string]$IntermediateImage = "cmd.exe",
        [string]$FinalImage = "powershell.exe",
        [string]$SessionImage = "wsmprovhost.exe",
        [string]$ConnectionGuid = $FINAL_GUID,
        [AllowNull()][string]$DestinationIp = $TEST_TARGET,
        [AllowNull()][string]$DestinationPort = [string]$TEST_PORT,
        [AllowNull()]$Protocol = "tcp",
        [switch]$OmitProtocol,
        [switch]$DuplicateFinal,
        [string]$SessionUtcTime = "2030-01-01 00:00:00.000"
    )

    $records = New-Object System.Collections.Generic.List[object]
    $records.Add((New-SyntheticRecord 1 1 $Computer ([ordered]@{
        UtcTime = $SessionUtcTime
        ProcessGuid = $SESSION_GUID; ProcessId = "4000"; Image = ("C:\synthetic\" + $SessionImage)
        ParentProcessGuid = $OUTSIDE_GUID; ParentProcessId = "700" })))
    $records.Add((New-SyntheticRecord 2 1 $Computer ([ordered]@{
        ProcessGuid = $INTERMEDIATE_GUID; ProcessId = "4100"; Image = ("C:\synthetic\" + $IntermediateImage)
        ParentProcessGuid = $SESSION_GUID; ParentProcessId = "4000" })))
    $records.Add((New-SyntheticRecord 3 1 $Computer ([ordered]@{
        ProcessGuid = $FINAL_GUID; ProcessId = "4200"; Image = ("C:\synthetic\" + $FinalImage)
        ParentProcessGuid = $INTERMEDIATE_GUID; ParentProcessId = "4100" })))
    if ($DuplicateFinal) {
        $records.Add((New-SyntheticRecord 5 1 $Computer ([ordered]@{
            ProcessGuid = $FINAL_GUID; ProcessId = "4200"; Image = ("C:\synthetic\" + $FinalImage)
            ParentProcessGuid = $SESSION_GUID; ParentProcessId = "4000" })))
    }
    if (-not [string]::IsNullOrEmpty($DestinationIp)) {
        $connection = [ordered]@{
            ProcessGuid = $ConnectionGuid; ProcessId = "4200"; Image = ("C:\synthetic\" + $FinalImage)
            Protocol = $Protocol; DestinationIp = $DestinationIp; DestinationPort = $DestinationPort }
        if ($OmitProtocol) { $connection.Remove("Protocol") }
        $records.Add((New-SyntheticRecord 4 3 $Computer $connection))
    }

    return $records.ToArray()
}

function ConvertTo-ParsedRecords {
    <# The records as Test-R1RunLineage receives them: parsed back from JSON lines. #>
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Records)
    return @($Records | ForEach-Object { ($_ | ConvertTo-Json -Compress -Depth 5) | ConvertFrom-Json })
}

function New-FakeTransport {
    <#
        A transport that records every call and answers the way Target-A would,
        without a session, a process or a file copy. The synthetic telemetry it
        "collects" follows what the runner asked it to launch, so a wrong launch
        shows up in the lineage check the same way it would on a real target.
    #>
    return @{
        open    = {
            param($Connection)
            $script:FakeCalls.Add("open")
            # Opening a session takes time on both clocks.
            $script:FakeNow = $script:FakeNow.AddSeconds([int](Get-FakeOption "OpenSeconds" 0))
            # A scenario file that is replaced once the run is under way: the run
            # has read it by now, so neither its plan nor its trace may change.
            $overwrite = [string](Get-FakeOption "OverwriteScenarioOnOpen" "")
            if (-not [string]::IsNullOrEmpty($overwrite)) {
                [System.IO.File]::WriteAllText($overwrite, '{"scenario_id":"R1","replaced":true}')
            }
            return ("session-" + $script:FakeCalls.Count)
        }
        invoke  = {
            param($Session, $Step, $Arguments)
            $script:FakeCalls.Add("invoke:" + $Step)
            $script:FakeArguments[$Step] = $Arguments
            if ((Get-FakeOption "FailStep" "") -eq $Step) { throw ("synthetic failure in step " + $Step) }

            $utc = Get-UtcStamp $script:FakeNow
            if ($Step -eq "probe") {
                return @{
                    utc                    = $utc
                    computer_name          = (Get-FakeOption "ComputerName" $TEST_HOST)
                    recorded_computer_name = (Get-FakeOption "RecordedComputerName" $null)
                    sysmon                 = (Get-FakeOption "SysmonState" @{
                        config_file        = "synthetic.xml"
                        config_hash        = ("SHA256=" + (Get-FakeOption "AppliedConfigSha" $TEST_CONFIG_SHA))
                        hashing_algorithms = "SHA256"
                    })
                    config_sha256          = $TEST_CONFIG_SHA
                }
            }
            if ($Step -eq "begin") {
                $script:FakeSessionUtc = $script:FakeNow.ToString("yyyy-MM-dd HH:mm:ss.fff")
                return @{
                    utc           = (Get-FakeOption "BeginUtc" $utc)
                    session_pid   = 4000
                    session_image = (Get-FakeOption "SessionImage" "C:\synthetic\wsmprovhost.exe")
                    computer_name = $TEST_HOST
                }
            }
            if ($Step -eq "prepare") { return @{ utc = $utc } }
            if ($Step -eq "launch") { return @{ utc = $utc; intermediate_pid = 4100; final_pid = 4200 } }
            if ($Step -eq "trigger") {
                $config = ([string]$script:FakeArguments["prepare"].channel_config) | ConvertFrom-Json
                return @{
                    utc    = $utc
                    status = @{
                        pid           = 4200
                        target        = (Get-FakeOption "StatusTarget" ([string]$config.target))
                        port          = [string]$config.port
                        protocol      = "TCP"
                        checked_utc   = $utc
                        started_utc   = $utc
                        ended_utc     = $utc
                        success       = [bool](Get-FakeOption "TriggerSuccess" $true)
                        skipped       = $false
                        timed_out     = (-not [bool](Get-FakeOption "TriggerSuccess" $true))
                        error_kind    = $null
                        attempts_made = 1
                    }
                }
            }
            if ($Step -eq "end") { return @{ utc = $utc } }
            if ($Step -eq "export") { return @{ utc = $utc; evtx_path = [string]$Arguments.export_path } }
            if ($Step -eq "cleanup") { return @{ utc = $utc } }
            throw ("unexpected remote step: " + $Step)
        }
        fetch   = {
            param($Session, $RemotePath, $LocalPath)
            $script:FakeCalls.Add("fetch")
            [System.IO.File]::WriteAllText($LocalPath, "synthetic evtx placeholder")
        }
        close   = {
            param($Session)
            $script:FakeCalls.Add("close")
        }
        convert = {
            param($EvtxPath, $JsonlPath)
            $script:FakeCalls.Add("convert")

            $config = ([string]$script:FakeArguments["prepare"].channel_config) | ConvertFrom-Json
            $destinationIp = $null
            $destinationPort = $null
            if ([bool]$config.connect -and $script:FakeArguments.ContainsKey("trigger")) {
                $destinationIp = [string]$config.target
                $destinationPort = [string]$config.port
            }
            $records = New-SyntheticRecords `
                -IntermediateImage (Get-FakeOption "TelemetryIntermediateImage" ([string]$script:FakeArguments["launch"].executable)) `
                -ConnectionGuid (Get-FakeOption "ConnectionGuid" $FINAL_GUID) `
                -DestinationIp $destinationIp -DestinationPort $destinationPort `
                -Protocol (Get-FakeOption "TelemetryProtocol" "tcp") `
                -SessionUtcTime (Get-FakeOption "SessionUtcTime" $script:FakeSessionUtc)
            $records = @($records) + @(Get-FakeOption "ExtraRecords" @())

            $lines = @($records | ForEach-Object { $_ | ConvertTo-Json -Compress -Depth 5 })
            $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
            [System.IO.File]::WriteAllLines($JsonlPath, [string[]]$lines, $utf8NoBom)
            return $lines.Count
        }
    }
}

function Invoke-FakeRun {
    param(
        [string]$RunType = "normal",
        [string]$RunId = "RUN-20300101-001",
        [string]$ScenarioPath,
        [string]$DataRoot,
        [string]$WorkDir = $TEST_WORK,
        [int]$ObservationSec = 660,
        [string]$VmSnapshot = "synthetic-snapshot",
        [string]$TargetSysmonBinary = "C:\synthetic\Sysmon64.exe",
        [string]$TargetSysmonConfigPath = "C:\synthetic\sysmonconfig.xml",
        [AllowNull()][hashtable]$Transport,
        [AllowNull()]$Connection = @{ address = "synthetic"; port = 5985 },
        [switch]$Rehearsal,
        [switch]$DryRun
    )

    return (Invoke-R1PilotRun -RunType $RunType -RunId $RunId -ScenarioJsonPath $ScenarioPath `
        -DataRoot $DataRoot -WorkDir $WorkDir -ObservationSec $ObservationSec `
        -VmSnapshot $VmSnapshot `
        -TargetSysmonBinary $TargetSysmonBinary -TargetSysmonConfigPath $TargetSysmonConfigPath `
        -Connection $Connection -Transport $Transport `
        -NowProvider $script:FakeNowProvider -Sleeper $script:FakeSleeper `
        -Rehearsal:$Rehearsal -DryRun:$DryRun)
}

function Get-CallCount {
    param([string]$Name)
    return @($script:FakeCalls | Where-Object { $_ -eq $Name }).Count
}

function Test-SuccessArtifactsAbsent {
    <# True when none of the three files a valid run ends with exists. #>
    param([string]$Root, [string]$RunId)

    $paths = @(
        (Join-Path $Root "raw\$RunId\manifest.json"),
        (Join-Path $Root "ground_truth\$RunId\execution_record.csv"),
        (Join-Path $Root "ground_truth\$RunId\run_metadata.json")
    )
    return (@($paths | Where-Object { Test-Path -LiteralPath $_ }).Count -eq 0)
}

function Get-FileSha256 {
    <# SHA-256 of a file in lower case hex, computed here and not by the code under test. #>
    param([Parameter(Mandatory = $true)][string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLower()
}

function Get-TraceOf {
    <# The operator trace a run left under a root: its directory, its parsed record and its scenario copy. #>
    param([Parameter(Mandatory = $true)][string]$Root, [Parameter(Mandatory = $true)][string]$RunId)

    $dir = Join-Path $Root ("operator_trace\" + $RunId)
    $recordPath = Join-Path $dir "r1_run_trace.json"
    $record = $null
    if (Test-Path -LiteralPath $recordPath) {
        $record = Get-Content -LiteralPath $recordPath -Raw -Encoding UTF8 | ConvertFrom-Json
    }
    return [ordered]@{
        dir           = $dir
        record_path   = $recordPath
        record        = $record
        scenario_path = (Join-Path $dir "scenario.json")
    }
}

 # ---------------------------------------------------------------------------
 # 1. Destination gate
 # ---------------------------------------------------------------------------

Write-Host "`n=== internal destination gate ===" -ForegroundColor Cyan

foreach ($case in @(
    @("10.20.30.20", "10.20.30.0/24"), @("10.1.2.3", "10.0.0.0/8"),
    @("172.31.255.254", "172.16.0.0/12"), @("192.168.200.7", "192.168.200.0/24"),
    @("10.0.0.5", "10.0.0.4/30"))) {
    Assert-True ("internal host accepted: " + $case[0] + " in " + $case[1]) (
        (Test-R1InternalDestination -Address $case[0] -LabCidr $case[1]).ok)
}

foreach ($case in @(
    @("8.8.8.8", $TEST_LAB, "target_not_private"),
    @("203.0.113.9", $TEST_LAB, "target_not_private"),
    @("127.0.0.1", $TEST_LAB, "target_not_private"),
    @("169.254.10.10", $TEST_LAB, "target_not_private"),
    @("172.32.0.1", "172.16.0.0/12", "target_not_private"),
    @("10.20.31.20", $TEST_LAB, "target_outside_lab_network"),
    @("10.20.30.0", $TEST_LAB, "target_not_a_host_address"),
    @("10.20.30.255", $TEST_LAB, "target_not_a_host_address"),
    @("10.20.030.20", $TEST_LAB, "target_not_ipv4"),
    @(" 10.20.30.20", $TEST_LAB, "target_not_ipv4"),
    @("fe80::1", $TEST_LAB, "target_not_ipv4"),
    @("target-b", $TEST_LAB, "target_not_ipv4"),
    @("", $TEST_LAB, "target_not_ipv4"),
    @($TEST_TARGET, "", "lab_network_invalid"),
    @($TEST_TARGET, "10.20.30.1/24", "lab_network_invalid"),
    @($TEST_TARGET, "10.20.30.0/31", "lab_network_invalid"),
    @($TEST_TARGET, "10.20.30.0", "lab_network_invalid"),
    @($TEST_TARGET, "8.8.8.0/24", "lab_network_not_private"),
    @($TEST_TARGET, "192.168.0.0/15", "lab_network_not_private"))) {
    $result = Test-R1InternalDestination -Address $case[0] -LabCidr $case[1]
    Assert-True ("refused as " + $case[2] + ": '" + $case[0] + "' in '" + $case[1] + "'") (
        (-not $result.ok) -and $result.reason -eq $case[2])
}

 # ---------------------------------------------------------------------------
 # 2. The task's single TCP attempt
 # ---------------------------------------------------------------------------

Write-Host "`n=== task connection attempt ===" -ForegroundColor Cyan

$script:FakeClientsCreated = 0

function New-FakeTcpClient {
    <# A stand-in for TcpClient that records that it was created but opens nothing. #>
    $script:FakeClientsCreated++
    $handle = [pscustomobject]@{}
    $handle | Add-Member -MemberType ScriptMethod -Name WaitOne -Value { param($ms, $exit) return $true }
    $async = [pscustomobject]@{ AsyncWaitHandle = $handle }
    $client = [pscustomobject]@{ Connected = $true }
    $client | Add-Member -MemberType ScriptMethod -Name BeginConnect -Value {
        param($target, $port, $cb, $state) return $async
    }.GetNewClosure()
    $client | Add-Member -MemberType ScriptMethod -Name EndConnect -Value { param($a) }
    $client | Add-Member -MemberType ScriptMethod -Name Close -Value { }
    return $client
}

$fakeFactory = { New-FakeTcpClient }
$fixedClock = { [datetime]::new(2030, 1, 1, 0, 8, 0, [System.DateTimeKind]::Utc) }

function New-TaskConfig {
    param(
        [string]$Target = $TEST_TARGET,
        [object]$Port = $TEST_PORT,
        [string]$Protocol = "TCP",
        [string]$LabCidr = $TEST_LAB,
        [object]$MaxAttempts = 1,
        [object]$TimeoutMs = 3000
    )
    return [pscustomobject]@{
        connect      = $true
        target       = $Target
        port         = $Port
        protocol     = $Protocol
        lab_cidr     = $LabCidr
        max_attempts = $MaxAttempts
        timeout_ms   = $TimeoutMs
        idle_sec     = 10
    }
}

function Invoke-Attempt {
    param($Config)
    $script:FakeClientsCreated = 0
    return Invoke-R1InternalTcpAttempt -Config $Config -NowUtcProvider $fixedClock -ClientFactory $fakeFactory
}

$attempt = Invoke-Attempt (New-TaskConfig)
Assert-True "an internal destination is attempted" ($attempt.success -eq $true)
Assert-True "exactly one client is created" ($script:FakeClientsCreated -eq 1)
Assert-True "one attempt is recorded" ($attempt.attempts_made -eq 1)
Assert-True "the attempt records its own start time" ($attempt.started_utc -eq "2030-01-01T00:08:00.000Z")

foreach ($case in @(
    @{ name = "a global target"; config = (New-TaskConfig -Target "8.8.8.8"); reason = "target_not_private" },
    @{ name = "a target outside the lab network"; config = (New-TaskConfig -Target "10.20.31.20"); reason = "target_outside_lab_network" },
    @{ name = "a missing lab network"; config = (New-TaskConfig -LabCidr ""); reason = "lab_network_invalid" },
    @{ name = "a port out of range"; config = (New-TaskConfig -Port 70000); reason = "port_not_valid" },
    @{ name = "a non-TCP protocol"; config = (New-TaskConfig -Protocol "UDP"); reason = "protocol_not_tcp" },
    @{ name = "more than one attempt"; config = (New-TaskConfig -MaxAttempts 2); reason = "attempts_not_one" },
    @{ name = "a timeout out of range"; config = (New-TaskConfig -TimeoutMs 0); reason = "timeout_not_valid" })) {
    $refused = Invoke-Attempt $case.config
    Assert-True ($case.name + " is refused as " + $case.reason) (
        $refused.success -eq $false -and $refused.error_kind -eq $case.reason)
    Assert-True ($case.name + " creates no client") ($script:FakeClientsCreated -eq 0)
    Assert-True ($case.name + " counts no attempt") ($refused.attempts_made -eq 0)
}

 # ---------------------------------------------------------------------------
 # 3. Launch plan
 # ---------------------------------------------------------------------------

Write-Host "`n=== launch plan ===" -ForegroundColor Cyan

$planScenario = New-ScenarioObject
$normalPlan = Get-R1LaunchPlan -Scenario $planScenario -RunType "normal" -WorkDir $TEST_WORK
$attackPlan = Get-R1LaunchPlan -Scenario $planScenario -RunType "attack" -WorkDir $TEST_WORK
$sessionImage = [string]$planScenario.planned_lineage.session_host.image
$finalImage = [string]$planScenario.planned_lineage.final_tool.image
$normalImage = [string]$planScenario.planned_lineage.intermediate.normal.image
$attackImage = [string]$planScenario.planned_lineage.intermediate.attack.image

Assert-True "normal plan is the three step lineage of the scenario" (
    ($normalPlan.expected_lineage -join ">") -eq (@($finalImage, $normalImage, $sessionImage) -join ">"))
Assert-True "attack plan is the three step lineage of the scenario" (
    ($attackPlan.expected_lineage -join ">") -eq (@($finalImage, $attackImage, $sessionImage) -join ">"))
Assert-True "normal starts the scenario's wrapper" ($normalPlan.intermediate.executable -eq $normalImage)
Assert-True "attack starts the scenario's other intermediate" ($attackPlan.intermediate.executable -eq $attackImage)
Assert-True "both lineages have the same depth" (
    @($normalPlan.expected_lineage).Count -eq 3 -and @($attackPlan.expected_lineage).Count -eq 3)
Assert-True "both runs start the same final tool" ($normalPlan.final.executable -eq $attackPlan.final.executable)
Assert-True "both runs give the final tool the same command line" (
    $normalPlan.final.command_line -ceq $attackPlan.final.command_line)
Assert-True "the session host is the same in both lineages" (
    $normalPlan.expected_lineage[2] -eq $attackPlan.expected_lineage[2])
Assert-True "only the intermediate differs between the lineages" (
    $normalPlan.expected_lineage[0] -eq $attackPlan.expected_lineage[0] -and
    $normalPlan.expected_lineage[1] -ne $attackPlan.expected_lineage[1] -and
    $normalPlan.expected_lineage[2] -eq $attackPlan.expected_lineage[2])
Assert-True "both runs use the same work and channel directories" (
    $normalPlan.work_dir -eq $attackPlan.work_dir -and $normalPlan.channel_dir -eq $attackPlan.channel_dir)

$normalFiles = @($normalPlan.files.Keys) -join ","
$attackFiles = @($attackPlan.files.Keys) -join ","
Assert-True "both runs write the same file names in the same order" ($normalFiles -ceq $attackFiles)
$sameContent = $true
foreach ($name in $normalPlan.files.Keys) {
    if ([string]$normalPlan.files[$name] -cne [string]$attackPlan.files[$name]) { $sameContent = $false }
}
Assert-True "both runs write byte-identical files" $sameContent
Assert-True "the task file is the repository task script" (
    [string]$normalPlan.files["r1_task.ps1"] -ceq [System.IO.File]::ReadAllText($R1_TASK_SOURCE))

foreach ($name in @($normalPlan.files.Keys | Where-Object { $_ -ne "r1_task.ps1" })) {
    $content = [string]$normalPlan.files[$name]
    Assert-True ("launcher " + $name + " runs the final tool command line") (
        $content.Contains($normalPlan.final.command_line) -or
        $content.Contains($normalPlan.final.command_line.Replace("\", "\\")))
}
Assert-True "the intermediate is handed its own launcher" (
    (@($normalPlan.intermediate.arguments) -contains $normalPlan.intermediate.launcher_path) -and
    (@($attackPlan.intermediate.arguments) -contains $attackPlan.intermediate.launcher_path))
foreach ($case in @(@{ type = "normal"; plan = $normalPlan }, @{ type = "attack"; plan = $attackPlan })) {
    $entry = $planScenario.planned_lineage.intermediate.($case.type)
    $expectedPath = $TEST_WORK + "\" + [string]$entry.launcher_file
    $expectedArguments = @($entry.arguments | ForEach-Object { ([string]$_).Replace("{launcher}", $expectedPath) })
    Assert-True ($case.type + ": the intermediate gets the launcher and arguments the scenario gives that run type") (
        $case.plan.intermediate.launcher_path -ceq $expectedPath -and
        (@($case.plan.intermediate.arguments) -join " ") -ceq ($expectedArguments -join " "))
}
Assert-True "the two intermediates are handed different launchers" (
    $normalPlan.intermediate.launcher_path -ne $attackPlan.intermediate.launcher_path)

foreach ($plan in @($normalPlan, $attackPlan)) {
    $all = @($plan.intermediate.arguments) + @($plan.final.arguments)
    Assert-True ($plan.run_type + ": no argument is an encoded command option") (
        @($all | Where-Object { Test-R1EncodedOption $_ }).Count -eq 0)
    $exposed = @($plan.intermediate.executable, $plan.final.executable, $plan.work_dir, $plan.channel_dir) +
        $all + @($plan.files.Keys) + @($plan.intermediate.launcher_path)
    Assert-True ($plan.run_type + ": nothing Target-A records names the run type") (
        @($exposed | Where-Object { $_ -match "(?i)normal|attack|benign|malicious" }).Count -eq 0)
    $threw = $false
    try { Assert-R1PlanShortcutFree -Plan $plan } catch { $threw = $true }
    Assert-True ($plan.run_type + ": the plan passes the shortcut check") (-not $threw)
}

foreach ($token in @("-e", "-ec", "-en", "-enc", "-Enc", "-EncodedCommand", "-encodedcommand", "/enc", "/EncodedCommand")) {
    Assert-True ("encoded option detected: " + $token) (Test-R1EncodedOption $token)
}
foreach ($token in @("-ExecutionPolicy", "-File", "-NoProfile", "/d", "/c", "//B", "//NoLogo", "-", "", "enc")) {
    Assert-True ("not an encoded option: '" + $token + "'") (-not (Test-R1EncodedOption $token))
}

$encoded = New-ScenarioObject
$encoded.planned_lineage.final_tool.arguments = @("-NoProfile", "-enc", "{task_script}", "-ChannelDir", "{channel_dir}")
Assert-Throws "a final tool with an encoded command option is refused" {
    Assert-R1PlanShortcutFree -Plan (Get-R1LaunchPlan -Scenario $encoded -RunType "attack" -WorkDir $TEST_WORK)
} "*encoded command option*"

$labelled = New-ScenarioObject
$labelled.planned_lineage.intermediate.attack.launcher_file = "r1_attack_launch.js"
Assert-Throws "a launcher file that names the run type is refused" {
    Assert-R1PlanShortcutFree -Plan (Get-R1LaunchPlan -Scenario $labelled -RunType "attack" -WorkDir $TEST_WORK)
} "*expose the run type*"
Assert-Throws "a work directory that names the run type is refused" {
    Assert-R1PlanShortcutFree -Plan (Get-R1LaunchPlan -Scenario (New-ScenarioObject) -RunType "normal" -WorkDir "C:\R1\normal")
} "*expose the run type*"

$sameIntermediate = New-ScenarioObject
$sameIntermediate.planned_lineage.intermediate.attack.image = $normalImage
Assert-Throws "two run types with the same intermediate are refused" {
    Get-R1LaunchPlan -Scenario $sameIntermediate -RunType "attack" -WorkDir $TEST_WORK
} "*same image*"

foreach ($bad in @("C:\R1 work", "R1\work", "C:\R1\work;x", 'C:\R1\"work"', "\\share\work", "")) {
    Assert-Throws ("an unsafe work directory is refused: '" + $bad + "'") {
        Get-R1LaunchPlan -Scenario (New-ScenarioObject) -RunType "normal" -WorkDir $bad
    } "*WorkDir must be*"
}

 # Without a planned lineage there is nothing to start.
$noPlanned = New-ScenarioObject
$noPlanned.PSObject.Properties.Remove("planned_lineage")
Assert-Throws "a scenario without a planned lineage cannot be planned" {
    Get-R1LaunchPlan -Scenario $noPlanned -RunType "normal" -WorkDir $TEST_WORK
} "*planned_lineage is missing*"

 # ---------------------------------------------------------------------------
 # 3b. Pair identity: family, variation, repetition
 # ---------------------------------------------------------------------------

Write-Host "`n=== pair identity ===" -ForegroundColor Cyan

function ConvertTo-RenderedScenario {
    <# The scenario as the runner reads it: written as JSON and parsed back. #>
    param([Parameter(Mandatory = $true)]$Scenario)
    return (($Scenario | ConvertTo-Json -Depth 10) | ConvertFrom-Json)
}

$stated = Get-R1PairIdentity -Scenario (ConvertTo-RenderedScenario (New-ScenarioObject))
Assert-True "the identity of the Pair is read from the scenario" (
    $stated.family_id -ceq $TEST_FAMILY -and $stated.variation_id -ceq $TEST_VARIATION -and
    $stated.repetition -eq $TEST_REPETITION)
Assert-True "the identity is the three values and nothing else" (
    (@($stated.Keys) -join ",") -ceq "family_id,variation_id,repetition")

$anotherPair = Get-R1PairIdentity -Scenario (ConvertTo-RenderedScenario (
    New-ScenarioObject -FamilyId "family_x7" -VariationId "V09" -Repetition 4))
Assert-True "any valid family, variation and repetition are taken as stated" (
    $anotherPair.family_id -ceq "family_x7" -and $anotherPair.variation_id -ceq "V09" -and
    $anotherPair.repetition -eq 4)

function Assert-IdentityRefused {
    param([string]$Name, [scriptblock]$Change, [string]$MessageLike)

    $changed = New-ScenarioObject
    & $Change $changed
    Assert-Throws $Name { Get-R1PairIdentity -Scenario (ConvertTo-RenderedScenario $changed) } $MessageLike
}

foreach ($field in @("family_id", "variation_id")) {
    Assert-IdentityRefused ("an empty " + $field + " is refused") {
        param($s) $s.$field = "" } ("*" + $field + " must be a non-empty string*")
    Assert-IdentityRefused ("a blank " + $field + " is refused") {
        param($s) $s.$field = "   " } ("*" + $field + " must be a non-empty string*")
    Assert-IdentityRefused ("a missing " + $field + " is refused") {
        param($s) $s.$field = $null } ("*" + $field + " must be a non-empty string*")
    Assert-IdentityRefused ("a " + $field + " that is not text is refused") {
        param($s) $s.$field = 7 } ("*" + $field + " must be a non-empty string*")
    Assert-IdentityRefused ("a " + $field + " with surrounding whitespace is refused") {
        param($s) $s.$field = " padded" } ("*" + $field + " must not have surrounding whitespace*")
    foreach ($labelled in @("normal_ops", "Attack-set", "BENIGN1", "x_malicious")) {
        Assert-IdentityRefused ("a " + $field + " that names a run type is refused: " + $labelled) {
            param($s) $s.$field = $labelled } ("*" + $field + " would expose the run type*")
    }
}

foreach ($bad in @(0, -1, 1.5, "1", $true, $null)) {
    Assert-IdentityRefused ("a repetition that is not an integer of 1 or more is refused: '" + [string]$bad + "'") {
        param($s) $s.repetition = $bad } "*repetition must be an integer of 1 or more*"
}

 # ---------------------------------------------------------------------------
 # 4. Fail-closed inputs: a refused run opens no session and starts nothing
 # ---------------------------------------------------------------------------

Write-Host "`n=== fail-closed inputs ===" -ForegroundColor Cyan

$goodScenario = Save-Scenario (New-ScenarioObject)

function Assert-RefusedBeforeAnyCall {
    param([string]$Name, [scriptblock]$Action, [string]$MessageLike)

    Reset-Fakes
    Assert-Throws $Name $Action $MessageLike
    Assert-True ($Name + " - no session, launch or connection") ($script:FakeCalls.Count -eq 0)
    Assert-True ($Name + " - nothing was waited for") ($script:SleepCalls.Count -eq 0)
}

Assert-RefusedBeforeAnyCall "a malformed run_id" {
    Invoke-FakeRun -RunId "RUN-2030-1" -ScenarioPath $goodScenario -DataRoot (New-TempRoot) -Transport (New-FakeTransport)
} "*run_id must match*"
Assert-RefusedBeforeAnyCall "an empty run_id" {
    Invoke-FakeRun -RunId "" -ScenarioPath $goodScenario -DataRoot (New-TempRoot) -Transport (New-FakeTransport)
} "*run_id must match*"
Assert-RefusedBeforeAnyCall "an unknown run type" {
    Invoke-FakeRun -RunType "other" -ScenarioPath $goodScenario -DataRoot (New-TempRoot) -Transport (New-FakeTransport)
} "*RunType must be one of*"
 # The dataset tier belongs to the Pair. The rendered scenario states it once for
 # both runs and the runner has no parameter for it: a scenario that states none,
 # or one the runner does not know, is refused before anything is opened, in a
 # dry run too, and the scenario of a rehearsal has to state pilot.
function Save-ScenarioWithTier {
    <# A rendered scenario whose dataset_tier is the given JSON value. -Omit leaves the field out. #>
    param([AllowNull()]$Tier, [switch]$Omit)

    $scenario = New-ScenarioObject
    if ($Omit) {
        $scenario.PSObject.Properties.Remove("dataset_tier")
    } else {
        $scenario.dataset_tier = $Tier
    }
    return (Save-Scenario $scenario)
}

$tierOmitted = Save-ScenarioWithTier -Omit
$tierNull = Save-ScenarioWithTier -Tier $null
$tierEmpty = Save-ScenarioWithTier -Tier ""
foreach ($case in @(
    @("a scenario that states no dataset tier", $tierOmitted),
    @("a scenario whose dataset tier is null", $tierNull),
    @("a scenario whose dataset tier is empty", $tierEmpty))) {
    Assert-RefusedBeforeAnyCall $case[0] {
        Invoke-FakeRun -ScenarioPath $case[1] -DataRoot (New-TempRoot) -Transport (New-FakeTransport)
    } "*dataset_tier is missing from the scenario*There is no default*--dataset-tier*"
    Assert-RefusedBeforeAnyCall ("a dry run of " + $case[0]) {
        Invoke-FakeRun -ScenarioPath $case[1] -DataRoot (New-TempRoot) -Transport $null -DryRun
    } "*dataset_tier is missing from the scenario*"
}
foreach ($unknownTier in @("formal", "Pilot", "DEVELOPMENT", " development", "development ", "dev", "hold-out",
        "pilot,development", "   ", 1, $true)) {
    $unknownTierPath = Save-ScenarioWithTier -Tier $unknownTier
    Assert-RefusedBeforeAnyCall ("a scenario with a dataset tier the runner does not know: '" + [string]$unknownTier + "'") {
        Invoke-FakeRun -ScenarioPath $unknownTierPath -DataRoot (New-TempRoot) -Transport (New-FakeTransport)
    } "*dataset_tier must be one of pilot, development, holdout*"
}
Assert-RefusedBeforeAnyCall "a dry run of a scenario with a dataset tier the runner does not know" {
    Invoke-FakeRun -ScenarioPath (Save-ScenarioWithTier -Tier "formal") -DataRoot (New-TempRoot) -Transport $null -DryRun
} "*dataset_tier must be one of*"
foreach ($formalTier in @("development", "holdout")) {
    $formalTierPath = Save-ScenarioWithTier -Tier $formalTier
    Assert-RefusedBeforeAnyCall ("a rehearsal of a scenario rendered as " + $formalTier) {
        Invoke-FakeRun -ScenarioPath $formalTierPath -DataRoot (New-TempRoot) -Transport (New-FakeTransport) -Rehearsal
    } "*a rehearsal is not formal data*dataset_tier pilot*"
    Assert-RefusedBeforeAnyCall ("a dry run of a rehearsal of a scenario rendered as " + $formalTier) {
        Invoke-FakeRun -ScenarioPath $formalTierPath -DataRoot (New-TempRoot) -Transport $null -Rehearsal -DryRun
    } "*a rehearsal is not formal data*"
}

 # One tier for the Pair: a run block cannot state its own.
foreach ($runType in @("normal", "attack")) {
    $ownTier = New-ScenarioObject
    $ownTier.runs.$runType | Add-Member -NotePropertyName "dataset_tier" -NotePropertyValue "holdout"
    $ownTierPath = Save-Scenario $ownTier
    Assert-RefusedBeforeAnyCall ("a " + $runType + " run block that states its own dataset tier") {
        Invoke-FakeRun -RunType $runType -ScenarioPath $ownTierPath -DataRoot (New-TempRoot) -Transport (New-FakeTransport)
    } ("*runs." + $runType + " states dataset_tier; a Pair states it once at the top level*")
}

 # Nothing a caller passes can state or replace the tier: no function of the
 # runner and neither run script has a parameter for it.
$tierParameters = @(foreach ($name in @("Invoke-R1PilotRun", "Assert-R1RunInputs", "Write-R1RunTrace")) {
    (Get-Command $name).Parameters.Keys | Where-Object { $_ -like "*Tier*" }
})
Assert-True "no function of the runner takes a dataset tier" ($tierParameters.Count -eq 0)
foreach ($runType in @("normal", "attack")) {
    $scriptParameters = (Get-Command (Join-Path $PSScriptRoot ("..\" + $runType + "\run.ps1"))).Parameters.Keys
    Assert-True ($runType + "\run.ps1 has no dataset tier parameter") (
        @($scriptParameters | Where-Object { $_ -like "*Tier*" }).Count -eq 0 -and
        @($scriptParameters | Where-Object { $_ -eq "ScenarioJsonPath" }).Count -eq 1)
}
Assert-RefusedBeforeAnyCall "the dataset tier argument of the earlier interface is not accepted any more" {
    Invoke-R1PilotRun -RunType "normal" -RunId "RUN-20300101-001" -ScenarioJsonPath $goodScenario `
        -DataRoot (New-TempRoot) -WorkDir $TEST_WORK -ObservationSec 660 -DatasetTier "development" `
        -VmSnapshot "synthetic-snapshot" -Transport (New-FakeTransport) -DryRun
} "*DatasetTier*"

 # A reference is only readable together with the policy it was taken under. A
 # scenario whose attack run names a reference action has to state the version,
 # for both runs of the Pair and before anything is opened. No value is fixed by
 # the runner: any non-blank version is taken as the scenario states it.
foreach ($blankPolicy in @($null, "", "   ", 7)) {
    $noPolicy = New-ScenarioObject
    $noPolicy.run_metadata.reference_policy_version = $blankPolicy
    $noPolicyPath = Save-Scenario $noPolicy
    foreach ($runType in @("attack", "normal")) {
        Assert-RefusedBeforeAnyCall ("a " + $runType + " run of a scenario that names an attack reference and states the policy version '" + [string]$blankPolicy + "'") {
            Invoke-FakeRun -RunType $runType -ScenarioPath $noPolicyPath -DataRoot (New-TempRoot) -Transport (New-FakeTransport)
        } "*run_metadata.reference_policy_version must be a non-blank string when runs.attack.reference_action_id is set*"
    }
    Assert-RefusedBeforeAnyCall ("a dry run of a scenario that names an attack reference and states the policy version '" + [string]$blankPolicy + "'") {
        Invoke-FakeRun -RunType "attack" -ScenarioPath $noPolicyPath -DataRoot (New-TempRoot) -Transport $null -DryRun
    } "*run_metadata.reference_policy_version must be a non-blank string*"
}

Assert-RefusedBeforeAnyCall "a missing scenario file" {
    Invoke-FakeRun -ScenarioPath (Join-Path (New-TempRoot) "absent.json") -DataRoot (New-TempRoot) -Transport (New-FakeTransport)
} "*scenario JSON not found*"
Assert-RefusedBeforeAnyCall "an empty data root" {
    Invoke-FakeRun -ScenarioPath $goodScenario -DataRoot "" -Transport (New-FakeTransport)
} "*DataRoot is required*"
Assert-RefusedBeforeAnyCall "an unsafe work directory" {
    Invoke-FakeRun -ScenarioPath $goodScenario -DataRoot (New-TempRoot) -WorkDir "C:\R1 work" -Transport (New-FakeTransport)
} "*WorkDir must be*"
Assert-RefusedBeforeAnyCall "an observation window shorter than the last action" {
    Invoke-FakeRun -ScenarioPath $goodScenario -DataRoot (New-TempRoot) -ObservationSec 599 -Transport (New-FakeTransport)
} "*does not cover the last action*"
Assert-RefusedBeforeAnyCall "a collection run without an internal destination" {
    Invoke-FakeRun -ScenarioPath (Save-Scenario (New-ScenarioObject -Target $null)) -DataRoot (New-TempRoot) -Transport (New-FakeTransport)
} "*internal_connection.target is null*"
Assert-RefusedBeforeAnyCall "a globally routable destination" {
    Invoke-FakeRun -ScenarioPath (Save-Scenario (New-ScenarioObject -Target "8.8.8.8")) -DataRoot (New-TempRoot) -Transport (New-FakeTransport)
} "*not an approved internal destination (target_not_private)*"
Assert-RefusedBeforeAnyCall "a destination outside the lab network" {
    Invoke-FakeRun -ScenarioPath (Save-Scenario (New-ScenarioObject -Target "10.20.31.20")) -DataRoot (New-TempRoot) -Transport (New-FakeTransport)
} "*target_outside_lab_network*"
Assert-RefusedBeforeAnyCall "a destination without a lab network" {
    Invoke-FakeRun -ScenarioPath (Save-Scenario (New-ScenarioObject -LabCidr $null)) -DataRoot (New-TempRoot) -Transport (New-FakeTransport)
} "*lab_network_invalid*"
Assert-RefusedBeforeAnyCall "a rehearsal with a globally routable destination" {
    Invoke-FakeRun -ScenarioPath (Save-Scenario (New-ScenarioObject -Target "8.8.8.8")) -DataRoot (New-TempRoot) -Transport (New-FakeTransport) -Rehearsal
} "*target_not_private*"
Assert-RefusedBeforeAnyCall "a port out of range" {
    Invoke-FakeRun -ScenarioPath (Save-Scenario (New-ScenarioObject -Port 70000)) -DataRoot (New-TempRoot) -Transport (New-FakeTransport)
} "*internal_connection.port*"
Assert-RefusedBeforeAnyCall "a missing target host" {
    Invoke-FakeRun -ScenarioPath (Save-Scenario (New-ScenarioObject -TargetHost $null)) -DataRoot (New-TempRoot) -Transport (New-FakeTransport)
} "*target_host is null*"
Assert-RefusedBeforeAnyCall "a missing snapshot attestation" {
    Invoke-FakeRun -ScenarioPath $goodScenario -DataRoot (New-TempRoot) -VmSnapshot "" -Transport (New-FakeTransport)
} "*VmSnapshot is required*"
Assert-RefusedBeforeAnyCall "a missing Sysmon binary path" {
    Invoke-FakeRun -ScenarioPath $goodScenario -DataRoot (New-TempRoot) -TargetSysmonBinary "" -Transport (New-FakeTransport)
} "*TargetSysmonBinary is required*"
Assert-RefusedBeforeAnyCall "a missing Sysmon config path" {
    Invoke-FakeRun -ScenarioPath $goodScenario -DataRoot (New-TempRoot) -TargetSysmonConfigPath "" -Transport (New-FakeTransport)
} "*TargetSysmonConfigPath is required*"
Assert-RefusedBeforeAnyCall "a missing connection" {
    Invoke-FakeRun -ScenarioPath $goodScenario -DataRoot (New-TempRoot) -Connection $null -Transport (New-FakeTransport)
} "*Connection is required*"
Assert-RefusedBeforeAnyCall "a missing transport" {
    Invoke-FakeRun -ScenarioPath $goodScenario -DataRoot (New-TempRoot) -Transport $null
} "*Transport is required*"

$wrongScenario = New-ScenarioObject
$wrongScenario.scenario_id = "S0"
Assert-RefusedBeforeAnyCall "a scenario that is not R1" {
    Invoke-FakeRun -ScenarioPath (Save-Scenario $wrongScenario) -DataRoot (New-TempRoot) -Transport (New-FakeTransport)
} "*scenario_id must be R1*"

$reorderedScenario = New-ScenarioObject
$reorderedScenario.runs.normal.actions = @($reorderedScenario.runs.normal.actions[0],
    $reorderedScenario.runs.normal.actions[2], $reorderedScenario.runs.normal.actions[1],
    $reorderedScenario.runs.normal.actions[3], $reorderedScenario.runs.normal.actions[4])
Assert-RefusedBeforeAnyCall "a scenario whose steps are out of order" {
    Invoke-FakeRun -ScenarioPath (Save-Scenario $reorderedScenario) -DataRoot (New-TempRoot) -Transport (New-FakeTransport)
} "*in that order*"

 # The reference action: an attack run names the action that opens the session,
 # a normal run names none.
$noReference = New-ScenarioObject
$noReference.runs.attack.reference_action_id = $null
Assert-RefusedBeforeAnyCall "an attack run whose scenario names no reference action" {
    Invoke-FakeRun -RunType "attack" -ScenarioPath (Save-Scenario $noReference) -DataRoot (New-TempRoot) -Transport (New-FakeTransport)
} "*runs.attack.reference_action_id is missing*"
$otherReference = New-ScenarioObject
$otherReference.runs.attack.reference_action_id = "A03"
Assert-RefusedBeforeAnyCall "an attack run whose reference action is not the one that opens the session" {
    Invoke-FakeRun -RunType "attack" -ScenarioPath (Save-Scenario $otherReference) -DataRoot (New-TempRoot) -Transport (New-FakeTransport)
} "*must be the session_begin action A01, found 'A03'*"
$normalReference = New-ScenarioObject
$normalReference.runs.normal.reference_action_id = "N01"
Assert-RefusedBeforeAnyCall "a normal run whose scenario names a reference action" {
    Invoke-FakeRun -ScenarioPath (Save-Scenario $normalReference) -DataRoot (New-TempRoot) -Transport (New-FakeTransport)
} "*only an attack run records a reference*"
Assert-RefusedBeforeAnyCall "a dry run of an attack run whose scenario names no reference action" {
    Invoke-FakeRun -RunType "attack" -ScenarioPath (Save-Scenario $noReference) -DataRoot (New-TempRoot) -Transport $null -DryRun
} "*runs.attack.reference_action_id is missing*"

 # The evaluation horizon is a scenario value, and the window covers it.
foreach ($badHorizon in @($null, 0, -1, "600")) {
    $horizonScenario = New-ScenarioObject
    $horizonScenario.run_length.evaluation_horizon_sec = $badHorizon
    Assert-RefusedBeforeAnyCall ("a scenario whose evaluation horizon is '" + [string]$badHorizon + "'") {
        Invoke-FakeRun -ScenarioPath (Save-Scenario $horizonScenario) -DataRoot (New-TempRoot) -Transport (New-FakeTransport)
    } "*evaluation_horizon_sec must be an integer of 1 or more*"
}
$noRunLength = New-ScenarioObject
$noRunLength.PSObject.Properties.Remove("run_length")
Assert-RefusedBeforeAnyCall "a scenario that states no run_length" {
    Invoke-FakeRun -ScenarioPath (Save-Scenario $noRunLength) -DataRoot (New-TempRoot) -Transport (New-FakeTransport)
} "*evaluation_horizon_sec must be an integer of 1 or more*"
$longHorizon = New-ScenarioObject
$longHorizon.run_length.evaluation_horizon_sec = 700
Assert-RefusedBeforeAnyCall "an observation window shorter than the evaluation horizon" {
    Invoke-FakeRun -ScenarioPath (Save-Scenario $longHorizon) -DataRoot (New-TempRoot) -Transport (New-FakeTransport)
} "*is shorter than the evaluation horizon of 700 s*"

$encodedScenario = New-ScenarioObject
$encodedScenario.planned_lineage.final_tool.arguments = @("-EncodedCommand", "{task_script}", "-ChannelDir", "{channel_dir}")
Assert-RefusedBeforeAnyCall "a scenario with an encoded command option" {
    Invoke-FakeRun -ScenarioPath (Save-Scenario $encodedScenario) -DataRoot (New-TempRoot) -Transport (New-FakeTransport)
} "*encoded command option*"

 # The identity of the Pair is checked with the other inputs, in every mode.
$noRepetition = New-ScenarioObject
$noRepetition.repetition = $null
Assert-RefusedBeforeAnyCall "a scenario that states no repetition" {
    Invoke-FakeRun -ScenarioPath (Save-Scenario $noRepetition) -DataRoot (New-TempRoot) -Transport (New-FakeTransport)
} "*repetition must be an integer of 1 or more*"
Assert-RefusedBeforeAnyCall "a rehearsal of a scenario that states no repetition" {
    Invoke-FakeRun -ScenarioPath (Save-Scenario $noRepetition) -DataRoot (New-TempRoot) -Transport (New-FakeTransport) -Rehearsal
} "*repetition must be an integer of 1 or more*"
Assert-RefusedBeforeAnyCall "a dry run of a scenario that states no repetition" {
    Invoke-FakeRun -ScenarioPath (Save-Scenario $noRepetition) -DataRoot (New-TempRoot) -Transport $null -DryRun
} "*repetition must be an integer of 1 or more*"

$labelledFamily = New-ScenarioObject -FamilyId "attack_family"
Assert-RefusedBeforeAnyCall "a family named after a run type" {
    Invoke-FakeRun -RunType "attack" -ScenarioPath (Save-Scenario $labelledFamily) -DataRoot (New-TempRoot) -Transport (New-FakeTransport)
} "*family_id would expose the run type*"

$ownRepetition = New-ScenarioObject
$ownRepetition.runs.attack | Add-Member -NotePropertyName "repetition" -NotePropertyValue 2
Assert-RefusedBeforeAnyCall "a run that states a repetition of its own" {
    Invoke-FakeRun -RunType "attack" -ScenarioPath (Save-Scenario $ownRepetition) -DataRoot (New-TempRoot) -Transport (New-FakeTransport)
} "*a Pair states it once at the top level*"

 # A reused run_id is refused before the first session and leaves the earlier output alone.
$reusedRoot = New-TempRoot
$reusedDir = Join-Path $reusedRoot "raw\RUN-20300101-001"
New-Item -ItemType Directory -Path $reusedDir -Force | Out-Null
Set-Content -Path (Join-Path $reusedDir "manifest.json") -Value "manifest-sentinel" -Encoding Ascii
Assert-RefusedBeforeAnyCall "a run_id that already produced output" {
    Invoke-FakeRun -ScenarioPath $goodScenario -DataRoot $reusedRoot -Transport (New-FakeTransport)
} "*already has output*"
Assert-True "the earlier output is untouched" (
    (Get-Content -LiteralPath (Join-Path $reusedDir "manifest.json") -Raw).Trim() -eq "manifest-sentinel")

 # ---------------------------------------------------------------------------
 # 4b. Label words in two languages, the same list as the Python side
 # ---------------------------------------------------------------------------

Write-Host "`n=== label words ===" -ForegroundColor Cyan

 # Korean is built from code points here too: this file is ASCII only. The three
 # labels mean normal, attack and malicious; the fourth word holds no label.
$KO_NORMAL = -join [char[]](0xC815, 0xC0C1)
$KO_ATTACK = -join [char[]](0xACF5, 0xACA9)
$KO_MALICIOUS = -join [char[]](0xC545, 0xC131)
$KO_UNRELATED = -join [char[]](0xC6D0, 0xACA9, 0xAD00, 0xB9AC)
$koLabels = @($KO_NORMAL, $KO_ATTACK, $KO_MALICIOUS)

function Test-SameText {
    <# Ordinal comparison, with $null equal only to $null. #>
    param([AllowNull()]$Left, [AllowNull()]$Right)
    if ($null -eq $Left -or $null -eq $Right) { return ($null -eq $Left -and $null -eq $Right) }
    return [string]::Equals([string]$Left, [string]$Right, [System.StringComparison]::Ordinal)
}

 # tests\label_shortcut_cases.json is read by this script and by
 # tests/collection/test_r1_pair_identity.py. Both sides have to hold its list
 # and give its answer for every case, so neither can change alone.
$labelCases = Get-Content -LiteralPath (Join-Path $PSScriptRoot "label_shortcut_cases.json") -Raw -Encoding UTF8 |
    ConvertFrom-Json
Assert-True "the label words are the shared list, in the same order" (
    @($R1_LABEL_WORDS).Count -eq 7 -and
    (Test-SameText (@($R1_LABEL_WORDS) -join "|") (@($labelCases.label_words) -join "|")))
Assert-True "the list holds the three Korean labels" (
    (Test-SameText $R1_LABEL_WORDS[4] $KO_NORMAL) -and (Test-SameText $R1_LABEL_WORDS[5] $KO_ATTACK) -and
    (Test-SameText $R1_LABEL_WORDS[6] $KO_MALICIOUS))
$caseNumber = 0
foreach ($case in @($labelCases.cases)) {
    $caseNumber++
    $found = Get-R1ExposedLabelWord -Value ([string]$case.value)
    Assert-True ("shared label case " + $caseNumber + ": " + [string]$case.note) (Test-SameText $found $case.word)
}
Assert-True "every shared label case was read" (
    $caseNumber -eq @($labelCases.cases).Count -and $caseNumber -ge 20)
Assert-True "an empty value holds no label" (
    $null -eq (Get-R1ExposedLabelWord -Value "") -and $null -eq (Get-R1ExposedLabelWord -Value $null))

 # Identity of the Pair.
foreach ($field in @("family_id", "variation_id")) {
    for ($index = 0; $index -lt $koLabels.Count; $index++) {
        $label = $koLabels[$index]
        Assert-IdentityRefused ("a " + $field + " that is Korean label " + ($index + 1) + " is refused") {
            param($s) $s.$field = $label } ("*" + $field + " would expose the run type*")
        Assert-IdentityRefused ("a " + $field + " that contains Korean label " + ($index + 1) + " is refused") {
            param($s) $s.$field = ("V02-" + $label + "-set") } ("*" + $field + " would expose the run type*")
    }
}
$koPair = Get-R1PairIdentity -Scenario (ConvertTo-RenderedScenario (
    New-ScenarioObject -FamilyId $KO_UNRELATED -VariationId ($KO_UNRELATED + "_V02")))
Assert-True "a Korean family and variation that hold no label are taken as stated" (
    (Test-SameText $koPair.family_id $KO_UNRELATED) -and (Test-SameText $koPair.variation_id ($KO_UNRELATED + "_V02")))

 # Launch plan: what the run would put on Target-A.
for ($index = 0; $index -lt $koLabels.Count; $index++) {
    $label = $koLabels[$index]

    $koImage = New-ScenarioObject
    $koImage.planned_lineage.intermediate.attack.image = ($label + ".exe")
    Assert-Throws ("an intermediate image that holds Korean label " + ($index + 1) + " is refused") {
        Assert-R1PlanShortcutFree -Plan (Get-R1LaunchPlan -Scenario $koImage -RunType "attack" -WorkDir $TEST_WORK)
    } "*expose the run type*"

    $koArgument = New-ScenarioObject
    $koArgument.planned_lineage.final_tool.arguments = @($koArgument.planned_lineage.final_tool.arguments) +
        @("r1_" + $label + ".txt")
    Assert-Throws ("a final tool argument that holds Korean label " + ($index + 1) + " is refused") {
        Assert-R1PlanShortcutFree -Plan (Get-R1LaunchPlan -Scenario $koArgument -RunType "normal" -WorkDir $TEST_WORK)
    } "*expose the run type*"
}
$koPlain = New-ScenarioObject
$koPlain.planned_lineage.final_tool.arguments = @($koPlain.planned_lineage.final_tool.arguments) + @($KO_UNRELATED)
$koPlainThrew = $false
try {
    Assert-R1PlanShortcutFree -Plan (Get-R1LaunchPlan -Scenario $koPlain -RunType "normal" -WorkDir $TEST_WORK)
} catch { $koPlainThrew = $true }
Assert-True "a Korean argument that holds no label passes the shortcut check" (-not $koPlainThrew)

 # The same rule through the whole run, read from a UTF-8 scenario file.
for ($index = 0; $index -lt $koLabels.Count; $index++) {
    $koFamilyScenario = Save-Scenario (New-ScenarioObject -FamilyId ($koLabels[$index] + "_family"))
    Assert-RefusedBeforeAnyCall ("a run whose family holds Korean label " + ($index + 1)) {
        Invoke-FakeRun -ScenarioPath $koFamilyScenario -DataRoot (New-TempRoot) -Transport (New-FakeTransport)
    } "*family_id would expose the run type*"
}
$koArgumentScenario = New-ScenarioObject
$koArgumentScenario.planned_lineage.intermediate.normal.arguments = @(
    $koArgumentScenario.planned_lineage.intermediate.normal.arguments) + @($KO_ATTACK)
$koArgumentPath = Save-Scenario $koArgumentScenario
Assert-RefusedBeforeAnyCall "a run whose plan holds a Korean label" {
    Invoke-FakeRun -ScenarioPath $koArgumentPath -DataRoot (New-TempRoot) -Transport (New-FakeTransport)
} "*expose the run type*"
Assert-RefusedBeforeAnyCall "a dry run whose plan holds a Korean label" {
    Invoke-FakeRun -ScenarioPath $koArgumentPath -DataRoot (New-TempRoot) -Transport $null -DryRun
} "*expose the run type*"

Reset-Fakes
$koRunRoot = New-TempRoot
$koRun = Invoke-FakeRun -RunId "RUN-20300101-050" -DataRoot $koRunRoot -Transport (New-FakeTransport) `
    -ScenarioPath (Save-Scenario (New-ScenarioObject -FamilyId $KO_UNRELATED))
$koMetadata = Get-Content -LiteralPath (Join-Path $koRunRoot "ground_truth\RUN-20300101-050\run_metadata.json") `
    -Raw -Encoding UTF8 | ConvertFrom-Json
Assert-True "a run of a Korean family that holds no label records that family unchanged" (
    $koRun.mode -eq "collection" -and (Test-SameText $koMetadata.family_id $KO_UNRELATED))

 # ---------------------------------------------------------------------------
 # 5. Dry run
 # ---------------------------------------------------------------------------

Write-Host "`n=== dry run ===" -ForegroundColor Cyan

Reset-Fakes
$dryRoot = New-TempRoot
$dry = Invoke-FakeRun -RunType "attack" -ScenarioPath $goodScenario -DataRoot $dryRoot -Transport $null `
    -Connection $null -DryRun
Assert-True "a dry run reports its mode" ($dry.mode -eq "dry_run")
Assert-True "a dry run reports the dataset tier its scenario states" (
    $dry.dataset_tier -ceq "pilot" -and
    (Invoke-FakeRun -ScenarioPath (Save-Scenario (New-ScenarioObject -DatasetTier "development")) `
        -DataRoot (New-TempRoot) -Transport $null -DryRun).dataset_tier -ceq "development")
Assert-True "a dry run returns the plan it would execute" ($dry.plan.intermediate.executable -eq $attackImage)
Assert-True "a dry run lists the actions in order" (($dry.actions -join ",") -eq "A01,A02,A03,A04,A05")
Assert-True "a dry run reports the destination it validated" ($dry.connection.target -eq $TEST_TARGET)
Assert-True "a dry run opens no session and starts nothing" ($script:FakeCalls.Count -eq 0)
Assert-True "a dry run waits for nothing" ($script:SleepCalls.Count -eq 0)
Assert-True "a dry run creates no directory" (@(Get-ChildItem -LiteralPath $dryRoot -Force).Count -eq 0)
Assert-True "a dry run writes no operator trace" (
    -not (Test-Path -LiteralPath (Join-Path $dryRoot "operator_trace")))
Assert-True "a dry run reports the SHA-256 of the scenario it read" (
    $dry.scenario_sha256 -ceq (Get-FileSha256 $goodScenario))
Assert-True "a dry run returns the identity of the Pair" (
    $dry.identity.family_id -ceq $TEST_FAMILY -and $dry.identity.variation_id -ceq $TEST_VARIATION -and
    $dry.identity.repetition -eq $TEST_REPETITION)

 # What a dry run prints is how the operator checks the Pair before a real run.
Reset-Fakes
$anotherPairScenario = Save-Scenario (New-ScenarioObject -FamilyId "family_x7" -VariationId "V09" -Repetition 4)
$dryLines = @(& {
        Invoke-FakeRun -RunType "normal" -ScenarioPath $anotherPairScenario -DataRoot (New-TempRoot) `
            -Transport $null -Connection $null -DryRun | Out-Null
    } 6>&1 | ForEach-Object { [string]$_ })
Assert-True "a dry run shows the family, the variation and the repetition" (
    @($dryLines | Where-Object { $_ -like "*pair: family_id=family_x7 variation_id=V09 repetition=4*" }).Count -eq 1)

Reset-Fakes
$dryNoTarget = Invoke-FakeRun -ScenarioPath (Save-Scenario (New-ScenarioObject -Target $null -TargetHost $null)) `
    -DataRoot (New-TempRoot) -Transport $null -Connection $null -DryRun
Assert-True "a dry run works on the rehearsal shape (no destination, no host)" (
    $dryNoTarget.mode -eq "dry_run" -and $null -eq $dryNoTarget.connection)
Assert-RefusedBeforeAnyCall "a dry run still refuses a globally routable destination" {
    Invoke-FakeRun -ScenarioPath (Save-Scenario (New-ScenarioObject -Target "8.8.8.8")) -DataRoot (New-TempRoot) -Transport $null -DryRun
} "*target_not_private*"

 # ---------------------------------------------------------------------------
 # 6. A complete run against the fake transport
 # ---------------------------------------------------------------------------

Write-Host "`n=== complete run (fake transport) ===" -ForegroundColor Cyan

$expectedCalls = "open,invoke:probe,close,open,invoke:begin,invoke:prepare,invoke:launch,invoke:trigger," +
    "invoke:end,close,open,invoke:export,fetch,invoke:cleanup,close,convert"

$runs = @{}
foreach ($case in @(
    @{ type = "normal"; run_id = "RUN-20300101-001"; ids = "N01,N02,N03,N04,N05"; image = $normalImage; plan = $normalPlan },
    @{ type = "attack"; run_id = "RUN-20300101-002"; ids = "A01,A02,A03,A04,A05"; image = $attackImage; plan = $attackPlan })) {

    Reset-Fakes
    $root = New-TempRoot
    $result = Invoke-FakeRun -RunType $case.type -RunId $case.run_id -ScenarioPath $goodScenario `
        -DataRoot $root -Transport (New-FakeTransport)
    $label = $case.type + ": "

    Assert-True ($label + "the run completes as a collection") ($result.mode -eq "collection")
    Assert-True ($label + "the lineage check matched") ($result.lineage.status -eq "matched")
    Assert-True ($label + "the final tool instance is identified") ($result.lineage.final_process_guid -eq $FINAL_GUID)
    Assert-True ($label + "calls happen in the designed order") (($script:FakeCalls -join ",") -eq $expectedCalls)
    Assert-True ($label + "the process launcher is called exactly once") ((Get-CallCount "invoke:launch") -eq 1)
    Assert-True ($label + "the connection is triggered exactly once") ((Get-CallCount "invoke:trigger") -eq 1)
    Assert-True ($label + "every opened session is closed") (
        (Get-CallCount "open") -eq 3 -and (Get-CallCount "close") -eq 3)
    Assert-True ($label + "the launcher starts the scenario's intermediate") (
        [string]$script:FakeArguments["launch"].executable -eq $case.image)
    Assert-True ($label + "the launcher is handed exactly the arguments of the plan") (
        (@($script:FakeArguments["launch"].arguments) -join " ") -ceq (@($case.plan.intermediate.arguments) -join " "))
    Assert-True ($label + "the offsets and the window are waited on the injected clock") (
        ($script:SleepCalls -join ",") -eq "120,180,180,120,60")
    Assert-True ($label + "the export reaches back to the start the target stamped, plus the margin") (
        [string]$script:FakeArguments["export"].start_utc -eq "2030-01-01T00:00:00.000Z" -and
        [int]$script:FakeArguments["export"].margin_ms -eq $EVTX_WINDOW_MARGIN_MS -and
        -not $script:FakeArguments["export"].ContainsKey("window_ms"))
    Assert-True ($label + "the run cleans its channel and export off the target") (
        (@($script:FakeArguments["cleanup"].paths) -join ",") -eq ($TEST_WORK + "\r1_chan," + $TEST_WORK + "\r1_sysmon_export.evtx"))

    $manifestPath = Join-Path $root ("raw\" + $case.run_id + "\manifest.json")
    $metadataPath = Join-Path $root ("ground_truth\" + $case.run_id + "\run_metadata.json")
    $recordPath = Join-Path $root ("ground_truth\" + $case.run_id + "\execution_record.csv")
    $jsonlPath = Join-Path $root ("raw\" + $case.run_id + "\telemetry\sysmon-0001.jsonl")
    $evtxPath = Join-Path $root ("raw\" + $case.run_id + "\telemetry\sysmon-0001.evtx")
    $present = @($manifestPath, $metadataPath, $recordPath, $jsonlPath, $evtxPath | Where-Object { Test-Path -LiteralPath $_ })
    Assert-True ($label + "the four artifacts exist") ($present.Count -eq 5)

    $metadata = Get-Content -LiteralPath $metadataPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $rows = @(Import-Csv -LiteralPath $recordPath -Encoding UTF8)
    $rowRunIds = @($rows | ForEach-Object { $_.run_id } | Sort-Object -Unique)
    Assert-True ($label + "run_metadata, manifest and every execution_record row carry one run_id") (
        $metadata.run_id -eq $case.run_id -and $manifest.run_id -eq $case.run_id -and
        $rowRunIds.Count -eq 1 -and $rowRunIds[0] -eq $case.run_id)
    Assert-True ($label + "run_metadata records the scenario, run type and host") (
        $metadata.scenario_id -eq "R1" -and $metadata.run_type -eq $case.type -and
        $metadata.target_host -eq $TEST_HOST -and $metadata.variation_id -eq "V02")
    Assert-True ($label + "run_metadata records the snapshot attestation") ($metadata.vm_snapshot -eq "synthetic-snapshot")
    $metadataText = Get-Content -LiteralPath $metadataPath -Raw -Encoding UTF8
    if ($case.type -eq "attack") {
        Assert-True ($label + "run_metadata records the reference: the action that opens the session and the EID 1 of its session host") (
            $metadata.reference_action_id -ceq "A01" -and
            $metadataText -match '"reference_time":\s+"2030-01-01T00:00:00\.000Z"' -and
            $metadataText -match '"reference_source_event_id":\s+"1"')
        Assert-True ($label + "the result reports the same reference") (
            $result.reference.reference_action_id -ceq "A01" -and
            $result.reference.reference_time -ceq "2030-01-01T00:00:00.000Z" -and
            $result.reference.reference_source_event_id -ceq "1")
    } else {
        Assert-True ($label + "the reference fields stay null") (
            $null -eq $metadata.reference_time -and $null -eq $metadata.reference_action_id -and
            $null -eq $metadata.reference_source_event_id -and
            $metadataText -match '"reference_time":\s+null' -and $null -eq $result.reference.reference_time -and
            $null -eq $result.reference.reference_action_id -and $null -eq $result.reference.reference_source_event_id)
    }
    Assert-True ($label + "run_metadata records the reference policy version the scenario states") (
        $metadata.reference_policy_version -ceq "r1-ref-v0.1")
    Assert-True ($label + "start and end are the target's stamps around the window") (
        $metadata.start_time -eq "2030-01-01T00:00:00.000Z" -and $metadata.end_time -eq "2030-01-01T00:11:00.000Z")
    Assert-True ($label + "the actions are recorded in order") ((@($rows | ForEach-Object { $_.action_id }) -join ",") -eq $case.ids)
    Assert-True ($label + "the actions are recorded at their real times") (
        (@($rows | ForEach-Object { $_.timestamp }) -join ",") -eq
        "2030-01-01T00:00:00.000Z,2030-01-01T00:02:00.000Z,2030-01-01T00:05:00.000Z,2030-01-01T00:08:00.000Z,2030-01-01T00:10:00.000Z")
    Assert-True ($label + "the manifest lists the EVTX and the JSONL derived from it") (
        @($manifest.items).Count -eq 2 -and
        @($manifest.items | Where-Object { $_.PSObject.Properties.Name -contains "derived_from" }).Count -eq 1)
    Assert-True ($label + "the manifest records the Sysmon configuration") (
        $manifest.sysmon.config_sha256 -eq $TEST_CONFIG_SHA)
    Assert-True ($label + "run_metadata records the family, variation and repetition the scenario states") (
        $metadata.family_id -ceq $TEST_FAMILY -and $metadata.variation_id -ceq $TEST_VARIATION -and
        $metadata.repetition -is [int] -and $metadata.repetition -eq $TEST_REPETITION)
    Assert-True ($label + "the result reports the identity it recorded") (
        $result.identity.family_id -ceq $metadata.family_id -and
        $result.identity.variation_id -ceq $metadata.variation_id -and
        $result.identity.repetition -eq $metadata.repetition)

    # The operator trace: what ties the run to the scenario it executed.
    $trace = Get-TraceOf -Root $root -RunId $case.run_id
    $scenarioSha = Get-FileSha256 $goodScenario
    Assert-True ($label + "the operator trace and the scenario copy exist next to raw and ground_truth") (
        (Test-Path -LiteralPath $trace.record_path) -and (Test-Path -LiteralPath $trace.scenario_path) -and
        (@(Get-ChildItem -LiteralPath $root -Force | ForEach-Object { $_.Name } | Sort-Object) -join ",") -ceq
        "ground_truth,operator_trace,raw")
    Assert-True ($label + "the trace holds exactly the five recorded values") (
        (@($trace.record.PSObject.Properties.Name) -join ",") -ceq
        "trace_version,run_id,dataset_tier,mode,scenario_sha256")
    Assert-True ($label + "the trace names the run, the mode and the Pilot tier") (
        $trace.record.trace_version -ceq "v1" -and $trace.record.run_id -ceq $case.run_id -and
        $trace.record.dataset_tier -ceq "pilot" -and $trace.record.mode -ceq "collection")
    Assert-True ($label + "the trace records the SHA-256 of the scenario file the run was given") (
        $trace.record.scenario_sha256 -ceq $scenarioSha -and $scenarioSha -match "^[0-9a-f]{64}$")
    Assert-True ($label + "the scenario copy is byte for byte the file the run was given") (
        (Get-FileSha256 $trace.scenario_path) -ceq $scenarioSha -and
        (Get-Item -LiteralPath $trace.scenario_path).Length -eq (Get-Item -LiteralPath $goodScenario).Length)
    Assert-True ($label + "the result reports the trace, the tier and the digest") (
        $result.trace_dir -eq $trace.dir -and $result.dataset_tier -ceq "pilot" -and
        $result.scenario_sha256 -ceq $scenarioSha)
    Assert-True ($label + "the trace is not a contract artifact: raw and ground_truth hold what they held") (
        (@(Get-ChildItem -LiteralPath (Join-Path $root ("raw\" + $case.run_id)) -Force |
            ForEach-Object { $_.Name } | Sort-Object) -join ",") -ceq "manifest.json,telemetry" -and
        (@(Get-ChildItem -LiteralPath (Join-Path $root ("ground_truth\" + $case.run_id)) -Force |
            ForEach-Object { $_.Name } | Sort-Object) -join ",") -ceq "execution_record.csv,run_metadata.json" -and
        -not ((Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8).Contains("operator_trace")))

    $runs[$case.type] = @{
        record   = (Get-Content -LiteralPath $recordPath -Raw -Encoding UTF8)
        prepare  = $script:FakeArguments["prepare"]
        launch   = $script:FakeArguments["launch"]
        trigger  = $script:FakeArguments["trigger"]
        run_id   = $case.run_id
        identity = ($metadata.family_id + "|" + $metadata.variation_id + "|" + $metadata.repetition)
    }
}

Assert-True "both runs of the Pair record the same family, variation and repetition" (
    $runs.normal.identity -ceq $runs.attack.identity)

Assert-True "both runs prepare the same files with the same content" (
    (($runs.normal.prepare.files.Keys | Sort-Object) -join ",") -ceq (($runs.attack.prepare.files.Keys | Sort-Object) -join ",") -and
    @($runs.normal.prepare.files.Keys | Where-Object {
        [string]$runs.normal.prepare.files[$_] -cne [string]$runs.attack.prepare.files[$_] }).Count -eq 0)
Assert-True "both runs give the task the same connection config" (
    [string]$runs.normal.prepare.channel_config -ceq [string]$runs.attack.prepare.channel_config)
Assert-True "both runs use the same work directory" ($runs.normal.launch.work_dir -eq $runs.attack.launch.work_dir)
Assert-True "the two runs start different intermediates" ($runs.normal.launch.executable -ne $runs.attack.launch.executable)
Assert-True "the task config carries the injected destination and one attempt" (
    (([string]$runs.normal.prepare.channel_config) | ConvertFrom-Json).target -eq $TEST_TARGET -and
    (([string]$runs.normal.prepare.channel_config) | ConvertFrom-Json).max_attempts -eq 1)
Assert-True "nothing sent to the target carries the run_id" (
    -not (([string]$runs.normal.prepare.channel_config) + ($runs.normal.launch.arguments -join " ") +
        (@($runs.normal.prepare.files.Values) -join " ")).Contains($runs.normal.run_id))

 # Determinism: the same run on the same clock writes the same execution record.
Reset-Fakes
$againRoot = New-TempRoot
Invoke-FakeRun -RunType "normal" -RunId "RUN-20300101-003" -ScenarioPath $goodScenario -DataRoot $againRoot `
    -Transport (New-FakeTransport) | Out-Null
$again = Get-Content -LiteralPath (Join-Path $againRoot "ground_truth\RUN-20300101-003\execution_record.csv") -Raw -Encoding UTF8
Assert-True "the execution record is deterministic apart from the run_id" (
    $again.Replace("RUN-20300101-003", "RUN-20300101-001") -ceq $runs.normal.record)

 # Another Pair. The values come from the rendered scenario, not from the runner,
 # and the repetition is written as the integer it was stated as.
$pairIdentities = New-Object System.Collections.Generic.List[string]
foreach ($case in @(
    @{ type = "normal"; run_id = "RUN-20300101-030" },
    @{ type = "attack"; run_id = "RUN-20300101-031" })) {

    Reset-Fakes
    $pairRoot = New-TempRoot
    Invoke-FakeRun -RunType $case.type -RunId $case.run_id -ScenarioPath $anotherPairScenario `
        -DataRoot $pairRoot -Transport (New-FakeTransport) | Out-Null
    $pairText = Get-Content -LiteralPath (Join-Path $pairRoot ("ground_truth\" + $case.run_id + "\run_metadata.json")) `
        -Raw -Encoding UTF8
    $pairMetadata = $pairText | ConvertFrom-Json
    $pairIdentities.Add($pairMetadata.family_id + "|" + $pairMetadata.variation_id + "|" + $pairMetadata.repetition)
    Assert-True ($case.type + ": the repetition is written as a JSON integer") ($pairText -match '"repetition":\s+4,')
}
Assert-True "another family, variation and repetition are recorded as the scenario states them" (
    $pairIdentities[0] -ceq "family_x7|V09|4")
Assert-True "both runs of that Pair record the same three values" ($pairIdentities[0] -ceq $pairIdentities[1])

 # Observation window boundary on the fake clock.
Reset-Fakes
$boundary = Invoke-FakeRun -RunId "RUN-20300101-004" -ScenarioPath $goodScenario -DataRoot (New-TempRoot) `
    -ObservationSec 600 -Transport (New-FakeTransport)
Assert-True "a window that ends with the last action is accepted" ($boundary.mode -eq "collection")
Assert-True "a window that ends with the last action adds no further wait" (
    ($script:SleepCalls -join ",") -eq "120,180,180,120")

Reset-Fakes
Invoke-FakeRun -RunId "RUN-20300101-005" -ScenarioPath $goodScenario -DataRoot (New-TempRoot) `
    -ObservationSec 1800 -Transport (New-FakeTransport) | Out-Null
Assert-True "a longer window is waited out to its end" (
    ($script:SleepCalls | Measure-Object -Sum).Sum -eq 1800 -and $script:SleepCalls[$script:SleepCalls.Count - 1] -eq 1200)

 # t+0 is the moment the Controller starts opening the session, on the clock of
 # the target. Here every session takes three seconds to open.
Reset-Fakes @{ OpenSeconds = 3 }
$slowRoot = New-TempRoot
Invoke-FakeRun -RunId "RUN-20300101-006" -ScenarioPath $goodScenario -DataRoot $slowRoot `
    -Transport (New-FakeTransport) | Out-Null
$slowRows = @(Import-Csv -LiteralPath (Join-Path $slowRoot "ground_truth\RUN-20300101-006\execution_record.csv") -Encoding UTF8)
$slowMetadata = Get-Content -LiteralPath (Join-Path $slowRoot "ground_truth\RUN-20300101-006\run_metadata.json") -Raw -Encoding UTF8 |
    ConvertFrom-Json
Assert-True "the session action is recorded when its open started, not after the session exists" (
    $slowRows[0].timestamp -eq "2030-01-01T00:00:03.000Z" -and $slowMetadata.start_time -eq "2030-01-01T00:00:03.000Z")
Assert-True "the later actions keep their offsets from the start of the run" (
    (@($slowRows | ForEach-Object { $_.timestamp }) -join ",") -eq
    "2030-01-01T00:00:03.000Z,2030-01-01T00:02:03.000Z,2030-01-01T00:05:03.000Z,2030-01-01T00:08:03.000Z,2030-01-01T00:10:03.000Z")
Assert-True "the time a session takes to open is not waited for a second time" (
    ($script:SleepCalls -join ",") -eq "117,180,180,120,60")
Assert-True "the run ends with the stamp of the collection session" ($slowMetadata.end_time -eq "2030-01-01T00:11:06.000Z")
Assert-True "the export is given the start_time the run recorded, whatever a session took to open" (
    [string]$script:FakeArguments["export"].start_utc -eq $slowMetadata.start_time)

 # The host check uses the name Sysmon writes into its records when the target
 # can read one, because that is the name the lineage check compares.
Reset-Fakes @{ ComputerName = "SHORTNAME"; RecordedComputerName = $TEST_HOST }
$namedRun = Invoke-FakeRun -RunId "RUN-20300101-007" -ScenarioPath $goodScenario -DataRoot (New-TempRoot) `
    -Transport (New-FakeTransport)
Assert-True "a target whose records carry the approved name is accepted" (
    $namedRun.mode -eq "collection" -and $namedRun.lineage.status -eq "matched")
Assert-True "the pre-run check is told which log to read the recorded name from" (
    [string]$script:FakeArguments["probe"].log_name -eq $SYSMON_LOG)

 # ---------------------------------------------------------------------------
 # 6b. The operator trace binds a run to the scenario it executed
 # ---------------------------------------------------------------------------

Write-Host "`n=== operator trace ===" -ForegroundColor Cyan

 # The tier the scenario of a Pair states is the tier the trace of a run records,
 # for each of the three. Nothing but the scenario decides it.
foreach ($tier in $R1_DATASET_TIERS) {
    Reset-Fakes
    $tierRoot = New-TempRoot
    $tierRunId = "RUN-20300101-03" + [array]::IndexOf($R1_DATASET_TIERS, $tier)
    $tierResult = Invoke-FakeRun -RunId $tierRunId -DataRoot $tierRoot `
        -ScenarioPath (Save-Scenario (New-ScenarioObject -DatasetTier $tier)) -Transport (New-FakeTransport)
    $tierTrace = Get-TraceOf -Root $tierRoot -RunId $tierRunId
    Assert-True ("a collection run of a scenario rendered as " + $tier + " records " + $tier + " in its trace and reports it") (
        $tierTrace.record.dataset_tier -ceq $tier -and $tierTrace.record.mode -ceq "collection" -and
        $tierResult.dataset_tier -ceq $tier)
    Assert-True ("the run_metadata of a " + $tier + " run carries no tier field: the trace is where it is recorded") (
        $null -eq (Get-Content -LiteralPath (Join-Path $tierRoot ("ground_truth\" + $tierRunId + "\run_metadata.json")) -Raw |
            ConvertFrom-Json).PSObject.Properties["dataset_tier"])
}

 # Both runs of a Pair read one rendered scenario, so they record one tier.
$pairScenario = Save-Scenario (New-ScenarioObject -DatasetTier "development")
$pairRoot = New-TempRoot
Reset-Fakes
Invoke-FakeRun -RunType "normal" -RunId "RUN-20300101-034" -DataRoot $pairRoot -ScenarioPath $pairScenario `
    -Transport (New-FakeTransport) | Out-Null
Reset-Fakes
Invoke-FakeRun -RunType "attack" -RunId "RUN-20300101-035" -DataRoot $pairRoot -ScenarioPath $pairScenario `
    -Transport (New-FakeTransport) | Out-Null
$pairNormalTrace = (Get-TraceOf -Root $pairRoot -RunId "RUN-20300101-034").record
$pairAttackTrace = (Get-TraceOf -Root $pairRoot -RunId "RUN-20300101-035").record
Assert-True "the normal and the attack run of one rendered scenario record the same tier and the same scenario" (
    $pairNormalTrace.dataset_tier -ceq "development" -and $pairAttackTrace.dataset_tier -ceq "development" -and
    $pairNormalTrace.scenario_sha256 -ceq $pairAttackTrace.scenario_sha256 -and
    $pairNormalTrace.scenario_sha256 -ceq (Get-FileSha256 $pairScenario))

 # The policy version is the scenario's: whatever non-blank value it states is
 # what both runs record, and the runner fixes none.
$otherPolicy = New-ScenarioObject
$otherPolicy.run_metadata.reference_policy_version = "synthetic-ref-v9"
$otherPolicyPath = Save-Scenario $otherPolicy
$otherPolicyRoot = New-TempRoot
Reset-Fakes
Invoke-FakeRun -RunType "attack" -RunId "RUN-20300101-036" -DataRoot $otherPolicyRoot -ScenarioPath $otherPolicyPath `
    -Transport (New-FakeTransport) | Out-Null
Assert-True "an attack run records the policy version its scenario states, whichever it is" (
    (Get-Content -LiteralPath (Join-Path $otherPolicyRoot "ground_truth\RUN-20300101-036\run_metadata.json") -Raw |
        ConvertFrom-Json).reference_policy_version -ceq "synthetic-ref-v9")

 # The scenario is read once. A file replaced after that changes neither what
 # the run does nor what its trace keeps.
$readOnceScenario = Save-Scenario (New-ScenarioObject)
$readOnceOriginal = [System.IO.File]::ReadAllBytes($readOnceScenario)
$readOnceSha = Get-FileSha256 $readOnceScenario
Reset-Fakes @{ OverwriteScenarioOnOpen = $readOnceScenario }
$readOnceRoot = New-TempRoot
$readOnce = Invoke-FakeRun -RunType "attack" -RunId "RUN-20300101-040" -ScenarioPath $readOnceScenario `
    -DataRoot $readOnceRoot -Transport (New-FakeTransport)
$readOnceTrace = Get-TraceOf -Root $readOnceRoot -RunId "RUN-20300101-040"
Assert-True "the scenario file was replaced while the run was under way" (
    (Get-FileSha256 $readOnceScenario) -cne $readOnceSha)
Assert-True "a run whose scenario file is replaced after the read still runs the plan it read" (
    $readOnce.mode -eq "collection" -and $readOnce.lineage.status -eq "matched" -and
    [string]$script:FakeArguments["launch"].executable -eq $attackImage)
Assert-True "the trace records the digest of the bytes that were read, not of the replaced file" (
    $readOnceTrace.record.scenario_sha256 -ceq $readOnceSha -and $readOnce.scenario_sha256 -ceq $readOnceSha)
Assert-True "the scenario copy is the bytes that were read" (
    (Get-FileSha256 $readOnceTrace.scenario_path) -ceq $readOnceSha -and
    [System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes($readOnceTrace.scenario_path)) -ceq
    [System.Convert]::ToBase64String($readOnceOriginal))

 # A trace is written once. One that exists stops the run before the first
 # session and is left as it was.
$tracedRoot = New-TempRoot
$tracedDir = Join-Path $tracedRoot "operator_trace\RUN-20300101-001"
New-Item -ItemType Directory -Path $tracedDir -Force | Out-Null
Set-Content -Path (Join-Path $tracedDir "r1_run_trace.json") -Value "trace-sentinel" -Encoding Ascii
Assert-RefusedBeforeAnyCall "a run_id that already has an operator trace" {
    Invoke-FakeRun -ScenarioPath $goodScenario -DataRoot $tracedRoot -Transport (New-FakeTransport)
} "*already has an operator trace*"
Assert-True "the earlier trace is untouched and nothing else was created" (
    (Get-Content -LiteralPath (Join-Path $tracedDir "r1_run_trace.json") -Raw).Trim() -eq "trace-sentinel" -and
    @(Get-ChildItem -LiteralPath $tracedDir -Force).Count -eq 1 -and
    (@(Get-ChildItem -LiteralPath $tracedRoot -Force | ForEach-Object { $_.Name }) -join ",") -ceq "operator_trace")
Assert-RefusedBeforeAnyCall "a rehearsal whose run_id already has a rehearsal trace" {
    $rehearsedRoot = New-TempRoot
    New-Item -ItemType Directory -Path (Join-Path $rehearsedRoot "_rehearsal\operator_trace\RUN-20300101-001") -Force | Out-Null
    Invoke-FakeRun -ScenarioPath $goodScenario -DataRoot $rehearsedRoot -Transport (New-FakeTransport) -Rehearsal
} "*already has an operator trace*"

 # The tier is read again where the trace is written, from the scenario and from
 # nowhere else, so no caller can leave a trace with a tier its scenario does not
 # state, and nothing is created for a scenario whose tier the runner refuses.
$unknownTierRoot = New-TempRoot
$traceScenario = ConvertTo-RenderedScenario (New-ScenarioObject)
Assert-Throws "a trace is never written for a scenario with a tier the runner does not know" {
    Write-R1RunTrace -EffectiveRoot $unknownTierRoot -RunId "RUN-20300101-042" -Mode "collection" `
        -Scenario (ConvertTo-RenderedScenario (New-ScenarioObject -DatasetTier "formal")) `
        -ScenarioBytes ([byte[]](1, 2, 3)) -ScenarioSha256 ("ab" * 32)
} "*dataset_tier must be one of*"
Assert-Throws "a rehearsal trace is never written for a scenario of a formal pool" {
    Write-R1RunTrace -EffectiveRoot $unknownTierRoot -RunId "RUN-20300101-043" -Mode "rehearsal" `
        -Scenario (ConvertTo-RenderedScenario (New-ScenarioObject -DatasetTier "development")) `
        -ScenarioBytes ([byte[]](1, 2, 3)) -ScenarioSha256 ("ab" * 32)
} "*a rehearsal is not formal data*"
Assert-True "a refused tier leaves no trace directory behind" (
    @(Get-ChildItem -LiteralPath $unknownTierRoot -Recurse -Force -ErrorAction SilentlyContinue).Count -eq 0)

 # Each of the two files is created, never replaced.
$onceRoot = New-TempRoot
$onceDir = Write-R1RunTrace -EffectiveRoot $onceRoot -RunId "RUN-20300101-041" -Mode "collection" `
    -Scenario $traceScenario -ScenarioBytes ([byte[]](1, 2, 3)) -ScenarioSha256 ("ab" * 32)
Assert-Throws "a second trace for the same run_id is refused" {
    Write-R1RunTrace -EffectiveRoot $onceRoot -RunId "RUN-20300101-041" -Mode "collection" `
        -Scenario $traceScenario -ScenarioBytes ([byte[]](9, 9, 9)) -ScenarioSha256 ("cd" * 32)
} "*already has an operator trace*"
Assert-Throws "an existing file is never replaced" {
    Write-R1NewFile -Path (Join-Path $onceDir "scenario.json") -Bytes ([byte[]](9, 9, 9))
}
Assert-True "the first trace is still what was written" (
    ([System.IO.File]::ReadAllBytes((Join-Path $onceDir "scenario.json")) -join ",") -ceq "1,2,3" -and
    (Get-TraceOf -Root $onceRoot -RunId "RUN-20300101-041").record.scenario_sha256 -ceq ("ab" * 32))

 # A run the pre-run check stops has started nothing on Target-A and leaves no
 # trace, so its run_id is still free. A run that fails later keeps its trace.
Reset-Fakes @{ ComputerName = "OTHER-HOST" }
$stoppedRoot = New-TempRoot
Assert-Throws "a run stopped by the pre-run check" {
    Invoke-FakeRun -RunId "RUN-20300101-042" -ScenarioPath $goodScenario -DataRoot $stoppedRoot `
        -Transport (New-FakeTransport)
} "*computer name mismatch*"
Assert-True "a run stopped by the pre-run check leaves no trace and no directory" (
    @(Get-ChildItem -LiteralPath $stoppedRoot -Force).Count -eq 0)

Reset-Fakes @{ FailStep = "launch" }
$failedRoot = New-TempRoot
Assert-Throws "a run that fails after its first action" {
    Invoke-FakeRun -RunId "RUN-20300101-043" -ScenarioPath $goodScenario -DataRoot $failedRoot `
        -Transport (New-FakeTransport)
} "*synthetic failure in step launch*"
$failedTrace = Get-TraceOf -Root $failedRoot -RunId "RUN-20300101-043"
Assert-True "a failed run keeps the trace of the scenario it ran and no success artifact" (
    $failedTrace.record.scenario_sha256 -ceq (Get-FileSha256 $goodScenario) -and
    $failedTrace.record.dataset_tier -ceq "pilot" -and
    (Test-SuccessArtifactsAbsent -Root $failedRoot -RunId "RUN-20300101-043"))
Assert-RefusedBeforeAnyCall "the run_id of a failed run is not used again" {
    Invoke-FakeRun -RunId "RUN-20300101-043" -ScenarioPath $goodScenario -DataRoot $failedRoot `
        -Transport (New-FakeTransport)
} "*already has*"

 # A scenario that is not UTF-8 is refused instead of being read with
 # replacement characters, which would change what the digest stands for.
$notUtf8 = Join-Path (New-TempRoot) "scenario.json"
[System.IO.File]::WriteAllBytes($notUtf8, [byte[]](0x7B, 0x22, 0xFF, 0xFE, 0x22, 0x7D))
Assert-RefusedBeforeAnyCall "a scenario file that is not UTF-8" {
    Invoke-FakeRun -ScenarioPath $notUtf8 -DataRoot (New-TempRoot) -Transport (New-FakeTransport)
} "*scenario JSON is not UTF-8*"

 # Read-R1ScenarioFile: the digest is of the bytes on disk, a BOM included.
$bomScenario = Join-Path (New-TempRoot) "scenario.json"
$bomBody = [System.Text.Encoding]::UTF8.GetBytes(((New-ScenarioObject) | ConvertTo-Json -Depth 10))
[System.IO.File]::WriteAllBytes($bomScenario, [byte[]](@(0xEF, 0xBB, 0xBF) + $bomBody))
$bomRead = Read-R1ScenarioFile -Path $bomScenario
Assert-True "the scenario is parsed from the bytes whose digest is returned" (
    $bomRead.sha256 -ceq (Get-FileSha256 $bomScenario) -and $bomRead.bytes.Length -eq ($bomBody.Length + 3) -and
    [string]$bomRead.scenario.scenario_id -eq "R1")

 # ---------------------------------------------------------------------------
 # 7. Failures leave no success artifact
 # ---------------------------------------------------------------------------

Write-Host "`n=== failures leave no success artifact ===" -ForegroundColor Cyan

function Assert-FailedRun {
    param([string]$Name, [hashtable]$Options, [string]$MessageLike, [string]$RunType = "normal",
        [string]$ExpectedCalls)

    Reset-Fakes $Options
    $root = New-TempRoot
    $runId = "RUN-20300101-010"
    Assert-Throws $Name {
        Invoke-FakeRun -RunType $RunType -RunId $runId -ScenarioPath $goodScenario -DataRoot $root `
            -Transport (New-FakeTransport)
    } $MessageLike
    Assert-True ($Name + " - no execution_record, run_metadata or manifest") (
        Test-SuccessArtifactsAbsent -Root $root -RunId $runId)
    Assert-True ($Name + " - every opened session is closed") ((Get-CallCount "open") -eq (Get-CallCount "close"))
    if ($ExpectedCalls) {
        Assert-True ($Name + " - the run stopped where it failed") (($script:FakeCalls -join ",") -eq $ExpectedCalls)
    }
}

Assert-FailedRun "the connection of another process is not accepted" `
    @{ ConnectionGuid = $INTERMEDIATE_GUID } "*lineage check failed*"
Assert-FailedRun "a connection that telemetry recorded as udp is not accepted" `
    @{ TelemetryProtocol = "udp" } "*lineage check failed*recorded Protocol udp*"
Assert-FailedRun "a connection that telemetry recorded with an empty Protocol is not accepted" `
    @{ TelemetryProtocol = "" } "*lineage check failed*recorded Protocol (missing)*"
Assert-FailedRun "telemetry showing another intermediate is not accepted" `
    @{ TelemetryIntermediateImage = $attackImage } "*lineage check failed*"
Assert-FailedRun "an attack run whose telemetry shows the wrapper is not accepted" `
    @{ TelemetryIntermediateImage = $normalImage } "*lineage check failed*" "attack"
Assert-FailedRun "a failed connection stops the run" @{ TriggerSuccess = $false } `
    "*internal connection did not succeed*" "normal" `
    "open,invoke:probe,close,open,invoke:begin,invoke:prepare,invoke:launch,invoke:trigger,close"
Assert-FailedRun "a connection to another destination stops the run" @{ StatusTarget = "10.20.30.99" } `
    "*the approved destination is*"
Assert-FailedRun "a target clock behind the recorded start of the session stops the run" `
    @{ BeginUtc = "2029-12-31T23:59:59.000Z" } "*a clock moved during the run*" "normal" `
    "open,invoke:probe,close,open,invoke:begin,close"
Assert-FailedRun "a failed launch stops the run" @{ FailStep = "launch" } "*synthetic failure in step launch*" `
    "normal" "open,invoke:probe,close,open,invoke:begin,invoke:prepare,invoke:launch,close"
Assert-FailedRun "a failed export stops the run" @{ FailStep = "export" } "*synthetic failure in step export*"
Assert-FailedRun "a host that is not the approved target stops the run" @{ ComputerName = "OTHER-HOST" } `
    "*computer name mismatch*" "normal" "open,invoke:probe,close"
Assert-FailedRun "the name Sysmon records is the one compared with the approved target" `
    @{ RecordedComputerName = "OTHER-HOST" } "*computer name mismatch*" "normal" "open,invoke:probe,close"
Assert-FailedRun "a Sysmon config that is not the applied one stops the run" `
    @{ AppliedConfigSha = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" } `
    "*Sysmon applied config differs*" "normal" "open,invoke:probe,close"

 # ---------------------------------------------------------------------------
 # 8. Lineage check on synthetic records
 # ---------------------------------------------------------------------------

Write-Host "`n=== lineage check ===" -ForegroundColor Cyan

$approval = [ordered]@{ target = $TEST_TARGET; port = $TEST_PORT; protocol = "TCP" }
$normalLineage = [string[]]@("powershell.exe", "cmd.exe", "wsmprovhost.exe")

function Invoke-Lineage {
    param([object[]]$Records, [string[]]$Expected = $normalLineage, $Approval = $approval,
        [int]$SessionPid = 4000, [int]$IntermediatePid = 4100, [int]$FinalPid = 4200, [string]$Computer = $TEST_HOST)

    return Test-R1RunLineage -Records @(ConvertTo-ParsedRecords $Records) -ComputerName $Computer `
        -SessionPid $SessionPid -IntermediatePid $IntermediatePid -FinalPid $FinalPid `
        -ExpectedLineage $Expected -Approval $Approval
}

$matched = Invoke-Lineage (New-SyntheticRecords)
Assert-True "matched: the chain, the images and the connection all fit" ($matched.status -eq "matched")
Assert-True "matched: the final tool's ProcessGuid is returned" ($matched.final_process_guid -eq $FINAL_GUID)
Assert-True "the image comparison ignores case" (
    (Invoke-Lineage (New-SyntheticRecords -FinalImage "PowerShell.EXE")).status -eq "matched")
Assert-True "lineage_only: no connection was requested" (
    (Invoke-Lineage (New-SyntheticRecords -DestinationIp $null) -Approval $null).status -eq "lineage_only")
Assert-True "mismatched: the connection is missing" (
    (Invoke-Lineage (New-SyntheticRecords -DestinationIp $null)).status -eq "mismatched")
Assert-True "mismatched: the connection belongs to the intermediate" (
    (Invoke-Lineage (New-SyntheticRecords -ConnectionGuid $INTERMEDIATE_GUID)).status -eq "mismatched")
Assert-True "mismatched: another destination" (
    (Invoke-Lineage (New-SyntheticRecords -DestinationIp "10.20.30.99")).status -eq "mismatched")
Assert-True "mismatched: another port" (
    (Invoke-Lineage (New-SyntheticRecords -DestinationPort "443")).status -eq "mismatched")
Assert-True "mismatched: another intermediate image" (
    (Invoke-Lineage (New-SyntheticRecords -IntermediateImage "cscript.exe")).status -eq "mismatched")
Assert-True "mismatched: another final tool image" (
    (Invoke-Lineage (New-SyntheticRecords -FinalImage "other.exe")).status -eq "mismatched")
Assert-True "mismatched: another session host image" (
    (Invoke-Lineage (New-SyntheticRecords -SessionImage "other.exe")).status -eq "mismatched")
Assert-True "mismatched: the intermediate is not the process the runner started" (
    (Invoke-Lineage (New-SyntheticRecords) -IntermediatePid 4999).status -eq "mismatched")
Assert-True "mismatched: the session host is not this run's session" (
    (Invoke-Lineage (New-SyntheticRecords) -SessionPid 4999).status -eq "mismatched")
Assert-True "mismatched: the final tool has no EID 1" (
    (Invoke-Lineage (New-SyntheticRecords) -FinalPid 4999).status -eq "mismatched")
Assert-True "mismatched: records of another host are not used" (
    (Invoke-Lineage (New-SyntheticRecords -Computer "OTHER-HOST")).status -eq "mismatched")
Assert-True "mismatched: a duplicate ProcessGuid makes the lineage ambiguous" (
    (Invoke-Lineage (New-SyntheticRecords -DuplicateFinal)).status -eq "mismatched")
Assert-True "mismatched: no records at all" ((Invoke-Lineage @()).status -eq "mismatched")
Assert-True "the attack lineage passes with its own expectation" (
    (Invoke-Lineage (New-SyntheticRecords -IntermediateImage "cscript.exe") `
        -Expected ([string[]]@("powershell.exe", "cscript.exe", "wsmprovhost.exe"))).status -eq "matched")

 # The approved connection is TCP. The process, the address and the port of the
 # records below all fit; only the Protocol Sysmon wrote differs.
function New-FinalToolConnection {
    <# One more synthetic EID 3 of the final tool to the approved destination. #>
    param([int]$RecordId, [string]$Protocol)

    return (New-SyntheticRecord $RecordId 3 $TEST_HOST ([ordered]@{
        ProcessGuid = $FINAL_GUID; ProcessId = "4200"; Image = "C:\synthetic\powershell.exe"
        Protocol = $Protocol; DestinationIp = $TEST_TARGET; DestinationPort = [string]$TEST_PORT }))
}

Assert-True "matched: the Protocol comparison ignores case" (
    (Invoke-Lineage (New-SyntheticRecords -Protocol "TCP")).status -eq "matched" -and
    (Invoke-Lineage (New-SyntheticRecords -Protocol "Tcp")).status -eq "matched")
$recordedAsUdp = Invoke-Lineage (New-SyntheticRecords -Protocol "udp")
Assert-True "mismatched: the connection was recorded as udp" ($recordedAsUdp.status -eq "mismatched")
Assert-True "mismatched: the reason names the approved and the recorded Protocol" (
    $recordedAsUdp.reason -like "*the approved Protocol TCP: recorded Protocol udp")
Assert-True "mismatched: a udp connection still returns the final tool's ProcessGuid" (
    $recordedAsUdp.final_process_guid -eq $FINAL_GUID)
$withoutProtocol = Invoke-Lineage (New-SyntheticRecords -OmitProtocol)
Assert-True "mismatched: the connection record carries no Protocol" ($withoutProtocol.status -eq "mismatched")
Assert-True "mismatched: the reason says the Protocol is missing" (
    $withoutProtocol.reason -like "*the approved Protocol TCP: recorded Protocol (missing)")
Assert-True "mismatched: a null Protocol" (
    (Invoke-Lineage (New-SyntheticRecords -Protocol $null)).status -eq "mismatched")
Assert-True "mismatched: an empty Protocol" (
    (Invoke-Lineage (New-SyntheticRecords -Protocol "")).status -eq "mismatched")
Assert-True "mismatched: a Protocol that only starts with tcp" (
    (Invoke-Lineage (New-SyntheticRecords -Protocol "tcpip")).status -eq "mismatched")
 # A soft hyphen is ignored by a culture-aware comparison, so "tc-p" would equal
 # "tcp" under -eq. The check compares ordinally.
Assert-True "mismatched: a Protocol that only looks like tcp" (
    (Invoke-Lineage (New-SyntheticRecords -Protocol ("tc" + [char]0x00AD + "p"))).status -eq "mismatched")
Assert-True "matched: the tcp record is the connection when a udp record precedes it" (
    (Invoke-Lineage (@(New-SyntheticRecords -Protocol "udp") + @(New-FinalToolConnection 6 "tcp"))).status -eq "matched")
Assert-True "matched: the tcp record is the connection when a udp record follows it" (
    (Invoke-Lineage (@(New-SyntheticRecords -Protocol "tcp") + @(New-FinalToolConnection 6 "udp"))).status -eq "matched")
$twoOthers = Invoke-Lineage (@(New-SyntheticRecords -Protocol "udp") + @(New-FinalToolConnection 6 ""))
Assert-True "mismatched: a udp record and a record without a Protocol are both named" (
    $twoOthers.status -eq "mismatched" -and $twoOthers.reason -like "*recorded Protocol udp, (missing)")
Assert-True "mismatched: a wrong destination is still reported as the destination" (
    (Invoke-Lineage (New-SyntheticRecords -DestinationIp "10.20.30.99")).reason -notlike "*Protocol*")
 # An approval without a protocol and a record without one must not meet.
$approvalWithoutProtocol = [ordered]@{ target = $TEST_TARGET; port = $TEST_PORT }
Assert-True "mismatched: an approval that states no protocol accepts no record" (
    (Invoke-Lineage (New-SyntheticRecords -OmitProtocol) -Approval $approvalWithoutProtocol).status -eq "mismatched" -and
    (Invoke-Lineage (New-SyntheticRecords) -Approval $approvalWithoutProtocol).status -eq "mismatched")

 # ---------------------------------------------------------------------------
 # 8b. The reference of an attack run
 # ---------------------------------------------------------------------------

Write-Host "`n=== reference of an attack run ===" -ForegroundColor Cyan

 # The session host of the run in the synthetic records: process id 4000, created
 # at 00:00:00.000, RecordId 1. The session was opened between the two bounds.
$REFERENCE_FROM = [datetime]::new(2030, 1, 1, 0, 0, 0, [System.DateTimeKind]::Utc)
$REFERENCE_TO = $REFERENCE_FROM.AddSeconds(1)

function New-SessionHostRecord {
    <# Another EID 1 of the session host image, as the session of another step would leave it. #>
    param([int]$RecordId, [string]$UtcTime, [string]$ProcessId = "4000",
        [string]$Guid = "{00000000-0000-0000-0000-000000009000}", [string]$Image = "wsmprovhost.exe",
        [string]$Computer = $TEST_HOST)

    return (New-SyntheticRecord $RecordId 1 $Computer ([ordered]@{
        UtcTime = $UtcTime; ProcessGuid = $Guid; ProcessId = $ProcessId; Image = ("C:\synthetic\" + $Image)
        ParentProcessGuid = $OUTSIDE_GUID; ParentProcessId = "700" }))
}

function Invoke-Reference {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Records,
        [string]$SessionImage = "C:\synthetic\wsmprovhost.exe", [string]$SessionHostGuid = $SESSION_GUID,
        [datetime]$NotBefore = $REFERENCE_FROM, [datetime]$NotAfter = $REFERENCE_TO)

    return (Get-R1ReferenceEvent -Records (ConvertTo-ParsedRecords $Records) -ComputerName $TEST_HOST `
        -SessionPid 4000 -SessionImage $SessionImage -ExpectedImage "wsmprovhost.exe" `
        -NotBefore $NotBefore -NotAfter $NotAfter -SessionHostGuid $SessionHostGuid)
}

function Invoke-FakeRunOrNull {
    <# A run that is expected to succeed, or $null when it threw, so that the case fails by its name. #>
    param([Parameter(Mandatory = $true)][hashtable]$Arguments)

    try {
        return (Invoke-FakeRun @Arguments)
    } catch {
        Write-Host ("       the run threw: " + $_.Exception.Message) -ForegroundColor Yellow
        return $null
    }
}

$selected = Invoke-Reference (New-SyntheticRecords)
Assert-True "selected: the one EID 1 of the session host in the window is the reference" (
    $selected.status -eq "selected" -and $selected.reference_time -ceq "2030-01-01T00:00:00.000Z" -and
    $selected.reference_source_event_id -ceq "1" -and $selected.reference_source_event_id -is [string] -and
    $selected.process_guid -eq $SESSION_GUID)

 # Sessions of other steps leave the same image on the same target. They are not
 # the session of the run, whatever their process id.
$withOtherSessions = @(New-SyntheticRecords) + @(
    (New-SessionHostRecord 20 "2029-12-31 23:59:58.000" -Guid "{00000000-0000-0000-0000-000000009001}"),
    (New-SessionHostRecord 21 "2030-01-01 00:11:00.000" -Guid "{00000000-0000-0000-0000-000000009002}"),
    (New-SessionHostRecord 22 "2030-01-01 00:00:00.500" -ProcessId "5555" -Guid "{00000000-0000-0000-0000-000000009003}"),
    (New-SessionHostRecord 23 "2030-01-01 00:00:00.500" -Image "cmd.exe" -Guid "{00000000-0000-0000-0000-000000009004}"),
    (New-SessionHostRecord 24 "2030-01-01 00:00:00.500" -Computer "OTHER-HOST" -Guid "{00000000-0000-0000-0000-000000009005}"))
$amongOthers = Invoke-Reference $withOtherSessions
Assert-True "a session host with the same process id before the action or after the session was open is not a candidate" (
    $amongOthers.status -eq "selected" -and $amongOthers.reference_source_event_id -ceq "1")
Assert-True "another process id, another image and another host are not candidates either" (
    $amongOthers.process_guid -eq $SESSION_GUID)

$bounds = @(New-SyntheticRecords -SessionUtcTime "2030-01-01 00:00:01.000")
Assert-True "the two bounds of the window are part of it" (
    (Invoke-Reference $bounds).status -eq "selected" -and
    (Invoke-Reference (New-SyntheticRecords -SessionUtcTime "2030-01-01 00:00:01.001")).status -eq "undetermined" -and
    (Invoke-Reference (New-SyntheticRecords -SessionUtcTime "2029-12-31 23:59:59.999")).status -eq "undetermined")

$none = Invoke-Reference (New-SyntheticRecords -SessionUtcTime "2030-01-01 00:05:00.000")
Assert-True "undetermined: no record of the session host in the window" (
    $none.status -eq "undetermined" -and $none.reason -like "no EID 1 of wsmprovhost.exe with the session process id 4000*" -and
    $null -eq $none.reference_time -and $null -eq $none.reference_source_event_id)

 # The process id decides nothing on its own: a reused id gives two records, and
 # which one is the session is not guessed.
$reused = @(New-SyntheticRecords) + @((New-SessionHostRecord 30 "2030-01-01 00:00:00.700"))
$twice = Invoke-Reference $reused
Assert-True "undetermined: two records fit the session (a reused process id)" (
    $twice.status -eq "undetermined" -and $twice.reason -like "2 EID 1 records*exactly one is the session of this run")

$otherGuid = Invoke-Reference (New-SyntheticRecords) -SessionHostGuid "{00000000-0000-0000-0000-00000000ffff}"
Assert-True "undetermined: the record that fits is not the session host of the lineage of the run" (
    $otherGuid.status -eq "undetermined" -and $otherGuid.reason -like "*but the session host of the lineage of this run is*")
Assert-True "without a lineage the record is still found by what the session reported (a rehearsal)" (
    (Invoke-Reference (New-SyntheticRecords) -SessionHostGuid "").status -eq "selected")

foreach ($unreadable in @("", "not-a-time", "2030-01-01T00:00:00.000Z", "2030-01-01 00:00:00")) {
    $badTime = @(New-SyntheticRecords -SessionUtcTime $unreadable)
    $badTime[0].TimeCreated = "2030-01-01T00:00:00.000Z"
    $noTime = Invoke-Reference $badTime
    Assert-True ("undetermined: UtcTime '" + $unreadable + "' cannot be read, and TimeCreated does not replace it") (
        $noTime.status -eq "undetermined" -and $noTime.reason -like "*TimeCreated is not used in its place*" -and
        $null -eq $noTime.reference_time)
}
$missingTime = @(New-SyntheticRecords)
$missingTime[0].EventData.Remove("UtcTime")
Assert-True "undetermined: the record has no UtcTime field" (
    (Invoke-Reference $missingTime).status -eq "undetermined")

$noGuid = @(New-SyntheticRecords)
$noGuid[0].EventData.ProcessGuid = ""
Assert-True "undetermined: the record carries no ProcessGuid" (
    (Invoke-Reference $noGuid -SessionHostGuid "").reason -like "*carries no ProcessGuid*")
$noRecordId = @(New-SyntheticRecords)
$noRecordId[0].Remove("RecordId")
Assert-True "undetermined: the record carries no RecordId" (
    (Invoke-Reference $noRecordId).reason -like "*carries no usable RecordId*")

 # Every time of a reference is UTC. The parser of EventData.UtcTime and the two
 # bounds of the window are strict today; the cases below pin that down, so that
 # a value read as local time, left without a kind or carrying an offset cannot
 # slip in later. They hold in whatever time zone the guards run.
 # Nothing below checks a DateTime this file built. A run is executed and what
 # its own code produced is looked at: the two bounds Invoke-R1PilotRun hands to
 # the selection (the recorded start of the first action and the stamp Target-A
 # took once the session existed), and the DateTime the parser of
 # Get-R1ReferenceEvent gave the record it selected. Both functions are wrapped
 # for the length of that one run and call the originals unchanged.
$UTC_KIND = [System.DateTimeKind]::Utc
$stampOriginal = ${function:Get-UtcStamp}
$referenceOriginal = ${function:Get-R1ReferenceEvent}
$script:ReferenceBounds = $null
$script:ReferenceStamps = New-Object System.Collections.Generic.List[datetime]
$script:InsideReference = $false
function Get-UtcStamp {
    param([datetime]$Value)
    # The selection stamps its two bounds and then the time of the record it chose.
    if ($script:InsideReference) { $script:ReferenceStamps.Add($Value) }
    return (& $stampOriginal $Value)
}
function Get-R1ReferenceEvent {
    param($Records, $ComputerName, $SessionPid, $SessionImage, $ExpectedImage,
        [datetime]$NotBefore, [datetime]$NotAfter, $SessionHostGuid)

    $script:ReferenceBounds = @{ NotBefore = $NotBefore; NotAfter = $NotAfter }
    $script:InsideReference = $true
    try {
        return (& $referenceOriginal -Records $Records -ComputerName $ComputerName -SessionPid $SessionPid `
            -SessionImage $SessionImage -ExpectedImage $ExpectedImage -NotBefore $NotBefore -NotAfter $NotAfter `
            -SessionHostGuid $SessionHostGuid)
    } finally {
        $script:InsideReference = $false
    }
}
try {
    # The session host is created 250 ms after the action and the session answers
    # 400 ms after it. The record carries a TimeCreated that is neither.
    Reset-Fakes @{ BeginUtc = "2030-01-01T00:00:00.400Z"; SessionUtcTime = "2030-01-01 00:00:00.250" }
    $boundRun = Invoke-FakeRunOrNull @{ RunType = "attack"; RunId = "RUN-20300101-061"; ScenarioPath = $goodScenario
        DataRoot = (New-TempRoot); Transport = (New-FakeTransport) }
} finally {
    Set-Item -Path function:Get-UtcStamp -Value $stampOriginal
    Set-Item -Path function:Get-R1ReferenceEvent -Value $referenceOriginal
}
Assert-True "the lower bound of a run, the recorded start of its first action, is a UTC DateTime" (
    $null -ne $script:ReferenceBounds -and $script:ReferenceBounds.NotBefore.Kind -eq $UTC_KIND -and
    $script:ReferenceBounds.NotBefore.Ticks -eq [datetime]::new(2030, 1, 1, 0, 0, 0, $UTC_KIND).Ticks)
Assert-True "the upper bound of a run, the stamp taken once the session existed, is a UTC DateTime" (
    $null -ne $script:ReferenceBounds -and $script:ReferenceBounds.NotAfter.Kind -eq $UTC_KIND -and
    $script:ReferenceBounds.NotAfter.Ticks -eq [datetime]::new(2030, 1, 1, 0, 0, 0, 400, $UTC_KIND).Ticks)
Assert-True "the time the parser of the runner gave the selected record in that run is a UTC DateTime" (
    $script:ReferenceStamps.Count -eq 3 -and $script:ReferenceStamps[2].Kind -eq $UTC_KIND -and
    $script:ReferenceStamps[2].Ticks -eq [datetime]::new(2030, 1, 1, 0, 0, 0, 250, $UTC_KIND).Ticks)
Assert-True "that run records the EventData.UtcTime between the two bounds as its reference_time, not TimeCreated" (
    $null -ne $boundRun -and $boundRun.reference.reference_time -ceq "2030-01-01T00:00:00.250Z" -and
    $boundRun.reference.reference_source_event_id -ceq "1")
Assert-True "the two functions are the ones of the runner again" (
    (Get-UtcStamp ([datetime]::new(2030, 1, 1, 0, 0, 0, $UTC_KIND))) -ceq "2030-01-01T00:00:00.000Z" -and
    $script:ReferenceStamps.Count -eq 3 -and (Invoke-Reference (New-SyntheticRecords)).status -eq "selected" -and
    $script:ReferenceStamps.Count -eq 3)

 # A time with an offset or without the UTC designator is not converted: it is
 # refused where it is read.
foreach ($offsetTime in @("2030-01-01 09:00:00.000+09:00", "2030-01-01 00:00:00.000Z", "2030-01-01 00:00:00.000 +00:00")) {
    Assert-True ("undetermined: an EventData.UtcTime that carries an offset or a designator is not read: '" + $offsetTime + "'") (
        (Invoke-Reference (New-SyntheticRecords -SessionUtcTime $offsetTime)).status -eq "undetermined")
}
foreach ($notUtcStamp in @("2030-01-01T09:00:00.400+09:00", "2030-01-01T00:00:00.400", "2030-01-01 00:00:00.400Z")) {
    Assert-FailedRun ("an attack run whose session stamp is not strict UTC: '" + $notUtcStamp + "'") `
        @{ BeginUtc = $notUtcStamp } "*begin utc must be ISO 8601 UTC ending in 'Z'*" "attack" `
        "open,invoke:probe,close,open,invoke:begin,close"
}

$otherImage = Invoke-Reference (New-SyntheticRecords) -SessionImage "C:\synthetic\other.exe"
Assert-True "undetermined: the session reported another image than the scenario expects" (
    $otherImage.status -eq "undetermined" -and $otherImage.reason -like "the session reported the image 'other.exe'*")

 # In a run: an attack run without its reference writes no Ground Truth.
Assert-FailedRun "an attack run whose session host record is not in the collected window" `
    @{ SessionUtcTime = "2030-01-01 00:05:00.000" } "*reference undetermined: no EID 1 of wsmprovhost.exe*" "attack"
Assert-FailedRun "an attack run with two records that fit its session" `
    @{ ExtraRecords = @((New-SessionHostRecord 30 "2030-01-01 00:00:00.000")) } `
    "*reference undetermined: 2 EID 1 records*" "attack"
Assert-FailedRun "an attack run whose session host record has no readable UtcTime" `
    @{ SessionUtcTime = "not-a-time" } "*TimeCreated is not used in its place*" "attack"
Assert-FailedRun "an attack run whose session reports another image" `
    @{ SessionImage = "C:\synthetic\other.exe" } "*reference undetermined: the session reported the image*" "attack"

 # A normal run takes no reference, so the same telemetry does not stop it.
Reset-Fakes @{ SessionUtcTime = "not-a-time" }
$normalWithoutSessionTime = Invoke-FakeRunOrNull @{ RunId = "RUN-20300101-051"; ScenarioPath = $goodScenario
    DataRoot = (New-TempRoot); Transport = (New-FakeTransport) }
Assert-True "a normal run is not stopped by a session host record without a readable time" (
    $null -ne $normalWithoutSessionTime -and $normalWithoutSessionTime.lineage.status -eq "matched" -and
    $null -eq $normalWithoutSessionTime.reference.reference_time)

 # The collection of an attack run has to reach reference_time plus the horizon.
 # The session below was open 30 s after its action, and its host was created then.
$late = @{ BeginUtc = "2030-01-01T00:00:30.000Z"; SessionUtcTime = "2030-01-01 00:00:30.000" }
Reset-Fakes $late
$shortRoot = New-TempRoot
Assert-Throws "an attack run that ends before reference_time plus the horizon is refused" {
    Invoke-FakeRun -RunType "attack" -RunId "RUN-20300101-052" -ObservationSec 600 -ScenarioPath $goodScenario `
        -DataRoot $shortRoot -Transport (New-FakeTransport)
} "*the collection ended at 2030-01-01T00:10:00.000Z, before reference_time + 600 s (2030-01-01T00:10:30.000Z)*"
Assert-True "an attack run that ends before the horizon - no execution_record, run_metadata or manifest" (
    Test-SuccessArtifactsAbsent -Root $shortRoot -RunId "RUN-20300101-052")
Reset-Fakes
$atHorizon = Invoke-FakeRunOrNull @{ RunType = "attack"; RunId = "RUN-20300101-053"; ObservationSec = 600
    ScenarioPath = $goodScenario; DataRoot = (New-TempRoot); Transport = (New-FakeTransport) }
Assert-True "an attack run that ends exactly at reference_time plus the horizon is accepted" (
    $null -ne $atHorizon -and $atHorizon.reference.reference_time -ceq "2030-01-01T00:00:00.000Z" -and
    $atHorizon.lineage.status -eq "matched")
Reset-Fakes $late
$normalShort = Invoke-FakeRunOrNull @{ RunId = "RUN-20300101-054"; ObservationSec = 600
    ScenarioPath = $goodScenario; DataRoot = (New-TempRoot); Transport = (New-FakeTransport) }
Assert-True "a normal run has no reference_time and is not held to a horizon from one" (
    $null -ne $normalShort -and $normalShort.lineage.status -eq "matched" -and
    $null -eq $normalShort.reference.reference_time)

 # A rehearsal does not wait, so it is not held to the horizon. Its attack run
 # still records its reference.
Reset-Fakes
$rehearsedAttackRoot = New-TempRoot
$rehearsedAttack = Invoke-FakeRunOrNull @{ RunType = "attack"; RunId = "RUN-20300101-055"; Rehearsal = $true
    ScenarioPath = $goodScenario; DataRoot = $rehearsedAttackRoot; Transport = (New-FakeTransport) }
$rehearsedMetadataPath = Join-Path $rehearsedAttackRoot "_rehearsal\ground_truth\RUN-20300101-055\run_metadata.json"
$rehearsedMetadata = ""
if (Test-Path -LiteralPath $rehearsedMetadataPath) {
    $rehearsedMetadata = Get-Content -LiteralPath $rehearsedMetadataPath -Raw -Encoding UTF8
}
Assert-True "a rehearsal of an attack run records its reference and is not held to the horizon" (
    $null -ne $rehearsedAttack -and $rehearsedAttack.reference.reference_source_event_id -ceq "1" -and
    $rehearsedMetadata -match '"reference_action_id":\s+"A01"' -and $script:SleepCalls.Count -eq 0)

 # ---------------------------------------------------------------------------
 # 9. Rehearsal
 # ---------------------------------------------------------------------------

Write-Host "`n=== rehearsal ===" -ForegroundColor Cyan

Reset-Fakes
$rehearsalRoot = New-TempRoot
$rehearsal = Invoke-FakeRun -RunId "RUN-20300101-020" -DataRoot $rehearsalRoot -Rehearsal `
    -ScenarioPath (Save-Scenario (New-ScenarioObject -Target $null)) -Transport (New-FakeTransport)
Assert-True "a rehearsal reports its mode" ($rehearsal.mode -eq "rehearsal")
Assert-True "a rehearsal without a destination triggers no connection" ((Get-CallCount "invoke:trigger") -eq 0)
Assert-True "a rehearsal still launches the lineage once" ((Get-CallCount "invoke:launch") -eq 1)
Assert-True "a rehearsal waits for nothing" ($script:SleepCalls.Count -eq 0)
Assert-True "a rehearsal without a connection reports the lineage only" ($rehearsal.lineage.status -eq "lineage_only")
Assert-True "the task is told not to connect" (
    (([string]$script:FakeArguments["prepare"].channel_config) | ConvertFrom-Json).connect -eq $false)
Assert-True "rehearsal output is kept under _rehearsal" (
    (Test-Path -LiteralPath (Join-Path $rehearsalRoot "_rehearsal\ground_truth\RUN-20300101-020\run_metadata.json")) -and
    -not (Test-Path -LiteralPath (Join-Path $rehearsalRoot "raw")) -and
    -not (Test-Path -LiteralPath (Join-Path $rehearsalRoot "ground_truth")))
Assert-True "rehearsal output carries the marker" (
    Test-Path -LiteralPath (Join-Path $rehearsalRoot "_rehearsal\REHEARSAL.txt"))
$rehearsalTrace = Get-TraceOf -Root (Join-Path $rehearsalRoot "_rehearsal") -RunId "RUN-20300101-020"
Assert-True "a rehearsal keeps its trace under _rehearsal, marked as a Pilot rehearsal" (
    $rehearsalTrace.record.run_id -ceq "RUN-20300101-020" -and $rehearsalTrace.record.dataset_tier -ceq "pilot" -and
    $rehearsalTrace.record.mode -ceq "rehearsal" -and $rehearsal.dataset_tier -ceq "pilot" -and
    (Test-Path -LiteralPath $rehearsalTrace.scenario_path) -and
    -not (Test-Path -LiteralPath (Join-Path $rehearsalRoot "operator_trace")))
$rehearsalRows = @(Import-Csv -LiteralPath (Join-Path $rehearsalRoot "_rehearsal\ground_truth\RUN-20300101-020\execution_record.csv") -Encoding UTF8)
Assert-True "the skipped connection is not recorded as executed" (
    (@($rehearsalRows | ForEach-Object { $_.action_id }) -join ",") -eq "N01,N02,N03,N05")

Reset-Fakes
$rehearsalWithTarget = Invoke-FakeRun -RunId "RUN-20300101-021" -DataRoot (New-TempRoot) -Rehearsal `
    -ScenarioPath $goodScenario -Transport (New-FakeTransport)
Assert-True "a rehearsal with an internal destination makes the one connection" (
    (Get-CallCount "invoke:trigger") -eq 1 -and $rehearsalWithTarget.lineage.status -eq "matched")

 # ---------------------------------------------------------------------------
 # 10. The probe step's query of Sysmon
 # ---------------------------------------------------------------------------

Write-Host "`n=== probe step: Sysmon query ===" -ForegroundColor Cyan

 # The one remote step that is executed here and not replaced, because what it
 # has to get right is how the two streams of a native program reach it. It runs
 # in a background job - like a remote session a host without a console, with
 # its argument passed through serialization - against a stand-in for Sysmon64:
 # a .cmd file that writes prepared bytes and starts nothing else. Every value in
 # those bytes is synthetic.

$script:ProbeRoot = New-TempRoot
$script:ProbeTools = New-Object System.Collections.Generic.List[object]
$probeConfig = Join-Path $script:ProbeRoot "config.xml"
[System.IO.File]::WriteAllText($probeConfig, "<Sysmon/>")
$probeConfigSha = Get-FileSha256 $probeConfig

function New-ProbeTool {
    <#
        A stand-in for Sysmon64 -c: a .cmd file that writes the given bytes to its
        stdout and its stderr and ends with the given exit code.

        The probe starts this path through ProcessStartInfo with
        UseShellExecute = false, exactly as the production step does. The
        supported Windows PowerShell 5.1 runners execute this .cmd fixture.

        cmd's "type" copies a file as it is unless the file starts with a UTF-16
        byte order mark, which it converts. The first byte of stdout is therefore
        kept in a file of its own, so that no file starts with one.
    #>
    param([Parameter(Mandatory = $true)][string]$Name, [byte[]]$Stdout = @(), [byte[]]$Stderr = @(),
        [int]$ExitCode = 0)

    $folder = Join-Path $script:ProbeRoot $Name
    New-Item -ItemType Directory -Path $folder | Out-Null
    [System.IO.File]::WriteAllBytes((Join-Path $folder "stdout-0.bin"), [byte[]]@($Stdout | Select-Object -First 1))
    [System.IO.File]::WriteAllBytes((Join-Path $folder "stdout-1.bin"), [byte[]]@($Stdout | Select-Object -Skip 1))
    [System.IO.File]::WriteAllBytes((Join-Path $folder "stderr.bin"), $Stderr)
    $tool = Join-Path $folder "tool.cmd"
    Set-Content -LiteralPath $tool -Encoding ASCII -Value @(
        "@echo off", 'type "%~dp0stderr.bin" 1>&2', 'type "%~dp0stdout-0.bin"', 'type "%~dp0stdout-1.bin"',
        ("exit /b " + $ExitCode))
    $script:ProbeTools.Add(@{ tool = $tool; stdout = $Stdout; stderr = $Stderr; exit_code = $ExitCode })
    return $tool
}

function Test-ProbeToolFaithful {
    <# True when a stand-in, with its two streams sent to files, wrote its bytes unchanged and ended with its exit code. #>
    param([Parameter(Mandatory = $true)][hashtable]$Entry)

    $folder = Split-Path -Parent $Entry.tool
    $readBack = Join-Path $folder "read-back.cmd"
    Set-Content -LiteralPath $readBack -Encoding ASCII -Value @(
        "@echo off", 'call "%~dp0tool.cmd" -c 1>"%~dp0seen-stdout.bin" 2>"%~dp0seen-stderr.bin"',
        "exit /b %ERRORLEVEL%")
    & $readBack | Out-Null
    $exitCode = $LASTEXITCODE
    $seenStdout = [System.IO.File]::ReadAllBytes((Join-Path $folder "seen-stdout.bin"))
    $seenStderr = [System.IO.File]::ReadAllBytes((Join-Path $folder "seen-stderr.bin"))
    return ($exitCode -eq $Entry.exit_code -and
        [System.Convert]::ToBase64String($seenStdout) -ceq [System.Convert]::ToBase64String($Entry.stdout) -and
        [System.Convert]::ToBase64String($seenStderr) -ceq [System.Convert]::ToBase64String($Entry.stderr))
}

function Invoke-ProbeStep {
    <# Runs the probe step against a stand-in the way the runner sends it. Returns its answer, or throws what it threw. #>
    param([Parameter(Mandatory = $true)][string]$Tool)

    $arguments = @{ sysmon_binary = $Tool; sysmon_config_path = $probeConfig; log_name = "R1-Guard-No-Such-Log" }
    $job = Start-Job -ScriptBlock $R1_REMOTE_STEPS.probe -ArgumentList (, $arguments)
    try {
        if (-not (Wait-Job -Job $job -Timeout 120)) { throw "the probe step did not end within 120 seconds" }
        return (Receive-Job -Job $job -ErrorAction Stop)
    } finally {
        Remove-Job -Job $job -Force
    }
}

function Get-ProbeAnswer {
    <# The answer of the probe step for a stand-in, or $null when the step threw, so that the case fails by its name. #>
    param([Parameter(Mandatory = $true)][string]$Tool)

    try {
        return (Invoke-ProbeStep $Tool)
    } catch {
        Write-Host ("       the probe step threw: " + $_.Exception.Message) -ForegroundColor Yellow
        return $null
    }
}

function Test-ProbeAnswer {
    <# True when an answer of the probe step carries the three fields of $probeText and the hash of the config file. #>
    param([AllowNull()]$Answer, [string]$ConfigFile = "C:\synthetic\config.xml")

    if ($null -eq $Answer) { return $false }
    return ([string]$Answer.sysmon.config_file -ceq $ConfigFile -and
        [string]$Answer.sysmon.config_hash -ceq ("SHA256=" + $probeConfigSha.ToUpper()) -and
        [string]$Answer.sysmon.hashing_algorithms -ceq "SHA256" -and
        [string]$Answer.config_sha256 -ceq $probeConfigSha)
}

 # What the first run on a VM met, in synthetic form: text that starts with an
 # empty line, written to stdout as UTF-16 without a byte order mark, and one
 # empty line on stderr although the exit code is 0. The step used to end on the
 # line on stderr, and it could not have read a field from that stdout.
$probeLines = @("", "Stand-in Monitor", "Current configuration:",
    " - Config file:                   C:\synthetic\config.xml",
    (" - Config hash:                   SHA256=" + $probeConfigSha.ToUpper()),
    " - HashingAlgorithms:             SHA256", "")
$probeText = $probeLines -join "`r`n"
$utf16 = [System.Text.Encoding]::Unicode
$ascii = [System.Text.Encoding]::ASCII
$emptyLine = [byte[]](0x0D, 0x0A)

$asMet = Get-ProbeAnswer (New-ProbeTool "utf16-and-stderr" -Stdout $utf16.GetBytes($probeText) -Stderr $emptyLine)
Assert-True "UTF-16 stdout is read while a line arrives on stderr" (Test-ProbeAnswer $asMet)
Assert-True "the answer keeps the shape the run reads" (
    $null -ne $asMet -and [string]$asMet.computer_name -eq $env:COMPUTERNAME -and
    $asMet.ContainsKey("recorded_computer_name") -and $null -eq $asMet.recorded_computer_name -and
    (ConvertTo-R1Utc $asMet.utc "probe utc") -is [datetime])
$accepted = $true
try {
    Test-SysmonConfigApplied -ConfigSha256 $asMet.config_sha256 -ConfigState $asMet.sysmon
} catch { $accepted = $false }
Assert-True "a collection run accepts that answer" $accepted

 # Each of the two alone, so that a regression names itself.
Assert-True "a line on stderr does not end the step" (Test-ProbeAnswer (Get-ProbeAnswer (
    New-ProbeTool "stderr-alone" -Stdout $ascii.GetBytes($probeText) -Stderr $emptyLine)))
Assert-True "UTF-16 stdout without a byte order mark is read" (Test-ProbeAnswer (Get-ProbeAnswer (
    New-ProbeTool "utf16-alone" -Stdout $utf16.GetBytes($probeText))))
Assert-True "UTF-16 stdout with a byte order mark is read" (Test-ProbeAnswer (Get-ProbeAnswer (
    New-ProbeTool "utf16-bom" -Stdout ([byte[]](@(0xFF, 0xFE) + $utf16.GetBytes($probeText))))))

 # What still ends the step. Text on stderr never does.
Assert-Throws "an exit code other than 0 ends the step, whatever stdout holds" {
    Invoke-ProbeStep (New-ProbeTool "exit-code" -Stdout $utf16.GetBytes($probeText) -ExitCode 3)
} "*exited with code 3 (stdout * bytes, stderr 0 bytes)*"
Assert-Throws "an empty stdout ends the step" {
    Invoke-ProbeStep (New-ProbeTool "no-stdout" -Stderr $ascii.GetBytes("only stderr`r`n"))
} "*wrote nothing to stdout*"
Assert-Throws "a Sysmon64 that is not there ends the step" {
    Invoke-ProbeStep (Join-Path $script:ProbeRoot "no-such-tool.exe")
}

 # Nothing is removed to make a stream readable: a byte too many, a U+0000 in
 # the text and half a surrogate pair each leave the step without an answer.
Assert-Throws "UTF-16 stdout with one byte too many is refused" {
    Invoke-ProbeStep (New-ProbeTool "odd-length" -Stdout ([byte[]]($utf16.GetBytes($probeText) + @(0x58))))
} "*in no encoding this step reads*"
Assert-Throws "stdout that holds U+0000 is refused, not cleaned" {
    Invoke-ProbeStep (New-ProbeTool "nul-character" -Stdout $utf16.GetBytes(
        $probeText.Replace("SHA256=", ("SHA256=" + [char]0))))
} "*in no encoding this step reads*"
Assert-Throws "stdout that is not valid UTF-16 is refused" {
    Invoke-ProbeStep (New-ProbeTool "half-pair" -Stdout (
        [byte[]]($utf16.GetBytes($probeText) + @(0x00, 0xD8, 0x41, 0x00))))
} "*in no encoding this step reads*"

 # Stdout without a zero byte is read with the system code page, and as strictly
 # as UTF-16 is: a byte that code page cannot decode is not turned into another
 # character. Which letters a code page holds and which bytes it cannot decode
 # differ from one to the next, so both are looked for here. A code page that
 # decodes every byte, such as 1252, has no stdout to refuse.
$codePage = [System.Text.Encoding]::GetEncoding([System.Text.Encoding]::Default.CodePage,
    [System.Text.EncoderFallback]::ExceptionFallback, [System.Text.DecoderFallback]::ExceptionFallback)
$codePagePath = $null
foreach ($letter in @(0x00E9, 0xD55C, 0x3042, 0x4E2D, 0x0416, 0x03A9, 0x05D0, 0x0E01, 0x0627)) {
    $candidate = "C:\synthetic\" + [char]$letter + "\config.xml"
    try { [void]$codePage.GetBytes($candidate); $codePagePath = $candidate; break } catch { continue }
}
Assert-True "stdout in the system code page is read, a letter outside ASCII included" (
    $null -ne $codePagePath -and (Test-ProbeAnswer -ConfigFile $codePagePath -Answer (Get-ProbeAnswer (
        New-ProbeTool "code-page" -Stdout $codePage.GetBytes(
            $probeText.Replace("C:\synthetic\config.xml", $codePagePath))))))

$undecodable = $null
foreach ($value in 0x80..0xFF) {
    try { [void]$codePage.GetString([byte[]]@([byte]$value)) } catch { $undecodable = [byte]$value; break }
}
if ($null -ne $undecodable) {
    Assert-Throws "stdout the system code page cannot decode is refused, not patched" {
        Invoke-ProbeStep (New-ProbeTool "code-page-undecodable" -Stdout (
            [byte[]]($ascii.GetBytes($probeText) + @($undecodable))))
    } "*in no encoding this step reads*"
} else {
    Write-Host ("       not run here: code page " + $codePage.CodePage +
        " decodes every byte, so it has no stdout to refuse") -ForegroundColor Yellow
}

 # A field the step does not find stays empty and a hash is passed on as it was
 # reported. The comparison the run makes with the answer decides both.
$withoutHash = Get-ProbeAnswer (New-ProbeTool "no-config-hash" -Stderr $emptyLine -Stdout $utf16.GetBytes(
    (@($probeLines | Where-Object { $_ -notlike "*Config hash:*" }) -join "`r`n")))
Assert-True "a missing Config hash line leaves the field empty" (
    $null -ne $withoutHash -and $null -eq $withoutHash.sysmon.config_hash -and
    [string]$withoutHash.sysmon.hashing_algorithms -ceq "SHA256")
if ($null -ne $withoutHash) {
    Assert-FailedRun "an answer without a config hash stops a collection run" `
        @{ SysmonState = $withoutHash.sysmon } "*Sysmon reported no config hash*" "normal" "open,invoke:probe,close"
}

$otherHash = Get-ProbeAnswer (New-ProbeTool "other-hash" -Stderr $emptyLine -Stdout $utf16.GetBytes(
    $probeText.Replace($probeConfigSha.ToUpper(), ("F" * 64))))
Assert-True "a reported hash is passed on as it was written" (
    $null -ne $otherHash -and [string]$otherHash.sysmon.config_hash -ceq ("SHA256=" + ("F" * 64)) -and
    [string]$otherHash.config_sha256 -ceq $probeConfigSha)
Assert-Throws "a collection run refuses a reported hash that is not the file's" {
    Test-SysmonConfigApplied -ConfigSha256 $otherHash.config_sha256 -ConfigState $otherHash.sysmon
} "*Sysmon applied config differs from the config file*"

 # The cases above rest on the stand-ins doing what they were given to do.
Assert-True "every stand-in wrote the bytes and the exit code it was given" (
    $script:ProbeTools.Count -gt 0 -and
    @($script:ProbeTools | Where-Object { -not (Test-ProbeToolFaithful $_) }).Count -eq 0)

 # ---------------------------------------------------------------------------
 # 10. Collection profile: an entry through WMI, the boot-to-end raw window,
 #     the readiness record and the collection provenance
 #
 # The scenario built here is synthetic. Its four actions, their offsets and the
 # length of a run follow the timeline that was handed over as decided; its
 # variation and its reference policy version are made up.
 # ---------------------------------------------------------------------------

Write-Host "`n=== collection profile (entry through WMI) ===" -ForegroundColor Cyan

$WMI_ROOT_GUID = "{00000000-0000-0000-0000-000000000900}"
$WMI_BOOT_UTC = "2029-12-31T23:50:00.000Z"
$RUN_START_UTC = "2030-01-01T00:00:00.000Z"

function New-WmiScenarioObject {
    <# A scenario whose intermediate is started through WMI. -Change edits it before it is returned. #>
    param([scriptblock]$Change, [AllowNull()][string]$Target = $TEST_TARGET)

    $scenario = New-ScenarioObject -FamilyId "wmi_management" -VariationId "synthetic_variation" -Target $Target
    $scenario.planned_lineage | Add-Member -NotePropertyName "entry" -NotePropertyValue (
        [pscustomobject]@{ kind = "wmi_process"; root_image = "WmiPrvSE.exe" })
    $scenario.planned_lineage.intermediate.normal = [pscustomobject]@{
        image = "wscript.exe"; launcher_kind = "jscript"; launcher_file = "r1_launch.js"
        arguments = @("//NoLogo", "//B", "{launcher}") }
    $scenario.planned_lineage.intermediate.attack = [pscustomobject]@{
        image = "cmd.exe"; launcher_kind = "batch"; launcher_file = "r1_launch.cmd"
        arguments = @("/d", "/c", "{launcher}") }
    $scenario | Add-Member -NotePropertyName "collection" -NotePropertyValue (
        [pscustomobject]@{ raw_window = "target_boot_to_run_end"; readiness_method = "out_of_band" })
    $scenario | Add-Member -NotePropertyName "reference_rule" -NotePropertyValue (
        [pscustomobject]@{ action_step = "invoke"; source = "wmi_created_process_create" })
    # The four actions of a run through WMI, the same in both runs. The run
    # that records a reference names the first of them.
    foreach ($runType in @("normal", "attack")) {
        $prefix = $runType.Substring(0, 1).ToUpper()
        $scenario.runs.$runType.actions = @(
            [pscustomobject]@{ action_id = ($prefix + "01"); offset_sec = 0; step = "invoke"
                               action_type = "wmi_process_create"; description = "synthetic" },
            [pscustomobject]@{ action_id = ($prefix + "02"); offset_sec = 300; step = "launch"
                               action_type = "process_create"; description = "synthetic" },
            [pscustomobject]@{ action_id = ($prefix + "03"); offset_sec = 480; step = "connect"
                               action_type = "network_connection"; description = "synthetic" },
            [pscustomobject]@{ action_id = ($prefix + "04"); offset_sec = 720; step = "run_end"
                               action_type = "run_end"; description = "synthetic" })
    }
    $scenario.shortcut_controls.actions_per_run = 4
    $scenario.run_length.observation_sec = 780
    $scenario.runs.attack.reference_action_id = "A01"
    $scenario.run_metadata.reference_policy_version = "synthetic-reference-policy"
    # The policies the scenario names, and what a renderer wrote about them after
    # it read the registries. Every identity, hash and path here is made up; the
    # window is two seconds after the call.
    $scenario | Add-Member -NotePropertyName "policies" -NotePropertyValue ([pscustomobject]@{
        approved_lineage = [pscustomobject]@{ policy_id = "synthetic-approved-lineage"; version = "v9.9" }
        reference        = [pscustomobject]@{ policy_id = "synthetic-reference" } })
    $scenario | Add-Member -NotePropertyName "policy_provenance" -NotePropertyValue ([pscustomobject]@{
        approved_lineage = [pscustomobject][ordered]@{
            policy_id = "synthetic-approved-lineage"; version = "v9.9"; family_id = "wmi_management"
            lifecycle = "development"; config_path = "configs/synthetic_approved_lineage_policies.yaml"
            config_hash = ("a1" * 32); loader = "load_r1_approved_lineage_policy" }
        reference        = [pscustomobject][ordered]@{
            policy_id = "synthetic-reference"; version = "synthetic-reference-policy"
            family_id = "wmi_management"; config_path = "configs/synthetic_reference_policies.yaml"
            config_hash = ("b2" * 32); loader = "synthetic-loader-v0"; reference_action_id = "A01"
            action_type = "wmi_process_create"; reference_process_name = "cmd.exe"
            candidate_start_offset_sec = 0; candidate_window_sec = 2; success_return_value = 0
            require_process_id = $true; expected_evaluation_horizon_sec = 600 } })
    if ($null -ne $Change) { & $Change $scenario | Out-Null }
    return $scenario
}

function New-TimedRecord {
    <# One synthetic record with the time Sysmon would write, which the plain fixture leaves out. #>
    param([int]$RecordId, [int]$EventId, [string]$UtcTime, $EventData, [string]$Computer = $TEST_HOST)

    $data = [ordered]@{ UtcTime = $UtcTime }
    foreach ($key in $EventData.Keys) { $data[$key] = $EventData[$key] }
    return (New-SyntheticRecord $RecordId $EventId $Computer $data)
}

function New-TimedRunRecords {
    <#
        What the raw export of one run holds, every record with its UtcTime.

        -FromBoot adds what an export from the boot of the target holds on top:
        the service host and the provider host, created at boot. The background
        process is five seconds older than the run, inside the margin the export
        has always had. With -FromBoot the intermediate is a child of the
        provider host; without it, of the session host.
    #>
    param(
        [string]$IntermediateImage = "wscript.exe",
        [switch]$FromBoot,
        [switch]$NoConnection,
        [string]$SessionUtcTime = "2030-01-01 00:00:00.000",
        [string]$IntermediateUtcTime = "",
        [double]$LaunchOffsetSec = 0,
        [double]$ToolOffsetSec = -1,
        [double]$ConnectOffsetSec = -1,
        [string]$FinalToolUtcTime = ""
    )

    # The intermediate, the final tool and its connection follow the launch,
    # which is at the start of the run unless -LaunchOffsetSec says later.
    $launchAt = [datetime]::new(2030, 1, 1, 0, 0, 0, [System.DateTimeKind]::Utc).AddSeconds($LaunchOffsetSec)
    $invariant = [System.Globalization.CultureInfo]::InvariantCulture
    if ([string]::IsNullOrEmpty($IntermediateUtcTime)) {
        $IntermediateUtcTime = $launchAt.AddMilliseconds(200).ToString("yyyy-MM-dd HH:mm:ss.fff", $invariant)
    }
    # The final tool is started by a later action when -ToolOffsetSec says so,
    # and makes its connection at -ConnectOffsetSec; without them both follow
    # the launch at once.
    $runStart = [datetime]::new(2030, 1, 1, 0, 0, 0, [System.DateTimeKind]::Utc)
    $toolAt = $launchAt
    if ($ToolOffsetSec -ge 0) { $toolAt = $runStart.AddSeconds($ToolOffsetSec) }
    $connectAt = $toolAt
    if ($ConnectOffsetSec -ge 0) { $connectAt = $runStart.AddSeconds($ConnectOffsetSec) }
    $finalUtcTime = $toolAt.AddMilliseconds(400).ToString("yyyy-MM-dd HH:mm:ss.fff", $invariant)
    if (-not [string]::IsNullOrEmpty($FinalToolUtcTime)) { $finalUtcTime = $FinalToolUtcTime }
    $connectionUtcTime = $connectAt.AddMilliseconds(600).ToString("yyyy-MM-dd HH:mm:ss.fff", $invariant)

    $records = New-Object System.Collections.Generic.List[object]
    $parentOfIntermediate = $SESSION_GUID
    if ($FromBoot) {
        $parentOfIntermediate = $WMI_ROOT_GUID
        $records.Add((New-TimedRecord 5 1 "2029-12-31 23:50:05.000" ([ordered]@{
            ProcessGuid = $OUTSIDE_GUID; ProcessId = "700"; Image = "C:\synthetic\svchost.exe" })))
        $records.Add((New-TimedRecord 10 1 "2029-12-31 23:50:22.000" ([ordered]@{
            ProcessGuid = $WMI_ROOT_GUID; ProcessId = "900"; Image = "C:\synthetic\WmiPrvSE.exe"
            ParentProcessGuid = $OUTSIDE_GUID; ParentProcessId = "700" })))
    }
    $records.Add((New-TimedRecord 11 1 "2029-12-31 23:59:55.000" ([ordered]@{
        ProcessGuid = "{00000000-0000-0000-0000-000000000800}"; ProcessId = "800"
        Image = "C:\synthetic\background.exe"; ParentProcessGuid = $OUTSIDE_GUID; ParentProcessId = "700" })))
    $records.Add((New-TimedRecord 1 1 $SessionUtcTime ([ordered]@{
        ProcessGuid = $SESSION_GUID; ProcessId = "4000"; Image = "C:\synthetic\wsmprovhost.exe"
        ParentProcessGuid = $OUTSIDE_GUID; ParentProcessId = "700" })))
    $records.Add((New-TimedRecord 2 1 $IntermediateUtcTime ([ordered]@{
        ProcessGuid = $INTERMEDIATE_GUID; ProcessId = "4100"; Image = ("C:\synthetic\" + $IntermediateImage)
        ParentProcessGuid = $parentOfIntermediate; ParentProcessId = "900" })))
    $records.Add((New-TimedRecord 3 1 $finalUtcTime ([ordered]@{
        ProcessGuid = $FINAL_GUID; ProcessId = "4200"; Image = "C:\synthetic\powershell.exe"
        ParentProcessGuid = $INTERMEDIATE_GUID; ParentProcessId = "4100" })))
    if (-not $NoConnection) {
        $records.Add((New-TimedRecord 4 3 $connectionUtcTime ([ordered]@{
            ProcessGuid = $FINAL_GUID; ProcessId = "4200"; Image = "C:\synthetic\powershell.exe"
            Protocol = "tcp"; DestinationIp = $TEST_TARGET; DestinationPort = [string]$TEST_PORT })))
    }
    return $records.ToArray()
}

function New-DestinationConnection {
    <# One more connection to the internal destination, by any process, at a given time. #>
    param([int]$RecordId, [string]$UtcTime, [string]$ProcessGuid = "{00000000-0000-0000-0000-000000000800}")
    return (New-TimedRecord $RecordId 3 $UtcTime ([ordered]@{
        ProcessGuid = $ProcessGuid; ProcessId = "800"; Image = "C:\synthetic\background.exe"
        Protocol = "tcp"; DestinationIp = $TEST_TARGET; DestinationPort = [string]$TEST_PORT }))
}

 # The plain fake transport, with the two things a declared collection needs:
 # the step that launches through WMI, the boot time when the probe is asked for
 # it, and telemetry whose records carry their UtcTime.
$script:PlainFakeInvoke = (New-FakeTransport).invoke
function New-CollectionFakeTransport {
    $script:FakeLaunchTime = $null
    $script:FakeToolTime = $null
    $script:FakeConnectTime = $null
    $transport = New-FakeTransport
    $transport.invoke = {
        param($Session, $Step, $Arguments)
        if ($Step -eq "launch_wmi") {
            $script:FakeCalls.Add("invoke:" + $Step)
            $script:FakeArguments[$Step] = $Arguments
            if ((Get-FakeOption "FailStep" "") -eq $Step) { throw ("synthetic failure in step " + $Step) }
            # What the step hands back: the stamp taken right before the call,
            # what the call returned, as unsigned numbers like the real one,
            # and the stamp taken when the call was back.
            $script:FakeLaunchTime = $script:FakeNow
            $answer = @{
                utc           = (Get-FakeOption "WmiActionUtc" (Get-UtcStamp $script:FakeNow))
                return_value  = (Get-FakeOption "WmiReturnValue" ([uint32]0))
                process_id    = (Get-FakeOption "WmiProcessId" ([uint32]4100))
                completed_utc = (Get-FakeOption "WmiCompletedUtc" (Get-UtcStamp $script:FakeNow.AddSeconds(1)))
            }
            foreach ($name in @(Get-FakeOption "WmiOmit" @())) { $answer.Remove($name) }
            # The call took the second the answer says it took.
            $script:FakeNow = $script:FakeNow.AddSeconds(1)
            return $answer
        }
        if ($Step -eq "open_gate" -or $Step -eq "start_tool" -or $Step -eq "end_run") {
            $script:FakeCalls.Add("invoke:" + $Step)
            $script:FakeArguments[$Step] = $Arguments
            if ((Get-FakeOption "FailStep" "") -eq $Step) { throw ("synthetic failure in step " + $Step) }
            $stamp = Get-UtcStamp $script:FakeNow
            if ($Step -eq "open_gate") { return @{ utc = $stamp } }
            if ($Step -eq "start_tool") {
                # The stamp taken right before the intermediate was told to start
                # the tool, the process id the tool reported, and the stamp taken
                # when it was ready.
                $script:FakeToolTime = $script:FakeNow
                $toolAnswer = @{
                    utc           = (Get-FakeOption "ToolActionUtc" $stamp)
                    final_pid     = (Get-FakeOption "ToolFinalPid" 4200)
                    completed_utc = (Get-FakeOption "ToolCompletedUtc" (Get-UtcStamp $script:FakeNow.AddSeconds(1)))
                }
                # The tool needed the second the answer says it needed.
                $script:FakeNow = $script:FakeNow.AddSeconds(1)
                return $toolAnswer
            }
            # end_run: every confirmed Run-owned process is accounted for, and
            # the provider host is still running afterwards. A failure path may
            # know only the intermediate or both intermediate and final tool.
            $owned = @($Arguments.owned)
            $defaultEnded = @($owned | ForEach-Object {
                    @{ process_id = [int]$_.process_id; image = [string]$_.image; outcome = "stopped" }
                })
            return @{
                utc           = $stamp
                ended         = (Get-FakeOption "EndRunEnded" $defaultEnded)
                provider_host = (Get-FakeOption "EndRunProvider" @{
                    process_id = 900; name = "WmiPrvSE.exe"; running_before = $true; running_after = $true })
                completed_utc = $stamp
            }
        }
        $answer = & $script:PlainFakeInvoke $Session $Step $Arguments
        if ($Step -eq "probe" -and $Arguments.ContainsKey("read_boot_time")) {
            $answer.boot_utc = (Get-FakeOption "BootUtc" $WMI_BOOT_UTC)
        }
        if ($Step -eq "trigger") {
            $script:FakeConnectTime = $script:FakeNow
            $answer.status.pid = [int](Get-FakeOption "StatusPid" $answer.status.pid)
        }
        return $answer
    }
    $transport.convert = {
        param($EvtxPath, $JsonlPath)
        $script:FakeCalls.Add("convert")

        $records = Get-FakeOption "Records" $null
        if ($null -eq $records) {
            $throughWmi = $script:FakeArguments.ContainsKey("launch_wmi")
            if ($throughWmi) {
                $image = ([string]$script:FakeArguments["launch_wmi"].command_line -split " ")[0]
            } else {
                $image = [string]$script:FakeArguments["launch"].executable
            }
            $launchOffset = 0
            if ($null -ne $script:FakeLaunchTime) {
                $launchOffset = ($script:FakeLaunchTime -
                    [datetime]::new(2030, 1, 1, 0, 0, 0, [System.DateTimeKind]::Utc)).TotalSeconds
            }
            $runStart = [datetime]::new(2030, 1, 1, 0, 0, 0, [System.DateTimeKind]::Utc)
            $toolOffset = -1
            if ($null -ne $script:FakeToolTime) { $toolOffset = ($script:FakeToolTime - $runStart).TotalSeconds }
            $connectOffset = -1
            if ($null -ne $script:FakeConnectTime -and $throughWmi) {
                $connectOffset = ($script:FakeConnectTime - $runStart).TotalSeconds
            }
            $records = New-TimedRunRecords -IntermediateImage $image -FromBoot:$throughWmi `
                -NoConnection:((-not $script:FakeArguments.ContainsKey("trigger")) -or
                    [bool](Get-FakeOption "TelemetryNoConnection" $false)) `
                -SessionUtcTime $script:FakeSessionUtc -LaunchOffsetSec $launchOffset `
                -ToolOffsetSec $toolOffset -ConnectOffsetSec $connectOffset `
                -FinalToolUtcTime ([string](Get-FakeOption "TelemetryFinalUtcTime" ""))
        }
        $records = @($records) + @(Get-FakeOption "ExtraRecords" @())

        $lines = @($records | ForEach-Object { $_ | ConvertTo-Json -Compress -Depth 5 })
        $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllLines($JsonlPath, [string[]]$lines, $utf8NoBom)
        return $lines.Count
    }
    return $transport
}

function Save-ReadinessRecord {
    <# The record an out-of-band readiness check hands to a run. -Change edits it; -Text replaces it. #>
    param([scriptblock]$Change, [string]$Text)

    $record = [ordered]@{
        method = "out_of_band"; checked_at = "2029-12-31T23:59:20.000Z"; result = "ready"
        active_tcp_probe_used = $false }
    if ($null -ne $Change) { & $Change $record | Out-Null }
    $path = Join-Path (New-TempRoot) "readiness.json"
    if ([string]::IsNullOrEmpty($Text)) { $Text = ($record | ConvertTo-Json) }
    [System.IO.File]::WriteAllText($path, $Text, (New-Object System.Text.UTF8Encoding($false)))
    return $path
}

function Invoke-FakeCollectionRun {
    param(
        [string]$RunType = "normal", [string]$RunId = "RUN-20300101-001", [string]$ScenarioPath,
        [string]$DataRoot, [AllowNull()][AllowEmptyString()][string]$ReadinessRecordPath,
        [AllowNull()][hashtable]$Transport, [int]$ObservationSec = 780, [switch]$Rehearsal, [switch]$DryRun,
        [string]$IncrementalStreamControlRoot = "", [switch]$PositionFinality, [int]$PositionFreezeAckTimeoutSec = 900,
        [scriptblock]$Sleeper = $script:FakeSleeper
    )
    return (Invoke-R1PilotRun -RunType $RunType -RunId $RunId -ScenarioJsonPath $ScenarioPath `
        -DataRoot $DataRoot -WorkDir $TEST_WORK -ObservationSec $ObservationSec -VmSnapshot "synthetic-snapshot" `
        -TargetSysmonBinary "C:\synthetic\Sysmon64.exe" -TargetSysmonConfigPath "C:\synthetic\sysmonconfig.xml" `
        -ReadinessRecordPath $ReadinessRecordPath `
        -Connection @{ address = "synthetic"; port = 5985 } -Transport $Transport `
        -NowProvider $script:FakeNowProvider -Sleeper $Sleeper `
        -IncrementalStreamControlRoot $IncrementalStreamControlRoot -PositionFinality:$PositionFinality `
        -PositionFreezeAckTimeoutSec $PositionFreezeAckTimeoutSec `
        -Rehearsal:$Rehearsal -DryRun:$DryRun)
}

 # --- the profile a scenario states --------------------------------------------

$sessionProfile = Get-R1CollectionProfile -Scenario (New-ScenarioObject)
Assert-True "a scenario that states no profile is collected as before" (
    $sessionProfile.entry_kind -ceq "remoting_session" -and $sessionProfile.root_image -ceq "wsmprovhost.exe" -and
    $sessionProfile.raw_window -ceq "run_window" -and $null -eq $sessionProfile.readiness_method -and
    $sessionProfile.reference_source -ceq "session_host_process_create" -and
    $sessionProfile.reference_step -ceq "session_begin" -and
    -not $sessionProfile.collection_declared)

$wmiProfile = Get-R1CollectionProfile -Scenario (New-WmiScenarioObject)
Assert-True "an entry through WMI has the provider host as its root and the boot-to-end raw window" (
    $wmiProfile.entry_kind -ceq "wmi_process" -and $wmiProfile.root_image -ceq "WmiPrvSE.exe" -and
    $wmiProfile.session_host_image -ceq "wsmprovhost.exe" -and
    $wmiProfile.raw_window -ceq "target_boot_to_run_end" -and $wmiProfile.collection_declared)
Assert-True "an entry through WMI establishes readiness out of band" ($wmiProfile.readiness_method -ceq "out_of_band")
Assert-True "an entry through WMI takes its reference from the process its launch action creates" (
    $wmiProfile.reference_source -ceq "wmi_created_process_create" -and
    $wmiProfile.reference_step -ceq "invoke")

foreach ($case in @(
    @{ name = "without a collection block"; like = "*collection.raw_window must be target_boot_to_run_end*"
       change = { param($s) $s.PSObject.Properties.Remove("collection") } },
    @{ name = "with the run window"; like = "*collection.raw_window must be target_boot_to_run_end*"
       change = { param($s) $s.collection.raw_window = "run_window" } },
    @{ name = "without a readiness method"; like = "*collection.readiness_method must be out_of_band*"
       change = { param($s) $s.collection.readiness_method = $null } },
    @{ name = "with an active probe as its readiness method"; like = "*collection.readiness_method must be out_of_band or null*"
       change = { param($s) $s.collection.readiness_method = "active_tcp_from_target" } },
    @{ name = "whose root is the session host"; like = "*must not be the session host image*"
       change = { param($s) $s.planned_lineage.entry.root_image = "wsmprovhost.exe" } },
    @{ name = "whose root is a path"; like = "*root_image must be a plain file name*"
       change = { param($s) $s.planned_lineage.entry.root_image = "C:\dir\WmiPrvSE.exe" } },
    @{ name = "with a key the entry does not have"; like = "*planned_lineage.entry states unknown key*"
       change = { param($s) $s.planned_lineage.entry | Add-Member -NotePropertyName "parent_image_fallback" -NotePropertyValue $true } },
    @{ name = "without a reference rule"; like = "*reference_rule must be stated for wmi_process*"
       change = { param($s) $s.PSObject.Properties.Remove("reference_rule") } },
    @{ name = "that names the session host as its reference source"; like = "*is not implemented for wmi_process*"
       change = { param($s) $s.reference_rule.source = "session_host_process_create"; $s.reference_rule.action_step = "session_begin" } },
    @{ name = "whose reference rule is left undecided"; like = "*is not implemented for wmi_process*"
       change = { param($s) $s.reference_rule.source = $null; $s.reference_rule.action_step = $null } },
    @{ name = "whose reference is taken at the session step"; like = "*reference_rule.action_step must be invoke*"
       change = { param($s) $s.reference_rule.action_step = "session_begin" } },
    @{ name = "whose normal run records its first action with another type"
       like = "*runs.normal: the invoke action of a wmi_process scenario is recorded as wmi_process_create*"
       change = { param($s) ($s.runs.normal.actions | Where-Object { $_.step -eq "invoke" }).action_type = "process_create" } },
    @{ name = "whose attack run records its first action with another type"
       like = "*runs.attack: the invoke action of a wmi_process scenario is recorded as wmi_process_create*"
       change = { param($s) ($s.runs.attack.actions | Where-Object { $_.step -eq "invoke" }).action_type = "process_create" } })) {

    $broken = New-WmiScenarioObject -Change $case.change
    Assert-Throws ("an entry through WMI " + $case.name + " is refused") {
        Get-R1CollectionProfile -Scenario $broken
    } $case.like
}

$unknownKind = New-ScenarioObject
$unknownKind.planned_lineage | Add-Member -NotePropertyName "entry" -NotePropertyValue (
    [pscustomobject]@{ kind = "scheduled_task"; root_image = "wsmprovhost.exe" })
Assert-Throws "an entry kind that is not implemented is refused" {
    Get-R1CollectionProfile -Scenario $unknownKind
} "*planned_lineage.entry.kind must be one of*"

$sessionWithBoot = New-ScenarioObject
$sessionWithBoot | Add-Member -NotePropertyName "collection" -NotePropertyValue (
    [pscustomobject]@{ raw_window = "target_boot_to_run_end"; readiness_method = "out_of_band" })
Assert-Throws "the session entry is not given the boot-to-end raw window" {
    Get-R1CollectionProfile -Scenario $sessionWithBoot
} "*collection.raw_window must be run_window for remoting_session*"

foreach ($case in @(
    @{ name = "left undecided"; rule = [pscustomobject]@{ action_step = $null; source = $null } },
    @{ name = "replaced by the rule of the entry through WMI"
       rule = [pscustomobject]@{ action_step = "invoke"; source = "wmi_created_process_create" } })) {

    $sessionOtherRule = New-ScenarioObject
    $sessionOtherRule | Add-Member -NotePropertyName "reference_rule" -NotePropertyValue $case.rule
    Assert-Throws ("the reference rule of the session entry cannot be " + $case.name) {
        Get-R1CollectionProfile -Scenario $sessionOtherRule
    } "*is not implemented for remoting_session*"
}

 # --- the launch plan -----------------------------------------------------------

$wmiScenario = New-WmiScenarioObject
$wmiNormalPlan = Get-R1LaunchPlan -Scenario $wmiScenario -RunType "normal" -WorkDir $TEST_WORK
$wmiAttackPlan = Get-R1LaunchPlan -Scenario $wmiScenario -RunType "attack" -WorkDir $TEST_WORK
Assert-True "through WMI the normal run is planned as provider host -> one intermediate -> the final tool" (
    (@($wmiNormalPlan.expected_lineage) -join ",") -ceq "powershell.exe,wscript.exe,WmiPrvSE.exe")
Assert-True "through WMI the attack run is planned with the other intermediate and the same root" (
    (@($wmiAttackPlan.expected_lineage) -join ",") -ceq "powershell.exe,cmd.exe,WmiPrvSE.exe")
Assert-True "through WMI the intermediate is handed over as one command line without quoting" (
    [string]$wmiNormalPlan.intermediate.command_line -ceq ("wscript.exe //NoLogo //B " + $TEST_WORK + "\r1_launch.js") -and
    [string]$wmiAttackPlan.intermediate.command_line -ceq ("cmd.exe /d /c " + $TEST_WORK + "\r1_launch.cmd"))
Assert-True "through WMI both runs still end in the same final command and write the same files" (
    $wmiNormalPlan.final.command_line -ceq $wmiAttackPlan.final.command_line -and
    (@($wmiNormalPlan.files.Keys) -join ",") -ceq (@($wmiAttackPlan.files.Keys) -join ","))
Assert-R1PlanShortcutFree -Plan $wmiNormalPlan
Assert-R1PlanShortcutFree -Plan $wmiAttackPlan
Assert-True "through WMI neither plan names the run type or carries an encoded command option" $true

$sessionPlan = Get-R1LaunchPlan -Scenario (New-ScenarioObject) -RunType "normal" -WorkDir $TEST_WORK
Assert-True "the plan of the session entry is the one it always was: no command line, the session host as its root" (
    -not $sessionPlan.intermediate.Contains("command_line") -and
    (@($sessionPlan.intermediate.Keys) -join ",") -ceq "executable,arguments,launcher_path" -and
    [string]$sessionPlan.expected_lineage[2] -ceq "wsmprovhost.exe")

Assert-Throws "a root that names the run type is refused before anything is started" {
    Get-R1LaunchPlan -Scenario (New-WmiScenarioObject -Change {
            param($s) $s.planned_lineage.entry.root_image = "attack_host.exe" }) -RunType "normal" -WorkDir $TEST_WORK
} "*planned_lineage.entry.root_image would expose the run type on Target-A*"
Assert-Throws "an argument that would need quoting in the command line is refused" {
    Get-R1LaunchPlan -Scenario (New-WmiScenarioObject -Change {
            param($s) $s.planned_lineage.intermediate.normal.arguments = @("//B", "{launcher}", "two words") }) `
        -RunType "normal" -WorkDir $TEST_WORK
} "*would need quoting in a command line*"

$launchWmiText = $R1_REMOTE_STEPS["launch_wmi"].ToString()
Assert-True "the step that launches through WMI calls the process class and runs no helper program" (
    $launchWmiText -match 'Invoke-CimMethod -ClassName Win32_Process -MethodName Create' -and
    $launchWmiText -notmatch 'wmic|Start-Process|cmd\.exe|powershell\.exe|schtasks|sc\.exe')
Assert-True "the step that launches through WMI hands back what the call returned and judges nothing" (
    $launchWmiText -match 'return_value\s+= \$returnValue' -and
    $launchWmiText -match 'process_id\s+= \$processId' -and
    $launchWmiText -notmatch 'Create returned')

 # The time of the action is the clock of the target, as UTC, on the line right
 # before the call: nothing is done between the stamp and the call.
$launchWmiLines = @($launchWmiText -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" })
$launchCallAt = -1
for ($index = 0; $index -lt $launchWmiLines.Count; $index++) {
    if ($launchWmiLines[$index] -like '$created = Invoke-CimMethod*') { $launchCallAt = $index }
}
Assert-True "the time of the launch is taken as UTC on the line right before the call" (
    $launchCallAt -gt 0 -and
    $launchWmiLines[$launchCallAt - 1] -ceq '$utc = (Get-Date).ToUniversalTime().ToString($stampFormat)' -and
    $launchWmiText -match '\$stampFormat = "yyyy-MM-ddTHH:mm:ss\.fffZ"')
Assert-True "the launch step starts the intermediate only: it does not wait for a final tool" (
    $launchWmiText -notmatch 'ready_file|Start-Sleep|final_pid')

 # The intermediate is started 300 s before it starts the final tool. Both
 # launchers wait in between by reading one line from a pipe of the target.
$gateCmd = [string]$wmiNormalPlan.files["r1_launch.cmd"]
$gateJs = [string]$wmiNormalPlan.files["r1_launch.js"]
Assert-True "through WMI the batch launcher reads the gate before it starts the final tool, and stops on any other word" (
    $gateCmd.Contains('set /p R1GATE=<\\.\pipe\r1_gate') -and
    $gateCmd.Contains('if not "%R1GATE%"=="go" exit /b 1') -and
    $gateCmd.IndexOf('exit /b 1') -lt $gateCmd.IndexOf([string]$wmiNormalPlan.final.command_line))
Assert-True "through WMI the script launcher reads the gate before it starts the final tool, and stops on any other word" (
    $gateJs.Contains('fso.OpenTextFile("\\\\.\\pipe\\r1_gate", 1)') -and
    $gateJs.Contains('if (word != "go") { WScript.Quit(1); }') -and
    $gateJs.IndexOf('WScript.Quit(1)') -lt $gateJs.IndexOf('shell.Run('))
Assert-True "waiting on the gate starts no process and reaches no other machine" (
    $gateCmd -notmatch 'timeout|ping|waitfor|choice|start |powershell -|\\\\[^.\\]' -and
    $gateJs -notmatch 'WScript\.Sleep|\.Exec\(|XMLHTTP|Socket')
Assert-True "through WMI both plans name the gate, and both runs write the same two launchers" (
    $wmiNormalPlan.intermediate.gate_pipe -ceq "r1_gate" -and $wmiAttackPlan.intermediate.gate_pipe -ceq "r1_gate" -and
    [string]$wmiAttackPlan.files["r1_launch.cmd"] -ceq $gateCmd -and [string]$wmiAttackPlan.files["r1_launch.js"] -ceq $gateJs)
Assert-True "the launchers of the session entry do not wait: they are the ones they always were" (
    @($sessionPlan.files.Keys | Where-Object { $_ -like 'r1_launch*' } |
        Where-Object { ([string]$sessionPlan.files[$_]) -match 'pipe|R1GATE|OpenTextFile' }).Count -eq 0)
Assert-True "the step of the session entry is not touched" (
    $R1_REMOTE_STEPS["launch"].ToString() -match 'Start-Process -FilePath \$Arguments\.executable' -and
    $R1_REMOTE_STEPS["launch"].ToString() -notmatch 'Cim')

 # --- the reference action of a scenario through WMI -----------------------------

$wmiScenarioPath = Save-Scenario (New-WmiScenarioObject)
$readinessPath = Save-ReadinessRecord
$wmiFixture = New-WmiScenarioObject
$wmiLaunchId = [string]($wmiFixture.runs.attack.actions | Where-Object { $_.step -eq "invoke" }).action_id
$wmiToolId = [string]($wmiFixture.runs.attack.actions | Where-Object { $_.step -eq "launch" }).action_id
$plainSessionId = [string]((New-ScenarioObject).runs.attack.actions |
    Where-Object { $_.step -eq "session_begin" }).action_id

$wmiInputs = Assert-R1RunInputs -RunType "attack" -RunId "RUN-20300101-001" -ScenarioJsonPath $wmiScenarioPath `
    -DataRoot (New-TempRoot) -WorkDir $TEST_WORK -ObservationSec 780
Assert-True "through WMI the attack run names its first action, the launch, as the reference action" (
    $wmiInputs.reference_step -ceq "invoke" -and $wmiInputs.reference_action_id -ceq $wmiLaunchId -and
    $wmiLaunchId -ceq "A01" -and (@($wmiInputs.step_order) -join ",") -ceq "invoke,launch,connect,run_end" -and
    (@($wmiInputs.actions | ForEach-Object { [string]$_.action_id + "@" + [string]$_.offset_sec }) -join ",") -ceq
        "A01@0,A02@300,A03@480,A04@720")
$wmiNormalInputs = Assert-R1RunInputs -RunType "normal" -RunId "RUN-20300101-001" -ScenarioJsonPath $wmiScenarioPath `
    -DataRoot (New-TempRoot) -WorkDir $TEST_WORK -ObservationSec 780
Assert-True "through WMI the normal run names no reference action" ($null -eq $wmiNormalInputs.reference_action_id)
$sessionInputs = Assert-R1RunInputs -RunType "attack" -RunId "RUN-20300101-001" -ScenarioJsonPath $goodScenario `
    -DataRoot (New-TempRoot) -WorkDir $TEST_WORK -ObservationSec 660
Assert-True "the session entry still names its session action" (
    $sessionInputs.reference_step -ceq "session_begin" -and $sessionInputs.reference_action_id -ceq $plainSessionId -and
    (@($sessionInputs.step_order) -join ",") -ceq "session_begin,prepare,launch,connect,session_end")

foreach ($case in @(
    @{ name = "naming its second action as its reference"
       like = ("*reference_action_id must be the invoke action " + $wmiLaunchId + "*")
       change = { param($s) $s.runs.attack.reference_action_id = $wmiToolId } },
    @{ name = "naming no reference action"; like = "*runs.attack.reference_action_id is missing*"
       change = { param($s) $s.runs.attack.reference_action_id = $null } },
    @{ name = "without a reference policy version"; like = "*reference_policy_version must be a non-blank string*"
       change = { param($s) $s.run_metadata.reference_policy_version = $null } })) {

    Reset-Fakes
    $root = New-TempRoot
    $brokenPath = Save-Scenario (New-WmiScenarioObject -Change $case.change)
    Assert-Throws ("an attack run through WMI " + $case.name + " is refused") {
        Invoke-FakeCollectionRun -RunType "attack" -ScenarioPath $brokenPath -DataRoot $root `
            -ReadinessRecordPath $readinessPath -Transport (New-CollectionFakeTransport) -Rehearsal
    } $case.like
    Assert-True ("  ... and it opens no session and writes nothing (" + $case.name + ")") (
        $script:FakeCalls.Count -eq 0 -and @(Get-ChildItem -LiteralPath $root -Recurse -Force).Count -eq 0)
}

Reset-Fakes
$wmiAttackDry = Invoke-FakeCollectionRun -RunType "attack" -ScenarioPath $wmiScenarioPath -DataRoot (New-TempRoot) -DryRun
Assert-True "a dry run of the attack run still shows its plan" (
    $wmiAttackDry.mode -eq "dry_run" -and $wmiAttackDry.plan.intermediate.executable -ceq "cmd.exe" -and
    [string]$wmiAttackDry.plan.expected_lineage[2] -ceq "WmiPrvSE.exe" -and $script:FakeCalls.Count -eq 0)

 # --- the readiness record ------------------------------------------------------

foreach ($case in @(
    @{ name = "without a readiness record"; path = ""; like = "*the readiness record is missing*" },
    @{ name = "whose readiness record does not exist"; path = (Join-Path (New-TempRoot) "absent.json"); like = "*the readiness record is missing*" },
    @{ name = "whose readiness record is not JSON"; path = (Save-ReadinessRecord -Text "ready"); like = "*the readiness record is not readable JSON*" },
    @{ name = "whose readiness record says a probe was used"; like = "*must state active_tcp_probe_used as false*"
       path = (Save-ReadinessRecord -Change { param($r) $r.active_tcp_probe_used = $true }) },
    @{ name = "whose readiness record states the probe as text"; like = "*must state active_tcp_probe_used as false*"
       path = (Save-ReadinessRecord -Change { param($r) $r.active_tcp_probe_used = "false" }) },
    @{ name = "whose readiness record does not state the probe"; like = "*the readiness record states no active_tcp_probe_used*"
       path = (Save-ReadinessRecord -Change { param($r) $r.Remove("active_tcp_probe_used") }) },
    @{ name = "whose readiness record is of another method"; like = "*the readiness record states the method*"
       path = (Save-ReadinessRecord -Change { param($r) $r.method = "active_tcp_from_target" }) },
    @{ name = "whose readiness record is not ready"; like = "*the run is not started unless it is ready*"
       path = (Save-ReadinessRecord -Change { param($r) $r.result = "not_ready" }) },
    @{ name = "whose readiness record has no time"; like = "*readiness checked_at*"
       path = (Save-ReadinessRecord -Change { param($r) $r.checked_at = "yesterday" }) })) {

    Reset-Fakes
    $root = New-TempRoot
    Assert-Throws ("a run through WMI " + $case.name + " is refused") {
        Invoke-FakeCollectionRun -ScenarioPath $wmiScenarioPath -DataRoot $root `
            -ReadinessRecordPath $case.path -Transport (New-CollectionFakeTransport) -Rehearsal
    } $case.like
    Assert-True ("  ... and it opens no session (" + $case.name + ")") ($script:FakeCalls.Count -eq 0)
}

Reset-Fakes
$root = New-TempRoot
$lateReadiness = Save-ReadinessRecord -Change { param($r) $r.checked_at = "2030-01-01T00:00:30.000Z" }
Assert-Throws "a readiness record taken after the start of the run is refused" {
    Invoke-FakeCollectionRun -ScenarioPath $wmiScenarioPath -DataRoot $root `
        -ReadinessRecordPath $lateReadiness -Transport (New-CollectionFakeTransport) -Rehearsal
} "*the readiness record was taken at*after the start of the run*"
Assert-True "  ... and nothing after the pre-run check is done" (
    ($script:FakeCalls -join ",") -eq "open,invoke:probe,close" -and
    -not (Test-Path -LiteralPath (Join-Path $root "_rehearsal\operator_trace")))

Reset-Fakes
Assert-Throws "a run of the session entry takes no readiness record" {
    Invoke-FakeCollectionRun -ScenarioPath $goodScenario -DataRoot (New-TempRoot) `
        -ReadinessRecordPath $readinessPath -Transport (New-FakeTransport)
} "*a readiness record is not an input of this run*"
Assert-True "  ... and it opens no session" ($script:FakeCalls.Count -eq 0)

 # --- a rehearsal of the normal run through WMI ----------------------------------

Reset-Fakes
$wmiRoot = New-TempRoot
$wmiRunId = "RUN-20300101-001"
$wmiResult = Invoke-FakeCollectionRun -ScenarioPath $wmiScenarioPath -DataRoot $wmiRoot `
    -ReadinessRecordPath $readinessPath -Transport (New-CollectionFakeTransport) -Rehearsal
$wmiEffectiveRoot = Join-Path $wmiRoot "_rehearsal"

Assert-True "wmi: the rehearsal completes and the lineage matches" (
    $wmiResult.mode -eq "rehearsal" -and $wmiResult.lineage.status -eq "matched" -and
    $wmiResult.lineage.final_process_guid -eq $FINAL_GUID)
Assert-True "wmi: the chain reports no session host, because the session host is not in it" (
    $null -eq $wmiResult.lineage.session_host_guid)
Assert-True "wmi: the intermediate is launched through WMI, once, and not by the session host" (
    ($script:FakeCalls -join ",") -eq ("open,invoke:probe,close,open,invoke:prepare,invoke:open_gate,invoke:launch_wmi," +
        "invoke:start_tool,invoke:trigger,invoke:end_run,close,open,invoke:export,fetch,invoke:cleanup,close,convert") -and
    (Get-CallCount "invoke:launch") -eq 0)
Assert-True "wmi: the step is handed the command line of the plan" (
    [string]$script:FakeArguments["launch_wmi"].command_line -ceq [string]$wmiNormalPlan.intermediate.command_line -and
    [string]$script:FakeArguments["launch_wmi"].work_dir -ceq $TEST_WORK)
Assert-True "wmi: the pre-run check is asked for the boot time of the target" (
    $script:FakeArguments["probe"].ContainsKey("read_boot_time") -and [bool]$script:FakeArguments["probe"].read_boot_time)
Assert-True "wmi: the export reaches back to the boot of the target, with the margin it always had" (
    [string]$script:FakeArguments["export"].start_utc -ceq $WMI_BOOT_UTC -and
    [int]$script:FakeArguments["export"].margin_ms -eq $EVTX_WINDOW_MARGIN_MS)

$wmiTraceDir = Join-Path $wmiEffectiveRoot ("operator_trace\" + $wmiRunId)
$wmiProvenancePath = Join-Path $wmiTraceDir "r1_wmi_collection_context.json"
Assert-True "wmi: the collection provenance is written to the operator trace" (
    (Test-Path -LiteralPath $wmiProvenancePath) -and [string]$wmiResult.collection_provenance -eq $wmiProvenancePath)
$wmiProvenance = Get-Content -LiteralPath $wmiProvenancePath -Raw -Encoding UTF8 | ConvertFrom-Json
$wmiProvenanceText = Get-Content -LiteralPath $wmiProvenancePath -Raw -Encoding UTF8

Assert-True "wmi: the raw window starts at the boot and says why" (
    $wmiProvenance.raw_window -ceq "target_boot_to_run_end" -and
    $wmiProvenance.raw_collection_start -ceq $WMI_BOOT_UTC -and
    $wmiProvenance.collection_window_extension_reason -ceq "lineage_root_created_before_run")
Assert-True "wmi: the observation starts at the start of the run, not at the start of the export" (
    $wmiProvenance.observation_start -ceq $RUN_START_UTC -and
    $wmiProvenance.observation_start -cne $wmiProvenance.raw_collection_start)
Assert-True "wmi: records are placed by EventData.UtcTime, and context only restores a lineage" (
    $wmiProvenance.time_field -ceq "EventData.UtcTime" -and
    $wmiProvenance.context_rule -ceq "EventData.UtcTime < observation_start" -and
    $wmiProvenance.context_use -ceq "lineage_restoration_only")
Assert-True "wmi: rehearsal records are still bounded by its actual end" (
    [int]$wmiProvenance.record_counts.total -eq 7 -and [int]$wmiProvenance.record_counts.context -eq 3 -and
    [int]$wmiProvenance.record_counts.observation -eq 3 -and
    [int]$wmiProvenance.record_counts.after_observation -eq 1)
Assert-True "wmi: a normal run has no evaluation window, whatever its raw window is" (
    $null -eq $wmiProvenance.evaluation_window_start -and $null -eq $wmiProvenance.evaluation_window_end -and
    [int]$wmiProvenance.evaluation_horizon_sec -eq 600 -and
    $wmiProvenanceText -match '"evaluation_window_start":\s+null')

$wmiLineage = $wmiProvenance.lineage
Assert-True "wmi: the lineage is three records linked by ProcessGuid, the root restored from context" (
    (@($wmiLineage.records | ForEach-Object { $_.role + ":" + $_.record_id + ":" + $_.zone }) -join ",") -ceq
        "final_tool:3:observation,intermediate:2:observation,root:10:context" -and
    (@($wmiLineage.linked_by) -join ",") -ceq "ProcessGuid,ParentProcessGuid")
Assert-True "wmi: the provenance names the context record and the record of the run that refers to it" (
    (@($wmiLineage.context_record_ids) -join ",") -ceq "10" -and @($wmiLineage.references_to_context).Count -eq 1 -and
    $wmiLineage.references_to_context[0].record_id -ceq "2" -and
    $wmiLineage.references_to_context[0].context_record_id -ceq "10" -and
    $wmiLineage.references_to_context[0].parent_process_guid -ceq $WMI_ROOT_GUID -and
    $wmiProvenance.evidence_link_key -ceq "RecordId")
Assert-True "wmi: a connection after the shortened rehearsal stays raw but is not observed" (
    $wmiLineage.connection.record_id -ceq "4" -and $wmiLineage.connection.zone -ceq "after_observation" -and
    $wmiLineage.connection.process_guid -ceq $FINAL_GUID)
Assert-True "wmi: record ids are written as text and lists stay lists" (
    $wmiProvenanceText -match '"record_id":\s+"10"' -and $wmiProvenanceText -match '"context_record_ids":\s+\[' -and
    $wmiProvenanceText -match '"references_to_context":\s+\[')

$readinessCopy = Join-Path $wmiTraceDir "r1_readiness_record.json"
Assert-True "wmi: the provenance carries the readiness record: out of band, ready, no probe" (
    $wmiProvenance.readiness.method -ceq "out_of_band" -and $wmiProvenance.readiness.result -ceq "ready" -and
    $wmiProvenance.readiness.active_tcp_probe_used -is [bool] -and -not $wmiProvenance.readiness.active_tcp_probe_used -and
    $wmiProvenance.readiness.checked_at -ceq "2029-12-31T23:59:20.000Z" -and
    $wmiProvenanceText -match '"active_tcp_probe_used":\s+false')
Assert-True "wmi: the readiness record is kept next to the provenance, byte for byte" (
    (Test-Path -LiteralPath $readinessCopy) -and
    (Get-FileSha256 $readinessCopy) -ceq (Get-FileSha256 $readinessPath) -and
    $wmiProvenance.readiness.record_sha256 -ceq (Get-FileSha256 $readinessPath))
$wmiTrace = Get-Content -LiteralPath (Join-Path $wmiTraceDir "r1_run_trace.json") -Raw -Encoding UTF8 | ConvertFrom-Json
Assert-True "wmi: the provenance is tied to the scenario, the manifest and the Sysmon configuration of the run" (
    $wmiProvenance.scenario_sha256 -ceq $wmiTrace.scenario_sha256 -and
    $wmiProvenance.manifest_sha256 -ceq (Get-FileSha256 (Join-Path $wmiEffectiveRoot ("raw\" + $wmiRunId + "\manifest.json"))) -and
    $wmiProvenance.sysmon_config_sha256 -ceq $TEST_CONFIG_SHA)
$wmiManifestText = Get-Content -LiteralPath (Join-Path $wmiEffectiveRoot ("raw\" + $wmiRunId + "\manifest.json")) -Raw -Encoding UTF8
Assert-True "wmi: the provenance and the readiness record are in no Manifest" (
    $wmiManifestText -notmatch 'r1_wmi_collection_context' -and $wmiManifestText -notmatch 'r1_readiness_record')
$wmiMetadataText = Get-Content -LiteralPath (Join-Path $wmiEffectiveRoot ("ground_truth\" + $wmiRunId + "\run_metadata.json")) -Raw -Encoding UTF8
Assert-True "wmi: the normal run records no reference, and the reference policy version of its scenario" (
    $wmiMetadataText -match '"reference_time":\s+null' -and $wmiMetadataText -match '"reference_action_id":\s+null' -and
    $wmiMetadataText -match '"reference_source_event_id":\s+null' -and
    $wmiMetadataText -match '"reference_policy_version":\s+"synthetic-reference-policy"')

 # --- the provenance of what the raw export holds --------------------------------

function Get-TestProvenance {
    <# The provenance and its problems for a run through WMI that left the given records. #>
    param([object[]]$Records, [string]$ReferenceTime = "", [AllowNull()]$Approval = @{ target = $TEST_TARGET; port = $TEST_PORT; protocol = "TCP" })

    $start = [datetime]::new(2030, 1, 1, 0, 0, 0, [System.DateTimeKind]::Utc)
    return (Get-R1CollectionProvenance -RunId "RUN-20300101-001" -FamilyId "wmi_management" `
        -CollectionProfile $wmiProfile -Records (ConvertTo-ParsedRecords $Records) -ComputerName $TEST_HOST `
        -RawCollectionStart $start.AddMinutes(-10) -StartTime $start -EndTime $start.AddSeconds(660) `
        -ReferenceTime $ReferenceTime -EvaluationHorizonSec 600 -FinalProcessGuid $FINAL_GUID `
        -Approval $Approval -Readiness $null)
}

$intact = Get-TestProvenance (New-TimedRunRecords -FromBoot)
Assert-True "provenance: an intact run through WMI has no problem" (@($intact.problems).Count -eq 0)

$atStart = Get-TestProvenance (New-TimedRunRecords -FromBoot -IntermediateUtcTime "2030-01-01 00:00:00.000")
Assert-True "provenance: a record at the very start of the run belongs to the run" (
    @($atStart.problems).Count -eq 0 -and $atStart.provenance.lineage.records[1].zone -ceq "observation")
$justBefore = Get-TestProvenance (New-TimedRunRecords -FromBoot -IntermediateUtcTime "2029-12-31 23:59:59.999")
Assert-True "provenance: a millisecond earlier it is context, and an intermediate older than the run fails" (
    $justBefore.provenance.lineage.records[1].zone -ceq "context" -and
    (@($justBefore.problems) -join "|") -like "*the intermediate of the lineage (RecordId 2) was created outside the observation interval*")

$justAfter = Get-TestProvenance (@(New-TimedRunRecords -FromBoot) + @(
        New-DestinationConnection 15 "2030-01-01 00:11:00.001"))
Assert-True "provenance: a record just after the run stays raw but is not observed" (
    @($justAfter.problems).Count -eq 0 -and
    [int]$justAfter.provenance.record_counts.total -eq 8 -and
    [int]$justAfter.provenance.record_counts.observation -eq 4 -and
    [int]$justAfter.provenance.record_counts.after_observation -eq 1 -and
    $justAfter.provenance.raw_collection_end -ceq "2030-01-01T00:11:00.001Z")

$unreadable = New-TimedRunRecords -FromBoot
$unreadable[2].EventData.UtcTime = "2029-12-31T23:59:55.000Z"
Assert-Throws "provenance: a record whose UtcTime cannot be read stops the run, TimeCreated or not" {
    Get-TestProvenance $unreadable
} "*carries no readable EventData.UtcTime*no other field is read in its place*"
$untimed = New-TimedRunRecords -FromBoot
$untimed[4].EventData.Remove("UtcTime")
Assert-Throws "provenance: a record without a UtcTime stops the run" {
    Get-TestProvenance $untimed
} "*carries no readable EventData.UtcTime*"

$withoutRoot = @(New-TimedRunRecords -FromBoot | Where-Object { $_.RecordId -notin @(5, 10) })
($withoutRoot | Where-Object { $_.RecordId -eq 2 }).EventData["ParentImage"] = "C:\synthetic\WmiPrvSE.exe"
$truncated = Get-TestProvenance $withoutRoot
Assert-True "provenance: without the record of the root the lineage is two records, whatever ParentImage says" (
    (@($truncated.problems) -join "|") -like "*the lineage of the final tool is 2 process-create record(s) linked by ProcessGuid, not 3*" -and
    @($truncated.provenance.lineage.records).Count -eq 2 -and @($truncated.provenance.lineage.context_record_ids).Count -eq 0)

$probed = Get-TestProvenance (@(New-TimedRunRecords -FromBoot) + @(New-DestinationConnection 12 "2029-12-31 23:59:30.000"))
Assert-True "provenance: a connection to the destination before the run fails it" (
    (@($probed.problems) -join "|") -like "*connected to the internal destination before the start of the run (RecordId 12)*")
$noConnection = Get-TestProvenance (New-TimedRunRecords -FromBoot -NoConnection)
Assert-True "provenance: a run without the connection of the scenario fails" (
    (@($noConnection.problems) -join "|") -like "*0 connection(s) of the target reach the internal destination in the run*" -and
    $null -eq $noConnection.provenance.lineage.connection)
$earlyOnly = Get-TestProvenance (@(New-TimedRunRecords -FromBoot -NoConnection) + @(New-DestinationConnection 12 "2029-12-31 23:59:30.000" $FINAL_GUID))
Assert-True "provenance: an earlier connection does not stand in for the missing one" (
    (@($earlyOnly.problems) -join "|") -like "*before the start of the run*" -and
    (@($earlyOnly.problems) -join "|") -like "*0 connection(s) of the target reach the internal destination in the run*")
$twoConnections = Get-TestProvenance (@(New-TimedRunRecords -FromBoot) + @(New-DestinationConnection 13 "2030-01-01 00:00:00.700"))
Assert-True "provenance: two connections to the destination in the run are ambiguous" (
    (@($twoConnections.problems) -join "|") -like "*2 connection(s) of the target reach the internal destination in the run*")

$duplicateRoot = @(New-TimedRunRecords -FromBoot) + @(New-TimedRecord 14 1 "2029-12-31 23:50:23.000" ([ordered]@{
    ProcessGuid = $WMI_ROOT_GUID; ProcessId = "901"; Image = "C:\synthetic\WmiPrvSE.exe" }))
Assert-True "provenance: a ProcessGuid recorded twice is reported, not chosen between" (
    (@((Get-TestProvenance $duplicateRoot).problems) -join "|") -like ("*duplicate EID 1 for ProcessGuid " + $WMI_ROOT_GUID + "*"))

 # A reference time is handed to the provenance here; how the record it comes
 # from is found is checked further down, on whole runs.
$withReference = Get-TestProvenance (New-TimedRunRecords -FromBoot -IntermediateImage "cmd.exe") -ReferenceTime "2030-01-01T00:00:00.200Z"
Assert-True "provenance: with a reference the evaluation ends at the reference plus the horizon, not at the end of the export" (
    @($withReference.problems).Count -eq 0 -and
    $withReference.provenance.evaluation_window_start -ceq "2030-01-01T00:00:00.200Z" -and
    $withReference.provenance.evaluation_window_end -ceq "2030-01-01T00:10:00.200Z" -and
    $withReference.provenance.evaluation_window_end -cne $withReference.provenance.raw_collection_end -and
    [string]$withReference.provenance.lineage.records[1].image -like "*cmd.exe")
$contextReference = Get-TestProvenance (New-TimedRunRecords -FromBoot) -ReferenceTime "2029-12-31T23:50:22.000Z"
Assert-True "provenance: a context record cannot be the reference of an evaluation" (
    (@($contextReference.problems) -join "|") -like "*a context record cannot be the reference of an evaluation*")

 # --- a declared collection on the session entry, in a collection run -----------
 # The session entry may declare its collection too. Its raw window is the run
 # window, so the only context is the margin before the start.

$declaredScenario = New-ScenarioObject
$declaredScenario | Add-Member -NotePropertyName "collection" -NotePropertyValue (
    [pscustomobject]@{ raw_window = "run_window"; readiness_method = $null })
$declaredPath = Save-Scenario $declaredScenario

Reset-Fakes
$declaredRoot = New-TempRoot
$declaredResult = Invoke-FakeCollectionRun -RunType "attack" -ScenarioPath $declaredPath -DataRoot $declaredRoot `
    -Transport (New-CollectionFakeTransport)
$declaredProvenance = Get-Content -LiteralPath $declaredResult.collection_provenance -Raw -Encoding UTF8 | ConvertFrom-Json
Assert-True "declared: a collection run of the session entry completes and writes its provenance" (
    $declaredResult.mode -eq "collection" -and $declaredResult.lineage.status -eq "matched" -and
    (Get-CallCount "invoke:launch") -eq 1 -and (Get-CallCount "invoke:launch_wmi") -eq 0)
Assert-True "declared: the run window is recorded as it always was exported, the margin before the start" (
    $declaredProvenance.raw_window -ceq "run_window" -and
    $declaredProvenance.raw_collection_start -ceq "2029-12-31T23:59:50.000Z" -and
    $null -eq $declaredProvenance.collection_window_extension_reason -and
    [string]$script:FakeArguments["export"].start_utc -ceq $RUN_START_UTC -and
    -not $script:FakeArguments["probe"].ContainsKey("read_boot_time"))
Assert-True "declared: the record of the margin is context, and the root is in the run" (
    [int]$declaredProvenance.record_counts.context -eq 1 -and [int]$declaredProvenance.record_counts.total -eq 5 -and
    [int]$declaredProvenance.record_counts.after_observation -eq 0 -and
    @($declaredProvenance.lineage.context_record_ids).Count -eq 0 -and
    $declaredProvenance.lineage.records[2].zone -ceq "observation")
Assert-True "declared: the evaluation window of the attack run is its reference plus the horizon" (
    $declaredProvenance.evaluation_window_start -ceq $declaredResult.reference.reference_time -and
    $declaredProvenance.evaluation_window_end -ceq "2030-01-01T00:10:00.000Z" -and
    $null -eq $declaredProvenance.readiness)

foreach ($case in @(
    @{ name = "a connection to the destination inside the margin"; like = "*collection provenance check failed*before the start of the run*"
       options = @{ ExtraRecords = @(New-DestinationConnection 12 "2029-12-31 23:59:58.000") } },
    @{ name = "a second connection to the destination in the run"; like = "*collection provenance check failed*2 connection(s)*"
       options = @{ ExtraRecords = @(New-DestinationConnection 13 "2030-01-01 00:00:00.700") } },
    @{ name = "telemetry without UtcTime"; like = "*carries no readable EventData.UtcTime*"
       options = @{ Records = (New-SyntheticRecords) } })) {

    Reset-Fakes $case.options
    $root = New-TempRoot
    Assert-Throws ("declared: a collection run with " + $case.name + " fails") {
        Invoke-FakeCollectionRun -ScenarioPath $declaredPath -DataRoot $root -Transport (New-CollectionFakeTransport)
    } $case.like
    Assert-True ("  ... and it leaves no execution_record, run_metadata, manifest or provenance (" + $case.name + ")") (
        (Test-SuccessArtifactsAbsent -Root $root -RunId "RUN-20300101-001") -and
        -not (Test-Path -LiteralPath (Join-Path $root "operator_trace\RUN-20300101-001\r1_wmi_collection_context.json")))
}

 # --- the session entry without a declared collection is run as before -----------

Reset-Fakes
$plainRoot = New-TempRoot
$plainResult = Invoke-FakeRun -RunType "attack" -ScenarioPath $goodScenario -DataRoot $plainRoot -Transport (New-FakeTransport)
Assert-True "plain: a run that declares no collection writes no provenance and no readiness record" (
    -not $plainResult.Contains("collection_provenance") -and
    (@(Get-ChildItem -LiteralPath (Join-Path $plainRoot "operator_trace\RUN-20300101-001") -Force |
            ForEach-Object { $_.Name } | Sort-Object) -join ",") -ceq "r1_run_trace.json,scenario.json")
Assert-True "plain: its probe is not asked for the boot time and its export starts at the start of the run" (
    (@($script:FakeArguments["probe"].Keys | Sort-Object) -join ",") -ceq "log_name,sysmon_binary,sysmon_config_path" -and
    [string]$script:FakeArguments["export"].start_utc -ceq $RUN_START_UTC)
Assert-True "plain: it is launched by the session host, with the arguments of the plan" (
    (Get-CallCount "invoke:launch") -eq 1 -and (Get-CallCount "invoke:launch_wmi") -eq 0 -and
    (@($script:FakeArguments["launch"].Keys | Sort-Object) -join ",") -ceq "arguments,channel_dir,executable,ready_file,timeout_sec,work_dir")

 # ---------------------------------------------------------------------------
 # 11. What the launch through WMI returned
 #
 # The step on the target hands back what the call returned. Whether the launch
 # action succeeded is decided by Get-R1WmiCreateResult, on the Controller.
 # ---------------------------------------------------------------------------

Write-Host "`n=== what the launch through WMI returned ===" -ForegroundColor Cyan

 # --- fixture -------------------------------------------------------------------

function New-WmiAnswer {
    <# What the launch step hands back for a call that started a process. -Set replaces values, -Remove drops keys. #>
    param([hashtable]$Set = @{}, [string[]]$Remove = @())

    $answer = @{
        utc = "2030-01-01T00:05:00.000Z"; completed_utc = "2030-01-01T00:05:01.000Z"
        return_value = [uint32]0; process_id = [uint32]4100 }
    foreach ($name in $Set.Keys) { $answer[$name] = $Set[$name] }
    foreach ($name in $Remove) { $answer.Remove($name) }
    return $answer
}

function New-ToolAnswer {
    <# What the step that starts the final tool hands back. -Set replaces values, -Remove drops keys. #>
    param([hashtable]$Set = @{}, [string[]]$Remove = @())

    $answer = @{ utc = "2030-01-01T00:05:00.000Z"; completed_utc = "2030-01-01T00:05:01.000Z"; final_pid = 4200 }
    foreach ($name in $Set.Keys) { $answer[$name] = $Set[$name] }
    foreach ($name in $Remove) { $answer.Remove($name) }
    return $answer
}

 # --- failure cases: the return value ---------------------------------------------

foreach ($case in @(
    @{ name = "a return value of 2"; set = @{ return_value = [uint32]2 } },
    @{ name = "a return value of 8"; set = @{ return_value = [uint32]8 } },
    @{ name = "a return value of 21"; set = @{ return_value = [uint32]21 } },
    @{ name = "a negative return value"; set = @{ return_value = -1 } },
    @{ name = "a return value of null"; set = @{ return_value = $null } },
    @{ name = "a return value as text"; set = @{ return_value = "0" } },
    @{ name = "a return value as a boolean"; set = @{ return_value = $false } },
    @{ name = "a return value with a fraction"; set = @{ return_value = 0.0 } })) {

    Assert-Throws ("a launch with " + $case.name + " did not succeed") {
        Get-R1WmiCreateResult -Created (New-WmiAnswer -Set $case.set)
    } "*the launch action succeeded only when it returns 0*"
}
Assert-Throws "a launch that states no return value did not succeed" {
    Get-R1WmiCreateResult -Created (New-WmiAnswer -Remove @("return_value"))
} "*the launch action succeeded only when it returns 0*"
Assert-Throws "a launch step that answered nothing did not succeed" {
    Get-R1WmiCreateResult -Created $null
} "*the launch action succeeded only when it returns 0*"

 # --- failure cases: the process id -------------------------------------------------

foreach ($case in @(
    @{ name = "a process id of null"; set = @{ process_id = $null } },
    @{ name = "a process id of 0"; set = @{ process_id = [uint32]0 } },
    @{ name = "a negative process id"; set = @{ process_id = -4100 } },
    @{ name = "a process id as text"; set = @{ process_id = "4100" } },
    @{ name = "a process id as a boolean"; set = @{ process_id = $true } },
    @{ name = "a process id with a fraction"; set = @{ process_id = 4100.5 } },
    @{ name = "a process id larger than a process id can be"; set = @{ process_id = [uint32]::MaxValue } })) {

    Assert-Throws ("a launch that returned " + $case.name + " did not succeed") {
        Get-R1WmiCreateResult -Created (New-WmiAnswer -Set $case.set)
    } "*returned no usable ProcessId*"
}
Assert-Throws "a launch that states no process id did not succeed" {
    Get-R1WmiCreateResult -Created (New-WmiAnswer -Remove @("process_id"))
} "*returned no usable ProcessId*"
Assert-Throws "the return value is judged first: a process id next to another return value changes nothing" {
    Get-R1WmiCreateResult -Created (New-WmiAnswer -Set @{ return_value = [uint32]9; process_id = [uint32]4100 })
} "*the launch action succeeded only when it returns 0*"

 # The final tool is not started by the launch: it is started by the second
 # action, and what that step returned is judged the same way.
foreach ($case in @(
    @{ name = "null"; set = @{ final_pid = $null } },
    @{ name = "0"; set = @{ final_pid = 0 } },
    @{ name = "a negative number"; set = @{ final_pid = -4200 } },
    @{ name = "text"; set = @{ final_pid = "4200" } },
    @{ name = "a boolean"; set = @{ final_pid = $true } })) {

    Assert-Throws ("a tool start whose final tool reported the process id " + $case.name + " did not succeed") {
        Get-R1ToolStartResult -Started (New-ToolAnswer -Set $case.set)
    } "*the final tool reported no usable process id*"
}
Assert-Throws "a tool start that states no process id did not succeed" {
    Get-R1ToolStartResult -Started (New-ToolAnswer -Remove @("final_pid"))
} "*the final tool reported no usable process id*"
foreach ($notUtc in @("2030-01-01T00:05:00.000", "2030-01-01T09:05:00.000+09:00", "2030-01-01 00:05:00.000", $null)) {
    Assert-Throws ("a tool start whose stamp is not UTC is refused: '" + [string]$notUtc + "'") {
        Get-R1ToolStartResult -Started (New-ToolAnswer -Set @{ utc = $notUtc })
    } "*launch utc must be ISO 8601 UTC ending in 'Z'*"
}
Assert-Throws "a final tool that was ready before it was told to start is refused" {
    Get-R1ToolStartResult -Started (New-ToolAnswer -Set @{ completed_utc = "2030-01-01T00:04:59.000Z" })
} "*a clock moved during the run*"
$toolStarted = Get-R1ToolStartResult -Started (New-ToolAnswer)
Assert-True "a tool start that reported a process id succeeded, and its time is kept as UTC" (
    $toolStarted.final_pid -eq 4200 -and $toolStarted.final_pid -is [int] -and
    $toolStarted.action_utc -ceq "2030-01-01T00:05:00.000Z" -and
    $toolStarted.action_time.Kind -eq [System.DateTimeKind]::Utc -and
    $toolStarted.completed_time.Kind -eq [System.DateTimeKind]::Utc)

 # --- failure cases: the time of the call ---------------------------------------------
 # The stamp taken right before the call has to be UTC and say so. A time
 # without the designator, with an offset or in another form is not read.

foreach ($case in @(
    @{ name = "without the UTC designator"; value = "2030-01-01T00:05:00.000" },
    @{ name = "with an offset"; value = "2030-01-01T09:05:00.000+09:00" },
    @{ name = "in the form Sysmon writes"; value = "2030-01-01 00:05:00.000" },
    @{ name = "a local time as text"; value = "01/01/2030 09:05:00" },
    @{ name = "empty"; value = "" },
    @{ name = "null"; value = $null })) {

    Assert-Throws ("a launch whose stamp is " + $case.name + " is refused") {
        Get-R1WmiCreateResult -Created (New-WmiAnswer -Set @{ utc = $case.value })
    } "*invoke utc must be ISO 8601 UTC ending in 'Z'*"
    Assert-Throws ("a launch whose end stamp is " + $case.name + " is refused") {
        Get-R1WmiCreateResult -Created (New-WmiAnswer -Set @{ completed_utc = $case.value })
    } "*invoke completed_utc must be ISO 8601 UTC ending in 'Z'*"
}
Assert-Throws "a launch that was over before its call is refused" {
    Get-R1WmiCreateResult -Created (New-WmiAnswer -Set @{ completed_utc = "2030-01-01T00:04:59.999Z" })
} "*a clock moved during the run*"

 # --- success cases ---------------------------------------------------------------------

$wmiCreated = Get-R1WmiCreateResult -Created (New-WmiAnswer)
Assert-True "a call that returned 0 and a process id succeeded" (
    $wmiCreated.return_value -eq 0 -and $wmiCreated.process_id -eq 4100 -and $wmiCreated.process_id -is [int] -and
    -not $wmiCreated.Contains("final_pid"))
Assert-True "the time of the call is kept as a UTC stamp and as a UTC time" (
    $wmiCreated.action_utc -ceq "2030-01-01T00:05:00.000Z" -and
    $wmiCreated.action_time.Kind -eq [System.DateTimeKind]::Utc -and
    $wmiCreated.action_time -eq [datetime]::new(2030, 1, 1, 0, 5, 0, [System.DateTimeKind]::Utc))
Assert-True "the end of the action is kept the same way" (
    $wmiCreated.completed_utc -ceq "2030-01-01T00:05:01.000Z" -and
    $wmiCreated.completed_time.Kind -eq [System.DateTimeKind]::Utc -and
    $wmiCreated.completed_time -gt $wmiCreated.action_time)

$wmiReadBack = Get-R1WmiCreateResult -Created ((New-WmiAnswer | ConvertTo-Json) | ConvertFrom-Json)
Assert-True "the same answer read back from JSON succeeds too" (
    $wmiReadBack.return_value -eq 0 -and $wmiReadBack.process_id -eq 4100 -and
    $wmiReadBack.action_utc -ceq $wmiCreated.action_utc)
$wmiSameInstant = Get-R1WmiCreateResult -Created (New-WmiAnswer -Set @{ completed_utc = "2030-01-01T00:05:00.000Z" })
Assert-True "an action that was over in the millisecond of its call is in order" (
    $wmiSameInstant.completed_time -eq $wmiSameInstant.action_time)

 # ---------------------------------------------------------------------------
 # 12. A run through WMI that fails
 #
 # It leaves a record of the failure in its operator trace and none of the
 # files a completed run ends with.
 # ---------------------------------------------------------------------------

Write-Host "`n=== a run through WMI that fails ===" -ForegroundColor Cyan

 # --- fixture -------------------------------------------------------------------

 # The length of a run through WMI, as its scenario states it.
$WMI_TEST_OBSERVATION_SEC = 780
$WMI_CALLS_UNTIL_LAUNCH = "open,invoke:probe,close,open,invoke:prepare,invoke:open_gate,invoke:launch_wmi,close"

function Assert-WmiFailedRun {
    <#
        Start a run through WMI that has to fail and check what it leaves: the
        error, no file of a completed run, an empty Ground Truth directory, and
        one failure record that says where and why the run stopped.

        Returns the failure record, or $null when there is none.
    #>
    param([string]$Name, [hashtable]$Options, [string]$MessageLike, [string]$Stage,
        [string]$RunType = "attack", [string]$ExpectedCalls, [switch]$Rehearsal)

    Reset-Fakes $Options
    $root = New-TempRoot
    $runId = "RUN-20300101-020"
    Assert-Throws $Name {
        Invoke-FakeCollectionRun -RunType $RunType -RunId $runId -ScenarioPath $wmiScenarioPath -DataRoot $root `
            -ReadinessRecordPath $readinessPath -Transport (New-CollectionFakeTransport) `
            -ObservationSec $WMI_TEST_OBSERVATION_SEC -Rehearsal:$Rehearsal
    } $MessageLike

    $effective = $root
    if ($Rehearsal) { $effective = Join-Path $root "_rehearsal" }
    $trace = Join-Path $effective ("operator_trace\" + $runId)
    Assert-True ($Name + " - no execution_record, run_metadata, manifest or provenance") (
        (Test-SuccessArtifactsAbsent -Root $effective -RunId $runId) -and
        -not (Test-Path -LiteralPath (Join-Path $trace "r1_wmi_collection_context.json")) -and
        @(Get-ChildItem -LiteralPath (Join-Path $effective ("ground_truth\" + $runId)) -Force).Count -eq 0 -and
        @(Get-ChildItem -LiteralPath $effective -Directory -Filter ".r1-completion-*" -Force).Count -eq 0)
    Assert-True ($Name + " - the trace holds the scenario, the trace record and the failure record only") (
        (@(Get-ChildItem -LiteralPath $trace -Force | ForEach-Object { $_.Name } | Sort-Object) -join ",") -ceq
            "r1_run_failure.json,r1_run_trace.json,scenario.json")

    $failure = $null
    $failurePath = Join-Path $trace "r1_run_failure.json"
    if (Test-Path -LiteralPath $failurePath) {
        $failure = Get-Content -LiteralPath $failurePath -Raw -Encoding UTF8 | ConvertFrom-Json
    }
    Assert-True ($Name + " - the failure record says where and why the run stopped") (
        $null -ne $failure -and $failure.run_id -ceq $runId -and $failure.run_type -ceq $RunType -and
        $failure.entry_kind -ceq "wmi_process" -and $failure.run_completed -is [bool] -and
        -not $failure.run_completed -and $failure.stage -ceq $Stage -and ([string]$failure.reason -like $MessageLike))
    Assert-True ($Name + " - the failure record states that no file of a completed run exists") (
        $null -ne $failure -and
        @($failure.completed_run_files.PSObject.Properties | Where-Object { $_.Value -isnot [bool] -or $_.Value }).Count -eq 0 -and
        @($failure.completed_run_files.PSObject.Properties).Count -eq 4)
    Assert-True ($Name + " - every opened session is closed") ((Get-CallCount "open") -eq (Get-CallCount "close"))
    if ($ExpectedCalls) {
        Assert-True ($Name + " - the run stopped where it failed") (($script:FakeCalls -join ",") -eq $ExpectedCalls)
    }
    return $failure
}

 # --- failure cases: the launch -----------------------------------------------------

$failed = Assert-WmiFailedRun "a launch that returned 8 stops the run" @{ WmiReturnValue = [uint32]8 } `
    "*the launch action succeeded only when it returns 0*" "action:invoke" -ExpectedCalls $WMI_CALLS_UNTIL_LAUNCH
Assert-True "  ... and the record keeps what the call returned" (
    $null -ne $failed -and [int]$failed.launch_returned.return_value -eq 8 -and
    [string]$failed.launch_returned.action_utc -ceq "2030-01-01T00:00:00.000Z" -and $null -eq $failed.reference)

foreach ($case in @(
    @{ name = "no process id"; options = @{ WmiProcessId = $null } },
    @{ name = "the process id 0"; options = @{ WmiProcessId = [uint32]0 } },
    @{ name = "a negative process id"; options = @{ WmiProcessId = -5 } },
    @{ name = "an answer without a process id"; options = @{ WmiOmit = @("process_id") } })) {

    Assert-WmiFailedRun ("a launch that returned " + $case.name + " stops the run") $case.options `
        "*returned no usable ProcessId*" "action:invoke" -ExpectedCalls $WMI_CALLS_UNTIL_LAUNCH | Out-Null
}

Assert-WmiFailedRun "a launch whose stamp does not say UTC stops the run" `
    @{ WmiActionUtc = "2030-01-01T00:05:00.000" } "*invoke utc must be ISO 8601 UTC ending in 'Z'*" "action:invoke" `
    -ExpectedCalls $WMI_CALLS_UNTIL_LAUNCH | Out-Null

$failed = Assert-WmiFailedRun "a launch step that fails on the target stops the run" @{ FailStep = "launch_wmi" } `
    "*synthetic failure in step launch_wmi*" "action:invoke" -ExpectedCalls $WMI_CALLS_UNTIL_LAUNCH
Assert-True "  ... and nothing is recorded as returned" ($null -ne $failed -and $null -eq $failed.launch_returned)

Assert-WmiFailedRun "the launch of a normal run is held to the same rule" @{ WmiReturnValue = [uint32]2 } `
    "*the launch action succeeded only when it returns 0*" "action:invoke" -RunType "normal" `
    -ExpectedCalls $WMI_CALLS_UNTIL_LAUNCH | Out-Null

Assert-WmiFailedRun "a rehearsal does not go on after a failed launch either" @{ WmiProcessId = [uint32]0 } `
    "*returned no usable ProcessId*" "action:invoke" -Rehearsal | Out-Null

$realCollectionProvenanceWriter = ${function:Write-R1CollectionProvenance}
try {
    function Write-R1CollectionProvenance { throw "synthetic sidecar writer failure" }
    Assert-WmiFailedRun "a sidecar writer failure publishes no partial completed run" @{} `
        "*synthetic sidecar writer failure*" "artifacts" | Out-Null
} finally {
    Set-Item -Path function:Write-R1CollectionProvenance -Value $realCollectionProvenanceWriter
}

 # ---------------------------------------------------------------------------
 # 13. The reference and the connection of a whole run through WMI
 # ---------------------------------------------------------------------------

Write-Host "`n=== the reference and the connection of a run through WMI ===" -ForegroundColor Cyan

 # --- fixture -------------------------------------------------------------------
 # In a collection run the launch is the first thing the run does, the final
 # tool is started 300 s later and connects at 480 s.

function New-WmiRunRecords {
    <# The raw export of a collection run through WMI of the attack run type. #>
    param([string]$IntermediateUtcTime = "", [switch]$NoConnection)
    return (New-TimedRunRecords -FromBoot -IntermediateImage "cmd.exe" -ToolOffsetSec 300 -ConnectOffsetSec 480 `
        -IntermediateUtcTime $IntermediateUtcTime -NoConnection:$NoConnection)
}

function New-SameProgramRecord {
    <# One more process-create record of the planned program, a child of the provider host unless -ParentGuid says otherwise. #>
    param([int]$RecordId, [string]$UtcTime, [string]$ParentGuid = $WMI_ROOT_GUID)
    return (New-TimedRecord $RecordId 1 $UtcTime ([ordered]@{
        ProcessGuid = "{00000000-0000-0000-0000-000000000a00}"; ProcessId = "5555"
        Image = "C:\synthetic\cmd.exe"; ParentProcessGuid = $ParentGuid; ParentProcessId = "900" }))
}

 # --- failure cases: the reference ----------------------------------------------------

$failed = Assert-WmiFailedRun "a run whose intermediate was recorded before the call has no created process" `
    @{ Records = (New-WmiRunRecords -IntermediateUtcTime "2029-12-31 23:59:59.900") } `
    "*created process undetermined: no EID 1 of cmd.exe whose parent is a context WmiPrvSE.exe*" "created_process"
Assert-True "  ... and the record says that no candidate was found" (
    $null -ne $failed -and $failed.reference.status -ceq "undetermined" -and
    @($failed.reference.candidate_record_ids).Count -eq 0 -and [int]$failed.launch_returned.process_id -eq 4100)

Assert-WmiFailedRun "a run whose intermediate was recorded after the window of the policy has no created process" `
    @{ Records = (New-WmiRunRecords -IntermediateUtcTime "2030-01-01 00:00:02.001") } `
    "*created process undetermined: no EID 1 of cmd.exe whose parent is a context WmiPrvSE.exe*" `
    "created_process" | Out-Null

$failed = Assert-WmiFailedRun "a run with two records of the planned program in the window has no created process" `
    @{ ExtraRecords = @((New-SameProgramRecord 20 "2030-01-01 00:00:00.500")) } `
    "*created process undetermined: 2 EID 1 records of cmd.exe whose parent is a context WmiPrvSE.exe*nothing chooses between them*" `
    "created_process"
Assert-True "  ... and the record names both candidates" (
    $null -ne $failed -and (@($failed.reference.candidate_record_ids) -join ",") -ceq "2,20")

Assert-WmiFailedRun "a run whose intermediate has no readable UtcTime has no created process" `
    @{ Records = (New-WmiRunRecords -IntermediateUtcTime "2030-01-01T00:00:00.200Z") } `
    "*created process undetermined:*has no readable EventData.UtcTime*TimeCreated is not used in its place*" `
    "created_process" | Out-Null

Assert-WmiFailedRun "a rehearsal of the attack run is not completed without its created process either" `
    @{ ExtraRecords = @((New-SameProgramRecord 20 "2030-01-01 00:00:00.500")) } `
    "*created process undetermined: 2 EID 1 records of cmd.exe*" "created_process" -Rehearsal | Out-Null
Assert-WmiFailedRun "a normal run is held to the same rule: its first action created exactly one process" `
    @{ Records = (@(New-TimedRunRecords -FromBoot -IntermediateImage "wscript.exe" -ToolOffsetSec 300 -ConnectOffsetSec 480 `
                -IntermediateUtcTime "2030-01-01 00:00:02.001")) } `
    "*created process undetermined: no EID 1 of wscript.exe whose parent is a context WmiPrvSE.exe*" `
    "created_process" -RunType "normal" | Out-Null
Assert-WmiFailedRun "a record that carries another process id than the call returned is not the created process" `
    @{ WmiProcessId = [uint32]4999 } `
    "*lineage check failed*" "lineage" | Out-Null

 # --- failure cases: the connection of the scenario --------------------------------------

foreach ($runType in @("normal", "attack")) {
    Assert-WmiFailedRun ("a " + $runType + " run whose telemetry holds no connection of the final tool fails") `
        @{ TelemetryNoConnection = $true } "*lineage check failed*no EID 3 with the final tool's ProcessGuid*" `
        "lineage" -RunType $runType | Out-Null
    Assert-WmiFailedRun ("a " + $runType + " run whose final tool could not connect fails") `
        @{ TriggerSuccess = $false } "*internal connection did not succeed*" "action:connect" -RunType $runType `
        -ExpectedCalls ("open,invoke:probe,close,open,invoke:prepare,invoke:open_gate,invoke:launch_wmi," +
            "invoke:start_tool,invoke:trigger,invoke:end_run,close") | Out-Null
}

Assert-WmiFailedRun "a trigger exception cleans up only the two confirmed Run-owned processes" `
    @{ FailStep = "trigger" } "*synthetic failure in step trigger*" "action:connect" `
    -ExpectedCalls ("open,invoke:probe,close,open,invoke:prepare,invoke:open_gate,invoke:launch_wmi," +
        "invoke:start_tool,invoke:trigger,invoke:end_run,close") | Out-Null
$failedTriggerOwned = @($script:FakeArguments["end_run"].owned)
Assert-True "  ... the provider host and every unconfirmed process are excluded from failure cleanup" (
    $failedTriggerOwned.Count -eq 2 -and
    (@($failedTriggerOwned | ForEach-Object { [int]$_.process_id }) -join ",") -ceq "4100,4200" -and
    @($failedTriggerOwned | Where-Object {
            [int]$_.process_id -eq 900 -or [string]$_.image -ieq "WmiPrvSE.exe" }).Count -eq 0)

Assert-WmiFailedRun "a connection to the destination before the run fails the run" `
    @{ ExtraRecords = @((New-DestinationConnection 12 "2029-12-31 23:59:30.000")) } `
    "*collection provenance check failed*before the start of the run*" "collection_provenance" | Out-Null
Assert-WmiFailedRun "an earlier connection does not stand in for the one the scenario makes" `
    @{ Records = (@(New-WmiRunRecords -NoConnection) + @(New-DestinationConnection 12 "2029-12-31 23:59:30.000" $FINAL_GUID)) } `
    "*collection provenance check failed*before the start of the run*0 connection(s) of the target*" `
    "collection_provenance" | Out-Null

 # --- success case: the attack run --------------------------------------------------------

Reset-Fakes
$wmiAttackRoot = New-TempRoot
$wmiAttackId = "RUN-20300101-021"
$wmiAttack = Invoke-FakeCollectionRun -RunType "attack" -RunId $wmiAttackId -ScenarioPath $wmiScenarioPath `
    -DataRoot $wmiAttackRoot -ReadinessRecordPath $readinessPath -Transport (New-CollectionFakeTransport) `
    -ObservationSec $WMI_TEST_OBSERVATION_SEC

Assert-True "attack: the collection run completes and the lineage matches" (
    $wmiAttack.mode -eq "collection" -and $wmiAttack.lineage.status -eq "matched")
Assert-True "attack: the reference is the record of the process the launch created, not of the session host" (
    $wmiAttack.reference.reference_action_id -ceq $wmiLaunchId -and
    $wmiAttack.reference.reference_source_event_id -ceq "2" -and
    $wmiAttack.reference.reference_time -ceq "2030-01-01T00:00:00.200Z")

$wmiAttackTruth = Join-Path $wmiAttackRoot ("ground_truth\" + $wmiAttackId)
$wmiAttackRows = @(Import-Csv -LiteralPath (Join-Path $wmiAttackTruth "execution_record.csv"))
$wmiLaunchRow = @($wmiAttackRows | Where-Object { $_.action_id -ceq $wmiLaunchId })
Assert-True "attack: the launch is recorded at the stamp taken right before the call, as what it is" (
    $wmiLaunchRow.Count -eq 1 -and $wmiLaunchRow[0].timestamp -ceq "2030-01-01T00:00:00.000Z" -and
    $wmiLaunchRow[0].action_type -ceq "wmi_process_create")
$wmiAttackMetadataText = Get-Content -LiteralPath (Join-Path $wmiAttackTruth "run_metadata.json") -Raw -Encoding UTF8
Assert-True "attack: run_metadata records the reference and the policy version of the scenario" (
    $wmiAttackMetadataText -match '"reference_time":\s+"2030-01-01T00:00:00.200Z"' -and
    $wmiAttackMetadataText -match ('"reference_action_id":\s+"' + $wmiLaunchId + '"') -and
    $wmiAttackMetadataText -match '"reference_source_event_id":\s+"2"' -and
    $wmiAttackMetadataText -match '"reference_policy_version":\s+"synthetic-reference-policy"')

$wmiAttackTrace = Join-Path $wmiAttackRoot ("operator_trace\" + $wmiAttackId)
Assert-True "attack: a completed run leaves no failure record" (
    (@(Get-ChildItem -LiteralPath $wmiAttackTrace -Force | ForEach-Object { $_.Name } | Sort-Object) -join ",") -ceq
        "r1_readiness_record.json,r1_run_trace.json,r1_wmi_collection_context.json,scenario.json")
$wmiAttackProvenanceText = Get-Content -LiteralPath $wmiAttack.collection_provenance -Raw -Encoding UTF8
$wmiAttackProvenance = $wmiAttackProvenanceText | ConvertFrom-Json

Assert-True "attack: the provenance states the version of its contract" (
    $wmiAttackProvenance.schema -ceq "r1-wmi-collection-context" -and
    $wmiAttackProvenance.contract_version -ceq "v0.1" -and
    $wmiAttackProvenance.context_rule_version -ceq "r1-context-rule-v0.1" -and
    $wmiAttackProvenance.run_start_inclusive -is [bool] -and $wmiAttackProvenance.run_start_inclusive -and
    $wmiAttackProvenance.time_fallback -ceq "none" -and
    $wmiAttackProvenance.selector_raw_input_scope -ceq "raw_collection_window" -and
    $wmiAttackProvenance.target_boot_utc -ceq $WMI_BOOT_UTC)
Assert-True "attack: the evaluation window starts at the reference, not at the call" (
    $wmiAttackProvenance.evaluation_window_start -ceq "2030-01-01T00:00:00.200Z" -and
    $wmiAttackProvenance.evaluation_window_end -ceq "2030-01-01T00:10:00.200Z" -and
    $wmiAttackProvenance.created_process.action_utc -ceq "2030-01-01T00:00:00.000Z")
Assert-True "attack: the provenance states the process the first action created" (
    $wmiAttackProvenance.created_process.window_start_utc -ceq "2030-01-01T00:00:00.000Z" -and
    $wmiAttackProvenance.created_process.window_end_utc -ceq "2030-01-01T00:00:02.000Z" -and
    $wmiAttackProvenance.created_process.selected_record_id -ceq "2" -and
    $wmiAttackProvenance.created_process.parent_record_id -ceq "10" -and
    $wmiAttackProvenance.created_process.expected_image -ceq "cmd.exe" -and
    [int]$wmiAttackProvenance.created_process.process_id -eq 4100 -and
    $wmiAttackProvenanceText -match '"return_value":\s+0,' -and
    $wmiAttackProvenanceText -match '"candidate_record_ids":\s+\[\s+"2"\s+\]')
Assert-True "attack: the sidecar links to the canonical artifact and restates no policy block" (
    $wmiAttackProvenance.canonical_provenance_linkage.filename -ceq "r1_collection_provenance.json" -and
    $wmiAttackProvenance.canonical_provenance_linkage.contract_version -ceq "v0.1" -and
    $wmiAttackProvenance.canonical_provenance_linkage.reference_policy_id -ceq "synthetic-reference" -and
    $wmiAttackProvenance.canonical_provenance_linkage.reference_policy_version -ceq "synthetic-reference-policy" -and
    $wmiAttackProvenance.canonical_provenance_linkage.reference_policy_config_hash -ceq ("b2" * 32) -and
    $null -eq $wmiAttackProvenance.canonical_provenance_linkage.canonical_sha256 -and
    @($wmiAttackProvenance.canonical_provenance_linkage.PSObject.Properties).Count -eq 6 -and
    $wmiAttackProvenance.scenario.scenario_id -ceq "R1" -and
    $wmiAttackProvenance.scenario.family_id -ceq "wmi_management" -and
    $wmiAttackProvenance.target_host -ceq $TEST_HOST -and
    $wmiAttackProvenanceText -notmatch '"policy_provenance"' -and
    $wmiAttackProvenanceText -notmatch '"reference_resolution"')
$runnerTextForPair = [System.IO.File]::ReadAllText((Join-Path (Split-Path -Parent $PSScriptRoot) "run-common.ps1"))
Assert-True "attack: collection writes only the sidecar and does not gate on later Role2 provenance" (
    (Split-Path -Leaf $wmiAttack.collection_provenance) -ceq "r1_wmi_collection_context.json" -and
    (Split-Path -Leaf (Split-Path -Parent $wmiAttack.collection_provenance)) -ceq $wmiAttackId -and
    (Split-Path -Leaf (Split-Path -Parent (Split-Path -Parent $wmiAttack.collection_provenance))) -ceq "operator_trace" -and
    $wmiAttackProvenance.canonical_provenance_linkage.filename -ceq "r1_collection_provenance.json" -and
    $runnerTextForPair -notmatch 'Write-R1NewFile[^;]*R1_CANONICAL_PROVENANCE_FILE' -and
    $runnerTextForPair -notmatch 'check_wmi_provenance_pair' -and
    $runnerTextForPair -match 'Write-R1NewFile -Path \$path -Bytes')
Assert-Throws "attack: the sidecar in the Run directory is not overwritten" {
    Write-R1NewFile -Path $wmiAttack.collection_provenance -Bytes ([byte[]]@(123, 125))
} "*r1_wmi_collection_context.json*"
Assert-True "attack: the sidecar was not changed by the refused overwrite" (
    [int]((Get-Item -LiteralPath $wmiAttack.collection_provenance).Length) -gt 2)
Assert-True "attack: the provenance states what was planned for each action and when the run started it" (
    (@($wmiAttackProvenance.actions | ForEach-Object { $_.action_id + "|" + $_.planned_offset_sec + "|" + $_.actual_utc }) -join ",") -ceq
        ("A01|0|2030-01-01T00:00:00.000Z,A02|300|2030-01-01T00:05:00.000Z," +
         "A03|480|2030-01-01T00:08:00.000Z,A04|720|2030-01-01T00:12:00.000Z"))
Assert-True "attack: the provenance names the context record the lineage was restored from, and why" (
    @($wmiAttackProvenance.context_events).Count -eq 1 -and
    $wmiAttackProvenance.context_events[0].record_id -ceq "10" -and
    [int]$wmiAttackProvenance.context_events[0].record_no -eq 2 -and
    $wmiAttackProvenance.context_events[0].role -ceq "root" -and
    $wmiAttackProvenance.context_events[0].reason -ceq "parent_of_a_run_process_created_before_the_run")
$wmiAttackJsonl = Join-Path $wmiAttackRoot ("raw\" + $wmiAttackId + "\telemetry\sysmon-0001.jsonl")
Assert-True "attack: the provenance names the host, the channel and the raw file its record ids belong to" (
    $wmiAttackProvenance.raw_source.host -ceq $TEST_HOST -and
    $wmiAttackProvenance.raw_source.channel -ceq "Microsoft-Windows-Sysmon/Operational" -and
    $wmiAttackProvenance.raw_source.jsonl_file -ceq "sysmon-0001.jsonl" -and
    $wmiAttackProvenance.raw_source.jsonl_sha256 -ceq (Get-FileSha256 $wmiAttackJsonl) -and
    $wmiAttackProvenance.raw_source.raw_log_id -ceq "RAW-002")
Assert-True "attack: every record of the lineage is named by its record id and its line in that file" (
    (@($wmiAttackProvenance.lineage.records | ForEach-Object { $_.record_id + "@" + $_.record_no }) -join ",") -ceq
        "3@6,2@5,10@2" -and
    ($wmiAttackProvenance.lineage.connection.record_id + "@" + $wmiAttackProvenance.lineage.connection.record_no) -ceq "4@7")

 # --- success case: the normal run ----------------------------------------------------------

Reset-Fakes
$wmiNormalRoot = New-TempRoot
$wmiNormal = Invoke-FakeCollectionRun -RunType "normal" -RunId $wmiAttackId -ScenarioPath $wmiScenarioPath `
    -DataRoot $wmiNormalRoot -ReadinessRecordPath $readinessPath -Transport (New-CollectionFakeTransport) `
    -ObservationSec $WMI_TEST_OBSERVATION_SEC
$wmiNormalProvenance = Get-Content -LiteralPath $wmiNormal.collection_provenance -Raw -Encoding UTF8 | ConvertFrom-Json
Assert-True "normal: the collection run completes with the same steps and records no reference" (
    $wmiNormal.mode -eq "collection" -and $wmiNormal.lineage.status -eq "matched" -and
    $null -eq $wmiNormal.reference.reference_time -and $null -eq $wmiNormal.reference.reference_action_id -and
    $null -eq $wmiNormal.reference.reference_source_event_id)
Assert-True "normal: its provenance states no evaluation window and links to the canonical artifact" (
    $null -eq $wmiNormalProvenance.evaluation_window_start -and
    $wmiNormalProvenance.canonical_provenance_linkage.reference_policy_version -ceq "synthetic-reference-policy" -and
    $wmiNormalProvenance.canonical_provenance_linkage.reference_policy_id -ceq "synthetic-reference")
Assert-True "normal: it states the one process its first action created, like the attack run" (
    $wmiNormalProvenance.created_process.action_id -ceq "N01" -and
    $wmiNormalProvenance.created_process.expected_image -ceq "wscript.exe" -and
    $wmiNormalProvenance.created_process.selected_record_id -ceq "2" -and
    (@($wmiNormalProvenance.created_process.candidate_record_ids) -join ",") -ceq "2")
Assert-True "normal: its launch is held to the same rule and recorded the same way" (
    @(Import-Csv -LiteralPath (Join-Path $wmiNormalRoot ("ground_truth\" + $wmiAttackId + "\execution_record.csv")) |
        Where-Object { $_.action_type -ceq "wmi_process_create" -and $_.timestamp -ceq "2030-01-01T00:00:00.000Z" }).Count -eq 1)

 # ---------------------------------------------------------------------------
 # 14. Get-R1WmiCreatedProcessEvent by itself
 #
 # The rule that finds the process the first action created: the planned
 # program, in the window of the reference policy, as a child of a context
 # provider host. Every record is synthetic.
 # ---------------------------------------------------------------------------

Write-Host "`n=== the record a call through WMI created ===" -ForegroundColor Cyan

 # --- fixture -------------------------------------------------------------------

$WMI_CALL_AT = [datetime]::new(2030, 1, 1, 0, 0, 0, [System.DateTimeKind]::Utc)

function Invoke-WmiCreated {
    <# Look for the created process among the given records: the call and the run start at 00:00:00, the window is two seconds. #>
    param([object[]]$Records, [string]$ExpectedImage = "cmd.exe", [string]$ExpectedRootImage = "WmiPrvSE.exe",
        [int]$ReturnedProcessId = 4100, [AllowEmptyString()][string]$FinalProcessGuid = $FINAL_GUID,
        [string]$ComputerName = $TEST_HOST, [int]$WindowSec = 2)

    return (Get-R1WmiCreatedProcessEvent -Records (ConvertTo-ParsedRecords $Records) -ComputerName $ComputerName `
        -ExpectedImage $ExpectedImage -ExpectedRootImage $ExpectedRootImage -RunStart $WMI_CALL_AT `
        -NotBefore $WMI_CALL_AT -NotAfter $WMI_CALL_AT.AddSeconds($WindowSec) `
        -ReturnedProcessId $ReturnedProcessId -FinalProcessGuid $FinalProcessGuid)
}

function New-WmiIntact {
    <# The records of an intact run: the intermediate is created 200 ms after the call. -Edit changes one record. #>
    param([int]$RecordId = 0, [scriptblock]$Edit, [string]$IntermediateUtcTime = "")

    $records = @(New-TimedRunRecords -FromBoot -IntermediateImage "cmd.exe" -IntermediateUtcTime $IntermediateUtcTime)
    if ($null -ne $Edit) { & $Edit ($records | Where-Object { $_.RecordId -eq $RecordId }) | Out-Null }
    return $records
}

function Assert-NoWmiCreated {
    param([string]$Name, $Found, [string]$ReasonLike)
    Assert-True ("undetermined: " + $Name) (
        $Found.status -eq "undetermined" -and ([string]$Found.reason -like $ReasonLike) -and
        $null -eq $Found.reference_time -and $null -eq $Found.reference_source_event_id)
}

$NO_CANDIDATE = "no EID 1 of cmd.exe whose parent is a context WmiPrvSE.exe*"

 # --- failure cases: the parent --------------------------------------------------------

Assert-NoWmiCreated "the record is the child of a process that has no record, whatever ParentImage says" (
    Invoke-WmiCreated (New-WmiIntact -RecordId 2 -Edit { param($r)
            $r.EventData.ParentProcessGuid = "{00000000-0000-0000-0000-000000000b00}"
            $r.EventData["ParentImage"] = "C:\synthetic\WmiPrvSE.exe" })) $NO_CANDIDATE
Assert-NoWmiCreated "the record names no parent at all" (
    Invoke-WmiCreated (New-WmiIntact -RecordId 2 -Edit { param($r) $r.EventData.Remove("ParentProcessGuid") })) $NO_CANDIDATE
Assert-NoWmiCreated "the parent of the record is another program than the planned root" (
    Invoke-WmiCreated (New-WmiIntact -RecordId 2 -Edit { param($r) $r.EventData.ParentProcessGuid = $OUTSIDE_GUID })) $NO_CANDIDATE
Assert-NoWmiCreated "the provider host was created in the run: it is not a context record" (
    Invoke-WmiCreated (New-WmiIntact -RecordId 10 -Edit { param($r) $r.EventData.UtcTime = "2030-01-01 00:00:00.000" })) $NO_CANDIDATE
Assert-NoWmiCreated "the provider host is recorded twice" (
    Invoke-WmiCreated (@(New-WmiIntact) + @(New-TimedRecord 14 1 "2029-12-31 23:50:23.000" ([ordered]@{
                ProcessGuid = $WMI_ROOT_GUID; ProcessId = "901"; Image = "C:\synthetic\WmiPrvSE.exe" })))) `
    "*of its parent has 2 process-create records*"
Assert-NoWmiCreated "a record of the provider host has no readable UtcTime" (
    Invoke-WmiCreated (New-WmiIntact -RecordId 10 -Edit { param($r) $r.EventData.UtcTime = "at boot" })) `
    "an EID 1 of WmiPrvSE.exe has no readable EventData.UtcTime*TimeCreated is not used in its place*"

 # --- failure cases: the program and the window -------------------------------------------

Assert-NoWmiCreated "the planned program is another one" (Invoke-WmiCreated (New-WmiIntact) -ExpectedImage "wscript.exe") `
    "no EID 1 of wscript.exe whose parent is a context WmiPrvSE.exe*"
Assert-NoWmiCreated "the record is of another host" (Invoke-WmiCreated (New-WmiIntact) -ComputerName "TARGET-B") `
    "no EID 1 of cmd.exe*was recorded on TARGET-B*"
Assert-NoWmiCreated "the record is a millisecond older than the call" (
    Invoke-WmiCreated (New-WmiIntact -IntermediateUtcTime "2029-12-31 23:59:59.999")) $NO_CANDIDATE
Assert-NoWmiCreated "the record is a millisecond younger than the window of the policy" (
    Invoke-WmiCreated (New-WmiIntact -IntermediateUtcTime "2030-01-01 00:00:02.001")) $NO_CANDIDATE
Assert-NoWmiCreated "the policy gives a shorter window than the record needs" (
    Invoke-WmiCreated (New-WmiIntact) -WindowSec 0) $NO_CANDIDATE
foreach ($unreadable in @("2030-01-01T00:00:00.200Z", "2030-01-01 00:00:00", "soon", "")) {
    Assert-NoWmiCreated ("the UtcTime of the record cannot be read: '" + $unreadable + "'") (
        Invoke-WmiCreated (New-WmiIntact -IntermediateUtcTime "placeholder" |
            ForEach-Object { if ($_.RecordId -eq 2) { $_.EventData.UtcTime = $unreadable }; $_ })) `
        "an EID 1 of cmd.exe has no readable EventData.UtcTime*TimeCreated is not used in its place*"
}
$twoFound = Invoke-WmiCreated (@(New-WmiIntact) + @(New-SameProgramRecord 20 "2030-01-01 00:00:00.500"))
Assert-NoWmiCreated "two records of the planned program are children of the provider host in the window" $twoFound `
    "2 EID 1 records of cmd.exe whose parent is a context WmiPrvSE.exe*nothing chooses between them*"
Assert-True "  ... and both are reported as candidates, in the order of the file" (
    (@($twoFound.candidate_record_ids) -join ",") -ceq "2,20")

 # --- failure cases: the record that was found ------------------------------------------------

Assert-NoWmiCreated "the record carries another process id than the call returned" (
    Invoke-WmiCreated (New-WmiIntact) -ReturnedProcessId 4999) `
    "*(RecordId 2) carries process id '4100', the call returned 4999"
Assert-NoWmiCreated "the record carries no process id" (
    Invoke-WmiCreated (New-WmiIntact -RecordId 2 -Edit { param($r) $r.EventData.Remove("ProcessId") })) `
    "*carries process id '', the call returned 4100"
Assert-NoWmiCreated "the record carries no ProcessGuid" (
    Invoke-WmiCreated (New-WmiIntact -RecordId 2 -Edit { param($r) $r.EventData.Remove("ProcessGuid") })) `
    "*carries no ProcessGuid*"
Assert-NoWmiCreated "the record carries no usable RecordId" (
    Invoke-WmiCreated (New-WmiIntact -RecordId 2 -Edit { param($r) $r.RecordId = "two" })) `
    "*carries no usable RecordId*"
Assert-NoWmiCreated "the final tool of the run is the child of another process" (
    Invoke-WmiCreated (New-WmiIntact -RecordId 3 -Edit { param($r) $r.EventData.ParentProcessGuid = $SESSION_GUID })) `
    "*but the parent of the final tool of this run is*"
Assert-NoWmiCreated "the lineage of the run gave no final tool" (Invoke-WmiCreated (New-WmiIntact) -FinalProcessGuid "") `
    "*the final tool of the lineage of this run was not established*"
Assert-NoWmiCreated "the final tool named for the run has no record" (
    Invoke-WmiCreated (New-WmiIntact) -FinalProcessGuid "{00000000-0000-0000-0000-000000000c00}") `
    "*the final tool of the lineage of this run was not established*"

 # --- success cases -------------------------------------------------------------------

$wmiFound = Invoke-WmiCreated (New-WmiIntact)
Assert-True "selected: the one record of the planned program, created in the window by the context provider host" (
    $wmiFound.status -eq "selected" -and $wmiFound.reference_source_event_id -ceq "2" -and
    $wmiFound.reference_source_event_id -is [string] -and $wmiFound.process_guid -ceq $INTERMEDIATE_GUID -and
    $wmiFound.reference_time -ceq "2030-01-01T00:00:00.200Z" -and $wmiFound.parent_record_id -ceq "10" -and
    (@($wmiFound.candidate_record_ids) -join ",") -ceq "2")
foreach ($edge in @("2030-01-01 00:00:00.000", "2030-01-01 00:00:02.000")) {
    Assert-True ("selected: a record at either end of the window belongs to it: " + $edge) (
        (Invoke-WmiCreated (New-WmiIntact -IntermediateUtcTime $edge)).status -eq "selected")
}
Assert-True "selected: the same program started by another parent is not a candidate" (
    (Invoke-WmiCreated (@(New-WmiIntact) + @(New-SameProgramRecord 20 "2030-01-01 00:00:00.500" $OUTSIDE_GUID))).status -eq "selected")
Assert-True "selected: the same program outside the window is not a candidate" (
    (Invoke-WmiCreated (@(New-WmiIntact) + @(New-SameProgramRecord 20 "2030-01-01 00:00:02.500"))).status -eq "selected")
Assert-True "selected: an Image is compared without regard to letter case, like the lineage" (
    (Invoke-WmiCreated (New-WmiIntact) -ExpectedImage "CMD.EXE" -ExpectedRootImage "wmiprvse.exe").status -eq "selected")
$createdText = (Get-Command Get-R1WmiCreatedProcessEvent).Definition
Assert-True "the function of the session entry is not called on this path" ($createdText -notmatch 'Get-R1ReferenceEvent\s+-')
Assert-True "neither ParentImage nor TimeCreated is read as a field of a record" (
    $createdText -notmatch '"ParentImage"|"TimeCreated"|"ParentProcessId"')
Assert-True "the process id is compared after the record was found, never to find one" (
    $createdText.IndexOf('$recordedPid -ne [string]$ReturnedProcessId') -gt $createdText.IndexOf('$chosen = $fitting[0]') -and
    [regex]::Matches($createdText, 'ReturnedProcessId').Count -eq 3)

 # ---------------------------------------------------------------------------
 # 15. Nothing connects from the target to the internal destination before the run
 #
 # Static checks of the code that runs before the first action, and of the
 # host block that establishes readiness, plus what a run hands to the target.
 # ---------------------------------------------------------------------------

Write-Host "`n=== nothing connects before the run ===" -ForegroundColor Cyan

 # --- fixture -------------------------------------------------------------------

$R1_DIR = Split-Path -Parent $PSScriptRoot
$HOST_BLOCK_PATH = Join-Path $R1_DIR "host\r1_readiness.ps1"
$hostBlockText = [System.IO.File]::ReadAllText($HOST_BLOCK_PATH)
$runnerText = [System.IO.File]::ReadAllText((Join-Path $R1_DIR "run-common.ps1"))
$taskText = [System.IO.File]::ReadAllText((Join-Path $R1_DIR "remote\r1_task.ps1"))

 # Calls that open a connection to an address.
$OPENS_CONNECTION = 'Test-NetConnection|Test-Connection|TcpClient|UdpClient|Net\.Sockets|WebRequest|RestMethod|WebClient|HttpClient|BitsTransfer'
 # Calls that reach into another machine or resolve a name.
$REACHES_OUT = 'New-PSSession|Enter-PSSession|Invoke-Command|New-CimSession|Resolve-DnsName|nslookup|\bping\b|telnet|\bcurl\b|\bftp\b'
 # Calls of the hypervisor tool that act on a VM or on its guest.
$ACTS_ON_VM = 'runProgramInGuest|runScriptInGuest|CopyFileFromHostToGuest|CopyFileFromGuestToHost|createDirectoryInGuest|killProcessInGuest|revertToSnapshot|deleteSnapshot|listProcessesInGuest'

function Test-NoMatch {
    param([string]$Text, [string]$Pattern)
    return (-not [regex]::IsMatch($Text, $Pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase))
}

 # --- the checks have teeth ---------------------------------------------------------

Assert-True "the pattern finds the one place of R1 that opens a connection: the task of the final tool" (
    -not (Test-NoMatch $taskText $OPENS_CONNECTION))
Assert-True "the pattern finds a probe when one is written" (
    -not (Test-NoMatch 'if (Test-NetConnection $target -Port $port) { "ready" }' $OPENS_CONNECTION) -and
    -not (Test-NoMatch '(New-Object System.Net.Sockets.TcpClient).Connect($target, $port)' $OPENS_CONNECTION))

 # --- failure cases a probe would cause ------------------------------------------------

Assert-Throws "a readiness method that probes from the target is not a method a scenario can state" {
    Get-R1CollectionProfile -Scenario (New-WmiScenarioObject -Change {
            param($s) $s.collection.readiness_method = "active_tcp_from_target" })
} "*collection.readiness_method must be out_of_band or null*"
Reset-Fakes
Assert-Throws "a readiness record that states a probe starts nothing" {
    Invoke-FakeCollectionRun -ScenarioPath $wmiScenarioPath -DataRoot (New-TempRoot) -Transport (New-CollectionFakeTransport) `
        -ReadinessRecordPath (Save-ReadinessRecord -Change { param($r) $r.active_tcp_probe_used = $true }) -Rehearsal
} "*must state active_tcp_probe_used as false*"
Assert-True "  ... not even the pre-run session" ($script:FakeCalls.Count -eq 0)

 # --- success cases: the code ------------------------------------------------------------

Assert-True "the runner opens no connection to an address anywhere" (Test-NoMatch $runnerText $OPENS_CONNECTION)
Assert-True "the pre-run check on the target opens no connection and reaches no other machine" (
    (Test-NoMatch $R1_REMOTE_STEPS["probe"].ToString() $OPENS_CONNECTION) -and
    (Test-NoMatch $R1_REMOTE_STEPS["probe"].ToString() $REACHES_OUT))
foreach ($stepName in @("begin", "prepare", "open_gate", "launch_wmi", "start_tool", "end_run")) {
    Assert-True ("the step '" + $stepName + "' opens no connection and reaches no other machine") (
        (Test-NoMatch $R1_REMOTE_STEPS[$stepName].ToString() $OPENS_CONNECTION) -and
        (Test-NoMatch $R1_REMOTE_STEPS[$stepName].ToString() $REACHES_OUT))
}
Assert-True "reading the readiness record opens no connection" (
    (Test-NoMatch (Get-Command Read-R1ReadinessRecord).Definition $OPENS_CONNECTION) -and
    (Test-NoMatch (Get-Command Read-R1ReadinessRecord).Definition $REACHES_OUT))
Assert-True "the host block opens no connection, reaches into no machine and acts on no VM" (
    (Test-NoMatch $hostBlockText $OPENS_CONNECTION) -and (Test-NoMatch $hostBlockText $REACHES_OUT) -and
    (Test-NoMatch $hostBlockText $ACTS_ON_VM))
Assert-True "the host block makes two calls of the hypervisor tool, and both read state" (
    $hostBlockText -match '\$R1_READINESS_VMRUN_CALLS = @\("list", "getGuestIPAddress"\)' -and
    @([regex]::Matches($hostBlockText, '& \$Vmrun @\("(\w+)"') | ForEach-Object { $_.Groups[1].Value } |
        Sort-Object -Unique | Where-Object { @("list", "getGuestIPAddress") -cnotcontains $_ }).Count -eq 0 -and
    [regex]::Matches($hostBlockText, '& \$Vmrun @\("(\w+)"').Count -eq 2)
Assert-True "the host block and the runner are ASCII, like the rest of R1" (
    (Test-NoMatch $hostBlockText '[^\x00-\x7F]') -and (Test-NoMatch $runnerText '[^\x00-\x7F]'))

 # --- success cases: what a run hands to the target ------------------------------------------

Reset-Fakes
Invoke-FakeCollectionRun -ScenarioPath $wmiScenarioPath -DataRoot (New-TempRoot) -ReadinessRecordPath $readinessPath `
    -Transport (New-CollectionFakeTransport) -Rehearsal | Out-Null
$callsOfRun = ($script:FakeCalls -join ",")
Assert-True "before the run starts the target is asked one thing: the pre-run check" (
    $callsOfRun.StartsWith("open,invoke:probe,close,open,"))
Assert-True "before the first action the run only writes its files and opens the gate of its intermediate" (
    $callsOfRun.StartsWith("open,invoke:probe,close,open,invoke:prepare,invoke:open_gate,invoke:launch_wmi,"))
Assert-True "the gate is a pipe of the target: it is opened by name, with no host and no address" (
    (@($script:FakeArguments["open_gate"].Keys) -join ",") -ceq "pipe_name" -and
    [string]$script:FakeArguments["open_gate"].pipe_name -ceq "r1_gate" -and
    $R1_REMOTE_STEPS["open_gate"].ToString() -match 'NamedPipeServerStream' -and
    $R1_REMOTE_STEPS["open_gate"].ToString() -notmatch 'NamedPipeClientStream')
Assert-True "the pre-run check is handed no address and no port" (
    (@($script:FakeArguments["probe"].Keys | Sort-Object) -join ",") -ceq "log_name,read_boot_time,sysmon_binary,sysmon_config_path" -and
    @($script:FakeArguments["probe"].Values | Where-Object { [string]$_ -like ("*" + $TEST_TARGET + "*") }).Count -eq 0)
Assert-True "the launch is handed no address and no port either" (
    @($script:FakeArguments["launch_wmi"].Values | Where-Object {
            [string]$_ -like ("*" + $TEST_TARGET + "*") -or [string]$_ -eq [string]$TEST_PORT }).Count -eq 0)
Assert-True "the destination reaches the target in the preparation, and the connection is made once, when it is triggered" (
    [string]$script:FakeArguments["prepare"].channel_config -like ("*" + $TEST_TARGET + "*") -and
    (Get-CallCount "invoke:trigger") -eq 1 -and
    $callsOfRun.IndexOf("invoke:trigger") -gt $callsOfRun.IndexOf("invoke:launch_wmi"))

 # ---------------------------------------------------------------------------
 # 16. The host block that establishes readiness out of band
 #
 # The hypervisor tool is a stand-in and every VM file, address and time is
 # synthetic. Nothing here asks a hypervisor or a VM anything.
 # ---------------------------------------------------------------------------

Write-Host "`n=== out-of-band readiness (host block) ===" -ForegroundColor Cyan

 # --- fixture -------------------------------------------------------------------

. $HOST_BLOCK_PATH

 # A minute before the start of the fake runs, which start at 2030-01-01T00:00:00Z.
$HOST_NOW = [datetime]::new(2029, 12, 31, 23, 59, 0, [System.DateTimeKind]::Utc)
$HOST_ADAPTER = "02:00:00:00:00:01"
$HOST_VMX_LINES = @('ethernet0.connectionType = "hostonly"', 'ethernet0.generatedAddress = "02:00:00:00:00:01"')
$script:VmrunCalls = New-Object System.Collections.Generic.List[string]

function New-VmxFile {
    <# A VM configuration file with the lines the check reads. #>
    param([string[]]$Lines = $HOST_VMX_LINES)
    $path = Join-Path (New-TempRoot) "synthetic.vmx"
    [System.IO.File]::WriteAllLines($path, [string[]](@('.encoding = "UTF-8"') + $Lines))
    return $path
}

function New-FakeVmrun {
    <# A stand-in for the hypervisor tool. It records the calls it gets and answers the two that read state. #>
    param([string[]]$Running = @(), [string]$GuestAddress = $TEST_TARGET, [string]$FailOn = "")

    $script:VmrunCalls = New-Object System.Collections.Generic.List[string]
    $calls = $script:VmrunCalls
    return {
        param([string[]]$CallArguments)
        $calls.Add($CallArguments[0])
        if ($CallArguments[0] -eq $FailOn) { throw ("synthetic failure of the call " + $FailOn) }
        if ($CallArguments[0] -eq "list") { return (@("Total running VMs: " + $Running.Count) + $Running) }
        if ($CallArguments[0] -eq "getGuestIPAddress") { return $GuestAddress }
        throw ("unexpected call of the hypervisor tool: " + $CallArguments[0])
    }.GetNewClosure()
}

function Invoke-HostReadiness {
    <# One readiness check of an intact destination VM, unless something is replaced. #>
    param([string[]]$VmxLines = $HOST_VMX_LINES, [switch]$NotRunning, [switch]$NoVmxFile,
        [string]$GuestAddress = $TEST_TARGET, [string]$FailOn = "", [hashtable]$With = @{})

    $vmx = New-VmxFile -Lines $VmxLines
    $running = @($vmx)
    if ($NotRunning) { $running = @() }
    if ($NoVmxFile) { Remove-Item -LiteralPath $vmx -Force }
    $arguments = @{
        Vmrun                  = (New-FakeVmrun -Running $running -GuestAddress $GuestAddress -FailOn $FailOn)
        DestinationVmx         = $vmx
        ExpectedAddress        = $TEST_TARGET
        ExpectedAdapterAddress = $HOST_ADAPTER
        ExpectedConnectionType = "hostonly"
        StartRequestedUtc      = $HOST_NOW.AddSeconds(-600)
        NowProvider            = { $HOST_NOW }
    }
    foreach ($name in $With.Keys) { $arguments[$name] = $With[$name] }
    return (Get-R1OutOfBandReadiness @arguments)
}

function Assert-NotReady {
    <# The record is not ready because of exactly the named check, and still states that nothing was probed. #>
    param([string]$Name, $Record, [string]$FailedCheck)
    $failedNames = @($Record.checks | Where-Object { -not $_.ok } | ForEach-Object { $_.name })
    Assert-True ("not ready: " + $Name) (
        $Record.result -ceq "not_ready" -and ($failedNames -join ",") -ceq $FailedCheck -and
        $Record.method -ceq "out_of_band" -and $Record.active_tcp_probe_used -is [bool] -and
        -not $Record.active_tcp_probe_used)
}

 # --- failure cases: the destination VM ------------------------------------------------

Assert-NotReady "the destination VM is not listed as running" (Invoke-HostReadiness -NotRunning) `
    "destination_vm_running,destination_guest_address"
Assert-True "  ... and the guest tools of a VM that is not running are not asked" (
    ($script:VmrunCalls -join ",") -ceq "list")
Assert-NotReady "the guest tools report another address" (Invoke-HostReadiness -GuestAddress "10.20.30.99") `
    "destination_guest_address"
Assert-NotReady "the guest tools report no address" (Invoke-HostReadiness -GuestAddress "") "destination_guest_address"
Assert-NotReady "the adapter is of another kind than stated" (
    Invoke-HostReadiness -VmxLines @('ethernet0.connectionType = "custom"', $HOST_VMX_LINES[1])) `
    "destination_adapter_kind,destination_active_adapters_isolated"
Assert-NotReady "the adapter reaches outside the lab" (
    Invoke-HostReadiness -VmxLines @('ethernet0.connectionType = "nat"', $HOST_VMX_LINES[1])) `
    "destination_adapter_kind,destination_active_adapters_isolated"
Assert-NotReady "the configuration states no adapter kind" (Invoke-HostReadiness -VmxLines @($HOST_VMX_LINES[1])) `
    "destination_adapter_kind,destination_active_adapters_isolated"
Assert-NotReady "another active adapter reaches outside the lab" (
    Invoke-HostReadiness -VmxLines @($HOST_VMX_LINES + @(
            'ethernet1.present = "TRUE"', 'ethernet1.connectionType = "bridged"'))) `
    "destination_active_adapters_isolated"
Assert-NotReady "the adapter has another address" (
    Invoke-HostReadiness -VmxLines @($HOST_VMX_LINES[0], 'ethernet0.generatedAddress = "02:00:00:00:00:02"')) `
    "destination_adapter_address"
Assert-NotReady "the configuration states no adapter address" (Invoke-HostReadiness -VmxLines @($HOST_VMX_LINES[0])) `
    "destination_adapter_address"
Assert-NotReady "the configuration file is not there" (Invoke-HostReadiness -NoVmxFile) `
    "destination_adapter_kind,destination_active_adapters_isolated,destination_adapter_address"
Assert-NotReady "the start of the VM was requested too recently" (
    Invoke-HostReadiness -With @{ StartRequestedUtc = $HOST_NOW.AddSeconds(-239) }) "destination_up_long_enough"
Assert-NotReady "the start of the VM is in the future" (
    Invoke-HostReadiness -With @{ StartRequestedUtc = $HOST_NOW.AddSeconds(30) }) "destination_up_long_enough"
Assert-NotReady "the list of running VMs cannot be read" (Invoke-HostReadiness -FailOn "list") `
    "destination_vm_running,destination_guest_address"
Assert-NotReady "the guest tools cannot be asked" (Invoke-HostReadiness -FailOn "getGuestIPAddress") `
    "destination_guest_address"

 # --- failure cases: the target VM, when it is checked too ---------------------------------

$otherVmx = New-VmxFile
Assert-NotReady "the target VM is not listed as running" (
    Invoke-HostReadiness -With @{ TargetVmx = $otherVmx; TargetStartRequestedUtc = $HOST_NOW.AddSeconds(-600) }) `
    "target_vm_running"
$targetWithBridge = New-VmxFile -Lines @($HOST_VMX_LINES + @(
        'ethernet1.present = "TRUE"', 'ethernet1.connectionType = "bridged"'))
$destinationForTargetCheck = New-VmxFile
$targetBridgeRecord = Get-R1OutOfBandReadiness `
    -Vmrun (New-FakeVmrun -Running @($destinationForTargetCheck, $targetWithBridge)) `
    -DestinationVmx $destinationForTargetCheck -ExpectedAddress $TEST_TARGET `
    -ExpectedAdapterAddress $HOST_ADAPTER -ExpectedConnectionType "hostonly" `
    -StartRequestedUtc $HOST_NOW.AddSeconds(-600) -TargetVmx $targetWithBridge `
    -TargetStartRequestedUtc $HOST_NOW.AddSeconds(-600) -NowProvider { $HOST_NOW }
Assert-NotReady "another active adapter of Target-A reaches outside the lab" $targetBridgeRecord `
    "target_active_adapters_isolated"
Assert-Throws "a target VM without the time its start was requested is refused" {
    Invoke-HostReadiness -With @{ TargetVmx = $otherVmx }
} "*TargetStartRequestedUtc is required when TargetVmx is given*"

 # --- failure cases: what the block refuses to do --------------------------------------------

foreach ($kind in @("nat", "bridged", "NAT")) {
    Assert-Throws ("an adapter of the kind '" + $kind + "' cannot be the expected one") {
        Invoke-HostReadiness -With @{ ExpectedConnectionType = $kind }
    } "*reaches outside the lab*"
}
Assert-Throws "the hypervisor tool has to exist" {
    New-R1VmrunCaller -VmrunPath (Join-Path (New-TempRoot) "absent.exe")
} "*the hypervisor command line tool was not found*"
 # The file given as the tool is never started here: every call below is refused first.
$refusingCaller = New-R1VmrunCaller -VmrunPath $HOST_BLOCK_PATH
foreach ($call in @("start", "stop", "reset", "suspend", "revertToSnapshot", "snapshot", "runProgramInGuest",
        "runScriptInGuest", "CopyFileFromHostToGuest", "List", "getguestipaddress")) {
    Assert-Throws ("the block makes no '" + $call + "' call of the hypervisor tool") {
        & $refusingCaller @($call, "synthetic.vmx")
    } ("*makes no '" + $call + "' call of the hypervisor tool*")
}
Assert-Throws "a call without a name is refused too" { & $refusingCaller @() } "*makes no*call of the hypervisor tool*"

$notReadyRecord = Invoke-HostReadiness -NotRunning
$notReadyPath = Join-Path (New-TempRoot) "readiness.json"
Write-R1ReadinessRecord -Record $notReadyRecord -Path $notReadyPath | Out-Null
Assert-Throws "a record that is not ready is written, and the runner refuses it" {
    Read-R1ReadinessRecord -Path $notReadyPath
} "*the run is not started unless it is ready*"
Assert-Throws "a readiness record is never replaced" {
    Write-R1ReadinessRecord -Record (Invoke-HostReadiness) -Path $notReadyPath
}
Assert-True "  ... and the first record is still the one in the file" (
    (Get-Content -LiteralPath $notReadyPath -Raw -Encoding UTF8) -match '"result":\s+"not_ready"')
$probed = Invoke-HostReadiness
$probed.active_tcp_probe_used = $true
Assert-Throws "a record that states a probe is not written" {
    Write-R1ReadinessRecord -Record $probed -Path (Join-Path (New-TempRoot) "readiness.json")
} "*a readiness record that states an active TCP probe is not written*"

 # --- success cases: the record ------------------------------------------------------------

$readyRecord = Invoke-HostReadiness
Assert-True "ready: every check of an intact destination VM holds" (
    $readyRecord.result -ceq "ready" -and @($readyRecord.checks | Where-Object { -not $_.ok }).Count -eq 0 -and
    (@($readyRecord.checks | ForEach-Object { $_.name }) -join ",") -ceq
        "destination_vm_running,destination_adapter_kind,destination_active_adapters_isolated,destination_adapter_address,destination_guest_address,destination_up_long_enough")
Assert-True "ready: the record states the method, the time of the check as UTC and that nothing was probed" (
    $readyRecord.method -ceq "out_of_band" -and $readyRecord.checked_at -ceq "2029-12-31T23:59:00.000Z" -and
    $readyRecord.active_tcp_probe_used -is [bool] -and -not $readyRecord.active_tcp_probe_used)
Assert-True "ready: the record says what it did not verify" (
    [string]$readyRecord.not_verified -like "*the listener of the internal destination*verified only by the connect action*")
Assert-True "ready: the hypervisor tool was asked two things, both of them read-only" (
    ($script:VmrunCalls -join ",") -ceq "list,getGuestIPAddress")
Assert-True "ready: each check names where its answer came from" (
    (@($readyRecord.checks | ForEach-Object { $_.source }) -join ",") -ceq
        "hypervisor,vm_configuration,vm_configuration,vm_configuration,hypervisor,orchestrator")

Assert-True "ready: an explicitly absent bridged adapter is not active" (
    (Invoke-HostReadiness -VmxLines @($HOST_VMX_LINES + @(
                'ethernet1.present = "FALSE"', 'ethernet1.connectionType = "bridged"'))).result -ceq "ready")

Assert-True "ready: an adapter address is compared without regard to separators and letter case" (
    (Invoke-HostReadiness -With @{ ExpectedAdapterAddress = "02-00-00-00-00-01" }).result -ceq "ready" -and
    (Invoke-HostReadiness -VmxLines @($HOST_VMX_LINES[0], 'ethernet0.address = "02:00:00:00:00:0a"') `
        -With @{ ExpectedAdapterAddress = "02:00:00:00:00:0A" }).result -ceq "ready")
Assert-True "ready: a VM that was started exactly the minimum time ago" (
    (Invoke-HostReadiness -With @{ StartRequestedUtc = $HOST_NOW.AddSeconds(-240) }).result -ceq "ready")
Assert-True "ready: another minimum is an argument of the check" (
    (Invoke-HostReadiness -With @{ StartRequestedUtc = $HOST_NOW.AddSeconds(-30); MinimumSecondsSinceStart = 30 }).result -ceq "ready")

$targetVmx = New-VmxFile
$bothVmx = New-VmxFile
$bothRecord = Get-R1OutOfBandReadiness -Vmrun (New-FakeVmrun -Running @($bothVmx, $targetVmx)) -DestinationVmx $bothVmx `
    -ExpectedAddress $TEST_TARGET -ExpectedAdapterAddress $HOST_ADAPTER -ExpectedConnectionType "hostonly" `
    -StartRequestedUtc $HOST_NOW.AddSeconds(-600) -TargetVmx $targetVmx `
    -TargetStartRequestedUtc $HOST_NOW.AddSeconds(-300) -NowProvider { $HOST_NOW }
Assert-True "ready: with the target VM checked too, it has to be running and up long enough" (
    $bothRecord.result -ceq "ready" -and @($bothRecord.checks).Count -eq 9 -and
    (@($bothRecord.checks | Select-Object -Last 3 | ForEach-Object { $_.name }) -join ",") -ceq
        "target_vm_running,target_active_adapters_isolated,target_up_long_enough" -and
    ($script:VmrunCalls -join ",") -ceq "list,getGuestIPAddress")

 # --- success cases: the stand-in tool behind the caller --------------------------------------

$standInDir = New-TempRoot
$standInTool = Join-Path $standInDir "tool.cmd"
[System.IO.File]::WriteAllText($standInTool, "@echo Total running VMs: 1`r`n@echo C:\synthetic\vm.vmx`r`n")
$standInLines = @(& (New-R1VmrunCaller -VmrunPath $standInTool) @("list"))
Assert-True "a call that reads state is passed to the tool and its lines come back" (
    $standInLines.Count -eq 2 -and [string]$standInLines[1] -ceq "C:\synthetic\vm.vmx")
$failingTool = Join-Path $standInDir "failing.cmd"
[System.IO.File]::WriteAllText($failingTool, "@exit /b 3`r`n")
Assert-Throws "a tool that ends with another exit code is not taken for an answer" {
    & (New-R1VmrunCaller -VmrunPath $failingTool) @("list")
} "*the hypervisor tool exited with code 3*"

 # --- success cases: the record reaches a run ----------------------------------------------------

$hostRecordPath = Join-Path (New-TempRoot) "readiness.json"
$hostWritten = Write-R1ReadinessRecord -Record $readyRecord -Path $hostRecordPath
Assert-True "the record is written once, without a byte order mark, and its hash is returned" (
    $hostWritten.path -ceq $hostRecordPath -and $hostWritten.sha256 -ceq (Get-FileSha256 $hostRecordPath) -and
    [System.IO.File]::ReadAllBytes($hostRecordPath)[0] -eq [byte][char]'{')
$hostRead = Read-R1ReadinessRecord -Path $hostRecordPath
Assert-True "the runner reads the record of the host block as out of band, ready and not probed" (
    $hostRead.method -ceq "out_of_band" -and $hostRead.result -ceq "ready" -and
    -not $hostRead.active_tcp_probe_used -and $hostRead.checked_at -ceq "2029-12-31T23:59:00.000Z" -and
    $hostRead.record_sha256 -ceq $hostWritten.sha256)

Reset-Fakes
$hostRunRoot = New-TempRoot
$hostRun = Invoke-FakeCollectionRun -ScenarioPath $wmiScenarioPath -DataRoot $hostRunRoot `
    -ReadinessRecordPath $hostRecordPath -Transport (New-CollectionFakeTransport) -Rehearsal
$hostRunProvenance = Get-Content -LiteralPath $hostRun.collection_provenance -Raw -Encoding UTF8 | ConvertFrom-Json
Assert-True "a run started with that record keeps it byte for byte and names it in its provenance" (
    $hostRunProvenance.readiness.record_sha256 -ceq $hostWritten.sha256 -and
    $hostRunProvenance.readiness.checked_at -ceq "2029-12-31T23:59:00.000Z" -and
    (Get-FileSha256 (Join-Path (Split-Path -Parent $hostRun.collection_provenance) "r1_readiness_record.json")) -ceq
        $hostWritten.sha256)

 # ---------------------------------------------------------------------------
 # 17. Who leaves a failure record
 # ---------------------------------------------------------------------------

Write-Host "`n=== failure records ===" -ForegroundColor Cyan

 # --- failure cases -------------------------------------------------------------------

 # The session entry with a declared collection leaves one too.
Reset-Fakes @{ ExtraRecords = @((New-DestinationConnection 12 "2029-12-31 23:59:58.000")) }
$declaredFailRoot = New-TempRoot
Assert-Throws "a failing run of the session entry with a declared collection is stopped as before" {
    Invoke-FakeCollectionRun -ScenarioPath $declaredPath -DataRoot $declaredFailRoot -Transport (New-CollectionFakeTransport)
} "*collection provenance check failed*before the start of the run*"
$declaredFailure = Join-Path $declaredFailRoot "operator_trace\RUN-20300101-001\r1_run_failure.json"
$declaredFailureRecord = $null
if (Test-Path -LiteralPath $declaredFailure) {
    $declaredFailureRecord = Get-Content -LiteralPath $declaredFailure -Raw -Encoding UTF8 | ConvertFrom-Json
}
Assert-True "  ... and it leaves a failure record that names its entry and no launch through WMI" (
    $null -ne $declaredFailureRecord -and $declaredFailureRecord.entry_kind -ceq "remoting_session" -and
    $declaredFailureRecord.stage -ceq "collection_provenance" -and $null -eq $declaredFailureRecord.launch_returned -and
    -not $declaredFailureRecord.run_completed -and
    (Test-SuccessArtifactsAbsent -Root $declaredFailRoot -RunId "RUN-20300101-001"))

 # A scenario that declares no collection block fails as it always did: no record.
Reset-Fakes @{ ConnectionGuid = $INTERMEDIATE_GUID }
$plainFailRoot = New-TempRoot
Assert-Throws "a failing run that declares no collection is stopped as before" {
    Invoke-FakeRun -ScenarioPath $goodScenario -DataRoot $plainFailRoot -Transport (New-FakeTransport)
} "*lineage check failed*"
Assert-True "  ... and it leaves no failure record: its trace holds the two files it always held" (
    (@(Get-ChildItem -LiteralPath (Join-Path $plainFailRoot "operator_trace\RUN-20300101-001") -Force |
            ForEach-Object { $_.Name } | Sort-Object) -join ",") -ceq "r1_run_trace.json,scenario.json" -and
    (Test-SuccessArtifactsAbsent -Root $plainFailRoot -RunId "RUN-20300101-001"))

 # A failed run is not replaced by a second run of the same run id.
Reset-Fakes @{ WmiReturnValue = [uint32]8 }
$onceRoot = New-TempRoot
Assert-Throws "the first run of a run id fails at its launch" {
    Invoke-FakeCollectionRun -RunType "attack" -ScenarioPath $wmiScenarioPath -DataRoot $onceRoot `
        -ReadinessRecordPath $readinessPath -Transport (New-CollectionFakeTransport) -ObservationSec $WMI_TEST_OBSERVATION_SEC
} "*the launch action succeeded only when it returns 0*"
$onceFailure = Join-Path $onceRoot "operator_trace\RUN-20300101-001\r1_run_failure.json"
$onceHash = Get-FileSha256 $onceFailure
Reset-Fakes
Assert-Throws "a second run of that run id is refused, although nothing is wrong with it" {
    Invoke-FakeCollectionRun -RunType "attack" -ScenarioPath $wmiScenarioPath -DataRoot $onceRoot `
        -ReadinessRecordPath $readinessPath -Transport (New-CollectionFakeTransport) -ObservationSec $WMI_TEST_OBSERVATION_SEC
}
Assert-True "  ... it opens no session, and the failure record and the absence of run files stay as they were" (
    $script:FakeCalls.Count -eq 0 -and (Get-FileSha256 $onceFailure) -ceq $onceHash -and
    (Test-SuccessArtifactsAbsent -Root $onceRoot -RunId "RUN-20300101-001"))

 # A failure record that cannot be written does not replace the failure it is about.
$unwritten = Write-R1RunFailure -TraceDir (Join-Path (New-TempRoot) "absent") -EffectiveRoot (New-TempRoot) `
    -RunId "RUN-20300101-001" -RunType "attack" -Mode "collection" -EntryKind "wmi_process" `
    -Stage "reference" -Reason "synthetic reason" -LaunchReturned $null -Reference $null
Assert-True "a failure record that cannot be written gives no path and raises nothing" ($null -eq $unwritten)

 # --- success cases -------------------------------------------------------------------

$writtenDir = New-TempRoot
$writtenFailure = Write-R1RunFailure -TraceDir $writtenDir -EffectiveRoot (New-TempRoot) `
    -RunId "RUN-20300101-001" -RunType "attack" -Mode "collection" -EntryKind "wmi_process" `
    -Stage "reference" -Reason "synthetic reason" `
    -LaunchReturned (New-WmiAnswer -Set @{ return_value = "not a number" }) `
    -Reference ([ordered]@{ status = "undetermined"; reason = "synthetic"; candidate_record_ids = [string[]]@("2", "20") })
$writtenText = Get-Content -LiteralPath $writtenFailure -Raw -Encoding UTF8
$writtenRecord = $writtenText | ConvertFrom-Json
Assert-True "a failure record keeps what the launch returned as it was, even when it is not a number" (
    $writtenRecord.launch_returned.return_value -ceq "not a number" -and
    [int]$writtenRecord.launch_returned.process_id -eq 4100 -and
    $writtenRecord.launch_returned.action_utc -ceq "2030-01-01T00:05:00.000Z")
Assert-True "a failure record is a draft like the provenance, says the run is not complete and lists its candidates" (
    $writtenRecord.failure_version -ceq "r1-run-failure-v0.1" -and $writtenRecord.run_completed -is [bool] -and
    $writtenRecord.record_kind -ceq "diagnostic" -and $writtenRecord.canonical_artifact -is [bool] -and
    -not $writtenRecord.canonical_artifact -and [string]$writtenRecord.note -like "*not Ground Truth*" -and
    -not $writtenRecord.run_completed -and $writtenText -match '"candidate_record_ids":\s+\[\s+"2",\s+"20"\s+\]')
Assert-Throws "a failure record is written once" {
    Write-R1NewFile -Path $writtenFailure -Bytes ([byte[]]@(1))
}

 # ---------------------------------------------------------------------------
 # 18. How long a run is, and when it has observed enough
 #
 # The plan is checked before anything starts: the observation has to reach the
 # evaluation horizon after the action the reference is taken from. The run is
 # then held to the reference_time it actually recorded.
 # ---------------------------------------------------------------------------

Write-Host "`n=== the length of a run and the evaluation horizon ===" -ForegroundColor Cyan

 # --- fixture -------------------------------------------------------------------

function New-WmiOffsetScenario {
    <# The fixture with other offsets, and with no length stated unless -ObservationSec gives one. #>
    param([int[]]$Offsets, [AllowNull()]$ObservationSec = $null)

    return (New-WmiScenarioObject -Change {
            param($s)
            foreach ($runType in @("normal", "attack")) {
                for ($index = 0; $index -lt 4; $index++) { $s.runs.$runType.actions[$index].offset_sec = $Offsets[$index] }
            }
            $s.run_length.observation_sec = $ObservationSec
        })
}

function Invoke-WmiInputs {
    param($Scenario, [int]$ObservationSec, [string]$RunType = "attack")
    return (Assert-R1RunInputs -RunType $RunType -RunId "RUN-20300101-001" -ScenarioJsonPath (Save-Scenario $Scenario) `
        -DataRoot (New-TempRoot) -WorkDir $TEST_WORK -ObservationSec $ObservationSec)
}

 # --- failure cases: the plan -----------------------------------------------------

foreach ($runType in @("normal", "attack")) {
    Assert-Throws ("a " + $runType + " run that is observed for less than the horizon after its reference action is refused") {
        Invoke-WmiInputs (New-WmiOffsetScenario -Offsets @(300, 400, 480, 720)) 899 $runType
    } "*ObservationSec 899 does not reach the evaluation horizon of 600 s after the invoke action at 300 s; it has to be 900 or more*"
}
Assert-Throws "a run that is shorter than the horizon is refused as it always was" {
    Invoke-WmiInputs (New-WmiOffsetScenario -Offsets @(0, 1, 2, 3)) 599
} "*ObservationSec 599 is shorter than the evaluation horizon of 600 s*"
Assert-Throws "a run that ends before its last action is refused as it always was" {
    Invoke-WmiInputs (New-WmiOffsetScenario -Offsets @(0, 300, 480, 720)) 700
} "*ObservationSec 700 does not cover the last action at 720 s*"
foreach ($other in @(779, 781, 960)) {
    Assert-Throws ("a run of " + $other + " s is refused when the scenario states 780") {
        Invoke-WmiInputs (New-WmiScenarioObject) $other
    } ("*ObservationSec " + $other + " is not the length this scenario states: run_length.observation_sec is 780*")
}
Assert-Throws "a length that is stated as text is refused" {
    Invoke-WmiInputs (New-WmiOffsetScenario -Offsets @(0, 300, 480, 720) -ObservationSec "780") 780
} "*run_length.observation_sec must be an integer of 1 or more or null*"
Reset-Fakes
$refusedRoot = New-TempRoot
Assert-Throws "a run of another length than its scenario states starts nothing" {
    Invoke-FakeCollectionRun -RunType "attack" -ScenarioPath $wmiScenarioPath -DataRoot $refusedRoot `
        -ReadinessRecordPath $readinessPath -Transport (New-CollectionFakeTransport) -ObservationSec 960
} "*is not the length this scenario states*"
Assert-True "  ... no session, no file" (
    $script:FakeCalls.Count -eq 0 -and @(Get-ChildItem -LiteralPath $refusedRoot -Recurse -Force).Count -eq 0)

 # --- failure case: the run itself ----------------------------------------------------
 # The plan holds: the reference action is planned at 0 s and the run is observed
 # for 600 s. Opening a session takes 5 s on this fake target, so the launch is
 # made 10 s into the run and the collection ends 0.2 s before the reference
 # plus the horizon.

$tightPath = Save-Scenario (New-WmiOffsetScenario -Offsets @(0, 1, 2, 3))
Reset-Fakes @{ OpenSeconds = 5 }
$tightRoot = New-TempRoot
Assert-Throws "an attack run whose collection ends before reference_time plus the horizon is refused" {
    Invoke-FakeCollectionRun -RunType "attack" -ScenarioPath $tightPath -DataRoot $tightRoot `
        -ReadinessRecordPath $readinessPath -Transport (New-CollectionFakeTransport) -ObservationSec 600
} "*the collection ended at 2030-01-01T00:10:10.000Z, before reference_time + 600 s (2030-01-01T00:10:10.200Z)*"
$tightFailure = Get-Content -LiteralPath (Join-Path $tightRoot "operator_trace\RUN-20300101-001\r1_run_failure.json") `
    -Raw -Encoding UTF8 | ConvertFrom-Json
Assert-True "  ... it is stopped where its reference is judged and leaves no file of a completed run" (
    $tightFailure.stage -ceq "reference" -and -not $tightFailure.run_completed -and
    (Test-SuccessArtifactsAbsent -Root $tightRoot -RunId "RUN-20300101-001"))

 # --- success cases ---------------------------------------------------------------------

$plannedInputs = Invoke-WmiInputs (New-WmiScenarioObject) 780
Assert-True "the decided run is observed for 780 s: past its last action at 720 s and past the horizon after its first" (
    $plannedInputs.last_offset -eq 720 -and $plannedInputs.evaluation_horizon_sec -eq 600 -and
    $plannedInputs.reference_step -ceq "invoke" -and
    [int]($plannedInputs.actions | Where-Object { $_.step -eq "invoke" }).offset_sec -eq 0)
Assert-True "a run whose reference action is planned later is accepted when it is observed long enough" (
    (Invoke-WmiInputs (New-WmiOffsetScenario -Offsets @(300, 400, 480, 720)) 900).reference_step -ceq "invoke")

 # The same fake target, a second longer: the collection reaches the horizon.
Reset-Fakes @{ OpenSeconds = 5 }
$reachedRoot = New-TempRoot
$reached = Invoke-FakeCollectionRun -RunType "attack" -ScenarioPath $tightPath -DataRoot $reachedRoot `
    -ReadinessRecordPath $readinessPath -Transport (New-CollectionFakeTransport) -ObservationSec 601
Assert-True "an attack run whose collection reaches reference_time plus the horizon completes" (
    $reached.mode -eq "collection" -and $reached.reference.reference_time -ceq "2030-01-01T00:00:10.200Z" -and
    (Test-Path -LiteralPath (Join-Path $reachedRoot "ground_truth\RUN-20300101-001\run_metadata.json")))
 # A normal run records no reference, so the same telemetry does not stop it.
Reset-Fakes @{ OpenSeconds = 5 }
$normalTight = Invoke-FakeCollectionRun -RunType "normal" -ScenarioPath $tightPath -DataRoot (New-TempRoot) `
    -ReadinessRecordPath $readinessPath -Transport (New-CollectionFakeTransport) -ObservationSec 600
Assert-True "a normal run has no evaluation window to reach" (
    $normalTight.mode -eq "collection" -and $null -eq $normalTight.reference.reference_time)

 # ---------------------------------------------------------------------------
 # 19. The final tool the second action started, and the connection it makes
 #
 # The process-create record of the tool is found by what the step returned.
 # What is compared with the lineage and with the connection is its ProcessGuid.
 # ---------------------------------------------------------------------------

Write-Host "`n=== the final tool of the second action and its connection ===" -ForegroundColor Cyan

 # --- fixture -------------------------------------------------------------------

$TOOL_TOLD_AT = [datetime]::new(2030, 1, 1, 0, 5, 0, [System.DateTimeKind]::Utc)
$TEST_APPROVAL = @{ target = $TEST_TARGET; port = $TEST_PORT; protocol = "TCP" }

function Invoke-ToolIdentity {
    <# Hold the given records to a tool that was told to start at 300 s and was ready a second later. #>
    param([object[]]$Records, [int]$FinalPid = 4200, [AllowEmptyString()][string]$FinalProcessGuid = $FINAL_GUID,
        [AllowNull()]$Approval = $TEST_APPROVAL)

    return (Test-R1ToolConnectionIdentity -Records (ConvertTo-ParsedRecords $Records) -ComputerName $TEST_HOST `
        -FinalPid $FinalPid -NotBefore $TOOL_TOLD_AT -NotAfter $TOOL_TOLD_AT.AddSeconds(1) `
        -FinalProcessGuid $FinalProcessGuid -Approval $Approval)
}

function New-ToolRecords {
    <# The records of an intact run, the final tool created 400 ms after it was told to start. #>
    param([string]$FinalUtcTime = "", [switch]$NoConnection, [object[]]$Extra = @())
    return (@(New-TimedRunRecords -FromBoot -IntermediateImage "cmd.exe" -ToolOffsetSec 300 -ConnectOffsetSec 480 `
            -FinalToolUtcTime $FinalUtcTime -NoConnection:$NoConnection) + @($Extra))
}

function New-ToolConnection {
    <# A connection to a destination, by the process with the given ProcessGuid. #>
    param([int]$RecordId, [string]$ProcessGuid, [string]$Port = [string]$TEST_PORT)
    return (New-TimedRecord $RecordId 3 "2030-01-01 00:08:00.700" ([ordered]@{
        ProcessGuid = $ProcessGuid; ProcessId = "4200"; Image = "C:\synthetic\powershell.exe"
        Protocol = "tcp"; DestinationIp = $TEST_TARGET; DestinationPort = $Port }))
}

function Assert-ToolMismatch {
    param([string]$Name, $Found, [string]$ReasonLike)
    Assert-True ("mismatched: " + $Name) (
        $Found.status -eq "mismatched" -and ([string]$Found.reason -like $ReasonLike) -and
        $null -eq $Found.connection_record_id)
}

 # --- failure cases: the record of the tool -----------------------------------------

Assert-ToolMismatch "the final tool already existed when it was told to start" (
    Invoke-ToolIdentity (New-ToolRecords -FinalUtcTime "2030-01-01 00:00:00.400")) `
    "0 EID 1 record(s) with the process id the final tool reported (4200)*exactly one is the tool the launch action started"
Assert-ToolMismatch "the final tool was created a millisecond before it was told to start" (
    Invoke-ToolIdentity (New-ToolRecords -FinalUtcTime "2030-01-01 00:04:59.999")) "0 EID 1 record(s)*"
Assert-ToolMismatch "the final tool was created after it had reported ready" (
    Invoke-ToolIdentity (New-ToolRecords -FinalUtcTime "2030-01-01 00:05:01.001")) "0 EID 1 record(s)*"
Assert-ToolMismatch "another process id was reported" (Invoke-ToolIdentity (New-ToolRecords) -FinalPid 4999) `
    "0 EID 1 record(s) with the process id the final tool reported (4999)*"
Assert-ToolMismatch "two records carry the reported process id in the time of the action" (
    Invoke-ToolIdentity (New-ToolRecords -Extra @((New-TimedRecord 21 1 "2030-01-01 00:05:00.800" ([ordered]@{
                    ProcessGuid = "{00000000-0000-0000-0000-000000000d00}"; ProcessId = "4200"
                    Image = "C:\synthetic\powershell.exe"; ParentProcessGuid = $OUTSIDE_GUID }))))) `
    "2 EID 1 record(s)*"
Assert-ToolMismatch "the UtcTime of the record cannot be read" (
    Invoke-ToolIdentity (New-ToolRecords -FinalUtcTime "2030-01-01T00:05:00.400Z")) `
    "*has no readable EventData.UtcTime*TimeCreated is not used in its place*"
Assert-ToolMismatch "the lineage of the run ends in another process" (
    Invoke-ToolIdentity (New-ToolRecords) -FinalProcessGuid $INTERMEDIATE_GUID) `
    ("the tool the launch action started has ProcessGuid " + $FINAL_GUID + ", the final tool of the lineage of this run is*")
Assert-ToolMismatch "the lineage of the run gave no final tool" (Invoke-ToolIdentity (New-ToolRecords) -FinalProcessGuid "") `
    "*the final tool of the lineage of this run is ''"

 # --- failure cases: the connection ----------------------------------------------------

Assert-ToolMismatch "the one connection to the destination carries another ProcessGuid" (
    Invoke-ToolIdentity (New-ToolRecords -NoConnection -Extra @((New-ToolConnection 4 $INTERMEDIATE_GUID)))) `
    ("0 of 1 connection(s) to the approved destination carry the ProcessGuid of the final tool*" + $FINAL_GUID + "*")
Assert-ToolMismatch "no connection reaches the destination" (Invoke-ToolIdentity (New-ToolRecords -NoConnection)) `
    "0 of 0 connection(s) to the approved destination carry the ProcessGuid of the final tool*"
Assert-ToolMismatch "the tool connected to another port" (
    Invoke-ToolIdentity (New-ToolRecords -NoConnection -Extra @((New-ToolConnection 4 $FINAL_GUID "9999")))) `
    "0 of 0 connection(s)*"
Assert-ToolMismatch "two connections carry the ProcessGuid of the tool" (
    Invoke-ToolIdentity (New-ToolRecords -Extra @((New-ToolConnection 22 $FINAL_GUID)))) "2 of 2 connection(s)*"

 # --- failure cases: whole runs -----------------------------------------------------------

foreach ($runType in @("normal", "attack")) {
    Assert-WmiFailedRun ("a " + $runType + " run whose final tool existed before its second action fails") `
        @{ TelemetryFinalUtcTime = "2030-01-01 00:00:00.400" } `
        "*tool identity check failed: 0 EID 1 record(s) with the process id the final tool reported*" `
        "tool_identity" -RunType $runType | Out-Null
}
Assert-WmiFailedRun "a connection that another process reported is not the one of the run" @{ StatusPid = 4100 } `
    "*the connection was reported by process id 4100, the final tool this run started is process id 4200*" `
    "action:connect" | Out-Null
Assert-WmiFailedRun "a connection that carries the ProcessGuid of the intermediate fails the run" `
    @{ Records = (New-ToolRecords -NoConnection -Extra @((New-ToolConnection 4 $INTERMEDIATE_GUID))) } `
    "*lineage check failed*no EID 3 with the final tool's ProcessGuid*" "lineage" | Out-Null
$WMI_CALLS_UNTIL_TOOL = (($WMI_CALLS_UNTIL_LAUNCH -replace ",close$", "") +
    ",invoke:start_tool,invoke:end_run,close")
Assert-WmiFailedRun "a final tool that reports no process id stops the run at its second action" `
    @{ ToolFinalPid = $null } "*the final tool reported no usable process id*" "action:launch" `
    -ExpectedCalls $WMI_CALLS_UNTIL_TOOL | Out-Null
Assert-WmiFailedRun "an intermediate that does not start the final tool stops the run at its second action" `
    @{ FailStep = "start_tool" } "*synthetic failure in step start_tool*" "action:launch" `
    -ExpectedCalls $WMI_CALLS_UNTIL_TOOL | Out-Null
Assert-WmiFailedRun "a second action whose stamp does not say UTC stops the run" `
    @{ ToolActionUtc = "2030-01-01T00:05:00.000" } "*launch utc must be ISO 8601 UTC ending in 'Z'*" `
    "action:launch" | Out-Null

 # --- success cases ------------------------------------------------------------------------

$toolFound = Invoke-ToolIdentity (New-ToolRecords)
Assert-True "matched: the record of the tool, the lineage and the connection carry one ProcessGuid" (
    $toolFound.status -eq "matched" -and $toolFound.tool_process_guid -ceq $FINAL_GUID -and
    $toolFound.tool_record_id -ceq "3" -and $toolFound.connection_record_id -ceq "4")
foreach ($edge in @("2030-01-01 00:05:00.000", "2030-01-01 00:05:01.000")) {
    Assert-True ("matched: a tool created at the edge of its action belongs to it: " + $edge) (
        (Invoke-ToolIdentity (New-ToolRecords -FinalUtcTime $edge)).status -eq "matched")
}
Assert-True "matched: a connection of another process does not change which one is the tool's" (
    (Invoke-ToolIdentity (New-ToolRecords -Extra @((New-ToolConnection 23 $INTERMEDIATE_GUID)))).connection_record_id -ceq "4")
$toolOnly = Invoke-ToolIdentity (New-ToolRecords -NoConnection) -Approval $null
Assert-True "tool_only: without a requested connection the tool is still the one the action started" (
    $toolOnly.status -eq "tool_only" -and $toolOnly.tool_process_guid -ceq $FINAL_GUID)

Reset-Fakes
$toolRunRoot = New-TempRoot
$toolRun = Invoke-FakeCollectionRun -RunType "attack" -ScenarioPath $wmiScenarioPath -DataRoot $toolRunRoot `
    -ReadinessRecordPath $readinessPath -Transport (New-CollectionFakeTransport)
Assert-True "run: the tool the second action started is the final tool of the lineage and made the connection" (
    $toolRun.tool_identity.status -eq "matched" -and
    $toolRun.tool_identity.tool_process_guid -ceq [string]$toolRun.lineage.final_process_guid -and
    $toolRun.tool_identity.tool_process_guid -ceq $FINAL_GUID -and $toolRun.tool_identity.connection_record_id -ceq "4")
$toolRows = @(Import-Csv -LiteralPath (Join-Path $toolRunRoot "ground_truth\RUN-20300101-001\execution_record.csv"))
Assert-True "run: the four actions are recorded at their times, with the types that were decided" (
    (@($toolRows | ForEach-Object { $_.action_id + "|" + $_.timestamp + "|" + $_.action_type }) -join ",") -ceq
        ("A01|2030-01-01T00:00:00.000Z|wmi_process_create,A02|2030-01-01T00:05:00.000Z|process_create," +
         "A03|2030-01-01T00:08:00.000Z|network_connection,A04|2030-01-01T00:12:00.000Z|run_end"))
Assert-True "run: the second action hands the intermediate the word of the gate and waits for the tool" (
    (@($script:FakeArguments["start_tool"].Keys | Sort-Object) -join ",") -ceq
        "channel_dir,gate_timeout_sec,gate_word,ready_file,timeout_sec" -and
    [string]$script:FakeArguments["start_tool"].gate_word -ceq "go" -and
    (@($script:FakeArguments["launch_wmi"].Keys | Sort-Object) -join ",") -ceq "command_line,work_dir")
$toolProvenance = Get-Content -LiteralPath $toolRun.collection_provenance -Raw -Encoding UTF8 | ConvertFrom-Json
Assert-True "run: in the provenance the connection carries the ProcessGuid of the final tool of the lineage" (
    $toolProvenance.lineage.connection.process_guid -ceq $toolProvenance.lineage.records[0].process_guid -and
    $toolProvenance.lineage.records[0].utc_time -ceq "2030-01-01 00:05:00.400" -and
    $toolProvenance.lineage.records[1].utc_time -ceq "2030-01-01 00:00:00.200")

 # ---------------------------------------------------------------------------
 # 20. The end of a run through WMI
 #
 # The run ends the two processes it started, by process id, and nothing else.
 # The provider host belongs to the target and is never ended.
 # ---------------------------------------------------------------------------

Write-Host "`n=== the end of a run through WMI ===" -ForegroundColor Cyan

 # --- fixture -------------------------------------------------------------------

function New-EndAnswer {
    <# What the step that ends a run hands back when it ended what the run started. -Set replaces values. #>
    param([hashtable]$Set = @{})

    $answer = @{
        utc           = "2030-01-01T00:12:00.000Z"
        completed_utc = "2030-01-01T00:12:01.000Z"
        ended         = @(
            @{ process_id = 4100; image = "cmd.exe"; outcome = "exited_by_itself" },
            @{ process_id = 4200; image = "powershell.exe"; outcome = "stopped" })
        provider_host = @{ process_id = 900; name = "WmiPrvSE.exe"; running_before = $true; running_after = $true }
    }
    foreach ($name in $Set.Keys) { $answer[$name] = $Set[$name] }
    return $answer
}

function Invoke-RunEnd {
    param($Answer)
    return (Get-R1RunEndResult -Ended $Answer -OwnedProcessIds ([int[]]@(4100, 4200)) -RootImage "WmiPrvSE.exe")
}

function Invoke-ActualEndRunStep {
    <# Invoke the actual remote step body with isolated process cmdlet stand-ins. #>
    param([object[]]$Owned, [bool]$AllowPartial)

    $step = $R1_REMOTE_STEPS["end_run"]
    return (& {
        param($Body, $Named, [bool]$Partial)

        $state = @{
            900  = [pscustomobject]@{ ProcessId = 900; Name = "WmiPrvSE.exe"; ParentProcessId = 4
                CreationDate = [datetime]::Parse("2029-12-31T23:00:00Z").ToUniversalTime() }
            4100 = [pscustomobject]@{ ProcessId = 4100; Name = "cmd.exe"; ParentProcessId = 900
                CreationDate = [datetime]::Parse("2030-01-01T00:00:00Z").ToUniversalTime() }
        }
        function Get-CimInstance {
            param([string]$ClassName, [string]$Filter)
            $id = [int]([regex]::Match($Filter, '\d+').Value)
            return $state[$id]
        }
        function Stop-Process {
            param([int]$Id, [switch]$Force)
            $state.Remove($Id)
        }
        function Start-Sleep { param([int]$Milliseconds) }

        return (& $Body @{ owned = $Named; wait_sec = 1; allow_partial = $Partial })
    } $step $Owned $AllowPartial)
}

$OWNED_ENDED = @(
    @{ process_id = 4100; image = "cmd.exe"; outcome = "exited_by_itself" },
    @{ process_id = 4200; image = "powershell.exe"; outcome = "stopped" })
$endRunText = $R1_REMOTE_STEPS["end_run"].ToString()

 # --- failure cases: what the step may not have done -----------------------------------

Assert-Throws "a step that ended the provider host is refused" {
    Invoke-RunEnd (New-EndAnswer -Set @{ ended = ($OWNED_ENDED + @(@{ process_id = 900; image = "WmiPrvSE.exe"; outcome = "stopped" })) })
} "*ended process id 900, which this run did not start: a run ends only what it started*"
Assert-Throws "a step that ended any other process is refused" {
    Invoke-RunEnd (New-EndAnswer -Set @{ ended = ($OWNED_ENDED + @(@{ process_id = 700; image = "svchost.exe"; outcome = "stopped" })) })
} "*ended process id 700, which this run did not start*"
Assert-Throws "a process of the run that turns out to be the root of the lineage is refused" {
    Invoke-RunEnd (New-EndAnswer -Set @{ ended = @(
            @{ process_id = 4100; image = "wmiprvse.exe"; outcome = "stopped" }, $OWNED_ENDED[1]) })
} "*the root of the lineage belongs to the target, not to the run*"
Assert-Throws "a provider host that was running before the step and is not after it is refused" {
    Invoke-RunEnd (New-EndAnswer -Set @{ provider_host = @{
            process_id = 900; name = "WmiPrvSE.exe"; running_before = $true; running_after = $false } })
} "*the provider host (process id 900) was running before the run ended its processes and is not running after*"
Assert-Throws "a provider host that is named as a process of the run is refused" {
    Invoke-RunEnd (New-EndAnswer -Set @{ provider_host = @{
            process_id = 4100; name = "WmiPrvSE.exe"; running_before = $true; running_after = $true } })
} "*both as the provider host and as a process of the run*"
foreach ($case in @(
    @{ name = "says nothing about the provider host"; provider = $null },
    @{ name = "states the provider host as text"; provider = @{ process_id = 900; running_before = "true"; running_after = "true" } },
    @{ name = "does not say whether the provider host is running after"; provider = @{ process_id = 900; running_before = $true } })) {

    Assert-Throws ("a step that " + $case.name + " is refused") {
        Invoke-RunEnd (New-EndAnswer -Set @{ provider_host = $case.provider })
    } "*did not state whether the provider host was running before and after it*"
}
foreach ($case in @(
    @{ name = "only one of the two processes"; ended = @($OWNED_ENDED[1]) },
    @{ name = "none of the processes"; ended = @() },
    @{ name = "one process twice"; ended = @($OWNED_ENDED[1], $OWNED_ENDED[1]) })) {

    Assert-Throws ("a step that accounts for " + $case.name + " is refused") {
        Invoke-RunEnd (New-EndAnswer -Set @{ ended = $case.ended })
    } "*the run_end step accounted for process id(s)*the run started 4100, 4200*"
}
foreach ($outcome in @("skipped", "", $null, "running")) {
    Assert-Throws ("a process left with the outcome '" + [string]$outcome + "' is refused") {
        Invoke-RunEnd (New-EndAnswer -Set @{ ended = @(
                $OWNED_ENDED[0], @{ process_id = 4200; image = "powershell.exe"; outcome = $outcome }) })
    } "*left process id 4200 with the outcome*a process of the run is ended or was already gone*"
}
Assert-Throws "a process named without a usable process id is refused" {
    Invoke-RunEnd (New-EndAnswer -Set @{ ended = @($OWNED_ENDED[0], @{ process_id = "4200"; image = "powershell.exe"; outcome = "stopped" }) })
} "*named a process without a usable process id*"
Assert-Throws "a step whose stamp does not say UTC is refused" {
    Invoke-RunEnd (New-EndAnswer -Set @{ utc = "2030-01-01T00:12:00.000" })
} "*run_end utc must be ISO 8601 UTC ending in 'Z'*"

 # --- failure cases: whole runs -------------------------------------------------------------

$WMI_CALLS_UNTIL_END = ("open,invoke:probe,close,open,invoke:prepare,invoke:open_gate,invoke:launch_wmi," +
    "invoke:start_tool,invoke:trigger,invoke:end_run,invoke:end_run,close")
Assert-WmiFailedRun "a run whose end ended the provider host too fails" `
    @{ EndRunEnded = ($OWNED_ENDED + @(@{ process_id = 900; image = "WmiPrvSE.exe"; outcome = "stopped" })) } `
    "*ended process id 900, which this run did not start*" "action:run_end" -ExpectedCalls $WMI_CALLS_UNTIL_END | Out-Null
Assert-WmiFailedRun "a run after whose end the provider host is gone fails" `
    @{ EndRunProvider = @{ process_id = 900; name = "WmiPrvSE.exe"; running_before = $true; running_after = $false } } `
    "*was running before the run ended its processes and is not running after*" "action:run_end" `
    -ExpectedCalls $WMI_CALLS_UNTIL_END | Out-Null
Assert-WmiFailedRun "a run whose end could not end its processes fails" @{ FailStep = "end_run" } `
    "*synthetic failure in step end_run*" "action:run_end" -RunType "normal" -ExpectedCalls $WMI_CALLS_UNTIL_END | Out-Null

 # --- success cases: the result -----------------------------------------------------------------

$ended = Invoke-RunEnd (New-EndAnswer)
Assert-True "a step that ended the two processes of the run and left the provider host running is accepted" (
    @($ended.ended).Count -eq 2 -and $ended.provider_host.running_before -and $ended.provider_host.running_after -and
    $ended.action_utc -ceq "2030-01-01T00:12:00.000Z" -and $ended.action_time.Kind -eq [System.DateTimeKind]::Utc)
Assert-True "a provider host that was already gone before the step is not something the run did" (
    (Invoke-RunEnd (New-EndAnswer -Set @{ provider_host = @{
                process_id = $null; name = $null; running_before = $false; running_after = $false } })).provider_host.running_after -eq $false)
Assert-True "processes that were already gone are accounted for as such" (
    @((Invoke-RunEnd (New-EndAnswer -Set @{ ended = @(
                    @{ process_id = 4100; image = "cmd.exe"; outcome = "already_exited" },
                    @{ process_id = 4200; image = "powershell.exe"; outcome = "already_exited" }) })).ended).Count -eq 2)
Assert-True "failure cleanup can invoke the actual end_run body for its one validated Run-owned process" (
    @((Invoke-ActualEndRunStep -Owned @(@{
                    process_id = 4100; image = "cmd.exe"
                    created_not_before_utc = "2030-01-01T00:00:00.000Z" }) -AllowPartial $true).ended).Count -eq 1)
Assert-Throws "the actual end_run body still refuses one process for a normal run end" {
    Invoke-ActualEndRunStep -Owned @(@{
            process_id = 4100; image = "cmd.exe"
            created_not_before_utc = "2030-01-01T00:00:00.000Z" }) -AllowPartial $false
} "*failure cleanup may name one or two, 1 were named*"

 # --- success cases: the step -------------------------------------------------------------------

Assert-True "the step ends a process in one place, by its process id" (
    [regex]::Matches($endRunText, 'Stop-Process').Count -eq 1 -and
    $endRunText.Contains('Stop-Process -Id ([int]$Item.entry.process_id) -Force'))
Assert-True "the step ends nothing by name, by parent or through another tool" (
    $endRunText -notmatch 'Stop-Process -Name|Get-Process|taskkill|wmic|\.Terminate\(|\.Kill\(|Stop-Service|Stop-Computer|Restart-|WmiPrvSE')
Assert-True "a process is shown to be the one the run started before anything is ended" (
    $endRunText.IndexOf('is not the process this run started') -gt 0 -and
    $endRunText.IndexOf('is not the process this run started') -lt $endRunText.IndexOf('Stop-Process') -and
    $endRunText.IndexOf('is the provider host; a run does not end it') -lt $endRunText.IndexOf('Stop-Process'))
Assert-True "no other step and no other part of the runner ends a process" (
    [regex]::Matches($runnerText, 'Stop-Process|taskkill|\.Kill\(').Count -eq 1)

 # --- success cases: a whole run ------------------------------------------------------------------

Reset-Fakes
$endRunRoot = New-TempRoot
$endRun = Invoke-FakeCollectionRun -RunType "attack" -ScenarioPath $wmiScenarioPath -DataRoot $endRunRoot `
    -ReadinessRecordPath $readinessPath -Transport (New-CollectionFakeTransport)
$endArguments = $script:FakeArguments["end_run"]
$endOwned = @($endArguments.owned)
Assert-True "run: the end is handed the two processes the run started, and nothing else" (
    (@($endArguments.Keys | Sort-Object) -join ",") -ceq "owned,wait_sec" -and $endOwned.Count -eq 2 -and
    [int]$endOwned[0].process_id -eq 4100 -and [string]$endOwned[0].image -ceq "cmd.exe" -and
    [int]$endOwned[1].process_id -eq 4200 -and [string]$endOwned[1].image -ceq "powershell.exe")
Assert-True "run: each of them is named with the action that started it, so another process with its id is not ended" (
    [string]$endOwned[0].created_not_before_utc -ceq "2030-01-01T00:00:00.000Z" -and
    [string]$endOwned[1].created_not_before_utc -ceq "2030-01-01T00:05:00.000Z")
Assert-True "run: the root of the lineage is not among them" (
    @($endOwned | Where-Object { [string]$_.image -eq "WmiPrvSE.exe" -or [int]$_.process_id -eq 900 }).Count -eq 0)
Assert-True "run: the provider host is still running after the run ended its processes" (
    $endRun.run_end.provider_host.running_before -and $endRun.run_end.provider_host.running_after -and
    @($endRun.run_end.ended).Count -eq 2)
Assert-True "run: the session is closed right after the end, and the run goes on to its collection" (
    ($script:FakeCalls -join ",").Contains("invoke:end_run,close,open,invoke:export,") -and
    (Get-CallCount "open") -eq (Get-CallCount "close") -and (Get-CallCount "invoke:end") -eq 0)
Assert-True "run: the end is recorded as the fourth action, 720 s into the run" (
    @(Import-Csv -LiteralPath (Join-Path $endRunRoot "ground_truth\RUN-20300101-001\execution_record.csv") |
        Where-Object { $_.action_id -ceq "A04" -and $_.action_type -ceq "run_end" -and
            $_.timestamp -ceq "2030-01-01T00:12:00.000Z" }).Count -eq 1)

 # The session entry ends as it always did: its last action closes the session.
Reset-Fakes
Invoke-FakeRun -RunType "attack" -ScenarioPath $goodScenario -DataRoot (New-TempRoot) -Transport (New-FakeTransport) | Out-Null
Assert-True "the session entry is not given an end of this kind" (
    (Get-CallCount "invoke:end") -eq 1 -and -not ($script:FakeCalls -contains "invoke:end_run") -and
    -not ($script:FakeCalls -contains "invoke:open_gate") -and -not ($script:FakeCalls -contains "invoke:start_tool"))

 # ---------------------------------------------------------------------------
 # 21. The four steps of a run through WMI, as the runner reads them
 # ---------------------------------------------------------------------------

Write-Host "`n=== the four steps of a run through WMI ===" -ForegroundColor Cyan

 # --- fixture -------------------------------------------------------------------

function Set-WmiAction {
    <# Change one value of one action of one run of the fixture. #>
    param($Scenario, [string]$OfRun, [int]$Index, [string]$Name, $Value)
    $Scenario.runs.$OfRun.actions[$Index].$Name = $Value
}

$startToolText = $R1_REMOTE_STEPS["start_tool"].ToString()
$startToolLines = @($startToolText -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" })

 # --- failure cases ---------------------------------------------------------------

foreach ($whichRun in @("normal", "attack")) {
    foreach ($case in @(
        @{ name = "records its launch as a plain process create"; index = 0; type = "process_create"; step = "invoke" },
        @{ name = "records the start of its tool as a launch through WMI"; index = 1; type = "wmi_process_create"; step = "launch" },
        @{ name = "records its connection as a process create"; index = 2; type = "process_create"; step = "connect" },
        @{ name = "records its end as a process termination"; index = 3; type = "process_terminate"; step = "run_end" },
        @{ name = "records its end as a session action"; index = 3; type = "remote_session"; step = "run_end" })) {

        Assert-Throws ("a " + $whichRun + " run through WMI that " + $case.name + " is refused") {
            Get-R1CollectionProfile -Scenario (New-WmiScenarioObject -Change {
                    param($s) Set-WmiAction $s $whichRun $case.index "action_type" $case.type })
        } ("*runs." + $whichRun + ": the " + $case.step + " action of a wmi_process scenario is recorded as*")
    }
    Assert-Throws ("a " + $whichRun + " run through WMI with a step of the session entry is refused") {
        Get-R1CollectionProfile -Scenario (New-WmiScenarioObject -Change {
                param($s) Set-WmiAction $s $whichRun 1 "step" "prepare" })
    } ("*runs." + $whichRun + " steps must be invoke, launch, connect, run_end in that order*")
    Assert-Throws ("a " + $whichRun + " run through WMI without its end is refused") {
        Get-R1CollectionProfile -Scenario (New-WmiScenarioObject -Change {
                param($s) $s.runs.$whichRun.actions = @($s.runs.$whichRun.actions | Select-Object -First 3) })
    } ("*runs." + $whichRun + " steps must be invoke, launch, connect, run_end in that order*")
}
Reset-Fakes
$fiveStepRoot = New-TempRoot
Assert-Throws "a scenario through WMI that keeps the five steps of the session entry starts nothing" {
    $fiveSteps = New-WmiScenarioObject -Change { param($s) $s.runs = (New-ScenarioObject).runs }
    Invoke-FakeCollectionRun -ScenarioPath (Save-Scenario $fiveSteps) -DataRoot $fiveStepRoot `
        -ReadinessRecordPath $readinessPath -Transport (New-CollectionFakeTransport) -Rehearsal
} "*steps must be invoke, launch, connect, run_end in that order*"
Assert-True "  ... no session, no file" (
    $script:FakeCalls.Count -eq 0 -and @(Get-ChildItem -LiteralPath $fiveStepRoot -Recurse -Force).Count -eq 0)
Assert-Throws "a scenario of the session entry that takes the four steps is refused as it always was" {
    $fourSteps = New-ScenarioObject
    $fourSteps.runs = (New-WmiScenarioObject).runs
    Invoke-FakeRun -ScenarioPath (Save-Scenario $fourSteps) -DataRoot (New-TempRoot) -Transport (New-FakeTransport) -DryRun
} "*must be the steps session_begin, prepare, launch, connect, session_end in that order*"

 # --- success cases ---------------------------------------------------------------

$fourStepProfile = Get-R1CollectionProfile -Scenario (New-WmiScenarioObject)
Assert-True "the runner reads four steps for an entry through WMI and five for the session entry" (
    (@($fourStepProfile.step_order) -join ",") -ceq "invoke,launch,connect,run_end" -and
    (@((Get-R1CollectionProfile -Scenario (New-ScenarioObject)).step_order) -join ",") -ceq
        "session_begin,prepare,launch,connect,session_end")

 # The second action: its time is taken right before the intermediate is told.
$wordAt = -1
for ($index = 0; $index -lt $startToolLines.Count; $index++) {
    if ($startToolLines[$index] -ceq '$gate.Write($word, 0, $word.Length)') { $wordAt = $index }
}
Assert-True "the time of the second action is taken as UTC on the line right before the word is written" (
    $wordAt -gt 0 -and
    $startToolLines[$wordAt - 1] -ceq '$utc = (Get-Date).ToUniversalTime().ToString($stampFormat)' -and
    $startToolText -match '\$stampFormat = "yyyy-MM-ddTHH:mm:ss\.fffZ"')
Assert-True "the second action waits for an intermediate that is at the gate, and gives up when none comes" (
    $startToolText -match 'BeginWaitForConnection' -and $startToolText -match 'AsyncWaitHandle\.WaitOne' -and
    $startToolText -match 'did not come to the gate' -and $startToolText -match '\$gate\.Dispose\(\)')
Assert-True "the second action starts nothing itself: only the intermediate starts the final tool" (
    $startToolText -notmatch 'Start-Process|Invoke-CimMethod|Win32_Process|ProcessStartInfo|cmd\.exe|powershell\.exe')
Assert-True "the runner calls WMI to create a process in one place only: the first action" (
    [regex]::Matches($runnerText, 'Invoke-CimMethod').Count -eq 1 -and
    [regex]::Matches($runnerText, '-MethodName Create').Count -eq 1 -and
    $runnerText -notmatch 'Invoke-WmiMethod|\[wmiclass\]|wmic\.exe|ManagementClass')

 # The end of the run: the condition that ties a process id to the run.
Assert-True "the end holds each process to the program and to the action that started it before it ends anything" (
    $endRunText.Contains('if ([string]$found.Name -ine [string]$entry.image -or $createdAt -lt $notBefore) {') -and
    $endRunText.Contains('if ($null -ne $provider.process_id -and [int]$item.entry.process_id -eq $provider.process_id) {') -and
    $endRunText.Contains('if ((-not $allowPartial -and $owned.Count -ne 2) -or') -and
    $endRunText.Contains('($allowPartial -and ($owned.Count -lt 1 -or $owned.Count -gt 2))) {'))

 # ---------------------------------------------------------------------------
 # 22. The registered policies a rendered scenario carries
 #
 # The runner cannot read the registries. It holds the block the renderer wrote
 # to the scenario it is in, uses the window it states and copies it into the
 # provenance; the validator resolves the names again through the loaders.
 # ---------------------------------------------------------------------------

Write-Host "`n=== the policies a rendered scenario carries ===" -ForegroundColor Cyan

 # --- fixture -------------------------------------------------------------------

function Invoke-PolicyProvenance {
    <# Read the policy provenance of the fixture after -Change edited the scenario. #>
    param([scriptblock]$Change)
    $changed = New-WmiScenarioObject -Change $Change
    return (Get-R1PolicyProvenance -Scenario $changed -CollectionProfile (Get-R1CollectionProfile -Scenario $changed))
}

 # --- failure cases -----------------------------------------------------------------

Assert-Throws "a scenario through WMI that carries no policy provenance is refused" {
    Invoke-PolicyProvenance { param($s) $s.PSObject.Properties.Remove("policy_provenance") }
} "*policy_provenance is missing from the scenario*"
foreach ($mode in @("dry run", "rehearsal", "collection")) {
    Reset-Fakes
    $withoutRoot = New-TempRoot
    $withoutPath = Save-Scenario (New-WmiScenarioObject -Change { param($s) $s.PSObject.Properties.Remove("policy_provenance") })
    Assert-Throws ("without the policy provenance a " + $mode + " starts nothing") {
        Invoke-FakeCollectionRun -RunType "attack" -ScenarioPath $withoutPath -DataRoot $withoutRoot `
            -ReadinessRecordPath $readinessPath -Transport (New-CollectionFakeTransport) `
            -DryRun:($mode -eq "dry run") -Rehearsal:($mode -eq "rehearsal")
    } "*policy_provenance is missing from the scenario*"
    Assert-True ("  ... no session, no file (" + $mode + ")") (
        $script:FakeCalls.Count -eq 0 -and @(Get-ChildItem -LiteralPath $withoutRoot -Recurse -Force).Count -eq 0)
}

foreach ($case in @(
    @{ name = "of another reference policy version"; like = "*policy_provenance.reference.version is*run_metadata.reference_policy_version is*"
       change = { param($s) $s.policy_provenance.reference.version = "another-version" } },
    @{ name = "of another reference action"; like = "*policy_provenance.reference.reference_action_id is 'A02'*"
       change = { param($s) $s.policy_provenance.reference.reference_action_id = "A02" } },
    @{ name = "of another horizon"; like = "*policy_provenance.reference.expected_evaluation_horizon_sec is '900'*"
       change = { param($s) $s.policy_provenance.reference.expected_evaluation_horizon_sec = 900 } },
    @{ name = "about another program"; like = "*reference_process_name is 'wscript.exe', the attack run is planned to start 'cmd.exe'*"
       change = { param($s) $s.policy_provenance.reference.reference_process_name = "wscript.exe" } },
    @{ name = "of another family"; like = "*policy_provenance.reference.family_id is 'remote_management'*"
       change = { param($s) $s.policy_provenance.reference.family_id = "remote_management" } },
    @{ name = "whose approved policy is of another family"; like = "*policy_provenance.approved_lineage.family_id is 'remote_management'*"
       change = { param($s) $s.policy_provenance.approved_lineage.family_id = "remote_management" } },
    @{ name = "with a window of zero seconds"; like = "*states no usable window*"
       change = { param($s) $s.policy_provenance.reference.candidate_window_sec = 0 } },
    @{ name = "with a window stated as text"; like = "*states no usable window*"
       change = { param($s) $s.policy_provenance.reference.candidate_window_sec = "2" } },
    @{ name = "with a window that starts before the call"; like = "*states no usable window*"
       change = { param($s) $s.policy_provenance.reference.candidate_start_offset_sec = -2 } },
    @{ name = "with a window that ends before it starts"; like = "*states no usable window*"
       change = { param($s) $s.policy_provenance.reference.candidate_start_offset_sec = 5 } },
    @{ name = "without a window"; like = "*policy_provenance.reference is missing: candidate_window_sec*"
       change = { param($s) $s.policy_provenance.reference.PSObject.Properties.Remove("candidate_window_sec") } },
    @{ name = "that does not require a process id"; like = "*require_process_id must be true*"
       change = { param($s) $s.policy_provenance.reference.require_process_id = $false } },
    @{ name = "whose hash is not a hash"; like = "*policy_provenance.reference.config_hash is not a SHA-256*"
       change = { param($s) $s.policy_provenance.reference.config_hash = "pending" } },
    @{ name = "whose approved hash is in upper case"; like = "*policy_provenance.approved_lineage.config_hash is not a SHA-256*"
       change = { param($s) $s.policy_provenance.approved_lineage.config_hash = ("A1" * 32) } },
    @{ name = "without the path of its configuration"; like = "*policy_provenance.reference.config_path must be a non-blank string*"
       change = { param($s) $s.policy_provenance.reference.config_path = "" } },
    @{ name = "without its approved lineage policy"; like = "*policy_provenance is missing: approved_lineage*"
       change = { param($s) $s.policy_provenance.PSObject.Properties.Remove("approved_lineage") } },
    @{ name = "with a key the block does not have"; like = "*policy_provenance.reference states unknown key*"
       change = { param($s) $s.policy_provenance.reference | Add-Member -NotePropertyName "approved" -NotePropertyValue $true } })) {

    Assert-Throws ("a policy provenance " + $case.name + " is refused") { Invoke-PolicyProvenance $case.change } $case.like
}

 # The window is the one the scenario was rendered with. With one second the
 # record written 1.5 s after the call is not the created process; with two it is.
$lateRecords = @(New-TimedRunRecords -FromBoot -IntermediateImage "cmd.exe" -ToolOffsetSec 300 -ConnectOffsetSec 480 `
    -IntermediateUtcTime "2030-01-01 00:00:01.500")
$oneSecondPath = Save-Scenario (New-WmiScenarioObject -Change { param($s) $s.policy_provenance.reference.candidate_window_sec = 1 })
Reset-Fakes @{ Records = $lateRecords }
$oneSecondRoot = New-TempRoot
Assert-Throws "with a window of one second a record written 1.5 s after the call is not the created process" {
    Invoke-FakeCollectionRun -RunType "attack" -ScenarioPath $oneSecondPath -DataRoot $oneSecondRoot `
        -ReadinessRecordPath $readinessPath -Transport (New-CollectionFakeTransport)
} "*created process undetermined: no EID 1 of cmd.exe*2030-01-01T00:00:00.000Z .. 2030-01-01T00:00:01.000Z*"
Assert-True "  ... and the run leaves no file of a completed run" (
    Test-SuccessArtifactsAbsent -Root $oneSecondRoot -RunId "RUN-20300101-001")

 # --- success cases ---------------------------------------------------------------

$carried = Invoke-PolicyProvenance $null
Assert-True "the block of the fixture is accepted as it is" (
    $carried.reference.policy_id -ceq "synthetic-reference" -and [int]$carried.reference.candidate_window_sec -eq 2 -and
    $carried.approved_lineage.policy_id -ceq "synthetic-approved-lineage")
Assert-True "a scenario of the session entry carries none and needs none" (
    $null -eq (Get-R1PolicyProvenance -Scenario (New-ScenarioObject) `
            -CollectionProfile (Get-R1CollectionProfile -Scenario (New-ScenarioObject))))

Reset-Fakes @{ Records = $lateRecords }
$twoSecondRun = Invoke-FakeCollectionRun -RunType "attack" -ScenarioPath $wmiScenarioPath -DataRoot (New-TempRoot) `
    -ReadinessRecordPath $readinessPath -Transport (New-CollectionFakeTransport)
$twoSecondProvenance = Get-Content -LiteralPath $twoSecondRun.collection_provenance -Raw -Encoding UTF8 | ConvertFrom-Json
Assert-True "with the window of two seconds the same record is the created process and the reference" (
    $twoSecondRun.reference.reference_time -ceq "2030-01-01T00:00:01.500Z" -and
    $twoSecondProvenance.created_process.window_end_utc -ceq "2030-01-01T00:00:02.000Z")
Assert-True "the sidecar links to the canonical artifact by policy identity and copies no policy block" (
    $twoSecondProvenance.canonical_provenance_linkage.reference_policy_id -ceq
        [string](New-WmiScenarioObject).policy_provenance.reference.policy_id -and
    $twoSecondProvenance.canonical_provenance_linkage.reference_policy_config_hash -ceq
        [string](New-WmiScenarioObject).policy_provenance.reference.config_hash -and
    -not (@($twoSecondProvenance.PSObject.Properties.Name) -contains "policy_provenance"))
Assert-True "the runner states no hash and no window of its own: both come from the scenario" (
    $runnerText -notmatch '[0-9a-f]{64}' -and $runnerText -notmatch 'candidate_window_sec\s*=\s*[0-9]')

Reset-Fakes
$policyDry = Invoke-FakeCollectionRun -RunType "attack" -ScenarioPath $wmiScenarioPath -DataRoot (New-TempRoot) -DryRun
Assert-True "a dry run of a scenario that carries its policies still shows its plan" (
    $policyDry.mode -eq "dry_run" -and $script:FakeCalls.Count -eq 0)

 # --- RecordId position finality: a whole run through WMI with -PositionFinality ----------------
 # The producer is a fake that answers the freeze request from the sleeper, the
 # way the real sidecar answers it between two polls. The RecordId-bounded export
 # is a fake remote step; scenarios\R1\tests\Test-R1PositionFinalityPath.ps1
 # checks the step itself.

$POSITION_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
$POSITION_IDENTITY = "d" * 64
$POSITION_CREATED = "2029-12-31T23:40:00.000Z"
# What the fake fetch writes, hashed here and not by the code under test.
$positionSha = [System.Security.Cryptography.SHA256]::Create()
$POSITION_EVTX_SHA = ([BitConverter]::ToString($positionSha.ComputeHash(
    (New-Object System.Text.UTF8Encoding($false)).GetBytes("synthetic evtx placeholder")))).Replace("-", "").ToLower()
$positionSha.Dispose()

$script:PositionControlDir = $null
$script:PositionProducerWrites = $true
$script:PositionAckHost = $TEST_HOST
$script:PositionExportSet = @{}
$script:PositionProducerFails = ""
$script:PositionFailureRequestSha = ""

function Get-PositionFileSha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLower()
}

function Write-FakeProducerBinding {
    <# What the producer writes at its start: its Run, host, partition and contract. #>
    param([string]$ControlRoot, [string]$RunId, [string]$BindingHost = $TEST_HOST,
        [string]$ContractHost = $TEST_HOST)
    $contractPath = Join-Path (Join-Path $ControlRoot "contracts") ($RunId + "-required-partitions.json")
    New-Item -ItemType Directory -Path (Split-Path $contractPath -Parent) -Force | Out-Null
    $contract = [ordered]@{ schema = "r1-required-partitions"; contract_version = "v0.1"; target_host = $ContractHost
        required_partitions = @([ordered]@{ source = "sysmon"; source_channel = $POSITION_CHANNEL }) }
    [System.IO.File]::WriteAllText($contractPath, ($contract | ConvertTo-Json -Depth 4))
    $binding = [ordered]@{
        schema = "r1-sysmon-collection-producer-binding"; contract_version = "v0.1"; run_id = $RunId; host_id = $BindingHost
        partition = [ordered]@{ run_id = $RunId; host_id = $BindingHost; source = "sysmon"; source_channel = $POSITION_CHANNEL }
        required_partition_contract = [ordered]@{
            path = $contractPath; sha256 = (Get-PositionFileSha256 $contractPath); target_host = $BindingHost }
        context_start_utc = $WMI_BOOT_UTC
    }
    $controlDir = Join-Path $ControlRoot $RunId
    New-Item -ItemType Directory -Path $controlDir -Force | Out-Null
    [System.IO.File]::WriteAllText((Join-Path $controlDir "collection-producer-binding.json"), ($binding | ConvertTo-Json -Depth 4))
    return $contractPath
}

$positionSleeper = {
    param($Seconds)
    & $script:FakeSleeper $Seconds
    $requestPath = Join-Path $script:PositionControlDir "collection-freeze-requested.json"
    $ackPath = Join-Path $script:PositionControlDir "collection-freeze-ack.json"
    if (-not $script:PositionProducerWrites -or -not (Test-Path -LiteralPath $requestPath) -or
        (Test-Path -LiteralPath $ackPath)) { return }
    $request = Get-Content -LiteralPath $requestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $now = Get-UtcStamp $script:FakeNow
    if (-not [string]::IsNullOrEmpty($script:PositionProducerFails)) {
        # The producer gave up: its failure, bound to the request bytes it read.
        $failurePath = Join-Path $script:PositionControlDir "collection-freeze-failed.json"
        if (Test-Path -LiteralPath $failurePath) { return }
        $requestSha = $script:PositionFailureRequestSha
        if ([string]::IsNullOrEmpty($requestSha)) { $requestSha = Get-PositionFileSha256 $requestPath }
        $failure = [ordered]@{
            schema = "r1-sysmon-collection-freeze-failure"; contract_version = "v0.1"
            run_id = $request.partition.run_id; host_id = $TEST_HOST; request_id = $request.request_id
            request_sha256 = $requestSha
            partition = [ordered]@{ run_id = $request.partition.run_id; host_id = $TEST_HOST; source = "sysmon"
                source_channel = $POSITION_CHANNEL }
            failed_at = $now; reason_code = $script:PositionProducerFails; snapshot_failures = @("view_mismatch")
        }
        [System.IO.File]::WriteAllText($failurePath, ($failure | ConvertTo-Json -Depth 6))
        return
    }
    $partition = [ordered]@{ run_id = $request.partition.run_id; host_id = $script:PositionAckHost
        source = "sysmon"; source_channel = $POSITION_CHANNEL }
    $generation = [ordered]@{
        schema = "r1-sysmon-channel-generation-observation"; contract_version = "v0.1"; phase = "freeze_ack"
        request_id = $request.request_id; partition = $partition
        source_lower_record_id = 1001; source_upper_record_id = 1006
        lower_anchor_raw_xml_sha256 = ("1" * 64); upper_anchor_raw_xml_sha256 = ("2" * 64)
        oldest_record_number = 900; log_creation_time_utc = $POSITION_CREATED; observed_at = $now
    }
    $ack = [ordered]@{
        schema = "r1-sysmon-collection-freeze-ack"; contract_version = "v0.1"; request_id = $request.request_id
        partition = $partition; source_lower_record_id = 1001; source_upper_record_id = 1006
        target_event_ids = @(1, 3); target_event_count = 3; target_identity_sha256 = $POSITION_IDENTITY
        covered_through_chunk_sequence = 2; allowed_lateness_ms = 2000; raw_segment_inventory_sha256 = ("b" * 64)
        acked_at = $now
    }
    [System.IO.File]::WriteAllText((Join-Path $script:PositionControlDir "collection-freeze-generation.json"),
        ($generation | ConvertTo-Json -Depth 6))
    [System.IO.File]::WriteAllText($ackPath, ($ack | ConvertTo-Json -Depth 6))
}

function New-PositionFakeTransport {
    $transport = New-CollectionFakeTransport
    $script:CollectionFakeInvoke = $transport.invoke
    $script:CollectionFakeConvert = $transport.convert
    $transport.invoke = {
        param($Session, $Step, $Arguments)
        if ($Step -ne "export_record_bounded") { return (& $script:CollectionFakeInvoke $Session $Step $Arguments) }
        $script:FakeCalls.Add("invoke:" + $Step)
        $script:FakeArguments[$Step] = $Arguments
        $answer = @{
            utc = (Get-UtcStamp $script:FakeNow); evtx_path = [string]$Arguments.export_path
            evtx_sha256 = $POSITION_EVTX_SHA; event_count = 3; identity_sha256 = $POSITION_IDENTITY
            record_keys = @("1001:1", "1002:1", "1004:3"); host_channel_bound = $true
            lower_anchor_raw_xml_sha256 = ("1" * 64); upper_anchor_raw_xml_sha256 = ("2" * 64)
            oldest_record_number = 900; log_creation_time_utc = $POSITION_CREATED
        }
        foreach ($key in $script:PositionExportSet.Keys) { $answer[$key] = $script:PositionExportSet[$key] }
        return $answer
    }
    $transport.convert = {
        param($EvtxPath, $JsonlPath)
        if ($EvtxPath -notlike "*\position-finality\*") { return (& $script:CollectionFakeConvert $EvtxPath $JsonlPath) }
        $script:FakeCalls.Add("convert:snapshot")
        $lines = @(@(@(1001, 1), @(1002, 1), @(1004, 3)) | ForEach-Object {
                ([ordered]@{ RecordId = $_[0]; EventId = $_[1]; TimeCreated = "2030-01-01T00:00:00.000Z"
                    Channel = $POSITION_CHANNEL; Computer = $TEST_HOST; Provider = "Microsoft-Windows-Sysmon"
                    EventData = @{ Image = "C:\Windows\System32\cmd.exe" } } | ConvertTo-Json -Compress) })
        [System.IO.File]::WriteAllLines($JsonlPath, [string[]]$lines, (New-Object System.Text.UTF8Encoding($false)))
        return $lines.Count
    }
    return $transport
}

function Invoke-PositionRun {
    param([string]$RunId, [string]$DataRoot, [string]$ControlRoot, [int]$TimeoutSec = 900, [switch]$NoBinding)
    $script:PositionControlDir = Join-Path $ControlRoot $RunId
    if (-not $NoBinding) { Write-FakeProducerBinding -ControlRoot $ControlRoot -RunId $RunId | Out-Null }
    return (Invoke-FakeCollectionRun -RunType "attack" -RunId $RunId -ScenarioPath $wmiScenarioPath -DataRoot $DataRoot `
        -ReadinessRecordPath $readinessPath -Transport (New-PositionFakeTransport) `
        -IncrementalStreamControlRoot $ControlRoot -PositionFinality -PositionFreezeAckTimeoutSec $TimeoutSec `
        -Sleeper $positionSleeper)
}

function Read-PositionJson {
    param([string]$ControlRoot, [string]$RunId, [string]$Name)
    return (Get-Content -LiteralPath (Join-Path (Join-Path $ControlRoot $RunId) $Name) -Raw -Encoding UTF8 | ConvertFrom-Json)
}

Reset-Fakes
$script:PositionProducerWrites = $true
$script:PositionAckHost = $TEST_HOST
$script:PositionExportSet = @{}
$positionRoot = New-TempRoot
$positionControl = New-TempRoot
$positionRunId = "RUN-20300101-031"
$positionRun = Invoke-PositionRun -RunId $positionRunId -DataRoot $positionRoot -ControlRoot $positionControl
$positionCalls = $script:FakeCalls -join ","
$positionDir = Join-Path $positionControl $positionRunId

Assert-True "position: the run completes with its lineage and a run-finalized" (
    $positionRun.mode -eq "collection" -and $positionRun.lineage.status -eq "matched" -and
    (Test-Path -LiteralPath $positionRun.position_finality.run_finalized) -and
    $positionRun.position_finality.lower_record_id -eq 1001 -and $positionRun.position_finality.upper_record_id -eq 1006)
Assert-True "position: the RecordId-bounded export follows the time-window export in the same collection session" (
    $positionCalls.Contains("open,invoke:export,fetch,invoke:export_record_bounded,fetch,invoke:cleanup,close") -and
    (Get-CallCount "invoke:export_record_bounded") -eq 1 -and $positionCalls.Contains("convert:snapshot"))
$boundedArguments = $script:FakeArguments["export_record_bounded"]
$windowArguments = $script:FakeArguments["export"]
Assert-True "position: the snapshot is exported through the acked bound and the window export is unchanged" (
    [long]$boundedArguments.lower -eq 1001 -and [long]$boundedArguments.upper -eq 1006 -and
    [string]$boundedArguments.expected_host -ceq $TEST_HOST -and
    [string]$boundedArguments.export_path -ceq ($TEST_WORK + "\r1_sysmon_record_bounded.evtx") -and
    (@($windowArguments.Keys | Sort-Object) -join ",") -ceq "event_ids,export_path,log_name,margin_ms,start_utc" -and
    @($script:FakeArguments["cleanup"].paths) -contains ($TEST_WORK + "\r1_sysmon_record_bounded.evtx"))
$positionRequest = Read-PositionJson $positionControl $positionRunId "collection-freeze-requested.json"
$positionBoundary = Read-PositionJson $positionControl $positionRunId "candidate-boundary-completed.json"
Assert-True "position: the request carries the A04 completion and the observation boundary of the run" (
    $positionRequest.candidate_boundary_at -ceq $positionBoundary.candidate_boundary_at -and
    $positionRequest.observation_boundary_at -ceq "2030-01-01T00:13:00.000Z" -and
    [string]$positionRequest.requested_at -ge [string]$positionRequest.observation_boundary_at -and
    $positionRequest.partition.host_id -ceq $TEST_HOST -and $positionRequest.partition.run_id -ceq $positionRunId)
$positionFinalized = Read-PositionJson $positionControl $positionRunId "run-finalized.json"
$positionExportGeneration = Read-PositionJson $positionControl $positionRunId "canonical-export-generation.json"
$positionAck = Read-PositionJson $positionControl $positionRunId "collection-freeze-ack.json"
$snapshotDir = Join-Path $positionDir "position-finality"
Assert-True "position: run-finalized binds the snapshot files and follows the ack and the export generation" (
    $positionFinalized.canonical_event_count -eq 3 -and $positionFinalized.canonical_identity_sha256 -ceq $POSITION_IDENTITY -and
    $positionFinalized.canonical_evtx_sha256 -ceq (Get-FileSha256 (Join-Path $snapshotDir "telemetry\sysmon-0001.evtx")) -and
    $positionFinalized.canonical_jsonl_sha256 -ceq (Get-FileSha256 (Join-Path $snapshotDir "telemetry\sysmon-0001.jsonl")) -and
    $positionFinalized.manifest_sha256 -ceq (Get-FileSha256 (Join-Path $snapshotDir "manifest.json")) -and
    [string]$positionAck.acked_at -le [string]$positionExportGeneration.observed_at -and
    [string]$positionExportGeneration.observed_at -le [string]$positionFinalized.finalized_at)
$positionAttestation = Get-Content -LiteralPath (Join-Path $snapshotDir "candidate-boundary-attestation.json") -Raw `
    -Encoding UTF8 | ConvertFrom-Json
$positionContext = Get-Content -LiteralPath (Join-Path $positionRoot ("operator_trace\" + $positionRunId +
    "\r1_wmi_collection_context.json")) -Raw -Encoding UTF8 | ConvertFrom-Json
$contextGuid = @{}
foreach ($record in @($positionContext.lineage.records)) { $contextGuid[[string]$record.role] = [string]$record.process_guid }
Assert-True "position: the A04 run_end result is attested with the lineage of the run and the request boundary" (
    $positionAttestation.action_id -ceq "A04" -and $positionAttestation.step -ceq "run_end" -and
    $positionAttestation.completed_at -ceq $positionRequest.candidate_boundary_at -and
    $positionAttestation.no_actions_after_boundary -eq $true -and
    (@($positionAttestation.owned_processes | ForEach-Object { $_.role + "=" + $_.terminal_state }) -join ",") -ceq
        "intermediate=stopped,final_tool=stopped" -and
    $positionAttestation.owned_processes[0].process_guid -ceq $contextGuid["intermediate"] -and
    $positionAttestation.owned_processes[1].process_guid -ceq $contextGuid["final_tool"] -and
    $positionAttestation.owned_processes[0].image -ceq "cmd.exe" -and
    $positionAttestation.owned_processes[1].image -ceq "powershell.exe" -and
    (@($positionAttestation.PSObject.Properties.Name) -join ",") -ceq
        "action_id,step,action_type,completed_at,no_actions_after_boundary,owned_processes")
$positionManifest = Get-Content -LiteralPath (Join-Path $positionRoot "raw\$positionRunId\manifest.json") -Raw -Encoding UTF8 |
    ConvertFrom-Json
Assert-True "position: the manifest of the Run lists its own window export and not the snapshot" (
    @($positionManifest.items).Count -eq 2 -and
    @($positionManifest.items | Where-Object { [string]$_.path -like "*position-finality*" }).Count -eq 0)

Reset-Fakes
$script:PositionProducerWrites = $false
$silentRoot = New-TempRoot
$silentControl = New-TempRoot
Assert-Throws "position: no freeze ack within the timeout fails the run" {
    Invoke-PositionRun -RunId "RUN-20300101-032" -DataRoot $silentRoot -ControlRoot $silentControl -TimeoutSec 30
} "*no collection freeze ack within 30 s*"
Assert-True "  ... before anything is exported, without the files of a valid run and with run-failed" (
    (Get-CallCount "invoke:export") -eq 0 -and (Get-CallCount "invoke:export_record_bounded") -eq 0 -and
    (Test-SuccessArtifactsAbsent -Root $silentRoot -RunId "RUN-20300101-032") -and
    -not (Test-Path -LiteralPath (Join-Path $silentControl "RUN-20300101-032\run-finalized.json")) -and
    (Read-PositionJson $silentControl "RUN-20300101-032" "run-failed.json").stage -ceq "collection_freeze")
$script:PositionProducerWrites = $true

foreach ($case in @(
        @{ name = "an export with another Event set"; id = "RUN-20300101-033"; set = @{ identity_sha256 = ("e" * 64) }
           like = "*canonical export drift*"; stage = "record_bounded_snapshot" },
        @{ name = "an export after the channel generation changed"; id = "RUN-20300101-034"
           set = @{ upper_anchor_raw_xml_sha256 = ("3" * 64) }; like = "*generation changed*"; stage = "record_bounded_snapshot" },
        @{ name = "an ack of another host"; id = "RUN-20300101-035"; set = @{}; ackHost = "TARGET-B"
           like = "*another request, Run, host*"; stage = "collection_freeze" })) {
    Reset-Fakes
    $script:PositionExportSet = $case.set
    $script:PositionAckHost = $TEST_HOST
    if ($case.ContainsKey("ackHost")) { $script:PositionAckHost = $case.ackHost }
    $caseRoot = New-TempRoot
    $caseControl = New-TempRoot
    Assert-Throws ("position: " + $case.name + " fails the run") {
        Invoke-PositionRun -RunId $case.id -DataRoot $caseRoot -ControlRoot $caseControl
    } $case.like
    Assert-True ("  ... without the files of a valid run or run-finalized (" + $case.name + ")") (
        (Test-SuccessArtifactsAbsent -Root $caseRoot -RunId $case.id) -and
        -not (Test-Path -LiteralPath (Join-Path $caseControl ($case.id + "\run-finalized.json"))) -and
        (Read-PositionJson $caseControl $case.id "run-failed.json").stage -ceq $case.stage)
}
$script:PositionExportSet = @{}
$script:PositionAckHost = $TEST_HOST

 # --- the producer binding before the first action ---------------------------------------

foreach ($case in @(
        @{ name = "without a producer binding"; id = "RUN-20300101-041"; noBinding = $true; like = "*no producer binding*" },
        @{ name = "whose producer collects another host"; id = "RUN-20300101-042"; bindingHost = "TARGET-B"
           like = "*collects another Run, host or partition*" },
        @{ name = "whose contract binds another host"; id = "RUN-20300101-043"; contractHost = "TARGET-B"
           like = "*does not bind exactly the Sysmon partition*" },
        @{ name = "whose contract changed after the producer started"; id = "RUN-20300101-044"; changeContract = $true
           like = "*not the one the producer was started with*" })) {
    Reset-Fakes
    $caseRoot = New-TempRoot
    $caseControl = New-TempRoot
    if (-not $case.ContainsKey("noBinding")) {
        $bindingHost = $TEST_HOST; if ($case.ContainsKey("bindingHost")) { $bindingHost = $case.bindingHost }
        $contractHost = $TEST_HOST; if ($case.ContainsKey("contractHost")) { $contractHost = $case.contractHost }
        $contractPath = Write-FakeProducerBinding -ControlRoot $caseControl -RunId $case.id -BindingHost $bindingHost `
            -ContractHost $contractHost
        if ($case.ContainsKey("contractHost")) {
            # The binding names the file as it is; only its host is not the runner's.
            $bindingPath = Join-Path (Join-Path $caseControl $case.id) "collection-producer-binding.json"
            $binding = Get-Content -LiteralPath $bindingPath -Raw | ConvertFrom-Json
            $binding.required_partition_contract.target_host = $TEST_HOST
            [System.IO.File]::WriteAllText($bindingPath, ($binding | ConvertTo-Json -Depth 4))
        }
        if ($case.ContainsKey("changeContract")) { [System.IO.File]::AppendAllText($contractPath, " ") }
    }
    Assert-Throws ("position: a run " + $case.name + " is refused") {
        Invoke-PositionRun -RunId $case.id -DataRoot $caseRoot -ControlRoot $caseControl -NoBinding
    } $case.like
    Assert-True ("  ... before its first action, with run-failed at the preflight (" + $case.name + ")") (
        (Get-CallCount "invoke:prepare") -eq 0 -and (Get-CallCount "invoke:launch_wmi") -eq 0 -and
        (Read-PositionJson $caseControl $case.id "run-failed.json").stage -ceq "position_preflight" -and
        -not (Test-Path -LiteralPath (Join-Path $caseControl ($case.id + "\collection-freeze-requested.json"))))
}

 # --- the producer's failure ends the wait ---------------------------------------------------

Reset-Fakes
$script:PositionProducerFails = "freeze_snapshot_rejected"
$failRoot = New-TempRoot
$failControl = New-TempRoot
Assert-Throws "position: the producer's failure fails the run at once with its reason code" {
    Invoke-PositionRun -RunId "RUN-20300101-045" -DataRoot $failRoot -ControlRoot $failControl
} "*collection freeze failure: freeze_snapshot_rejected (view_mismatch)*"
Assert-True "  ... after one poll of the ack, before anything is exported, and with run-failed" (
    @($script:SleepCalls | Where-Object { $_ -eq 5 }).Count -eq 1 -and
    (Get-CallCount "invoke:export") -eq 0 -and (Get-CallCount "invoke:export_record_bounded") -eq 0 -and
    (Test-SuccessArtifactsAbsent -Root $failRoot -RunId "RUN-20300101-045") -and
    (Read-PositionJson $failControl "RUN-20300101-045" "run-failed.json").stage -ceq "collection_freeze")
Reset-Fakes
$script:PositionFailureRequestSha = "e" * 64
$staleRoot = New-TempRoot
$staleControl = New-TempRoot
Assert-Throws "position: a failure bound to other request bytes is not consumed as this run's failure" {
    Invoke-PositionRun -RunId "RUN-20300101-046" -DataRoot $staleRoot -ControlRoot $staleControl
} "*a collection freeze failure of another Run, request, host or partition*"
$script:PositionProducerFails = ""
$script:PositionFailureRequestSha = ""

Reset-Fakes
Assert-Throws "position: position finality without a control root is refused before any session" {
    Invoke-FakeCollectionRun -RunType "attack" -ScenarioPath $wmiScenarioPath -DataRoot (New-TempRoot) `
        -ReadinessRecordPath $readinessPath -Transport (New-PositionFakeTransport) -PositionFinality
} "*PositionFinality needs IncrementalStreamControlRoot*"
Assert-True "  ... and it opens no session" ($script:FakeCalls.Count -eq 0)

Reset-Fakes
$usedControl = New-TempRoot
New-Item -ItemType Directory -Path (Join-Path $usedControl "RUN-20300101-036") | Out-Null
[System.IO.File]::WriteAllText((Join-Path $usedControl "RUN-20300101-036\collection-freeze-requested.json"), "{}")
Assert-Throws "position: a run whose freeze artifacts already exist is refused" {
    Invoke-PositionRun -RunId "RUN-20300101-036" -DataRoot (New-TempRoot) -ControlRoot $usedControl
} "*position-finality artifact of this run already exists*"
Assert-True "  ... before its first action" ((Get-CallCount "invoke:launch_wmi") -eq 0 -and (Get-CallCount "invoke:prepare") -eq 0)

Write-Host ""
if ($script:Failures -eq 0) {
    # Every case worked on a directory this script created. They hold synthetic
    # output only and are removed once nothing is left to inspect.
    foreach ($path in $script:TempRoots) {
        if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Recurse -Force }
    }
    Write-Host "ALL $($script:Total) CHECKS PASSED" -ForegroundColor Green
    exit 0
}

Write-Host "$($script:Failures) of $($script:Total) CHECKS FAILED" -ForegroundColor Red
Write-Host ("temporary output kept for inspection under " + [System.IO.Path]::GetTempPath() + "r1-guard-*")
exit 1
