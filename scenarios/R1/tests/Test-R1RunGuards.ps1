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
           run.

        The repository has no PowerShell test harness, so this script is a plain
        runner: it prints one line per case and exits non-zero when any case fails.

            powershell -ExecutionPolicy Bypass -File scenarios\R1\tests\Test-R1RunGuards.ps1

        By default the cases use the small scenario below. -BaseScenarioJson runs
        the same cases against a rendered scenarios/R1/scenario.yaml:

            python tools/r1_scenario_to_json.py scenarios/R1/scenario.yaml --out build/R1/scenario.json `
                --repetition 1
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
  "run_metadata": {
    "target_host": null,
    "sysmon_config_version": "sysmonconfig-sample-v0.1",
    "detector_set_version": null,
    "reference_policy_version": null,
    "schema_versions": {
      "run_metadata": "v0.2", "event": "v0.3", "evidence": "v0.2", "fast_hit": "v0.2",
      "detection_result": "v0.2", "fusion_result": "v0.3", "decision_result": "v0.2",
      "execution_record": "v0.1", "evaluation_input": "v0.1"
    }
  },
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
      "run_type": "attack", "reference_action_id": null,
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
        [int]$Repetition = $TEST_REPETITION
    )

    $scenario = $script:BaseScenarioText | ConvertFrom-Json
    $scenario.family_id = $FamilyId
    $scenario.variation_id = $VariationId
    $scenario.repetition = $Repetition
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
        [switch]$DuplicateFinal
    )

    $records = New-Object System.Collections.Generic.List[object]
    $records.Add((New-SyntheticRecord 1 1 $Computer ([ordered]@{
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
                return @{ utc = (Get-FakeOption "BeginUtc" $utc); session_pid = 4000; computer_name = $TEST_HOST }
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
                -Protocol (Get-FakeOption "TelemetryProtocol" "tcp")

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
        -DataRoot $DataRoot -WorkDir $WorkDir -ObservationSec $ObservationSec -VmSnapshot $VmSnapshot `
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

$referenceScenario = New-ScenarioObject
$referenceScenario.runs.attack.reference_action_id = "A01"
Assert-RefusedBeforeAnyCall "a scenario that names a reference action" {
    Invoke-FakeRun -RunType "attack" -ScenarioPath (Save-Scenario $referenceScenario) -DataRoot (New-TempRoot) -Transport (New-FakeTransport)
} "*records no reference action yet*"

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
    Assert-True ($label + "the reference fields stay null") (
        $null -eq $metadata.reference_time -and $null -eq $metadata.reference_action_id -and
        $null -eq $metadata.reference_source_event_id)
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

 # Each of the two files is created, never replaced.
$onceRoot = New-TempRoot
$onceDir = Write-R1RunTrace -EffectiveRoot $onceRoot -RunId "RUN-20300101-041" -Mode "collection" `
    -ScenarioBytes ([byte[]](1, 2, 3)) -ScenarioSha256 ("ab" * 32)
Assert-Throws "a second trace for the same run_id is refused" {
    Write-R1RunTrace -EffectiveRoot $onceRoot -RunId "RUN-20300101-041" -Mode "collection" `
        -ScenarioBytes ([byte[]](9, 9, 9)) -ScenarioSha256 ("cd" * 32)
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
