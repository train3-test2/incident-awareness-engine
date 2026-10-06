<#
    .SYNOPSIS
        Execute the R1-V02 attack run and write its four artifacts.

    .DESCRIPTION
        Run on the Controller. The five actions are the ones listed in
        docs/scenarios/r1.md section 4-1 and are performed on Target-A through one
        remote session:

            A01  remote_session      the Controller opens the session
            A02  file_operation      common preparation in the session
            A03  process_create      session host -> planned intermediate -> the same final tool
            A04  network_connection  that final tool instance connects internally
            A05  remote_session      the session is closed

        This file implements no attack technique. The run starts the same harmless
        final tool task as the normal run and makes the same internal connection;
        it only reaches the final tool through a different intermediate process,
        which is the lineage difference the Pilot observes. There is no credential
        access, no privilege change, no log clearing and no encoded command.

        Which intermediate and which final tool are started comes from
        scenario.json (scenario.yaml, planned_lineage); nothing in this file names
        them. Both runs use one account, one work directory, the same final tool
        command line and the same destination, and nothing on Target-A carries the
        run type in a file name or an argument.

        The family, the variation and the repetition of the Pair are read from
        scenario.json and written to RunMetadata. The dataset tier of the Pair
        (pilot, development or holdout) is read from scenario.json too and
        written to the operator trace of the run. This script takes no parameter
        for any of them: both runs of a Pair use one rendered scenario.json, and
        the tier is given once, when that file is rendered
        (tools/r1_scenario_to_json.py --dataset-tier).

        -DryRun validates every input, builds the launch plan and prints it. It
        opens no session and starts nothing, so it can be run anywhere.

        -Rehearsal performs the actions without waiting for the offsets or the
        observation window and writes under <DataRoot>\_rehearsal. The connection
        is made only when scenario.json carries an internal destination. Rehearsal
        artifacts are not a valid R1 run.

        The orchestration, the remote steps and the checks live in
        ..\run-common.ps1.

        NOTE: this file is intentionally ASCII only. Windows PowerShell 5.1
        misreads UTF-8 source files without a BOM, and a lost BOM corrupts
        string literals.

    .PARAMETER RunId
        RUN-YYYYMMDD-NNN. Issued outside the VMs so a snapshot restore cannot hand
        out the same value twice.

    .PARAMETER ObservationSec
        Length of the observation window in seconds from the start of the run. It
        has to cover the last action and the evaluation horizon the scenario
        states (docs/scenarios/r1.md section 11-4).

    .PARAMETER TargetAddress
        Name or address the Controller uses to reach Target-A over WinRM. It is
        not written to any artifact.

    .PARAMETER Credential
        The account both runs use. Prompted for by the operator; never stored.

    .EXAMPLE
        .\run.ps1 -RunId RUN-YYYYMMDD-NNN -ScenarioJsonPath C:\Tools\R1\scenario.json `
            -DataRoot C:\R1\data -WorkDir C:\R1\work -ObservationSec 660 -DryRun
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$RunId,
    [Parameter(Mandatory = $true)][string]$ScenarioJsonPath,
    [Parameter(Mandatory = $true)][string]$DataRoot,
    [Parameter(Mandatory = $true)][string]$WorkDir,
    [Parameter(Mandatory = $true)][int]$ObservationSec,
    [string]$VmSnapshot,
    [string]$TargetAddress,
    [int]$WinRmPort = 0,
    [switch]$UseSsl,
    [System.Management.Automation.PSCredential]$Credential,
    [string]$TargetSysmonBinary,
    [string]$TargetSysmonConfigPath,
    [string]$ExpectedSysmonConfigSha256,
    [switch]$Rehearsal,
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "..\run-common.ps1")

$connection = $null
$transport = $null
if (-not $DryRun) {
    # The address, the port and the credential are run inputs. A run that would
    # open a session refuses to start without them.
    if ([string]::IsNullOrWhiteSpace($TargetAddress)) { throw "TargetAddress is required" }
    if ($WinRmPort -lt 1 -or $WinRmPort -gt 65535) { throw "WinRmPort must be given as 1..65535" }
    if ($null -eq $Credential) { throw "Credential is required" }

    $connection = @{
        address    = $TargetAddress
        port       = $WinRmPort
        use_ssl    = [bool]$UseSsl
        credential = $Credential
    }
    $transport = New-R1WinRmTransport
}

Invoke-R1PilotRun -RunType "attack" -RunId $RunId -ScenarioJsonPath $ScenarioJsonPath `
    -DataRoot $DataRoot -WorkDir $WorkDir -ObservationSec $ObservationSec `
    -VmSnapshot $VmSnapshot -TargetSysmonBinary $TargetSysmonBinary `
    -TargetSysmonConfigPath $TargetSysmonConfigPath `
    -ExpectedSysmonConfigSha256 $ExpectedSysmonConfigSha256 `
    -Connection $connection -Transport $transport `
    -Rehearsal:$Rehearsal -DryRun:$DryRun | Out-Null
