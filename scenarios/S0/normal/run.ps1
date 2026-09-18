<#
    .SYNOPSIS
        Execute the S0 normal run and write its four artifacts.

    .DESCRIPTION
        Run inside the experiment VM with Administrator privileges. The actions
        are the ones listed in docs/scenarios/s0.md section 4-1.

            N01  admin_action     plain PowerShell management script
            N02  admin_action     outbound HTTPS lookup           (see below)
            N03  file_operation   copy and compress work files
            N04  admin_action     local backup and cleanup

        N02 needs a globally routable destination, so it is not implemented in
        this file. The destination and the network mode are decided in issue #71.
        Until then the action raises, and -Rehearsal skips it so the artifact
        flow can be exercised without any outbound traffic.

        Shortcut controls (docs/scenarios/s0.md section 7): both runs use the
        same account, the same working directory and the s0_ filename prefix,
        and both perform four actions. Nothing here encodes the run type into a
        file or process name.

        NOTE: this file is intentionally ASCII only. Windows PowerShell 5.1
        misreads UTF-8 source files without a BOM, and a lost BOM corrupts
        string literals.

    .PARAMETER RunId
        RUN-YYYYMMDD-NNN. Issued outside the VM so a snapshot restore cannot
        hand out the same value twice.

    .PARAMETER Rehearsal
        Skip the offset waits and the external action. Artifacts produced this
        way are not a valid S0 run; use them only to check the scripts.

    .EXAMPLE
        .\run.ps1 -RunId RUN-20260914-001 -ScenarioJsonPath C:\Tools\S0\scenario.json `
            -DataRoot C:\S0\data -VmSnapshot poc-clean-v1 `
            -SysmonBinary C:\Tools\Sysmon\Sysmon64.exe `
            -SysmonConfigPath C:\Tools\S0\sysmonconfig-sample-v0.1.xml -Rehearsal
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$RunId,
    [Parameter(Mandatory = $true)][string]$ScenarioJsonPath,
    [Parameter(Mandatory = $true)][string]$DataRoot,
    [Parameter(Mandatory = $true)][string]$VmSnapshot,
    [Parameter(Mandatory = $true)][string]$SysmonBinary,
    [Parameter(Mandatory = $true)][string]$SysmonConfigPath,
    [string]$ExpectedSysmonConfigSha256,
    [string]$WorkDir = "C:\S0\work",
    [switch]$Rehearsal
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "..\run-common.ps1")

function Invoke-ExternalLookup {
    <#
        N02 - outbound HTTPS lookup.

        Not implemented. The destination must satisfy the Evidence condition
        script_interpreter_external_connection (globally routable address), and
        the network mode for a run that leaves the isolated network is decided in
        issue #71. Implement this action only after that decision is recorded in
        docs/scenarios/s0.md, and keep it to a single connection.
    #>
    param([Parameter(Mandatory = $true)]$Context)

    $target = $Context.scenario.external_connection.target
    throw ("N02 is not implemented. external_connection.target='" + $target +
        "'; see " + $Context.scenario.external_connection.decision_reference)
}


 # ---------------------------------------------------------------------------
 # Run
 # ---------------------------------------------------------------------------

if ($Rehearsal) {
    Write-Fail "rehearsal mode: offsets are skipped and N02 is not executed. Artifacts are not a valid S0 run."
}

$context = New-RunContext -RunId $RunId -RunType "normal" -ScenarioJsonPath $ScenarioJsonPath `
    -DataRoot $DataRoot -VmSnapshot $VmSnapshot -SysmonBinary $SysmonBinary `
    -SysmonConfigPath $SysmonConfigPath -ExpectedSysmonConfigSha256 $ExpectedSysmonConfigSha256 `
    -Rehearsal:$Rehearsal

Initialize-WorkDir -Path $WorkDir

Write-Step "N01 management script"
Wait-ForOffset -Context $context -Rehearsal:$Rehearsal `
    -OffsetSec (Get-ActionOffset -Context $context -ActionId "N01")
$n01 = Start-ScenarioScript -ScriptPath (Join-Path $WorkDir "s0_inventory.ps1")
Add-ExecutionRecord -Context $context -ActionId "N01" -Timestamp $n01.started_at

Write-Step "N02 outbound HTTPS lookup"
Wait-ForOffset -Context $context -Rehearsal:$Rehearsal `
    -OffsetSec (Get-ActionOffset -Context $context -ActionId "N02")
if ($Rehearsal) {
    Write-Fail "N02 skipped (rehearsal)"
} else {
    $n02StartedAt = Get-Date
    Invoke-ExternalLookup -Context $context
    Add-ExecutionRecord -Context $context -ActionId "N02" -Timestamp $n02StartedAt
}

Write-Step "N03 copy and compress work files"
Wait-ForOffset -Context $context -Rehearsal:$Rehearsal `
    -OffsetSec (Get-ActionOffset -Context $context -ActionId "N03")
$n03 = Start-ScenarioScript -ScriptPath (Join-Path $WorkDir "s0_archive.ps1")
Add-ExecutionRecord -Context $context -ActionId "N03" -Timestamp $n03.started_at

Write-Step "N04 local backup and cleanup"
Wait-ForOffset -Context $context -Rehearsal:$Rehearsal `
    -OffsetSec (Get-ActionOffset -Context $context -ActionId "N04")
$n04 = Start-ScenarioScript -ScriptPath (Join-Path $WorkDir "s0_cleanup.ps1")
Add-ExecutionRecord -Context $context -ActionId "N04" -Timestamp $n04.started_at

 # A normal run has no reference_time, so the observation window is anchored to the
 # run start and lasts as long as the attack run (docs/scenarios/s0.md sections 7 and 9).
Wait-ForObservationEnd -Context $context -AnchorTime $context.start_time -Rehearsal:$Rehearsal

$endTime = Get-Date
$events = Export-SysmonRunWindow -Context $context

 # A normal run carries no Ground Truth reference: RunMetadata rejects a normal
 # run whose reference_time is not null (docs/scenarios/s0.md section 5).
Write-ExecutionRecord -Context $context | Out-Null
Write-RunMetadata -Context $context -EndTime $endTime `
    -ReferenceTime $null -ReferenceActionId $null -ReferenceSourceEventId $null | Out-Null
Write-RunManifest -Context $context | Out-Null

Write-Ok ("normal run finished: " + $context.run_id + " events=" + $events.Count +
    " actions=" + $context.execution_records.Count)
