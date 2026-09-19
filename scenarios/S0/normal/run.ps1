<#
    .SYNOPSIS
        Execute the S0 normal run and write its four artifacts.

    .DESCRIPTION
        Run inside the experiment VM with Administrator privileges. The actions
        are the ones listed in docs/scenarios/s0.md section 4-1.

            N01  admin_action     plain PowerShell management script
            N02  admin_action     outbound connection from its own process
            N03  file_operation   copy and compress work files
            N04  admin_action     local backup and cleanup

        N02 needs a globally routable destination (issue #71). In a formal run a
        dedicated worker process (New-ConnectionWorker) makes one approved TCP
        connection with no payload, and its EID 3 is verified against that
        worker's own ProcessGuid so a background connection is never taken for
        N02. -Rehearsal skips N02 and needs no approval, so the artifact flow can
        be exercised without any outbound traffic. The approval and connection
        helpers live in run-common.ps1 and docs/scenarios/s0-formal-actions.md.

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
    [int]$AnchorTimeoutSec = 60,
    [string]$ApprovedStartUtc,
    [string]$ApprovedEndUtc,
    [string]$ApprovedComputerName,
    [int]$MaxConnectionAttempts = 1,
    [int]$ConnectTimeoutMs = 3000,
    [switch]$Rehearsal
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "..\run-common.ps1")


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

 # Validate every approval input before anything runs, and again right before N02.
 # Rehearsal requires no approval and makes no connection.
$approval = $null
if (-not $Rehearsal) {
    $approval = Assert-FormalConnectionApproval -Context $context `
        -ApprovedStartUtc $ApprovedStartUtc -ApprovedEndUtc $ApprovedEndUtc `
        -ApprovedComputerName $ApprovedComputerName -MaxConnectionAttempts $MaxConnectionAttempts
}

Initialize-WorkDir -Path $WorkDir

$worker = $null

try {

Write-Step "N01 management script"
Wait-ForOffset -Context $context -Rehearsal:$Rehearsal `
    -OffsetSec (Get-ActionOffset -Context $context -ActionId "N01")
$n01 = Start-ScenarioScript -ScriptPath (Join-Path $WorkDir "s0_inventory.ps1")
Add-ExecutionRecord -Context $context -ActionId "N01" -Timestamp $n01.started_at

Write-Step "N02 outbound connection from its own process"
Wait-ForOffset -Context $context -Rehearsal:$Rehearsal `
    -OffsetSec (Get-ActionOffset -Context $context -ActionId "N02")
$n02WorkerGuid = $null
$n02StartedAt = $null
if ($Rehearsal) {
    Write-Fail "N02 skipped (rehearsal)"
} else {
    # A dedicated worker process makes the connection, so N02's EID 3 carries that
    # process's own ProcessGuid and cannot be confused with another background
    # process's EID 3.
    #
    # File launch is requested explicitly: a normal run must not carry
    # -EncodedCommand on its command line, so it produces only the external
    # connection Evidence and never encoded_powershell_command.
    $worker = New-ConnectionWorker -WorkDir $WorkDir -RunId $RunId -Approval $approval `
        -LaunchMode "File" -ConnectTimeoutMs $ConnectTimeoutMs
    $n02WorkerGuid = (Get-AnchorTelemetry -ProcessId $worker.process.Id -Since $worker.started_at `
        -TimeoutSec $AnchorTimeoutSec).process_guid

    Assert-FormalConnectionApproval -Context $context `
        -ApprovedStartUtc $ApprovedStartUtc -ApprovedEndUtc $ApprovedEndUtc `
        -ApprovedComputerName $ApprovedComputerName -MaxConnectionAttempts $MaxConnectionAttempts | Out-Null
    $connection = Invoke-WorkerConnection -Worker $worker -Approval $approval
    $n02StartedAt = $connection.started_utc
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

 # N02 causality: the EID 3 must be the worker's own connection to the approved
 # destination. Fail closed in a formal run so a background process's EID 3 can
 # never pass as N02.
if (-not $Rehearsal) {
    $causality = Test-ActionCausality -Events $events -AnchorProcessGuid $n02WorkerGuid `
        -ChildStartedAt $n02StartedAt `
        -ExpectedDestination $context.scenario.external_connection.target `
        -ExpectedPort $context.scenario.external_connection.port
    Write-Ok ("N02 causality: " + $causality.status + " (" + $causality.reason + ")")
    Assert-FormalCausalityMatched -Causality $causality
}

 # A normal run carries no Ground Truth reference: RunMetadata rejects a normal
 # run whose reference_time is not null (docs/scenarios/s0.md section 5).
Write-ExecutionRecord -Context $context | Out-Null
Write-RunMetadata -Context $context -EndTime $endTime `
    -ReferenceTime $null -ReferenceActionId $null -ReferenceSourceEventId $null | Out-Null
Write-RunManifest -Context $context | Out-Null

Write-Ok ("normal run finished: " + $context.run_id + " events=" + $events.Count +
    " actions=" + $context.execution_records.Count)

}
finally {
    # Stop the N02 worker and remove its channel so no trigger/status remains for
    # a later run. In rehearsal $worker is null and nothing needs stopping.
    if ($null -ne $worker) {
        Stop-ConnectionWorker -Worker $worker
    }
}
