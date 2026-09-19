<#
    .SYNOPSIS
        Orchestrate the S0 attack run and write its four artifacts.

    .DESCRIPTION
        Run inside the isolated experiment VM with Administrator privileges. The
        actions are the ones listed in docs/scenarios/s0.md section 4-2.

            A01  execution             anchor process (reference_time source)
            A02  command_and_control   outbound connection from the A01 process
            A03  collection            local directory collect and compress
            A04  execution             follow-on process

        This file does NOT implement the malicious shape of the scenario. A01 is
        a harmless anchor process in every mode: the obfuscated -EncodedCommand
        launch is intentionally not written. In rehearsal the anchor is a local
        sleep script and A02 is skipped. In a formal run A01 is the connection
        worker (New-ConnectionWorker) and A02 is that same worker making one
        approved TCP connection with no payload; the approval, worker and
        causality checks are in run-common.ps1 and docs/scenarios/s0-formal-actions.md.

        reference_time is the first Sysmon EID 1 the A01 process produces, and
        reference_source_event_id is that record's Sysmon RecordId
        (docs/scenarios/s0.md section 6). A02 runs inside the A01 process (same
        ProcessGuid, section 4-2); Test-ActionCausality checks that, and a formal
        run stops unless the result is "matched". Rehearsal keeps not_verified.

        NOTE: this file is intentionally ASCII only. Windows PowerShell 5.1
        misreads UTF-8 source files without a BOM, and a lost BOM corrupts
        string literals.

    .PARAMETER RunId
        RUN-YYYYMMDD-NNN. Issued outside the VM so a snapshot restore cannot hand
        out the same value twice.

    .PARAMETER Rehearsal
        Run the harmless anchor, skip A02, skip the offset waits and the
        observation window. Artifacts produced this way are NOT a valid S0 run;
        use them only to check the scripts.

    .EXAMPLE
        .\run.ps1 -RunId RUN-20260914-002 -ScenarioJsonPath C:\Tools\S0\scenario.json `
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

function Initialize-AttackWorkDir {
    <#
        Create the shared working directory and the local helper scripts A03 and
        A04 use. Both runs use the same directory and the same s0_ prefix so the
        path and the file names cannot separate normal from attack
        (docs/scenarios/s0.md section 7). No attack tooling is written here.
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

    # The anchor process must outlive A02: in a real run A02 is performed inside
    # this same process (same ProcessGuid), so it cannot exit first. The rehearsal
    # anchor therefore sleeps and is stopped by Stop-AnchorProcess at the end.
    $anchor = @'
$ErrorActionPreference = "Stop"
$marker = Join-Path $PSScriptRoot "s0_anchor.txt"
Set-Content -Path $marker -Value ("anchor " + (Get-Date).ToUniversalTime().ToString("o")) -Encoding Ascii
Start-Sleep -Seconds 3600
'@
    [System.IO.File]::WriteAllText((Join-Path $Path "s0_anchor.ps1"), $anchor, $utf8NoBom)

    $collect = @'
$ErrorActionPreference = "Stop"
$source = Join-Path $PSScriptRoot "s0_docs"
$staging = Join-Path $PSScriptRoot "s0_staging"
New-Item -ItemType Directory -Path $staging -Force | Out-Null
Copy-Item -Path (Join-Path $source "*") -Destination $staging -Force
$zip = Join-Path $PSScriptRoot "s0_collection.zip"
if (Test-Path $zip) { Remove-Item $zip -Force }
Compress-Archive -Path (Join-Path $staging "*") -DestinationPath $zip
'@
    [System.IO.File]::WriteAllText((Join-Path $Path "s0_collect.ps1"), $collect, $utf8NoBom)

    $followon = @'
$ErrorActionPreference = "Stop"
$log = Join-Path $PSScriptRoot "s0_followon.log"
Add-Content -Path $log -Value ("follow-on " + (Get-Date).ToUniversalTime().ToString("o")) -Encoding Ascii
'@
    [System.IO.File]::WriteAllText((Join-Path $Path "s0_followon.ps1"), $followon, $utf8NoBom)

    Write-Ok "work directory ready: $Path"
}

function Start-AnchorProcess {
    <#
        A01 - the process reference_time is measured from.

        The process is started and its PID is returned WITHOUT waiting for it to
        exit. A02 must run inside this same process so their Sysmon ProcessGuid
        matches (docs/scenarios/s0.md section 4-2); if the anchor exited here, A02
        could only run as a separate process and the causality would be broken.
        The caller stops the rehearsal anchor with Stop-AnchorProcess after the
        run, never before A02.

        This is the rehearsal anchor only: it starts a harmless local script so
        the PID and the reference_time path can be exercised without a
        connection. A formal run does not call this; it starts the connection
        worker (New-ConnectionWorker) as A01, and A02 is a behaviour of that same
        worker process, not a new Start-Process. A non-rehearsal call is refused
        so this harmless anchor can never stand in for a formal A01.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$ScriptPath,
        [switch]$Rehearsal
    )

    if (-not $Rehearsal) {
        throw ("Start-AnchorProcess is the rehearsal anchor only. A formal A01 is the " +
            "connection worker; see New-ConnectionWorker.")
    }

    $startedAt = Get-Date
    $process = Start-Process -FilePath "powershell.exe" `
        -ArgumentList @("-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
            "-File", $ScriptPath) `
        -WindowStyle Hidden -PassThru

    # No WaitForExit: the anchor must stay alive until the run is finished so A02
    # can be performed inside it. Start-Process already failed if it could not
    # launch; a non-zero exit is checked later by Stop-AnchorProcess.
    return [ordered]@{ process = $process; started_at = $startedAt }
}

function Stop-AnchorProcess {
    <#
        Stop the rehearsal anchor after the run. Called only at the end, never
        before A02, so A01 never exits ahead of A02.
    #>
    param([object]$AnchorResult)

    if ($null -eq $AnchorResult) { return }
    $process = $AnchorResult.process
    if ($null -ne $process -and -not $process.HasExited) {
        $process.Kill()
        $process.WaitForExit()
        Write-Ok "rehearsal anchor stopped"
    }
}

 # ---------------------------------------------------------------------------
 # Run
 # ---------------------------------------------------------------------------

if ($Rehearsal) {
    Write-Fail ("rehearsal mode: A01 runs a harmless anchor, A02 is skipped, offsets and the " +
        "observation window are skipped. Artifacts are not a valid S0 run.")
}

$context = New-RunContext -RunId $RunId -RunType "attack" -ScenarioJsonPath $ScenarioJsonPath `
    -DataRoot $DataRoot -VmSnapshot $VmSnapshot -SysmonBinary $SysmonBinary `
    -SysmonConfigPath $SysmonConfigPath -ExpectedSysmonConfigSha256 $ExpectedSysmonConfigSha256 `
    -Rehearsal:$Rehearsal

 # Validate every approval input before anything runs. This throws before a
 # worker or a socket exists, and it is checked again right before A02. Rehearsal
 # requires no approval and makes no connection.
$approval = $null
if (-not $Rehearsal) {
    $approval = Assert-FormalConnectionApproval -Context $context `
        -ApprovedStartUtc $ApprovedStartUtc -ApprovedEndUtc $ApprovedEndUtc `
        -ApprovedComputerName $ApprovedComputerName -MaxConnectionAttempts $MaxConnectionAttempts
}

Initialize-AttackWorkDir -Path $WorkDir

$anchorProcessGuid = $null
$a02StartedAt = $null
$a01 = $null
$worker = $null

try {

Write-Step "A01 anchor process"
Wait-ForOffset -Context $context -Rehearsal:$Rehearsal `
    -OffsetSec (Get-ActionOffset -Context $context -ActionId "A01")
if ($Rehearsal) {
    # A harmless anchor exercises the reference_time and causality plumbing.
    $a01 = Start-AnchorProcess -ScriptPath (Join-Path $WorkDir "s0_anchor.ps1") -Rehearsal:$Rehearsal
} else {
    # A01 is the connection worker. A02 is performed inside this same process, so
    # the EID 3 ProcessGuid equals this process's EID 1 ProcessGuid.
    $worker = New-ConnectionWorker -WorkDir $WorkDir -RunId $RunId -Approval $approval `
        -ConnectTimeoutMs $ConnectTimeoutMs
    $a01 = [ordered]@{ process = $worker.process; started_at = $worker.started_at }
}
Add-ExecutionRecord -Context $context -ActionId "A01" -Timestamp $a01.started_at

 # reference_time is read from the live Sysmon channel, not from the EVTX export,
 # because the export happens after the observation window closes and the window
 # end depends on reference_time (docs/scenarios/s0.md sections 6 and 9).
$reference = Get-AnchorTelemetry -ProcessId $a01.process.Id -Since $a01.started_at `
    -TimeoutSec $AnchorTimeoutSec
$anchorProcessGuid = $reference.process_guid
Write-Ok ("reference_time=" + $reference.reference_time +
    " record_id=" + $reference.reference_source_event_id)

Write-Step "A02 external connection from the anchor process"
Wait-ForOffset -Context $context -Rehearsal:$Rehearsal `
    -OffsetSec (Get-ActionOffset -Context $context -ActionId "A02")
if ($Rehearsal) {
    Write-Fail "A02 skipped (rehearsal)"
} else {
    # Re-check the approval window right before the connection, then let the A01
    # worker make exactly one approved TCP connection. The recorded time is the
    # worker's real attempt time, not the moment the trigger was written.
    Assert-FormalConnectionApproval -Context $context `
        -ApprovedStartUtc $ApprovedStartUtc -ApprovedEndUtc $ApprovedEndUtc `
        -ApprovedComputerName $ApprovedComputerName -MaxConnectionAttempts $MaxConnectionAttempts | Out-Null
    $connection = Invoke-WorkerConnection -Worker $worker -Approval $approval
    $a02StartedAt = $connection.started_utc
    Add-ExecutionRecord -Context $context -ActionId "A02" -Timestamp $a02StartedAt
}

Write-Step "A03 local collect and compress"
Wait-ForOffset -Context $context -Rehearsal:$Rehearsal `
    -OffsetSec (Get-ActionOffset -Context $context -ActionId "A03")
$a03 = Start-ScenarioScript -ScriptPath (Join-Path $WorkDir "s0_collect.ps1")
Add-ExecutionRecord -Context $context -ActionId "A03" -Timestamp $a03.started_at

Write-Step "A04 follow-on process"
Wait-ForOffset -Context $context -Rehearsal:$Rehearsal `
    -OffsetSec (Get-ActionOffset -Context $context -ActionId "A04")
$a04 = Start-ScenarioScript -ScriptPath (Join-Path $WorkDir "s0_followon.ps1")
Add-ExecutionRecord -Context $context -ActionId "A04" -Timestamp $a04.started_at

 # An attack run is observed from reference_time for the horizon plus the margin
 # (docs/scenarios/s0.md section 9).
$referenceTime = [datetime]::Parse($reference.reference_time).ToUniversalTime()
Wait-ForObservationEnd -Context $context -AnchorTime $referenceTime -Rehearsal:$Rehearsal

$endTime = Get-Date
$events = Export-SysmonRunWindow -Context $context

 # A02 causality. Matching needs the A02 start time and the expected destination
 # so an earlier connection by the anchor process is not mistaken for A02. While
 # A02 is unimplemented, $a02StartedAt is null and the result is not_verified.
$causality = Test-ActionCausality -Events $events -AnchorProcessGuid $anchorProcessGuid `
    -ChildStartedAt $a02StartedAt `
    -ExpectedDestination $context.scenario.external_connection.target `
    -ExpectedPort $context.scenario.external_connection.port
Write-Ok ("A01 -> A02 causality: " + $causality.status + " (" + $causality.reason + ")")

 # Fail closed: a formal run must not produce a success manifest unless the EID 3
 # is the anchor's own connection to the approved destination. Rehearsal keeps
 # the not_verified result and still writes its (clearly marked) artifacts.
if (-not $Rehearsal) {
    Assert-FormalCausalityMatched -Causality $causality
}

Write-ExecutionRecord -Context $context | Out-Null
Write-RunMetadata -Context $context -EndTime $endTime `
    -ReferenceTime $reference.reference_time `
    -ReferenceActionId $context.run.reference_action_id `
    -ReferenceSourceEventId $reference.reference_source_event_id | Out-Null
Write-RunManifest -Context $context | Out-Null

Write-Ok ("attack run finished: " + $context.run_id + " events=" + $events.Count +
    " actions=" + $context.execution_records.Count + " causality=" + $causality.status)

}
finally {
    # Stop the anchor only here, after every action and the export, so A01 never
    # exits before A02. Rehearsal used a harmless anchor; a formal run used the
    # connection worker, whose channel is removed here so no trigger/status is
    # left behind for a later run to reuse.
    if ($null -ne $worker) {
        Stop-ConnectionWorker -Worker $worker
    } else {
        Stop-AnchorProcess -AnchorResult $a01
    }
}
