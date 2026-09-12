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
        run as a harmless local anchor only in rehearsal, so the reference_time
        and causality plumbing can be exercised without any attack behaviour. In a
        normal run A01 and A02 raise an explicit "not implemented" error: the
        -EncodedCommand launch (A01) and the external connection (A02) are written
        only after the network isolation decision on issue #71 is recorded, and
        no substitute behaviour is created in the meantime.

        reference_time is the first Sysmon EID 1 the A01 process produces, and
        reference_source_event_id is that record's Sysmon RecordId
        (docs/scenarios/s0.md section 6). A02 must run inside the A01 process
        (same ProcessGuid, section 4-2); Test-ActionCausality checks that once A02
        exists. Until then the check returns not_verified, which is expected.

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
            -SysmonConfigPath C:\Tools\sysmonconfig-sample-v0.1.xml -Rehearsal
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

    $anchor = @'
$ErrorActionPreference = "Stop"
$marker = Join-Path $PSScriptRoot "s0_anchor.txt"
Set-Content -Path $marker -Value ("anchor " + (Get-Date).ToUniversalTime().ToString("o")) -Encoding Ascii
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

        In rehearsal this starts a harmless local script so the PID and the
        reference_time path can be exercised. In a normal run the real A01
        (-EncodedCommand launch) is not implemented: the malicious shape is
        written only after the issue #71 decision, with no substitute here.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$ScriptPath,
        [switch]$Rehearsal
    )

    if (-not $Rehearsal) {
        throw ("A01 is not implemented for a real run. The -EncodedCommand launch " +
            "is written after the network isolation decision (see scenario.external_connection). " +
            "No substitute behaviour is created here.")
    }

    $startedAt = Get-Date
    $process = Start-Process -FilePath "powershell.exe" `
        -ArgumentList @("-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
            "-File", $ScriptPath) `
        -WindowStyle Hidden -PassThru
    $process.WaitForExit()
    if ($process.ExitCode -ne 0) {
        throw "anchor script failed with exit code $($process.ExitCode): $ScriptPath"
    }

    return [ordered]@{ process = $process; started_at = $startedAt }
}

function Invoke-ExternalConnection {
    <#
        A02 - the A01 process connects outbound to a global destination.

        Not implemented. The destination must satisfy the Evidence condition
        script_interpreter_external_connection (globally routable address), and a
        run that leaves the isolated network needs the issue #71 decision. The
        connection must be made by the A01 process itself so the ProcessGuid
        matches (docs/scenarios/s0.md section 4-2); that is written together with
        the real A01.
    #>
    param([Parameter(Mandatory = $true)]$Context)

    $target = $Context.scenario.external_connection.target
    throw ("A02 is not implemented. external_connection.target='" + $target +
        "'; see " + $Context.scenario.external_connection.decision_reference)
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

Initialize-AttackWorkDir -Path $WorkDir

$anchorProcessGuid = $null
$a02StartedAt = $null

Write-Step "A01 anchor process"
Wait-ForOffset -Context $context -Rehearsal:$Rehearsal `
    -OffsetSec (Get-ActionOffset -Context $context -ActionId "A01")
$a01 = Start-AnchorProcess -ScriptPath (Join-Path $WorkDir "s0_anchor.ps1") -Rehearsal:$Rehearsal
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
    $a02StartedAt = Get-Date
    Invoke-ExternalConnection -Context $context
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
$a02Action = $context.run.actions | Where-Object { $_.action_id -eq "A02" }
$causality = Test-ActionCausality -Events $events -AnchorProcessGuid $anchorProcessGuid `
    -ChildStartedAt $a02StartedAt `
    -ExpectedDestination $context.scenario.external_connection.target `
    -ExpectedPort $context.scenario.external_connection.port
Write-Ok ("A01 -> A02 causality: " + $causality.status + " (" + $causality.reason + ")")

Write-ExecutionRecord -Context $context | Out-Null
Write-RunMetadata -Context $context -EndTime $endTime `
    -ReferenceTime $reference.reference_time `
    -ReferenceActionId $context.run.reference_action_id `
    -ReferenceSourceEventId $reference.reference_source_event_id | Out-Null
Write-RunManifest -Context $context | Out-Null

Write-Ok ("attack run finished: " + $context.run_id + " events=" + $events.Count +
    " actions=" + $context.execution_records.Count + " causality=" + $causality.status)
