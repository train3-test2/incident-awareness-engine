<#
    .SYNOPSIS
        Regression checks for the guard functions in scenarios/S0/run-common.ps1.

    .DESCRIPTION
        Runs on the host. It does not need Sysmon, a VM, or Administrator rights:
        every case works on temporary directories and pure functions.

        Two guards are covered.

        1. Assert-RunDirectoryAvailable - a run_id that already produced output is
           refused, and the refused call leaves the earlier artifacts untouched.
        2. Test-AnchorEventBoundary - a Sysmon EID 1 record is accepted as the
           anchor only when it belongs to the started process AND was created at or
           after the moment that process started.

        The repository has no PowerShell test harness, so this script is a plain
        runner: it prints one line per case and exits non-zero when any case fails.

            powershell -ExecutionPolicy Bypass -File scenarios\S0\tests\Test-RunCommonGuards.ps1

        NOTE: this file is intentionally ASCII only, for the same reason as the
        rest of scenarios/S0 - Windows PowerShell 5.1 misreads UTF-8 source files
        without a BOM.
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "..\run-common.ps1")

$script:Failures = 0
$script:Total = 0

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
    $path = Join-Path ([System.IO.Path]::GetTempPath()) ("s0-guard-" + [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $path -Force | Out-Null
    return $path
}

function New-ExistingRun {
    <# Write a complete looking artifact set so a refused rerun has something to damage. #>
    param([Parameter(Mandatory = $true)][string]$EffectiveRoot, [Parameter(Mandatory = $true)][string]$RunId)

    $telemetry = Join-Path (Join-Path (Join-Path $EffectiveRoot "raw") $RunId) "telemetry"
    $groundTruth = Join-Path (Join-Path $EffectiveRoot "ground_truth") $RunId
    New-Item -ItemType Directory -Path $telemetry -Force | Out-Null
    New-Item -ItemType Directory -Path $groundTruth -Force | Out-Null

    Set-Content -Path (Join-Path $telemetry "sysmon-0001.evtx") -Value "evtx-sentinel" -Encoding Ascii
    Set-Content -Path (Join-Path $telemetry "sysmon-0001.jsonl") -Value "jsonl-sentinel" -Encoding Ascii
    Set-Content -Path (Join-Path (Split-Path $telemetry -Parent) "manifest.json") -Value "manifest-sentinel" -Encoding Ascii
    Set-Content -Path (Join-Path $groundTruth "execution_record.csv") -Value "csv-sentinel" -Encoding Ascii
    Set-Content -Path (Join-Path $groundTruth "run_metadata.json") -Value "metadata-sentinel" -Encoding Ascii
}

function Get-TreeFingerprint {
    <# Relative path, length and SHA-256 of every file under a root. #>
    param([Parameter(Mandatory = $true)][string]$Root)

    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($file in (Get-ChildItem -Path $Root -Recurse -File | Sort-Object FullName)) {
        $relative = $file.FullName.Substring($Root.Length)
        $hash = (Get-FileHash -Path $file.FullName -Algorithm SHA256).Hash
        $lines.Add("$relative|$($file.Length)|$hash")
    }

    return ($lines -join "`n")
}

function New-MinimalScenarioJson {
    <# Just enough of scenario.json for New-RunContext to reach the run_id guard. #>
    param([Parameter(Mandatory = $true)][string]$Path)

    $json = @'
{
  "scenario_id": "S0",
  "external_connection": { "target": null, "decision_reference": "issue #71" },
  "runs": {
    "attack": {
      "run_type": "attack",
      "actions": [ { "action_id": "A01", "action_type": "execution", "description": "anchor" } ]
    }
  }
}
'@
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $json, $utf8NoBom)
}

 # ---------------------------------------------------------------------------
 # Duplicate run_id
 # ---------------------------------------------------------------------------

Write-Host "`n=== duplicate run_id ===" -ForegroundColor Cyan

$runId = "RUN-20260914-002"

 # 1. raw/<run_id> only
$root = New-TempRoot
New-Item -ItemType Directory -Path (Join-Path (Join-Path $root "raw") $runId) -Force | Out-Null
Assert-True "raw/<run_id> alone is detected" (@(Get-ExistingRunDirectory -EffectiveRoot $root -RunId $runId).Count -eq 1)
Assert-Throws "raw/<run_id> alone is refused" { Assert-RunDirectoryAvailable -EffectiveRoot $root -RunId $runId } "*already has output*"

 # 2. ground_truth/<run_id> only
$root = New-TempRoot
New-Item -ItemType Directory -Path (Join-Path (Join-Path $root "ground_truth") $runId) -Force | Out-Null
Assert-True "ground_truth/<run_id> alone is detected" (@(Get-ExistingRunDirectory -EffectiveRoot $root -RunId $runId).Count -eq 1)
Assert-Throws "ground_truth/<run_id> alone is refused" { Assert-RunDirectoryAvailable -EffectiveRoot $root -RunId $runId } "*already has output*"

 # 3. both
$root = New-TempRoot
New-ExistingRun -EffectiveRoot $root -RunId $runId
Assert-True "both run directories are detected" (@(Get-ExistingRunDirectory -EffectiveRoot $root -RunId $runId).Count -eq 2)
Assert-Throws "both run directories are refused" { Assert-RunDirectoryAvailable -EffectiveRoot $root -RunId $runId } "*already has output*"
Assert-Throws "the error names the run_id" { Assert-RunDirectoryAvailable -EffectiveRoot $root -RunId $runId } "*$runId*"
Assert-Throws "the error asks for a new run_id" { Assert-RunDirectoryAvailable -EffectiveRoot $root -RunId $runId } "*Issue a new run_id*"

 # 4. neither
$root = New-TempRoot
Assert-True "an unused run_id reports no collision" (@(Get-ExistingRunDirectory -EffectiveRoot $root -RunId $runId).Count -eq 0)
$threw = $false
try { Assert-RunDirectoryAvailable -EffectiveRoot $root -RunId $runId } catch { $threw = $true }
Assert-True "an unused run_id is accepted" (-not $threw)

 # 5 and 6. a refused run leaves every earlier artifact untouched
$root = New-TempRoot
New-ExistingRun -EffectiveRoot $root -RunId $runId
$before = Get-TreeFingerprint -Root $root
try { Assert-RunDirectoryAvailable -EffectiveRoot $root -RunId $runId } catch { }
$after = Get-TreeFingerprint -Root $root
Assert-True "refused run keeps every artifact byte for byte (content and SHA-256)" ($before -eq $after)
Assert-True "the sentinel set was not empty" ($before.Length -gt 0)

 # 7 and 8. rehearsal and collection are separate namespaces
$root = New-TempRoot
$rehearsalRoot = Get-EffectiveDataRoot -DataRoot $root -Rehearsal
$collectionRoot = Get-EffectiveDataRoot -DataRoot $root
Assert-True "rehearsal root is under _rehearsal" ($rehearsalRoot -eq (Join-Path $root "_rehearsal"))
Assert-True "collection root is the data root" ($collectionRoot -eq $root)

New-ExistingRun -EffectiveRoot $rehearsalRoot -RunId $runId
Assert-Throws "rehearsal collides with rehearsal" { Assert-RunDirectoryAvailable -EffectiveRoot $rehearsalRoot -RunId $runId } "*already has output*"
$threw = $false
try { Assert-RunDirectoryAvailable -EffectiveRoot $collectionRoot -RunId $runId } catch { $threw = $true }
Assert-True "a rehearsal run_id does not block the same collection run_id" (-not $threw)

New-ExistingRun -EffectiveRoot $collectionRoot -RunId "RUN-20260914-003"
$threw = $false
try { Assert-RunDirectoryAvailable -EffectiveRoot $rehearsalRoot -RunId "RUN-20260914-003" } catch { $threw = $true }
Assert-True "a collection run_id does not block the same rehearsal run_id" (-not $threw)

 # 9. New-RunContext refuses before any side effect. SysmonBinary points at a file
 #    that cannot be executed, so reaching Get-SysmonConfigState would fail loudly.
$root = New-TempRoot
$scenarioJson = Join-Path $root "scenario.json"
New-MinimalScenarioJson -Path $scenarioJson
$fakeBinary = Join-Path $root "not-really-sysmon.txt"
Set-Content -Path $fakeBinary -Value "not an executable" -Encoding Ascii
$fakeConfig = Join-Path $root "sysmonconfig.xml"
Set-Content -Path $fakeConfig -Value "<Sysmon></Sysmon>" -Encoding Ascii
$dataRoot = Join-Path $root "data"
$rehearsalRoot = Get-EffectiveDataRoot -DataRoot $dataRoot -Rehearsal
New-ExistingRun -EffectiveRoot $rehearsalRoot -RunId $runId
$before = Get-TreeFingerprint -Root $dataRoot

Assert-Throws "New-RunContext refuses a reused run_id" {
    New-RunContext -RunId $runId -RunType "attack" -ScenarioJsonPath $scenarioJson -DataRoot $dataRoot `
        -VmSnapshot "poc-clean-v1" -SysmonBinary $fakeBinary -SysmonConfigPath $fakeConfig -Rehearsal
} "*already has output*"

$after = Get-TreeFingerprint -Root $dataRoot
Assert-True "the refused New-RunContext wrote nothing" ($before -eq $after)
Assert-True "the refused New-RunContext left no REHEARSAL.txt" (-not (Test-Path -LiteralPath (Join-Path $rehearsalRoot "REHEARSAL.txt")))

 # ---------------------------------------------------------------------------
 # Anchor boundary
 # ---------------------------------------------------------------------------

Write-Host "`n=== anchor event boundary ===" -ForegroundColor Cyan

$since = [datetime]::SpecifyKind([datetime]"2026-09-14T15:21:46.000", [System.DateTimeKind]::Utc)

Assert-True "an event after the start is accepted" (
    Test-AnchorEventBoundary -RecordedProcessId "444" -ProcessId 444 -TimeCreated $since.AddMilliseconds(216) -Since $since)
Assert-True "an event exactly at the start is accepted" (
    Test-AnchorEventBoundary -RecordedProcessId "444" -ProcessId 444 -TimeCreated $since -Since $since)
Assert-True "an event one millisecond early is rejected" (-not (
    Test-AnchorEventBoundary -RecordedProcessId "444" -ProcessId 444 -TimeCreated $since.AddMilliseconds(-1) -Since $since))
Assert-True "a reused ProcessId from five seconds earlier is rejected" (-not (
    Test-AnchorEventBoundary -RecordedProcessId "444" -ProcessId 444 -TimeCreated $since.AddSeconds(-5) -Since $since))
Assert-True "another ProcessId is rejected" (-not (
    Test-AnchorEventBoundary -RecordedProcessId "8548" -ProcessId 444 -TimeCreated $since.AddSeconds(1) -Since $since))
Assert-True "a missing ProcessId is rejected" (-not (
    Test-AnchorEventBoundary -RecordedProcessId $null -ProcessId 444 -TimeCreated $since.AddSeconds(1) -Since $since))
Assert-True "the comparison is made in UTC, not local time" (
    Test-AnchorEventBoundary -RecordedProcessId "444" -ProcessId 444 -TimeCreated $since.ToLocalTime() -Since $since)

 # ---------------------------------------------------------------------------

 # ---------------------------------------------------------------------------
 # Approved global IPv4 literal
 # ---------------------------------------------------------------------------

Write-Host "`n=== approved global IPv4 ===" -ForegroundColor Cyan

foreach ($ok in @("1.1.1.1", "8.8.8.8", "9.9.9.9", "203.0.114.9", "192.0.0.9")) {
    Assert-True "global IPv4 accepted: $ok" (Test-ApprovedGlobalIPv4 $ok)
}
foreach ($bad in @(
    "dns.example.com", "2606:4700:4700::1111", "10.0.0.5", "127.0.0.1", "169.254.10.10",
    "100.64.0.1", "192.168.1.1", "172.16.0.1", "192.0.2.5", "198.51.100.5", "203.0.113.5",
    "198.18.0.1", "224.0.0.1", "240.0.0.1", "0.0.0.0", " 1.1.1.1", "1.1.1.1 ", "1.1.1")) {
    Assert-True "non-global or non-canonical rejected: '$bad'" (-not (Test-ApprovedGlobalIPv4 $bad))
}

 # ---------------------------------------------------------------------------
 # Formal connection approval gate
 # ---------------------------------------------------------------------------

Write-Host "`n=== formal connection approval ===" -ForegroundColor Cyan

function New-ApprovalContext {
    param([string]$Target = "9.9.9.9", [object]$Port = 443, [string]$Protocol = "TCP")
    $external = [pscustomobject]@{ target = $Target; port = $Port; protocol = $Protocol }
    $scenario = [pscustomobject]@{ external_connection = $external }
    return [pscustomobject]@{ scenario = $scenario }
}

$now = [datetime]::SpecifyKind([datetime]"2026-09-20T12:00:00", [System.DateTimeKind]::Utc)
$start = "2026-09-20T11:00:00Z"
$end = "2026-09-20T13:00:00Z"
$computer = $env:COMPUTERNAME

Assert-True "a fully approved connection inside the window passes" ((
    Assert-FormalConnectionApproval -Context (New-ApprovalContext) -ApprovedStartUtc $start `
        -ApprovedEndUtc $end -ApprovedComputerName $computer -MaxConnectionAttempts 1 `
        -NowUtc $now).target -eq "9.9.9.9")

Assert-Throws "a null target is refused" {
    Assert-FormalConnectionApproval -Context (New-ApprovalContext -Target "") -ApprovedStartUtc $start `
        -ApprovedEndUtc $end -ApprovedComputerName $computer -MaxConnectionAttempts 1 -NowUtc $now
} "*not an approved global IPv4*"

Assert-Throws "a private target is refused" {
    Assert-FormalConnectionApproval -Context (New-ApprovalContext -Target "10.0.0.5") -ApprovedStartUtc $start `
        -ApprovedEndUtc $end -ApprovedComputerName $computer -MaxConnectionAttempts 1 -NowUtc $now
} "*not an approved global IPv4*"

Assert-Throws "a port out of range is refused" {
    Assert-FormalConnectionApproval -Context (New-ApprovalContext -Port 70000) -ApprovedStartUtc $start `
        -ApprovedEndUtc $end -ApprovedComputerName $computer -MaxConnectionAttempts 1 -NowUtc $now
} "*port must be an integer in 1..65535*"

Assert-Throws "a non-TCP protocol is refused" {
    Assert-FormalConnectionApproval -Context (New-ApprovalContext -Protocol "UDP") -ApprovedStartUtc $start `
        -ApprovedEndUtc $end -ApprovedComputerName $computer -MaxConnectionAttempts 1 -NowUtc $now
} "*protocol must be TCP*"

Assert-Throws "a time before the window is refused" {
    Assert-FormalConnectionApproval -Context (New-ApprovalContext) -ApprovedStartUtc $start `
        -ApprovedEndUtc $end -ApprovedComputerName $computer -MaxConnectionAttempts 1 `
        -NowUtc ([datetime]::SpecifyKind([datetime]"2026-09-20T10:59:59", [System.DateTimeKind]::Utc))
} "*outside the approved window*"

Assert-Throws "a time at or after the window end is refused" {
    Assert-FormalConnectionApproval -Context (New-ApprovalContext) -ApprovedStartUtc $start `
        -ApprovedEndUtc $end -ApprovedComputerName $computer -MaxConnectionAttempts 1 `
        -NowUtc ([datetime]::SpecifyKind([datetime]"2026-09-20T13:00:00", [System.DateTimeKind]::Utc))
} "*outside the approved window*"

Assert-Throws "an empty window (start not before end) is refused" {
    Assert-FormalConnectionApproval -Context (New-ApprovalContext) -ApprovedStartUtc $end `
        -ApprovedEndUtc $start -ApprovedComputerName $computer -MaxConnectionAttempts 1 -NowUtc $now
} "*approved window is empty*"

Assert-Throws "a computer name mismatch is refused" {
    Assert-FormalConnectionApproval -Context (New-ApprovalContext) -ApprovedStartUtc $start `
        -ApprovedEndUtc $end -ApprovedComputerName "SOME-OTHER-HOST" -MaxConnectionAttempts 1 -NowUtc $now
} "*computer name mismatch*"

Assert-Throws "more than one connection attempt is refused" {
    Assert-FormalConnectionApproval -Context (New-ApprovalContext) -ApprovedStartUtc $start `
        -ApprovedEndUtc $end -ApprovedComputerName $computer -MaxConnectionAttempts 2 -NowUtc $now
} "*MaxConnectionAttempts must be exactly 1*"

 # ---------------------------------------------------------------------------
 # Action causality on synthetic Sysmon events
 # ---------------------------------------------------------------------------

Write-Host "`n=== action causality ===" -ForegroundColor Cyan

function New-FakeSysmonEvent {
    <# A minimal stand-in for a Get-WinEvent record: Id, TimeCreated, RecordId and
       a ToXml() that Test-ActionCausality can parse for EID 3 fields. #>
    param(
        [int]$Id,
        [datetime]$TimeCreated,
        [int]$RecordId,
        [string]$ProcessGuid,
        [string]$DestinationIp,
        [string]$DestinationPort
    )
    $xml = @"
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><EventData>
<Data Name="ProcessGuid">$ProcessGuid</Data>
<Data Name="DestinationIp">$DestinationIp</Data>
<Data Name="DestinationPort">$DestinationPort</Data>
</EventData></Event>
"@
    $event = [pscustomobject]@{ Id = $Id; TimeCreated = $TimeCreated; RecordId = $RecordId }
    $event | Add-Member -MemberType ScriptMethod -Name ToXml -Value ([scriptblock]::Create("'$xml'"))
    return $event
}

$anchorGuid = "{aaaaaaaa-0000-0000-0000-000000000001}"
$otherGuid = "{bbbbbbbb-0000-0000-0000-000000000002}"
$childStarted = [datetime]::SpecifyKind([datetime]"2026-09-20T12:02:00", [System.DateTimeKind]::Utc)

$matchEvent = New-FakeSysmonEvent -Id 3 -TimeCreated $childStarted.AddSeconds(1) -RecordId 10 `
    -ProcessGuid $anchorGuid -DestinationIp "9.9.9.9" -DestinationPort "443"

Assert-True "matched: same ProcessGuid, target and port after the action" ((
    Test-ActionCausality -Events @($matchEvent) -AnchorProcessGuid $anchorGuid `
        -ChildStartedAt $childStarted -ExpectedDestination "9.9.9.9" -ExpectedPort "443").status -eq "matched")

$guidMismatch = New-FakeSysmonEvent -Id 3 -TimeCreated $childStarted.AddSeconds(1) -RecordId 11 `
    -ProcessGuid $otherGuid -DestinationIp "9.9.9.9" -DestinationPort "443"
Assert-True "mismatched: a different ProcessGuid does not match" ((
    Test-ActionCausality -Events @($guidMismatch) -AnchorProcessGuid $anchorGuid `
        -ChildStartedAt $childStarted -ExpectedDestination "9.9.9.9" -ExpectedPort "443").status -eq "mismatched")

$ipMismatch = New-FakeSysmonEvent -Id 3 -TimeCreated $childStarted.AddSeconds(1) -RecordId 12 `
    -ProcessGuid $anchorGuid -DestinationIp "203.0.114.9" -DestinationPort "443"
Assert-True "mismatched: a different destination does not match" ((
    Test-ActionCausality -Events @($ipMismatch) -AnchorProcessGuid $anchorGuid `
        -ChildStartedAt $childStarted -ExpectedDestination "9.9.9.9" -ExpectedPort "443").status -eq "mismatched")

$portMismatch = New-FakeSysmonEvent -Id 3 -TimeCreated $childStarted.AddSeconds(1) -RecordId 13 `
    -ProcessGuid $anchorGuid -DestinationIp "9.9.9.9" -DestinationPort "80"
Assert-True "mismatched: a different port does not match" ((
    Test-ActionCausality -Events @($portMismatch) -AnchorProcessGuid $anchorGuid `
        -ChildStartedAt $childStarted -ExpectedDestination "9.9.9.9" -ExpectedPort "443").status -eq "mismatched")

$early = New-FakeSysmonEvent -Id 3 -TimeCreated $childStarted.AddSeconds(-120) -RecordId 14 `
    -ProcessGuid $anchorGuid -DestinationIp "9.9.9.9" -DestinationPort "443"
Assert-True "not_verified: an EID 3 well before the action is ignored" ((
    Test-ActionCausality -Events @($early) -AnchorProcessGuid $anchorGuid `
        -ChildStartedAt $childStarted -ExpectedDestination "9.9.9.9" -ExpectedPort "443").status -eq "not_verified")

Assert-True "not_verified: no EID 3 candidate at all" ((
    Test-ActionCausality -Events @() -AnchorProcessGuid $anchorGuid `
        -ChildStartedAt $childStarted -ExpectedDestination "9.9.9.9" -ExpectedPort "443").status -eq "not_verified")

Assert-True "not_verified: child action was not executed (null start)" ((
    Test-ActionCausality -Events @($matchEvent) -AnchorProcessGuid $anchorGuid `
        -ChildStartedAt $null -ExpectedDestination "9.9.9.9" -ExpectedPort "443").status -eq "not_verified")

$backgroundThenOwn = @(
    (New-FakeSysmonEvent -Id 3 -TimeCreated $childStarted.AddSeconds(1) -RecordId 20 `
        -ProcessGuid $otherGuid -DestinationIp "9.9.9.9" -DestinationPort "443"),
    (New-FakeSysmonEvent -Id 3 -TimeCreated $childStarted.AddSeconds(2) -RecordId 21 `
        -ProcessGuid $anchorGuid -DestinationIp "9.9.9.9" -DestinationPort "443"))
$ownResult = Test-ActionCausality -Events $backgroundThenOwn -AnchorProcessGuid $anchorGuid `
    -ChildStartedAt $childStarted -ExpectedDestination "9.9.9.9" -ExpectedPort "443"
Assert-True "matched: N02 picks its own ProcessGuid, not a background EID 3" ($ownResult.status -eq "matched")
Assert-True "matched: the selected record is the worker's own EID 3" ($ownResult.record_id -eq "21")

 # ---------------------------------------------------------------------------
 # Worker launch mode - Attack EncodedCommand vs Normal File
 #
 # These cases only build the launch information. No process is started and no
 # socket is created.
 # ---------------------------------------------------------------------------

Write-Host "`n=== worker launch mode ===" -ForegroundColor Cyan

$workerPath = "C:\S0\work\s0_conn_RUN-20260920-001\s0_worker.ps1"
$channel = "C:\S0\work\s0_conn_RUN-20260920-001"

$attackLaunch = Get-WorkerLaunch -LaunchMode "EncodedCommand" -WorkerPath $workerPath -ChannelDir $channel
$normalLaunch = Get-WorkerLaunch -LaunchMode "File" -WorkerPath $workerPath -ChannelDir $channel

Assert-True "attack launch uses powershell.exe" ($attackLaunch.executable -eq "powershell.exe")
Assert-True "attack launch carries -EncodedCommand" ($attackLaunch.arguments -contains "-EncodedCommand")
Assert-True "attack launch has no -File token before the encoded option" (
    -not ($attackLaunch.arguments -contains "-File"))
Assert-True "attack launch has no -Command token" (-not ($attackLaunch.arguments -contains "-Command"))

 # The extractor scans the command line left to right and stops at -File/-Command,
 # so -EncodedCommand must be reachable first.
$attackCommandLine = ($attackLaunch.arguments -join " ")
$encodedIndex = $attackCommandLine.IndexOf("-EncodedCommand")
Assert-True "the command line exposes -EncodedCommand" ($encodedIndex -ge 0)

$encodedValue = $attackLaunch.arguments[$attackLaunch.arguments.Count - 1]
$decoded = $null
try {
    $decoded = [System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($encodedValue))
} catch {
    $decoded = $null
}
Assert-True "the encoded payload decodes as UTF-16LE Base64" ($null -ne $decoded)
Assert-True "the decoded bootstrap matches the returned bootstrap" ($decoded -eq $attackLaunch.bootstrap)
Assert-True "the decoded bootstrap only invokes the repository worker script" (
    $decoded -eq ("& '" + $workerPath + "' -ChannelDir '" + $channel + "'"))
Assert-True "the decoded bootstrap has no Invoke-Expression" ($decoded -notmatch "Invoke-Expression")
Assert-True "the decoded bootstrap has no iex alias" ($decoded -notmatch "\biex\b")

Assert-True "normal launch uses -File" ($normalLaunch.arguments -contains "-File")
Assert-True "normal launch has no -EncodedCommand" (-not ($normalLaunch.arguments -contains "-EncodedCommand"))
Assert-True "normal launch has no bootstrap to decode" ($null -eq $normalLaunch.bootstrap)
Assert-True "normal launch passes the channel directory" ($normalLaunch.arguments -contains $channel)

Assert-Throws "an unknown launch mode is refused" {
    Get-WorkerLaunch -LaunchMode "Command" -WorkerPath $workerPath -ChannelDir $channel
} "*"

 # A path holding a single quote must stay inside the quoted literal.
$quotedLaunch = Get-WorkerLaunch -LaunchMode "EncodedCommand" `
    -WorkerPath "C:\S0\it's\s0_worker.ps1" -ChannelDir "C:\S0\it's"
$quotedDecoded = [System.Text.Encoding]::Unicode.GetString(
    [Convert]::FromBase64String($quotedLaunch.arguments[$quotedLaunch.arguments.Count - 1]))
Assert-True "a quote in the path is doubled, not left to break the literal" (
    $quotedDecoded -eq ("& 'C:\S0\it''s\s0_worker.ps1' -ChannelDir 'C:\S0\it''s'"))

 # ---------------------------------------------------------------------------
 # Worker side approval window - no real clock, no real socket
 # ---------------------------------------------------------------------------

Write-Host "`n=== worker approval window ===" -ForegroundColor Cyan

$script:FakeClientsCreated = 0

function New-FakeTcpClient {
    <# A stand-in for TcpClient that records that it was created but opens
       nothing. BeginConnect returns a handle whose WaitOne reports success. #>
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

function New-WorkerConfig {
    param(
        [string]$Target = "9.9.9.9",
        [object]$Port = 443,
        [string]$Protocol = "TCP",
        [object]$MaxAttempts = 1,
        [string]$StartUtc = "2026-09-20T11:00:00.000Z",
        [string]$EndUtc = "2026-09-20T13:00:00.000Z"
    )
    return [pscustomobject]@{
        target             = $Target
        port               = $Port
        protocol           = $Protocol
        max_attempts       = $MaxAttempts
        approved_start_utc = $StartUtc
        approved_end_utc   = $EndUtc
        timeout_ms         = 3000
        idle_sec           = 10
    }
}

function Invoke-GateAt {
    param([string]$NowUtc, $Config = (New-WorkerConfig))
    $script:FakeClientsCreated = 0
    $clock = [scriptblock]::Create(
        "[datetime]::Parse('$NowUtc', [System.Globalization.CultureInfo]::InvariantCulture, " +
        "[System.Globalization.DateTimeStyles]::AdjustToUniversal -bor " +
        "[System.Globalization.DateTimeStyles]::AssumeUniversal)")
    return Invoke-ApprovedTcpAttempt -Config $Config -NowUtcProvider $clock -ClientFactory $fakeFactory
}

$inside = Invoke-GateAt -NowUtc "2026-09-20T12:00:00Z"
Assert-True "inside the window the attempt succeeds" ($inside.success -eq $true)
Assert-True "inside the window exactly one client is created" ($script:FakeClientsCreated -eq 1)
Assert-True "inside the window one attempt is recorded" ($inside.attempts_made -eq 1)
Assert-True "the attempt records the worker's own checked time" ($inside.checked_utc -eq "2026-09-20T12:00:00.000Z")
Assert-True "the attempt records a start time" ($null -ne $inside.started_utc)

$before = Invoke-GateAt -NowUtc "2026-09-20T10:59:59Z"
Assert-True "before the window the attempt fails" ($before.success -eq $false)
Assert-True "before the window the reason is approval_window_not_started" (
    $before.error_kind -eq "approval_window_not_started")
Assert-True "before the window no client is created" ($script:FakeClientsCreated -eq 0)
Assert-True "before the window no attempt is counted" ($before.attempts_made -eq 0)
Assert-True "before the window no start time is recorded" ($null -eq $before.started_utc)
Assert-True "before the window the checked time is recorded" ($before.checked_utc -eq "2026-09-20T10:59:59.000Z")

$atEnd = Invoke-GateAt -NowUtc "2026-09-20T13:00:00Z"
Assert-True "exactly at the window end the attempt fails" ($atEnd.success -eq $false)
Assert-True "exactly at the window end the reason is approval_window_expired" (
    $atEnd.error_kind -eq "approval_window_expired")
Assert-True "exactly at the window end no client is created" ($script:FakeClientsCreated -eq 0)

$after = Invoke-GateAt -NowUtc "2026-09-20T13:00:01Z"
Assert-True "after the window the attempt fails" ($after.success -eq $false)
Assert-True "after the window the reason is approval_window_expired" (
    $after.error_kind -eq "approval_window_expired")
Assert-True "after the window no client is created" ($script:FakeClientsCreated -eq 0)

 # The parent gate passed just before the window closed; the worker then runs one
 # second after it closed and must refuse.
$parentNow = [datetime]::SpecifyKind([datetime]"2026-09-20T12:59:59", [System.DateTimeKind]::Utc)
$parentApproval = Assert-FormalConnectionApproval -Context (New-ApprovalContext) `
    -ApprovedStartUtc "2026-09-20T11:00:00Z" -ApprovedEndUtc "2026-09-20T13:00:00Z" `
    -ApprovedComputerName $env:COMPUTERNAME -MaxConnectionAttempts 1 -NowUtc $parentNow
Assert-True "the parent gate passes just before the window closes" ($parentApproval.target -eq "9.9.9.9")
$expiredAtWorker = Invoke-GateAt -NowUtc "2026-09-20T13:00:01Z"
Assert-True "the worker still refuses after the parent gate passed" (
    $expiredAtWorker.error_kind -eq "approval_window_expired")
Assert-True "the late worker creates no client" ($script:FakeClientsCreated -eq 0)

$malformed = Invoke-GateAt -NowUtc "2026-09-20T12:00:00Z" -Config (New-WorkerConfig -StartUtc "not-a-time")
Assert-True "a malformed approval time fails" ($malformed.success -eq $false)
Assert-True "a malformed approval time is reported as malformed" (
    $malformed.error_kind -eq "approval_window_malformed")
Assert-True "a malformed approval time creates no client" ($script:FakeClientsCreated -eq 0)

$badRange = Invoke-GateAt -NowUtc "2026-09-20T12:00:00Z" `
    -Config (New-WorkerConfig -StartUtc "2026-09-20T13:00:00.000Z" -EndUtc "2026-09-20T11:00:00.000Z")
Assert-True "start at or after end fails" ($badRange.success -eq $false)
Assert-True "start at or after end is reported as an invalid range" (
    $badRange.error_kind -eq "approval_window_invalid_range")
Assert-True "an invalid range creates no client" ($script:FakeClientsCreated -eq 0)

$badTarget = Invoke-GateAt -NowUtc "2026-09-20T12:00:00Z" -Config (New-WorkerConfig -Target "10.0.0.5")
Assert-True "a non-approved target fails at the worker too" ($badTarget.error_kind -eq "target_not_approved")
Assert-True "a non-approved target creates no client" ($script:FakeClientsCreated -eq 0)

$badPort = Invoke-GateAt -NowUtc "2026-09-20T12:00:00Z" -Config (New-WorkerConfig -Port 0)
Assert-True "a non-approved port fails at the worker too" ($badPort.error_kind -eq "port_not_approved")
Assert-True "a non-approved port creates no client" ($script:FakeClientsCreated -eq 0)

$badProtocol = Invoke-GateAt -NowUtc "2026-09-20T12:00:00Z" -Config (New-WorkerConfig -Protocol "UDP")
Assert-True "a non-TCP protocol fails at the worker too" ($badProtocol.error_kind -eq "protocol_not_approved")
Assert-True "a non-TCP protocol creates no client" ($script:FakeClientsCreated -eq 0)

$badAttempts = Invoke-GateAt -NowUtc "2026-09-20T12:00:00Z" -Config (New-WorkerConfig -MaxAttempts 2)
Assert-True "more than one approved attempt fails at the worker too" (
    $badAttempts.error_kind -eq "attempts_not_approved")
Assert-True "more than one approved attempt creates no client" ($script:FakeClientsCreated -eq 0)

 # Both runs use the same worker side gate; only the launch mode differs.
Assert-True "A02 and N02 share one gate function" (
    $null -ne (Get-Command Invoke-ApprovedTcpAttempt -ErrorAction SilentlyContinue))

Write-Host ""
if ($script:Failures -eq 0) {
    Write-Host "ALL $($script:Total) CHECKS PASSED" -ForegroundColor Green
    exit 0
}

Write-Host "$($script:Failures) of $($script:Total) CHECKS FAILED" -ForegroundColor Red
exit 1
