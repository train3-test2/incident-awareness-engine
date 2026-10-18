<# Static regression checks for the diagnostic finality smoke and contract. #>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$script:Failures = 0
$script:Total = 0

function Assert-True {
    param([string]$Name, [bool]$Condition)
    $script:Total++
    if ($Condition) {
        Write-Host "[PASS] $Name" -ForegroundColor Green
    } else {
        $script:Failures++
        Write-Host "[FAIL] $Name" -ForegroundColor Red
    }
}

$scriptPath = Join-Path $PSScriptRoot "..\host\Test-R1RecordBoundedFinality.ps1"
$contractPath = Join-Path $PSScriptRoot "..\..\..\docs\schema\r1-sysmon-record-bounded-finality-v0.md"
$tokens = $null
$parseErrors = $null
[void][System.Management.Automation.Language.Parser]::ParseFile(
    $scriptPath, [ref]$tokens, [ref]$parseErrors)
$scriptText = Get-Content -LiteralPath $scriptPath -Raw
$contractText = Get-Content -LiteralPath $contractPath -Raw

Assert-True "smoke script parses in Windows PowerShell" ($parseErrors.Count -eq 0)
Assert-True "all-channel cursor is captured before target queries" (
    $scriptText.IndexOf('-MaxEvents 1') -ge 0 -and
    $scriptText.IndexOf('$seed = @(') -ge 0 -and
    $scriptText.IndexOf('-MaxEvents 1') -lt $scriptText.IndexOf('$seed = @('))
Assert-True "all compared views use an inclusive RecordId bound" (
    $scriptText -match 'EventRecordID >= \$lowerRecordId' -and
    $scriptText -match 'EventRecordID <= \$upperRecordId')
Assert-True "the target set is exactly Sysmon EID 1 and 3" (
    $scriptText -match 'EventID=1 or EventID=3' -and
    $scriptText -match 'event_ids = @\(1, 3\)')
Assert-True "query and export compare raw XML identity digests" (
    $scriptText -match '\.ToXml\(\)' -and
    $scriptText -match '\$firstDigest -ceq \$secondDigest' -and
    $scriptText -match '\$firstDigest -ceq \$exportedDigest')
Assert-True "diagnostic smoke cannot issue finality" (
    $scriptText -match 'diagnostic_only = \$true' -and
    $scriptText -match 'issued_finality = \$false' -and
    $scriptText -notmatch 'publish-watermark|publish-close')
Assert-True "diagnostic output directory is unique and never force-reused" (
    $scriptText -match '\[Guid\]::NewGuid\(\)' -and
    $scriptText -match 'result-\{0\}-\{1\}' -and
    $scriptText -notmatch 'New-Item -ItemType Directory -Path \$resultDir -Force')
Assert-True "contract requires chunk continuity and post-commit ack" (
    $contractText -match 'covered_through_chunk_sequence' -and
    $contractText -match 'post-commit ack')
Assert-True "contract explicitly excludes provider drain and early close claims" (
    $contractText -match 'provider queue drain' -and
    $contractText -match 'A04.*early close')
Assert-True "snapshot verification cannot become an event-time watermark" (
    $contractText.Contains('`observation_boundary_at`을 기존 `source_watermark.watermark_at`으로 매핑하지 않는다.'))
Assert-True "snapshot verification cannot issue stream finality" (
    $contractText.Contains('이 v0.1 계약만으로는 `source_watermark`, `run_closed`, accepted-close, seal 또는 proof를 발급하지 않는다.'))

if ($script:Failures -eq 0) {
    Write-Host "ALL $($script:Total) CHECKS PASSED" -ForegroundColor Green
    exit 0
}
Write-Host "$($script:Failures) of $($script:Total) CHECKS FAILED" -ForegroundColor Red
exit 1

