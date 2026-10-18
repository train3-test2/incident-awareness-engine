<#
    Validate a record-bounded Sysmon snapshot on the real R1 Target-A VM.

    This is a diagnostic smoke test. It does not issue a Run/Pair ID, source
    watermark, run_closed, seal, proof, Evidence, or Ground Truth.

    The test captures one all-channel EventRecordID upper bound, derives one
    lower bound from the requested lookback only once, then queries Sysmon
    EID 1/3 twice through the exact closed RecordId range and exports the same
    range to EVTX. All three views must have the same ordered
    RecordId/EventId/raw-XML identities. This validates the contract's
    bounded-snapshot premise; it does not prove provider queue drain.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$OutputRoot,
    [string]$Channel = "Microsoft-Windows-Sysmon/Operational",
    [int]$LookbackMinutes = 30
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ($LookbackMinutes -lt 1) { throw "LookbackMinutes must be at least 1" }

function Get-Sha256Text {
    param([Parameter(Mandatory = $true)][string[]]$Lines)

    $utf8 = New-Object System.Text.UTF8Encoding($false)
    $bytes = $utf8.GetBytes((($Lines -join "`n") + "`n"))
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace("-", "").ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

function Get-EventIdentityLines {
    param([Parameter(Mandatory = $true)][object[]]$Events)

    return @($Events | Sort-Object RecordId | ForEach-Object {
        $xmlSha = Get-Sha256Text -Lines @($_.ToXml())
        "{0}`t{1}`t{2}" -f ([long]$_.RecordId), ([int]$_.Id), $xmlSha
    })
}

$now = [DateTime]::UtcNow
$start = $now.AddMinutes(-1 * $LookbackMinutes)
$stamp = $now.ToString("yyyyMMddTHHmmssZ")
$runToken = [Guid]::NewGuid().ToString("N")
$resultDir = Join-Path $OutputRoot ("result-{0}-{1}" -f $stamp, $runToken)
New-Item -ItemType Directory -Path $resultDir | Out-Null

$upperEvent = Get-WinEvent -LogName $Channel -MaxEvents 1 -ErrorAction Stop
$upperRecordId = [long]$upperEvent.RecordId
$capturedAt = [DateTime]::UtcNow

# Time is used only once to choose a practical lower RecordId. Every compared
# view below uses the same closed RecordId interval.
$seed = @(Get-WinEvent -FilterHashtable @{
    LogName = $Channel
    Id = @(1, 3)
    StartTime = $start
} -ErrorAction Stop | Where-Object {
    [long]$_.RecordId -le $upperRecordId
} | Sort-Object RecordId)
if ($seed.Count -eq 0) {
    throw "the lookback contains no Sysmon EID 1/3 record through the captured upper bound"
}
$lowerRecordId = [long]$seed[0].RecordId
$recordXPath = "*[System[(EventID=1 or EventID=3) and EventRecordID >= $lowerRecordId and EventRecordID <= $upperRecordId]]"

function Read-BoundedTargetEvents {
    return @(Get-WinEvent -LogName $Channel -FilterXPath $recordXPath `
        -ErrorAction Stop | Sort-Object RecordId)
}

$first = @(Read-BoundedTargetEvents)
$second = @(Read-BoundedTargetEvents)
$firstLines = @(Get-EventIdentityLines -Events $first)
$secondLines = @(Get-EventIdentityLines -Events $second)

$evtxPath = Join-Path $resultDir "sysmon-record-bounded.evtx"
& wevtutil epl $Channel $evtxPath "/q:$recordXPath" /ow:true | Out-Null
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $evtxPath)) {
    throw "wevtutil bounded export failed"
}

$exported = @(Get-WinEvent -Path $evtxPath -ErrorAction Stop | Sort-Object RecordId)
$exportedLines = @(Get-EventIdentityLines -Events $exported)

$firstPath = Join-Path $resultDir "query-first.tsv"
$secondPath = Join-Path $resultDir "query-second.tsv"
$exportedPath = Join-Path $resultDir "exported.tsv"
$firstLines | Set-Content -LiteralPath $firstPath -Encoding UTF8
$secondLines | Set-Content -LiteralPath $secondPath -Encoding UTF8
$exportedLines | Set-Content -LiteralPath $exportedPath -Encoding UTF8

$firstDigest = Get-Sha256Text -Lines $firstLines
$secondDigest = Get-Sha256Text -Lines $secondLines
$exportedDigest = Get-Sha256Text -Lines $exportedLines
$pass = (
    $firstLines.Count -eq $secondLines.Count -and
    $firstLines.Count -eq $exportedLines.Count -and
    $firstDigest -ceq $secondDigest -and
    $firstDigest -ceq $exportedDigest
)

$record = [ordered]@{
    schema = "r1-record-bounded-finality-smoke"
    contract_version = "v0.1"
    diagnostic_only = $true
    channel = $Channel
    captured_at_utc = $capturedAt.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    query_start_utc = $start.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    source_lower_record_id = $lowerRecordId
    source_upper_record_id = $upperRecordId
    event_ids = @(1, 3)
    first = [ordered]@{ count = $firstLines.Count; identity_sha256 = $firstDigest }
    second = [ordered]@{ count = $secondLines.Count; identity_sha256 = $secondDigest }
    export = [ordered]@{
        count = $exportedLines.Count
        identity_sha256 = $exportedDigest
        evtx_sha256 = (Get-FileHash -LiteralPath $evtxPath -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    exact_match = $pass
    issued_finality = $false
    limitation = "The result proves equality inside one immutable EventRecordID-bounded snapshot; it does not prove provider queue drain or raw-source completeness."
}
$recordPath = Join-Path $resultDir "record-bounded-finality-smoke.json"
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[IO.File]::WriteAllText($recordPath, (($record | ConvertTo-Json -Depth 8) + "`n"), $utf8NoBom)

$inventory = @(Get-ChildItem -LiteralPath $resultDir -File | Sort-Object Name | ForEach-Object {
    "{0}`t{1}`t{2}" -f $_.Name, $_.Length, (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
})
[IO.File]::WriteAllText((Join-Path $resultDir "SHA256SUMS.tsv"), (($inventory -join "`n") + "`n"), $utf8NoBom)

if (-not $pass) {
    Write-Host "FAIL bounded snapshot mismatch" -ForegroundColor Red
    Write-Host "RESULT $recordPath"
    exit 1
}

Write-Host "PASS bounded snapshot exact match" -ForegroundColor Green
Write-Host ("upper_record_id={0} events={1} identity_sha256={2}" -f `
        $upperRecordId, $firstLines.Count, $firstDigest)
Write-Host "No watermark/run_closed/seal/proof was issued."
Write-Host "RESULT $recordPath"

