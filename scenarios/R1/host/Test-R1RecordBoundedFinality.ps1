<#
    Validate a record-bounded Sysmon snapshot on the real R1 Target-A VM.

    This is a diagnostic smoke test. It does not issue a Run/Pair ID, source
    watermark, run_closed, seal, proof, Evidence, or Ground Truth.

    The test captures one all-channel EventRecordID upper bound, derives one
    lower bound from the requested lookback only once, then queries Sysmon
    EID 1/3 twice through the exact closed RecordId range and exports the same
    range to EVTX. All three views must be non-empty, come from the expected
    host and channel, and have the same ordered
    host/channel/RecordId/EventId/raw-XML identities. The raw XML of the two
    bound records and the channel state captured with the upper bound are read
    again after the export, so a clear, rollover or stale channel between the
    capture and the export fails closed. This validates the contract's
    bounded-snapshot premise; it does not prove provider queue drain.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$OutputRoot,
    [Parameter(Mandatory = $true)][string]$ExpectedHost,
    [string]$Channel = "Microsoft-Windows-Sysmon/Operational",
    [int]$LookbackMinutes = 30
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ($LookbackMinutes -lt 1) { throw "LookbackMinutes must be at least 1" }
if ([string]::IsNullOrWhiteSpace($ExpectedHost) -or $ExpectedHost -cne $ExpectedHost.Trim()) {
    throw "ExpectedHost must be a non-empty host name without surrounding whitespace"
}

function Get-Sha256Text {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$Lines)

    $utf8 = New-Object System.Text.UTF8Encoding($false)
    $bytes = $utf8.GetBytes((($Lines -join "`n") + "`n"))
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace("-", "").ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

# One identity line per Event, in the field order of the contract (section 4):
# host_id, source_channel, RecordId, EventId, raw XML SHA-256.
function Get-EventIdentityLines {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Events)

    return @($Events | Sort-Object RecordId | ForEach-Object {
        $xmlSha = Get-Sha256Text -Lines @($_.ToXml())
        "{0}`t{1}`t{2}`t{3}`t{4}" -f [string]$_.MachineName, [string]$_.LogName, ([long]$_.RecordId), ([int]$_.Id), $xmlSha
    })
}

function Test-HostAndChannel {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Events)

    foreach ($item in $Events) {
        if (-not ([string]$item.MachineName -ceq $ExpectedHost)) { return $false }
        if (-not ([string]$item.LogName -ceq $Channel)) { return $false }
    }
    return $true
}

# An empty result is returned as an empty view so that it is recorded as a
# failure; any other query error still stops the test.
function Get-EventsOrEmpty {
    param([Parameter(Mandatory = $true)][scriptblock]$Query)

    try {
        return @(& $Query)
    } catch {
        if ($_.FullyQualifiedErrorId -like "NoMatchingEventsFound*") { return @() }
        throw
    }
}

function Get-ChannelState {
    $info = [System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.GetLogInformation(
        $Channel, [System.Diagnostics.Eventing.Reader.PathType]::LogName)
    # PowerShell unwraps the nullable values of EventLogInformation.
    $created = $null
    if ($null -ne $info.CreationTime) {
        $created = ([DateTime]$info.CreationTime).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    }
    $oldest = $null
    if ($null -ne $info.OldestRecordNumber) { $oldest = [long]$info.OldestRecordNumber }
    return [ordered]@{
        oldest_record_number = $oldest
        creation_time_utc = $created
    }
}

function Get-RecordAnchorDigest {
    param([Parameter(Mandatory = $true)][long]$RecordId)

    $found = @(Get-EventsOrEmpty {
        Get-WinEvent -LogName $Channel -FilterXPath "*[System[EventRecordID=$RecordId]]" `
            -MaxEvents 1 -ErrorAction Stop
    })
    if ($found.Count -ne 1) { return $null }
    return Get-Sha256Text -Lines @($found[0].ToXml())
}

$now = [DateTime]::UtcNow
$start = $now.AddMinutes(-1 * $LookbackMinutes)
$stamp = $now.ToString("yyyyMMddTHHmmssZ")
$runToken = [Guid]::NewGuid().ToString("N")
$resultDir = Join-Path $OutputRoot ("result-{0}-{1}" -f $stamp, $runToken)
New-Item -ItemType Directory -Path $resultDir | Out-Null

$upperEvent = Get-WinEvent -LogName $Channel -MaxEvents 1 -ErrorAction Stop
$upperRecordId = [long]$upperEvent.RecordId
$upperAnchorDigest = Get-Sha256Text -Lines @($upperEvent.ToXml())
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
$lowerAnchorDigest = Get-Sha256Text -Lines @($seed[0].ToXml())
$lowerIdentityLine = @(Get-EventIdentityLines -Events @($seed[0]))[0]
$stateAtCapture = Get-ChannelState
$recordXPath = "*[System[(EventID=1 or EventID=3) and EventRecordID >= $lowerRecordId and EventRecordID <= $upperRecordId]]"

function Read-BoundedTargetEvents {
    return @(Get-EventsOrEmpty {
        Get-WinEvent -LogName $Channel -FilterXPath $recordXPath -ErrorAction Stop
    } | Sort-Object RecordId)
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

$exported = @(Get-EventsOrEmpty {
    Get-WinEvent -Path $evtxPath -ErrorAction Stop
} | Sort-Object RecordId)
$exportedLines = @(Get-EventIdentityLines -Events $exported)

# Read the two bound records and the channel state again after the export.
# A cleared, rolled-over or regenerated channel no longer holds the same raw
# records at the captured RecordIds.
$upperAnchorAfter = Get-RecordAnchorDigest -RecordId $upperRecordId
$lowerAnchorAfter = Get-RecordAnchorDigest -RecordId $lowerRecordId
$stateAfterExport = Get-ChannelState

$firstPath = Join-Path $resultDir "query-first.tsv"
$secondPath = Join-Path $resultDir "query-second.tsv"
$exportedPath = Join-Path $resultDir "exported.tsv"
$firstLines | Set-Content -LiteralPath $firstPath -Encoding UTF8
$secondLines | Set-Content -LiteralPath $secondPath -Encoding UTF8
$exportedLines | Set-Content -LiteralPath $exportedPath -Encoding UTF8

$firstDigest = Get-Sha256Text -Lines $firstLines
$secondDigest = Get-Sha256Text -Lines $secondLines
$exportedDigest = Get-Sha256Text -Lines $exportedLines

$failures = New-Object System.Collections.Generic.List[string]
if ($firstLines.Count -eq 0 -or $secondLines.Count -eq 0 -or $exportedLines.Count -eq 0) {
    $failures.Add("empty_view")
}
if (-not (
    $firstLines.Count -eq $secondLines.Count -and
    $firstLines.Count -eq $exportedLines.Count -and
    $firstDigest -ceq $secondDigest -and
    $firstDigest -ceq $exportedDigest)) {
    $failures.Add("view_mismatch")
}
$hostChannelBound = (
    (Test-HostAndChannel -Events @($upperEvent, $seed[0])) -and
    (Test-HostAndChannel -Events $first) -and
    (Test-HostAndChannel -Events $second) -and
    (Test-HostAndChannel -Events $exported))
if (-not $hostChannelBound) { $failures.Add("host_or_channel_mismatch") }
$lowerAnchorInViews = (
    $firstLines.Count -gt 0 -and $firstLines[0] -ceq $lowerIdentityLine -and
    $secondLines.Count -gt 0 -and $secondLines[0] -ceq $lowerIdentityLine -and
    $exportedLines.Count -gt 0 -and $exportedLines[0] -ceq $lowerIdentityLine)
if (-not $lowerAnchorInViews) { $failures.Add("lower_anchor_not_in_views") }
$anchorsUnchanged = (
    $null -ne $upperAnchorAfter -and $upperAnchorAfter -ceq $upperAnchorDigest -and
    $null -ne $lowerAnchorAfter -and $lowerAnchorAfter -ceq $lowerAnchorDigest -and
    $stateAfterExport.creation_time_utc -ceq $stateAtCapture.creation_time_utc)
if (-not $anchorsUnchanged) { $failures.Add("channel_generation_changed") }
$boundRetained = (
    $null -ne $stateAtCapture.oldest_record_number -and
    $null -ne $stateAfterExport.oldest_record_number -and
    $stateAtCapture.oldest_record_number -le $lowerRecordId -and
    $stateAfterExport.oldest_record_number -le $lowerRecordId -and
    $stateAfterExport.oldest_record_number -ge $stateAtCapture.oldest_record_number)
if (-not $boundRetained) { $failures.Add("bound_not_retained") }
$pass = ($failures.Count -eq 0)

$record = [ordered]@{
    schema = "r1-record-bounded-finality-smoke"
    contract_version = "v0.2"
    diagnostic_only = $true
    host_id = $ExpectedHost
    channel = $Channel
    identity_fields = @("host_id", "source_channel", "RecordId", "EventId", "raw_xml_sha256")
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
    generation = [ordered]@{
        lower_anchor_sha256 = $lowerAnchorDigest
        upper_anchor_sha256 = $upperAnchorDigest
        lower_anchor_after_export_sha256 = $lowerAnchorAfter
        upper_anchor_after_export_sha256 = $upperAnchorAfter
        at_capture = $stateAtCapture
        after_export = $stateAfterExport
        lower_anchor_in_views = $lowerAnchorInViews
        anchors_unchanged = $anchorsUnchanged
        bound_retained = $boundRetained
    }
    host_channel_bound = $hostChannelBound
    failures = @($failures)
    exact_match = $pass
    issued_finality = $false
    limitation = "The result proves equality inside one non-empty EventRecordID-bounded snapshot of the expected host and channel, bound to the channel generation captured with the upper bound; it does not prove provider queue drain or raw-source completeness."
}
$recordPath = Join-Path $resultDir "record-bounded-finality-smoke.json"
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[IO.File]::WriteAllText($recordPath, (($record | ConvertTo-Json -Depth 8) + "`n"), $utf8NoBom)

$inventory = @(Get-ChildItem -LiteralPath $resultDir -File | Sort-Object Name | ForEach-Object {
    "{0}`t{1}`t{2}" -f $_.Name, $_.Length, (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
})
[IO.File]::WriteAllText((Join-Path $resultDir "SHA256SUMS.tsv"), (($inventory -join "`n") + "`n"), $utf8NoBom)

if (-not $pass) {
    Write-Host ("FAIL bounded snapshot: {0}" -f ($failures -join ", ")) -ForegroundColor Red
    Write-Host "RESULT $recordPath"
    exit 1
}

Write-Host "PASS bounded snapshot exact match" -ForegroundColor Green
Write-Host ("host={0} upper_record_id={1} events={2} identity_sha256={3}" -f `
        $ExpectedHost, $upperRecordId, $firstLines.Count, $firstDigest)
Write-Host "No watermark/run_closed/seal/proof was issued."
Write-Host "RESULT $recordPath"
