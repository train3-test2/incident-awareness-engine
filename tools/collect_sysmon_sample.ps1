<#
    .SYNOPSIS
        Collect a Sysmon sample (Event ID 1 / 3) for schema development.

    .DESCRIPTION
        Run inside the experiment VM with Administrator privileges.

        This produces the "Sample based conversion" input described in
        docs/roles/role3-first-cycle.md Phase 2. It is NOT an experiment run:
        no run_id, no RunMetadata, no Ground Truth, no reference_time.

        Actions performed:
            A. plain process create        -> Event ID 1
            B. encoded PowerShell launch   -> Event ID 1 (-EncodedCommand in command line)
            C. loopback TCP connect        -> Event ID 3 (destination is loopback)
            D. external TCP connect        -> Event ID 3 (destination is a global IP, optional)

        By default only loopback is used and no outbound traffic is generated.
        Action D runs only when -ExternalTarget is supplied.

        After collection the script reports whether these Evidence conditions are met.
        Conditions are owned by the Evidence role; this script only checks them.

            encoded_powershell_command
                event_type   = process_create
                image        = powershell / pwsh
                command line = contains -enc or -encodedcommand

            script_interpreter_external_connection
                event_type = network_connection
                image      = powershell / pwsh / cmd / wscript / cscript
                             (the process that made the connection, not its parent)
                dst_ip     = external (global) IP

        NOTE: this file is intentionally ASCII only. Windows PowerShell 5.1 misreads
        UTF-8 source files without a BOM, and a lost BOM corrupts string literals.

    .PARAMETER OutputDir
        Destination folder. Defaults to .\sysmon-sample

    .PARAMETER ExternalTarget
        IPv4 address for the external connection. Empty means skip action D.

    .PARAMETER ExternalPort
        Port for the external connection. Defaults to 443.

    .EXAMPLE
        .\collect_sysmon_sample.ps1

    .EXAMPLE
        .\collect_sysmon_sample.ps1 -ExternalTarget 1.1.1.1
#>

[CmdletBinding()]
param(
    [string]$OutputDir = (Join-Path (Get-Location) "sysmon-sample"),
    [string]$ExternalTarget = "",
    [int]$ExternalPort = 443
)

$ErrorActionPreference = "Stop"
$SYSMON_LOG = "Microsoft-Windows-Sysmon/Operational"

 # Evidence conditions fixed by the Evidence role
$SCRIPT_INTERPRETERS = @("powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe")
$ENCODED_OPTIONS = @("-enc", "-encodedcommand")

function Write-Step {
    param([string]$Message)
    Write-Host "[*] $Message" -ForegroundColor Cyan
}

function Write-Ok {
    param([string]$Message)
    Write-Host "[+] $Message" -ForegroundColor Green
}

function Write-Fail {
    param([string]$Message)
    Write-Host "[!] $Message" -ForegroundColor Red
}

function Test-GlobalIPv4 {
     # Loopback, private, link-local and multicast are not global.
    param([string]$Address)

    $parsed = [System.Net.IPAddress]::Any
    if (-not [System.Net.IPAddress]::TryParse($Address, [ref]$parsed)) {
        return $false
    }
    if ($parsed.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
        return $false
    }

    $octet = $parsed.GetAddressBytes()
    if ($octet[0] -eq 0) { return $false }
    if ($octet[0] -eq 10) { return $false }
    if ($octet[0] -eq 127) { return $false }
    if ($octet[0] -eq 172 -and $octet[1] -ge 16 -and $octet[1] -le 31) { return $false }
    if ($octet[0] -eq 192 -and $octet[1] -eq 168) { return $false }
    if ($octet[0] -eq 169 -and $octet[1] -eq 254) { return $false }
    if ($octet[0] -ge 224) { return $false }

    return $true
}

function Get-ImageFileName {
    param([string]$ImagePath)
    if ([string]::IsNullOrWhiteSpace($ImagePath)) { return "" }
    return (Split-Path $ImagePath -Leaf).ToLower()
}

 # 1. Preflight
Write-Step "Preflight"

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Fail "Administrator privileges required. Reopen PowerShell as Administrator."
    exit 1
}

$sysmonService = Get-Service -Name "Sysmon*" -ErrorAction SilentlyContinue
if (-not $sysmonService) {
    Write-Fail "Sysmon service not found. Install Sysmon first (see samples/raw/README.md)."
    exit 1
}
Write-Ok "Sysmon service: $($sysmonService.Name) / $($sysmonService.Status)"

try {
    Get-WinEvent -LogName $SYSMON_LOG -MaxEvents 1 -ErrorAction Stop | Out-Null
} catch {
    Write-Fail "Cannot read Sysmon log channel: $SYSMON_LOG"
    exit 1
}
Write-Ok "Sysmon log channel is readable"

New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
Write-Ok "Output folder: $OutputDir"

 # 2. Fix the collection start time so earlier events are excluded
$startTime = (Get-Date).AddSeconds(-2)
$startLabel = $startTime.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
Write-Step "Collection start: $startLabel"

 # 3. Action A - plain process create
Write-Step "Action A - plain process create"
$procA = Start-Process -FilePath "powershell.exe" `
    -ArgumentList "-NoProfile", "-NonInteractive", "-Command", "Get-Date | Out-Null" `
    -WindowStyle Hidden -PassThru -Wait
Write-Ok "Action A done (exit=$($procA.ExitCode))"

 # 4. Action B - encoded PowerShell launch
 # -EncodedCommand takes base64 of UTF-16LE
Write-Step "Action B - encoded PowerShell launch"
$innerCommand = "Write-Output 's0-sample-encoded'"
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($innerCommand))
$procB = Start-Process -FilePath "powershell.exe" `
    -ArgumentList "-NoProfile", "-NonInteractive", "-EncodedCommand", $encoded `
    -WindowStyle Hidden -PassThru -Wait
Write-Ok "Action B done (exit=$($procB.ExitCode))"

 # 5. Action C - loopback TCP connect
 # Connects to a port that is already listening locally. No outbound traffic.
Write-Step "Action C - loopback TCP connect"
$listening = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
    Where-Object { $_.LocalAddress -in @("0.0.0.0", "127.0.0.1") -and $_.LocalPort -lt 50000 } |
    Sort-Object LocalPort

$connected = $false
foreach ($endpoint in $listening) {
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $async = $client.BeginConnect("127.0.0.1", $endpoint.LocalPort, $null, $null)
        if ($async.AsyncWaitHandle.WaitOne(1000, $false) -and $client.Connected) {
            $client.EndConnect($async)
            Start-Sleep -Milliseconds 300
            $client.Close()
            Write-Ok "Action C done (127.0.0.1 port $($endpoint.LocalPort))"
            $connected = $true
            break
        }
        $client.Close()
    } catch {
        continue
    }
}

if (-not $connected) {
    Write-Fail "Loopback connect failed. Event ID 3 may not be collected."
}

 # 6. Action D - external TCP connect (optional)
 # script_interpreter_external_connection requires a global destination IP.
 # Loopback and private addresses cannot satisfy that condition.
$externalConnected = $false
if ([string]::IsNullOrWhiteSpace($ExternalTarget)) {
    Write-Step "Action D - skipped (-ExternalTarget not supplied)"
    Write-Host "    script_interpreter_external_connection will NOT be satisfied." -ForegroundColor Yellow
} elseif (-not (Test-GlobalIPv4 $ExternalTarget)) {
    Write-Fail "Action D - $ExternalTarget is not a global IPv4 address. Skipping."
} else {
    $endpointLabel = $ExternalTarget + " port " + $ExternalPort
    Write-Step "Action D - external TCP connect ($endpointLabel)"
    try {
        $extClient = New-Object System.Net.Sockets.TcpClient
        $extAsync = $extClient.BeginConnect($ExternalTarget, $ExternalPort, $null, $null)
        if ($extAsync.AsyncWaitHandle.WaitOne(3000, $false) -and $extClient.Connected) {
            $extClient.EndConnect($extAsync)
            Start-Sleep -Milliseconds 300
            $extClient.Close()
            Write-Ok "Action D done"
            $externalConnected = $true
        } else {
            $extClient.Close()
            Write-Fail "Action D - not connected. Check VM network access."
        }
    } catch {
        Write-Fail "Action D - connect failed: $($_.Exception.Message)"
    }
}

 # 7. Let Sysmon flush
Write-Step "Waiting 5s for Sysmon to flush"
Start-Sleep -Seconds 5

 # 8. Collect events
Write-Step "Collecting events"
$events = @()
try {
    $events = Get-WinEvent -FilterHashtable @{
        LogName   = $SYSMON_LOG
        Id        = @(1, 3)
        StartTime = $startTime
    } -ErrorAction Stop | Sort-Object RecordId
} catch {
    Write-Fail "No Event ID 1/3 in the collection window. Check the Sysmon config."
    exit 1
}

$count1 = ($events | Where-Object { $_.Id -eq 1 }).Count
$count3 = ($events | Where-Object { $_.Id -eq 3 }).Count
Write-Ok "Collected $($events.Count) events (EID 1 = $count1, EID 3 = $count3)"

if ($count1 -eq 0) {
    Write-Fail "Event ID 1 count is 0. ProcessCreate is not being logged."
}
if ($count3 -eq 0) {
    Write-Fail "Event ID 3 count is 0. NetworkConnect is not being logged."
}

 # 9. Check Evidence conditions. This does not create Evidence.
Write-Step "Checking Evidence conditions"
$encodedHits = 0
$externalHits = 0

foreach ($event in $events) {
    $xml = [xml]$event.ToXml()
    $fields = @{}
    foreach ($item in $xml.Event.EventData.Data) {
        $fields[$item.Name] = $item."#text"
    }

    $imageName = Get-ImageFileName $fields["Image"]

    if ($event.Id -eq 1) {
        $commandLine = "$($fields['CommandLine'])".ToLower()
        $isShell = $imageName -in @("powershell.exe", "pwsh.exe")
        $hasOption = $false
        foreach ($option in $ENCODED_OPTIONS) {
            $pattern = "(^|\s)" + [regex]::Escape($option) + "(\s|$)"
            if ($commandLine -match $pattern) {
                $hasOption = $true
                break
            }
        }
        if ($isShell -and $hasOption) { $encodedHits++ }
    }

    if ($event.Id -eq 3) {
        $isInterpreter = $imageName -in $SCRIPT_INTERPRETERS
        if ($isInterpreter -and (Test-GlobalIPv4 $fields["DestinationIp"])) { $externalHits++ }
    }
}

if ($encodedHits -gt 0) {
    Write-Ok "encoded_powershell_command : $encodedHits"
} else {
    Write-Fail "encoded_powershell_command : 0"
}

if ($externalHits -gt 0) {
    Write-Ok "script_interpreter_external_connection : $externalHits"
} else {
    Write-Fail "script_interpreter_external_connection : 0 (no global-IP destination)"
}

 # 10. Convert to JSONL
 # Sysmon native structure is preserved. event_v0 conversion is the Data Platform role.
Write-Step "Writing JSONL"
$lines = New-Object System.Collections.Generic.List[string]

foreach ($event in $events) {
    $xml = [xml]$event.ToXml()
    $eventData = [ordered]@{}
    foreach ($item in $xml.Event.EventData.Data) {
        $eventData[$item.Name] = $item."#text"
    }

    $record = [ordered]@{
        RecordId    = $event.RecordId
        EventId     = $event.Id
        TimeCreated = $event.TimeCreated.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        Channel     = $event.LogName
        Computer    = $event.MachineName
        Provider    = $event.ProviderName
        EventData   = $eventData
    }

    $lines.Add(($record | ConvertTo-Json -Compress -Depth 5))
}

$jsonlPath = Join-Path $OutputDir "sysmon-0001.jsonl"
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllLines($jsonlPath, $lines, $utf8NoBom)
Write-Ok "JSONL written: $jsonlPath"

 # 11. Collection metadata
Write-Step "Writing collection metadata"
$sysmonVersion = "unknown"
$sysmonBinary = Get-Command "Sysmon64.exe", "Sysmon.exe" -ErrorAction SilentlyContinue |
    Select-Object -First 1
if ($sysmonBinary) {
    $sysmonVersion = $sysmonBinary.Version.ToString()
}

$meta = [ordered]@{
    collected_at            = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    collection_start        = $startLabel
    purpose                 = "schema-development-sample"
    sysmon_config_version   = "sysmonconfig-sample-v0.1"
    sysmon_version          = $sysmonVersion
    os_caption              = (Get-CimInstance Win32_OperatingSystem).Caption
    os_version              = [System.Environment]::OSVersion.Version.ToString()
    raw_computer            = $env:COMPUTERNAME
    raw_user                = $env:USERNAME
    event_counts            = [ordered]@{ id_1 = $count1; id_3 = $count3; total = $events.Count }
    external_connection     = [ordered]@{
        requested = -not [string]::IsNullOrWhiteSpace($ExternalTarget)
        succeeded = $externalConnected
        port      = $ExternalPort
    }
    evidence_condition_hits = [ordered]@{
        encoded_powershell_command             = $encodedHits
        script_interpreter_external_connection = $externalHits
    }
}

$metaPath = Join-Path $OutputDir "collection-meta.json"
[System.IO.File]::WriteAllText($metaPath, ($meta | ConvertTo-Json -Depth 5), $utf8NoBom)
Write-Ok "Metadata written: $metaPath"

Write-Host ""
Write-Ok "Done. Copy these two files to the host."
Write-Host "    $jsonlPath"
Write-Host "    $metaPath"
