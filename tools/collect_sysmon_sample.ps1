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

        Output formats:
            JSONL  normalization input for the Data Platform role
            EVTX   native format required by Hayabusa and other EVTX-only tools

        EVTX cannot be sanitized. It is a binary format, so the text replacement used
        for the JSONL sample does not apply. Collect it on a VM whose computer and
        account names are already non-identifying, and do not commit it to the repo.

        NOTE: this file is intentionally ASCII only. Windows PowerShell 5.1 misreads
        UTF-8 source files without a BOM, and a lost BOM corrupts string literals.

    .PARAMETER OutputDir
        Destination folder. Defaults to .\sysmon-sample

    .PARAMETER ExternalTarget
        IPv4 address for the external connection. Empty means skip action D.

    .PARAMETER ExternalPort
        Port for the external connection. Defaults to 443.

    .PARAMETER SysmonConfigPath
        Path to the Sysmon configuration applied to this VM. When supplied the
        script records its SHA-256 so the metadata reflects the configuration that
        was actually used instead of a hardcoded label.

    .PARAMETER IncludeSecurityLog
        Also export the Windows Security channel as EVTX and report how many
        1102 / 4624 / 5140 records the collection window contains. Use this when the
        Detection role needs Security-channel records for false positive checks.

    .PARAMETER SkipEvtx
        Skip the EVTX export and produce JSONL only.

    .EXAMPLE
        .\collect_sysmon_sample.ps1

    .EXAMPLE
        .\collect_sysmon_sample.ps1 -ExternalTarget 1.1.1.1 -SysmonConfigPath C:\Tools\sysmonconfig-sample-v0.1.xml

    .EXAMPLE
        .\collect_sysmon_sample.ps1 -IncludeSecurityLog
#>

[CmdletBinding()]
param(
    [string]$OutputDir = (Join-Path (Get-Location) "sysmon-sample"),
    [string]$ExternalTarget = "",
    [int]$ExternalPort = 443,
    [string]$SysmonConfigPath = "",
    [switch]$IncludeSecurityLog,
    [switch]$SkipEvtx
)

$ErrorActionPreference = "Stop"
$SYSMON_LOG = "Microsoft-Windows-Sysmon/Operational"
$SECURITY_LOG = "Security"

 # Security channel IDs the Detection role checks for false positives
$SECURITY_IDS_OF_INTEREST = @(1102, 4624, 5140)

 # Slack absorbed by the EVTX time window. See the export step for why it is small.
$EVTX_WINDOW_MARGIN_MS = 10000

 # Evidence conditions fixed by the Evidence role.
 #
 # This script reimplements them to check whether a collected sample can satisfy
 # them. It is NOT the authority on Evidence; the Evidence extractor owns that.
 # Record which condition set was mirrored so later drift is visible.
$SCRIPT_INTERPRETERS = @("powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe")
$ENCODED_OPTIONS = @("-enc", "-encodedcommand")
$EVIDENCE_CONDITION_SOURCE = "configs/evidence_types_v0.2.yaml"

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
    <#
        Returns true only for globally reachable IPv4 addresses.
        Special-purpose ranges from the IANA IPv4 Special-Purpose Address Registry
        are rejected, including documentation and benchmarking blocks that are
        otherwise easy to mistake for public addresses.
    #>
    param([string]$Address)

    $parsed = [System.Net.IPAddress]::Any
    if (-not [System.Net.IPAddress]::TryParse($Address, [ref]$parsed)) {
        return $false
    }
    if ($parsed.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
        return $false
    }

    $octet = $parsed.GetAddressBytes()

     # 192.0.0.9 and 192.0.0.10 are the only globally reachable hosts in 192.0.0.0/24
    if ($octet[0] -eq 192 -and $octet[1] -eq 0 -and $octet[2] -eq 0) {
        return ($octet[3] -eq 9 -or $octet[3] -eq 10)
    }

     # 0.0.0.0/8, 10.0.0.0/8, 127.0.0.0/8
    if ($octet[0] -eq 0) { return $false }
    if ($octet[0] -eq 10) { return $false }
    if ($octet[0] -eq 127) { return $false }

     # 100.64.0.0/10 carrier-grade NAT
    if ($octet[0] -eq 100 -and $octet[1] -ge 64 -and $octet[1] -le 127) { return $false }

     # 169.254.0.0/16 link-local
    if ($octet[0] -eq 169 -and $octet[1] -eq 254) { return $false }

     # 172.16.0.0/12 private
    if ($octet[0] -eq 172 -and $octet[1] -ge 16 -and $octet[1] -le 31) { return $false }

     # 192.0.2.0/24 TEST-NET-1
    if ($octet[0] -eq 192 -and $octet[1] -eq 0 -and $octet[2] -eq 2) { return $false }

     # 192.88.99.0/24 deprecated 6to4 relay anycast
    if ($octet[0] -eq 192 -and $octet[1] -eq 88 -and $octet[2] -eq 99) { return $false }

     # 192.168.0.0/16 private
    if ($octet[0] -eq 192 -and $octet[1] -eq 168) { return $false }

     # 198.18.0.0/15 benchmarking
    if ($octet[0] -eq 198 -and ($octet[1] -eq 18 -or $octet[1] -eq 19)) { return $false }

     # 198.51.100.0/24 TEST-NET-2
    if ($octet[0] -eq 198 -and $octet[1] -eq 51 -and $octet[2] -eq 100) { return $false }

     # 203.0.113.0/24 TEST-NET-3
    if ($octet[0] -eq 203 -and $octet[1] -eq 0 -and $octet[2] -eq 113) { return $false }

     # 224.0.0.0/4 multicast and 240.0.0.0/4 reserved
    if ($octet[0] -ge 224) { return $false }

    return $true
}

function Get-ImageFileName {
    param([string]$ImagePath)
    if ([string]::IsNullOrWhiteSpace($ImagePath)) { return "" }
    return (Split-Path $ImagePath -Leaf).ToLower()
}

function Export-ChannelEvtx {
    <#
        Export one channel to EVTX, limited to the collection window.

        The window is expressed with the event log timediff() XPath function rather
        than a literal timestamp comparison. XPath 1.0 compares strings numerically
        with >=, so comparing @SystemTime against an ISO 8601 string does not work.
    #>
    param(
        [string]$Channel,
        [string]$DestinationPath,
        [int]$WindowMilliseconds,
        [int[]]$EventIds = @()
    )

    $timeClause = "TimeCreated[timediff(@SystemTime) <= $WindowMilliseconds]"
    if ($EventIds.Count -gt 0) {
        $idClause = ($EventIds | ForEach-Object { "EventID=$_" }) -join " or "
        $query = "*[System[($idClause) and $timeClause]]"
    } else {
        $query = "*[System[$timeClause]]"
    }

    if (Test-Path $DestinationPath) {
        Remove-Item $DestinationPath -Force
    }

     # Do not redirect stderr. In Windows PowerShell 5.1 "2>&1" on a native command
     # wraps stderr lines in ErrorRecord objects, which raises NativeCommandError
     # under $ErrorActionPreference = "Stop" before the exit code can be inspected.
    & wevtutil epl $Channel $DestinationPath "/q:$query" /ow:true | Out-Null
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $DestinationPath)) {
        return $null
    }

    return $DestinationPath
}

function Get-Sha256 {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return $null }
    return (Get-FileHash -Path $Path -Algorithm SHA256).Hash.ToLower()
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

 # Required checks are accumulated and reported at the end.
 # Output files are still written so a failed run can be diagnosed, but the
 # script exits non-zero so the sample is never mistaken for a valid one.
$failures = New-Object System.Collections.Generic.List[string]

if ($count1 -eq 0) {
    Write-Fail "Event ID 1 count is 0. ProcessCreate is not being logged."
    $failures.Add("event_id_1_missing")
}
if ($count3 -eq 0) {
    Write-Fail "Event ID 3 count is 0. NetworkConnect is not being logged."
    $failures.Add("event_id_3_missing")
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
    $failures.Add("encoded_powershell_command_missing")
}

 # This condition needs a global destination IP, so it is only required when
 # an external target was requested.
$externalRequested = -not [string]::IsNullOrWhiteSpace($ExternalTarget)
if ($externalHits -gt 0) {
    Write-Ok "script_interpreter_external_connection : $externalHits"
} elseif ($externalRequested) {
    Write-Fail "script_interpreter_external_connection : 0 (no global-IP destination)"
    $failures.Add("script_interpreter_external_connection_missing")
} else {
    Write-Host "[-] script_interpreter_external_connection : 0 (-ExternalTarget not supplied)" `
        -ForegroundColor Yellow
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

 # 10-1. Export EVTX
 # Hayabusa and other detection tools read EVTX, not JSONL.
$artifacts = New-Object System.Collections.Generic.List[object]
$artifacts.Add([ordered]@{
    file    = "sysmon-0001.jsonl"
    kind    = "jsonl"
    channel = $SYSMON_LOG
    sha256  = (Get-Sha256 $jsonlPath)
})

$securityCounts = $null
$fileShareAudit = $null

if ($SkipEvtx) {
    Write-Step "EVTX export skipped (-SkipEvtx)"
} else {
    Write-Step "Exporting EVTX"

     # timediff() measures backwards from the moment the query runs, so any margin
     # reaches further into the past and pulls in events from before the collection
     # started. Keep it small: it only has to absorb the delay between computing the
     # window here and wevtutil evaluating it.
    $windowMs = [int]((Get-Date) - $startTime).TotalMilliseconds + $EVTX_WINDOW_MARGIN_MS

    $sysmonEvtx = Join-Path $OutputDir "sysmon-0001.evtx"
    $exported = Export-ChannelEvtx -Channel $SYSMON_LOG -DestinationPath $sysmonEvtx `
        -WindowMilliseconds $windowMs -EventIds @(1, 3)

    if ($exported) {
        $evtxCount = @(Get-WinEvent -Path $sysmonEvtx -ErrorAction SilentlyContinue).Count
        Write-Ok "Sysmon EVTX written: $sysmonEvtx ($evtxCount events)"
        $artifacts.Add([ordered]@{
            file    = "sysmon-0001.evtx"
            kind    = "evtx"
            channel = $SYSMON_LOG
            events  = $evtxCount
            sha256  = (Get-Sha256 $sysmonEvtx)
        })
        if ($evtxCount -ne $events.Count) {
            Write-Host "[-] EVTX has $evtxCount events, JSONL has $($events.Count)." `
                -ForegroundColor Yellow
            Write-Host "    EVTX reaches $EVTX_WINDOW_MARGIN_MS ms further back than the JSONL filter." `
                -ForegroundColor Yellow
            Write-Host "    A small difference is expected; a large one means the margin is wrong." `
                -ForegroundColor Yellow
        }
    } else {
        Write-Fail "Sysmon EVTX export failed."
        $failures.Add("sysmon_evtx_export_failed")
    }

    if ($IncludeSecurityLog) {
        $securityEvtx = Join-Path $OutputDir "security-0001.evtx"
        $exportedSecurity = Export-ChannelEvtx -Channel $SECURITY_LOG `
            -DestinationPath $securityEvtx -WindowMilliseconds $windowMs

        if ($exportedSecurity) {
            $securityEvents = @(Get-WinEvent -Path $securityEvtx -ErrorAction SilentlyContinue)
            Write-Ok "Security EVTX written: $securityEvtx ($($securityEvents.Count) events)"

            $securityCounts = [ordered]@{}
            foreach ($id in $SECURITY_IDS_OF_INTEREST) {
                $hits = @($securityEvents | Where-Object { $_.Id -eq $id }).Count
                $securityCounts["id_$id"] = $hits
                Write-Host "    EventID $id : $hits"
            }

            $artifacts.Add([ordered]@{
                file    = "security-0001.evtx"
                kind    = "evtx"
                channel = $SECURITY_LOG
                events  = $securityEvents.Count
                sha256  = (Get-Sha256 $securityEvtx)
            })

             # 5140 needs the File Share audit subcategory, which is off by default.
             # Record the policy so a zero count is not mistaken for a clean result.
             #
             # The whole policy is saved as CSV because the subcategory display name is
             # localized, so matching it by name fails on a non-English Windows.
            try {
                $auditCsvPath = Join-Path $OutputDir "auditpol.csv"
                $auditRows = & auditpol /get /category:* /r
                if ($LASTEXITCODE -eq 0 -and $auditRows) {
                    [System.IO.File]::WriteAllLines($auditCsvPath, $auditRows, $utf8NoBom)
                    Write-Ok "Audit policy written: $auditCsvPath"
                    $artifacts.Add([ordered]@{
                        file    = "auditpol.csv"
                        kind    = "csv"
                        channel = "audit-policy"
                        sha256  = (Get-Sha256 $auditCsvPath)
                    })

                     # Documented GUID of the File Share subcategory. The script does not
                     # depend on it: when the lookup misses, the full CSV is still saved.
                    $fileShareGuid = "{0CCE9224-69AE-11D9-BED3-505054503030}"
                    $row = $auditRows | Where-Object { $_ -like "*$fileShareGuid*" } |
                        Select-Object -First 1
                    if ($row) {
                        $fields = $row -split ","
                        if ($fields.Count -ge 5) {
                            $fileShareAudit = $fields[4].Trim()
                            Write-Host "    File Share audit policy : $fileShareAudit"
                        }
                    } else {
                        Write-Host "    File Share row not matched; see auditpol.csv" `
                            -ForegroundColor Yellow
                    }
                } else {
                    Write-Host "[-] auditpol returned $LASTEXITCODE; audit policy not saved." `
                        -ForegroundColor Yellow
                }
            } catch {
                Write-Host "[-] Could not read the audit policy: $($_.Exception.Message)" `
                    -ForegroundColor Yellow
            }
        } else {
            Write-Fail "Security EVTX export failed."
            $failures.Add("security_evtx_export_failed")
        }
    }
}

 # 11. Collection metadata
Write-Step "Writing collection metadata"
$sysmonVersion = "unknown"
$sysmonBinary = Get-Command "Sysmon64.exe", "Sysmon.exe" -ErrorAction SilentlyContinue |
    Select-Object -First 1
if ($sysmonBinary) {
    $sysmonVersion = $sysmonBinary.Version.ToString()
}

 # Record what the configuration actually was instead of a fixed label.
 # The file hash identifies the configuration that was handed to Sysmon; the
 # active hash is taken from the running service and is the authoritative one.
$configVersion = "unspecified"
$configSha256 = $null
$activeConfigSha256 = $null

if (-not [string]::IsNullOrWhiteSpace($SysmonConfigPath)) {
    if (Test-Path $SysmonConfigPath) {
        $configVersion = [System.IO.Path]::GetFileNameWithoutExtension($SysmonConfigPath)
        $configSha256 = (Get-FileHash -Path $SysmonConfigPath -Algorithm SHA256).Hash.ToLower()
    } else {
        Write-Fail "SysmonConfigPath not found: $SysmonConfigPath"
        $failures.Add("sysmon_config_path_missing")
    }
} else {
    Write-Host "[-] -SysmonConfigPath not supplied; config identity is unverified." -ForegroundColor Yellow
}

if ($sysmonBinary) {
    try {
        $activeConfig = & $sysmonBinary.Source -c | Out-String
        if (-not [string]::IsNullOrWhiteSpace($activeConfig)) {
            $stream = New-Object System.IO.MemoryStream(
                , [System.Text.Encoding]::UTF8.GetBytes($activeConfig))
            $activeConfigSha256 = (Get-FileHash -InputStream $stream -Algorithm SHA256).Hash.ToLower()
            $stream.Dispose()
        }
    } catch {
        Write-Host "[-] Could not read the active Sysmon configuration." -ForegroundColor Yellow
    }
}

$meta = [ordered]@{
    collected_at                = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    collection_start            = $startLabel
    purpose                     = "schema-development-sample"
    sysmon_config_version       = $configVersion
    sysmon_config_sha256        = $configSha256
    sysmon_active_config_sha256 = $activeConfigSha256
    sysmon_version              = $sysmonVersion
    os_caption                  = (Get-CimInstance Win32_OperatingSystem).Caption
    os_version                  = [System.Environment]::OSVersion.Version.ToString()
    raw_computer                = $env:COMPUTERNAME
    raw_user                    = $env:USERNAME
    event_counts                = [ordered]@{
        id_1  = $count1
        id_3  = $count3
        total = $events.Count
    }
    external_connection         = [ordered]@{
        requested = $externalRequested
        succeeded = $externalConnected
        port      = $ExternalPort
    }
    evidence_condition_hits     = [ordered]@{
        encoded_powershell_command             = $encodedHits
        script_interpreter_external_connection = $externalHits
    }
    evidence_condition_check    = [ordered]@{
        conditions_from = $EVIDENCE_CONDITION_SOURCE
        implemented_in  = "tools/collect_sysmon_sample.ps1"
        authoritative   = $false
        note            = "collection sanity check; the Evidence extractor decides Evidence"
    }
     # Assign the lists directly. In Windows PowerShell 5.1 an [ordered] literal
     # throws "Argument types do not match" when a value is @(<List of IDictionary>).
    artifacts                   = $artifacts
    security_log                = [ordered]@{
        included         = [bool]$IncludeSecurityLog
        event_counts     = $securityCounts
        file_share_audit = $fileShareAudit
    }
    validation_failures         = $failures
}

$metaPath = Join-Path $OutputDir "collection-meta.json"
[System.IO.File]::WriteAllText($metaPath, ($meta | ConvertTo-Json -Depth 5), $utf8NoBom)
Write-Ok "Metadata written: $metaPath"

Write-Host ""
if ($failures.Count -gt 0) {
    Write-Fail "Required checks failed: $($failures -join ', ')"
    Write-Host "    Output was still written so the run can be diagnosed."
    Write-Host "    Do not publish this sample until the checks pass."
    Write-Host "    $OutputDir"
    exit 1
}

Write-Ok "Done. Copy this folder to the host: $OutputDir"
foreach ($artifact in $artifacts) {
    Write-Host "    $($artifact.file)  [$($artifact.kind)]"
}
Write-Host "    collection-meta.json"

if (-not $SkipEvtx) {
    Write-Host ""
    Write-Host "EVTX carries the real computer and account names and cannot be sanitized." `
        -ForegroundColor Yellow
    Write-Host "Share it only if those names are already non-identifying." `
        -ForegroundColor Yellow
}
