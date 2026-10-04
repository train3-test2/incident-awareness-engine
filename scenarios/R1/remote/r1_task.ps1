<#
    .SYNOPSIS
        The harmless task the R1 final management tool runs on Target-A.

    .DESCRIPTION
        The R1 Pilot starts this file with the final management tool in both
        runs, so the final process and what it does are the same whichever
        intermediate process started it (docs/scenarios/r1.md section 4-1).

        Started with -ChannelDir it

          1. writes r1_task_ready.json with its own process id,
          2. waits for r1_conn_trigger in the channel directory,
          3. makes at most one TCP connection, with no payload, to the internal
             destination named in r1_conn_config.json, and
          4. writes r1_conn_status.json and exits.

        It reads only values from the config: an address, a port, a protocol, an
        attempt count, a timeout and the lab network. It never reads a command
        from the channel and never uses Invoke-Expression.

        Dot-sourced without -ChannelDir it only defines its functions. The
        Controller side gate (scenarios/R1/run-common.ps1) and the guard tests
        load it that way, so the destination rule has one implementation.

        The destination must be an RFC 1918 address inside the lab network handed
        to the run. Anything else, a globally routable address included, is
        refused before a socket exists.

        NOTE: this file is intentionally ASCII only. Windows PowerShell 5.1
        misreads UTF-8 source files without a BOM, and a lost BOM corrupts
        string literals.
#>

param([string]$ChannelDir)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$R1_READY_FILE = "r1_task_ready.json"
$R1_CONFIG_FILE = "r1_conn_config.json"
$R1_TRIGGER_FILE = "r1_conn_trigger"
$R1_STATUS_FILE = "r1_conn_status.json"

function Get-R1UtcStamp {
    <# UTC ISO 8601 with milliseconds. "fff" truncates, it does not round. #>
    param([datetime]$Value)
    return $Value.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
}

function ConvertTo-R1IPv4Number {
    <#
        A canonical dotted IPv4 literal as a number, or $null for anything else.

        TryParse accepts "10.1" and other shortened forms, so the value has to
        round-trip to the same four octets. A hostname, an IPv6 literal and a
        value with surrounding whitespace are refused.
    #>
    param([AllowNull()][AllowEmptyString()][string]$Address)

    if ([string]::IsNullOrEmpty($Address)) { return $null }
    if ($Address -ne $Address.Trim()) { return $null }
    if ($Address.Contains(":")) { return $null }

    $parsed = [System.Net.IPAddress]::Any
    if (-not [System.Net.IPAddress]::TryParse($Address, [ref]$parsed)) { return $null }
    if ($parsed.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { return $null }
    if ($parsed.ToString() -ne $Address) { return $null }

    $octet = $parsed.GetAddressBytes()
    return (([long]$octet[0] * 16777216) + ([long]$octet[1] * 65536) +
        ([long]$octet[2] * 256) + [long]$octet[3])
}

function Get-R1PrivateBlock {
    <# The RFC 1918 block a number falls in, as its first and last number, or $null. #>
    param([Parameter(Mandatory = $true)][long]$Number)

    $blocks = @(
        @{ first = [long]167772160; last = [long]184549375 },      # 10.0.0.0/8
        @{ first = [long]2886729728; last = [long]2887778303 },    # 172.16.0.0/12
        @{ first = [long]3232235520; last = [long]3232301055 }     # 192.168.0.0/16
    )
    foreach ($block in $blocks) {
        if ($Number -ge $block.first -and $Number -le $block.last) { return $block }
    }

    return $null
}

function ConvertTo-R1LabNetwork {
    <#
        Parse the lab network "a.b.c.d/n".

        The network address has to be canonical (no host bits), the prefix has to
        be 8..30 and the whole range has to sit inside one RFC 1918 block, so a
        lab network can never reach a globally routable address.

        Returns ok, the first and last number of the range and a reason when the
        value is refused.
    #>
    param([AllowNull()][AllowEmptyString()][string]$LabCidr)

    $refused = [ordered]@{ ok = $false; first = $null; last = $null; reason = "lab_network_invalid" }
    if ([string]::IsNullOrEmpty($LabCidr)) { return $refused }

    $parts = $LabCidr.Split("/")
    if ($parts.Count -ne 2) { return $refused }
    if ($parts[1] -notmatch '^[0-9]{1,2}$') { return $refused }

    $prefix = [int]$parts[1]
    if ($prefix -lt 8 -or $prefix -gt 30) { return $refused }

    $first = ConvertTo-R1IPv4Number $parts[0]
    if ($null -eq $first) { return $refused }

    $size = [long][Math]::Pow(2, 32 - $prefix)
    if (($first % $size) -ne 0) { return $refused }

    $last = $first + $size - 1
    $block = Get-R1PrivateBlock -Number $first
    if ($null -eq $block -or $last -gt $block.last) {
        return [ordered]@{ ok = $false; first = $null; last = $null; reason = "lab_network_not_private" }
    }

    return [ordered]@{ ok = $true; first = $first; last = $last; reason = $null }
}

function Test-R1InternalDestination {
    <#
        Decide whether an address may be the destination of the internal
        connection.

        It must be a canonical IPv4 literal, an RFC 1918 address, and a host
        address inside the lab network (not its network or broadcast address).
        Returns ok and, when refused, the reason the task status records.
    #>
    param(
        [AllowNull()][AllowEmptyString()][string]$Address,
        [AllowNull()][AllowEmptyString()][string]$LabCidr
    )

    $number = ConvertTo-R1IPv4Number $Address
    if ($null -eq $number) { return [ordered]@{ ok = $false; reason = "target_not_ipv4" } }

    if ($null -eq (Get-R1PrivateBlock -Number $number)) {
        return [ordered]@{ ok = $false; reason = "target_not_private" }
    }

    $network = ConvertTo-R1LabNetwork $LabCidr
    if (-not $network.ok) { return [ordered]@{ ok = $false; reason = [string]$network.reason } }

    if ($number -lt $network.first -or $number -gt $network.last) {
        return [ordered]@{ ok = $false; reason = "target_outside_lab_network" }
    }
    if ($number -eq $network.first -or $number -eq $network.last) {
        return [ordered]@{ ok = $false; reason = "target_not_a_host_address" }
    }

    return [ordered]@{ ok = $true; reason = $null }
}

function Invoke-R1InternalTcpAttempt {
    <#
        The destination gate followed by at most one TCP connect.

        The Controller already checked the destination before it opened a
        session. This runs inside the final tool's own process immediately before
        a socket would exist, so a config that was changed on the way still
        cannot reach anything but an internal address.

        NowUtcProvider and ClientFactory are the only seams: production uses the
        real clock and a real TcpClient, and the tests pass a fake clock and a
        fake client factory so no socket is ever created. There is no way to
        skip the gate. On any refusal no client is created and attempts_made
        stays 0.
    #>
    param(
        [Parameter(Mandatory = $true)]$Config,
        [scriptblock]$NowUtcProvider = { (Get-Date).ToUniversalTime() },
        [scriptblock]$ClientFactory = { New-Object System.Net.Sockets.TcpClient }
    )

    $target = [string]$Config.target
    $protocol = ([string]$Config.protocol).ToUpper()
    $port = 0
    $attempts = 0
    $timeoutMs = 0

    $checkedUtc = (& $NowUtcProvider).ToUniversalTime()

    $refusal = $null
    $destination = Test-R1InternalDestination -Address $target -LabCidr ([string]$Config.lab_cidr)
    if (-not $destination.ok) {
        $refusal = [string]$destination.reason
    } elseif (-not [int]::TryParse([string]$Config.port, [ref]$port) -or
        $port -lt 1 -or $port -gt 65535) {
        $refusal = "port_not_valid"
    } elseif ($protocol -ne "TCP") {
        $refusal = "protocol_not_tcp"
    } elseif (-not [int]::TryParse([string]$Config.max_attempts, [ref]$attempts) -or $attempts -ne 1) {
        $refusal = "attempts_not_one"
    } elseif (-not [int]::TryParse([string]$Config.timeout_ms, [ref]$timeoutMs) -or
        $timeoutMs -lt 1 -or $timeoutMs -gt 60000) {
        $refusal = "timeout_not_valid"
    }

    if ($null -ne $refusal) {
        # No socket object is created on this path.
        return [ordered]@{
            pid           = $PID
            target        = $target
            port          = [string]$Config.port
            protocol      = $protocol
            checked_utc   = (Get-R1UtcStamp $checkedUtc)
            started_utc   = $null
            ended_utc     = $null
            success       = $false
            skipped       = $false
            timed_out     = $false
            error_kind    = $refusal
            attempts_made = 0
        }
    }

    $startedUtc = (& $NowUtcProvider).ToUniversalTime()
    $success = $false
    $timedOut = $false
    $errorKind = $null
    $client = $null
    try {
        $client = & $ClientFactory
        $async = $client.BeginConnect($target, $port, $null, $null)
        if ($async.AsyncWaitHandle.WaitOne($timeoutMs, $false) -and $client.Connected) {
            $client.EndConnect($async)
            $success = $true
        } else {
            $timedOut = $true
            $errorKind = "timeout"
        }
    } catch {
        $errorKind = $_.Exception.GetType().Name
    } finally {
        if ($null -ne $client) { $client.Close() }
    }
    $endedUtc = (& $NowUtcProvider).ToUniversalTime()

    return [ordered]@{
        pid           = $PID
        target        = $target
        port          = [string]$port
        protocol      = $protocol
        checked_utc   = (Get-R1UtcStamp $checkedUtc)
        started_utc   = (Get-R1UtcStamp $startedUtc)
        ended_utc     = (Get-R1UtcStamp $endedUtc)
        success       = $success
        skipped       = $false
        timed_out     = $timedOut
        error_kind    = $errorKind
        attempts_made = 1
    }
}

function Write-R1ChannelJson {
    <# Write one JSON file into the channel through a temporary name, then move it. #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Value
    )

    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    $temporary = $Path + ".tmp"
    [System.IO.File]::WriteAllText($temporary, ($Value | ConvertTo-Json), $utf8NoBom)
    [System.IO.File]::Move($temporary, $Path)
}

function Invoke-R1TaskMain {
    <#
        The task body. It reports its own process id first, so the orchestrator
        can tie this instance to its Sysmon EID 1, then waits for the trigger.

        A config with connect = false is the lineage-only rehearsal: the trigger
        is still honoured, but no socket is created and the status says so.
    #>
    param([Parameter(Mandatory = $true)][string]$ChannelDir)

    $config = Get-Content -LiteralPath (Join-Path $ChannelDir $R1_CONFIG_FILE) -Raw -Encoding UTF8 |
        ConvertFrom-Json

    Write-R1ChannelJson -Path (Join-Path $ChannelDir $R1_READY_FILE) -Value ([ordered]@{
        pid         = $PID
        started_utc = (Get-R1UtcStamp (Get-Date))
    })

    $triggerPath = Join-Path $ChannelDir $R1_TRIGGER_FILE
    $deadline = (Get-Date).AddSeconds([int]$config.idle_sec)
    while (-not (Test-Path -LiteralPath $triggerPath)) {
        if ((Get-Date) -ge $deadline) { return }
        Start-Sleep -Milliseconds 200
    }

    if ([bool]$config.connect) {
        $status = Invoke-R1InternalTcpAttempt -Config $config
    } else {
        $status = [ordered]@{
            pid           = $PID
            target        = $null
            port          = $null
            protocol      = $null
            checked_utc   = (Get-R1UtcStamp (Get-Date))
            started_utc   = $null
            ended_utc     = $null
            success       = $false
            skipped       = $true
            timed_out     = $false
            error_kind    = "connection_not_requested"
            attempts_made = 0
        }
    }

    Write-R1ChannelJson -Path (Join-Path $ChannelDir $R1_STATUS_FILE) -Value $status
}

if (-not [string]::IsNullOrEmpty($ChannelDir)) {
    Invoke-R1TaskMain -ChannelDir $ChannelDir
}
