<#
    R1 - out-of-band readiness record of a run whose raw export starts at the
    boot of Target-A. Dot-source this file on the host that runs the VMs:

        . .\scenarios\R1\host\r1_readiness.ps1

    Why it exists. A scenario that states collection.raw_window
    target_boot_to_run_end exports everything Target-A recorded since it booted.
    A connection opened from Target-A to the internal destination to see whether
    it is ready would be in that export, as one more connection to that
    destination before the run. Such a scenario therefore states
    collection.readiness_method out_of_band: readiness is established from
    outside Target-A, written to a record, and the record is handed to the run
    (-ReadinessRecordPath). The runner reads it before its first session and
    starts nothing unless it says: out_of_band, ready, no active TCP probe.

    What is read here, and nothing else:

      - the hypervisor, through two read-only calls of its command line tool:
        which VMs are running, and the address the guest tools of a VM report,
      - the configuration file of a VM: the kind and the address of its adapter,
      - the clock of this host: how long ago the start of a VM was requested.

    No guest is logged in to, no program is run in a guest, no VM is started,
    stopped, suspended or reverted, and no packet is sent to a VM by this file:
    it opens no connection at all. New-R1VmrunCaller refuses every call of the
    hypervisor tool other than the two above.

    What is NOT established: that the listener of the internal destination
    accepts a connection. The baseline snapshot states that, and the connect
    action of the scenario is the only thing that verifies it. When that
    connection is missing the run fails; it is not tried again in the same boot.

    Every address, path and time is an argument. Nothing here names a VM, a
    host, an address or an account.

    NOTE: this file is intentionally ASCII only, like the rest of scenarios/R1:
    Windows PowerShell 5.1 misreads UTF-8 source files without a BOM.
#>

Set-StrictMode -Version Latest

$R1_READINESS_METHOD = "out_of_band"
$R1_READINESS_RESULT_READY = "ready"
$R1_READINESS_RESULT_NOT_READY = "not_ready"
$R1_READINESS_STAMP_FORMAT = "yyyy-MM-dd'T'HH:mm:ss.fff'Z'"
# The only calls of the hypervisor tool this file makes. Both read state.
$R1_READINESS_VMRUN_CALLS = @("list", "getGuestIPAddress")
# An adapter of one of these kinds reaches outside the lab, so a VM that has
# one is never ready, whatever else is stated.
$R1_READINESS_REFUSED_ADAPTERS = @("nat", "bridged")
$R1_READINESS_NOT_VERIFIED = ("the listener of the internal destination: stated by the baseline snapshot " +
    "and verified only by the connect action of the run")

function Get-R1VmxValue {
    <# The value of one key of a VM configuration file, or $null when the key is not stated. #>
    param([AllowEmptyCollection()][string[]]$Lines, [Parameter(Mandatory = $true)][string]$Key)

    foreach ($line in $Lines) {
        if ($line -match ('^\s*' + [regex]::Escape($Key) + '\s*=\s*"(.*)"\s*$')) { return $Matches[1] }
    }
    return $null
}

function New-R1VmrunCaller {
    <#
        A script block that calls the hypervisor command line tool and returns
        its output lines. It takes the arguments of one call as an array.

        Only the two calls this file needs are made. Any other call - starting,
        stopping or reverting a VM, running a program in a guest, copying a file
        - throws before the tool is started.
    #>
    param([Parameter(Mandatory = $true)][string]$VmrunPath)

    if (-not (Test-Path -LiteralPath $VmrunPath -PathType Leaf)) {
        throw ("the hypervisor command line tool was not found: '" + $VmrunPath + "'")
    }
    $allowed = $R1_READINESS_VMRUN_CALLS
    return {
        param([string[]]$CallArguments)
        if ($null -eq $CallArguments -or $CallArguments.Count -eq 0 -or
            -not ($allowed -ccontains $CallArguments[0])) {
            throw ("the readiness check makes no '" + [string]($CallArguments | Select-Object -First 1) +
                "' call of the hypervisor tool; it only reads: " + ($allowed -join ", "))
        }
        # stderr is not redirected: in Windows PowerShell 5.1 "2>&1" on a native
        # command raises an error record before the exit code can be read.
        $output = @(& $VmrunPath @CallArguments)
        if ($LASTEXITCODE -ne 0) {
            throw ("the hypervisor tool exited with code " + $LASTEXITCODE + " for the call '" +
                $CallArguments[0] + "'")
        }
        return $output
    }.GetNewClosure()
}

function Get-R1OutOfBandReadiness {
    <#
        One readiness record of the internal destination VM, from the hypervisor
        and the VM configuration.

        -Vmrun is a script block that takes the arguments of one call of the
        hypervisor tool and returns its output lines (New-R1VmrunCaller; the
        tests pass a fake). -NowProvider gives the clock of this host.

        The checks of the destination VM: it is listed as running, its adapter
        is of the stated kind and has the stated address, the guest tools report
        the stated address, and its start was requested long enough ago. When
        -TargetVmx is given, Target-A is checked for running and for the time
        since its start too. An adapter of a kind that reaches outside the lab
        is refused whatever was stated.

        The result is "ready" only when every check holds. The record always
        states that no active TCP probe was used: there is no code here that
        could make one. A check that could not be made is a check that failed.
    #>
    param(
        [Parameter(Mandatory = $true)][scriptblock]$Vmrun,
        [Parameter(Mandatory = $true)][string]$DestinationVmx,
        [Parameter(Mandatory = $true)][string]$ExpectedAddress,
        [Parameter(Mandatory = $true)][string]$ExpectedAdapterAddress,
        [Parameter(Mandatory = $true)][string]$ExpectedConnectionType,
        [Parameter(Mandatory = $true)][datetime]$StartRequestedUtc,
        [AllowEmptyString()][string]$TargetVmx,
        [AllowNull()][Nullable[datetime]]$TargetStartRequestedUtc,
        [int]$MinimumSecondsSinceStart = 240,
        [scriptblock]$NowProvider = { (Get-Date).ToUniversalTime() }
    )

    if ($R1_READINESS_REFUSED_ADAPTERS -contains $ExpectedConnectionType) {
        throw ("an adapter of the kind '" + $ExpectedConnectionType + "' reaches outside the lab; " +
            "it cannot be the expected adapter of an R1 VM")
    }
    if ($MinimumSecondsSinceStart -lt 0) { throw "MinimumSecondsSinceStart must be 0 or more" }
    $checkTarget = -not [string]::IsNullOrWhiteSpace($TargetVmx)
    if ($checkTarget -and $null -eq $TargetStartRequestedUtc) {
        throw "TargetStartRequestedUtc is required when TargetVmx is given"
    }

    $now = (& $NowProvider).ToUniversalTime()
    $checks = New-Object System.Collections.Generic.List[object]
    $add = {
        param([string]$Name, [string]$Source, [bool]$Ok, [string]$Seen)
        $checks.Add([ordered]@{ name = $Name; source = $Source; ok = $Ok; seen = $Seen })
    }

    # --- the hypervisor: which VMs are running ----------------------------------
    $listed = @()
    $listError = $null
    try {
        $listed = @(& $Vmrun @("list") | ForEach-Object { ([string]$_).Trim() })
    } catch {
        $listError = $_.Exception.Message
    }
    $running = (@($listed | Where-Object { $_ -ieq $DestinationVmx }).Count -eq 1)
    $seen = "listed as running: " + $running
    if ($null -ne $listError) { $seen = "the list of running VMs could not be read: " + $listError }
    & $add "destination_vm_running" "hypervisor" $running $seen

    # --- the VM configuration: the adapter of the destination --------------------
    $lines = @()
    if (Test-Path -LiteralPath $DestinationVmx -PathType Leaf) {
        $lines = @(Get-Content -LiteralPath $DestinationVmx -Encoding UTF8)
    }
    $kind = Get-R1VmxValue -Lines $lines -Key "ethernet0.connectionType"
    $kindOk = ($null -ne $kind -and $kind -ieq $ExpectedConnectionType -and
        -not ($R1_READINESS_REFUSED_ADAPTERS -contains $kind))
    & $add "destination_adapter_kind" "vm_configuration" $kindOk ("connection type: " + [string]$kind)

    $adapterAddress = Get-R1VmxValue -Lines $lines -Key "ethernet0.address"
    if ([string]::IsNullOrEmpty($adapterAddress)) {
        $adapterAddress = Get-R1VmxValue -Lines $lines -Key "ethernet0.generatedAddress"
    }
    $addressSeen = ([string]$adapterAddress -replace '[:-]', '').ToUpperInvariant()
    $addressWanted = ($ExpectedAdapterAddress -replace '[:-]', '').ToUpperInvariant()
    & $add "destination_adapter_address" "vm_configuration" (
        $addressSeen -ne "" -and $addressSeen -ceq $addressWanted) ("adapter address: " + [string]$adapterAddress)

    # --- the hypervisor: the address the guest tools report -----------------------
    $guestAddress = ""
    $guestSeen = "not asked: the VM is not listed as running"
    if ($running) {
        try {
            $guestAddress = ([string](@(& $Vmrun @("getGuestIPAddress", $DestinationVmx)) |
                    Select-Object -First 1)).Trim()
            $guestSeen = "address reported by the guest tools: " + $guestAddress
        } catch {
            $guestSeen = "the guest tools reported no address: " + $_.Exception.Message
        }
    }
    & $add "destination_guest_address" "hypervisor" ($guestAddress -ne "" -and $guestAddress -ceq $ExpectedAddress) $guestSeen

    # --- this host: how long ago the start was requested --------------------------
    $destinationUp = [int][Math]::Floor(($now - $StartRequestedUtc.ToUniversalTime()).TotalSeconds)
    & $add "destination_up_long_enough" "orchestrator" ($destinationUp -ge $MinimumSecondsSinceStart) (
        "seconds since the start was requested: " + $destinationUp + " (minimum " + $MinimumSecondsSinceStart + ")")

    if ($checkTarget) {
        $targetRunning = (@($listed | Where-Object { $_ -ieq $TargetVmx }).Count -eq 1)
        & $add "target_vm_running" "hypervisor" $targetRunning ("listed as running: " + $targetRunning)
        $targetUp = [int][Math]::Floor(($now - ([datetime]$TargetStartRequestedUtc).ToUniversalTime()).TotalSeconds)
        & $add "target_up_long_enough" "orchestrator" ($targetUp -ge $MinimumSecondsSinceStart) (
            "seconds since the start was requested: " + $targetUp + " (minimum " + $MinimumSecondsSinceStart + ")")
    }

    $failed = @($checks | Where-Object { -not $_.ok })
    $result = $R1_READINESS_RESULT_NOT_READY
    if ($failed.Count -eq 0) { $result = $R1_READINESS_RESULT_READY }

    return [ordered]@{
        method                = $R1_READINESS_METHOD
        checked_at            = $now.ToString($R1_READINESS_STAMP_FORMAT)
        result                = $result
        active_tcp_probe_used = $false
        checks                = [object[]]$checks.ToArray()
        not_verified          = $R1_READINESS_NOT_VERIFIED
    }
}

function Write-R1ReadinessRecord {
    <#
        Write a readiness record to a file that must not exist yet, as UTF-8
        without a byte order mark.

        A record that is not ready is written too: it says which check failed,
        and the runner refuses it. An existing file is never replaced, so the
        record a run was started with stays the one that was checked.

        Returns the path and the SHA-256 of the bytes written.
    #>
    param(
        [Parameter(Mandatory = $true)]$Record,
        [Parameter(Mandatory = $true)][string]$Path
    )

    foreach ($name in @("method", "checked_at", "result", "active_tcp_probe_used")) {
        if (-not $Record.Contains($name)) { throw ("the readiness record states no " + $name) }
    }
    if ($Record.active_tcp_probe_used -isnot [bool] -or $Record.active_tcp_probe_used) {
        throw "a readiness record that states an active TCP probe is not written"
    }

    $bytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes(($Record | ConvertTo-Json -Depth 5))
    $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::CreateNew,
        [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    try {
        $stream.Write($bytes, 0, $bytes.Length)
    } finally {
        $stream.Dispose()
    }

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $digest = -join ($sha256.ComputeHash($bytes) | ForEach-Object { $_.ToString("x2") })
    } finally {
        $sha256.Dispose()
    }
    return [ordered]@{ path = $Path; sha256 = $digest }
}

function Invoke-R1ReadinessCheck {
    <#
        Make the out-of-band readiness check and write its record.

        The record is written whatever the result is. The function returns the
        record with the path and the hash of the file; a caller that goes on to
        a run does so only when result is "ready".
    #>
    param(
        [Parameter(Mandatory = $true)][string]$VmrunPath,
        [Parameter(Mandatory = $true)][string]$DestinationVmx,
        [Parameter(Mandatory = $true)][string]$ExpectedAddress,
        [Parameter(Mandatory = $true)][string]$ExpectedAdapterAddress,
        [Parameter(Mandatory = $true)][string]$ExpectedConnectionType,
        [Parameter(Mandatory = $true)][datetime]$StartRequestedUtc,
        [Parameter(Mandatory = $true)][string]$OutputPath,
        [AllowEmptyString()][string]$TargetVmx,
        [AllowNull()][Nullable[datetime]]$TargetStartRequestedUtc,
        [int]$MinimumSecondsSinceStart = 240
    )

    if (Test-Path -LiteralPath $OutputPath) {
        throw ("a readiness record already exists at '" + $OutputPath + "'; it is not replaced")
    }
    $record = Get-R1OutOfBandReadiness -Vmrun (New-R1VmrunCaller -VmrunPath $VmrunPath) `
        -DestinationVmx $DestinationVmx -ExpectedAddress $ExpectedAddress `
        -ExpectedAdapterAddress $ExpectedAdapterAddress -ExpectedConnectionType $ExpectedConnectionType `
        -StartRequestedUtc $StartRequestedUtc -TargetVmx $TargetVmx `
        -TargetStartRequestedUtc $TargetStartRequestedUtc -MinimumSecondsSinceStart $MinimumSecondsSinceStart
    $written = Write-R1ReadinessRecord -Record $record -Path $OutputPath

    foreach ($check in $record.checks) {
        $mark = "[!]"
        if ($check.ok) { $mark = "[+]" }
        Write-Host ($mark + " " + $check.name + " (" + $check.source + "): " + $check.seen)
    }
    Write-Host ("readiness: " + $record.result + ", record " + $written.path + " sha256=" + $written.sha256)

    $record.record_path = $written.path
    $record.record_sha256 = $written.sha256
    return $record
}
