<#
    .SYNOPSIS
        Shared helpers for the R1-V02 Pilot runs (normal and attack).

    .DESCRIPTION
        Dot-source this file from normal/run.ps1 or attack/run.ps1 on the
        Controller. It drives one remote session on Target-A through the five
        actions of docs/scenarios/r1.md section 4-1, collects Target-A's Sysmon
        window and writes the same four artifacts an S0 run writes:

            data/raw/<run_id>/telemetry/       sysmon EVTX and JSONL
            data/raw/<run_id>/manifest.json    path / sha256 / layer / source
            data/ground_truth/<run_id>/execution_record.csv
            data/ground_truth/<run_id>/run_metadata.json

        Both runs start the same final management tool with the same task. Only
        the intermediate process between the remote session host and that tool
        differs, and which one a run uses comes from the scenario file, not from
        this code (scenario.yaml, planned_lineage).

        The planned lineage is what a run executes and what its collection is
        checked against. Whether a lineage is approved is not decided here: the
        approved lineage policy of a family is not part of the scenario, and the
        runner reads none.

        The rendered scenario is the only source of what a run does and records.
        The family, the variation and the repetition of the Pair are read from it
        and written to RunMetadata; no parameter of a run overrides them.

        Every side effect on Target-A goes through a transport: open a session,
        invoke a named remote step, fetch a file, close the session. The
        production transport (New-R1WinRmTransport) is the only place a WinRM
        session, a process or a socket is created. The guard tests pass a fake
        transport, a fake clock and a fake sleeper, so they start nothing.

        Times in the artifacts are Target-A's clock, as returned by the remote
        steps. The Controller clock only schedules the offsets and measures
        durations. The one derived time is t+0: no session exists yet when the
        Controller starts opening it, so it is the pre-run stamp from Target-A
        plus the time the Controller measured since.

        Shared code: the run_id rule, the UTC stamp, the output directory guard
        and the writers of the artifacts are the S0 functions in
        ..\S0\run-common.ps1. Loading that file runs nothing.

        NOTE: this file is intentionally ASCII only. Windows PowerShell 5.1
        misreads UTF-8 source files without a BOM, and a lost BOM corrupts
        string literals.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "..\S0\run-common.ps1")

# The destination rule and the single TCP primitive. Loaded without -ChannelDir it
# only defines functions; the same file is what Target-A runs as the final task.
# Loading it leaves an empty $ChannelDir behind, so nothing here uses that name.
. (Join-Path $PSScriptRoot "remote\r1_task.ps1")

$R1_SCENARIO_ID = "R1"
$R1_TASK_SOURCE = Join-Path $PSScriptRoot "remote\r1_task.ps1"
$R1_TASK_FILE = "r1_task.ps1"
$R1_CHANNEL_NAME = "r1_chan"
$R1_PREPARED_NOTE = "r1_prepared.txt"
$R1_EXPORT_FILE = "r1_sysmon_export.evtx"
$R1_STEP_ORDER = @("session_begin", "prepare", "launch", "connect", "session_end")
$R1_RUN_TYPES = @("normal", "attack")

# Words that would give the run type away if they reached a process name, an
# argument or a file name on Target-A (docs/scenarios/r1.md section 7), or the
# family and variation both runs of a Pair record.
#
# The last three are the Korean labels for normal, attack and malicious. This
# file is ASCII only, so they are built from their code points. The list is the
# same one, in the same order, as LABEL_WORDS in
# src/incident_awareness/collection/r1_pair_identity.py; both are checked against
# tests\label_shortcut_cases.json.
$R1_LABEL_WORDS = @(
    "normal", "attack", "benign", "malicious",
    (-join [char[]](0xC815, 0xC0C1)),
    (-join [char[]](0xACF5, 0xACA9)),
    (-join [char[]](0xC545, 0xC131))
)

$R1_READY_TIMEOUT_SEC = 60
$R1_STATUS_TIMEOUT_SEC = 60
$R1_CONNECT_TIMEOUT_MS = 3000
$R1_TASK_IDLE_SEC = 3600

# The operator trace of a run: what ties the run to the scenario it executed and
# says which dataset tier it belongs to. It is kept next to raw/ and
# ground_truth/, not inside them: those two hold exactly the files the contracts
# and the Manifest describe.
$R1_TRACE_DIR = "operator_trace"
$R1_TRACE_FILE = "r1_run_trace.json"
$R1_TRACE_SCENARIO_FILE = "scenario.json"
$R1_TRACE_VERSION = "v1"

# Every run of this runner is a Pilot run, a rehearsal included. A formal
# evaluation selector has to leave out every run whose trace says so.
$R1_DATASET_TIER = "pilot"

function Get-R1Value {
    <# A property of a parsed JSON object or a key of a dictionary, or $null when it is absent. #>
    param([AllowNull()]$Object, [Parameter(Mandatory = $true)][string]$Name)

    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name)) { return $Object[$Name] }
        return $null
    }

    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function ConvertTo-R1Utc {
    <# Read a stamp a remote step returned. The same strict parser S0 uses for approved times. #>
    param([AllowNull()]$Value, [Parameter(Mandatory = $true)][string]$Label)

    $parsed = ConvertTo-ApprovedUtc -Value ([string]$Value) -Label $Label
    if (-not $parsed.ok) { throw $parsed.reason }
    return $parsed.value
}

function Test-R1SafePath {
    <#
        True for a drive rooted Windows path made only of letters, digits, '_',
        '-', '.' and '\'.

        The work directory ends up inside command lines and inside the launcher
        files. Refusing spaces and quoting characters keeps those command lines
        free of quoting, so both runs produce the same final command line.
    #>
    param([AllowNull()][AllowEmptyString()][string]$Path)

    if ([string]::IsNullOrEmpty($Path)) { return $false }
    return ($Path -match '^[A-Za-z]:(\\[A-Za-z0-9_.-]+)+$')
}

function Get-R1ExposedLabelWord {
    <#
        The label word a value contains, or $null.

        The value is lower cased without regard to the culture of the machine and
        searched for each word of $R1_LABEL_WORDS as a substring, in the order of
        that list. It is the rule exposed_label_word applies on the Python side:
        the identity of a Pair and everything the launch plan puts on Target-A
        go through this one function.
    #>
    param([AllowNull()][AllowEmptyString()][string]$Value)

    if ([string]::IsNullOrEmpty($Value)) { return $null }

    $lower = $Value.ToLowerInvariant()
    foreach ($word in $R1_LABEL_WORDS) {
        if ($lower.Contains($word)) { return $word }
    }
    return $null
}

function Test-R1EncodedOption {
    <#
        True when PowerShell would read a command line token as -EncodedCommand.

        PowerShell accepts any prefix of the option name and the alias -ec, with
        either '-' or '/'. The first Pilot does not use an encoded command, so a
        token of this shape anywhere in the plan stops the run.
    #>
    param([AllowNull()][AllowEmptyString()][string]$Token)

    if ([string]::IsNullOrEmpty($Token)) { return $false }

    $value = $Token.ToLower()
    if ($value.StartsWith("/")) { $value = "-" + $value.Substring(1) }
    if ($value -eq "-ec") { return $true }

    return ($value.Length -ge 2 -and "-encodedcommand".StartsWith($value))
}

function Get-R1LauncherContent {
    <#
        The text of one launcher file. Every kind runs the same final command
        line, which is what makes the final process identical in both runs.

            batch    run by the command shell
            jscript  run by the script host
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Kind,
        [Parameter(Mandatory = $true)][string]$CommandLine
    )

    if ($Kind -eq "batch") {
        return ("@echo off`r`n" + $CommandLine + "`r`n")
    }
    if ($Kind -eq "jscript") {
        $escaped = $CommandLine.Replace("\", "\\").Replace('"', '\"')
        return ('var shell = new ActiveXObject("WScript.Shell");' + "`r`n" +
            'WScript.Quit(shell.Run("' + $escaped + '", 0, true));' + "`r`n")
    }

    throw ("unknown launcher_kind '" + $Kind + "'; expected batch or jscript")
}

function Get-R1LaunchPlan {
    <#
        Build everything a run starts on Target-A, without starting it.

        This is the single place a command line is produced: the runner hands the
        returned executable and arguments to the remote launch step unchanged, and
        the guard tests check the same values without starting a process.

        The plan holds the launcher files of BOTH run types. Both runs write the
        same files in the common preparation step, so the files on disk do not
        tell the runs apart; the run type only selects which intermediate is
        started.
    #>
    param(
        [Parameter(Mandatory = $true)]$Scenario,
        [Parameter(Mandatory = $true)][ValidateSet("normal", "attack")][string]$RunType,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$WorkDir
    )

    if (-not (Test-R1SafePath $WorkDir)) {
        throw ("WorkDir must be a drive rooted path of letters, digits, '_', '-' and '.' " +
            "without spaces, found '" + $WorkDir + "'")
    }

    # What a run starts comes from the planned lineage of the scenario alone.
    $lineage = Get-R1Value $Scenario "planned_lineage"
    if ($null -eq $lineage) { throw "planned_lineage is missing from the scenario" }
    $sessionHostImage = [string](Get-R1Value (Get-R1Value $lineage "session_host") "image")
    $final = Get-R1Value $lineage "final_tool"
    $finalImage = [string](Get-R1Value $final "image")
    $finalTemplates = @(Get-R1Value $final "arguments")
    $intermediates = Get-R1Value $lineage "intermediate"

    if ([string]::IsNullOrWhiteSpace($sessionHostImage)) { throw "planned_lineage.session_host.image is missing" }
    if ([string]::IsNullOrWhiteSpace($finalImage)) { throw "planned_lineage.final_tool.image is missing" }
    foreach ($placeholder in @("{task_script}", "{channel_dir}")) {
        if (-not ($finalTemplates -contains $placeholder)) {
            throw ("planned_lineage.final_tool.arguments must contain " + $placeholder)
        }
    }

    $taskScript = $WorkDir + "\" + $R1_TASK_FILE
    $channelDir = $WorkDir + "\" + $R1_CHANNEL_NAME
    $finalArguments = @(foreach ($template in $finalTemplates) {
        ([string]$template).Replace("{task_script}", $taskScript).Replace("{channel_dir}", $channelDir)
    })
    $finalCommandLine = $finalImage + " " + ($finalArguments -join " ")

    # Launcher files for every run type, keyed by file name so both runs hold the
    # same set in the same order.
    $launchers = @{}
    $images = @{}
    foreach ($type in $R1_RUN_TYPES) {
        $entry = Get-R1Value $intermediates $type
        if ($null -eq $entry) { throw ("planned_lineage.intermediate." + $type + " is missing") }

        $image = [string](Get-R1Value $entry "image")
        $file = [string](Get-R1Value $entry "launcher_file")
        if ([string]::IsNullOrWhiteSpace($image)) { throw ("planned_lineage.intermediate." + $type + ".image is missing") }
        if ($file -notmatch '^[A-Za-z0-9_.-]+$') {
            throw ("planned_lineage.intermediate." + $type + ".launcher_file is not a plain file name: '" + $file + "'")
        }
        if ($launchers.ContainsKey($file)) {
            throw ("planned_lineage.intermediate entries share the launcher file '" + $file + "'")
        }

        $launchers[$file] = Get-R1LauncherContent -Kind ([string](Get-R1Value $entry "launcher_kind")) `
            -CommandLine $finalCommandLine
        $images[$type] = $image
    }
    if ($images["normal"] -eq $images["attack"]) {
        throw "planned_lineage.intermediate.normal and .attack name the same image; the pair would not differ"
    }

    $files = [ordered]@{}
    $files[$R1_TASK_FILE] = [System.IO.File]::ReadAllText($R1_TASK_SOURCE)
    foreach ($file in ($launchers.Keys | Sort-Object)) { $files[$file] = $launchers[$file] }

    $selected = Get-R1Value $intermediates $RunType
    $launcherPath = $WorkDir + "\" + [string](Get-R1Value $selected "launcher_file")
    $intermediateTemplates = @(Get-R1Value $selected "arguments")
    if (-not ($intermediateTemplates -contains "{launcher}")) {
        throw ("planned_lineage.intermediate." + $RunType + ".arguments must contain {launcher}")
    }
    $intermediateArguments = @(foreach ($template in $intermediateTemplates) {
        ([string]$template).Replace("{launcher}", $launcherPath)
    })

    return [ordered]@{
        run_type         = $RunType
        work_dir         = $WorkDir
        channel_dir      = $channelDir
        task_script      = $taskScript
        intermediate     = [ordered]@{
            executable    = $images[$RunType]
            arguments     = $intermediateArguments
            launcher_path = $launcherPath
        }
        final            = [ordered]@{
            executable   = $finalImage
            arguments    = $finalArguments
            command_line = $finalCommandLine
        }
        files            = $files
        # Closest first, the order a parent walk returns: final tool,
        # intermediate, remote session host.
        expected_lineage = @($finalImage, $images[$RunType], $sessionHostImage)
    }
}

function Assert-R1PlanShortcutFree {
    <#
        Stop when the plan would put the run type, or an encoded command option,
        into something Sysmon records on Target-A.

        Checked: both executables, every argument, every file name, the work and
        channel directories and every line of the launcher files. The task file is
        the same in both runs and is not scanned for label words.
    #>
    param([Parameter(Mandatory = $true)]$Plan)

    $tokens = New-Object System.Collections.Generic.List[string]
    $tokens.Add([string]$Plan.intermediate.executable)
    $tokens.Add([string]$Plan.final.executable)
    foreach ($argument in @($Plan.intermediate.arguments)) { $tokens.Add([string]$argument) }
    foreach ($argument in @($Plan.final.arguments)) { $tokens.Add([string]$argument) }
    $tokens.Add([string]$Plan.work_dir)
    $tokens.Add([string]$Plan.channel_dir)
    foreach ($name in $Plan.files.Keys) {
        $tokens.Add([string]$name)
        if ($name -eq $R1_TASK_FILE) { continue }
        foreach ($line in ([string]$Plan.files[$name] -split "`r?`n")) {
            foreach ($word in ($line -split '[\s"(),;]+')) {
                if ($word.Length -gt 0) { $tokens.Add($word) }
            }
        }
    }

    foreach ($token in $tokens) {
        if (Test-R1EncodedOption $token) {
            throw ("the plan carries an encoded command option, which the first Pilot does not use: '" +
                $token + "'")
        }
        $exposedWord = Get-R1ExposedLabelWord -Value $token
        if ($null -ne $exposedWord) {
            throw ("the plan would expose the run type on Target-A: '" + $token +
                "' contains '" + $exposedWord + "'")
        }
    }
}

function Get-R1ConnectionApproval {
    <#
        Validate the internal destination injected into scenario.json.

        Returns $null when no destination was injected, which only a rehearsal or
        a dry run may use (the connection is then skipped). An injected value is
        checked whatever the mode: it has to be an RFC 1918 host address inside
        the lab network, TCP, one attempt. A globally routable address is refused
        here, before a session exists, and again by the task before a socket
        exists.
    #>
    param([Parameter(Mandatory = $true)]$Scenario)

    $internal = Get-R1Value $Scenario "internal_connection"
    if ($null -eq $internal) { throw "scenario has no internal_connection block" }

    $target = [string](Get-R1Value $internal "target")
    if ([string]::IsNullOrWhiteSpace($target)) { return $null }

    $labCidr = [string](Get-R1Value $internal "lab_cidr")
    $check = Test-R1InternalDestination -Address $target -LabCidr $labCidr
    if (-not $check.ok) {
        throw ("internal_connection.target is not an approved internal destination (" +
            [string]$check.reason + "): '" + $target + "' with lab network '" + $labCidr +
            "'. Render scenario.json with tools/r1_scenario_to_json.py.")
    }

    $port = 0
    if (-not [int]::TryParse([string](Get-R1Value $internal "port"), [ref]$port) -or
        $port -lt 1 -or $port -gt 65535) {
        throw ("internal_connection.port must be an integer in 1..65535, found '" +
            [string](Get-R1Value $internal "port") + "'")
    }

    $protocol = ([string](Get-R1Value $internal "protocol")).ToUpper()
    if ($protocol -ne "TCP") {
        throw ("internal_connection.protocol must be TCP, found '" + $protocol + "'")
    }

    $attempts = 0
    if (-not [int]::TryParse([string](Get-R1Value $internal "max_attempts"), [ref]$attempts) -or
        $attempts -ne 1) {
        throw ("internal_connection.max_attempts must be exactly 1, found '" +
            [string](Get-R1Value $internal "max_attempts") + "'")
    }

    return [ordered]@{
        target       = $target
        port         = $port
        protocol     = $protocol
        lab_cidr     = $labCidr
        max_attempts = $attempts
    }
}

function Get-R1PairIdentity {
    <#
        The family, the variation and the repetition a rendered scenario states
        for its Pair.

        The scenario is the only source. The runner has no parameter for any of
        them, so both runs of a Pair, which read one rendered file, record the
        same three values. A value that is missing, of the wrong type or named
        after a run type throws.

        The family and the variation are design values of the scenario YAML; the
        renderer does not replace them. Only the repetition is given when the
        JSON is rendered.
    #>
    param([Parameter(Mandatory = $true)]$Scenario)

    $identity = [ordered]@{}
    foreach ($name in @("family_id", "variation_id")) {
        $value = Get-R1Value $Scenario $name
        if ($value -isnot [string] -or [string]::IsNullOrWhiteSpace($value)) {
            throw ($name + " must be a non-empty string; the scenario YAML states it and " +
                "rendering does not replace it")
        }
        if ($value -cne $value.Trim()) {
            throw ($name + " must not have surrounding whitespace: '" + $value + "'")
        }
        $exposedWord = Get-R1ExposedLabelWord -Value $value
        if ($null -ne $exposedWord) {
            throw ($name + " would expose the run type: '" + $value + "' contains '" + $exposedWord + "'")
        }
        $identity[$name] = $value
    }

    # An integer as JSON wrote it. A number with a fraction, a string and a
    # boolean are refused even when they would convert.
    $repetition = Get-R1Value $Scenario "repetition"
    if (($repetition -isnot [int] -and $repetition -isnot [long]) -or $repetition -lt 1) {
        throw ("repetition must be an integer of 1 or more, found '" + [string]$repetition +
            "'; state it when rendering scenario.json (--repetition)")
    }
    $identity["repetition"] = $repetition

    return $identity
}

function Read-R1ScenarioFile {
    <#
        Read the rendered scenario exactly once.

        The bytes read here are the ones that are parsed, hashed and later kept
        in the operator trace of the run. The plan a run executes and the
        scenario its record names therefore cannot differ, whatever happens to
        the file afterwards.

        Returns the bytes, their SHA-256 in lower case hex and the parsed
        scenario. Bytes that are not UTF-8 are refused instead of being read
        with replacement characters.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    $bytes = [System.IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $Path).ProviderPath)

    $strictUtf8 = New-Object System.Text.UTF8Encoding($false, $true)
    try {
        $text = $strictUtf8.GetString($bytes)
    } catch {
        throw ("scenario JSON is not UTF-8: '" + $Path + "'")
    }
    if ($text.Length -gt 0 -and $text[0] -eq [char]0xFEFF) { $text = $text.Substring(1) }

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $digest = -join ($sha256.ComputeHash($bytes) | ForEach-Object { $_.ToString("x2") })
    } finally {
        $sha256.Dispose()
    }

    return [ordered]@{
        bytes    = $bytes
        sha256   = $digest
        scenario = ($text | ConvertFrom-Json)
    }
}

function Get-R1TraceDirectory {
    <# Where the operator trace of one run lives under the root the run writes to. #>
    param(
        [Parameter(Mandatory = $true)][string]$EffectiveRoot,
        [Parameter(Mandatory = $true)][string]$RunId
    )

    return (Join-Path (Join-Path $EffectiveRoot $R1_TRACE_DIR) $RunId)
}

function Assert-R1TraceAvailable {
    <#
        Refuse to start when this run_id already has an operator trace.

        A trace is written once. One that exists belongs to an earlier run of
        this run_id, and writing a second scenario beside it would leave the
        record of that run ambiguous. The check runs before the first session.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$EffectiveRoot,
        [Parameter(Mandatory = $true)][string]$RunId
    )

    $traceDir = Get-R1TraceDirectory -EffectiveRoot $EffectiveRoot -RunId $RunId
    if (Test-Path -LiteralPath $traceDir) {
        throw ("run_id " + $RunId + " already has an operator trace at " + $traceDir +
            ". Issue a new run_id: the trace of a run is written once.")
    }
}

function Write-R1NewFile {
    <# Create a file that must not exist yet and write the bytes to it. An existing file throws. #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$Bytes
    )

    $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::CreateNew,
        [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    try {
        $stream.Write($Bytes, 0, $Bytes.Length)
    } finally {
        $stream.Dispose()
    }
}

function Write-R1RunTrace {
    <#
        Keep what ties this run to the scenario it executes.

        Two files are written, each exactly once, under
        <root>\operator_trace\<run_id>\:

            scenario.json        the bytes the plan of this run was built from
            r1_run_trace.json    run_id, mode, dataset tier and the SHA-256 of
                                 those bytes

        The host validator refuses a run whose trace is missing or whose
        scenario is not the one given to it, so a scenario edited after the run
        cannot be used to judge the run. The trace is operator evidence: it is
        not listed in the Manifest and no contract file changes.

        Returns the trace directory.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$EffectiveRoot,
        [Parameter(Mandatory = $true)][string]$RunId,
        [Parameter(Mandatory = $true)][string]$Mode,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$ScenarioBytes,
        [Parameter(Mandatory = $true)][string]$ScenarioSha256
    )

    Assert-R1TraceAvailable -EffectiveRoot $EffectiveRoot -RunId $RunId
    $traceDir = Get-R1TraceDirectory -EffectiveRoot $EffectiveRoot -RunId $RunId
    New-Item -ItemType Directory -Path $traceDir -Force | Out-Null

    Write-R1NewFile -Path (Join-Path $traceDir $R1_TRACE_SCENARIO_FILE) -Bytes $ScenarioBytes

    $trace = [ordered]@{
        trace_version   = $R1_TRACE_VERSION
        run_id          = $RunId
        dataset_tier    = $R1_DATASET_TIER
        mode            = $Mode
        scenario_sha256 = $ScenarioSha256
    }
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    Write-R1NewFile -Path (Join-Path $traceDir $R1_TRACE_FILE) `
        -Bytes $utf8NoBom.GetBytes(($trace | ConvertTo-Json))

    return $traceDir
}

function Assert-R1RunInputs {
    <#
        Check every input before anything is created, opened or started.

        A value that is missing or malformed throws here, so a refused run leaves
        no directory, no session and no process behind. Returns the parsed
        scenario, the bytes it was parsed from and their SHA-256, the identity of
        the Pair, the action list of this run type and the connection approval
        ($null when the connection is skipped).
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$RunType,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$RunId,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$ScenarioJsonPath,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$DataRoot,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$WorkDir,
        [Parameter(Mandatory = $true)][int]$ObservationSec,
        [switch]$Rehearsal,
        [switch]$DryRun
    )

    if (-not ($R1_RUN_TYPES -contains $RunType)) {
        throw ("RunType must be one of " + ($R1_RUN_TYPES -join ", ") + ", found '" + $RunType + "'")
    }
    if (-not (Test-RunId -RunId $RunId)) {
        throw "run_id must match RUN-YYYYMMDD-NNN with a real date: '$RunId'"
    }
    if ([string]::IsNullOrWhiteSpace($ScenarioJsonPath) -or -not (Test-Path -LiteralPath $ScenarioJsonPath)) {
        throw "scenario JSON not found: '$ScenarioJsonPath'"
    }
    if ([string]::IsNullOrWhiteSpace($DataRoot)) { throw "DataRoot is required" }
    if (-not (Test-R1SafePath $WorkDir)) {
        throw ("WorkDir must be a drive rooted path of letters, digits, '_', '-' and '.' " +
            "without spaces, found '" + $WorkDir + "'")
    }

    # One read. Everything below works on what these bytes said, and the same
    # bytes are what the operator trace keeps.
    $loaded = Read-R1ScenarioFile -Path $ScenarioJsonPath
    $scenario = $loaded.scenario
    if ([string](Get-R1Value $scenario "scenario_id") -ne $R1_SCENARIO_ID) {
        throw ("scenario_id must be " + $R1_SCENARIO_ID + ", found '" +
            [string](Get-R1Value $scenario "scenario_id") + "'")
    }

    $identity = Get-R1PairIdentity -Scenario $scenario

    $run = Get-R1Value (Get-R1Value $scenario "runs") $RunType
    if ($null -eq $run) { throw ("runs." + $RunType + " is missing from the scenario") }

    # The identity of a Pair is stated once for both runs. A run that stated its
    # own could disagree with the other run of the Pair.
    foreach ($name in @("family_id", "variation_id", "repetition")) {
        if ($null -ne $run.PSObject.Properties[$name]) {
            throw ("runs." + $RunType + " states " + $name + "; a Pair states it once at the top level")
        }
    }

    # The Pilot records no reference action: r1.md section 11-5 has not decided
    # one. A scenario that names one would get a RunMetadata without it, so stop.
    if (-not [string]::IsNullOrEmpty([string](Get-R1Value $run "reference_action_id"))) {
        throw ("runs." + $RunType + ".reference_action_id is set, but the Pilot runner records no " +
            "reference action yet (docs/scenarios/r1.md section 11-5)")
    }

    $actions = @(Get-R1Value $run "actions")
    $steps = @($actions | ForEach-Object { [string](Get-R1Value $_ "step") })
    if (($steps -join ",") -ne ($R1_STEP_ORDER -join ",")) {
        throw ("runs." + $RunType + ".actions must be the steps " + ($R1_STEP_ORDER -join ", ") +
            " in that order, found " + ($steps -join ", "))
    }

    $lastOffset = 0
    $previous = -1
    foreach ($action in $actions) {
        $offset = 0
        if (-not [int]::TryParse([string](Get-R1Value $action "offset_sec"), [ref]$offset) -or $offset -lt 0) {
            throw ("action " + [string](Get-R1Value $action "action_id") + " has no usable offset_sec")
        }
        if ($offset -lt $previous) {
            throw ("action " + [string](Get-R1Value $action "action_id") + " is scheduled before the one before it")
        }
        $previous = $offset
        $lastOffset = $offset
    }

    # The window has to cover the last action; how much longer it runs is a run
    # input, because the evaluation horizon is not decided (r1.md section 11-4).
    if ($ObservationSec -lt $lastOffset -or $ObservationSec -lt 1) {
        throw ("ObservationSec " + $ObservationSec + " does not cover the last action at " +
            $lastOffset + " s")
    }

    $approval = Get-R1ConnectionApproval -Scenario $scenario
    if ($null -eq $approval -and -not $Rehearsal -and -not $DryRun) {
        throw ("internal_connection.target is null. A collection run needs the internal " +
            "destination; render scenario.json with --internal-target, --internal-port and --lab-cidr.")
    }

    return [ordered]@{
        scenario        = $scenario
        scenario_bytes  = $loaded.bytes
        scenario_sha256 = $loaded.sha256
        identity        = $identity
        run             = $run
        actions         = $actions
        approval        = $approval
        last_offset     = $lastOffset
    }
}

# ---------------------------------------------------------------------------
# Remote steps - production only
#
# Each script block runs on Target-A inside a remote session and returns exactly
# one hashtable. The guard tests never execute them: they replace the transport
# that would send them.
# ---------------------------------------------------------------------------

$R1_REMOTE_STEPS = @{
    # Pre-run check in its own session, so the Sysmon64 process it starts is over
    # before the run's start time is stamped.
    probe = {
        param($Arguments)
        Set-StrictMode -Version Latest
        $ErrorActionPreference = "Stop"

        $sysmon = @{ config_file = $null; config_hash = $null; hashing_algorithms = $null }
        $output = & $Arguments.sysmon_binary -c | Out-String
        foreach ($line in ($output -split "`r?`n")) {
            if ($line -match '^\s*-?\s*Config file:\s*(.+?)\s*$') { $sysmon.config_file = $Matches[1] }
            if ($line -match '^\s*-?\s*Config hash:\s*(.+?)\s*$') { $sysmon.config_hash = $Matches[1] }
            if ($line -match '^\s*-?\s*HashingAlgorithms:\s*(.+?)\s*$') { $sysmon.hashing_algorithms = $Matches[1] }
        }
        $configSha256 = (Get-FileHash -LiteralPath $Arguments.sysmon_config_path -Algorithm SHA256).Hash.ToLower()

        # The name Sysmon writes into its records. The lineage check compares
        # that name, not the environment variable, with target_host.
        $recordedName = $null
        try {
            $latest = Get-WinEvent -LogName $Arguments.log_name -MaxEvents 1 -ErrorAction Stop
            $recordedName = [string]$latest.MachineName
        } catch {
            $recordedName = $null
        }

        return @{
            utc                    = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
            computer_name          = $env:COMPUTERNAME
            recorded_computer_name = $recordedName
            sysmon                 = $sysmon
            config_sha256          = $configSha256
        }
    }

    # t+0: the session exists. $PID here is the remote session host process.
    begin = {
        param($Arguments)
        return @{
            utc           = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
            session_pid   = $PID
            computer_name = $env:COMPUTERNAME
        }
    }

    # t+2: common preparation, identical in both runs.
    prepare = {
        param($Arguments)
        Set-StrictMode -Version Latest
        $ErrorActionPreference = "Stop"

        $utc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        if (Test-Path -LiteralPath $Arguments.channel_dir) {
            throw ("channel directory already exists on the target: " + $Arguments.channel_dir +
                ". Restore the snapshot before a run.")
        }
        New-Item -ItemType Directory -Path $Arguments.work_dir -Force | Out-Null
        New-Item -ItemType Directory -Path $Arguments.channel_dir -Force | Out-Null

        $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        foreach ($name in @($Arguments.files.Keys | Sort-Object)) {
            [System.IO.File]::WriteAllText((Join-Path $Arguments.work_dir $name),
                [string]$Arguments.files[$name], $utf8NoBom)
        }
        [System.IO.File]::WriteAllText((Join-Path $Arguments.channel_dir $Arguments.config_file),
            [string]$Arguments.channel_config, $utf8NoBom)
        [System.IO.File]::WriteAllText((Join-Path $Arguments.work_dir $Arguments.note_file),
            ("prepared " + $utc), $utf8NoBom)

        return @{ utc = $utc }
    }

    # t+5: the session host starts the intermediate, which starts the final tool.
    launch = {
        param($Arguments)
        Set-StrictMode -Version Latest
        $ErrorActionPreference = "Stop"

        $utc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        $process = Start-Process -FilePath $Arguments.executable -ArgumentList @($Arguments.arguments) `
            -WorkingDirectory $Arguments.work_dir -WindowStyle Hidden -PassThru

        $readyPath = Join-Path $Arguments.channel_dir $Arguments.ready_file
        $deadline = (Get-Date).AddSeconds([int]$Arguments.timeout_sec)
        while (-not (Test-Path -LiteralPath $readyPath)) {
            if ((Get-Date) -ge $deadline) {
                throw ("the final tool did not report ready within " + $Arguments.timeout_sec + " s")
            }
            Start-Sleep -Milliseconds 200
        }
        $ready = Get-Content -LiteralPath $readyPath -Raw -Encoding UTF8 | ConvertFrom-Json

        return @{
            utc              = $utc
            intermediate_pid = [int]$process.Id
            final_pid        = [int]$ready.pid
        }
    }

    # t+8: let the final tool make its one connection and read what it reports.
    trigger = {
        param($Arguments)
        Set-StrictMode -Version Latest
        $ErrorActionPreference = "Stop"

        $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText((Join-Path $Arguments.channel_dir $Arguments.trigger_file),
            "connect", $utf8NoBom)

        $statusPath = Join-Path $Arguments.channel_dir $Arguments.status_file
        $deadline = (Get-Date).AddSeconds([int]$Arguments.timeout_sec)
        while (-not (Test-Path -LiteralPath $statusPath)) {
            if ((Get-Date) -ge $deadline) {
                throw ("the final tool wrote no connection status within " + $Arguments.timeout_sec + " s")
            }
            Start-Sleep -Milliseconds 200
        }
        $status = Get-Content -LiteralPath $statusPath -Raw -Encoding UTF8 | ConvertFrom-Json

        return @{
            utc    = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
            status = @{
                pid           = [int]$status.pid
                target        = [string]$status.target
                port          = [string]$status.port
                protocol      = [string]$status.protocol
                checked_utc   = [string]$status.checked_utc
                started_utc   = [string]$status.started_utc
                ended_utc     = [string]$status.ended_utc
                success       = [bool]$status.success
                skipped       = [bool]$status.skipped
                timed_out     = [bool]$status.timed_out
                error_kind    = [string]$status.error_kind
                attempts_made = [int]$status.attempts_made
            }
        }
    }

    # t+10: the last thing the scenario session does before it is closed.
    end = {
        param($Arguments)
        return @{ utc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ") }
    }

    # After the observation window, in a session of its own: export the Sysmon
    # records of the run window. The window reaches back from now to the start of
    # the run plus a margin. Both ends are this host's clock - the start is the
    # stamp it gave in the pre-run check - which is also the clock the records
    # carry, so the Controller clock and the time a session takes to open do not
    # move the window.
    export = {
        param($Arguments)
        Set-StrictMode -Version Latest
        $ErrorActionPreference = "Stop"

        $now = (Get-Date).ToUniversalTime()
        $start = [datetime]::ParseExact([string]$Arguments.start_utc, "yyyy-MM-dd'T'HH:mm:ss.fff'Z'",
            [System.Globalization.CultureInfo]::InvariantCulture,
            ([System.Globalization.DateTimeStyles]::AssumeUniversal -bor
                [System.Globalization.DateTimeStyles]::AdjustToUniversal))
        if ($now -lt $start) { throw "the start of the run is later than the clock of this host" }
        $windowMs = [long]($now - $start).TotalMilliseconds + [long]$Arguments.margin_ms

        $idClause = (@($Arguments.event_ids) | ForEach-Object { "EventID=$_" }) -join " or "
        $query = "*[System[($idClause) and TimeCreated[timediff(@SystemTime) <= $windowMs]]]"
        if (Test-Path -LiteralPath $Arguments.export_path) { Remove-Item -LiteralPath $Arguments.export_path -Force }

        # Do not redirect stderr: in Windows PowerShell 5.1 "2>&1" on a native
        # command raises NativeCommandError before the exit code can be read.
        & wevtutil epl $Arguments.log_name $Arguments.export_path "/q:$query" /ow:true | Out-Null
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $Arguments.export_path)) {
            throw ("wevtutil epl failed for " + $Arguments.log_name)
        }

        return @{
            utc       = $now.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
            evtx_path = [string]$Arguments.export_path
            window_ms = $windowMs
        }
    }

    # Remove what the run left on Target-A once the export has been fetched.
    cleanup = {
        param($Arguments)
        $ErrorActionPreference = "Stop"

        foreach ($path in @($Arguments.paths)) {
            if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Recurse -Force }
        }
        return @{ utc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ") }
    }
}

function Convert-R1EvtxToJsonl {
    <#
        Render a fetched EVTX file as the JSONL shape the S0 runner writes: one
        record per line with RecordId, EventId, TimeCreated, Channel, Computer,
        Provider and EventData. Returns the number of records.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$EvtxPath,
        [Parameter(Mandatory = $true)][string]$JsonlPath
    )

    $events = @(Get-WinEvent -Path $EvtxPath -ErrorAction SilentlyContinue | Sort-Object RecordId)
    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($event in $events) {
        $xml = [xml]$event.ToXml()
        $eventData = [ordered]@{}
        foreach ($item in $xml.Event.EventData.Data) { $eventData[$item.Name] = $item."#text" }

        $record = [ordered]@{
            RecordId    = $event.RecordId
            EventId     = $event.Id
            TimeCreated = (Get-UtcStamp $event.TimeCreated)
            Channel     = $event.LogName
            Computer    = $event.MachineName
            Provider    = $event.ProviderName
            EventData   = $eventData
        }
        $lines.Add(($record | ConvertTo-Json -Compress -Depth 5))
    }

    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllLines($JsonlPath, $lines, $utf8NoBom)
    return $lines.Count
}

function New-R1WinRmTransport {
    <#
        The production transport. This is the only place a WinRM session is
        opened, a remote step is sent, a file is copied or an EVTX is read.

        The connection value it receives carries the address, the WinRM port,
        whether to use TLS and the credential. None of them is stored in the
        repository or in an artifact.
    #>
    return @{
        open    = {
            param($Connection)
            $options = @{
                ComputerName = [string]$Connection.address
                Port         = [int]$Connection.port
                Credential   = $Connection.credential
            }
            if ([bool]$Connection.use_ssl) { $options.UseSSL = $true }
            return (New-PSSession @options)
        }
        invoke  = {
            param($Session, $Step, $Arguments)
            return (Invoke-Command -Session $Session -ScriptBlock $R1_REMOTE_STEPS[$Step] `
                -ArgumentList (, $Arguments))
        }
        fetch   = {
            param($Session, $RemotePath, $LocalPath)
            # The remote path is the work directory, which Test-R1SafePath limits
            # to characters that are not wildcards, plus a fixed file name.
            Copy-Item -FromSession $Session -Path $RemotePath -Destination $LocalPath -Force
        }
        close   = {
            param($Session)
            Remove-PSSession -Session $Session
        }
        convert = {
            param($EvtxPath, $JsonlPath)
            return (Convert-R1EvtxToJsonl -EvtxPath $EvtxPath -JsonlPath $JsonlPath)
        }
    }
}

function Test-R1RunLineage {
    <#
        Check, on the collected records, that the processes this run started form
        the lineage the scenario describes and that the final tool made the
        connection.

        The runner knows three process ids from its own steps: the remote session
        host, the intermediate it started and the final tool that reported ready.
        The records have to show exactly that chain through ParentProcessGuid,
        with the expected Image at each step, and - when a connection was made -
        an EID 3 carrying the final tool's ProcessGuid to the approved
        destination, recorded with the approved protocol. A record with another
        Protocol, or with none, is not that connection.

        No time is compared. The process ids tie the records to this run, and
        which raw time orders records is not decided (r1.md section 8-1, S-7).

        This only confirms that the run executed as designed. It does not decide
        whether a run is normal or an attack; both run types pass the same check
        with their own expected lineage.

        Returns status "matched", "lineage_only" (no connection was requested) or
        "mismatched", with a reason and the final tool's ProcessGuid.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Records,
        [Parameter(Mandatory = $true)][string]$ComputerName,
        [Parameter(Mandatory = $true)][int]$SessionPid,
        [Parameter(Mandatory = $true)][int]$IntermediatePid,
        [Parameter(Mandatory = $true)][int]$FinalPid,
        [Parameter(Mandatory = $true)][string[]]$ExpectedLineage,
        [AllowNull()]$Approval
    )

    $mismatch = {
        param($Reason)
        return [ordered]@{ status = "mismatched"; reason = $Reason; final_process_guid = $null }
    }

    $creates = @{}
    $connections = New-Object System.Collections.Generic.List[object]
    foreach ($record in $Records) {
        if ([string](Get-R1Value $record "Computer") -ne $ComputerName) { continue }

        $eventId = [string](Get-R1Value $record "EventId")
        $data = Get-R1Value $record "EventData"
        $guid = [string](Get-R1Value $data "ProcessGuid")
        if ($eventId -eq "1") {
            if ([string]::IsNullOrEmpty($guid)) { continue }
            if ($creates.ContainsKey($guid)) {
                return (& $mismatch ("duplicate EID 1 for ProcessGuid " + $guid))
            }
            $creates[$guid] = $data
        } elseif ($eventId -eq "3") {
            $connections.Add($data)
        }
    }

    $expectedIds = @($FinalPid, $IntermediatePid, $SessionPid)
    $labels = @("final tool", "intermediate", "session host")
    $chains = New-Object System.Collections.Generic.List[object]
    foreach ($guid in $creates.Keys) {
        if ([string](Get-R1Value $creates[$guid] "ProcessId") -ne [string]$FinalPid) { continue }

        $chain = New-Object System.Collections.Generic.List[object]
        $current = $creates[$guid]
        for ($index = 0; $index -lt 3; $index++) {
            if ($null -eq $current) { break }
            $chain.Add($current)
            $parentGuid = [string](Get-R1Value $current "ParentProcessGuid")
            if ($creates.ContainsKey($parentGuid)) { $current = $creates[$parentGuid] } else { $current = $null }
        }
        if ($chain.Count -ne 3) { continue }

        $fits = $true
        for ($index = 0; $index -lt 3; $index++) {
            if ([string](Get-R1Value $chain[$index] "ProcessId") -ne [string]$expectedIds[$index]) { $fits = $false }
        }
        if ($fits) { $chains.Add($chain) }
    }

    if ($chains.Count -eq 0) {
        return (& $mismatch ("no EID 1 chain links the final tool (pid " + $FinalPid +
            ") through the intermediate (pid " + $IntermediatePid + ") to the session host (pid " +
            $SessionPid + ") on " + $ComputerName))
    }
    if ($chains.Count -gt 1) {
        return (& $mismatch "more than one EID 1 chain fits the process ids of this run")
    }

    $chain = $chains[0]
    for ($index = 0; $index -lt 3; $index++) {
        $image = [string](Get-R1Value $chain[$index] "Image")
        $name = [System.IO.Path]::GetFileName($image)
        if ($name -ne $ExpectedLineage[$index]) {
            return (& $mismatch ("the " + $labels[$index] + " is '" + $name + "', the scenario expects '" +
                $ExpectedLineage[$index] + "'"))
        }
    }

    $finalGuid = [string](Get-R1Value $chain[0] "ProcessGuid")
    if ($null -eq $Approval) {
        return [ordered]@{
            status             = "lineage_only"
            reason             = "the lineage matches; no connection was requested"
            final_process_guid = $finalGuid
        }
    }

    # The approved connection is one protocol (Get-R1ConnectionApproval admits
    # only TCP). An approval that states none could be met by a record that
    # states none, so it accepts nothing.
    $approvedProtocol = [string](Get-R1Value $Approval "protocol")
    if ([string]::IsNullOrWhiteSpace($approvedProtocol)) {
        return [ordered]@{
            status             = "mismatched"
            reason             = "the approval states no protocol, so no EID 3 can be the approved connection"
            final_process_guid = $finalGuid
        }
    }

    $otherProtocols = New-Object System.Collections.Generic.List[string]
    foreach ($data in $connections) {
        if ([string](Get-R1Value $data "ProcessGuid") -ne $finalGuid) { continue }
        if ([string](Get-R1Value $data "DestinationIp") -ne [string]$Approval.target) { continue }
        if ([string](Get-R1Value $data "DestinationPort") -ne [string]$Approval.port) { continue }

        # Sysmon writes "tcp" and the scenario states "TCP": only case may differ.
        # Another Protocol, an empty one or a record without the field is kept
        # for the reason below and is never the approved connection.
        $recordedProtocol = [string](Get-R1Value $data "Protocol")
        if (-not [string]::Equals($recordedProtocol, $approvedProtocol,
                [System.StringComparison]::OrdinalIgnoreCase)) {
            if ([string]::IsNullOrWhiteSpace($recordedProtocol)) { $recordedProtocol = "(missing)" }
            if (-not $otherProtocols.Contains($recordedProtocol)) { $otherProtocols.Add($recordedProtocol) }
            continue
        }

        return [ordered]@{
            status             = "matched"
            reason             = "the lineage matches and the final tool made the approved connection"
            final_process_guid = $finalGuid
        }
    }

    if ($otherProtocols.Count -gt 0) {
        return [ordered]@{
            status             = "mismatched"
            reason             = ("an EID 3 with the final tool's ProcessGuid reaches the approved " +
                "destination, but none was recorded with the approved Protocol " + $approvedProtocol +
                ": recorded Protocol " + ($otherProtocols -join ", "))
            final_process_guid = $finalGuid
        }
    }

    return [ordered]@{
        status             = "mismatched"
        reason             = "no EID 3 with the final tool's ProcessGuid reaches the approved destination"
        final_process_guid = $finalGuid
    }
}

function Wait-R1Until {
    <# Sleep until a moment on the injected clock. Never sleeps for a moment already passed. #>
    param(
        [Parameter(Mandatory = $true)][datetime]$Due,
        [Parameter(Mandatory = $true)][scriptblock]$NowProvider,
        [Parameter(Mandatory = $true)][scriptblock]$Sleeper
    )

    $remaining = ($Due.ToUniversalTime() - (& $NowProvider).ToUniversalTime()).TotalSeconds
    if ($remaining -gt 0) {
        & $Sleeper ([int][Math]::Ceiling($remaining)) | Out-Null
    }
}

function Invoke-R1PilotRun {
    <#
        Run one R1-V02 Pilot run and write its artifacts.

        Order of side effects, so that a refusal leaves nothing behind:

          1. every input is validated and the launch plan is built (nothing is
             created; -DryRun returns here with the plan). The scenario file is
             read once, and those bytes are what the plan is built from,
          2. the run_id must not have produced output or an operator trace
             already,
          3. a pre-run session checks the Sysmon configuration on Target-A. Once
             it passes, the scenario bytes and their SHA-256 are kept in the
             operator trace of the run, before the first action,
          4. the scenario session runs the five actions at their offsets,
          5. the observation window is waited out,
          6. a collection session exports and fetches the Sysmon window,
          7. the collected records must show the lineage this run started,
          8. only then execution_record, run_metadata and the manifest are written.

        A failure at any step throws before step 8, so a failed run never has the
        three files a valid run has. A rehearsal skips the waits, may skip the
        connection, writes under _rehearsal and does not stop on step 7.

        Every run is marked dataset_tier=pilot in its operator trace, a
        rehearsal included. A dry run writes nothing, the trace included.

        Transport, NowProvider and Sleeper are the seams the guard tests replace.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$RunType,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$RunId,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$ScenarioJsonPath,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$DataRoot,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$WorkDir,
        [Parameter(Mandatory = $true)][int]$ObservationSec,
        [AllowEmptyString()][string]$VmSnapshot,
        [AllowEmptyString()][string]$TargetSysmonBinary,
        [AllowEmptyString()][string]$TargetSysmonConfigPath,
        [AllowEmptyString()][string]$ExpectedSysmonConfigSha256,
        [AllowNull()]$Connection,
        [AllowNull()][hashtable]$Transport,
        [scriptblock]$NowProvider = { Get-Date },
        [scriptblock]$Sleeper = { param($Seconds) Start-Sleep -Seconds $Seconds },
        [switch]$Rehearsal,
        [switch]$DryRun
    )

    $inputs = Assert-R1RunInputs -RunType $RunType -RunId $RunId -ScenarioJsonPath $ScenarioJsonPath `
        -DataRoot $DataRoot -WorkDir $WorkDir -ObservationSec $ObservationSec `
        -Rehearsal:$Rehearsal -DryRun:$DryRun
    $scenario = $inputs.scenario
    $identity = $inputs.identity
    $approval = $inputs.approval

    $plan = Get-R1LaunchPlan -Scenario $scenario -RunType $RunType -WorkDir $WorkDir
    Assert-R1PlanShortcutFree -Plan $plan

    $pairLine = ("pair: family_id=" + $identity.family_id + " variation_id=" + $identity.variation_id +
        " repetition=" + $identity.repetition)

    if ($DryRun) {
        Write-Ok ("dry run: " + $RunId + " (" + $RunType + ") would start " +
            $plan.intermediate.executable + " " + ($plan.intermediate.arguments -join " "))
        Write-Ok ("dry run: the final tool command is " + $plan.final.command_line)
        Write-Ok ("dry run: " + $pairLine)
        Write-Ok ("dry run: scenario sha256=" + $inputs.scenario_sha256)
        return [ordered]@{
            mode            = "dry_run"
            run_id          = $RunId
            run_type        = $RunType
            identity        = $identity
            plan            = $plan
            connection      = $approval
            actions         = @($inputs.actions | ForEach-Object { [string](Get-R1Value $_ "action_id") })
            scenario_sha256 = $inputs.scenario_sha256
        }
    }

    # Everything a real run needs beyond the plan. Checked before the first
    # session, so a missing value starts nothing.
    $targetHost = [string](Get-R1Value (Get-R1Value $scenario "run_metadata") "target_host")
    if ([string]::IsNullOrWhiteSpace($targetHost)) {
        throw "run_metadata.target_host is null; render scenario.json with --target-host"
    }
    if ([string]::IsNullOrWhiteSpace($VmSnapshot)) { throw "VmSnapshot is required" }
    if ([string]::IsNullOrWhiteSpace($TargetSysmonBinary)) { throw "TargetSysmonBinary is required" }
    if ([string]::IsNullOrWhiteSpace($TargetSysmonConfigPath)) { throw "TargetSysmonConfigPath is required" }
    if ($null -eq $Connection) { throw "Connection is required for a run that opens a session" }
    if ($null -eq $Transport) { throw "Transport is required for a run that opens a session" }
    foreach ($name in @("open", "invoke", "fetch", "close", "convert")) {
        if (-not $Transport.ContainsKey($name)) { throw ("Transport has no '" + $name + "' entry") }
    }

    $effectiveRoot = Get-EffectiveDataRoot -DataRoot $DataRoot -Rehearsal:$Rehearsal
    Assert-RunDirectoryAvailable -EffectiveRoot $effectiveRoot -RunId $RunId
    Assert-R1TraceAvailable -EffectiveRoot $effectiveRoot -RunId $RunId

    $mode = "collection"
    if ($Rehearsal) {
        $mode = "rehearsal"
        Write-Fail "rehearsal mode: offsets and the observation window are skipped. Artifacts are not a valid R1 run."
    }
    Write-Ok $pairLine

    $session = $null
    try {
        # --- 3. pre-run session ------------------------------------------------
        Write-Step "pre-run check of Target-A"
        $session = & $Transport.open $Connection
        $probe = & $Transport.invoke $session "probe" @{
            sysmon_binary      = $TargetSysmonBinary
            sysmon_config_path = $TargetSysmonConfigPath
            log_name           = $SYSMON_LOG
        }
        # The Controller reads its own clock as soon as the stamp of the target
        # arrives, so the two readings are apart by the way back at most.
        $clockStart = & $NowProvider
        & $Transport.close $session | Out-Null
        $session = $null

        # target_host has to be the name the records of this run will carry, so
        # the name Sysmon recorded is compared when the target could read one.
        # A mismatch found here costs nothing; found after the run it would cost
        # the whole observation window.
        $reportedName = [string](Get-R1Value $probe "recorded_computer_name")
        if ([string]::IsNullOrWhiteSpace($reportedName)) { $reportedName = [string]$probe.computer_name }
        if ($reportedName -ne $targetHost) {
            throw ("computer name mismatch: the target reports '" + $reportedName +
                "', run_metadata.target_host is '" + $targetHost + "'")
        }
        $configSha256 = [string]$probe.config_sha256
        if ($ExpectedSysmonConfigSha256 -and $configSha256 -ne $ExpectedSysmonConfigSha256.ToLower()) {
            throw "Sysmon config sha256 mismatch. expected=$ExpectedSysmonConfigSha256 actual=$configSha256"
        }
        Test-SysmonConfigApplied -ConfigSha256 $configSha256 -ConfigState $probe.sysmon -Rehearsal:$Rehearsal

        # The run starts at the stamp of the pre-run check. start_time is
        # Target-A's clock; the Controller clock, read when that stamp arrived,
        # only schedules the offsets and measures durations.
        $startTime = ConvertTo-R1Utc $probe.utc "probe utc"

        if ($Rehearsal) {
            New-Item -ItemType Directory -Path $effectiveRoot -Force | Out-Null
            $utf8NoBomMarker = New-Object System.Text.UTF8Encoding($false)
            [System.IO.File]::WriteAllText((Join-Path $effectiveRoot "REHEARSAL.txt"),
                "Rehearsal output. NOT a valid R1 collection. Do not use as data/raw or data/ground_truth.",
                $utf8NoBomMarker)
        }
        $telemetryDir = Join-Path $effectiveRoot "raw\$RunId\telemetry"
        $groundTruthDir = Join-Path $effectiveRoot "ground_truth\$RunId"
        foreach ($dir in @($telemetryDir, $groundTruthDir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }

        # Kept before the first action: from here on the record of this run_id
        # names the bytes its plan was built from, whatever happens to the file.
        $traceDir = Write-R1RunTrace -EffectiveRoot $effectiveRoot -RunId $RunId -Mode $mode `
            -ScenarioBytes $inputs.scenario_bytes -ScenarioSha256 $inputs.scenario_sha256
        Write-Ok ("operator trace written: dataset_tier=" + $R1_DATASET_TIER + " mode=" + $mode +
            " scenario sha256=" + $inputs.scenario_sha256)

        $context = [ordered]@{
            run_id               = $RunId
            run_type             = $RunType
            rehearsal            = [bool]$Rehearsal
            scenario             = $scenario
            run                  = $inputs.run
            start_time           = $startTime
            telemetry_dir        = $telemetryDir
            ground_truth_dir     = $groundTruthDir
            vm_snapshot          = $VmSnapshot
            sysmon_config_sha256 = $configSha256
            sysmon_config_state  = $probe.sysmon
            execution_records    = New-Object System.Collections.Generic.List[object]
            artifacts            = New-Object System.Collections.Generic.List[object]
        }
        Write-Ok ("run context ready: " + $RunId + " (" + $RunType + ") start " + (Get-UtcStamp $startTime))

        # --- 4. scenario session -----------------------------------------------
        $sessionPid = 0
        $launched = $null
        foreach ($action in $inputs.actions) {
            $actionId = [string](Get-R1Value $action "action_id")
            $step = [string](Get-R1Value $action "step")
            if (-not $Rehearsal) {
                Wait-R1Until -Due $clockStart.AddSeconds([int](Get-R1Value $action "offset_sec")) `
                    -NowProvider $NowProvider -Sleeper $Sleeper
            }
            Write-Step ($actionId + " " + $step)

            if ($step -eq "session_begin") {
                # Like every other action, t+0 is recorded as the moment it was
                # started, so the EID 1 of the session host comes after it. No
                # session exists yet to ask Target-A for the time, so it is the
                # pre-run stamp plus the time the Controller measured since.
                $elapsedMs = ((& $NowProvider).ToUniversalTime() - $clockStart.ToUniversalTime()).TotalMilliseconds
                $beginAt = $startTime.AddMilliseconds($elapsedMs)

                $session = & $Transport.open $Connection
                $begin = & $Transport.invoke $session "begin" @{}
                $sessionPid = [int]$begin.session_pid

                # The stamp Target-A takes once the session exists bounds it.
                $openedAt = ConvertTo-R1Utc $begin.utc "begin utc"
                if ($beginAt -gt $openedAt) {
                    throw ("the session was open at " + (Get-UtcStamp $openedAt) + " on the target, before the " +
                        "recorded start of that action (" + (Get-UtcStamp $beginAt) + "): a clock moved during the run")
                }
                Add-ExecutionRecord -Context $context -ActionId $actionId -Timestamp $beginAt
            } elseif ($step -eq "prepare") {
                $files = @{}
                foreach ($name in $plan.files.Keys) { $files[$name] = [string]$plan.files[$name] }
                $channelConfig = [ordered]@{
                    connect      = ($null -ne $approval)
                    target       = $null
                    port         = $null
                    protocol     = $null
                    lab_cidr     = $null
                    max_attempts = 1
                    timeout_ms   = $R1_CONNECT_TIMEOUT_MS
                    idle_sec     = $R1_TASK_IDLE_SEC
                }
                if ($null -ne $approval) {
                    $channelConfig.target = $approval.target
                    $channelConfig.port = $approval.port
                    $channelConfig.protocol = $approval.protocol
                    $channelConfig.lab_cidr = $approval.lab_cidr
                }
                $prepared = & $Transport.invoke $session "prepare" @{
                    work_dir       = $plan.work_dir
                    channel_dir    = $plan.channel_dir
                    files          = $files
                    config_file    = $R1_CONFIG_FILE
                    channel_config = ($channelConfig | ConvertTo-Json)
                    note_file      = $R1_PREPARED_NOTE
                }
                Add-ExecutionRecord -Context $context -ActionId $actionId `
                    -Timestamp (ConvertTo-R1Utc $prepared.utc "prepare utc")
            } elseif ($step -eq "launch") {
                $launched = & $Transport.invoke $session "launch" @{
                    executable  = $plan.intermediate.executable
                    arguments   = @($plan.intermediate.arguments)
                    work_dir    = $plan.work_dir
                    channel_dir = $plan.channel_dir
                    ready_file  = $R1_READY_FILE
                    timeout_sec = $R1_READY_TIMEOUT_SEC
                }
                Add-ExecutionRecord -Context $context -ActionId $actionId `
                    -Timestamp (ConvertTo-R1Utc $launched.utc "launch utc")
            } elseif ($step -eq "connect") {
                if ($null -eq $approval) {
                    # Only a rehearsal reaches this: a collection run without a
                    # destination was refused before the first session.
                    Write-Fail ($actionId + " skipped: no internal destination was injected (rehearsal)")
                } else {
                    $triggered = & $Transport.invoke $session "trigger" @{
                        channel_dir  = $plan.channel_dir
                        trigger_file = $R1_TRIGGER_FILE
                        status_file  = $R1_STATUS_FILE
                        timeout_sec  = $R1_STATUS_TIMEOUT_SEC
                    }
                    $status = $triggered.status
                    if (-not [bool]$status.success) {
                        throw ("internal connection did not succeed: timed_out=" + [string]$status.timed_out +
                            " error_kind=" + [string]$status.error_kind +
                            " attempts_made=" + [string]$status.attempts_made)
                    }
                    if ([string]$status.target -ne [string]$approval.target) {
                        throw ("the final tool connected to '" + [string]$status.target +
                            "', the approved destination is '" + [string]$approval.target + "'")
                    }
                    if ([string]$status.port -ne [string]$approval.port) {
                        throw ("the final tool connected to port " + [string]$status.port +
                            ", the approved port is " + [string]$approval.port)
                    }
                    if ([int]$status.attempts_made -ne 1) {
                        throw ("the final tool reported " + [string]$status.attempts_made +
                            " connection attempts, exactly 1 is allowed")
                    }
                    # The recorded time is when the tool attempted the connection,
                    # not when the trigger was written.
                    Add-ExecutionRecord -Context $context -ActionId $actionId `
                        -Timestamp (ConvertTo-R1Utc $status.started_utc "connection started_utc")
                }
            } elseif ($step -eq "session_end") {
                $ended = & $Transport.invoke $session "end" @{}
                & $Transport.close $session | Out-Null
                $session = $null
                Add-ExecutionRecord -Context $context -ActionId $actionId `
                    -Timestamp (ConvertTo-R1Utc $ended.utc "end utc")
            }
        }

        # --- 5. observation window ---------------------------------------------
        if ($Rehearsal) {
            Write-Fail "observation window skipped (rehearsal)"
        } else {
            Wait-R1Until -Due $clockStart.AddSeconds($ObservationSec) -NowProvider $NowProvider -Sleeper $Sleeper
        }

        # --- 6. collection session ---------------------------------------------
        Write-Step "collecting the Sysmon window from Target-A"
        $exportPath = $plan.work_dir + "\" + $R1_EXPORT_FILE
        $evtxPath = Join-Path $telemetryDir "sysmon-0001.evtx"
        $jsonlPath = Join-Path $telemetryDir "sysmon-0001.jsonl"

        # The target measures the window itself, from the start it stamped.
        $session = & $Transport.open $Connection
        $export = & $Transport.invoke $session "export" @{
            start_utc   = (Get-UtcStamp $startTime)
            margin_ms   = $EVTX_WINDOW_MARGIN_MS
            log_name    = $SYSMON_LOG
            event_ids   = @($SYSMON_EVENT_IDS)
            export_path = $exportPath
        }
        & $Transport.fetch $session ([string]$export.evtx_path) $evtxPath | Out-Null
        & $Transport.invoke $session "cleanup" @{ paths = @($plan.channel_dir, $exportPath) } | Out-Null
        & $Transport.close $session | Out-Null
        $session = $null

        $endTime = ConvertTo-R1Utc $export.utc "export utc"
        $eventCount = & $Transport.convert $evtxPath $jsonlPath
        foreach ($path in @($evtxPath, $jsonlPath)) {
            if (-not (Test-Path -LiteralPath $path)) { throw ("collection produced no file at " + $path) }
        }
        $context.artifacts.Add([ordered]@{ path = $evtxPath; source = "sysmon"; layer = "raw_telemetry" })
        $context.artifacts.Add([ordered]@{
            path = $jsonlPath; source = "sysmon"; layer = "raw_telemetry"; derived_from = $evtxPath
        })
        Write-Ok ("sysmon window collected: " + $eventCount + " events")

        # --- 7. lineage of this run ---------------------------------------------
        $records = @(Get-Content -LiteralPath $jsonlPath -Encoding UTF8 |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            ForEach-Object { $_ | ConvertFrom-Json })
        $lineage = Test-R1RunLineage -Records $records -ComputerName $targetHost `
            -SessionPid $sessionPid -IntermediatePid ([int]$launched.intermediate_pid) `
            -FinalPid ([int]$launched.final_pid) -ExpectedLineage ([string[]]$plan.expected_lineage) `
            -Approval $approval
        if ($lineage.status -eq "mismatched") {
            Write-Fail ("lineage: " + $lineage.status + " (" + $lineage.reason + ")")
        } else {
            Write-Ok ("lineage: " + $lineage.status + " (" + $lineage.reason + ")")
        }

        # Fail closed: a collection run writes its Ground Truth and manifest only
        # when the records show the designed lineage and the approved connection.
        if (-not $Rehearsal -and $lineage.status -ne "matched") {
            throw ("lineage check failed: " + $lineage.status + " (" + $lineage.reason + ")")
        }

        # --- 8. artifacts ---------------------------------------------------------
        Write-ExecutionRecord -Context $context | Out-Null
        Write-RunMetadata -Context $context -EndTime $endTime `
            -ReferenceTime $null -ReferenceActionId $null -ReferenceSourceEventId $null | Out-Null
        Write-RunManifest -Context $context | Out-Null

        Write-Ok ($RunType + " run finished: " + $RunId + " events=" + $eventCount +
            " actions=" + $context.execution_records.Count + " lineage=" + $lineage.status)

        return [ordered]@{
            mode             = $mode
            run_id           = $RunId
            run_type         = $RunType
            identity         = $identity
            events           = $eventCount
            actions          = $context.execution_records.Count
            lineage          = $lineage
            telemetry_dir    = $telemetryDir
            ground_truth_dir = $groundTruthDir
            trace_dir        = $traceDir
            dataset_tier     = $R1_DATASET_TIER
            scenario_sha256  = $inputs.scenario_sha256
        }
    }
    finally {
        # Closing the scenario session ends every process it started on Target-A.
        if ($null -ne $session) {
            try { & $Transport.close $session | Out-Null } catch { Write-Fail ("closing the session failed: " + $_.Exception.Message) }
        }
    }
}
