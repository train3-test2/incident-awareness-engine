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

# The runner side of the RecordId position-finality path; used only with -PositionFinality.
. (Join-Path $PSScriptRoot "r1-position-finality-common.ps1")

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

# The dataset tier belongs to the Pair. The rendered scenario states it once for
# both runs (tools/r1_scenario_to_json.py --dataset-tier) and the runner has no
# parameter for it: it reads the value, refuses one that is missing or is not one
# of these before anything is created, and writes it to the operator trace
# unchanged. "pilot" is every run outside the formal pools, and a rehearsal is
# always one. "development" and "holdout" are the two formal pools (README
# section 1-3).
$R1_DATASET_TIERS = @("pilot", "development", "holdout")
$R1_REHEARSAL_TIER = "pilot"

# The reference of an attack run (r1.md section 4-2) is taken from the Sysmon
# record of the session host that the session_begin action created, so that is
# the only action a scenario can name as the reference action. The time of a
# record is EventData.UtcTime in the form Sysmon writes it. TimeCreated is never
# read in its place.
$R1_REFERENCE_STEP = "session_begin"
$R1_EVENT_UTC_FORMAT = "yyyy-MM-dd HH:mm:ss.fff"

# How the raw telemetry of a family is collected. A scenario may state how the
# intermediate is started (planned_lineage.entry), which window the raw export
# covers and how readiness is established (collection), and where an attack run
# takes its reference from (reference_rule). A scenario that states none of them
# is run exactly as before. What may be stated together is the rule of
# src/incident_awareness/collection/r1_collection_profile.py, which the renderer
# and the validator read; this file repeats it, as it repeats the other checks
# of the renderer (docs/scenarios/r1-collection-profile.md).
$R1_ENTRY_REMOTING = "remoting_session"
$R1_ENTRY_WMI = "wmi_process"
$R1_ENTRY_KINDS = @($R1_ENTRY_REMOTING, $R1_ENTRY_WMI)
$R1_RAW_WINDOW_RUN = "run_window"
$R1_RAW_WINDOW_BOOT = "target_boot_to_run_end"
$R1_RAW_WINDOWS = @($R1_RAW_WINDOW_RUN, $R1_RAW_WINDOW_BOOT)
$R1_RAW_WINDOW_EXTENSION_REASON = "lineage_root_created_before_run"
$R1_READINESS_OUT_OF_BAND = "out_of_band"
$R1_READINESS_READY = "ready"
$R1_REFERENCE_SOURCE_SESSION_HOST = "session_host_process_create"
# An entry through WMI takes its reference from the process its launch action
# creates. A run of it has four actions, the same in both run types: the call
# through WMI that starts the intermediate (invoke), the start of the final
# tool by that intermediate (launch), the connection of the final tool
# (connect) and the end of the run (run_end). The four action types were
# handed over as decided. The step names are the ones the tests of this
# family already use; this file does not fix them as a contract.
# The session to the target and the files of the run are set up before the
# first action and are not actions.
$R1_REFERENCE_SOURCE_WMI_CREATED = "wmi_created_process_create"
$R1_REFERENCE_STEP_INVOKE = "invoke"
$R1_WMI_STEP_ORDER = @("invoke", "launch", "connect", "run_end")
$R1_WMI_ACTION_TYPES = @{
    invoke  = "wmi_process_create"
    launch  = "process_create"
    connect = "network_connection"
    run_end = "run_end"
}
# The intermediate of such a run is started long before it starts the final
# tool. It waits on a named pipe of the target until the run writes one word
# to it. A pipe of the local machine is not a network connection, reading
# from it starts no process, and both kinds of launcher wait the same way.
$R1_GATE_PIPE = "r1_gate"
$R1_GATE_WORD = "go"
$R1_GATE_TIMEOUT_SEC = 60
$R1_RUN_END_WAIT_SEC = 15

# A run whose scenario declares a collection block keeps two more files in its
# operator trace: the collection provenance, and the readiness record it was
# given when the scenario states a readiness method. Like the rest of the trace
# they are in no Manifest. The provenance states the version of its contract:
# the first one, written for a run through WMI. Nobody froze it.
$R1_PROVENANCE_FILE = "r1_wmi_collection_context.json"
$R1_SCHEMA_NAME = "r1-wmi-collection-context"
$R1_CONTRACT_VERSION = "v0.1"
$R1_CANONICAL_PROVENANCE_FILE = "r1_collection_provenance.json"
$R1_CANONICAL_CONTRACT_VERSION = "v0.1"
$R1_CONTEXT_RULE_VERSION = "r1-context-rule-v0.1"
$R1_SELECTOR_RAW_INPUT_SCOPE = "raw_collection_window"
$R1_CONTEXT_REASON = "parent_of_a_run_process_created_before_the_run"
$R1_READINESS_COPY_FILE = "r1_readiness_record.json"
# A run of such a scenario that fails once its trace exists leaves a record of
# the failure there, and none of the files a completed run ends with.
$R1_FAILURE_FILE = "r1_run_failure.json"

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

        With -GatePipe the launcher first waits: it reads one line from that
        named pipe of the local machine and goes on only when the line is the
        word of the run. A pipe that is not there, a pipe that is closed or
        any other line ends the launcher without starting anything. Without
        -GatePipe the text is the one it always was.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Kind,
        [Parameter(Mandatory = $true)][string]$CommandLine,
        [AllowEmptyString()][string]$GatePipe = ""
    )

    if (-not [string]::IsNullOrEmpty($GatePipe)) {
        if ($GatePipe -notmatch '^[A-Za-z0-9_]+$') {
            throw ("the gate pipe is not a plain name: '" + $GatePipe + "'")
        }
        if ($Kind -eq "batch") {
            return ("@echo off`r`n" +
                'set "R1GATE="' + "`r`n" +
                'set /p R1GATE=<\\.\pipe\' + $GatePipe + "`r`n" +
                'if not "%R1GATE%"=="' + $R1_GATE_WORD + '" exit /b 1' + "`r`n" +
                $CommandLine + "`r`n")
        }
        if ($Kind -eq "jscript") {
            $escaped = $CommandLine.Replace("\", "\\").Replace('"', '\"')
            return ('var fso = new ActiveXObject("Scripting.FileSystemObject");' + "`r`n" +
                'var gate = fso.OpenTextFile("\\\\.\\pipe\\' + $GatePipe + '", 1);' + "`r`n" +
                'var word = gate.ReadLine();' + "`r`n" +
                'gate.Close();' + "`r`n" +
                'if (word != "' + $R1_GATE_WORD + '") { WScript.Quit(1); }' + "`r`n" +
                'var shell = new ActiveXObject("WScript.Shell");' + "`r`n" +
                'WScript.Quit(shell.Run("' + $escaped + '", 0, true));' + "`r`n")
        }
        throw ("unknown launcher_kind '" + $Kind + "'; expected batch or jscript")
    }

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

    # How the intermediate is started. A scenario that states no entry is
    # launched as before, by the session host. The root of another entry is
    # recorded on Target-A like every other Image.
    $collectionProfile = Get-R1CollectionProfile -Scenario $Scenario
    $entryIsSession = ($collectionProfile.entry_kind -ceq $R1_ENTRY_REMOTING)
    if (-not $entryIsSession) {
        $exposedRoot = Get-R1ExposedLabelWord -Value $collectionProfile.root_image
        if ($null -ne $exposedRoot) {
            throw ("planned_lineage.entry.root_image would expose the run type on Target-A: '" +
                $collectionProfile.root_image + "' contains '" + $exposedRoot + "'")
        }
        # The intermediate is started at the first action and starts the final
        # tool at the second, so both launchers wait for the run in between.
        foreach ($type in $R1_RUN_TYPES) {
            $entry = Get-R1Value $intermediates $type
            $launchers[[string](Get-R1Value $entry "launcher_file")] = Get-R1LauncherContent `
                -Kind ([string](Get-R1Value $entry "launcher_kind")) -CommandLine $finalCommandLine `
                -GatePipe $R1_GATE_PIPE
        }
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

    $intermediate = [ordered]@{
        executable    = $images[$RunType]
        arguments     = $intermediateArguments
        launcher_path = $launcherPath
    }
    if (-not $entryIsSession) {
        # Started through WMI, the intermediate is handed over as one command
        # line. No argument may need quoting, so the line is the same text
        # whichever run builds it.
        foreach ($argument in $intermediateArguments) {
            if ($argument -match '[\s"]') {
                throw ("planned_lineage.intermediate." + $RunType + ".arguments holds an argument " +
                    "that would need quoting in a command line: '" + $argument + "'")
            }
        }
        $intermediate.command_line = $images[$RunType] + " " + ($intermediateArguments -join " ")
        $intermediate.gate_pipe = $R1_GATE_PIPE
    }

    return [ordered]@{
        run_type         = $RunType
        work_dir         = $WorkDir
        channel_dir      = $channelDir
        task_script      = $taskScript
        intermediate     = $intermediate
        final            = [ordered]@{
            executable   = $finalImage
            arguments    = $finalArguments
            command_line = $finalCommandLine
        }
        files            = $files
        # Closest first, the order a parent walk returns: final tool,
        # intermediate, and the root of the lineage. That is the remote session
        # host unless the scenario states another entry.
        expected_lineage = @($finalImage, $images[$RunType], $collectionProfile.root_image)
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

function Write-R1AtomicNewFile {
    <# Publish a new control file only after all bytes are durable in a sibling stage file. #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$Bytes
    )

    if (Test-Path -LiteralPath $Path) { throw "immutable control path already exists: $Path" }
    $stage = $Path + "." + [Guid]::NewGuid().ToString("N") + ".tmp"
    try {
        $stream = [System.IO.File]::Open($stage, [System.IO.FileMode]::CreateNew,
            [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
        try {
            $stream.Write($Bytes, 0, $Bytes.Length)
            $stream.Flush($true)
        } finally {
            $stream.Dispose()
        }
        [System.IO.File]::Move($stage, $Path)
    } finally {
        if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Force }
    }
}

function Get-R1DatasetTier {
    <#
        The dataset tier a rendered scenario states for its Pair.

        The scenario is the only source, as it is for the identity of the Pair:
        both runs read one rendered file and therefore record one tier. Nothing
        stands in for a value that is missing, null or empty. The comparison is
        exact: "Pilot" or " development" is not a tier, and a value that is not
        a string is none. A rehearsal is never formal data, so its scenario has
        to state "pilot".
    #>
    param(
        [Parameter(Mandatory = $true)]$Scenario,
        [switch]$Rehearsal
    )

    $value = Get-R1Value $Scenario "dataset_tier"
    if ($null -eq $value -or ($value -is [string] -and $value.Length -eq 0)) {
        throw ("dataset_tier is missing from the scenario: one of " + ($R1_DATASET_TIERS -join ", ") +
            ". There is no default; state it when rendering scenario.json (--dataset-tier)")
    }
    if ($value -isnot [string] -or -not ($R1_DATASET_TIERS -ccontains $value)) {
        throw ("dataset_tier must be one of " + ($R1_DATASET_TIERS -join ", ") + ", found '" +
            [string]$value + "'")
    }
    if ($Rehearsal -and $value -cne $R1_REHEARSAL_TIER) {
        throw ("a rehearsal is not formal data: its scenario has to state dataset_tier " +
            $R1_REHEARSAL_TIER + ", found '" + $value + "'")
    }
    return $value
}

function Write-R1RunTrace {
    <#
        Keep what ties this run to the scenario it executes.

        Two files are written, each exactly once, under
        <root>\operator_trace\<run_id>\:

            scenario.json        the bytes the plan of this run was built from
            r1_run_trace.json    run_id, mode, the dataset tier the scenario
                                 states and the SHA-256 of those bytes

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
        [Parameter(Mandatory = $true)]$Scenario,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$ScenarioBytes,
        [Parameter(Mandatory = $true)][string]$ScenarioSha256
    )

    # Read again where the value is written, from the scenario and from nowhere
    # else: a trace never carries a tier its scenario does not state.
    $datasetTier = Get-R1DatasetTier -Scenario $Scenario -Rehearsal:($Mode -eq "rehearsal")
    Assert-R1TraceAvailable -EffectiveRoot $EffectiveRoot -RunId $RunId
    $traceDir = Get-R1TraceDirectory -EffectiveRoot $EffectiveRoot -RunId $RunId
    New-Item -ItemType Directory -Path $traceDir -Force | Out-Null

    Write-R1NewFile -Path (Join-Path $traceDir $R1_TRACE_SCENARIO_FILE) -Bytes $ScenarioBytes

    $trace = [ordered]@{
        trace_version   = $R1_TRACE_VERSION
        run_id          = $RunId
        dataset_tier    = $datasetTier
        mode            = $Mode
        scenario_sha256 = $ScenarioSha256
    }
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    Write-R1NewFile -Path (Join-Path $traceDir $R1_TRACE_FILE) `
        -Bytes $utf8NoBom.GetBytes(($trace | ConvertTo-Json))

    return $traceDir
}

function Test-R1Stated {
    <# Whether a parsed JSON object or a dictionary states a key at all, whatever its value. #>
    param([AllowNull()]$Object, [Parameter(Mandatory = $true)][string]$Name)

    if ($null -eq $Object) { return $false }
    if ($Object -is [System.Collections.IDictionary]) { return $Object.Contains($Name) }
    return ($null -ne $Object.PSObject.Properties[$Name])
}

function Assert-R1Keys {
    <#
        Stop unless a block is an object that states exactly the given keys.

        A key this file does not know could be read as a switch it does not
        have, so an unknown key is refused like a missing one.
    #>
    param(
        [AllowNull()]$Object,
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][string[]]$Keys
    )

    $names = $null
    if ($Object -is [System.Collections.IDictionary]) {
        $names = @($Object.Keys | ForEach-Object { [string]$_ })
    } elseif ($Object -is [System.Management.Automation.PSCustomObject]) {
        $names = @($Object.PSObject.Properties | ForEach-Object { [string]$_.Name })
    }
    if ($null -eq $names) { throw ($Label + " must be a mapping") }

    $unknown = @($names | Where-Object { -not ($Keys -ccontains $_) } | Sort-Object)
    if ($unknown.Count -gt 0) { throw ($Label + " states unknown key(s): " + ($unknown -join ", ")) }
    $missing = @($Keys | Where-Object { -not ($names -ccontains $_) })
    if ($missing.Count -gt 0) { throw ($Label + " is missing: " + ($missing -join ", ")) }
}

function Get-R1CollectionProfile {
    <#
        How the scenario says its raw telemetry is collected.

        Returns the entry kind and the root of the planned lineage, the raw
        window, the readiness method ($null when none is stated), the reference
        rule and whether a collection block is declared. A scenario that states
        none of this gets the values every run had before: the session host
        starts the intermediate, the export covers the run window and the
        reference of an attack run is the record of the session host its first
        action creates. An entry through WMI has to state its own rule: the
        record of the process its launch action creates.

        A value or a combination that could not be collected throws here, before
        anything is created. The same rule, with the reasons, is
        src/incident_awareness/collection/r1_collection_profile.py.
    #>
    param([Parameter(Mandatory = $true)]$Scenario)

    $lineage = Get-R1Value $Scenario "planned_lineage"
    if ($null -eq $lineage) { throw "planned_lineage is missing from the scenario" }
    $sessionHostImage = [string](Get-R1Value (Get-R1Value $lineage "session_host") "image")
    if ([string]::IsNullOrWhiteSpace($sessionHostImage)) { throw "planned_lineage.session_host.image is missing" }

    # --- entry: how the intermediate is started --------------------------------
    $entryKind = $R1_ENTRY_REMOTING
    $rootImage = $sessionHostImage
    if (Test-R1Stated $lineage "entry") {
        $entry = Get-R1Value $lineage "entry"
        Assert-R1Keys -Object $entry -Label "planned_lineage.entry" -Keys @("kind", "root_image")

        $entryKind = Get-R1Value $entry "kind"
        if ($entryKind -isnot [string] -or -not ($R1_ENTRY_KINDS -ccontains $entryKind)) {
            throw ("planned_lineage.entry.kind must be one of " + ($R1_ENTRY_KINDS -join ", ") +
                ", found '" + [string]$entryKind + "'")
        }
        $statedRoot = Get-R1Value $entry "root_image"
        if ($statedRoot -isnot [string] -or $statedRoot -notmatch '^[A-Za-z0-9_.-]+$') {
            throw ("planned_lineage.entry.root_image must be a plain file name, found '" +
                [string]$statedRoot + "'")
        }
        $same = [string]::Equals($statedRoot, $sessionHostImage, [System.StringComparison]::OrdinalIgnoreCase)
        if ($entryKind -ceq $R1_ENTRY_REMOTING -and -not $same) {
            throw ("planned_lineage.entry.root_image must be planned_lineage.session_host.image for " +
                $R1_ENTRY_REMOTING + ": the session host starts the intermediate; found '" +
                $statedRoot + "' and '" + $sessionHostImage + "'")
        }
        if ($entryKind -cne $R1_ENTRY_REMOTING) {
            if ($same) {
                throw ("planned_lineage.entry.root_image must not be the session host image for " +
                    $entryKind + ": the intermediate is not started by the session host; found '" +
                    $statedRoot + "'")
            }
            $rootImage = $statedRoot
        }
    }

    # --- collection: what the raw export covers --------------------------------
    $rawWindow = $R1_RAW_WINDOW_RUN
    $readinessMethod = $null
    $declared = Test-R1Stated $Scenario "collection"
    if ($declared) {
        $collection = Get-R1Value $Scenario "collection"
        Assert-R1Keys -Object $collection -Label "collection" -Keys @("raw_window", "readiness_method")

        $rawWindow = Get-R1Value $collection "raw_window"
        if ($rawWindow -isnot [string] -or -not ($R1_RAW_WINDOWS -ccontains $rawWindow)) {
            throw ("collection.raw_window must be one of " + ($R1_RAW_WINDOWS -join ", ") +
                ", found '" + [string]$rawWindow + "'")
        }
        $readinessMethod = Get-R1Value $collection "readiness_method"
        if ($null -ne $readinessMethod -and
            ($readinessMethod -isnot [string] -or $readinessMethod -cne $R1_READINESS_OUT_OF_BAND)) {
            throw ("collection.readiness_method must be " + $R1_READINESS_OUT_OF_BAND +
                " or null, found '" + [string]$readinessMethod + "'")
        }
    }
    # The root of a lineage that is not started in the run is created at boot.
    # Its record is only in a raw export that starts there.
    if ($entryKind -ceq $R1_ENTRY_WMI -and $rawWindow -cne $R1_RAW_WINDOW_BOOT) {
        throw ("collection.raw_window must be " + $R1_RAW_WINDOW_BOOT + " for " + $R1_ENTRY_WMI +
            ": the provider host is created when the target boots, so a run window does not hold " +
            "the root of the lineage; found '" + [string]$rawWindow + "'")
    }
    # A family whose root is created in the run has no reason to collect more.
    if ($entryKind -ceq $R1_ENTRY_REMOTING -and $rawWindow -cne $R1_RAW_WINDOW_RUN) {
        throw ("collection.raw_window must be " + $R1_RAW_WINDOW_RUN + " for " + $R1_ENTRY_REMOTING +
            ": the session host is created in the run; found '" + [string]$rawWindow + "'")
    }
    # Everything before the run is in an extended window, a readiness connection included.
    if ($rawWindow -ceq $R1_RAW_WINDOW_BOOT -and $readinessMethod -cne $R1_READINESS_OUT_OF_BAND) {
        throw ("collection.readiness_method must be " + $R1_READINESS_OUT_OF_BAND + " when " +
            "collection.raw_window is " + $R1_RAW_WINDOW_BOOT + ": a connection opened from the " +
            "target before the run would be collected; found '" + [string]$readinessMethod + "'")
    }

    # --- reference rule: where an attack run takes its reference from -----------
    # Each entry kind has one source. The record of the session host needs the
    # session host to be in the lineage and is the rule of a scenario that
    # states none. An entry through WMI has no rule by default: it states the
    # record of the process its launch action creates.
    $implementedSource = $R1_REFERENCE_SOURCE_SESSION_HOST
    $implementedStep = $R1_REFERENCE_STEP
    if ($entryKind -ceq $R1_ENTRY_WMI) {
        $implementedSource = $R1_REFERENCE_SOURCE_WMI_CREATED
        $implementedStep = $R1_REFERENCE_STEP_INVOKE
    }
    $referenceStep = $R1_REFERENCE_STEP
    $referenceSource = $R1_REFERENCE_SOURCE_SESSION_HOST
    if (Test-R1Stated $Scenario "reference_rule") {
        $rule = Get-R1Value $Scenario "reference_rule"
        Assert-R1Keys -Object $rule -Label "reference_rule" -Keys @("action_step", "source")
        $referenceStep = Get-R1Value $rule "action_step"
        $referenceSource = Get-R1Value $rule "source"

        if ($referenceSource -isnot [string] -or $referenceSource -cne $implementedSource) {
            throw ("reference_rule.source '" + [string]$referenceSource + "' is not implemented for " +
                $entryKind + "; implemented: " + $implementedSource)
        }
        if ($referenceStep -isnot [string] -or $referenceStep -cne $implementedStep) {
            throw ("reference_rule.action_step must be " + $implementedStep + " for the source " +
                $referenceSource + ", found '" + [string]$referenceStep + "'")
        }
    } elseif ($entryKind -cne $R1_ENTRY_REMOTING) {
        throw ("reference_rule must be stated for " + $entryKind + ": the session host is not in the " +
            "lineage, so the rule of a scenario that states none does not apply; implemented: " +
            $implementedSource)
    }

    # Both runs do the same things in the same order, so both record them with
    # the same types. The session entry leaves its types to the scenario.
    $stepOrder = $R1_STEP_ORDER
    if ($entryKind -ceq $R1_ENTRY_WMI) {
        $stepOrder = $R1_WMI_STEP_ORDER
        foreach ($runType in $R1_RUN_TYPES) {
            $runBlock = Get-R1Value (Get-R1Value $Scenario "runs") $runType
            $runActions = @(Get-R1Value $runBlock "actions" | Where-Object { $null -ne $_ })
            $runSteps = @($runActions | ForEach-Object { [string](Get-R1Value $_ "step") })
            if (($runSteps -join ",") -cne ($R1_WMI_STEP_ORDER -join ",")) {
                throw ("runs." + $runType + " steps must be " + ($R1_WMI_STEP_ORDER -join ", ") +
                    " in that order for a " + $entryKind + " scenario, found " + ($runSteps -join ", "))
            }
            foreach ($action in $runActions) {
                $stepName = [string](Get-R1Value $action "step")
                $actionType = Get-R1Value $action "action_type"
                if ($actionType -isnot [string] -or $actionType -cne $R1_WMI_ACTION_TYPES[$stepName]) {
                    throw ("runs." + $runType + ": the " + $stepName + " action of a " + $entryKind +
                        " scenario is recorded as " + $R1_WMI_ACTION_TYPES[$stepName] + ", found '" +
                        [string]$actionType + "'")
                }
            }
        }
    }

    return [ordered]@{
        entry_kind          = [string]$entryKind
        root_image          = [string]$rootImage
        session_host_image  = $sessionHostImage
        raw_window          = [string]$rawWindow
        readiness_method    = $readinessMethod
        reference_step      = [string]$referenceStep
        reference_source    = [string]$referenceSource
        step_order          = [string[]]$stepOrder
        collection_declared = [bool]$declared
    }
}

function Read-R1ReadinessRecord {
    <#
        Read the readiness record an out-of-band check wrote before the run.

        A run whose raw export starts at the boot of the target cannot check
        readiness by connecting from the target: that connection would be in the
        export. Readiness is established from outside the target instead, and
        the result is handed to the run as this record. It has to say that the
        method was out_of_band, that the result is ready and, as a boolean, that
        no active TCP probe was used. A record that is missing, unreadable or
        says anything else throws, so the run starts nothing.

        Returns the four values, the time of the check, the bytes of the record
        and their SHA-256.
    #>
    param([AllowNull()][AllowEmptyString()][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw ("the readiness record is missing: '" + [string]$Path + "'. This scenario states " +
            "collection.readiness_method " + $R1_READINESS_OUT_OF_BAND + ", so the run needs the " +
            "record of that check (-ReadinessRecordPath)")
    }

    $bytes = [System.IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $Path).ProviderPath)
    $strictUtf8 = New-Object System.Text.UTF8Encoding($false, $true)
    $record = $null
    try {
        $text = $strictUtf8.GetString($bytes)
        if ($text.Length -gt 0 -and $text[0] -eq [char]0xFEFF) { $text = $text.Substring(1) }
        $record = $text | ConvertFrom-Json
    } catch {
        throw ("the readiness record is not readable JSON: '" + $Path + "'")
    }
    if ($record -isnot [System.Management.Automation.PSCustomObject]) {
        throw ("the readiness record is not a JSON object: '" + $Path + "'")
    }
    foreach ($name in @("method", "checked_at", "result", "active_tcp_probe_used")) {
        if (-not (Test-R1Stated $record $name)) { throw ("the readiness record states no " + $name) }
    }

    if ($record.method -isnot [string] -or $record.method -cne $R1_READINESS_OUT_OF_BAND) {
        throw ("the readiness record states the method '" + [string]$record.method + "', expected " +
            $R1_READINESS_OUT_OF_BAND)
    }
    if ($record.result -isnot [string] -or $record.result -cne $R1_READINESS_READY) {
        throw ("the readiness record states the result '" + [string]$record.result +
            "'; the run is not started unless it is " + $R1_READINESS_READY)
    }
    # Stated as a boolean and false. A missing value, a string or true is not a
    # statement that nothing connected from the target before the run.
    if ($record.active_tcp_probe_used -isnot [bool] -or $record.active_tcp_probe_used) {
        throw ("the readiness record must state active_tcp_probe_used as false, found '" +
            [string]$record.active_tcp_probe_used + "': nothing connects from the target before the run")
    }
    $checkedAt = ConvertTo-R1Utc $record.checked_at "readiness checked_at"

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $digest = -join ($sha256.ComputeHash($bytes) | ForEach-Object { $_.ToString("x2") })
    } finally {
        $sha256.Dispose()
    }

    return [ordered]@{
        method                = $R1_READINESS_OUT_OF_BAND
        checked_at            = (Get-UtcStamp $checkedAt)
        checked_at_time       = $checkedAt
        result                = $R1_READINESS_READY
        active_tcp_probe_used = $false
        record_sha256         = $digest
        bytes                 = $bytes
    }
}

function ConvertTo-R1EventUtc {
    <#
        EventData.UtcTime of one record as a UTC time.

        It is the only time of a record that is read. A record without a
        readable one throws: TimeCreated and the position of the record in the
        file are not read in its place.
    #>
    param([AllowNull()]$Value, [Parameter(Mandatory = $true)][string]$Label)

    $parsed = [datetime]::MinValue
    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor
        [System.Globalization.DateTimeStyles]::AdjustToUniversal
    if ($Value -isnot [string] -or -not [datetime]::TryParseExact($Value, $R1_EVENT_UTC_FORMAT,
            [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$parsed)) {
        throw ($Label + " carries no readable EventData.UtcTime ('" + [string]$Value +
            "'); no other field is read in its place")
    }
    return $parsed
}

function Get-R1CollectionProvenance {
    <#
        Build the collection provenance of one run from its collected records.

        Three things are kept apart. The raw collection window is what the
        export holds. The observation is the inclusive interval from the start
        to the end of the run: a record before it is context, and a record after
        it stays raw but is not an evaluation input. The
        evaluation of a run that has a reference ends at its reference time plus
        the evaluation horizon; a run without a reference has none.

        A context record restores a lineage and nothing else. The provenance
        names the three records of the lineage, which of them are context and
        which record of the run refers to a context record through its
        ParentProcessGuid. Records are named by RecordId, which is also what an
        Evidence refers to its source records by.

        The provenance also says how the reference of the run was found and
        which reference policy version the scenario names. The identity of a
        registered reference policy - its id, its file, its hash, what loads it
        - is left null: none is registered for a run to have read. Where the
        records come from (raw_source) is filled in when the record is written.

        Returns the provenance without its three hashes, and the problems that
        make the run unusable: a connection from the target to the internal
        destination before the run, anything but one such connection in the run,
        or a lineage that is not three records with the final tool and the
        intermediate created in the run. A record without a readable
        EventData.UtcTime throws.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$RunId,
        [Parameter(Mandatory = $true)][string]$FamilyId,
        [Parameter(Mandatory = $true)]$CollectionProfile,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Records,
        [Parameter(Mandatory = $true)][string]$ComputerName,
        [Parameter(Mandatory = $true)][datetime]$RawCollectionStart,
        [Parameter(Mandatory = $true)][datetime]$StartTime,
        [Parameter(Mandatory = $true)][datetime]$EndTime,
        [AllowNull()][AllowEmptyString()][string]$ReferenceTime,
        [Parameter(Mandatory = $true)][int]$EvaluationHorizonSec,
        [AllowNull()][AllowEmptyString()][string]$FinalProcessGuid,
        [AllowNull()]$Approval,
        [AllowNull()]$Readiness,
        [AllowNull()]$ReferenceResolution,
        [AllowNull()]$CreatedProcess,
        [AllowNull()]$PolicyProvenance,
        [AllowNull()][AllowEmptyCollection()][object[]]$Actions,
        [AllowNull()][AllowEmptyString()][string]$TargetBootUtc,
        [AllowNull()][AllowEmptyString()][string]$BootSessionId,
        [string]$ScenarioId = "",
        [string]$VariationId = "",
        [string]$ScenarioVersion = "",
        [AllowNull()][int[]]$RecordLines
    )

    $problems = New-Object System.Collections.Generic.List[string]
    $start = $StartTime.ToUniversalTime()
    $end = $EndTime.ToUniversalTime()
    $rawEnd = $end
    # The line of each record in the raw file, 1-based. Without the lines the
    # records are taken to be one per line, in order.
    if ($null -ne $RecordLines -and $RecordLines.Count -ne $Records.Count) {
        throw ("the raw file holds " + $Records.Count + " record(s) and " + $RecordLines.Count +
            " line number(s); a record cannot be named by its line")
    }

    # --- every record is placed by EventData.UtcTime alone ----------------------
    $contextCount = 0
    $afterObservationCount = 0
    $creates = @{}
    $duplicates = New-Object System.Collections.Generic.List[string]
    $reaching = New-Object System.Collections.Generic.List[object]
    for ($position = 0; $position -lt $Records.Count; $position++) {
        $record = $Records[$position]
        $recordNo = $position + 1
        if ($null -ne $RecordLines) { $recordNo = [int]$RecordLines[$position] }
        $recordId = [string](Get-R1Value $record "RecordId")
        $data = Get-R1Value $record "EventData"
        $moment = ConvertTo-R1EventUtc (Get-R1Value $data "UtcTime") ("record " + $recordId)
        $zone = "observation"
        if ($moment -lt $start) { $zone = "context"; $contextCount++ }
        elseif ($moment -gt $end) { $zone = "after_observation"; $afterObservationCount++ }
        if ($moment -gt $rawEnd) { $rawEnd = $moment }

        if ([string](Get-R1Value $record "Computer") -ne $ComputerName) { continue }
        $eventId = [string](Get-R1Value $record "EventId")
        $guid = [string](Get-R1Value $data "ProcessGuid")
        $item = [ordered]@{ record_id = $recordId; record_no = $recordNo; data = $data; zone = $zone }
        if ($eventId -eq "1") {
            if ([string]::IsNullOrEmpty($guid)) { continue }
            if ($creates.ContainsKey($guid)) { $duplicates.Add($guid) } else { $creates[$guid] = $item }
        } elseif ($eventId -eq "3" -and $null -ne $Approval) {
            if ([string](Get-R1Value $data "DestinationIp") -ne [string]$Approval.target) { continue }
            if ([string](Get-R1Value $data "DestinationPort") -ne [string]$Approval.port) { continue }
            if (-not [string]::Equals([string](Get-R1Value $data "Protocol"), [string]$Approval.protocol,
                    [System.StringComparison]::OrdinalIgnoreCase)) { continue }
            $reaching.Add($item)
        }
    }
    foreach ($guid in $duplicates) { $problems.Add("duplicate EID 1 for ProcessGuid " + $guid) }

    # --- the lineage: three process-create records linked by ProcessGuid only -----
    $roles = @("final_tool", "intermediate", "root")
    $nodes = New-Object System.Collections.Generic.List[object]
    $current = $null
    if (-not [string]::IsNullOrEmpty($FinalProcessGuid) -and $creates.ContainsKey($FinalProcessGuid)) {
        $current = $creates[$FinalProcessGuid]
    }
    while ($null -ne $current -and $nodes.Count -lt $roles.Count) {
        $nodes.Add($current)
        # The parent is found by its own process-create record. ParentImage and
        # process ids are not read: a parent without a record ends the walk.
        $parentGuid = [string](Get-R1Value $current.data "ParentProcessGuid")
        if (-not [string]::IsNullOrEmpty($parentGuid) -and $creates.ContainsKey($parentGuid)) {
            $current = $creates[$parentGuid]
        } else {
            $current = $null
        }
    }

    $lineageRecords = New-Object System.Collections.Generic.List[object]
    for ($index = 0; $index -lt $nodes.Count; $index++) {
        $node = $nodes[$index]
        $image = Get-R1Value $node.data "Image"
        if ($image -is [string]) { $image = $image.Trim() }
        $parentGuid = Get-R1Value $node.data "ParentProcessGuid"
        if ($parentGuid -is [string]) { $parentGuid = $parentGuid.Trim() }
        if ([string]::IsNullOrEmpty([string]$parentGuid)) { $parentGuid = $null }
        $lineageRecords.Add([ordered]@{
            role                = $roles[$index]
            record_id           = $node.record_id
            process_guid        = [string](Get-R1Value $node.data "ProcessGuid")
            parent_process_guid = $parentGuid
            image               = $image
            utc_time            = [string](Get-R1Value $node.data "UtcTime")
            zone                = $node.zone
            record_no           = [int]$node.record_no
        })
    }
    if ($nodes.Count -ne $roles.Count) {
        $problems.Add("the lineage of the final tool is " + $nodes.Count + " process-create record(s) " +
            "linked by ProcessGuid, not " + $roles.Count)
    } else {
        foreach ($index in @(0, 1)) {
            if ($lineageRecords[$index].zone -ne "observation") {
                $problems.Add("the " + $lineageRecords[$index].role + " of the lineage (RecordId " +
                    $lineageRecords[$index].record_id + ") was created outside the observation interval")
            }
        }
    }

    $contextIds = New-Object System.Collections.Generic.List[string]
    $references = New-Object System.Collections.Generic.List[object]
    for ($index = 0; $index -lt $lineageRecords.Count; $index++) {
        $child = $lineageRecords[$index]
        if ($child.zone -eq "context") { $contextIds.Add($child.record_id) }
        if ($index + 1 -ge $lineageRecords.Count) { continue }
        $parent = $lineageRecords[$index + 1]
        # A record of the run whose parent is a context record: the link through
        # which a context record reaches the run.
        if ($child.zone -eq "observation" -and $parent.zone -eq "context") {
            $references.Add([ordered]@{
                record_id           = $child.record_id
                role                = $child.role
                parent_process_guid = $child.parent_process_guid
                context_record_id   = $parent.record_id
            })
        }
    }

    # --- connections of the target to the internal destination ------------------
    $connection = $null
    if ($null -ne $Approval) {
        $before = @($reaching | Where-Object { $_.zone -eq "context" } | ForEach-Object { $_.record_id })
        $during = @($reaching | Where-Object { $_.zone -eq "observation" } | ForEach-Object { $_.record_id })
        if ($before.Count -gt 0) {
            $problems.Add("the target connected to the internal destination before the start of the run " +
                "(RecordId " + ($before -join ", ") + "): nothing connects before the run, and that " +
                "connection is not the one the scenario makes")
        }
        if ($during.Count -ne 1) {
            $problems.Add([string]$during.Count + " connection(s) of the target reach the internal " +
                "destination in the run; the scenario makes exactly one")
        }
        $ofFinalTool = @($reaching | Where-Object {
                [string](Get-R1Value $_.data "ProcessGuid") -eq [string]$FinalProcessGuid })
        if ($ofFinalTool.Count -eq 1) {
            $connection = [ordered]@{
                record_id    = $ofFinalTool[0].record_id
                process_guid = [string](Get-R1Value $ofFinalTool[0].data "ProcessGuid")
                utc_time     = [string](Get-R1Value $ofFinalTool[0].data "UtcTime")
                zone         = $ofFinalTool[0].zone
                record_no    = [int]$ofFinalTool[0].record_no
            }
        }
    }

    # --- the three windows -------------------------------------------------------
    $extensionReason = $null
    if ($CollectionProfile.raw_window -eq $R1_RAW_WINDOW_BOOT) { $extensionReason = $R1_RAW_WINDOW_EXTENSION_REASON }
    $evaluationReference = $null
    $evaluationEnd = $null
    if (-not [string]::IsNullOrEmpty($ReferenceTime)) {
        $referenceMoment = ConvertTo-R1Utc $ReferenceTime "reference_time"
        if ($referenceMoment -lt $start) {
            $problems.Add("the reference time of the run is before its start: a context record " +
                "cannot be the reference of an evaluation")
        }
        # The evaluation ends at the reference plus the horizon, and never
        # after the end of the run.
        $evaluationReference = (Get-UtcStamp $referenceMoment)
        $horizonMoment = $referenceMoment.AddSeconds($EvaluationHorizonSec)
        if ($EndTime.ToUniversalTime() -lt $horizonMoment) { $horizonMoment = $EndTime.ToUniversalTime() }
        $evaluationEnd = (Get-UtcStamp $horizonMoment)
    }

    $readinessBlock = $null
    if ($null -ne $Readiness) {
        $readinessBlock = [ordered]@{
            method                = $Readiness.method
            checked_at            = $Readiness.checked_at
            result                = $Readiness.result
            active_tcp_probe_used = [bool]$Readiness.active_tcp_probe_used
            record_sha256         = $Readiness.record_sha256
        }
    }

    # The context records the lineage was restored from, each named by its
    # RecordId and its line in the raw file, with why it is used.
    $contextEvents = New-Object System.Collections.Generic.List[object]
    foreach ($lineageRecord in $lineageRecords) {
        if ($lineageRecord.zone -ne "context") { continue }
        $contextEvents.Add([ordered]@{
            record_id = $lineageRecord.record_id
            record_no = [int]$lineageRecord.record_no
            role      = $lineageRecord.role
            reason    = $R1_CONTEXT_REASON
        })
    }
    $bootUtc = $null
    if (-not [string]::IsNullOrWhiteSpace($TargetBootUtc)) { $bootUtc = $TargetBootUtc }
    $bootSession = $null
    if (-not [string]::IsNullOrWhiteSpace($BootSessionId)) { $bootSession = $BootSessionId }
    $actionList = @()
    if ($null -ne $Actions) { $actionList = @($Actions) }
    # The linkage to the Role2 canonical artifact. It records the canonical
    # filename and contract and the reference-policy identity this collection
    # used, read from the scenario the renderer resolved. It does not restate
    # the canonical reference values. canonical_sha256 is null: the canonical
    # artifact is written on another path, and a reader compares it then.
    $referencePolicyId = ""
    $referencePolicyVersion = ""
    $referencePolicyHash = ""
    if ($null -ne $PolicyProvenance) {
        $referencePolicyId = [string](Get-R1Value $PolicyProvenance.reference "policy_id")
        $referencePolicyVersion = [string](Get-R1Value $PolicyProvenance.reference "version")
        $referencePolicyHash = [string](Get-R1Value $PolicyProvenance.reference "config_hash")
    }
    $canonicalLinkage = [ordered]@{
        filename                     = $R1_CANONICAL_PROVENANCE_FILE
        contract_version             = $R1_CANONICAL_CONTRACT_VERSION
        reference_policy_id          = $referencePolicyId
        reference_policy_version     = $referencePolicyVersion
        reference_policy_config_hash = $referencePolicyHash
        canonical_sha256             = $null
    }

    $provenance = [ordered]@{
        schema                             = $R1_SCHEMA_NAME
        contract_version                   = $R1_CONTRACT_VERSION
        run_id                             = $RunId
        target_host                        = $ComputerName
        scenario                           = [ordered]@{
            scenario_id      = $ScenarioId
            family_id        = $FamilyId
            variation_id     = $VariationId
            scenario_version = $ScenarioVersion
        }
        entry_kind                         = $CollectionProfile.entry_kind
        raw_window                         = $CollectionProfile.raw_window
        raw_collection_start               = (Get-UtcStamp $RawCollectionStart)
        raw_collection_end                 = (Get-UtcStamp $rawEnd)
        collection_window_extension_reason = $extensionReason
        export_margin_ms                   = [int]$EVTX_WINDOW_MARGIN_MS
        target_boot_utc                    = $bootUtc
        boot_session_id                    = $bootSession
        observation_start                  = (Get-UtcStamp $StartTime)
        observation_end                    = (Get-UtcStamp $EndTime)
        time_field                         = "EventData.UtcTime"
        time_fallback                      = "none"
        context_rule                       = "EventData.UtcTime < observation_start"
        context_rule_version               = $R1_CONTEXT_RULE_VERSION
        run_start_inclusive                = $true
        context_use                        = "lineage_restoration_only"
        selector_raw_input_scope           = $R1_SELECTOR_RAW_INPUT_SCOPE
        evaluation_window_start            = $evaluationReference
        evaluation_horizon_sec             = $EvaluationHorizonSec
        evaluation_window_end              = $evaluationEnd
        record_counts                      = [ordered]@{
            total             = [int]$Records.Count
            context           = [int]$contextCount
            observation       = [int]($Records.Count - $contextCount - $afterObservationCount)
            after_observation = [int]$afterObservationCount
        }
        lineage                            = [ordered]@{
            linked_by             = [string[]]@("ProcessGuid", "ParentProcessGuid")
            records               = [object[]]$lineageRecords.ToArray()
            context_record_ids    = [string[]]$contextIds.ToArray()
            references_to_context = [object[]]$references.ToArray()
            connection            = $connection
        }
        context_events                     = [object[]]$contextEvents.ToArray()
        evidence_link_key                  = "RecordId"
        readiness                          = $readinessBlock
        raw_source                         = $null
        actions                            = [object[]]$actionList
        created_process                    = $CreatedProcess
        canonical_provenance_linkage       = $canonicalLinkage
    }

    return [ordered]@{
        provenance = $provenance
        problems   = [string[]]$problems.ToArray()
    }
}

function Write-R1CollectionProvenance {
    <#
        Write the collection provenance of a run to its operator trace, once.

        The three hashes tie the record to what the run is made of: the scenario
        bytes its plan was built from, the manifest written for it and the
        Sysmon configuration the pre-run check found on the target. raw_source
        says where its RecordIds and lines belong: the host and the channel the
        records were exported from, and the raw file they are read from, by
        name, by hash and by the id the manifest gives it. The record is
        operator evidence like the rest of the trace: it is in no Manifest.

        Returns the path.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$TraceDir,
        [Parameter(Mandatory = $true)]$Provenance,
        [Parameter(Mandatory = $true)][string]$ScenarioSha256,
        [Parameter(Mandatory = $true)][string]$ManifestPath,
        [Parameter(Mandatory = $true)][string]$SysmonConfigSha256,
        [Parameter(Mandatory = $true)][string]$ComputerName,
        [Parameter(Mandatory = $true)][string]$JsonlPath
    )

    $jsonlName = [System.IO.Path]::GetFileName($JsonlPath)
    $manifest = Get-Content -LiteralPath $ManifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $listed = @(@($manifest.items) | Where-Object {
            [System.IO.Path]::GetFileName([string]$_.path) -eq $jsonlName })
    if ($listed.Count -ne 1) {
        throw ("the manifest lists " + $listed.Count + " item(s) named " + $jsonlName +
            "; the raw source of the provenance is exactly one")
    }
    $Provenance.raw_source = [ordered]@{
        host         = $ComputerName
        channel      = $SYSMON_LOG
        jsonl_file   = $jsonlName
        jsonl_sha256 = (Get-Sha256 -Path $JsonlPath)
        raw_log_id   = [string]$listed[0].raw_log_id
    }

    $Provenance.scenario_sha256 = $ScenarioSha256
    $Provenance.manifest_sha256 = (Get-Sha256 -Path $ManifestPath)
    $Provenance.sysmon_config_sha256 = $SysmonConfigSha256

    $path = Join-Path $TraceDir $R1_PROVENANCE_FILE
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    Write-R1NewFile -Path $path -Bytes $utf8NoBom.GetBytes(($Provenance | ConvertTo-Json -Depth 8))
    return $path
}

function Assert-R1RunInputs {
    <#
        Check every input before anything is created, opened or started.

        A value that is missing or malformed throws here, so a refused run leaves
        no directory, no session and no process behind. Returns the parsed
        scenario, the bytes it was parsed from and their SHA-256, the identity
        and the dataset tier of the Pair, the action list of this run type and
        the connection approval ($null when the connection is skipped).
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
    $datasetTier = Get-R1DatasetTier -Scenario $scenario -Rehearsal:$Rehearsal

    $run = Get-R1Value (Get-R1Value $scenario "runs") $RunType
    if ($null -eq $run) { throw ("runs." + $RunType + " is missing from the scenario") }

    # The identity and the tier of a Pair are stated once for both runs. A run
    # that stated its own could disagree with the other run of the Pair.
    foreach ($name in @("family_id", "variation_id", "repetition", "dataset_tier")) {
        if ($null -ne $run.PSObject.Properties[$name]) {
            throw ("runs." + $RunType + " states " + $name + "; a Pair states it once at the top level")
        }
    }

    # A scenario that states another entry, or a reference rule of its own, is
    # read with its collection profile: the steps of its entry kind and the
    # action of its rule. A scenario that states neither is checked as it
    # always was.
    $stepOrder = $R1_STEP_ORDER
    $referenceStep = $R1_REFERENCE_STEP
    if ((Test-R1Stated $scenario "reference_rule") -or
        (Test-R1Stated (Get-R1Value $scenario "planned_lineage") "entry")) {
        $statedProfile = Get-R1CollectionProfile -Scenario $scenario
        $stepOrder = @($statedProfile.step_order)
        $referenceStep = [string]$statedProfile.reference_step
    }

    $actions = @(Get-R1Value $run "actions")
    $steps = @($actions | ForEach-Object { [string](Get-R1Value $_ "step") })
    if (($steps -join ",") -ne ($stepOrder -join ",")) {
        throw ("runs." + $RunType + ".actions must be the steps " + ($stepOrder -join ", ") +
            " in that order, found " + ($steps -join ", "))
    }

    # The reference action (r1.md section 4-2). A normal run has none. An attack
    # run names the action that opens the session: its reference is the Sysmon
    # record of the session host that action created, so no other action can be
    # named, and an attack run that names none would get a RunMetadata without
    # its reference.
    #
    # A scenario that states another entry, or a reference rule of its own,
    # names the action of that rule instead (read above).
    $referenceActionId = [string](Get-R1Value $run "reference_action_id")
    $beginAction = @($actions | Where-Object { [string](Get-R1Value $_ "step") -eq $referenceStep })[0]
    $beginActionId = [string](Get-R1Value $beginAction "action_id")

    if ($RunType -eq "attack") {
        if ([string]::IsNullOrEmpty($referenceActionId)) {
            throw ("runs.attack.reference_action_id is missing; an attack run records its reference " +
                "(docs/scenarios/r1.md section 4-2)")
        }
        if ($referenceActionId -cne $beginActionId) {
            throw ("runs.attack.reference_action_id must be the " + $referenceStep + " action " +
                $beginActionId + ", found '" + $referenceActionId + "'")
        }
    } elseif (-not [string]::IsNullOrEmpty($referenceActionId)) {
        throw ("runs." + $RunType + ".reference_action_id is set; only an attack run records a " +
            "reference (docs/scenarios/r1.md section 4-2)")
    } else {
        $referenceActionId = $null
    }

    # A reference is only readable together with the policy it was taken under,
    # and both runs of the Pair record that version. A scenario whose attack run
    # names a reference action therefore has to state it, whichever run this is.
    # No particular version is expected: the value is the scenario's.
    $attackRun = Get-R1Value (Get-R1Value $scenario "runs") "attack"
    if (-not [string]::IsNullOrEmpty([string](Get-R1Value $attackRun "reference_action_id"))) {
        $policyVersion = Get-R1Value (Get-R1Value $scenario "run_metadata") "reference_policy_version"
        if ($policyVersion -isnot [string] -or [string]::IsNullOrWhiteSpace($policyVersion)) {
            throw ("run_metadata.reference_policy_version must be a non-blank string when " +
                "runs.attack.reference_action_id is set, found '" + [string]$policyVersion + "'")
        }
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

    # The window has to cover the last action. How long it runs is a run input.
    if ($ObservationSec -lt $lastOffset -or $ObservationSec -lt 1) {
        throw ("ObservationSec " + $ObservationSec + " does not cover the last action at " +
            $lastOffset + " s")
    }

    # The evaluation horizon is a scenario value (r1.md section 11-4). The window
    # cannot be shorter than it, and after the collection an attack run is held
    # to it from its reference_time.
    $horizon = Get-R1Value (Get-R1Value $scenario "run_length") "evaluation_horizon_sec"
    if (($horizon -isnot [int] -and $horizon -isnot [long]) -or $horizon -lt 1) {
        throw ("run_length.evaluation_horizon_sec must be an integer of 1 or more, found '" +
            [string]$horizon + "'")
    }
    if ($ObservationSec -lt $horizon) {
        throw ("ObservationSec " + $ObservationSec + " is shorter than the evaluation horizon of " +
            $horizon + " s")
    }
    # The collection of an attack run has to reach the end of its evaluation
    # window, which starts no earlier than the action it takes its reference
    # from. Both runs of a Pair are equally long, so both are held to it. This
    # is the plan; after the collection the run is held to the recorded
    # reference_time itself.
    $referenceOffset = [int](Get-R1Value $beginAction "offset_sec")
    if ($ObservationSec -lt ($referenceOffset + $horizon)) {
        throw ("ObservationSec " + $ObservationSec + " does not reach the evaluation horizon of " +
            $horizon + " s after the " + $referenceStep + " action at " + $referenceOffset +
            " s; it has to be " + ($referenceOffset + $horizon) + " or more")
    }
    # A scenario may state how long its runs are observed. A run of it is that
    # long: another length would make the two runs of a Pair differ.
    $statedObservation = Get-R1Value (Get-R1Value $scenario "run_length") "observation_sec"
    if ($null -ne $statedObservation) {
        if (($statedObservation -isnot [int] -and $statedObservation -isnot [long]) -or $statedObservation -lt 1) {
            throw ("run_length.observation_sec must be an integer of 1 or more or null, found '" +
                [string]$statedObservation + "'")
        }
        if ($ObservationSec -ne $statedObservation) {
            throw ("ObservationSec " + $ObservationSec + " is not the length this scenario states: " +
                "run_length.observation_sec is " + $statedObservation)
        }
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
        dataset_tier    = $datasetTier
        reference_action_id    = $referenceActionId
        reference_step         = $referenceStep
        step_order             = [string[]]$stepOrder
        evaluation_horizon_sec = [int]$horizon
    }
}

# ---------------------------------------------------------------------------
# Remote steps - production only
#
# Each script block runs on Target-A inside a remote session and returns exactly
# one hashtable. The guard tests replace the transport that would send them and
# execute one of them, the probe step, in a background job against a stand-in
# for Sysmon64.
# ---------------------------------------------------------------------------

$R1_REMOTE_STEPS = @{
    # Pre-run check in its own session, so the Sysmon64 process it starts is over
    # before the run's start time is stamped.
    probe = {
        param($Arguments)
        Set-StrictMode -Version Latest
        $ErrorActionPreference = "Stop"

        # "Sysmon64 -c" is started as a process of its own and its two streams are
        # read as bytes. Through the native pipeline of a remote session the line
        # Sysmon writes to stderr becomes an error record, which ends this step
        # under "Stop", and its UTF-16 stdout is read with the code page of the
        # session, which leaves a NUL after every character and matches none of
        # the lines below. Whether stderr carried anything decides nothing here:
        # the exit code and the fields do.
        $startInfo = New-Object System.Diagnostics.ProcessStartInfo
        $startInfo.FileName = [string]$Arguments.sysmon_binary
        $startInfo.Arguments = "-c"
        $startInfo.UseShellExecute = $false
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        $startInfo.CreateNoWindow = $true
        $query = [System.Diagnostics.Process]::Start($startInfo)
        $stderrBytes = New-Object System.IO.MemoryStream
        $stderrCopy = $query.StandardError.BaseStream.CopyToAsync($stderrBytes)
        $stdoutBytes = New-Object System.IO.MemoryStream
        $query.StandardOutput.BaseStream.CopyTo($stdoutBytes)
        $query.WaitForExit()
        $stderrCopy.Wait()
        $exitCode = $query.ExitCode
        $query.Dispose()
        if ($exitCode -ne 0) {
            throw ("Sysmon64 -c exited with code " + $exitCode + " (stdout " + $stdoutBytes.Length +
                " bytes, stderr " + $stderrBytes.Length + " bytes)")
        }

        # The encoding is decided from the bytes, and nothing is dropped or
        # replaced to make them fit: a UTF-16 byte order mark, or no zero byte at
        # all (read with the system code page), or bytes that are valid UTF-16LE.
        # Both decoders throw on bytes they cannot decode. Text that still holds
        # U+0000, and anything else, is refused, so a stream this step cannot
        # read is never taken for an answer.
        $bytes = $stdoutBytes.ToArray()
        if ($bytes.Length -eq 0) { throw "Sysmon64 -c wrote nothing to stdout" }
        $output = $null
        $strictUtf16 = New-Object System.Text.UnicodeEncoding($false, $false, $true)
        $strictCodePage = [System.Text.Encoding]::GetEncoding([System.Text.Encoding]::Default.CodePage,
            [System.Text.EncoderFallback]::ExceptionFallback, [System.Text.DecoderFallback]::ExceptionFallback)
        try {
            if ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) {
                $output = $strictUtf16.GetString($bytes, 2, $bytes.Length - 2)
            } elseif ([System.Array]::IndexOf($bytes, [byte]0) -lt 0) {
                $output = $strictCodePage.GetString($bytes)
            } elseif ($bytes.Length % 2 -eq 0) {
                $output = $strictUtf16.GetString($bytes)
            }
        } catch [System.ArgumentException] {
            $output = $null
        }
        if ($null -eq $output -or $output.IndexOf([char]0) -ge 0) {
            throw ("the stdout of Sysmon64 -c is in no encoding this step reads (" + $bytes.Length +
                " bytes)")
        }

        $sysmon = @{ config_file = $null; config_hash = $null; hashing_algorithms = $null }
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

        # Only a run whose raw export starts at the boot of this host asks for
        # it. It is read before the stamp below, which stays the last thing this
        # step does.
        $bootUtc = $null
        if ($Arguments.ContainsKey("read_boot_time") -and [bool]$Arguments.read_boot_time) {
            $bootUtc = (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString(
                "yyyy-MM-ddTHH:mm:ss.fffZ")
        }

        $answer = @{
            utc                    = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
            computer_name          = $env:COMPUTERNAME
            recorded_computer_name = $recordedName
            sysmon                 = $sysmon
            config_sha256          = $configSha256
        }
        if ($null -ne $bootUtc) { $answer.boot_utc = $bootUtc }
        return $answer
    }

    # t+0: the session exists. $PID here is the remote session host process, and
    # it reports its own image: no process is started to ask for it.
    begin = {
        param($Arguments)
        return @{
            utc           = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
            session_pid   = $PID
            session_image = [string](Get-Process -Id $PID).Path
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

    # Before the first action of an entry through WMI: the gate the intermediate
    # will wait on. It is a pipe of this host, kept by this session, and it is
    # opened before the launch so the launcher finds it whenever it gets there.
    # Nothing here reaches another machine.
    open_gate = {
        param($Arguments)
        Set-StrictMode -Version Latest
        $ErrorActionPreference = "Stop"

        $global:R1Gate = New-Object System.IO.Pipes.NamedPipeServerStream(
            [string]$Arguments.pipe_name, [System.IO.Pipes.PipeDirection]::Out, 1,
            [System.IO.Pipes.PipeTransmissionMode]::Byte, [System.IO.Pipes.PipeOptions]::Asynchronous)
        return @{ utc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ") }
    }

    # The first action of an entry through WMI: the provider host starts the
    # intermediate. The session only makes the call. No helper program is run
    # for it: its process-create record and its command line would be in the
    # raw export.
    #
    # The time of the action is the clock of this host right before the call:
    # everything the call needs is built first, and nothing is done between the
    # stamp and the call. What the call returned is handed back as it is, with
    # the stamp taken when the call was back. Whether the action succeeded is
    # decided by the Controller, from the return value and the process id.
    launch_wmi = {
        param($Arguments)
        Set-StrictMode -Version Latest
        $ErrorActionPreference = "Stop"

        $startup = New-CimInstance -ClassName Win32_ProcessStartup -ClientOnly -Property @{ ShowWindow = [uint16]0 }
        $callArguments = @{
            CommandLine               = [string]$Arguments.command_line
            CurrentDirectory          = [string]$Arguments.work_dir
            ProcessStartupInformation = $startup
        }
        $stampFormat = "yyyy-MM-ddTHH:mm:ss.fffZ"

        $utc = (Get-Date).ToUniversalTime().ToString($stampFormat)
        $created = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments $callArguments
        $completedUtc = (Get-Date).ToUniversalTime().ToString($stampFormat)

        $returnValue = $null
        $processId = $null
        if ($null -ne $created) {
            $returnValue = $created.ReturnValue
            $processId = $created.ProcessId
        }
        return @{
            utc           = $utc
            return_value  = $returnValue
            process_id    = $processId
            completed_utc = $completedUtc
        }
    }

    # The second action of an entry through WMI: the intermediate, which has
    # been waiting on the gate since the launch, is told to start the final
    # tool. The time of the action is the clock of this host right before the
    # word is written. An intermediate that does not come to the gate in time,
    # or that is gone, ends the step: nothing else starts the final tool.
    start_tool = {
        param($Arguments)
        Set-StrictMode -Version Latest
        $ErrorActionPreference = "Stop"

        $gate = Get-Variable -Name R1Gate -Scope Global -ValueOnly -ErrorAction SilentlyContinue
        if ($null -eq $gate) { throw "the gate of this run was not opened in this session" }
        $readyPath = Join-Path $Arguments.channel_dir $Arguments.ready_file
        $stampFormat = "yyyy-MM-ddTHH:mm:ss.fffZ"
        $word = [System.Text.Encoding]::ASCII.GetBytes([string]$Arguments.gate_word + "`r`n")

        $utc = $null
        try {
            $waiting = $gate.BeginWaitForConnection($null, $null)
            if (-not $waiting.AsyncWaitHandle.WaitOne([int]$Arguments.gate_timeout_sec * 1000)) {
                throw ("the intermediate did not come to the gate within " + $Arguments.gate_timeout_sec + " s")
            }
            $gate.EndWaitForConnection($waiting)

            $utc = (Get-Date).ToUniversalTime().ToString($stampFormat)
            $gate.Write($word, 0, $word.Length)
            $gate.WaitForPipeDrain()
        } finally {
            $gate.Dispose()
            $global:R1Gate = $null
        }

        $deadline = (Get-Date).AddSeconds([int]$Arguments.timeout_sec)
        while (-not (Test-Path -LiteralPath $readyPath)) {
            if ((Get-Date) -ge $deadline) {
                throw ("the final tool did not report ready within " + $Arguments.timeout_sec + " s")
            }
            Start-Sleep -Milliseconds 200
        }
        $ready = Get-Content -LiteralPath $readyPath -Raw -Encoding UTF8 | ConvertFrom-Json

        return @{
            utc           = $utc
            final_pid     = [int]$ready.pid
            completed_utc = (Get-Date).ToUniversalTime().ToString($stampFormat)
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

    # The last action of an entry through WMI: the run ends the processes it
    # started, and only those. Failure cleanup uses the same step after only the
    # intermediate was created. Closing the session does not end either case,
    # because the session did not start those processes.
    #
    # A process is ended by its process id and by nothing else, and only after
    # it was shown to be the one the run started: the planned program, created
    # no earlier than the action that started it. A process id that now belongs
    # to anything else stops the step before a single process is ended. The
    # provider host - the parent of the intermediate - is looked at before and
    # after, and is never ended: it belongs to the target, not to the run.
    #
    # The final tool is ended first. The intermediate was waiting for it and
    # then ends by itself; it is ended here only when it is still there.
    end_run = {
        param($Arguments)
        Set-StrictMode -Version Latest
        $ErrorActionPreference = "Stop"

        $stampFormat = "yyyy-MM-ddTHH:mm:ss.fffZ"
        $utc = (Get-Date).ToUniversalTime().ToString($stampFormat)
        $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor
            [System.Globalization.DateTimeStyles]::AdjustToUniversal
        $find = {
            param($Id)
            return (Get-CimInstance -ClassName Win32_Process -Filter ("ProcessId = " + [int]$Id))
        }

        # --- every process the run names is looked up and checked first -----------
        $owned = New-Object System.Collections.Generic.List[object]
        foreach ($entry in @($Arguments.owned)) {
            $found = & $find $entry.process_id
            if ($null -ne $found) {
                $notBefore = [datetime]::ParseExact([string]$entry.created_not_before_utc,
                    "yyyy-MM-dd'T'HH:mm:ss.fff'Z'", [System.Globalization.CultureInfo]::InvariantCulture, $styles)
                $createdAt = $found.CreationDate.ToUniversalTime()
                if ([string]$found.Name -ine [string]$entry.image -or $createdAt -lt $notBefore) {
                    throw ("process id " + $entry.process_id + " is not the process this run started: it is " +
                        [string]$found.Name + ", created " + $createdAt.ToString($stampFormat) +
                        "; the run started " + [string]$entry.image + " no earlier than " +
                        [string]$entry.created_not_before_utc)
                }
            }
            $owned.Add(@{ entry = $entry; found = $found })
        }
        $allowPartial = $false
        if ($Arguments.ContainsKey("allow_partial")) {
            if ($Arguments.allow_partial -isnot [bool]) { throw "allow_partial must be boolean" }
            $allowPartial = [bool]$Arguments.allow_partial
        }
        if ((-not $allowPartial -and $owned.Count -ne 2) -or
            ($allowPartial -and ($owned.Count -lt 1 -or $owned.Count -gt 2))) {
            throw ("a run ends the two processes it started; failure cleanup may name one or two, " +
                $owned.Count + " were named")
        }
        $intermediate = $owned[0]
        $finalTool = if ($owned.Count -eq 2) { $owned[1] } else { $null }

        # --- the provider host: looked at, never ended ------------------------------
        $provider = @{ process_id = $null; name = $null; running_before = $false; running_after = $false }
        $providerCreated = $null
        if ($null -ne $intermediate.found) {
            $parent = & $find $intermediate.found.ParentProcessId
            if ($null -ne $parent -and $parent.CreationDate -le $intermediate.found.CreationDate) {
                $provider.process_id = [int]$parent.ProcessId
                $provider.name = [string]$parent.Name
                $provider.running_before = $true
                $providerCreated = $parent.CreationDate
            }
        }
        foreach ($item in $owned) {
            if ($null -ne $provider.process_id -and [int]$item.entry.process_id -eq $provider.process_id) {
                throw ("process id " + $item.entry.process_id + " is the provider host; a run does not end it")
            }
        }

        # --- the processes of the run ---------------------------------------------------
        $waitSec = [int]$Arguments.wait_sec
        $gone = {
            param($Item)
            $now = & $find $Item.entry.process_id
            return ($null -eq $now -or $now.CreationDate -ne $Item.found.CreationDate)
        }
        $endOwned = {
            param($Item)
            if ($null -eq $Item.found) { return "already_exited" }
            if (& $gone $Item) { return "exited_by_itself" }
            Stop-Process -Id ([int]$Item.entry.process_id) -Force
            $deadline = (Get-Date).AddSeconds($waitSec)
            while (-not (& $gone $Item)) {
                if ((Get-Date) -ge $deadline) {
                    throw ("process id " + $Item.entry.process_id + " was not ended within " + $waitSec + " s")
                }
                Start-Sleep -Milliseconds 200
            }
            return "stopped"
        }

        $finalOutcome = $null
        if ($null -ne $finalTool) { $finalOutcome = & $endOwned $finalTool }
        if ($null -ne $finalTool -and $null -ne $intermediate.found) {
            $deadline = (Get-Date).AddSeconds($waitSec)
            while (-not (& $gone $intermediate) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 200 }
        }
        $intermediateOutcome = & $endOwned $intermediate

        if ($null -ne $provider.process_id) {
            $after = & $find $provider.process_id
            $provider.running_after = ($null -ne $after -and $after.CreationDate -eq $providerCreated)
        }

        $ended = New-Object System.Collections.Generic.List[object]
        $ended.Add(@{ process_id = [int]$intermediate.entry.process_id; image = [string]$intermediate.entry.image
            outcome = $intermediateOutcome })
        if ($null -ne $finalTool) {
            $ended.Add(@{ process_id = [int]$finalTool.entry.process_id; image = [string]$finalTool.entry.image
                outcome = $finalOutcome })
        }

        return @{
            utc           = $utc
            ended         = [object[]]$ended.ToArray()
            provider_host = $provider
            completed_utc = (Get-Date).ToUniversalTime().ToString($stampFormat)
        }
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

# The export of the freeze ack's closed RecordId bound (-PositionFinality only).
$R1_REMOTE_STEPS["export_record_bounded"] = $R1_RECORD_BOUNDED_EXPORT_STEP

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
        "mismatched", with a reason, the final tool's ProcessGuid and the
        ProcessGuid of the session host of the chain that was found.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Records,
        [Parameter(Mandatory = $true)][string]$ComputerName,
        [Parameter(Mandatory = $true)][int]$SessionPid,
        [Parameter(Mandatory = $true)][int]$IntermediatePid,
        [Parameter(Mandatory = $true)][int]$FinalPid,
        [Parameter(Mandatory = $true)][string[]]$ExpectedLineage,
        [AllowNull()]$Approval,
        [ValidateSet("remoting_session", "wmi_process")][string]$EntryKind = "remoting_session"
    )

    # With an entry through WMI the root of the chain is not a process the runner
    # started or knows the id of: it is whatever process-create record the
    # ProcessGuid chain ends at, and only its Image is compared.
    $rootIsSession = ($EntryKind -ceq "remoting_session")

    $mismatch = {
        param($Reason)
        return [ordered]@{
            status = "mismatched"; reason = $Reason; final_process_guid = $null; session_host_guid = $null
        }
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
    if (-not $rootIsSession) { $labels = @("final tool", "intermediate", "lineage root") }
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
            if ($index -eq 2 -and -not $rootIsSession) { continue }
            if ([string](Get-R1Value $chain[$index] "ProcessId") -ne [string]$expectedIds[$index]) { $fits = $false }
        }
        if ($fits) { $chains.Add($chain) }
    }

    if ($chains.Count -eq 0 -and -not $rootIsSession) {
        return (& $mismatch ("no EID 1 chain of three records links the final tool (pid " + $FinalPid +
            ") through the intermediate (pid " + $IntermediatePid + ") to a parent that has a " +
            "process-create record on " + $ComputerName))
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
    $sessionGuid = [string](Get-R1Value $chain[2] "ProcessGuid")
    # The root of another entry is not the session host, so no session host of
    # this chain is reported.
    if (-not $rootIsSession) { $sessionGuid = $null }
    if ($null -eq $Approval) {
        return [ordered]@{
            status             = "lineage_only"
            reason             = "the lineage matches; no connection was requested"
            final_process_guid = $finalGuid
            session_host_guid  = $sessionGuid
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
            session_host_guid  = $sessionGuid
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
            session_host_guid  = $sessionGuid
        }
    }

    if ($otherProtocols.Count -gt 0) {
        return [ordered]@{
            status             = "mismatched"
            reason             = ("an EID 3 with the final tool's ProcessGuid reaches the approved " +
                "destination, but none was recorded with the approved Protocol " + $approvedProtocol +
                ": recorded Protocol " + ($otherProtocols -join ", "))
            final_process_guid = $finalGuid
            session_host_guid  = $sessionGuid
        }
    }

    return [ordered]@{
        status             = "mismatched"
        reason             = "no EID 3 with the final tool's ProcessGuid reaches the approved destination"
        final_process_guid = $finalGuid
        session_host_guid  = $sessionGuid
    }
}

function Get-R1ReferenceEvent {
    <#
        Find the Sysmon record an attack run takes its reference from: the EID 1
        of the remote session host that the session_begin action created
        (r1.md section 4-2).

        The runner knows that process from its own steps: the process id and the
        image the session reported about itself, and two bounds on when it was
        created - the recorded start of the action and the stamp Target-A gave
        once the session existed. A record is the reference only when it is the
        one EID 1 on the target that fits all of that. The process id narrows
        the search and decides nothing on its own: the record has to carry a
        ProcessGuid, and when the lineage of the run was found, that ProcessGuid
        has to be the session host of the lineage.

        The time compared and returned is EventData.UtcTime, the time Sysmon
        gives the event. TimeCreated is never read: a record whose UtcTime
        cannot be read is not given another time, it leaves the run without a
        reference.

        Returns status "selected" with reference_time (a UTC stamp),
        reference_source_event_id (the RecordId as a string) and process_guid,
        or status "undetermined" with the reason.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Records,
        [Parameter(Mandatory = $true)][string]$ComputerName,
        [Parameter(Mandatory = $true)][int]$SessionPid,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$SessionImage,
        [Parameter(Mandatory = $true)][string]$ExpectedImage,
        [Parameter(Mandatory = $true)][datetime]$NotBefore,
        [Parameter(Mandatory = $true)][datetime]$NotAfter,
        [AllowEmptyString()][string]$SessionHostGuid
    )

    $undetermined = {
        param($Reason)
        return [ordered]@{
            status = "undetermined"; reason = $Reason; reference_time = $null
            reference_source_event_id = $null; process_guid = $null
        }
    }

    $reportedName = [System.IO.Path]::GetFileName($SessionImage)
    if ($reportedName -ne $ExpectedImage) {
        return (& $undetermined ("the session reported the image '" + $reportedName +
            "', the scenario expects the session host '" + $ExpectedImage + "'"))
    }

    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor
        [System.Globalization.DateTimeStyles]::AdjustToUniversal
    $fitting = New-Object System.Collections.Generic.List[object]
    foreach ($record in $Records) {
        if ([string](Get-R1Value $record "Computer") -ne $ComputerName) { continue }
        if ([string](Get-R1Value $record "EventId") -ne "1") { continue }
        $data = Get-R1Value $record "EventData"
        if ([System.IO.Path]::GetFileName([string](Get-R1Value $data "Image")) -ne $ExpectedImage) { continue }
        if ([string](Get-R1Value $data "ProcessId") -ne [string]$SessionPid) { continue }

        # A record that could be the reference and has no readable time is not
        # skipped: skipping it could leave one other record looking unique.
        $stated = [string](Get-R1Value $data "UtcTime")
        $created = [datetime]::MinValue
        if (-not [datetime]::TryParseExact($stated, $R1_EVENT_UTC_FORMAT,
                [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$created)) {
            return (& $undetermined ("an EID 1 of " + $ExpectedImage + " with the session process id " +
                $SessionPid + " has no readable EventData.UtcTime ('" + $stated +
                "'); TimeCreated is not used in its place"))
        }
        if ($created -lt $NotBefore -or $created -gt $NotAfter) { continue }
        $fitting.Add(@{ record = $record; data = $data; created = $created })
    }

    $window = (Get-UtcStamp $NotBefore) + " .. " + (Get-UtcStamp $NotAfter)
    if ($fitting.Count -eq 0) {
        return (& $undetermined ("no EID 1 of " + $ExpectedImage + " with the session process id " +
            $SessionPid + " was recorded on " + $ComputerName + " in " + $window))
    }
    if ($fitting.Count -gt 1) {
        return (& $undetermined ([string]$fitting.Count + " EID 1 records of " + $ExpectedImage +
            " with the session process id " + $SessionPid + " were recorded on " + $ComputerName +
            " in " + $window + "; exactly one is the session of this run"))
    }

    $chosen = $fitting[0]
    $guid = [string](Get-R1Value $chosen.data "ProcessGuid")
    if ([string]::IsNullOrWhiteSpace($guid)) {
        return (& $undetermined "the EID 1 of the session host carries no ProcessGuid")
    }
    $recordId = [string](Get-R1Value $chosen.record "RecordId")
    if ($recordId -notmatch "^[0-9]+$") {
        return (& $undetermined ("the EID 1 of the session host carries no usable RecordId ('" +
            $recordId + "')"))
    }
    if (-not [string]::IsNullOrEmpty($SessionHostGuid) -and $guid -ne $SessionHostGuid) {
        return (& $undetermined ("the EID 1 that fits the session has ProcessGuid " + $guid +
            ", but the session host of the lineage of this run is " + $SessionHostGuid))
    }

    return [ordered]@{
        status                    = "selected"
        reason                    = "one EID 1 of the session host fits the session of this run"
        reference_time            = (Get-UtcStamp $chosen.created)
        reference_source_event_id = $recordId
        process_guid              = $guid
    }
}

function Test-R1WholeNumber {
    <# Whether a value is a whole number as a remote step returns one. A string, a boolean or $null is not. #>
    param([AllowNull()]$Value)

    return ($Value -is [int] -or $Value -is [long] -or $Value -is [uint32] -or $Value -is [uint64] -or
        $Value -is [int16] -or $Value -is [uint16] -or $Value -is [byte] -or $Value -is [sbyte])
}

function Get-R1WmiCreateResult {
    <#
        What the launch through WMI returned, held to what a started process
        returns.

        The launch action succeeded only when Win32_Process.Create returned 0
        and a process id. Anything else - another return value, no return value,
        a process id of 0 or less, one that is missing or is not a number -
        throws, so the run stops where the action failed and nothing later is
        attributed to it. The step on the target hands back what the call
        returned as it is; the decision is made here.

        The time of the action is the stamp the target took right before the
        call, and the action was over at the stamp it took when the call was
        back. The process the call created was created between the two. The
        final tool is not started by this action.

        Returns the two stamps and their times, the return value and the
        process id of the created process.
    #>
    param([AllowNull()]$Created, [long]$SuccessReturnValue = 0)

    $returnValue = Get-R1Value $Created "return_value"
    if (-not (Test-R1WholeNumber $returnValue) -or [long]$returnValue -ne $SuccessReturnValue) {
        throw ("Win32_Process.Create returned '" + [string]$returnValue + "': the launch action succeeded " +
            "only when it returns " + $SuccessReturnValue + ", so the intermediate was not started")
    }
    $processId = Get-R1Value $Created "process_id"
    if (-not (Test-R1WholeNumber $processId) -or [long]$processId -le 0 -or
        [long]$processId -gt [int]::MaxValue) {
        throw ("Win32_Process.Create returned no usable ProcessId ('" + [string]$processId + "'): the " +
            "launch action succeeded only when it returns the id of the process it created")
    }
    $actionTime = ConvertTo-R1Utc (Get-R1Value $Created "utc") "invoke utc"
    $completedTime = ConvertTo-R1Utc (Get-R1Value $Created "completed_utc") "invoke completed_utc"
    if ($completedTime -lt $actionTime) {
        throw ("the launch action was over at " + (Get-UtcStamp $completedTime) + " on the target, before " +
            "the call was made (" + (Get-UtcStamp $actionTime) + "): a clock moved during the run")
    }

    return [ordered]@{
        action_utc     = (Get-UtcStamp $actionTime)
        action_time    = $actionTime
        completed_utc  = (Get-UtcStamp $completedTime)
        completed_time = $completedTime
        return_value   = [int]$returnValue
        process_id     = [int]$processId
    }
}

function Get-R1ToolStartResult {
    <#
        What the step that starts the final tool returned, held to what a
        started tool returns: the process id the tool reported about itself,
        and the two stamps of the action, as UTC and in order. The first stamp
        was taken right before the intermediate was told to start the tool, the
        second when the tool had reported ready. Anything else throws.
    #>
    param([AllowNull()]$Started)

    $finalPid = Get-R1Value $Started "final_pid"
    if (-not (Test-R1WholeNumber $finalPid) -or [long]$finalPid -le 0 -or [long]$finalPid -gt [int]::MaxValue) {
        throw ("the final tool reported no usable process id ('" + [string]$finalPid + "')")
    }
    $actionTime = ConvertTo-R1Utc (Get-R1Value $Started "utc") "launch utc"
    $completedTime = ConvertTo-R1Utc (Get-R1Value $Started "completed_utc") "launch completed_utc"
    if ($completedTime -lt $actionTime) {
        throw ("the final tool was ready at " + (Get-UtcStamp $completedTime) + " on the target, before it " +
            "was told to start (" + (Get-UtcStamp $actionTime) + "): a clock moved during the run")
    }

    return [ordered]@{
        action_utc     = (Get-UtcStamp $actionTime)
        action_time    = $actionTime
        completed_utc  = (Get-UtcStamp $completedTime)
        completed_time = $completedTime
        final_pid      = [int]$finalPid
    }
}

function Get-R1RunEndResult {
    <#
        What the step that ends a run through WMI returned, held to what a run
        may end.

        A run ends the processes it started and nothing else. The step has to
        account for exactly those process ids, each as ended or as already
        gone. A process id the run did not start, a process with the Image of
        the root of the lineage, or a provider host that was running before the
        step and is not running after it throws: the provider host belongs to
        the target. A provider host that was already gone before the step is
        not an error; the run did not end it.

        Returns the two stamps of the action, what was ended and what was seen
        of the provider host.
    #>
    param(
        [AllowNull()]$Ended,
        [Parameter(Mandatory = $true)][int[]]$OwnedProcessIds,
        [Parameter(Mandatory = $true)][string]$RootImage
    )

    $actionTime = ConvertTo-R1Utc (Get-R1Value $Ended "utc") "run_end utc"
    $completedTime = ConvertTo-R1Utc (Get-R1Value $Ended "completed_utc") "run_end completed_utc"

    $list = @(Get-R1Value $Ended "ended" | Where-Object { $null -ne $_ })
    $endedIds = New-Object System.Collections.Generic.List[int]
    foreach ($item in $list) {
        $id = Get-R1Value $item "process_id"
        if (-not (Test-R1WholeNumber $id) -or [long]$id -le 0 -or [long]$id -gt [int]::MaxValue) {
            throw ("the run_end step named a process without a usable process id ('" + [string]$id + "')")
        }
        if ($OwnedProcessIds -notcontains [int]$id) {
            throw ("the run_end step ended process id " + [string]$id + ", which this run did not start: " +
                "a run ends only what it started")
        }
        if ([string](Get-R1Value $item "image") -eq $RootImage) {
            throw ("the run_end step ended " + $RootImage + ": the root of the lineage belongs to the target, " +
                "not to the run")
        }
        $outcome = Get-R1Value $item "outcome"
        if ($outcome -isnot [string] -or @("stopped", "exited_by_itself", "already_exited") -cnotcontains $outcome) {
            throw ("the run_end step left process id " + [string]$id + " with the outcome '" + [string]$outcome +
                "'; a process of the run is ended or was already gone")
        }
        $endedIds.Add([int]$id)
    }
    $missing = @($OwnedProcessIds | Where-Object { -not $endedIds.Contains($_) })
    if ($missing.Count -gt 0 -or $endedIds.Count -ne $OwnedProcessIds.Count) {
        throw ("the run_end step accounted for process id(s) '" + ($endedIds -join ", ") + "'; the run started " +
            ($OwnedProcessIds -join ", "))
    }

    $provider = Get-R1Value $Ended "provider_host"
    $runningBefore = Get-R1Value $provider "running_before"
    $runningAfter = Get-R1Value $provider "running_after"
    if ($runningBefore -isnot [bool] -or $runningAfter -isnot [bool]) {
        throw "the run_end step did not state whether the provider host was running before and after it"
    }
    $providerId = Get-R1Value $provider "process_id"
    if ($null -ne $providerId -and (Test-R1WholeNumber $providerId) -and $OwnedProcessIds -contains [int]$providerId) {
        throw ("the run_end step names process id " + [string]$providerId + " both as the provider host and " +
            "as a process of the run")
    }
    if ($runningBefore -and -not $runningAfter) {
        throw ("the provider host (process id " + [string]$providerId + ") was running before the run ended " +
            "its processes and is not running after: a run ends only what it started")
    }

    return [ordered]@{
        action_utc    = (Get-UtcStamp $actionTime)
        action_time   = $actionTime
        completed_utc = (Get-UtcStamp $completedTime)
        ended         = [object[]]$list
        provider_host = [ordered]@{
            process_id     = $providerId
            name           = Get-R1Value $provider "name"
            running_before = [bool]$runningBefore
            running_after  = [bool]$runningAfter
        }
    }
}

function Test-R1ToolConnectionIdentity {
    <#
        Hold the connection of a run through WMI to the final tool its second
        action started.

        The runner knows that tool from its own step: the process id the tool
        reported about itself, the stamp taken right before the intermediate
        was told to start it and the stamp taken when it was ready. Its
        process-create record is the one EID 1 of the target that carries that
        process id and whose EventData.UtcTime lies between the two stamps. A
        final tool that existed before the action was not started by it. The
        ProcessGuid of that record has to be the final tool of the lineage of
        the run, and exactly one connection to the approved destination has to
        carry the same ProcessGuid. Process ids only find the record; what is
        compared is the ProcessGuid. TimeCreated is never read.

        Returns status "matched", "tool_only" (no connection was requested) or
        "mismatched", with a reason, the ProcessGuid and RecordId of the tool
        and the RecordId of its connection.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Records,
        [Parameter(Mandatory = $true)][string]$ComputerName,
        [Parameter(Mandatory = $true)][int]$FinalPid,
        [Parameter(Mandatory = $true)][datetime]$NotBefore,
        [Parameter(Mandatory = $true)][datetime]$NotAfter,
        [AllowNull()][AllowEmptyString()][string]$FinalProcessGuid,
        [AllowNull()]$Approval
    )

    $answer = {
        param($Status, $Reason, $ToolGuid, $ToolRecordId, $ConnectionRecordId)
        return [ordered]@{
            status = $Status; reason = $Reason; tool_process_guid = $ToolGuid
            tool_record_id = $ToolRecordId; connection_record_id = $ConnectionRecordId
        }
    }

    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor
        [System.Globalization.DateTimeStyles]::AdjustToUniversal
    $started = New-Object System.Collections.Generic.List[object]
    $reaching = New-Object System.Collections.Generic.List[object]
    foreach ($record in $Records) {
        if ([string](Get-R1Value $record "Computer") -ne $ComputerName) { continue }
        $eventId = [string](Get-R1Value $record "EventId")
        $data = Get-R1Value $record "EventData"

        if ($eventId -eq "1" -and [string](Get-R1Value $data "ProcessId") -eq [string]$FinalPid) {
            $stated = Get-R1Value $data "UtcTime"
            $created = [datetime]::MinValue
            if ($stated -isnot [string] -or -not [datetime]::TryParseExact($stated, $R1_EVENT_UTC_FORMAT,
                    [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$created)) {
                return (& $answer "mismatched" ("an EID 1 with the process id the final tool reported (" +
                    $FinalPid + ") has no readable EventData.UtcTime ('" + [string]$stated +
                    "'); TimeCreated is not used in its place") $null $null $null)
            }
            if ($created -ge $NotBefore -and $created -le $NotAfter) { $started.Add($record) }
        } elseif ($eventId -eq "3" -and $null -ne $Approval) {
            if ([string](Get-R1Value $data "DestinationIp") -ne [string]$Approval.target) { continue }
            if ([string](Get-R1Value $data "DestinationPort") -ne [string]$Approval.port) { continue }
            if (-not [string]::Equals([string](Get-R1Value $data "Protocol"), [string]$Approval.protocol,
                    [System.StringComparison]::OrdinalIgnoreCase)) { continue }
            $reaching.Add($record)
        }
    }

    $window = (Get-UtcStamp $NotBefore) + " .. " + (Get-UtcStamp $NotAfter)
    if ($started.Count -ne 1) {
        return (& $answer "mismatched" ([string]$started.Count + " EID 1 record(s) with the process id the " +
            "final tool reported (" + $FinalPid + ") were recorded on " + $ComputerName + " in " + $window +
            "; exactly one is the tool the launch action started") $null $null $null)
    }
    $toolData = Get-R1Value $started[0] "EventData"
    $toolGuid = [string](Get-R1Value $toolData "ProcessGuid")
    $toolRecordId = [string](Get-R1Value $started[0] "RecordId")
    if ([string]::IsNullOrWhiteSpace($toolGuid)) {
        return (& $answer "mismatched" "the EID 1 of the final tool carries no ProcessGuid" $null $toolRecordId $null)
    }
    if ([string]::IsNullOrEmpty($FinalProcessGuid) -or $toolGuid -ne $FinalProcessGuid) {
        return (& $answer "mismatched" ("the tool the launch action started has ProcessGuid " + $toolGuid +
            ", the final tool of the lineage of this run is '" + [string]$FinalProcessGuid + "'") `
            $toolGuid $toolRecordId $null)
    }
    if ($null -eq $Approval) {
        return (& $answer "tool_only" "the final tool is the one the launch action started; no connection was requested" `
            $toolGuid $toolRecordId $null)
    }

    $ofTool = @($reaching | Where-Object { [string](Get-R1Value (Get-R1Value $_ "EventData") "ProcessGuid") -eq $toolGuid })
    if ($ofTool.Count -ne 1) {
        return (& $answer "mismatched" ([string]$ofTool.Count + " of " + $reaching.Count + " connection(s) to the " +
            "approved destination carry the ProcessGuid of the final tool the launch action started (" +
            $toolGuid + "); exactly one does in a run") $toolGuid $toolRecordId $null)
    }
    return (& $answer "matched" "the one connection of the final tool carries the ProcessGuid of the tool the launch action started" `
        $toolGuid $toolRecordId ([string](Get-R1Value $ofTool[0] "RecordId")))
}

function Invoke-R1WmiRunSetup {
    <#
        What a run through WMI sets up on the target before its first action:
        the files of the run and its channel, as the preparation of every R1
        run writes them, and the gate its intermediate will wait on. None of it
        is an action and none of it is recorded as one.
    #>
    param(
        [Parameter(Mandatory = $true)][hashtable]$Transport,
        [Parameter(Mandatory = $true)]$Session,
        [Parameter(Mandatory = $true)]$Plan,
        [AllowNull()]$Approval
    )

    $files = @{}
    foreach ($name in $Plan.files.Keys) { $files[$name] = [string]$Plan.files[$name] }
    $channelConfig = [ordered]@{
        connect      = ($null -ne $Approval)
        target       = $null
        port         = $null
        protocol     = $null
        lab_cidr     = $null
        max_attempts = 1
        timeout_ms   = $R1_CONNECT_TIMEOUT_MS
        idle_sec     = $R1_TASK_IDLE_SEC
    }
    if ($null -ne $Approval) {
        $channelConfig.target = $Approval.target
        $channelConfig.port = $Approval.port
        $channelConfig.protocol = $Approval.protocol
        $channelConfig.lab_cidr = $Approval.lab_cidr
    }
    & $Transport.invoke $Session "prepare" @{
        work_dir       = $Plan.work_dir
        channel_dir    = $Plan.channel_dir
        files          = $files
        config_file    = $R1_CONFIG_FILE
        channel_config = ($channelConfig | ConvertTo-Json)
        note_file      = $R1_PREPARED_NOTE
    } | Out-Null
    & $Transport.invoke $Session "open_gate" @{ pipe_name = [string]$Plan.intermediate.gate_pipe } | Out-Null
}

function Get-R1PolicyProvenance {
    <#
        The provenance of the registered policies a rendered scenario carries.

        A scenario names its policies by identity. When it is rendered, the
        loaders of the two registries read the registered configuration and
        what they said is written into the rendered scenario as
        policy_provenance: the identity and the hash of each policy and, for
        the reference policy, the values a run needs from it - which program
        the reference is the process-create record of, and the window after the
        call in which that record is looked for.

        This file has no reader for the registered configuration, so nothing is
        compared with it here. The block is held to the scenario it is in, so a
        block of another scenario or one with a value missing starts nothing,
        and it is copied into the collection provenance of the run. The
        validator resolves the names again through the loaders and holds both
        copies to what the loaders say then.

        Returns the block, or $null for a scenario that names no policy. A
        scenario whose intermediate is started through WMI has to carry it.
    #>
    param(
        [Parameter(Mandatory = $true)]$Scenario,
        [Parameter(Mandatory = $true)]$CollectionProfile
    )

    $stated = Get-R1Value $Scenario "policy_provenance"
    if ($null -eq $stated) {
        if ($CollectionProfile.entry_kind -ceq $R1_ENTRY_WMI) {
            throw ("policy_provenance is missing from the scenario: a scenario whose intermediate is " +
                "started through WMI is rendered with the registered policies it names " +
                "(policies.approved_lineage and policies.reference)")
        }
        return $null
    }

    Assert-R1Keys -Object $stated -Label "policy_provenance" -Keys @("approved_lineage", "reference")
    $approved = Get-R1Value $stated "approved_lineage"
    $reference = Get-R1Value $stated "reference"
    Assert-R1Keys -Object $approved -Label "policy_provenance.approved_lineage" -Keys @(
        "policy_id", "version", "family_id", "lifecycle", "config_path", "config_hash", "loader")
    Assert-R1Keys -Object $reference -Label "policy_provenance.reference" -Keys @(
        "policy_id", "version", "family_id", "config_path", "config_hash", "loader", "reference_action_id",
        "action_type", "reference_process_name", "candidate_start_offset_sec", "candidate_window_sec",
        "success_return_value", "require_process_id", "expected_evaluation_horizon_sec")

    foreach ($block in @(@{ name = "approved_lineage"; value = $approved }, @{ name = "reference"; value = $reference })) {
        foreach ($field in @("policy_id", "version", "family_id", "config_path", "loader")) {
            $text = Get-R1Value $block.value $field
            if ($text -isnot [string] -or [string]::IsNullOrWhiteSpace($text)) {
                throw ("policy_provenance." + $block.name + "." + $field + " must be a non-blank string")
            }
        }
        $hash = Get-R1Value $block.value "config_hash"
        if ($hash -isnot [string] -or $hash -cnotmatch '^[0-9a-f]{64}$') {
            throw ("policy_provenance." + $block.name + ".config_hash is not a SHA-256 in lower case hex")
        }
        $family = [string](Get-R1Value $block.value "family_id")
        if ($family -cne [string](Get-R1Value $Scenario "family_id")) {
            throw ("policy_provenance." + $block.name + ".family_id is '" + $family + "', the scenario is of the " +
                "family '" + [string](Get-R1Value $Scenario "family_id") + "'")
        }
    }

    # The reference policy has to be the one this scenario was rendered with.
    $statedVersion = [string](Get-R1Value (Get-R1Value $Scenario "run_metadata") "reference_policy_version")
    if ([string]$reference.version -cne $statedVersion) {
        throw ("policy_provenance.reference.version is '" + [string]$reference.version +
            "', run_metadata.reference_policy_version is '" + $statedVersion + "'")
    }
    $attackRun = Get-R1Value (Get-R1Value $Scenario "runs") "attack"
    $namedAction = [string](Get-R1Value $attackRun "reference_action_id")
    if ([string]$reference.reference_action_id -cne $namedAction) {
        throw ("policy_provenance.reference.reference_action_id is '" + [string]$reference.reference_action_id +
            "', runs.attack.reference_action_id is '" + $namedAction + "'")
    }
    $horizon = Get-R1Value (Get-R1Value $Scenario "run_length") "evaluation_horizon_sec"
    if (-not (Test-R1WholeNumber $reference.expected_evaluation_horizon_sec) -or
        [long]$reference.expected_evaluation_horizon_sec -ne [long]$horizon) {
        throw ("policy_provenance.reference.expected_evaluation_horizon_sec is '" +
            [string]$reference.expected_evaluation_horizon_sec + "', run_length.evaluation_horizon_sec is '" +
            [string]$horizon + "'")
    }
    $plannedAttack = [string](Get-R1Value (Get-R1Value (Get-R1Value (
                    Get-R1Value $Scenario "planned_lineage") "intermediate") "attack") "image")
    if ($reference.reference_process_name -isnot [string] -or
        -not [string]::Equals($reference.reference_process_name, $plannedAttack, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw ("policy_provenance.reference.reference_process_name is '" + [string]$reference.reference_process_name +
            "', the attack run is planned to start '" + $plannedAttack + "'")
    }

    # The window a created process is looked for in, in whole seconds after the call.
    $startOffset = $reference.candidate_start_offset_sec
    $windowSec = $reference.candidate_window_sec
    if (-not (Test-R1WholeNumber $startOffset) -or [long]$startOffset -lt 0 -or
        -not (Test-R1WholeNumber $windowSec) -or [long]$windowSec -lt 1 -or [long]$windowSec -lt [long]$startOffset) {
        throw ("policy_provenance.reference states no usable window: candidate_start_offset_sec '" +
            [string]$startOffset + "', candidate_window_sec '" + [string]$windowSec + "'")
    }
    if (-not (Test-R1WholeNumber $reference.success_return_value)) {
        throw "policy_provenance.reference.success_return_value must be a whole number"
    }
    if ($reference.require_process_id -isnot [bool] -or -not $reference.require_process_id) {
        throw "policy_provenance.reference.require_process_id must be true: a call that returned no process id started nothing"
    }
    return $stated
}

function Get-R1WmiCreatedProcessEvent {
    <#
        Find the Sysmon record of the process the first action of a run through
        WMI created. Both runs of a Pair are held to it; an attack run also
        takes its reference from that record.

        This is the path of an entry through WMI only. The reference of the
        session entry is Get-R1ReferenceEvent, which this function does not call
        and does not change.

        A candidate is an EID 1 of the target
          - whose Image is the planned program,
          - whose EventData.UtcTime lies in the window the registered reference
            policy gives after the call, both ends included,
          - whose ParentProcessGuid is the ProcessGuid of a context record of
            the planned root: a process-create record of that program written
            before the start of the run.
        Exactly one candidate is the record; with none, or with several, nothing
        is chosen. The process id the call returned does not find a record: it
        is compared after the record was found, and a record that carries
        another one leaves the run without a created process. ParentImage and
        TimeCreated are never read, and a record of either program whose
        UtcTime cannot be read is not skipped and not given another time.

        The record is then tied to the lineage of the run: it has to be the
        parent of the final tool, by ProcessGuid.

        Returns status "selected" with reference_time (a UTC stamp),
        reference_source_event_id (the RecordId as a string), process_guid, the
        RecordId of the context parent and the RecordIds of the candidates, or
        status "undetermined" with the reason and the candidates found so far.
    #>
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Records,
        [Parameter(Mandatory = $true)][string]$ComputerName,
        [Parameter(Mandatory = $true)][string]$ExpectedImage,
        [Parameter(Mandatory = $true)][string]$ExpectedRootImage,
        [Parameter(Mandatory = $true)][datetime]$RunStart,
        [Parameter(Mandatory = $true)][datetime]$NotBefore,
        [Parameter(Mandatory = $true)][datetime]$NotAfter,
        [Parameter(Mandatory = $true)][int]$ReturnedProcessId,
        [AllowNull()][AllowEmptyString()][string]$FinalProcessGuid
    )

    $candidateIds = New-Object System.Collections.Generic.List[string]
    $undetermined = {
        param($Reason)
        return [ordered]@{
            status = "undetermined"; reason = $Reason; reference_time = $null
            reference_source_event_id = $null; process_guid = $null; parent_record_id = $null
            candidate_record_ids = [string[]]$candidateIds.ToArray()
        }
    }

    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor
        [System.Globalization.DateTimeStyles]::AdjustToUniversal
    $readTime = {
        param($Stated)
        $moment = [datetime]::MinValue
        if ($Stated -isnot [string] -or -not [datetime]::TryParseExact($Stated, $R1_EVENT_UTC_FORMAT,
                [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$moment)) { return $null }
        return $moment
    }

    $creates = @{}
    $contextRoots = @{}
    $inWindow = New-Object System.Collections.Generic.List[object]
    foreach ($record in $Records) {
        if ([string](Get-R1Value $record "Computer") -ne $ComputerName) { continue }
        if ([string](Get-R1Value $record "EventId") -ne "1") { continue }
        $data = Get-R1Value $record "EventData"
        $guid = [string](Get-R1Value $data "ProcessGuid")
        if (-not [string]::IsNullOrEmpty($guid)) {
            if (-not $creates.ContainsKey($guid)) { $creates[$guid] = New-Object System.Collections.Generic.List[object] }
            $creates[$guid].Add($record)
        }

        $name = [System.IO.Path]::GetFileName([string](Get-R1Value $data "Image"))
        if ($name -ne $ExpectedRootImage -and $name -ne $ExpectedImage) { continue }
        # A record of either program without a readable time is not skipped:
        # skipping it could leave one other record looking unique.
        $created = & $readTime (Get-R1Value $data "UtcTime")
        if ($null -eq $created) {
            return (& $undetermined ("an EID 1 of " + $name + " has no readable EventData.UtcTime ('" +
                [string](Get-R1Value $data "UtcTime") + "'); TimeCreated is not used in its place"))
        }
        if ($name -eq $ExpectedRootImage -and $created -lt $RunStart -and -not [string]::IsNullOrEmpty($guid)) {
            $contextRoots[$guid] = $record
        }
        if ($name -eq $ExpectedImage -and $created -ge $NotBefore -and $created -le $NotAfter) {
            $inWindow.Add(@{ record = $record; data = $data; created = $created })
        }
    }

    $fitting = @($inWindow | Where-Object { $contextRoots.ContainsKey([string](Get-R1Value $_.data "ParentProcessGuid")) })
    foreach ($item in $fitting) { $candidateIds.Add([string](Get-R1Value $item.record "RecordId")) }
    $described = ("of " + $ExpectedImage + " whose parent is a context " + $ExpectedRootImage)
    $window = (Get-UtcStamp $NotBefore) + " .. " + (Get-UtcStamp $NotAfter)
    if ($fitting.Count -eq 0) {
        return (& $undetermined ("no EID 1 " + $described + " was recorded on " + $ComputerName + " in " + $window))
    }
    if ($fitting.Count -gt 1) {
        return (& $undetermined ([string]$fitting.Count + " EID 1 records " + $described + " were recorded on " +
            $ComputerName + " in " + $window + "; exactly one is the process the action created, and " +
            "nothing chooses between them"))
    }

    $chosen = $fitting[0]
    $guid = [string](Get-R1Value $chosen.data "ProcessGuid")
    if ([string]::IsNullOrWhiteSpace($guid)) {
        return (& $undetermined "the EID 1 of the created process carries no ProcessGuid")
    }
    $recordId = [string](Get-R1Value $chosen.record "RecordId")
    if ($recordId -notmatch "^[0-9]+$") {
        return (& $undetermined ("the EID 1 of the created process carries no usable RecordId ('" +
            $recordId + "')"))
    }
    $rootGuid = [string](Get-R1Value $chosen.data "ParentProcessGuid")
    foreach ($checked in @(@{ guid = $guid; what = "the created process" }, @{ guid = $rootGuid; what = "its parent" })) {
        if ($creates[$checked.guid].Count -ne 1) {
            return (& $undetermined ("ProcessGuid " + $checked.guid + " of " + $checked.what + " has " +
                $creates[$checked.guid].Count + " process-create records on " + $ComputerName))
        }
    }
    # The process id does not find the record. It is what the call returned,
    # and the record that was found has to carry it.
    $recordedPid = [string](Get-R1Value $chosen.data "ProcessId")
    if ($recordedPid -ne [string]$ReturnedProcessId) {
        return (& $undetermined ("the EID 1 of the created process (RecordId " + $recordId +
            ") carries process id '" + $recordedPid + "', the call returned " + $ReturnedProcessId))
    }

    # The created process is the intermediate of the lineage of this run: the
    # parent of its final tool, by ProcessGuid.
    if ([string]::IsNullOrEmpty($FinalProcessGuid) -or -not $creates.ContainsKey($FinalProcessGuid) -or
        $creates[$FinalProcessGuid].Count -ne 1) {
        return (& $undetermined ("the final tool of the lineage of this run was not established, so the " +
            "created process (" + $guid + ") cannot be tied to it by ProcessGuid"))
    }
    $parentOfFinal = [string](Get-R1Value (Get-R1Value $creates[$FinalProcessGuid][0] "EventData") "ParentProcessGuid")
    if ($parentOfFinal -ne $guid) {
        return (& $undetermined ("the created process has ProcessGuid " + $guid +
            ", but the parent of the final tool of this run is " + $parentOfFinal))
    }

    return [ordered]@{
        status                    = "selected"
        reason                    = "one EID 1 of the planned program, created in the window of the reference policy by a context parent"
        reference_time            = (Get-UtcStamp $chosen.created)
        reference_source_event_id = $recordId
        process_guid              = $guid
        parent_record_id          = [string](Get-R1Value $contextRoots[$rootGuid] "RecordId")
        candidate_record_ids      = [string[]]$candidateIds.ToArray()
    }
}

function Write-R1RunFailure {
    <#
        Leave one record of a failed run in its operator trace.

        A run that fails writes none of the files a completed run ends with: no
        execution_record, no run_metadata, no manifest and no collection
        provenance. What it leaves instead is this record: where it stopped and
        why, what the launch through WMI returned when the run got that far, and
        which candidates a reference was looked for among. It is a diagnostic.
        It is in no Manifest, it is not Ground Truth, and nothing reads it as
        the result of a run.

        Returns the path, or $null when the record could not be written: the
        failure that is being recorded is never replaced by one of this
        function.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$TraceDir,
        [Parameter(Mandatory = $true)][string]$EffectiveRoot,
        [Parameter(Mandatory = $true)][string]$RunId,
        [Parameter(Mandatory = $true)][string]$RunType,
        [Parameter(Mandatory = $true)][string]$Mode,
        [Parameter(Mandatory = $true)][string]$EntryKind,
        [Parameter(Mandatory = $true)][string]$Stage,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Reason,
        [AllowNull()]$LaunchReturned,
        [AllowNull()]$Reference
    )

    try {
        $plain = {
            param($Value)
            if ($null -eq $Value) { return $null }
            if (Test-R1WholeNumber $Value) { return [long]$Value }
            return [string]$Value
        }
        $launch = $null
        if ($null -ne $LaunchReturned) {
            $launch = [ordered]@{
                action_utc    = (& $plain (Get-R1Value $LaunchReturned "utc"))
                completed_utc = (& $plain (Get-R1Value $LaunchReturned "completed_utc"))
                return_value  = (& $plain (Get-R1Value $LaunchReturned "return_value"))
                process_id    = (& $plain (Get-R1Value $LaunchReturned "process_id"))
            }
        }
        $looked = $null
        if ($null -ne $Reference) {
            $looked = [ordered]@{
                status               = [string](Get-R1Value $Reference "status")
                reason               = [string](Get-R1Value $Reference "reason")
                candidate_record_ids = [string[]]@(Get-R1Value $Reference "candidate_record_ids" |
                    Where-Object { $null -ne $_ })
            }
        }
        $record = [ordered]@{
            record_kind         = "diagnostic"
            canonical_artifact  = $false
            note                = ("A record of a failed run for the operator. It is in no contract of the " +
                "data set: it is not Ground Truth, not RunMetadata, not a Manifest and not a result.")
            failure_version     = "r1-run-failure-v0.1"
            run_id              = $RunId
            run_type            = $RunType
            mode                = $Mode
            entry_kind          = $EntryKind
            run_completed       = $false
            stage               = $Stage
            reason              = $Reason
            completed_run_files = [ordered]@{
                execution_record      = (Test-Path -LiteralPath (Join-Path $EffectiveRoot "ground_truth\$RunId\execution_record.csv"))
                run_metadata          = (Test-Path -LiteralPath (Join-Path $EffectiveRoot "ground_truth\$RunId\run_metadata.json"))
                manifest              = (Test-Path -LiteralPath (Join-Path $EffectiveRoot "raw\$RunId\manifest.json"))
                collection_provenance = (Test-Path -LiteralPath (Join-Path $TraceDir $R1_PROVENANCE_FILE))
            }
            launch_returned     = $launch
            reference           = $looked
        }
        $path = Join-Path $TraceDir $R1_FAILURE_FILE
        $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        Write-R1NewFile -Path $path -Bytes $utf8NoBom.GetBytes(($record | ConvertTo-Json -Depth 6))
        return $path
    } catch {
        Write-Fail ("the failure record could not be written: " + $_.Exception.Message)
        return $null
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

function New-R1CompletionStage {
    <# A same-volume private tree in which every completion artifact is built first. #>
    param(
        [Parameter(Mandatory = $true)]$Context,
        [Parameter(Mandatory = $true)][string]$EffectiveRoot,
        [Parameter(Mandatory = $true)][string]$RunId
    )

    $root = Join-Path $EffectiveRoot (".r1-completion-" + $RunId + "-" + [guid]::NewGuid().ToString("N"))
    $groundTruth = Join-Path $root ("ground_truth\" + $RunId)
    $telemetry = Join-Path $root ("raw\" + $RunId + "\telemetry")
    $trace = Join-Path $root ("operator_trace\" + $RunId)
    foreach ($dir in @($groundTruth, $telemetry, $trace)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    $stagedContext = [ordered]@{}
    foreach ($key in $Context.Keys) { $stagedContext[$key] = $Context[$key] }
    $stagedContext.ground_truth_dir = $groundTruth
    $stagedContext.telemetry_dir = $telemetry
    return [ordered]@{
        root       = $root
        trace_dir  = $trace
        context    = $stagedContext
    }
}

function Publish-R1CompletionFile {
    <# Atomically move one staged file into an empty final run directory. #>
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination,
        [Parameter(Mandatory = $true)]$Published
    )

    if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) {
        throw ("a staged completion file is missing: " + $Source)
    }
    [System.IO.File]::Move($Source, $Destination)
    $Published.Add($Destination)
    return $Destination
}

function Remove-R1CompletionStage {
    <# Remove only a private completion tree created by New-R1CompletionStage. #>
    param([AllowNull()]$Stage)

    if ($null -ne $Stage -and -not [string]::IsNullOrWhiteSpace([string]$Stage.root) -and
        (Test-Path -LiteralPath ([string]$Stage.root))) {
        [System.IO.Directory]::Delete([string]$Stage.root, $true)
    }
}

function Get-R1FailureCleanupOwnedProcesses {
    <# Only PIDs returned by successful WMI actions are owned by this failed run. #>
    param([AllowNull()]$WmiCall, [AllowNull()]$ToolStart, [Parameter(Mandatory = $true)]$Plan)

    $owned = New-Object System.Collections.Generic.List[object]
    if ($null -ne $WmiCall -and [int]$WmiCall.process_id -gt 0) {
        $owned.Add([ordered]@{
            process_id            = [int]$WmiCall.process_id
            image                 = [string]$Plan.expected_lineage[1]
            created_not_before_utc = [string]$WmiCall.action_utc
        })
    }
    if ($null -ne $ToolStart -and [int]$ToolStart.final_pid -gt 0) {
        $owned.Add([ordered]@{
            process_id            = [int]$ToolStart.final_pid
            image                 = [string]$Plan.expected_lineage[0]
            created_not_before_utc = [string]$ToolStart.action_utc
        })
    }
    return [object[]]$owned.ToArray()
}

function Invoke-R1PilotRun {
    <#
        Run one R1-V02 run and write its artifacts.

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
          8. an attack run takes its reference from those records - the EID 1 of
             the session host its first action created, or, with an entry
             through WMI, the EID 1 of the process its launch action created -
             and a collection run has to have observed the evaluation horizon
             after it,
          9. only then execution_record, run_metadata and the manifest are written.

        A failure at any step throws before step 9, so a failed run never has the
        three files a valid run has. A run whose scenario declares a collection
        block also leaves a record of the failure in its operator trace, once
        that trace exists. A rehearsal skips the waits, may skip the
        connection, writes under _rehearsal, does not stop on step 7 and is not
        held to the horizon of step 8. Its attack run still needs its reference.

        The dataset tier is not an input of a run. It is read from the scenario
        in step 1, where the identity of the Pair is read, and written to the
        operator trace of the run; the scenario of a rehearsal has to state
        pilot. A dry run reads and reports it too and writes nothing, the trace
        included.

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
        [AllowEmptyString()][string]$ReadinessRecordPath,
        [AllowEmptyString()][string]$IncrementalStreamControlRoot,
        [switch]$PositionFinality,
        [int]$PositionFreezeAckTimeoutSec = 900,
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
    $collectionProfile = Get-R1CollectionProfile -Scenario $scenario
    $entryIsSession = ($collectionProfile.entry_kind -ceq $R1_ENTRY_REMOTING)
    $rawFromBoot = ($collectionProfile.raw_window -ceq $R1_RAW_WINDOW_BOOT)
    if ($entryIsSession -and -not [string]::IsNullOrWhiteSpace($IncrementalStreamControlRoot)) {
        throw "IncrementalStreamControlRoot is supported only by the WMI collection path"
    }
    if ($PositionFinality) {
        if ([string]::IsNullOrWhiteSpace($IncrementalStreamControlRoot)) {
            throw "PositionFinality needs IncrementalStreamControlRoot: the freeze request, the producer's ack and run-finalized are written there"
        }
        if ($entryIsSession) { throw "PositionFinality is supported only by the WMI collection path" }
        if ($PositionFreezeAckTimeoutSec -lt 1) { throw "PositionFreezeAckTimeoutSec must be at least 1" }
    }
    # The registered policies the scenario was rendered with. A scenario whose
    # intermediate is started through WMI has to carry them: nothing is
    # started without them, not even a dry run.
    $policyProvenance = Get-R1PolicyProvenance -Scenario $scenario -CollectionProfile $collectionProfile

    $pairLine = ("pair: family_id=" + $identity.family_id + " variation_id=" + $identity.variation_id +
        " repetition=" + $identity.repetition)

    if ($DryRun) {
        Write-Ok ("dry run: " + $RunId + " (" + $RunType + ") would start " +
            $plan.intermediate.executable + " " + ($plan.intermediate.arguments -join " "))
        Write-Ok ("dry run: the final tool command is " + $plan.final.command_line)
        Write-Ok ("dry run: " + $pairLine)
        Write-Ok ("dry run: scenario sha256=" + $inputs.scenario_sha256)
        Write-Ok ("dry run: dataset_tier=" + $inputs.dataset_tier + " (stated by the scenario)")
        if (-not $entryIsSession -or $collectionProfile.collection_declared) {
            Write-Ok ("dry run: entry=" + $collectionProfile.entry_kind + " root=" + $collectionProfile.root_image +
                " raw_window=" + $collectionProfile.raw_window + " readiness_method=" +
                [string]$collectionProfile.readiness_method)
        }
        return [ordered]@{
            mode            = "dry_run"
            run_id          = $RunId
            run_type        = $RunType
            dataset_tier    = $inputs.dataset_tier
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

    # Readiness established from outside the target is an input of the run. It
    # is read and checked here, before the first session, so a record that is
    # missing or does not say "ready, and nothing connected" starts nothing. A
    # scenario that states no readiness method takes no such record.
    $readiness = $null
    if ($collectionProfile.readiness_method -ceq $R1_READINESS_OUT_OF_BAND) {
        $readiness = Read-R1ReadinessRecord -Path $ReadinessRecordPath
    } elseif (-not [string]::IsNullOrWhiteSpace($ReadinessRecordPath)) {
        throw ("ReadinessRecordPath was given, but this scenario states no collection.readiness_method; " +
            "a readiness record is not an input of this run")
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
    # What a failure record of this run would say: where the run is, and what
    # it has got from the target so far.
    $traceDir = $null
    $stage = "pre_run_check"
    $launchReturned = $null
    $wmiCall = $null
    $wmiActionId = $null
    $toolStart = $null
    $runEnd = $null
    $toolIdentity = $null
    $reference = $null
    $completionStage = $null
    $publishedCompletionPaths = New-Object System.Collections.Generic.List[string]
    try {
        # --- 3. pre-run session ------------------------------------------------
        Write-Step "pre-run check of Target-A"
        $session = & $Transport.open $Connection
        $probeArguments = @{
            sysmon_binary      = $TargetSysmonBinary
            sysmon_config_path = $TargetSysmonConfigPath
            log_name           = $SYSMON_LOG
        }
        # The boot time of the target is the start of an extended raw window.
        if ($rawFromBoot) { $probeArguments.read_boot_time = $true }
        $probe = & $Transport.invoke $session "probe" $probeArguments
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

        # The raw export of this run starts here: at the start of the run, as it
        # always has, or at the boot of the target when the scenario says the
        # root of the lineage was created then. Both are stamps of the target.
        $rawStartTime = $startTime
        if ($rawFromBoot) {
            $rawStartTime = ConvertTo-R1Utc (Get-R1Value $probe "boot_utc") "probe boot_utc"
            if ($rawStartTime -gt $startTime) {
                throw ("the target reports a boot at " + (Get-UtcStamp $rawStartTime) +
                    ", after the start of the run (" + (Get-UtcStamp $startTime) + ")")
            }
        }

        if (-not [string]::IsNullOrWhiteSpace($IncrementalStreamControlRoot)) {
            $controlDir = Join-Path $IncrementalStreamControlRoot $RunId
            New-Item -ItemType Directory -Path $controlDir -Force | Out-Null
            if ($PositionFinality) {
                # Before any action: no artifact of this run yet, and a producer
                # for the same Run, host, partition and contract.
                $stage = "position_preflight"
                $preflightPaths = Get-R1PositionPaths -ControlDir $controlDir
                Assert-R1PositionControlFree -Paths $preflightPaths
                Assert-R1PositionPreflight -Paths $preflightPaths -RunId $RunId -TargetHost $targetHost `
                    -Channel $SYSMON_LOG -ExpectedContextStartUtc $rawStartTime -Scenario $scenario
                $stage = "pre_run_check"
            }
            $startControl = [ordered]@{
                schema = "r1-incremental-run-control"
                contract_version = "v0.1"
                message_type = "run_started"
                run_id = $RunId
                target_host = $targetHost
                run_start = (Get-UtcStamp $startTime)
            }
            $utf8Control = New-Object System.Text.UTF8Encoding($false)
            Write-R1AtomicNewFile -Path (Join-Path $controlDir "run-started.json") `
                -Bytes $utf8Control.GetBytes(($startControl | ConvertTo-Json -Compress))
        }

        if ($null -ne $readiness -and $readiness.checked_at_time -gt $startTime) {
            throw ("the readiness record was taken at " + $readiness.checked_at +
                ", after the start of the run (" + (Get-UtcStamp $startTime) + ")")
        }

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
            -Scenario $scenario -ScenarioBytes $inputs.scenario_bytes `
            -ScenarioSha256 $inputs.scenario_sha256
        Write-Ok ("operator trace written: dataset_tier=" + $inputs.dataset_tier + " mode=" + $mode +
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
        $sessionImage = ""
        $sessionBeginAt = $null
        $sessionOpenedAt = $null
        $launched = $null
        if (-not $entryIsSession) {
            # A run through WMI sets up its session, its files and the gate of
            # its intermediate before its first action. None of it is an action.
            $stage = "setup"
            Write-Step "setting up the run on Target-A"
            $session = & $Transport.open $Connection
            Invoke-R1WmiRunSetup -Transport $Transport -Session $session -Plan $plan -Approval $approval
        }
        foreach ($action in $inputs.actions) {
            $actionId = [string](Get-R1Value $action "action_id")
            $step = [string](Get-R1Value $action "step")
            if (-not $Rehearsal) {
                Wait-R1Until -Due $clockStart.AddSeconds([int](Get-R1Value $action "offset_sec")) `
                    -NowProvider $NowProvider -Sleeper $Sleeper
            }
            Write-Step ($actionId + " " + $step)
            $stage = "action:" + $step

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
                $sessionImage = [string](Get-R1Value $begin "session_image")

                # The stamp Target-A takes once the session exists bounds it.
                $openedAt = ConvertTo-R1Utc $begin.utc "begin utc"
                if ($beginAt -gt $openedAt) {
                    throw ("the session was open at " + (Get-UtcStamp $openedAt) + " on the target, before the " +
                        "recorded start of that action (" + (Get-UtcStamp $beginAt) + "): a clock moved during the run")
                }
                # The session host was created between these two stamps.
                $sessionBeginAt = $beginAt
                $sessionOpenedAt = $openedAt
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
            } elseif ($step -eq "invoke") {
                $launchReturned = & $Transport.invoke $session "launch_wmi" @{
                    command_line = $plan.intermediate.command_line
                    work_dir     = $plan.work_dir
                }
                # The action succeeded only with a return value of 0 and a
                # process id; anything else stops the run here. It is
                # recorded at the stamp the target took right before the call.
                $wmiActionId = $actionId
                $wmiCall = Get-R1WmiCreateResult -Created $launchReturned `
                    -SuccessReturnValue ([long]$policyProvenance.reference.success_return_value)
                Add-ExecutionRecord -Context $context -ActionId $actionId -Timestamp $wmiCall.action_time
            } elseif ($step -eq "launch" -and -not $entryIsSession) {
                # The intermediate has been waiting since the launch. It is
                # told to start the final tool, and the action is recorded at
                # the stamp the target took right before it was told.
                $toolReturned = & $Transport.invoke $session "start_tool" @{
                    channel_dir      = $plan.channel_dir
                    ready_file       = $R1_READY_FILE
                    timeout_sec      = $R1_READY_TIMEOUT_SEC
                    gate_word        = $R1_GATE_WORD
                    gate_timeout_sec = $R1_GATE_TIMEOUT_SEC
                }
                $toolStart = Get-R1ToolStartResult -Started $toolReturned
                $launched = @{ intermediate_pid = $wmiCall.process_id; final_pid = $toolStart.final_pid }
                Add-ExecutionRecord -Context $context -ActionId $actionId -Timestamp $toolStart.action_time
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
                    # The connection of a run through WMI is made by the tool its
                    # second action started, and by no other process.
                    if (-not $entryIsSession -and [int]$status.pid -ne [int]$launched.final_pid) {
                        throw ("the connection was reported by process id " + [string]$status.pid +
                            ", the final tool this run started is process id " + [string]$launched.final_pid)
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
            } elseif ($step -eq "run_end") {
                # The session did not start the processes of this run, so
                # closing it would not end them. The run ends the two it
                # started, by process id, and nothing else.
                $ownedIds = [int[]]@($wmiCall.process_id, $toolStart.final_pid)
                $endReturned = & $Transport.invoke $session "end_run" @{
                    owned    = @(
                        @{ process_id = $wmiCall.process_id; image = [string]$plan.expected_lineage[1]
                           created_not_before_utc = $wmiCall.action_utc },
                        @{ process_id = $toolStart.final_pid; image = [string]$plan.expected_lineage[0]
                           created_not_before_utc = $toolStart.action_utc })
                    wait_sec = $R1_RUN_END_WAIT_SEC
                }
                $runEnd = Get-R1RunEndResult -Ended $endReturned -OwnedProcessIds $ownedIds `
                    -RootImage ([string]$plan.expected_lineage[2])
                & $Transport.close $session | Out-Null
                $session = $null
                Add-ExecutionRecord -Context $context -ActionId $actionId -Timestamp $runEnd.action_time
                if (-not [string]::IsNullOrWhiteSpace($IncrementalStreamControlRoot)) {
                    $boundaryControl = [ordered]@{
                        schema = "r1-incremental-run-control"
                        contract_version = "v0.1"
                        message_type = "candidate_boundary_completed"
                        run_id = $RunId
                        target_host = $targetHost
                        action_id = $actionId
                        candidate_boundary_at = [string]$runEnd.completed_utc
                    }
                    $controlDir = Join-Path $IncrementalStreamControlRoot $RunId
                    $utf8Control = New-Object System.Text.UTF8Encoding($false)
                    Write-R1AtomicNewFile -Path (Join-Path $controlDir "candidate-boundary-completed.json") `
                        -Bytes $utf8Control.GetBytes(($boundaryControl | ConvertTo-Json -Compress))
                }
            }
        }

        # --- 5. observation window ---------------------------------------------
        $stage = "observation_window"
        if ($Rehearsal) {
            Write-Fail "observation window skipped (rehearsal)"
        } else {
            Wait-R1Until -Due $clockStart.AddSeconds($ObservationSec) -NowProvider $NowProvider -Sleeper $Sleeper
        }

        # --- 5b. collection freeze (RecordId position finality) ---------------------
        # The request is written once the observation boundary of the run has
        # passed on the Controller clock too, also in a rehearsal, and the run
        # exports nothing until the producer has acked a RecordId bound.
        $positionPaths = $null
        $freezeRequest = $null
        $frozen = $null
        if ($PositionFinality) {
            $stage = "collection_freeze"
            $positionPaths = Get-R1PositionPaths -ControlDir (Join-Path $IncrementalStreamControlRoot $RunId)
            $candidateBoundary = Read-R1CandidateBoundary -ControlDir $positionPaths.control_dir -RunId $RunId `
                -TargetHost $targetHost
            $observationBoundary = $startTime.AddSeconds($ObservationSec)
            Wait-R1Until -Due $observationBoundary -NowProvider $NowProvider -Sleeper $Sleeper
            $freezeRequest = New-R1FreezeRequest -RunId $RunId -TargetHost $targetHost -Channel $SYSMON_LOG `
                -CandidateBoundaryAt $candidateBoundary -ObservationBoundaryAt $observationBoundary `
                -RequestedAt (& $NowProvider)
            Write-R1PositionJson -Path $positionPaths.request -Value $freezeRequest | Out-Null
            Write-Step ("collection freeze requested; waiting for the producer's ack (" +
                $PositionFreezeAckTimeoutSec + " s at most)")
            $frozen = Wait-R1FreezeAck -Paths $positionPaths -Request $freezeRequest `
                -RequestSha256 (Get-R1FileSha256 -Path $positionPaths.request) `
                -TimeoutSec $PositionFreezeAckTimeoutSec -NowProvider $NowProvider -Sleeper $Sleeper
            Write-Ok ("collection freeze acked: RecordId " + $frozen.lower + ".." + $frozen.upper + ", " +
                $frozen.target_event_count + " EID 1/3 Event(s)")
        }

        # --- 6. collection session ---------------------------------------------
        $stage = "collection"
        Write-Step "collecting the Sysmon window from Target-A"
        $exportPath = $plan.work_dir + "\" + $R1_EXPORT_FILE
        $evtxPath = Join-Path $telemetryDir "sysmon-0001.evtx"
        $jsonlPath = Join-Path $telemetryDir "sysmon-0001.jsonl"

        # The target measures the window itself, from the start it stamped.
        $session = & $Transport.open $Connection
        $export = & $Transport.invoke $session "export" @{
            start_utc   = (Get-UtcStamp $rawStartTime)
            margin_ms   = $EVTX_WINDOW_MARGIN_MS
            log_name    = $SYSMON_LOG
            event_ids   = @($SYSMON_EVENT_IDS)
            export_path = $exportPath
        }
        & $Transport.fetch $session ([string]$export.evtx_path) $evtxPath | Out-Null
        $cleanupPaths = @($plan.channel_dir, $exportPath)
        $positionExport = $null
        if ($PositionFinality) {
            # The canonical snapshot: the same closed RecordId bound the producer
            # acked, exported next to the time-window export and never in its place.
            $stage = "record_bounded_export"
            $positionExportPath = $plan.work_dir + "\" + $R1_POSITION_EXPORT_FILE
            $cleanupPaths += $positionExportPath
            $positionExport = & $Transport.invoke $session "export_record_bounded" @{
                log_name      = $SYSMON_LOG
                lower         = [long]$frozen.lower
                upper         = [long]$frozen.upper
                expected_host = $targetHost
                export_path   = $positionExportPath
            }
            $positionExportObservedAt = & $NowProvider
            New-Item -ItemType Directory -Path $positionPaths.telemetry_dir | Out-Null
            & $Transport.fetch $session ([string]$positionExport.evtx_path) $positionPaths.evtx | Out-Null
            $stage = "collection"
        }
        & $Transport.invoke $session "cleanup" @{ paths = $cleanupPaths } | Out-Null
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

        $positionSnapshot = $null
        if ($PositionFinality) {
            $stage = "record_bounded_snapshot"
            $positionSnapshot = Complete-R1PositionSnapshot -Paths $positionPaths -Request $freezeRequest `
                -Frozen $frozen -Export $positionExport -ExportObservedAt $positionExportObservedAt `
                -RunId $RunId -TargetHost $targetHost -Channel $SYSMON_LOG -Convert $Transport.convert `
                -NowProvider $NowProvider
            Write-Ok ("RecordId-bounded snapshot exported: " + $positionSnapshot.canonical_event_count +
                " Event(s), identity " + $positionSnapshot.canonical_identity_sha256)
        }

        # --- 7. lineage of this run ---------------------------------------------
        $stage = "lineage"
        $records = @(Get-Content -LiteralPath $jsonlPath -Encoding UTF8 |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            ForEach-Object { $_ | ConvertFrom-Json })
        $lineage = Test-R1RunLineage -Records $records -ComputerName $targetHost `
            -SessionPid $sessionPid -IntermediatePid ([int]$launched.intermediate_pid) `
            -FinalPid ([int]$launched.final_pid) -ExpectedLineage ([string[]]$plan.expected_lineage) `
            -Approval $approval -EntryKind $collectionProfile.entry_kind
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

        # --- 7b. the final tool of a run through WMI and its connection ---------
        # The tool is the one the launch action started, and the connection
        # of the run carries its ProcessGuid.
        if (-not $entryIsSession) {
            $stage = "tool_identity"
            $toolIdentity = Test-R1ToolConnectionIdentity -Records $records -ComputerName $targetHost `
                -FinalPid $toolStart.final_pid -NotBefore $toolStart.action_time `
                -NotAfter $toolStart.completed_time `
                -FinalProcessGuid ([string](Get-R1Value $lineage "final_process_guid")) -Approval $approval
            if ($toolIdentity.status -eq "mismatched") {
                Write-Fail ("tool identity: " + $toolIdentity.reason)
                if (-not $Rehearsal) { throw ("tool identity check failed: " + $toolIdentity.reason) }
            } else {
                Write-Ok ("tool identity: " + $toolIdentity.status + " (" + $toolIdentity.reason + ")")
            }
        }

        # --- 8. the process the first action created, and the reference of an attack run ---
        # Both runs through WMI: the first action succeeded only when exactly
        # one record is the process it created. The window that record is
        # looked for in is the one of the registered reference policy, counted
        # from the stamp taken right before the call.
        $referenceTime = $null
        $referenceEventId = $null
        $referenceResolution = $null
        $createdProcess = $null
        if (-not $entryIsSession) {
            $stage = "created_process"
            $referencePolicy = $policyProvenance.reference
            $windowStart = $wmiCall.action_time.AddSeconds([long]$referencePolicy.candidate_start_offset_sec)
            $windowEnd = $wmiCall.action_time.AddSeconds([long]$referencePolicy.candidate_window_sec)
            $reference = Get-R1WmiCreatedProcessEvent -Records $records -ComputerName $targetHost `
                -ExpectedImage ([string]$plan.expected_lineage[1]) `
                -ExpectedRootImage ([string]$plan.expected_lineage[2]) `
                -RunStart $startTime -NotBefore $windowStart -NotAfter $windowEnd `
                -ReturnedProcessId $wmiCall.process_id `
                -FinalProcessGuid ([string](Get-R1Value $lineage "final_process_guid"))
            if ($reference.status -ne "selected") {
                throw ("created process undetermined: " + $reference.reason)
            }
            $createdProcess = [ordered]@{
                action_id            = [string]$wmiActionId
                action_utc           = $wmiCall.action_utc
                window_start_utc     = (Get-UtcStamp $windowStart)
                window_end_utc       = (Get-UtcStamp $windowEnd)
                return_value         = [int]$wmiCall.return_value
                process_id           = [int]$wmiCall.process_id
                expected_image       = [string]$plan.expected_lineage[1]
                candidate_record_ids = [string[]]@($reference.candidate_record_ids)
                selected_record_id   = [string]$reference.reference_source_event_id
                parent_record_id     = [string]$reference.parent_record_id
            }
            Write-Ok ("created process: action=" + $wmiActionId + " record_id=" +
                $reference.reference_source_event_id + " process_guid=" + $reference.process_guid)
        }

        # No mode writes the Ground Truth of an attack run without its reference.
        $stage = "reference"
        if ($null -ne $inputs.reference_action_id) {
            if ($collectionProfile.reference_source -cne $R1_REFERENCE_SOURCE_WMI_CREATED) {
                $reference = Get-R1ReferenceEvent -Records $records -ComputerName $targetHost `
                    -SessionPid $sessionPid -SessionImage $sessionImage `
                    -ExpectedImage ([string]$plan.expected_lineage[2]) `
                    -NotBefore $sessionBeginAt -NotAfter $sessionOpenedAt `
                    -SessionHostGuid ([string](Get-R1Value $lineage "session_host_guid"))
            } elseif ([string]$inputs.reference_action_id -cne [string]$wmiActionId) {
                # The reference of an entry through WMI is the process its first
                # action created, so that action is the one the run names.
                throw ("the reference action is " + $inputs.reference_action_id + ", but the process was created by " +
                    [string]$wmiActionId)
            }
            if ($reference.status -ne "selected") {
                throw ("reference undetermined: " + $reference.reason)
            }
            $referenceTime = [string]$reference.reference_time
            $referenceEventId = [string]$reference.reference_source_event_id
            $referenceResolution = [ordered]@{
                source             = [string]$collectionProfile.reference_source
                action_id          = [string]$inputs.reference_action_id
                selected_record_id = $referenceEventId
            }
            Write-Ok ("reference: action=" + $inputs.reference_action_id + " reference_time=" + $referenceTime +
                " record_id=" + $referenceEventId + " process_guid=" + $reference.process_guid)

            # The evaluation window of an attack run is its reference_time plus
            # the horizon, and the collection has to reach its end. A rehearsal
            # does not wait and is not held to it.
            $horizonEnd = (ConvertTo-R1Utc $referenceTime "reference_time").AddSeconds($inputs.evaluation_horizon_sec)
            if (-not $Rehearsal -and $endTime -lt $horizonEnd) {
                throw ("the collection ended at " + (Get-UtcStamp $endTime) + ", before reference_time + " +
                    $inputs.evaluation_horizon_sec + " s (" + (Get-UtcStamp $horizonEnd) + ")")
            }
        }

        # --- 8b. collection provenance of a scenario that declares a collection block ---
        # Built before the artifacts are written: a record that cannot be placed
        # by EventData.UtcTime throws here, and in a collection run so does a
        # connection to the internal destination before the run, anything but
        # one such connection in the run, or a lineage whose final tool or
        # intermediate is older than the run.
        $provenance = $null
        if ($collectionProfile.collection_declared) {
            $stage = "collection_provenance"
            # Where each record is in the raw file: its line, counted as the
            # records were read above, with blank lines skipped.
            $recordLines = New-Object System.Collections.Generic.List[int]
            $lineNumber = 0
            foreach ($line in @(Get-Content -LiteralPath $jsonlPath -Encoding UTF8)) {
                $lineNumber++
                if (-not [string]::IsNullOrWhiteSpace($line)) { $recordLines.Add($lineNumber) }
            }
            $rawWindowStart = $rawStartTime
            if (-not $rawFromBoot) { $rawWindowStart = $startTime.AddMilliseconds(-$EVTX_WINDOW_MARGIN_MS) }
            $targetBootUtc = $null
            if ($rawFromBoot) { $targetBootUtc = (Get-UtcStamp $rawStartTime) }
            # What the scenario planned for each action and when the run started it.
            # The two are written side by side and never in place of each other.
            $plannedAndActual = New-Object System.Collections.Generic.List[object]
            foreach ($planned in $inputs.actions) {
                $plannedId = [string](Get-R1Value $planned "action_id")
                $recorded = @($context.execution_records | Where-Object { $_.action_id -ceq $plannedId })
                $actualUtc = $null
                if ($recorded.Count -eq 1) { $actualUtc = [string]$recorded[0].timestamp }
                $plannedAndActual.Add([ordered]@{
                    action_id          = $plannedId
                    step               = [string](Get-R1Value $planned "step")
                    action_type        = [string](Get-R1Value $planned "action_type")
                    planned_offset_sec = [int](Get-R1Value $planned "offset_sec")
                    actual_utc         = $actualUtc
                })
            }
            $built = Get-R1CollectionProvenance -RunId $RunId -FamilyId ([string]$identity.family_id) `
                -CollectionProfile $collectionProfile -Records $records -ComputerName $targetHost `
                -RawCollectionStart $rawWindowStart -StartTime $startTime -EndTime $endTime `
                -ReferenceTime $referenceTime -EvaluationHorizonSec $inputs.evaluation_horizon_sec `
                -FinalProcessGuid ([string](Get-R1Value $lineage "final_process_guid")) `
                -Approval $approval -Readiness $readiness `
                -ReferenceResolution $referenceResolution -CreatedProcess $createdProcess `
                -PolicyProvenance $policyProvenance -Actions ([object[]]$plannedAndActual.ToArray()) `
                -TargetBootUtc $targetBootUtc -BootSessionId "" `
                -ScenarioId ([string](Get-R1Value $scenario "scenario_id")) `
                -VariationId ([string]$identity.variation_id) `
                -ScenarioVersion ([string](Get-R1Value $scenario "scenario_version")) `
                -RecordLines ([int[]]$recordLines.ToArray())
            $provenance = $built.provenance
            $counts = $provenance.record_counts
            Write-Ok ("collection window: raw from " + $provenance.raw_collection_start + ", observation from " +
                $provenance.observation_start + "; " + $counts.context + " of " + $counts.total +
                " record(s) are context")
            foreach ($problem in @($built.problems)) { Write-Fail ("collection provenance: " + $problem) }
            if (-not $Rehearsal -and @($built.problems).Count -gt 0) {
                throw ("collection provenance check failed: " + (@($built.problems) -join "; "))
            }
        }

        # --- 9. artifacts ---------------------------------------------------------
        $stage = "artifacts"
        # Build every completion artifact in a private same-volume tree first.
        # The manifest is moved last and is the existing completion signal for
        # consumers. A failure before then removes every file already moved.
        $completionStage = New-R1CompletionStage -Context $context `
            -EffectiveRoot $effectiveRoot -RunId $RunId
        $stagedContext = $completionStage.context
        $stagedExecutionPath = Write-ExecutionRecord -Context $stagedContext
        $stagedMetadataPath = Write-RunMetadata -Context $stagedContext -EndTime $endTime `
            -ReferenceTime $referenceTime -ReferenceActionId $inputs.reference_action_id `
            -ReferenceSourceEventId $referenceEventId
        $stagedManifestPath = Write-RunManifest -Context $stagedContext

        $stagedReadinessPath = $null
        $stagedProvenancePath = $null
        if ($null -ne $provenance) {
            if ($null -ne $readiness) {
                $stagedReadinessPath = Join-Path $completionStage.trace_dir $R1_READINESS_COPY_FILE
                Write-R1NewFile -Path $stagedReadinessPath -Bytes $readiness.bytes
            }
            $stagedProvenancePath = Write-R1CollectionProvenance `
                -TraceDir $completionStage.trace_dir -Provenance $provenance `
                -ScenarioSha256 $inputs.scenario_sha256 -ManifestPath ([string]$stagedManifestPath) `
                -SysmonConfigSha256 $configSha256 -ComputerName $targetHost -JsonlPath $jsonlPath
        }

        $provenancePath = $null
        if ($null -ne $stagedReadinessPath) {
            Publish-R1CompletionFile -Source $stagedReadinessPath `
                -Destination (Join-Path $traceDir $R1_READINESS_COPY_FILE) `
                -Published $publishedCompletionPaths | Out-Null
        }
        if ($null -ne $stagedProvenancePath) {
            $provenancePath = Publish-R1CompletionFile -Source $stagedProvenancePath `
                -Destination (Join-Path $traceDir $R1_PROVENANCE_FILE) `
                -Published $publishedCompletionPaths
        }
        Publish-R1CompletionFile -Source $stagedExecutionPath `
            -Destination (Join-Path $groundTruthDir "execution_record.csv") `
            -Published $publishedCompletionPaths | Out-Null
        Publish-R1CompletionFile -Source $stagedMetadataPath `
            -Destination (Join-Path $groundTruthDir "run_metadata.json") `
            -Published $publishedCompletionPaths | Out-Null
        $manifestPath = Publish-R1CompletionFile -Source $stagedManifestPath `
            -Destination (Join-Path (Split-Path $telemetryDir -Parent) "manifest.json") `
            -Published $publishedCompletionPaths
        Remove-R1CompletionStage -Stage $completionStage
        $completionStage = $null

        # run-finalized is the last file of a run with position finality. A
        # failure here still removes the Run files published above.
        $runFinalizedPath = $null
        if ($PositionFinality) {
            $stage = "run_finalized"
            # The A04 result the seal needs, recorded once the run has succeeded.
            # The failure path removes it with the other files of this run.
            if ($null -eq $provenance) { throw "a run with position finality has no collection provenance" }
            $attestation = New-R1BoundaryAttestation -BoundaryAction (@($inputs.actions)[-1]) `
                -CompletedUtc ([string]$runEnd.completed_utc) `
                -RequestCandidateBoundaryAt ([string]$freezeRequest.candidate_boundary_at) -RunEnd $runEnd `
                -IntermediatePid ([int]$wmiCall.process_id) -FinalPid ([int]$toolStart.final_pid) `
                -LineageRecords ([object[]]@($provenance.lineage.records))
            $attestationExisted = Test-Path -LiteralPath $positionPaths.boundary_attestation
            Write-R1PositionJsonOnce -Path $positionPaths.boundary_attestation -Value $attestation | Out-Null
            if (-not $attestationExisted) { $publishedCompletionPaths.Add($positionPaths.boundary_attestation) }
            $runFinalizedPath = Write-R1RunFinalized -Paths $positionPaths -Request $freezeRequest -Frozen $frozen `
                -Snapshot $positionSnapshot -FinalizedAt (& $NowProvider)
            Write-Ok ("run-finalized written: " + $runFinalizedPath)
        }
        if ($null -ne $provenancePath) {
            Write-Ok ("collection provenance written: " + $provenancePath)
        }

        Write-Ok ($RunType + " run finished: " + $RunId + " events=" + $eventCount +
            " actions=" + $context.execution_records.Count + " lineage=" + $lineage.status)

        $result = [ordered]@{
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
            dataset_tier     = $inputs.dataset_tier
            scenario_sha256  = $inputs.scenario_sha256
            reference        = [ordered]@{
                reference_action_id       = $inputs.reference_action_id
                reference_time            = $referenceTime
                reference_source_event_id = $referenceEventId
            }
        }
        if ($null -ne $provenancePath) { $result.collection_provenance = $provenancePath }
        if ($PositionFinality) {
            $result.position_finality = [ordered]@{
                freeze_request    = $positionPaths.request
                freeze_ack        = $positionPaths.ack
                run_finalized     = $runFinalizedPath
                boundary_attestation = $positionPaths.boundary_attestation
                snapshot_manifest = $positionPaths.manifest
                lower_record_id   = [long]$frozen.lower
                upper_record_id   = [long]$frozen.upper
                event_count       = [long]$positionSnapshot.canonical_event_count
                identity_sha256   = [string]$positionSnapshot.canonical_identity_sha256
            }
        }
        if ($null -ne $toolIdentity) {
            $result.tool_identity = $toolIdentity
            $result.run_end = $runEnd
        }
        return $result
    }
    catch {
        $runFailure = $_
        # No partial publication is a completed run. Remove only files this
        # invocation moved, then discard its private staging tree.
        foreach ($path in @($publishedCompletionPaths.ToArray())) {
            if (Test-Path -LiteralPath $path -PathType Leaf) {
                try { [System.IO.File]::Delete($path) } catch {
                    Write-Fail ("removing an incomplete completion file failed: " + $_.Exception.Message)
                }
            }
        }
        try { Remove-R1CompletionStage -Stage $completionStage } catch {
            Write-Fail ("removing the completion stage failed: " + $_.Exception.Message)
        }

        # WMI-created processes outlive the remoting session. On every failure
        # after a successful create, end only the PIDs whose successful action
        # results this run already validated. Never end WmiPrvSE.exe.
        if (-not $entryIsSession -and $null -eq $runEnd) {
            $cleanupOwned = @(Get-R1FailureCleanupOwnedProcesses `
                -WmiCall $wmiCall -ToolStart $toolStart -Plan $plan)
            if ($cleanupOwned.Count -gt 0) {
                try {
                    if ($null -eq $session) { $session = & $Transport.open $Connection }
                    $cleanupReturned = & $Transport.invoke $session "end_run" @{
                        owned         = $cleanupOwned
                        wait_sec      = $R1_RUN_END_WAIT_SEC
                        allow_partial = $true
                    }
                    $cleanupIds = [int[]]@($cleanupOwned | ForEach-Object { [int]$_.process_id })
                    $runEnd = Get-R1RunEndResult -Ended $cleanupReturned `
                        -OwnedProcessIds $cleanupIds -RootImage ([string]$plan.expected_lineage[2])
                    Write-Ok ("failure cleanup ended or confirmed gone " + $cleanupOwned.Count +
                        " Run-owned process(es)")
                } catch {
                    Write-Fail ("failure cleanup failed: " + $_.Exception.Message)
                }
            }
        }

        # A run of a scenario that declares a collection block leaves a record
        # of its failure once its trace exists. None of the files of a
        # completed run is written for it, and the failure itself is thrown on
        # unchanged. A scenario that declares no collection block fails as it
        # always did.
        if ($null -ne $traceDir -and $collectionProfile.collection_declared) {
            $failurePath = Write-R1RunFailure -TraceDir $traceDir -EffectiveRoot $effectiveRoot `
                -RunId $RunId -RunType $RunType -Mode $mode -EntryKind $collectionProfile.entry_kind `
                -Stage $stage -Reason ([string]$runFailure.Exception.Message) `
                -LaunchReturned $launchReturned -Reference $reference
            if ($null -ne $failurePath) { Write-Fail ("failure record written: " + $failurePath) }
        }
        if (-not [string]::IsNullOrWhiteSpace($IncrementalStreamControlRoot)) {
            try {
                $failedControl = [ordered]@{
                    schema = "r1-incremental-run-control"
                    contract_version = "v0.1"
                    message_type = "run_failed"
                    run_id = $RunId
                    target_host = $targetHost
                    stage = $stage
                    error = [string]$runFailure.Exception.Message
                    failed_at = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                }
                $controlDir = Join-Path $IncrementalStreamControlRoot $RunId
                New-Item -ItemType Directory -Path $controlDir -Force | Out-Null
                $utf8Control = New-Object System.Text.UTF8Encoding($false)
                Write-R1AtomicNewFile -Path (Join-Path $controlDir "run-failed.json") `
                    -Bytes $utf8Control.GetBytes(($failedControl | ConvertTo-Json -Compress))
            } catch {
                Write-Fail ("writing run-failed control failed: " + $_.Exception.Message)
            }
        }
        throw $runFailure
    }
    finally {
        # Session closure is transport cleanup only. WMI-created processes are
        # ended explicitly by run_end or by the failure cleanup above.
        if ($null -ne $session) {
            try { & $Transport.close $session | Out-Null } catch { Write-Fail ("closing the session failed: " + $_.Exception.Message) }
        }
    }
}
