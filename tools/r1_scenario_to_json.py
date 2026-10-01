"""Render scenarios/R1/scenario.yaml as JSON for the R1 Pilot runner.

`scenarios/R1/scenario.yaml` is the canonical R1-V02 Pilot definition. Windows
PowerShell 5.1 has no YAML reader, so the host renders the same values as JSON
and copies that file to the Controller together with the run scripts. The
rendered file is a build artifact and is not committed; see
`scenarios/R1/README.md`.

    python tools/r1_scenario_to_json.py scenarios/R1/scenario.yaml --out build/R1/scenario.json

The canonical YAML keeps the Target-A host name, the internal destination and
the lab network as null. They are injected only when the JSON is rendered for a
run and are never stored in the repository:

    --target-host       Target-A computer name, written to RunMetadata
    --internal-target   destination of the internal connection
    --internal-port     destination port
    --lab-cidr          lab network the destination has to be inside

Without them the rendered JSON keeps the nulls, which is the shape a dry run
uses. The destination has to be an RFC 1918 host address inside the lab network:
this scenario only ever connects inside the lab (docs/scenarios/r1.md section
1), so a globally routable address is refused here, again by the runner and
again by the task that makes the connection. The rule itself is
`incident_awareness.collection.r1_destination`.

The loader also checks what both runs have to share - one final tool, one
intermediate each, the same steps at the same offsets - and refuses a scenario
that would carry an encoded command option or the run type in a file name or an
argument. The runner repeats the last two checks on the plan it builds.
"""

import argparse
import copy
import re
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from incident_awareness.collection.r1_destination import (
    validate_internal_port,
    validate_internal_target,
    validate_lab_cidr,
)
from tools.scenario_to_json import render_json

SCENARIO_ID = "R1"
RUN_TYPES = ("normal", "attack")
STEP_ORDER = ("session_begin", "prepare", "launch", "connect", "session_end")
LAUNCHER_KINDS = ("batch", "jscript")

# Words that would give the run type away in something Sysmon records on Target-A.
LABEL_WORDS = ("normal", "attack", "benign", "malicious")

_REQUIRED_TOP_LEVEL = (
    "scenario_version",
    "scenario_id",
    "run_metadata",
    "internal_connection",
    "lineage",
    "shortcut_controls",
    "runs",
)
_ENCODED_OPTION = "-encodedcommand"
_ENCODED_ALIAS = "-ec"
_FILE_NAME = re.compile(r"^[A-Za-z0-9_.-]+$")
_HOST_NAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,253}[A-Za-z0-9])?$")


def is_encoded_option(token: object) -> bool:
    """Whether PowerShell would read a command line token as -EncodedCommand.

    PowerShell accepts any prefix of the option name and the alias -ec, with
    either `-` or `/`. `-ExecutionPolicy` is not a prefix of the option, so it is
    not caught.
    """
    if not isinstance(token, str) or not token:
        return False

    value = token.lower()
    if value.startswith("/"):
        value = "-" + value[1:]
    if value == _ENCODED_ALIAS:
        return True

    return len(value) >= 2 and _ENCODED_OPTION.startswith(value)


def _require_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a non-empty string")
    if value != value.strip():
        raise ValueError(f"{label} must not have surrounding whitespace")
    return value


def _require_arguments(value: object, label: str, placeholders: tuple[str, ...]) -> list[str]:
    if not isinstance(value, list) or not value:
        raise ValueError(f"{label} must be a non-empty list")
    arguments = [_require_text(item, f"{label}[{index}]") for index, item in enumerate(value)]

    for placeholder in placeholders:
        if placeholder not in arguments:
            raise ValueError(f"{label} must contain {placeholder}")
    for argument in arguments:
        if is_encoded_option(argument):
            raise ValueError(
                f"{label} carries an encoded command option, which the first Pilot does not "
                f"use: {argument!r}"
            )

    return arguments


def _reject_label_words(value: str, label: str) -> None:
    lowered = value.lower()
    for word in LABEL_WORDS:
        if word in lowered:
            raise ValueError(f"{label} would expose the run type on Target-A: {value!r}")


def _check_lineage(lineage: object) -> None:
    if not isinstance(lineage, dict):
        raise TypeError("lineage must be a mapping")

    session_host = lineage.get("session_host") or {}
    final_tool = lineage.get("final_tool") or {}
    intermediate = lineage.get("intermediate") or {}

    exposed = [
        (_require_text(session_host.get("image"), "lineage.session_host.image"), "session host"),
        (_require_text(final_tool.get("image"), "lineage.final_tool.image"), "final tool"),
    ]
    exposed += [
        (argument, "lineage.final_tool.arguments")
        for argument in _require_arguments(
            final_tool.get("arguments"),
            "lineage.final_tool.arguments",
            ("{task_script}", "{channel_dir}"),
        )
    ]

    images: dict[str, str] = {}
    launcher_files: dict[str, str] = {}
    for run_type in RUN_TYPES:
        label = f"lineage.intermediate.{run_type}"
        entry = intermediate.get(run_type)
        if entry is None:
            raise ValueError(f"{label} is missing")
        if not isinstance(entry, dict):
            raise TypeError(f"{label} must be a mapping")

        image = _require_text(entry.get("image"), f"{label}.image")
        launcher_file = _require_text(entry.get("launcher_file"), f"{label}.launcher_file")
        if not _FILE_NAME.fullmatch(launcher_file):
            raise ValueError(f"{label}.launcher_file is not a plain file name: {launcher_file!r}")
        if entry.get("launcher_kind") not in LAUNCHER_KINDS:
            raise ValueError(
                f"{label}.launcher_kind must be one of {LAUNCHER_KINDS}, "
                f"found {entry.get('launcher_kind')!r}"
            )

        images[run_type] = image
        launcher_files[run_type] = launcher_file
        exposed.append((image, f"{label}.image"))
        exposed.append((launcher_file, f"{label}.launcher_file"))
        exposed += [
            (argument, f"{label}.arguments")
            for argument in _require_arguments(
                entry.get("arguments"), f"{label}.arguments", ("{launcher}",)
            )
        ]

    # The pair exists to show two lineages of the same depth that end in the same
    # tool. One intermediate each, and they have to differ.
    if images["normal"].lower() == images["attack"].lower():
        raise ValueError(
            "lineage.intermediate.normal and .attack name the same image; the pair would not differ"
        )
    if launcher_files["normal"].lower() == launcher_files["attack"].lower():
        raise ValueError("lineage.intermediate entries share one launcher file")

    for value, label in exposed:
        _reject_label_words(value, label)


def _check_runs(scenario: dict) -> None:
    runs = scenario["runs"]
    expected = scenario["shortcut_controls"].get("actions_per_run")
    shapes: dict[str, list[tuple[object, object, object]]] = {}

    for run_type in RUN_TYPES:
        if run_type not in runs:
            raise ValueError(f"runs.{run_type} is missing")

        actions = runs[run_type].get("actions") or []
        if len(actions) != expected:
            raise ValueError(
                f"runs.{run_type} has {len(actions)} actions, "
                f"shortcut_controls.actions_per_run is {expected}"
            )

        action_ids = [action.get("action_id") for action in actions]
        if len(action_ids) != len(set(action_ids)):
            raise ValueError(f"runs.{run_type} has duplicate action_id values")

        steps = tuple(action.get("step") for action in actions)
        if steps != STEP_ORDER:
            raise ValueError(
                f"runs.{run_type} steps must be {list(STEP_ORDER)} in that order, "
                f"found {list(steps)}"
            )

        offsets = [action.get("offset_sec") for action in actions]
        if any(isinstance(offset, bool) or not isinstance(offset, int) for offset in offsets):
            raise ValueError(f"runs.{run_type} offset_sec values must be integers")
        if offsets != sorted(offsets) or offsets[0] < 0:
            raise ValueError(f"runs.{run_type} offset_sec values must not go backwards")

        shapes[run_type] = [
            (action.get("step"), action.get("offset_sec"), action.get("action_type"))
            for action in actions
        ]

    # Both runs do the same things at the same moments; only the lineage differs.
    if shapes["normal"] != shapes["attack"]:
        raise ValueError(
            "runs.normal and runs.attack must share step, offset_sec and action_type per action"
        )


def load_r1_scenario(path: Path) -> dict:
    """Load the R1 scenario and check the rules the runner depends on."""
    with path.open(encoding="utf-8") as stream:
        scenario = yaml.safe_load(stream)

    if not isinstance(scenario, dict):
        raise TypeError(f"scenario must be a mapping: {path}")

    missing = [key for key in _REQUIRED_TOP_LEVEL if key not in scenario]
    if missing:
        raise ValueError(f"missing required keys: {sorted(missing)}")

    if scenario["scenario_id"] != SCENARIO_ID:
        raise ValueError(f"scenario_id must be {SCENARIO_ID!r}, found {scenario['scenario_id']!r}")

    _check_lineage(scenario["lineage"])
    _check_runs(scenario)
    return scenario


def validate_target_host(value: object) -> str:
    """Return the Target-A computer name as it will be written to RunMetadata."""
    if not isinstance(value, str):
        raise TypeError("target host must be a string")
    if value != value.strip():
        raise ValueError("target host must not have surrounding whitespace")
    if not _HOST_NAME.fullmatch(value):
        raise ValueError(f"target host is not a host name: {value!r}")
    return value


def apply_run_inputs(
    scenario: dict,
    *,
    target_host: str | None = None,
    internal_target: str | None = None,
    internal_port: int | None = None,
    lab_cidr: str | None = None,
) -> dict:
    """Return a copy with the run inputs injected.

    The input mapping is not mutated, so the canonical YAML on disk is never
    rewritten. Both runs read the same blocks, so an injected value applies
    identically to normal and attack. The destination, its port and the lab
    network are given together or not at all.
    """
    rendered = copy.deepcopy(scenario)

    if target_host is not None:
        rendered["run_metadata"]["target_host"] = validate_target_host(target_host)

    connection_inputs = (internal_target, internal_port, lab_cidr)
    if any(value is not None for value in connection_inputs):
        if any(value is None for value in connection_inputs):
            raise ValueError(
                "--internal-target, --internal-port and --lab-cidr have to be given together"
            )

        network = validate_lab_cidr(lab_cidr)
        internal = rendered["internal_connection"]
        internal["target"] = validate_internal_target(internal_target, network)
        internal["port"] = validate_internal_port(internal_port)
        internal["lab_cidr"] = str(network)

    return rendered


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", type=Path, help="path to scenarios/R1/scenario.yaml")
    parser.add_argument("--out", type=Path, required=True, help="path of the JSON to write")
    parser.add_argument("--target-host", help="Target-A computer name; omit for a dry run")
    parser.add_argument(
        "--internal-target",
        help="RFC 1918 IPv4 destination inside the lab network; omit to skip the connection",
    )
    parser.add_argument("--internal-port", type=int, help="destination port")
    parser.add_argument("--lab-cidr", help="lab network, for example 10.20.30.0/24")
    args = parser.parse_args()

    scenario = apply_run_inputs(
        load_r1_scenario(args.scenario),
        target_host=args.target_host,
        internal_target=args.internal_target,
        internal_port=args.internal_port,
        lab_cidr=args.lab_cidr,
    )

    destination = render_json(scenario, args.out)
    print(f"[+] {args.scenario} -> {destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
