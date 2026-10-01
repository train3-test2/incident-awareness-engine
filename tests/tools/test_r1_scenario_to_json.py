"""The canonical R1 scenario and the values injected when it is rendered.

The checks on `scenarios/R1/scenario.yaml` are the design rules of the first
Pilot: both runs reach the same final tool through one intermediate each, the
plan carries no encoded command option, and nothing Target-A records names the
run type. The injected values used here are synthetic; no host name or address
of the lab appears.
"""

import copy
import json
import sys
from collections.abc import Callable
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from incident_awareness.collection.r1_pilot_validation import load_r1_pilot_expectation
from tools import r1_scenario_to_json as renderer
from tools.r1_scenario_to_json import (
    LABEL_WORDS,
    RUN_TYPES,
    STEP_ORDER,
    apply_run_inputs,
    is_encoded_option,
    load_r1_scenario,
    validate_target_host,
)
from tools.scenario_to_json import render_json

CANONICAL_SCENARIO = Path("scenarios/R1/scenario.yaml")
S0_SCENARIO = Path("scenarios/S0/scenario.yaml")

TARGET_HOST = "TARGET-A"
LAB_CIDR = "10.20.30.0/24"
INTERNAL_TARGET = "10.20.30.20"
INTERNAL_PORT = 8443


def _load_canonical() -> dict:
    return load_r1_scenario(CANONICAL_SCENARIO)


def _designed_lineage(scenario: dict, run_type: str) -> tuple[str, str, str]:
    """Session host, intermediate, final tool: the order the processes are started in."""
    lineage = scenario["lineage"]
    return (
        lineage["session_host"]["image"],
        lineage["intermediate"][run_type]["image"],
        lineage["final_tool"]["image"],
    )


def _recorded_tokens(scenario: dict) -> list[str]:
    """Every value of the scenario that ends up in something Target-A records."""
    lineage = scenario["lineage"]
    tokens = [lineage["session_host"]["image"], lineage["final_tool"]["image"]]
    tokens += lineage["final_tool"]["arguments"]
    for run_type in RUN_TYPES:
        entry = lineage["intermediate"][run_type]
        tokens += [entry["image"], entry["launcher_file"], *entry["arguments"]]
    tokens.append(scenario["shortcut_controls"]["filename_prefix"])
    return tokens


def _load_mutated(tmp_path: Path, mutate: Callable[[dict], None]) -> dict:
    scenario = yaml.safe_load(CANONICAL_SCENARIO.read_text(encoding="utf-8"))
    mutate(scenario)
    path = tmp_path / "scenario.yaml"
    path.write_text(yaml.safe_dump(scenario, allow_unicode=True), encoding="utf-8")
    return load_r1_scenario(path)


# ---------------------------------------------------------------------------
# The canonical scenario
# ---------------------------------------------------------------------------


def test_normal_run_is_designed_as_the_approved_three_step_lineage() -> None:
    scenario = _load_canonical()

    assert _designed_lineage(scenario, "normal") == ("wsmprovhost.exe", "cmd.exe", "powershell.exe")


def test_attack_run_is_designed_as_the_other_three_step_lineage() -> None:
    scenario = _load_canonical()

    assert _designed_lineage(scenario, "attack") == (
        "wsmprovhost.exe",
        "cscript.exe",
        "powershell.exe",
    )


def test_both_runs_share_the_final_tool_and_differ_only_in_the_intermediate() -> None:
    # Given
    scenario = _load_canonical()
    normal = _designed_lineage(scenario, "normal")
    attack = _designed_lineage(scenario, "attack")

    # Then: same depth, same ends, one different step in the middle
    assert len(normal) == len(attack) == 3
    assert normal[0] == attack[0]
    assert normal[2] == attack[2]
    assert normal[1] != attack[1]
    # One final tool definition serves both runs, so its command line cannot differ.
    assert set(scenario["lineage"]["final_tool"]) == {"image", "arguments"}
    assert set(scenario["lineage"]["intermediate"]) == set(RUN_TYPES)


def test_canonical_scenario_carries_no_encoded_command_option() -> None:
    scenario = _load_canonical()

    assert [token for token in _recorded_tokens(scenario) if is_encoded_option(token)] == []


@pytest.mark.parametrize(
    "token",
    ["-enc", "-EncodedCommand", "-e", "-ec", "-EC", "/enc", "/EncodedCommand", "-encodedc", "-En"],
)
def test_encoded_command_spellings_are_recognised(token: str) -> None:
    assert is_encoded_option(token)


@pytest.mark.parametrize(
    "token",
    ["-ExecutionPolicy", "-ex", "-File", "-NoProfile", "-NonInteractive", "Bypass", "-", "", None],
)
def test_other_options_are_not_taken_for_an_encoded_command(token: object) -> None:
    assert not is_encoded_option(token)


def test_nothing_the_target_records_names_the_run_type() -> None:
    scenario = _load_canonical()

    exposed = [
        token
        for token in _recorded_tokens(scenario)
        if any(word in token.lower() for word in LABEL_WORDS)
    ]

    assert exposed == []


def test_both_runs_do_the_same_steps_at_the_same_offsets() -> None:
    # Given
    scenario = _load_canonical()
    shapes = {
        run_type: [
            (action["step"], action["offset_sec"], action["action_type"])
            for action in scenario["runs"][run_type]["actions"]
        ]
        for run_type in RUN_TYPES
    }

    # Then: five actions in the designed order, identical apart from their ids
    assert shapes["normal"] == shapes["attack"]
    assert tuple(step for step, _, _ in shapes["normal"]) == STEP_ORDER
    assert [offset for _, offset, _ in shapes["normal"]] == [0, 120, 300, 480, 600]
    assert [action["action_id"] for action in scenario["runs"]["normal"]["actions"]] == [
        "N01",
        "N02",
        "N03",
        "N04",
        "N05",
    ]
    assert [action["action_id"] for action in scenario["runs"]["attack"]["actions"]] == [
        "A01",
        "A02",
        "A03",
        "A04",
        "A05",
    ]


def test_canonical_scenario_keeps_every_run_input_null() -> None:
    scenario = _load_canonical()

    assert scenario["run_metadata"]["target_host"] is None
    internal = scenario["internal_connection"]
    assert (internal["target"], internal["port"], internal["lab_cidr"]) == (None, None, None)
    assert internal["protocol"] == "TCP"
    assert internal["max_attempts"] == 1
    assert scenario["run_length"]["observation_sec"] is None


def test_canonical_scenario_records_no_reference_and_no_frozen_comparator() -> None:
    scenario = _load_canonical()

    assert [scenario["runs"][run_type]["reference_action_id"] for run_type in RUN_TYPES] == [
        None,
        None,
    ]
    assert scenario["run_metadata"]["reference_policy_version"] is None
    assert scenario["run_metadata"]["detector_set_version"] is None
    assert scenario["decisive_comparator"] == {"required": True, "frozen_version": None}


def test_gate_values_follow_the_r1_feasibility_gate() -> None:
    scenario = _load_canonical()

    assert scenario["scenario_id"] == "R1"
    assert scenario["variation_id"] == "V02"
    assert scenario["gate_type"] == "feasibility"
    assert scenario["ambiguity_required"] is True
    assert scenario["performance_claim_allowed"] is True


def test_r1_records_the_same_contract_versions_as_s0() -> None:
    # Given: both scenarios are written into RunMetadata by the same writer
    r1_versions = _load_canonical()["run_metadata"]["schema_versions"]
    s0_versions = yaml.safe_load(S0_SCENARIO.read_text(encoding="utf-8"))["run_metadata"][
        "schema_versions"
    ]

    # Then: the S0 test pins these to the current contracts, so R1 follows them
    assert r1_versions == s0_versions


# ---------------------------------------------------------------------------
# Scenarios the loader refuses
# ---------------------------------------------------------------------------


def _same_intermediate(scenario: dict) -> None:
    scenario["lineage"]["intermediate"]["attack"]["image"] = "CMD.EXE"


def _shared_launcher_file(scenario: dict) -> None:
    scenario["lineage"]["intermediate"]["attack"]["launcher_file"] = "r1_launch.cmd"


def _encoded_final_argument(scenario: dict) -> None:
    scenario["lineage"]["final_tool"]["arguments"].insert(0, "-enc")


def _encoded_intermediate_argument(scenario: dict) -> None:
    scenario["lineage"]["intermediate"]["normal"]["arguments"].append("-EncodedCommand")


def _labelled_launcher_file(scenario: dict) -> None:
    scenario["lineage"]["intermediate"]["attack"]["launcher_file"] = "r1_attack.js"


def _labelled_argument(scenario: dict) -> None:
    scenario["lineage"]["final_tool"]["arguments"].append("normal")


def _labelled_image(scenario: dict) -> None:
    scenario["lineage"]["intermediate"]["normal"]["image"] = "benign_wrapper.exe"


def _no_task_placeholder(scenario: dict) -> None:
    scenario["lineage"]["final_tool"]["arguments"].remove("{task_script}")


def _no_launcher_placeholder(scenario: dict) -> None:
    scenario["lineage"]["intermediate"]["attack"]["arguments"].remove("{launcher}")


def _unknown_launcher_kind(scenario: dict) -> None:
    scenario["lineage"]["intermediate"]["attack"]["launcher_kind"] = "vbscript"


def _launcher_file_with_a_path(scenario: dict) -> None:
    scenario["lineage"]["intermediate"]["normal"]["launcher_file"] = "..\\r1_launch.cmd"


def _missing_intermediate(scenario: dict) -> None:
    del scenario["lineage"]["intermediate"]["attack"]


def _different_offset(scenario: dict) -> None:
    scenario["runs"]["attack"]["actions"][2]["offset_sec"] = 301


def _different_action_type(scenario: dict) -> None:
    scenario["runs"]["attack"]["actions"][2]["action_type"] = "execution"


def _swapped_steps(scenario: dict) -> None:
    actions = scenario["runs"]["normal"]["actions"]
    actions[2]["step"], actions[3]["step"] = actions[3]["step"], actions[2]["step"]


def _extra_action(scenario: dict) -> None:
    actions = scenario["runs"]["attack"]["actions"]
    actions.append({**actions[-1], "action_id": "A06"})


def _repeated_action_id(scenario: dict) -> None:
    scenario["runs"]["normal"]["actions"][1]["action_id"] = "N01"


def _offsets_going_backwards(scenario: dict) -> None:
    for run_type in RUN_TYPES:
        scenario["runs"][run_type]["actions"][3]["offset_sec"] = 200


def _other_scenario_id(scenario: dict) -> None:
    scenario["scenario_id"] = "S0"


def _no_lineage(scenario: dict) -> None:
    del scenario["lineage"]


@pytest.mark.parametrize(
    "mutate",
    [
        _same_intermediate,
        _shared_launcher_file,
        _encoded_final_argument,
        _encoded_intermediate_argument,
        _labelled_launcher_file,
        _labelled_argument,
        _labelled_image,
        _no_task_placeholder,
        _no_launcher_placeholder,
        _unknown_launcher_kind,
        _launcher_file_with_a_path,
        _missing_intermediate,
        _different_offset,
        _different_action_type,
        _swapped_steps,
        _extra_action,
        _repeated_action_id,
        _offsets_going_backwards,
        _other_scenario_id,
        _no_lineage,
    ],
)
def test_scenario_breaking_a_pilot_rule_is_refused(
    tmp_path: Path, mutate: Callable[[dict], None]
) -> None:
    with pytest.raises(ValueError):
        _load_mutated(tmp_path, mutate)


def test_intermediate_that_is_not_a_mapping_is_refused(tmp_path: Path) -> None:
    def mutate(scenario: dict) -> None:
        scenario["lineage"]["intermediate"]["attack"] = "cscript.exe"

    with pytest.raises(TypeError):
        _load_mutated(tmp_path, mutate)


def test_unmutated_copy_of_the_canonical_scenario_still_loads(tmp_path: Path) -> None:
    # The refusals above come from the mutation, not from the YAML round trip.
    assert _load_mutated(tmp_path, lambda scenario: None) == _load_canonical()


# ---------------------------------------------------------------------------
# Run inputs
# ---------------------------------------------------------------------------


def test_run_inputs_are_injected_into_a_copy() -> None:
    # Given
    scenario = _load_canonical()
    before = copy.deepcopy(scenario)

    # When
    rendered = apply_run_inputs(
        scenario,
        target_host=TARGET_HOST,
        internal_target=INTERNAL_TARGET,
        internal_port=INTERNAL_PORT,
        lab_cidr=LAB_CIDR,
    )

    # Then: the values are in the copy and the input is untouched
    assert rendered["run_metadata"]["target_host"] == TARGET_HOST
    assert rendered["internal_connection"]["target"] == INTERNAL_TARGET
    assert rendered["internal_connection"]["port"] == INTERNAL_PORT
    assert rendered["internal_connection"]["lab_cidr"] == LAB_CIDR
    assert scenario == before


def test_both_runs_read_the_same_injected_destination(tmp_path: Path) -> None:
    # Given: the scenario rendered once for a pair
    rendered = apply_run_inputs(
        _load_canonical(),
        target_host=TARGET_HOST,
        internal_target=INTERNAL_TARGET,
        internal_port=INTERNAL_PORT,
        lab_cidr=LAB_CIDR,
    )
    out = render_json(rendered, tmp_path / "scenario.json")

    # When: the host validator reads the design of each run type from it
    normal = load_r1_pilot_expectation(out, "normal")
    attack = load_r1_pilot_expectation(out, "attack")

    # Then: one host, one destination, one final tool; only the intermediate differs
    assert normal.target_host == attack.target_host == TARGET_HOST
    assert (normal.destination_ip, normal.destination_port) == (INTERNAL_TARGET, "8443")
    assert (attack.destination_ip, attack.destination_port) == (INTERNAL_TARGET, "8443")
    assert normal.images == ("powershell.exe", "cmd.exe", "wsmprovhost.exe")
    assert attack.images == ("powershell.exe", "cscript.exe", "wsmprovhost.exe")
    assert [action.offset_sec for action in normal.actions] == [
        action.offset_sec for action in attack.actions
    ]


def test_target_host_alone_gives_the_lineage_only_rehearsal_shape() -> None:
    rendered = apply_run_inputs(_load_canonical(), target_host=TARGET_HOST)

    assert rendered["run_metadata"]["target_host"] == TARGET_HOST
    assert rendered["internal_connection"]["target"] is None
    assert rendered["internal_connection"]["port"] is None
    assert rendered["internal_connection"]["lab_cidr"] is None


@pytest.mark.parametrize(
    "inputs",
    [
        {"internal_target": INTERNAL_TARGET},
        {"internal_port": INTERNAL_PORT},
        {"lab_cidr": LAB_CIDR},
        {"internal_target": INTERNAL_TARGET, "internal_port": INTERNAL_PORT},
        {"internal_target": INTERNAL_TARGET, "lab_cidr": LAB_CIDR},
        {"internal_port": INTERNAL_PORT, "lab_cidr": LAB_CIDR},
    ],
)
def test_destination_inputs_are_given_together_or_not_at_all(inputs: dict) -> None:
    with pytest.raises(ValueError, match="given together"):
        apply_run_inputs(_load_canonical(), **inputs)


@pytest.mark.parametrize(
    "target",
    ["8.8.8.8", "203.0.113.9", "127.0.0.1", "10.20.31.20", "10.20.30.0", "target-b", "fe80::1"],
)
def test_destination_outside_the_lab_is_refused_before_rendering(target: str) -> None:
    with pytest.raises(ValueError):
        apply_run_inputs(
            _load_canonical(),
            target_host=TARGET_HOST,
            internal_target=target,
            internal_port=INTERNAL_PORT,
            lab_cidr=LAB_CIDR,
        )


@pytest.mark.parametrize("value", ["TARGET-A", "target-a.lab", "a", "T1"])
def test_target_host_accepts_a_host_name(value: str) -> None:
    assert validate_target_host(value) == value


@pytest.mark.parametrize("value", ["", " TARGET-A", "TARGET A", "-target", "target_a", "a/b"])
def test_target_host_refuses_anything_else(value: str) -> None:
    with pytest.raises(ValueError):
        validate_target_host(value)


def test_target_host_must_be_text() -> None:
    with pytest.raises(TypeError):
        validate_target_host(None)


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def test_render_keeps_the_values_and_writes_utf8_lf_without_bom(tmp_path: Path) -> None:
    # Given
    scenario = _load_canonical()
    out = tmp_path / "scenario.json"

    # When
    render_json(scenario, out)

    # Then: PowerShell 5.1 on the Controller reads this file as UTF-8
    raw = out.read_bytes()
    assert not raw.startswith(b"\xef\xbb\xbf")
    assert b"\r" not in raw
    assert raw.endswith(b"\n")
    assert json.loads(raw.decode("utf-8")) == scenario


def test_rendering_does_not_rewrite_the_canonical_yaml(tmp_path: Path) -> None:
    before = CANONICAL_SCENARIO.read_bytes()

    render_json(
        apply_run_inputs(
            _load_canonical(),
            target_host=TARGET_HOST,
            internal_target=INTERNAL_TARGET,
            internal_port=INTERNAL_PORT,
            lab_cidr=LAB_CIDR,
        ),
        tmp_path / "scenario.json",
    )

    assert CANONICAL_SCENARIO.read_bytes() == before


def test_cli_renders_the_injected_values(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    out = tmp_path / "build" / "scenario.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "r1_scenario_to_json.py",
            str(CANONICAL_SCENARIO),
            "--out",
            str(out),
            "--target-host",
            TARGET_HOST,
            "--internal-target",
            INTERNAL_TARGET,
            "--internal-port",
            str(INTERNAL_PORT),
            "--lab-cidr",
            LAB_CIDR,
        ],
    )

    assert renderer.main() == 0

    rendered = json.loads(out.read_text(encoding="utf-8"))
    assert rendered["run_metadata"]["target_host"] == TARGET_HOST
    assert rendered["internal_connection"]["target"] == INTERNAL_TARGET
    assert rendered["internal_connection"]["port"] == INTERNAL_PORT


def test_cli_writes_nothing_for_a_global_destination(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = tmp_path / "build" / "scenario.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "r1_scenario_to_json.py",
            str(CANONICAL_SCENARIO),
            "--out",
            str(out),
            "--target-host",
            TARGET_HOST,
            "--internal-target",
            "8.8.8.8",
            "--internal-port",
            str(INTERNAL_PORT),
            "--lab-cidr",
            LAB_CIDR,
        ],
    )

    with pytest.raises(ValueError, match="RFC 1918"):
        renderer.main()

    assert not out.exists()
    assert not out.parent.exists()
