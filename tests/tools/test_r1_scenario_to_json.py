"""The canonical R1 scenario and the values injected when it is rendered.

The checks on `scenarios/R1/scenario.yaml` are the design rules of the first
Pilot: both runs reach the same final tool through one intermediate each, the
plan carries no encoded command option, and nothing Target-A records names the
run type. The injected values used here are synthetic; no host name or address
of the lab appears.
"""

import copy
import json
import re
import sys
from collections.abc import Callable
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from incident_awareness.collection.r1_pair_identity import (
    LABEL_WORDS,
    R1PairIdentity,
    R1PairIdentityError,
)
from incident_awareness.collection.r1_pilot_validation import load_r1_pilot_expectation
from tools import r1_scenario_to_json as renderer
from tools.r1_scenario_to_json import (
    IDENTITY_KEYS,
    RUN_TYPES,
    STEP_ORDER,
    apply_run_inputs,
    is_encoded_option,
    load_r1_scenario,
    require_pair_identity,
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
    lineage = scenario["planned_lineage"]
    return (
        lineage["session_host"]["image"],
        lineage["intermediate"][run_type]["image"],
        lineage["final_tool"]["image"],
    )


def _recorded_tokens(scenario: dict) -> list[str]:
    """Every value of the scenario that ends up in something Target-A records."""
    lineage = scenario["planned_lineage"]
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
    assert set(scenario["planned_lineage"]["final_tool"]) == {"image", "arguments"}
    assert set(scenario["planned_lineage"]["intermediate"]) == set(RUN_TYPES)


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
    scenario["planned_lineage"]["intermediate"]["attack"]["image"] = "CMD.EXE"


def _shared_launcher_file(scenario: dict) -> None:
    scenario["planned_lineage"]["intermediate"]["attack"]["launcher_file"] = "r1_launch.cmd"


def _encoded_final_argument(scenario: dict) -> None:
    scenario["planned_lineage"]["final_tool"]["arguments"].insert(0, "-enc")


def _encoded_intermediate_argument(scenario: dict) -> None:
    scenario["planned_lineage"]["intermediate"]["normal"]["arguments"].append("-EncodedCommand")


def _labelled_launcher_file(scenario: dict) -> None:
    scenario["planned_lineage"]["intermediate"]["attack"]["launcher_file"] = "r1_attack.js"


def _labelled_argument(scenario: dict) -> None:
    scenario["planned_lineage"]["final_tool"]["arguments"].append("normal")


def _labelled_image(scenario: dict) -> None:
    scenario["planned_lineage"]["intermediate"]["normal"]["image"] = "benign_wrapper.exe"


def _no_task_placeholder(scenario: dict) -> None:
    scenario["planned_lineage"]["final_tool"]["arguments"].remove("{task_script}")


def _no_launcher_placeholder(scenario: dict) -> None:
    scenario["planned_lineage"]["intermediate"]["attack"]["arguments"].remove("{launcher}")


def _unknown_launcher_kind(scenario: dict) -> None:
    scenario["planned_lineage"]["intermediate"]["attack"]["launcher_kind"] = "vbscript"


def _launcher_file_with_a_path(scenario: dict) -> None:
    scenario["planned_lineage"]["intermediate"]["normal"]["launcher_file"] = "..\\r1_launch.cmd"


def _missing_intermediate(scenario: dict) -> None:
    del scenario["planned_lineage"]["intermediate"]["attack"]


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
    del scenario["planned_lineage"]


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
        scenario["planned_lineage"]["intermediate"]["attack"] = "cscript.exe"

    with pytest.raises(TypeError):
        _load_mutated(tmp_path, mutate)


def test_unmutated_copy_of_the_canonical_scenario_still_loads(tmp_path: Path) -> None:
    # The refusals above come from the mutation, not from the YAML round trip.
    assert _load_mutated(tmp_path, lambda scenario: None) == _load_canonical()


def _with_text(place: str, text: str) -> Callable[[dict], None]:
    """Put a text into one place of the scenario that ends up identifying or running a run."""

    def mutate(scenario: dict) -> None:
        lineage = scenario["planned_lineage"]
        if place == "family_id":
            scenario["family_id"] = f"{text}_family"
        elif place == "variation_id":
            scenario["variation_id"] = f"V02-{text}"
        elif place == "session host image":
            lineage["session_host"]["image"] = f"{text}.exe"
        elif place == "final tool image":
            lineage["final_tool"]["image"] = f"{text}.exe"
        elif place == "final tool argument":
            lineage["final_tool"]["arguments"].append(f"r1_{text}.txt")
        elif place == "intermediate image":
            lineage["intermediate"]["attack"]["image"] = f"{text}.exe"
        elif place == "intermediate argument":
            lineage["intermediate"]["normal"]["arguments"].append(text)
        else:
            raise AssertionError(place)

    return mutate


_LABELLED_PLACES = [
    "family_id",
    "variation_id",
    "session host image",
    "final tool image",
    "final tool argument",
    "intermediate image",
    "intermediate argument",
]


@pytest.mark.parametrize("label", ["정상", "공격", "악성"])
@pytest.mark.parametrize("place", _LABELLED_PLACES)
def test_korean_label_in_the_identity_or_the_plan_is_refused(
    tmp_path: Path, place: str, label: str
) -> None:
    # The labels are refused in Korean as in English, in the identity of the Pair
    # and in everything the launch plan puts on Target-A.
    with pytest.raises(ValueError, match="would expose the run type"):
        _load_mutated(tmp_path, _with_text(place, label))


@pytest.mark.parametrize("place", _LABELLED_PLACES)
def test_korean_text_without_a_label_is_accepted(tmp_path: Path, place: str) -> None:
    # Given: the same places holding a Korean word that is not a label
    scenario = _load_mutated(tmp_path, _with_text(place, "원격관리"))

    # Then: it loads and renders with the text unchanged
    out = render_json(apply_run_inputs(scenario, repetition=1), tmp_path / "scenario.json")
    written = json.loads(out.read_text(encoding="utf-8"))
    assert written == apply_run_inputs(scenario, repetition=1)
    assert "원격관리" in json.dumps(written, ensure_ascii=False)


def test_label_words_of_the_renderer_are_the_shared_list() -> None:
    # The renderer imports the list the identity rules use; the same list is in
    # the PowerShell runner (tests/collection/test_r1_pair_identity.py).
    shared = json.loads(
        Path("scenarios/R1/tests/label_shortcut_cases.json").read_text(encoding="ascii")
    )

    assert list(LABEL_WORDS) == shared["label_words"]


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
        repetition=1,
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
            "--repetition",
            "1",
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


# ---------------------------------------------------------------------------
# The Pair a scenario is rendered for: family, variation, repetition
# ---------------------------------------------------------------------------


def test_canonical_scenario_states_its_family_and_variation_but_no_repetition() -> None:
    scenario = _load_canonical()

    assert scenario["family_id"] == "remote_management"
    assert scenario["variation_id"] == "V02"
    assert scenario["repetition"] is None


def _load_stating(tmp_path: Path, **stated: object) -> dict:
    """A scenario file that states the given top-level values, read by the R1 loader."""

    def mutate(scenario: dict) -> None:
        scenario.update(stated)

    return _load_mutated(tmp_path, mutate)


@pytest.mark.parametrize(
    ("family_id", "variation_id", "repetition"),
    [("family_x7", "V09", 4), ("holdout-b", "v1", 1), ("F3", "lineage-axis", 5)],
)
def test_any_valid_identity_is_written_to_the_rendered_json(
    tmp_path: Path, family_id: str, variation_id: str, repetition: int
) -> None:
    # Given: a scenario file that states that family and variation, rendered for
    # one Pair of it
    scenario = _load_stating(tmp_path, family_id=family_id, variation_id=variation_id)
    rendered = apply_run_inputs(scenario, repetition=repetition)
    out = render_json(rendered, tmp_path / "scenario.json")

    # Then: the three values are in the JSON as they were stated, the repetition
    # as a JSON integer
    written = json.loads(out.read_text(encoding="utf-8"))
    assert written["family_id"] == family_id
    assert written["variation_id"] == variation_id
    assert written["repetition"] == repetition
    assert type(written["repetition"]) is int
    assert require_pair_identity(written) == R1PairIdentity(family_id, variation_id, repetition)


def test_repetition_is_injected_into_a_copy() -> None:
    scenario = _load_canonical()
    before = copy.deepcopy(scenario)

    rendered = apply_run_inputs(scenario, repetition=3)

    assert (rendered["variation_id"], rendered["repetition"]) == ("V02", 3)
    assert scenario == before


@pytest.mark.parametrize("repetition", [1, 3, 5])
def test_rendering_keeps_the_family_and_variation_the_scenario_states(
    tmp_path: Path, repetition: int
) -> None:
    # Given: the canonical scenario as it is in the repository
    canonical = yaml.safe_load(CANONICAL_SCENARIO.read_text(encoding="utf-8"))

    # When: it is rendered with every run input there is
    rendered = apply_run_inputs(
        _load_canonical(),
        target_host=TARGET_HOST,
        internal_target=INTERNAL_TARGET,
        internal_port=INTERNAL_PORT,
        lab_cidr=LAB_CIDR,
        repetition=repetition,
    )
    written = json.loads(render_json(rendered, tmp_path / "scenario.json").read_text("utf-8"))

    # Then: only the repetition is the caller's; the design values are the file's
    assert written["family_id"] == canonical["family_id"] == "remote_management"
    assert written["variation_id"] == canonical["variation_id"] == "V02"
    assert written["repetition"] == repetition


@pytest.mark.parametrize(
    "run_input", [{"family_id": "family_x7"}, {"variation_id": "V09"}], ids=["family", "variation"]
)
def test_family_and_variation_are_not_run_inputs(run_input: dict) -> None:
    # A family is what the data is split by. One design rendered under two family
    # names would be counted as two families, so no call can rename it.
    with pytest.raises(TypeError, match="unexpected keyword argument"):
        apply_run_inputs(_load_canonical(), repetition=1, **run_input)


@pytest.mark.parametrize("field", ["family_id", "variation_id"])
@pytest.mark.parametrize("value", ["", " ", "\t"])
def test_empty_family_or_variation_is_refused(tmp_path: Path, field: str, value: str) -> None:
    with pytest.raises(R1PairIdentityError, match="must be a non-empty string"):
        _load_stating(tmp_path, **{field: value})


@pytest.mark.parametrize("field", ["family_id", "variation_id"])
@pytest.mark.parametrize("value", ["normal_family", "V02-Attack", "BENIGN", "x-malicious"])
def test_family_or_variation_named_after_a_run_type_is_refused(
    tmp_path: Path, field: str, value: str
) -> None:
    with pytest.raises(R1PairIdentityError, match="would expose the run type"):
        _load_stating(tmp_path, **{field: value})


@pytest.mark.parametrize("repetition", [0, -1, -3, 1.5, 2.0, "1", True, False])
def test_repetition_that_is_not_an_integer_of_one_or_more_is_refused(repetition: object) -> None:
    with pytest.raises(R1PairIdentityError, match="repetition must be"):
        apply_run_inputs(_load_canonical(), repetition=repetition)


def _run_with_its_own_family(scenario: dict) -> None:
    scenario["runs"]["attack"]["family_id"] = "family_b"


def _run_with_its_own_variation(scenario: dict) -> None:
    scenario["runs"]["normal"]["variation_id"] = "V03"


def _run_with_its_own_repetition(scenario: dict) -> None:
    scenario["runs"]["attack"]["repetition"] = 2


@pytest.mark.parametrize(
    "mutate",
    [_run_with_its_own_family, _run_with_its_own_variation, _run_with_its_own_repetition],
)
def test_run_cannot_state_an_identity_of_its_own(
    tmp_path: Path, mutate: Callable[[dict], None]
) -> None:
    # The two runs of a Pair share one identity because there is only one to read.
    with pytest.raises(ValueError, match="a Pair states them once at the top level"):
        _load_mutated(tmp_path, mutate)


def test_both_runs_of_a_pair_read_the_same_identity(tmp_path: Path) -> None:
    # Given: one JSON rendered for the Pair of a scenario that states its family
    rendered = apply_run_inputs(
        _load_stating(tmp_path, family_id="family_x7", variation_id="V09"),
        target_host=TARGET_HOST,
        repetition=4,
    )
    out = render_json(rendered, tmp_path / "scenario.json")

    # When: each run type reads what it is validated against
    normal = load_r1_pilot_expectation(out, "normal")
    attack = load_r1_pilot_expectation(out, "attack")

    # Then: the identity is the same object of the scenario, not one per run
    assert normal.identity == attack.identity == R1PairIdentity("family_x7", "V09", 4)
    assert all(
        key not in rendered["runs"][run_type] for key in IDENTITY_KEYS for run_type in RUN_TYPES
    )


def _no_repetition_key(scenario: dict) -> None:
    del scenario["repetition"]


def _no_family_key(scenario: dict) -> None:
    del scenario["family_id"]


def _blank_family(scenario: dict) -> None:
    scenario["family_id"] = " "


def _numeric_variation(scenario: dict) -> None:
    scenario["variation_id"] = 2


def _stated_bad_repetition(scenario: dict) -> None:
    scenario["repetition"] = 0


@pytest.mark.parametrize(
    "mutate",
    [
        _no_repetition_key,
        _no_family_key,
        _blank_family,
        _numeric_variation,
        _stated_bad_repetition,
    ],
)
def test_scenario_with_an_unusable_identity_is_refused(
    tmp_path: Path, mutate: Callable[[dict], None]
) -> None:
    with pytest.raises(ValueError):
        _load_mutated(tmp_path, mutate)


def test_cli_does_not_render_a_scenario_without_a_repetition(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = tmp_path / "build" / "scenario.json"
    monkeypatch.setattr(
        sys, "argv", ["r1_scenario_to_json.py", str(CANONICAL_SCENARIO), "--out", str(out)]
    )

    with pytest.raises(R1PairIdentityError, match="--repetition"):
        renderer.main()

    assert not out.exists()
    assert not out.parent.exists()


def test_cli_renders_the_identity_of_the_scenario_with_the_given_repetition(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # Given: a scenario file that states its own family and variation
    scenario_path = tmp_path / "scenario.yaml"
    stated = yaml.safe_load(CANONICAL_SCENARIO.read_text(encoding="utf-8"))
    stated.update(family_id="family_x7", variation_id="V09")
    scenario_path.write_text(yaml.safe_dump(stated, allow_unicode=True), encoding="utf-8")
    out = tmp_path / "build" / "scenario.json"
    monkeypatch.setattr(
        sys,
        "argv",
        ["r1_scenario_to_json.py", str(scenario_path), "--out", str(out), "--repetition", "3"],
    )

    assert renderer.main() == 0

    # Then: the family and the variation are the file's, the repetition the caller's
    rendered = json.loads(out.read_text(encoding="utf-8"))
    assert (rendered["family_id"], rendered["variation_id"], rendered["repetition"]) == (
        "family_x7",
        "V09",
        3,
    )
    printed = capsys.readouterr().out
    assert "pair: family_id=family_x7 variation_id=V09 repetition=3" in printed


@pytest.mark.parametrize(
    "removed",
    [["--family-id", "family_x7"], ["--variation-id", "V09"], ["--family-id=family_x7"]],
    ids=["family", "variation", "family-with-equals"],
)
def test_cli_refuses_the_removed_family_and_variation_options(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    removed: list[str],
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
            "--repetition",
            "1",
            *removed,
        ],
    )

    # The parser stops the command before anything is loaded or written.
    with pytest.raises(SystemExit) as stopped:
        renderer.main()

    assert stopped.value.code == 2
    assert "unrecognized arguments" in capsys.readouterr().err
    assert not out.exists()
    assert not out.parent.exists()


# ---------------------------------------------------------------------------
# Planned lineage: what each run is planned to execute
# ---------------------------------------------------------------------------


def test_rendered_scenario_carries_the_plan_of_each_run_type(tmp_path: Path) -> None:
    # Given: the canonical scenario as it is in the repository, and one rendering of it
    canonical = yaml.safe_load(CANONICAL_SCENARIO.read_text(encoding="utf-8"))
    rendered = apply_run_inputs(_load_canonical(), repetition=1)
    out = render_json(rendered, tmp_path / "scenario.json")
    written = json.loads(out.read_text(encoding="utf-8"))

    # Then: one planned lineage block, keyed by run type, and no other lineage key
    for scenario in (canonical, written):
        assert set(scenario["planned_lineage"]["intermediate"]) == set(RUN_TYPES)
        assert "lineage" not in scenario
    assert written["planned_lineage"] == canonical["planned_lineage"]


def test_attack_planned_lineage_of_the_first_pilot_is_the_cscript_lineage() -> None:
    # The canonical scenario is read as it is in the repository, not through the loader.
    scenario = yaml.safe_load(CANONICAL_SCENARIO.read_text(encoding="utf-8"))

    assert _designed_lineage(scenario, "attack") == (
        "wsmprovhost.exe",
        "cscript.exe",
        "powershell.exe",
    )
    assert _designed_lineage(scenario, "normal") == ("wsmprovhost.exe", "cmd.exe", "powershell.exe")


def test_scenario_that_still_uses_the_old_lineage_key_is_refused(tmp_path: Path) -> None:
    def mutate(scenario: dict) -> None:
        scenario["lineage"] = scenario.pop("planned_lineage")

    with pytest.raises(ValueError, match="planned_lineage"):
        _load_mutated(tmp_path, mutate)


# ---------------------------------------------------------------------------
# A key stated twice
# ---------------------------------------------------------------------------

# A second block for each place a repeated key would change what a run does.
# Plain YAML loading would use these and drop the canonical ones.
_SECOND_ATTACK_INTERMEDIATE = """
    attack:
      image: wscript.exe
      launcher_kind: jscript
      launcher_file: r1_other.js
      arguments:
        - "{launcher}"
"""
_SECOND_INTERNAL_CONNECTION = """
internal_connection:
  required: true
  target: null
  port: null
  protocol: UDP
  lab_cidr: null
  max_attempts: 1
"""
_SECOND_NORMAL_RUN = """
  normal:
    run_type: normal
    reference_action_id: null
    actions: []
"""


def _canonical_text() -> str:
    return CANONICAL_SCENARIO.read_text(encoding="utf-8")


def _load_text(tmp_path: Path, text: str) -> dict:
    path = tmp_path / "scenario.yaml"
    path.write_text(text, encoding="utf-8", newline="\n")
    return load_r1_scenario(path)


def _after(text: str, line: str, added: str) -> str:
    """The text with `added` right after the one place `line` occurs."""
    assert text.count(line) == 1, line
    return text.replace(line, line + added)


def _before(text: str, line: str, added: str) -> str:
    """The text with `added` right before the one place `line` occurs."""
    assert text.count(line) == 1, line
    return text.replace(line, added + line)


def _repeated_top_level_scalar(text: str) -> str:
    return text + "\nscenario_id: R1\n"


def _repeated_internal_connection(text: str) -> str:
    return _before(text, "\nshortcut_controls:\n", _SECOND_INTERNAL_CONNECTION)


def _repeated_protocol(text: str) -> str:
    return _after(text, "  protocol: TCP\n", "  protocol: UDP\n")


def _repeated_attack_intermediate(text: str) -> str:
    # The comment lines above shortcut_controls do not end the intermediate mapping.
    return _before(text, "\nshortcut_controls:\n", _SECOND_ATTACK_INTERMEDIATE)


def _repeated_attack_image(text: str) -> str:
    return _after(text, "      image: cscript.exe\n", "      image: wscript.exe\n")


def _repeated_final_tool_arguments(text: str) -> str:
    return _before(text, "  intermediate:\n", '    arguments:\n      - "-File"\n')


def _repeated_normal_run(text: str) -> str:
    return text.rstrip("\n") + "\n" + _SECOND_NORMAL_RUN


def _repeated_run_type(text: str) -> str:
    return _after(text, "    run_type: normal\n", "    run_type: attack\n")


def _repeated_key_inside_an_action(text: str) -> str:
    return _after(text, "      - action_id: N01\n", "        action_id: N09\n")


@pytest.mark.parametrize(
    ("repeat", "key"),
    [
        (_repeated_top_level_scalar, "scenario_id"),
        (_repeated_internal_connection, "internal_connection"),
        (_repeated_protocol, "protocol"),
        (_repeated_attack_intermediate, "attack"),
        (_repeated_attack_image, "image"),
        (_repeated_final_tool_arguments, "arguments"),
        (_repeated_normal_run, "normal"),
        (_repeated_run_type, "run_type"),
        (_repeated_key_inside_an_action, "action_id"),
    ],
)
def test_key_stated_twice_in_one_mapping_is_refused_at_any_depth(
    tmp_path: Path, repeat: Callable[[str], str], key: str
) -> None:
    # Given: the canonical scenario with one key of one mapping stated a second time
    text = repeat(_canonical_text())
    # Plain loading accepts the text, so the refusal below is this loader's own.
    assert isinstance(yaml.safe_load(text), dict)

    # When / Then
    with pytest.raises(ValueError, match=f"duplicate key '{key}' in one mapping") as refusal:
        _load_text(tmp_path, text)

    # And: the two line numbers of the message are the two places the key is stated
    message = str(refusal.value)
    numbers = re.search(r"line (\d+) repeats line (\d+)", message)
    assert numbers is not None, message
    second, first = (int(number) for number in numbers.groups())
    lines = text.splitlines()
    assert first < second
    for number in (first, second):
        assert lines[number - 1].strip().removeprefix("- ").startswith(f"{key}:"), message
    assert "scenario.yaml" in message


def test_repeated_block_would_otherwise_replace_the_reviewed_one(tmp_path: Path) -> None:
    # Given: a second attack intermediate, which plain loading silently prefers
    text = _repeated_attack_intermediate(_canonical_text())
    silently_used = yaml.safe_load(text)["planned_lineage"]["intermediate"]["attack"]
    assert silently_used["image"] == "wscript.exe"
    assert silently_used["launcher_file"] == "r1_other.js"

    # Then: the R1 loader refuses the file instead of planning the second block
    with pytest.raises(ValueError, match="duplicate key 'attack'"):
        _load_text(tmp_path, text)


def test_keys_that_load_to_one_value_are_a_repeat_too(tmp_path: Path) -> None:
    # YAML reads the plain scalars 5 and 0x5 as the same integer; a dict keeps one of them.
    text = _canonical_text() + "\nextra_block:\n  5: first\n  0x5: second\n"
    assert yaml.safe_load(text)["extra_block"] == {5: "second"}

    with pytest.raises(ValueError, match="duplicate key 5 in one mapping"):
        _load_text(tmp_path, text)


def test_same_key_in_different_mappings_is_not_a_repeat(tmp_path: Path) -> None:
    # `image` and `arguments` are stated once in each of several mappings, and an
    # unknown block may reuse a key name of another block.
    text = _canonical_text() + "\nextra_block:\n  image: x\n  nested:\n    image: y\n"

    scenario = _load_text(tmp_path, text)

    assert scenario["extra_block"] == {"image": "x", "nested": {"image": "y"}}
    assert scenario["planned_lineage"] == _load_canonical()["planned_lineage"]


def test_canonical_scenario_loads_and_renders_as_plain_loading_would(tmp_path: Path) -> None:
    # Given: the canonical scenario read by the R1 loader and by plain safe loading
    loaded = _load_canonical()
    plain = yaml.safe_load(_canonical_text())

    # Then: the same values in the same order
    assert loaded == plain
    assert json.dumps(loaded) == json.dumps(plain)

    # And: the same rendered bytes
    inputs = {
        "target_host": TARGET_HOST,
        "internal_target": INTERNAL_TARGET,
        "internal_port": INTERNAL_PORT,
        "lab_cidr": LAB_CIDR,
        "repetition": 1,
    }
    from_loader = render_json(apply_run_inputs(loaded, **inputs), tmp_path / "loader.json")
    from_plain = render_json(apply_run_inputs(plain, **inputs), tmp_path / "plain.json")
    assert from_loader.read_bytes() == from_plain.read_bytes()


def test_loader_constructs_only_what_safe_loading_constructs(tmp_path: Path) -> None:
    assert issubclass(renderer._UniqueKeyLoader, yaml.SafeLoader)

    # A tag that builds a Python object is refused, as yaml.safe_load refuses it.
    text = _canonical_text().replace(
        "scenario_version: v1\n", "scenario_version: !!python/object/apply:os.getcwd []\n", 1
    )
    with pytest.raises(yaml.constructor.ConstructorError):
        yaml.safe_load(text)
    with pytest.raises(yaml.constructor.ConstructorError):
        _load_text(tmp_path, text)


def test_cli_writes_nothing_for_a_repeated_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scenario_path = tmp_path / "scenario.yaml"
    scenario_path.write_text(
        _repeated_attack_intermediate(_canonical_text()), encoding="utf-8", newline="\n"
    )
    out = tmp_path / "build" / "scenario.json"
    monkeypatch.setattr(
        sys,
        "argv",
        ["r1_scenario_to_json.py", str(scenario_path), "--out", str(out), "--repetition", "1"],
    )

    with pytest.raises(ValueError, match="duplicate key 'attack'"):
        renderer.main()

    assert not out.exists()
    assert not out.parent.exists()
