import hashlib
import json
from pathlib import Path

import pytest

from incident_awareness.collection.s0_validation import (
    ManifestPathError,
    manifest_artifact_name,
    validate_s0_run,
)

RUN_ID = "RUN-20260914-002"
REFERENCE_RECORD_ID = 7809
REFERENCE_TIME = "2026-09-14T15:21:46.216Z"
CONFIG_SHA256 = "1e5c2424ed807ea418a2fa685b81acb23885fc576f77718c8e283ef9b19de8ea"
VM_TELEMETRY_DIR = "C:\\S0\\data\\_rehearsal\\raw\\" + RUN_ID + "\\telemetry"

START_TIME = "2026-09-14T15:21:45.000Z"
# evaluation_horizon_sec is 600, so a collection run may not end before
# reference_time (attack) or start_time (normal) plus ten minutes.
FORMAL_END_TIME = "2026-09-14T15:32:00.000Z"
SHORT_END_TIME = "2026-09-14T15:21:55.000Z"

SCENARIO_YAML = """
scenario_version: v1
scenario_id: S0
run_length:
  evaluation_horizon_sec: 600
  post_reference_margin_sec: 60
shortcut_controls:
  actions_per_run: 4
runs:
  normal:
    run_type: normal
    reference_action_id: null
    actions:
      - action_id: N01
        action_type: admin_action
      - action_id: N02
        action_type: admin_action
        uses_external_connection: true
      - action_id: N03
        action_type: file_operation
      - action_id: N04
        action_type: admin_action
  attack:
    run_type: attack
    reference_action_id: A01
    actions:
      - action_id: A01
        action_type: execution
      - action_id: A02
        action_type: command_and_control
        uses_external_connection: true
      - action_id: A03
        action_type: collection
      - action_id: A04
        action_type: execution
"""

ATTACK_ACTIONS = (
    ("A01", "2026-09-14T15:21:45.981Z", "execution", "anchor process"),
    ("A02", "2026-09-14T15:21:47.000Z", "command_and_control", "outbound connection"),
    ("A03", "2026-09-14T15:21:48.518Z", "collection", "local collection"),
    ("A04", "2026-09-14T15:21:50.620Z", "execution", "follow-on process"),
)
NORMAL_ACTIONS = (
    ("N01", "2026-09-14T15:21:45.981Z", "admin_action", "management script"),
    ("N02", "2026-09-14T15:21:47.000Z", "admin_action", "outbound lookup"),
    ("N03", "2026-09-14T15:21:48.518Z", "file_operation", "copy and compress"),
    ("N04", "2026-09-14T15:21:50.620Z", "admin_action", "backup and cleanup"),
)

SCHEMA_VERSIONS = {
    "run_metadata": "v0.2",
    "event": "v0.2",
    "evidence": "v0.2",
    "fast_hit": "v0.2",
    "detection_result": "v0.2",
    "fusion_result": "v0.2",
    "decision_result": "v0.2",
    "execution_record": "v0.1",
    "evaluation_input": "v0.1",
}


def _write_scenario(tmp_path: Path, body: str = SCENARIO_YAML) -> Path:
    scenario_path = tmp_path / "scenario.yaml"
    scenario_path.write_text(body, encoding="utf-8")
    return scenario_path


def _jsonl_body() -> str:
    records = [
        {
            "RecordId": 7808,
            "EventId": 3,
            "TimeCreated": "2026-09-14T15:21:44.100Z",
            "EventData": {"DestinationIp": "192.168.9.2"},
        },
        {
            "RecordId": REFERENCE_RECORD_ID,
            "EventId": 1,
            "TimeCreated": REFERENCE_TIME,
            "EventData": {"ProcessId": "444", "Image": "powershell.exe"},
        },
        {
            "RecordId": 7810,
            "EventId": 1,
            "TimeCreated": "2026-09-14T15:21:48.541Z",
            "EventData": {"ProcessId": "11160", "Image": "powershell.exe"},
        },
    ]
    return "".join(json.dumps(record) + "\n" for record in records)


def build_run(
    root: Path,
    *,
    run_type: str = "attack",
    rehearsal: bool = False,
    actions: tuple[tuple[str, str, str, str], ...] | None = None,
    end_time: str | None = FORMAL_END_TIME,
    scenario_id: str = "S0",
) -> Path:
    """Write one complete, valid S0 artifact set under `root`."""
    telemetry_dir = root / "raw" / RUN_ID / "telemetry"
    ground_truth_dir = root / "ground_truth" / RUN_ID
    telemetry_dir.mkdir(parents=True)
    ground_truth_dir.mkdir(parents=True)

    if rehearsal:
        (root / "REHEARSAL.txt").write_text("Rehearsal output.", encoding="utf-8")

    evtx_path = telemetry_dir / "sysmon-0001.evtx"
    evtx_path.write_bytes(bytes(range(256)) * 4)
    jsonl_path = telemetry_dir / "sysmon-0001.jsonl"
    jsonl_path.write_text(_jsonl_body(), encoding="utf-8")

    if actions is None:
        actions = ATTACK_ACTIONS if run_type == "attack" else NORMAL_ACTIONS

    header = "run_id,action_id,timestamp,action_type,description\n"
    rows = "".join(
        f'"{RUN_ID}","{action_id}","{timestamp}","{action_type}","{description}"\n'
        for action_id, timestamp, action_type, description in actions
    )
    (ground_truth_dir / "execution_record.csv").write_text(header + rows, encoding="utf-8")

    metadata = {
        "run_id": RUN_ID,
        "scenario_id": scenario_id,
        "run_type": run_type,
        "target_host": "WIN-01",
        "start_time": START_TIME,
        "end_time": end_time,
        "family_id": "local_powershell",
        "variation_id": "v1",
        "repetition": 1,
        "reference_time": REFERENCE_TIME if run_type == "attack" else None,
        "reference_action_id": "A01" if run_type == "attack" else None,
        "reference_source_event_id": str(REFERENCE_RECORD_ID) if run_type == "attack" else None,
        "vm_snapshot": "poc-clean-v1",
        "sysmon_config_version": "sysmonconfig-sample-v0.1",
        "detector_set_version": None,
        "scenario_version": "v1",
        "schema_versions": SCHEMA_VERSIONS,
        "reference_policy_version": "ref-v0.1",
    }
    (ground_truth_dir / "run_metadata.json").write_text(
        json.dumps(metadata, indent=2), encoding="utf-8"
    )

    manifest = {
        "run_id": RUN_ID,
        "generated_at": "2026-09-14T15:22:00.944Z",
        "config_version": None,
        "sysmon": {
            "config_version": "sysmonconfig-sample-v0.1",
            "config_sha256": CONFIG_SHA256,
            "config_hash": "SHA256=" + CONFIG_SHA256.upper(),
            "hashing_algorithms": "SHA256",
        },
        "items": [
            {
                "raw_log_id": "RAW-001",
                "path": VM_TELEMETRY_DIR + "\\sysmon-0001.evtx",
                "sha256": hashlib.sha256(evtx_path.read_bytes()).hexdigest(),
                "layer": "raw_telemetry",
                "source": "sysmon",
            },
            {
                "raw_log_id": "RAW-002",
                "path": VM_TELEMETRY_DIR + "\\sysmon-0001.jsonl",
                "sha256": hashlib.sha256(jsonl_path.read_bytes()).hexdigest(),
                "layer": "raw_telemetry",
                "source": "sysmon",
                "derived_from": VM_TELEMETRY_DIR + "\\sysmon-0001.evtx",
            },
        ],
    }
    (root / "raw" / RUN_ID / "manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )
    return root


def _rewrite_manifest(root: Path, mutate) -> None:
    manifest_path = root / "raw" / RUN_ID / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    mutate(manifest)
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")


def _csv_path(root: Path) -> Path:
    return root / "ground_truth" / RUN_ID / "execution_record.csv"


def _validate(
    root: Path,
    tmp_path: Path,
    *,
    rehearsal: bool = False,
    scenario_body: str = SCENARIO_YAML,
):
    return validate_s0_run(
        artifact_root=root,
        run_id=RUN_ID,
        rehearsal=rehearsal,
        scenario_path=_write_scenario(tmp_path, scenario_body),
    )


def test_accepts_a_complete_attack_run(tmp_path: Path) -> None:
    root = build_run(tmp_path / "data")

    report = _validate(root, tmp_path)

    assert report.ok, report.errors
    assert report.run_type == "attack"
    assert not report.rehearsal


def test_accepts_a_complete_normal_run(tmp_path: Path) -> None:
    root = build_run(tmp_path / "data", run_type="normal")

    report = _validate(root, tmp_path)

    assert report.ok, report.errors
    assert report.run_type == "normal"


def test_accepts_a_rehearsal_run_without_the_external_action(tmp_path: Path) -> None:
    # A rehearsal skips the observation wait, so a short run must still pass.
    actions = tuple(action for action in ATTACK_ACTIONS if action[0] != "A02")
    root = build_run(
        tmp_path / "_rehearsal", rehearsal=True, actions=actions, end_time=SHORT_END_TIME
    )

    report = _validate(root, tmp_path, rehearsal=True)

    assert report.ok, report.errors
    assert report.rehearsal


def test_rejects_a_rehearsal_run_missing_a_local_action(tmp_path: Path) -> None:
    actions = tuple(action for action in ATTACK_ACTIONS if action[0] not in {"A02", "A03"})
    root = build_run(tmp_path / "_rehearsal", rehearsal=True, actions=actions)

    report = _validate(root, tmp_path, rehearsal=True)

    assert not report.ok
    assert any("missing action_id(s): ['A03']" in error for error in report.errors)


@pytest.mark.parametrize(
    "relative_path",
    [
        "raw/" + RUN_ID + "/telemetry/sysmon-0001.evtx",
        "raw/" + RUN_ID + "/telemetry/sysmon-0001.jsonl",
        "raw/" + RUN_ID + "/manifest.json",
        "ground_truth/" + RUN_ID + "/execution_record.csv",
        "ground_truth/" + RUN_ID + "/run_metadata.json",
    ],
)
def test_rejects_a_missing_required_artifact(tmp_path: Path, relative_path: str) -> None:
    root = build_run(tmp_path / "data")
    (root / relative_path).unlink()

    report = _validate(root, tmp_path)

    assert not report.ok
    assert any("required artifact is missing" in error for error in report.errors)


def test_rejects_a_csv_with_a_utf8_bom(tmp_path: Path) -> None:
    root = build_run(tmp_path / "data")
    csv_path = _csv_path(root)
    csv_path.write_bytes(b"\xef\xbb\xbf" + csv_path.read_bytes())

    report = _validate(root, tmp_path)

    assert not report.ok
    assert any("UTF-8 BOM" in error for error in report.errors)


@pytest.mark.parametrize(
    "header",
    [
        "run_id,action_id,timestamp,action_type",
        "action_id,run_id,timestamp,action_type,description",
        "run_id,action_id,timestamp,action_type,description,note",
    ],
    ids=["missing-column", "wrong-order", "extra-column"],
)
def test_rejects_an_unexpected_csv_header(tmp_path: Path, header: str) -> None:
    root = build_run(tmp_path / "data")
    csv_path = _csv_path(root)
    body = csv_path.read_text(encoding="utf-8").split("\n", 1)[1]
    csv_path.write_text(header + "\n" + body, encoding="utf-8")

    report = _validate(root, tmp_path)

    assert not report.ok
    assert any("header must be exactly" in error for error in report.errors)


def test_rejects_an_empty_csv(tmp_path: Path) -> None:
    root = build_run(tmp_path / "data")
    _csv_path(root).write_text("", encoding="utf-8")

    report = _validate(root, tmp_path)

    assert not report.ok
    assert any("is empty" in error for error in report.errors)


def test_rejects_a_csv_with_only_a_header(tmp_path: Path) -> None:
    root = build_run(tmp_path / "data")
    _csv_path(root).write_text(
        "run_id,action_id,timestamp,action_type,description\n", encoding="utf-8"
    )

    report = _validate(root, tmp_path)

    assert not report.ok
    assert any("no rows" in error for error in report.errors)


def test_rejects_a_csv_row_with_another_run_id(tmp_path: Path) -> None:
    root = build_run(tmp_path / "data")
    csv_path = _csv_path(root)
    csv_path.write_text(
        csv_path.read_text(encoding="utf-8").replace(
            '"' + RUN_ID + '","A03"', '"RUN-20260914-003","A03"'
        ),
        encoding="utf-8",
    )

    report = _validate(root, tmp_path)

    assert not report.ok
    assert any("carries run_id(s) other than" in error for error in report.errors)


def test_rejects_run_metadata_that_breaks_the_contract(tmp_path: Path) -> None:
    root = build_run(tmp_path / "data")
    metadata_path = root / "ground_truth" / RUN_ID / "run_metadata.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    del metadata["schema_versions"]["evidence"]
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")

    report = _validate(root, tmp_path)

    assert not report.ok
    assert any("does not satisfy RunMetadata" in error for error in report.errors)


def test_rejects_a_manifest_sha256_mismatch(tmp_path: Path) -> None:
    root = build_run(tmp_path / "data")
    _rewrite_manifest(root, lambda manifest: manifest["items"][0].update({"sha256": "0" * 64}))

    report = _validate(root, tmp_path)

    assert not report.ok
    assert any("sha256 mismatch" in error for error in report.errors)


def test_rejects_a_manifest_without_a_config_hash(tmp_path: Path) -> None:
    root = build_run(tmp_path / "data")
    _rewrite_manifest(root, lambda manifest: manifest["sysmon"].update({"config_hash": ""}))

    report = _validate(root, tmp_path)

    assert not report.ok
    assert any("config_hash is empty" in error for error in report.errors)


def test_rejects_a_config_hash_from_another_algorithm(tmp_path: Path) -> None:
    root = build_run(tmp_path / "data")
    _rewrite_manifest(
        root, lambda manifest: manifest["sysmon"].update({"config_hash": "MD5=" + "a" * 32})
    )

    report = _validate(root, tmp_path)

    assert not report.ok
    assert any("cannot be compared with the SHA-256" in error for error in report.errors)


def test_rejects_a_config_hash_that_differs_from_the_file(tmp_path: Path) -> None:
    root = build_run(tmp_path / "data")
    _rewrite_manifest(
        root, lambda manifest: manifest["sysmon"].update({"config_hash": "SHA256=" + "b" * 64})
    )

    report = _validate(root, tmp_path)

    assert not report.ok
    assert any("config hashes differ" in error for error in report.errors)


def test_rejects_a_manifest_path_that_escapes_the_run_directory(tmp_path: Path) -> None:
    root = build_run(tmp_path / "data")
    _rewrite_manifest(
        root,
        lambda manifest: manifest["items"][0].update(
            {"path": "C:\\S0\\data\\raw\\..\\..\\sysmon-0001.evtx"}
        ),
    )

    report = _validate(root, tmp_path)

    assert not report.ok
    assert any("relative segments" in error for error in report.errors)


def test_rejects_an_unexpected_manifest_file_name(tmp_path: Path) -> None:
    root = build_run(tmp_path / "data")
    _rewrite_manifest(
        root,
        lambda manifest: manifest["items"][0].update({"path": VM_TELEMETRY_DIR + "\\secrets.txt"}),
    )

    report = _validate(root, tmp_path)

    assert not report.ok
    assert any("unexpected artifact file name" in error for error in report.errors)


def test_rejects_a_derived_from_path_that_escapes_the_run_directory(tmp_path: Path) -> None:
    root = build_run(tmp_path / "data")
    _rewrite_manifest(
        root,
        lambda manifest: manifest["items"][1].update({"derived_from": "..\\..\\sysmon-0001.evtx"}),
    )

    report = _validate(root, tmp_path)

    assert not report.ok
    assert any("derived_from rejected" in error for error in report.errors)


def test_rejects_a_reference_record_id_that_is_not_in_the_jsonl(tmp_path: Path) -> None:
    root = build_run(tmp_path / "data")
    metadata_path = root / "ground_truth" / RUN_ID / "run_metadata.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata["reference_source_event_id"] = "9999"
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")

    report = _validate(root, tmp_path)

    assert not report.ok
    assert any("is not traceable" in error for error in report.errors)


def test_rejects_a_reference_event_that_is_not_a_process_create(tmp_path: Path) -> None:
    root = build_run(tmp_path / "data")
    metadata_path = root / "ground_truth" / RUN_ID / "run_metadata.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata["reference_source_event_id"] = "7808"
    metadata["reference_time"] = "2026-09-14T15:21:44.100Z"
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")

    report = _validate(root, tmp_path)

    assert not report.ok
    assert any("expected 1" in error for error in report.errors)


def test_rejects_a_reference_time_that_does_not_match_the_record(tmp_path: Path) -> None:
    root = build_run(tmp_path / "data")
    metadata_path = root / "ground_truth" / RUN_ID / "run_metadata.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata["reference_time"] = "2026-09-14T15:21:46.999Z"
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")

    report = _validate(root, tmp_path)

    assert not report.ok
    assert any("does not match the TimeCreated" in error for error in report.errors)


def test_rejects_a_normal_run_that_carries_a_reference(tmp_path: Path) -> None:
    root = build_run(tmp_path / "data", run_type="normal")
    metadata_path = root / "ground_truth" / RUN_ID / "run_metadata.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata["reference_action_id"] = "N01"
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")

    report = _validate(root, tmp_path)

    assert not report.ok
    assert any("must leave" in error for error in report.errors)


def test_rejects_an_end_time_before_the_start_time(tmp_path: Path) -> None:
    # RunMetadata owns the ordering rule, so the run is rejected as a contract failure.
    root = build_run(tmp_path / "data")
    metadata_path = root / "ground_truth" / RUN_ID / "run_metadata.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata["end_time"] = "2026-09-14T15:21:44.000Z"
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")

    report = _validate(root, tmp_path)

    assert not report.ok
    assert any("does not satisfy RunMetadata" in error for error in report.errors)


def test_rejects_an_execution_record_outside_the_run_window(tmp_path: Path) -> None:
    actions = (("A01", "2026-09-14T15:21:40.000Z", "execution", "too early"), *ATTACK_ACTIONS[1:])
    root = build_run(tmp_path / "data", actions=actions)

    report = _validate(root, tmp_path)

    assert not report.ok
    assert any("before start_time" in error for error in report.errors)


def test_rejects_rehearsal_artifacts_validated_as_a_collection(tmp_path: Path) -> None:
    root = build_run(tmp_path / "_rehearsal", rehearsal=True)

    report = _validate(root, tmp_path)

    assert not report.ok
    assert any("cannot be validated as a formal S0 collection" in error for error in report.errors)


def test_rejects_rehearsal_mode_without_a_marker(tmp_path: Path) -> None:
    root = build_run(tmp_path / "data")

    report = _validate(root, tmp_path, rehearsal=True)

    assert not report.ok
    assert any("REHEARSAL.txt is missing" in error for error in report.errors)


@pytest.mark.parametrize(
    "raw_path",
    [
        "C:\\S0\\data\\raw\\..\\sysmon-0001.evtx",
        "C:/S0/data/./sysmon-0001.evtx",
        "C:\\S0\\data\\telemetry\\",
        "C:\\S0\\data\\raw\\" + RUN_ID + "\\telemetry\\secrets.txt",
        "C:\\S0\\data\\raw\\RUN-20260914-003\\telemetry\\sysmon-0001.evtx",
        "C:\\S0\\data\\" + RUN_ID + "\\telemetry\\sysmon-0001.evtx",
        "sysmon-0001.evtx",
        "",
        "   ",
    ],
)
def test_manifest_artifact_name_rejects_unsafe_paths(raw_path: str) -> None:
    with pytest.raises(ManifestPathError):
        manifest_artifact_name(raw_path, run_id=RUN_ID)


@pytest.mark.parametrize(
    "raw_path",
    [
        VM_TELEMETRY_DIR + "\\sysmon-0001.jsonl",
        "/srv/s0/raw/" + RUN_ID + "/telemetry/sysmon-0001.jsonl",
    ],
    ids=["windows", "posix"],
)
def test_manifest_artifact_name_accepts_both_separators(raw_path: str) -> None:
    assert manifest_artifact_name(raw_path, run_id=RUN_ID) == "sysmon-0001.jsonl"


# --- Manifest completeness -------------------------------------------------


def test_rejects_a_manifest_that_repeats_the_evtx_and_omits_the_jsonl(tmp_path: Path) -> None:
    def mutate(manifest: dict) -> None:
        manifest["items"][1] = dict(manifest["items"][0], raw_log_id="RAW-002")

    root = build_run(tmp_path / "data")
    _rewrite_manifest(root, mutate)

    report = _validate(root, tmp_path)

    assert not report.ok
    assert any("repeats the artifact sysmon-0001.evtx" in error for error in report.errors)
    assert any("does not describe this run's artifact(s)" in error for error in report.errors)


def test_rejects_a_manifest_with_a_duplicate_path(tmp_path: Path) -> None:
    def mutate(manifest: dict) -> None:
        manifest["items"][1]["path"] = manifest["items"][0]["path"]

    root = build_run(tmp_path / "data")
    _rewrite_manifest(root, mutate)

    report = _validate(root, tmp_path)

    assert not report.ok
    assert any("repeats the artifact" in error for error in report.errors)


def test_rejects_a_manifest_with_a_duplicate_raw_log_id(tmp_path: Path) -> None:
    def mutate(manifest: dict) -> None:
        manifest["items"][1]["raw_log_id"] = manifest["items"][0]["raw_log_id"]

    root = build_run(tmp_path / "data")
    _rewrite_manifest(root, mutate)

    report = _validate(root, tmp_path)

    assert not report.ok
    assert any("repeats raw_log_id" in error for error in report.errors)


def test_rejects_a_jsonl_item_without_derived_from(tmp_path: Path) -> None:
    def mutate(manifest: dict) -> None:
        del manifest["items"][1]["derived_from"]

    root = build_run(tmp_path / "data")
    _rewrite_manifest(root, mutate)

    report = _validate(root, tmp_path)

    assert not report.ok
    assert any("must declare derived_from" in error for error in report.errors)


def test_rejects_a_jsonl_derived_from_that_points_at_itself(tmp_path: Path) -> None:
    def mutate(manifest: dict) -> None:
        manifest["items"][1]["derived_from"] = manifest["items"][1]["path"]

    root = build_run(tmp_path / "data")
    _rewrite_manifest(root, mutate)

    report = _validate(root, tmp_path)

    assert not report.ok
    assert any("derived_from points at sysmon-0001.jsonl" in error for error in report.errors)


def test_rejects_a_derived_from_target_that_is_not_a_manifest_item(tmp_path: Path) -> None:
    def mutate(manifest: dict) -> None:
        manifest["items"] = [manifest["items"][1]]

    root = build_run(tmp_path / "data")
    _rewrite_manifest(root, mutate)

    report = _validate(root, tmp_path)

    assert not report.ok
    assert any("which is not a manifest item" in error for error in report.errors)


def test_rejects_an_evtx_item_that_declares_derived_from(tmp_path: Path) -> None:
    def mutate(manifest: dict) -> None:
        manifest["items"][0]["derived_from"] = manifest["items"][1]["path"]

    root = build_run(tmp_path / "data")
    _rewrite_manifest(root, mutate)

    report = _validate(root, tmp_path)

    assert not report.ok
    assert any("the EVTX is the source artifact" in error for error in report.errors)


def test_rejects_a_manifest_path_from_another_run(tmp_path: Path) -> None:
    def mutate(manifest: dict) -> None:
        manifest["items"][0]["path"] = (
            "C:\\S0\\data\\raw\\RUN-20260914-003\\telemetry\\sysmon-0001.evtx"
        )

    root = build_run(tmp_path / "data")
    _rewrite_manifest(root, mutate)

    report = _validate(root, tmp_path)

    assert not report.ok
    assert any("path must end with raw/" + RUN_ID in error for error in report.errors)


def test_rejects_a_manifest_item_with_another_layer(tmp_path: Path) -> None:
    def mutate(manifest: dict) -> None:
        manifest["items"][0]["layer"] = "normalized"

    root = build_run(tmp_path / "data")
    _rewrite_manifest(root, mutate)

    report = _validate(root, tmp_path)

    assert not report.ok
    assert any("layer is 'normalized'" in error for error in report.errors)


def test_rejects_a_manifest_item_with_another_source(tmp_path: Path) -> None:
    def mutate(manifest: dict) -> None:
        manifest["items"][0]["source"] = "hayabusa"

    root = build_run(tmp_path / "data")
    _rewrite_manifest(root, mutate)

    report = _validate(root, tmp_path)

    assert not report.ok
    assert any("source is 'hayabusa'" in error for error in report.errors)


# --- Observation window ----------------------------------------------------


def test_rejects_an_attack_run_that_ends_before_the_horizon(tmp_path: Path) -> None:
    root = build_run(tmp_path / "data", end_time=SHORT_END_TIME)

    report = _validate(root, tmp_path)

    assert not report.ok
    assert any("before reference_time + evaluation_horizon_sec" in error for error in report.errors)


def test_rejects_a_normal_run_that_ends_before_the_horizon(tmp_path: Path) -> None:
    root = build_run(tmp_path / "data", run_type="normal", end_time=SHORT_END_TIME)

    report = _validate(root, tmp_path)

    assert not report.ok
    assert any("before start_time + evaluation_horizon_sec" in error for error in report.errors)


def test_rejects_a_collection_run_without_an_end_time(tmp_path: Path) -> None:
    root = build_run(tmp_path / "data", end_time=None)

    report = _validate(root, tmp_path)

    assert not report.ok
    assert any("must record end_time" in error for error in report.errors)


@pytest.mark.parametrize("horizon", ["0", "-1", "'600'", "null", "true"])
def test_rejects_an_unusable_evaluation_horizon(tmp_path: Path, horizon: str) -> None:
    root = build_run(tmp_path / "data")
    body = SCENARIO_YAML.replace(
        "evaluation_horizon_sec: 600", f"evaluation_horizon_sec: {horizon}"
    )

    report = _validate(root, tmp_path, scenario_body=body)

    assert not report.ok
    assert any("evaluation_horizon_sec must be a positive integer" in e for e in report.errors)


# --- Scenario and execution record consistency -----------------------------


def test_rejects_a_scenario_id_that_does_not_match_the_scenario_file(tmp_path: Path) -> None:
    root = build_run(tmp_path / "data", scenario_id="R1")

    report = _validate(root, tmp_path)

    assert not report.ok
    assert any("scenario_id is 'R1'" in error for error in report.errors)


def test_reports_a_scenario_action_that_is_not_a_mapping(tmp_path: Path) -> None:
    root = build_run(tmp_path / "data")
    body = SCENARIO_YAML.replace(
        "      - action_id: A04\n        action_type: execution\n", "      - A04\n"
    )

    report = _validate(root, tmp_path, scenario_body=body)

    assert not report.ok
    assert any("must be a mapping" in error for error in report.errors)


def test_reports_a_scenario_that_defines_an_action_twice(tmp_path: Path) -> None:
    root = build_run(tmp_path / "data")
    body = SCENARIO_YAML.replace("      - action_id: A04", "      - action_id: A03")

    report = _validate(root, tmp_path, scenario_body=body)

    assert not report.ok
    assert any("more than once" in error for error in report.errors)


def test_rejects_an_execution_record_with_a_repeated_action_id(tmp_path: Path) -> None:
    actions = (*ATTACK_ACTIONS, ("A03", "2026-09-14T15:21:49.000Z", "collection", "again"))
    root = build_run(tmp_path / "data", actions=actions)

    report = _validate(root, tmp_path)

    assert not report.ok
    assert any("records action_id(s) more than once: ['A03']" in error for error in report.errors)


def test_rejects_an_action_type_that_does_not_match_the_scenario(tmp_path: Path) -> None:
    actions = (("A01", "2026-09-14T15:21:45.981Z", "collection", "anchor"), *ATTACK_ACTIONS[1:])
    root = build_run(tmp_path / "data", actions=actions)

    report = _validate(root, tmp_path)

    assert not report.ok
    assert any("action_type does not match the scenario" in error for error in report.errors)


def test_rejects_a_collection_run_missing_the_external_action(tmp_path: Path) -> None:
    actions = tuple(action for action in ATTACK_ACTIONS if action[0] != "A02")
    root = build_run(tmp_path / "data", actions=actions)

    report = _validate(root, tmp_path)

    assert not report.ok
    assert any("missing action_id(s): ['A02']" in error for error in report.errors)
