"""The strict writer and loader of the Role4 sidecar artifact (r1_wmi_collection_context.json).

These tests hold the artifact to its own contract, without the raw export it
describes. The deep check against a run's records is in
test_r1_collection_window.py; this file is the artifact-level strictness: a
duplicate key, an unknown or missing field, a value of the wrong type, a stamp
out of order, a missing source identifier, an active probe, a canonical linkage
that does not match, and an overwrite.
"""

import copy
import json
from pathlib import Path

import pytest

from incident_awareness.collection.r1_collection_window import (
    CANONICAL_CONTRACT_VERSION,
    CANONICAL_PROVENANCE_FILENAME,
    CONTRACT_VERSION,
    PROVENANCE_FIELDS,
    PROVENANCE_FILENAME,
    SCHEMA_NAME,
    R1WmiCollectionContextError,
    check_wmi_provenance_pair,
    load_r1_wmi_collection_context,
    sidecar_sha256,
    write_r1_wmi_collection_context,
)

HASH_A = "a1" * 32
HASH_B = "b2" * 32


def valid_document() -> dict:
    """A sidecar whose every field the loader accepts. created_process/actions/lineage are not read here."""
    return {
        "schema": SCHEMA_NAME,
        "contract_version": CONTRACT_VERSION,
        "run_id": "RUN-20300101-001",
        "target_host": "TARGET-A",
        "scenario": {
            "scenario_id": "R1",
            "family_id": "wmi_management",
            "variation_id": "V01",
            "scenario_version": "v1",
        },
        "entry_kind": "wmi_process",
        "raw_window": "target_boot_to_run_end",
        "raw_collection_start": "2030-01-01T23:50:00.000Z",
        "raw_collection_end": "2030-01-02T00:13:00.000Z",
        "collection_window_extension_reason": "lineage_root_created_before_run",
        "export_margin_ms": 10000,
        "observation_start": "2030-01-02T00:00:00.000Z",
        "observation_end": "2030-01-02T00:13:00.000Z",
        "time_field": "EventData.UtcTime",
        "context_rule": "EventData.UtcTime < observation_start",
        "context_use": "lineage_restoration_only",
        "evaluation_window_start": "2030-01-02T00:00:00.200Z",
        "evaluation_horizon_sec": 600,
        "evaluation_window_end": "2030-01-02T00:10:00.200Z",
        "record_counts": {"total": 7, "context": 3, "observation": 4},
        "lineage": {
            "linked_by": ["ProcessGuid", "ParentProcessGuid"],
            "records": [],
            "context_record_ids": ["10"],
            "references_to_context": [],
            "connection": None,
        },
        "evidence_link_key": "RecordId",
        "readiness": {
            "method": "out_of_band",
            "checked_at": "2030-01-01T23:59:00.000Z",
            "result": "ready",
            "active_tcp_probe_used": False,
            "record_sha256": HASH_A,
        },
        "raw_source": {
            "host": "TARGET-A",
            "channel": "Microsoft-Windows-Sysmon/Operational",
            "jsonl_file": "sysmon-0001.jsonl",
            "jsonl_sha256": HASH_B,
            "raw_log_id": "RAW-002",
        },
        "created_process": None,
        "actions": [],
        "context_events": [],
        "context_rule_version": "r1-context-rule-v0.1",
        "run_start_inclusive": True,
        "time_fallback": "none",
        "selector_raw_input_scope": "raw_collection_window",
        "target_boot_utc": "2030-01-01T23:50:00.000Z",
        "boot_session_id": None,
        "scenario_sha256": "c3" * 32,
        "manifest_sha256": "d4" * 32,
        "sysmon_config_sha256": "e5" * 32,
        "canonical_provenance_linkage": {
            "filename": CANONICAL_PROVENANCE_FILENAME,
            "contract_version": CANONICAL_CONTRACT_VERSION,
            "reference_policy_id": "r1-wmi-a01-reference",
            "reference_policy_version": "wmi-ref-v0.1",
            "reference_policy_config_hash": "f6" * 32,
            "canonical_sha256": None,
        },
    }


def write(tmp_path: Path, document: dict) -> Path:
    path = tmp_path / PROVENANCE_FILENAME
    path.write_bytes(
        (json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
    )
    return path


def test_a_valid_sidecar_round_trips_through_the_writer_and_the_loader(tmp_path: Path) -> None:
    document = valid_document()
    path, digest = write_r1_wmi_collection_context(document, tmp_path / PROVENANCE_FILENAME)

    assert path.name == PROVENANCE_FILENAME
    assert digest == sidecar_sha256(document)
    loaded = load_r1_wmi_collection_context(path)
    assert loaded == document


def test_collection_seals_the_sidecar_before_role2_canonical_provenance_exists(
    tmp_path: Path,
) -> None:
    """Collection owns only the sidecar; later Role2 output is not a collection gate."""
    path, _ = write_r1_wmi_collection_context(
        valid_document(), tmp_path / "operator_trace" / RUN_ID / PROVENANCE_FILENAME
    )

    assert not (path.parent / CANONICAL_PROVENANCE_FILENAME).exists()
    assert load_r1_wmi_collection_context(path)["run_id"] == RUN_ID


def test_the_canonical_serialization_is_deterministic(tmp_path: Path) -> None:
    document = valid_document()
    shuffled = dict(reversed(list(document.items())))

    assert sidecar_sha256(document) == sidecar_sha256(shuffled)
    _, first = write_r1_wmi_collection_context(document, tmp_path / "a" / PROVENANCE_FILENAME)
    _, second = write_r1_wmi_collection_context(shuffled, tmp_path / "b" / PROVENANCE_FILENAME)
    assert first == second


def test_the_writer_does_not_overwrite_a_published_sidecar(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / PROVENANCE_FILENAME
    original = b"already published\n"
    path.write_bytes(original)

    # An exists-then-write implementation can be raced. Pretend its pre-check
    # saw no file; exclusive creation must still protect the published bytes.
    monkeypatch.setattr(Path, "exists", lambda _path: False)

    with pytest.raises(R1WmiCollectionContextError, match="already exists"):
        write_r1_wmi_collection_context(valid_document(), path)
    assert path.read_bytes() == original


def test_a_file_that_is_not_named_like_the_sidecar_is_refused(tmp_path: Path) -> None:
    with pytest.raises(R1WmiCollectionContextError, match="is named"):
        write_r1_wmi_collection_context(valid_document(), tmp_path / "other.json")


def test_a_duplicate_json_key_is_refused(tmp_path: Path) -> None:
    path = tmp_path / PROVENANCE_FILENAME
    path.write_text(
        '{"run_id": "RUN-20300101-001", "run_id": "RUN-20300101-002"}', encoding="utf-8"
    )

    with pytest.raises(R1WmiCollectionContextError, match="more than once"):
        load_r1_wmi_collection_context(path)


@pytest.mark.parametrize("field", PROVENANCE_FIELDS)
def test_a_sidecar_missing_a_field_is_refused(tmp_path: Path, field: str) -> None:
    document = valid_document()
    del document[field]

    with pytest.raises(R1WmiCollectionContextError, match="missing"):
        load_r1_wmi_collection_context(write(tmp_path, document))


def test_a_sidecar_with_an_unknown_field_is_refused(tmp_path: Path) -> None:
    document = valid_document()
    document["parent_image_fallback"] = True

    with pytest.raises(R1WmiCollectionContextError, match="unknown"):
        load_r1_wmi_collection_context(write(tmp_path, document))


@pytest.mark.parametrize(
    ("mutate", "match"),
    [
        (lambda d: d.update(schema="other"), "schema is"),
        (lambda d: d.update(contract_version="v9"), "contract_version is"),
        (lambda d: d.update(time_fallback="TimeCreated"), "time_fallback is"),
        (lambda d: d.update(run_start_inclusive=False), "run_start_inclusive must be true"),
        (lambda d: d.update(run_id="  "), "run_id must be a non-blank string"),
        (
            lambda d: d["scenario"].update(scenario_id=""),
            "scenario.scenario_id must be a non-blank",
        ),
        (lambda d: d["scenario"].pop("variation_id"), "scenario must hold exactly"),
        (
            lambda d: d.update(raw_collection_start="2030-01-02T00:05:00.000Z"),
            "raw_collection_start must be at or before observation_start",
        ),
        (
            lambda d: d.update(observation_start="not a stamp"),
            "observation_start is not a UTC stamp",
        ),
        (
            lambda d: d.update(evaluation_window_end="2030-01-02T00:00:00.100Z"),
            "evaluation_window_end is before evaluation_window_start",
        ),
        (
            lambda d: d.update(evaluation_window_end=None),
            "evaluation_window_start and evaluation_window_end are both set or both null",
        ),
        (
            lambda d: d.update(target_boot_utc=None, boot_session_id=None),
            "the boot is not identified",
        ),
        (
            lambda d: d["readiness"].update(active_tcp_probe_used=True),
            "readiness.active_tcp_probe_used must be false",
        ),
        (
            lambda d: d["readiness"].update(checked_at="soon"),
            "readiness.checked_at is not a UTC stamp",
        ),
        (
            lambda d: d["readiness"].update(record_sha256="nope"),
            "readiness.record_sha256 is not a SHA-256",
        ),
        (
            lambda d: d["raw_source"].update(raw_log_id=""),
            "raw_source.raw_log_id must be a non-blank",
        ),
        (
            lambda d: d["raw_source"].update(jsonl_sha256="nope"),
            "raw_source.jsonl_sha256 is not a SHA-256",
        ),
        (lambda d: d.update(scenario_sha256="nope"), "scenario_sha256 is not a SHA-256"),
    ],
    ids=[
        "another_schema",
        "another_contract",
        "another_fallback",
        "not_inclusive",
        "blank_run_id",
        "blank_scenario_id",
        "scenario_missing_a_field",
        "raw_after_observation",
        "unreadable_observation",
        "evaluation_end_before_start",
        "half_an_evaluation_window",
        "no_boot_identity",
        "active_probe",
        "unreadable_checked_at",
        "readiness_hash",
        "blank_raw_log_id",
        "raw_source_hash",
        "scenario_hash",
    ],
)
def test_a_sidecar_that_breaks_a_rule_is_refused(tmp_path: Path, mutate, match: str) -> None:
    document = valid_document()
    mutate(document)

    with pytest.raises(R1WmiCollectionContextError, match=match):
        load_r1_wmi_collection_context(write(tmp_path, document))


@pytest.mark.parametrize(
    ("mutate", "match"),
    [
        (
            lambda link: link.update(filename="other.json"),
            "canonical_provenance_linkage.filename is",
        ),
        (
            lambda link: link.update(contract_version="v9"),
            "canonical_provenance_linkage.contract_version is",
        ),
        (
            lambda link: link.update(reference_policy_id=""),
            "reference_policy_id must be a non-blank",
        ),
        (
            lambda link: link.update(reference_policy_config_hash="nope"),
            "config_hash is not a SHA-256",
        ),
        (
            lambda link: link.update(canonical_sha256="nope"),
            "canonical_sha256 must be null or a SHA-256",
        ),
        (
            lambda link: link.pop("reference_policy_version"),
            "canonical_provenance_linkage must hold exactly",
        ),
    ],
    ids=[
        "another_filename",
        "another_contract",
        "blank_policy_id",
        "policy_hash",
        "bad_canonical_hash",
        "linkage_missing_a_field",
    ],
)
def test_a_canonical_linkage_that_breaks_a_rule_is_refused(
    tmp_path: Path, mutate, match: str
) -> None:
    document = valid_document()
    mutate(document["canonical_provenance_linkage"])

    with pytest.raises(R1WmiCollectionContextError, match=match):
        load_r1_wmi_collection_context(write(tmp_path, document))


def test_the_loader_holds_a_supplied_canonical_artifact_to_the_linkage(tmp_path: Path) -> None:
    """A canonical artifact the sidecar records a SHA-256 for has to hash to it."""
    document = valid_document()
    canonical = tmp_path / CANONICAL_PROVENANCE_FILENAME
    canonical.write_bytes(b'{"contract_version": "v0.1"}\n')
    document["canonical_provenance_linkage"]["canonical_sha256"] = "0" * 64
    path = write(tmp_path, copy.deepcopy(document))

    with pytest.raises(R1WmiCollectionContextError, match="hashes to"):
        load_r1_wmi_collection_context(path, canonical_path=canonical)


# ---------------------------------------------------------------------------
# Post-Evidence pairing of the two provenance artifacts in one Run directory.
# Collection itself is covered above and succeeds with only the Role4 sidecar.
# ---------------------------------------------------------------------------

RUN_ID = "RUN-20300101-001"


def canonical_document(run_id: str = RUN_ID) -> dict:
    """A Role2 canonical artifact whose policy identity matches valid_document()'s linkage."""
    return {
        "contract_version": "v0.1",
        "run_id": run_id,
        "selected_target_host": "TARGET-A",
        "scenario_identifier": "R1",
        "scenario_version": "v1",
        "reference_policy_canonical_path": "configs/r1_reference_policies_v0.1.yaml",
        "reference_policy_id": "r1-wmi-a01-reference",
        "reference_policy_version": "wmi-ref-v0.1",
        "reference_policy_config_hash": "f6" * 32,
        "loader_selected_policy_identity": {
            "policy_id": "r1-wmi-a01-reference",
            "version": "wmi-ref-v0.1",
            "config_hash": "f6" * 32,
        },
        "scenario_evaluation_horizon_sec": 600,
        "policy_expected_evaluation_horizon_sec": 600,
        "horizon_matches": True,
        "reference_action_id": "A01",
        "reference_time": "2030-01-02T00:00:00.200Z",
        "reference_source_event_id": "30",
        "reference_event_id": "EVT-30",
        "action_process_id": 4321,
        "execution_commit": "0" * 40,
        "loader_version": "r1-reference-policy-loader-v0.1",
    }


def write_pair(trace: Path, *, canonical: dict | None, sidecar: dict | None) -> None:
    trace.mkdir(parents=True, exist_ok=True)
    if canonical is not None:
        (trace / CANONICAL_PROVENANCE_FILENAME).write_text(
            json.dumps(canonical, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    if sidecar is not None:
        write(trace, sidecar)


def test_post_evidence_validation_without_the_canonical_artifact_fails_closed(
    tmp_path: Path,
) -> None:
    write_pair(tmp_path, canonical=None, sidecar=valid_document())

    with pytest.raises(R1WmiCollectionContextError, match="missing.*r1_collection_provenance.json"):
        check_wmi_provenance_pair(tmp_path, RUN_ID)


def test_post_evidence_validation_without_the_sidecar_fails_closed(tmp_path: Path) -> None:
    write_pair(tmp_path, canonical=canonical_document(), sidecar=None)

    with pytest.raises(
        R1WmiCollectionContextError, match="missing.*r1_wmi_collection_context.json"
    ):
        check_wmi_provenance_pair(tmp_path, RUN_ID)


def test_a_canonical_artifact_of_another_run_fails_closed(tmp_path: Path) -> None:
    write_pair(tmp_path, canonical=canonical_document("RUN-20300101-999"), sidecar=valid_document())

    with pytest.raises(R1WmiCollectionContextError, match="canonical artifact states run_id"):
        check_wmi_provenance_pair(tmp_path, RUN_ID)


def test_an_explicit_canonical_path_with_another_name_fails_closed(tmp_path: Path) -> None:
    write_pair(tmp_path, canonical=canonical_document(), sidecar=valid_document())
    renamed = tmp_path / "renamed-reference-provenance.json"
    renamed.write_text(
        json.dumps(canonical_document(), indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    with pytest.raises(R1WmiCollectionContextError, match="canonical artifact is named"):
        check_wmi_provenance_pair(tmp_path, RUN_ID, canonical_path=renamed)


def _skip_without_role2_loader() -> None:
    try:
        import incident_awareness.pipeline.r1_artifacts  # noqa: F401
    except (ImportError, SyntaxError) as error:
        pytest.skip(f"the Role2 canonical loader cannot be imported here: {type(error).__name__}")


def test_a_canonical_loader_contract_error_uses_the_sidecar_exception(tmp_path: Path) -> None:
    _skip_without_role2_loader()
    malformed = {"run_id": RUN_ID}
    write_pair(tmp_path, canonical=malformed, sidecar=valid_document())

    with pytest.raises(R1WmiCollectionContextError, match="does not match its contract"):
        check_wmi_provenance_pair(tmp_path, RUN_ID)


def test_the_two_artifacts_of_one_run_in_one_directory_pass(tmp_path: Path) -> None:
    _skip_without_role2_loader()
    write_pair(tmp_path, canonical=canonical_document(), sidecar=valid_document())

    check_wmi_provenance_pair(tmp_path, RUN_ID)  # does not raise


def test_a_sidecar_of_another_run_fails_closed(tmp_path: Path) -> None:
    _skip_without_role2_loader()
    sidecar = valid_document()
    sidecar["run_id"] = "RUN-20300101-002"
    write_pair(tmp_path, canonical=canonical_document(), sidecar=sidecar)

    with pytest.raises(R1WmiCollectionContextError, match="run_id"):
        check_wmi_provenance_pair(tmp_path, RUN_ID)
