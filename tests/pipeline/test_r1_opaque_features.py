import hashlib
import itertools
import json
import random
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from incident_awareness.common.models.evidence import Evidence
from incident_awareness.decision.fusion.config import EVIDENCE_TYPE_VOCABULARY_PATH
from incident_awareness.evaluation.baselines.static_features import extract_static_features
from incident_awareness.evidence.r1_approved_lineage_policy import (
    DEFAULT_R1_FAMILY_BOUND_APPROVED_LINEAGE_POLICIES_PATH,
    load_r1_approved_lineage_policy,
)
from incident_awareness.pipeline import r1_opaque_features as opaque
from incident_awareness.pipeline.r1_production import (
    R1_SELECTOR_LINEAGE_EVENT_COUNT,
    R1_SELECTOR_POLICY_CONFIG_HASH,
    R1_SELECTOR_POLICY_ID,
    R1_SELECTOR_POLICY_VERSION,
)

HOST = "R1-TGTA"
CHANNEL = "Microsoft-Windows-Sysmon/Operational"
# 합성 테스트 전용 가상값이다. 실제 후보 item, Run, raw identity가 아니다.
ITEM_A = "EC-00000000000000a1"
ITEM_B = "EC-00000000000000b2"
RAW_LOG_ID = "RAW-SYNTHETIC-002"
T0 = datetime(2030, 1, 1, 0, 10, tzinfo=UTC)
NAMES = (
    "encoded_powershell_command",
    "script_interpreter_external_connection",
    "remote_session_process_lineage_deviation",
    "remote_process_network_follow_on",
)
ROW_FIELDS = {"item_id", "feature_config_version", "feature_names", "values", "extraction_status"}


def _config(**changes: object) -> opaque.R1OpaqueExtractionConfig:
    approved = load_r1_approved_lineage_policy(
        "r1-wmi-management-approved-lineage",
        "v0.1",
        config_path=DEFAULT_R1_FAMILY_BOUND_APPROVED_LINEAGE_POLICIES_PATH,
    )
    data = {
        "schema_version": "r1-opaque-extraction-config-v0.1",
        "feature_config_version": "r1-wmi-v01-whole-observation-presence-evtypes-v0.2",
        "feature_names": list(NAMES),
        "vocabulary_sha256": hashlib.sha256(EVIDENCE_TYPE_VOCABULARY_PATH.read_bytes()).hexdigest(),
        "family_id": "wmi_management",
        "approved_policy_id": approved.policy_id,
        "approved_policy_version": approved.version,
        "approved_policy_config_hash": approved.config_hash,
        "approved_policy_lifecycle": "development",
        "selector_policy_id": R1_SELECTOR_POLICY_ID,
        "selector_policy_version": R1_SELECTOR_POLICY_VERSION,
        "selector_policy_config_hash": R1_SELECTOR_POLICY_CONFIG_HASH,
        "selector_lineage_event_count": R1_SELECTOR_LINEAGE_EVENT_COUNT,
        "host_id": HOST,
        "source": "sysmon",
        "source_channel": CHANNEL,
        "raw_log_id": RAW_LOG_ID,
        **changes,
    }
    return opaque.load_r1_opaque_extraction_config(data)


def _ts(offset: float) -> tuple[str, str]:
    value = T0 + timedelta(seconds=offset)
    return value.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3], value.isoformat().replace("+00:00", "Z")


def _guid(n: int) -> str:
    return f"{{00000000-0000-0000-0000-{n:012d}}}"


def _process(record_id, offset, guid, image, parent_guid, parent_image, channel=CHANNEL):
    utc, created = _ts(offset)
    return {
        "RecordId": record_id,
        "EventId": 1,
        "TimeCreated": created,
        "Channel": channel,
        "Computer": HOST,
        "EventData": {
            "UtcTime": utc,
            "ProcessGuid": _guid(guid),
            "ProcessId": str(guid),
            "Image": image,
            "CommandLine": image,
            "ParentProcessGuid": _guid(parent_guid),
            "ParentProcessId": str(parent_guid),
            "ParentImage": parent_image,
        },
    }


def _network(record_id, offset, guid, image, dst="192.168.34.30", port="8443"):
    utc, created = _ts(offset)
    return {
        "RecordId": record_id,
        "EventId": 3,
        "TimeCreated": created,
        "Channel": CHANNEL,
        "Computer": HOST,
        "EventData": {
            "UtcTime": utc,
            "ProcessGuid": _guid(guid),
            "ProcessId": str(guid),
            "Image": image,
            "Protocol": "tcp",
            "SourceIp": "192.168.34.20",
            "SourcePort": "49673",
            "DestinationIp": dst,
            "DestinationPort": port,
        },
    }


WMI = r"C:\Windows\System32\wbem\WmiPrvSE.exe"
WSCRIPT = r"C:\Windows\System32\wscript.exe"
CSCRIPT = r"C:\Windows\System32\cscript.exe"
POWERSHELL = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
SVCHOST = r"C:\Windows\System32\svchost.exe"


def _records(*, middle: str = WSCRIPT, network: bool = True, extra_terminal: bool = False):
    # WmiPrvSE는 관측 시작 전에 시작해 lineage 복원 context로만 쓰인다.
    records = [
        _process(1, -60, 10, WMI, 1, SVCHOST),
        _process(2, 30, 11, middle, 10, WMI),
        _process(3, 31, 12, POWERSHELL, 11, middle),
    ]
    if network:
        records.append(_network(4, 40, 12, POWERSHELL))
    if extra_terminal:
        records.append(_process(5, 50, 20, r"C:\Edge\msedge.exe", 2, r"C:\explorer.exe"))
        records.append(_network(6, 51, 20, r"C:\Edge\msedge.exe", "224.0.0.251", "5353"))
    return records


def _write(root: Path, member: str, records: list[dict]) -> str:
    path = root / member
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes("".join(json.dumps(r) + "\n" for r in records).encode("utf-8"))
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _context(item: str, member: str, digest: str, count: int, **changes: object) -> dict:
    return {
        "item_id": item,
        "telemetry_member": member,
        "telemetry_sha256": digest,
        "canonical_event_count": count,
        "authoritative_observation_start": T0.isoformat(),
        "authoritative_observation_end": (T0 + timedelta(minutes=13)).isoformat(),
        "raw_log_id": RAW_LOG_ID,
        "host_id": HOST,
        "source": "sysmon",
        "source_channel": CHANNEL,
        "family_id": "wmi_management",
        "approved_policy_id": "r1-wmi-management-approved-lineage",
        "approved_policy_version": "v0.1",
        **changes,
    }


def _bundle(tmp_path: Path, specs: dict[str, dict], **context_changes):
    contexts = []
    for item_id, spec in specs.items():
        records = _records(**spec)
        digest = _write(tmp_path, f"{item_id}/sysmon.jsonl", records)
        changes = context_changes.get(item_id, {})
        contexts.append(
            _context(item_id, f"{item_id}/sysmon.jsonl", digest, len(records), **changes)
        )
    return contexts


def _build(tmp_path, contexts, expected=None, config=None):
    return opaque.build_r1_opaque_feature_bundle(
        config=config or _config(),
        expected_item_ids=expected if expected is not None else [c["item_id"] for c in contexts],
        item_contexts=contexts,
        telemetry_root=tmp_path,
    )


def test_synthetic_items_produce_training_equivalent_rows(tmp_path: Path) -> None:
    contexts = _bundle(tmp_path, {ITEM_A: {}, ITEM_B: {"middle": CSCRIPT}})

    result = _build(tmp_path, contexts)

    assert result.status == "validated" and result.failures == ()
    assert [(r["item_id"], r["values"]) for r in result.rows] == [
        (ITEM_A, [0, 0, 0, 1]),
        (ITEM_B, [0, 0, 1, 1]),
    ]
    for row in result.rows:
        assert set(row) == ROW_FIELDS
        assert row["feature_names"] == list(NAMES)
        assert row["extraction_status"] == "validated"
        assert not {"run_id", "pair_id", "label", "entity_id"} & set(row)


def test_rows_are_independent_of_context_order(tmp_path: Path) -> None:
    contexts = _bundle(tmp_path, {ITEM_A: {}, ITEM_B: {"middle": CSCRIPT}})

    forward = _build(tmp_path, contexts)
    backward = _build(tmp_path, list(reversed(contexts)), expected=[ITEM_B, ITEM_A])

    assert forward.rows == backward.rows
    assert opaque.opaque_feature_rows_digest(forward.rows) == opaque.opaque_feature_rows_digest(
        backward.rows
    )


def _single_failure(result) -> tuple[str, str]:
    assert result.status == "blocked" and result.rows == ()
    return result.failures[0].stage, result.failures[0].reason


@pytest.mark.parametrize(
    ("spec", "stage", "reason"),
    [
        ({"extra_terminal": True}, "selector", "ambiguous_terminal_candidate"),
        ({"network": False}, "selector", "no_terminal_candidate"),
    ],
)
def test_selector_failure_blocks_bundle_without_zero_vector(tmp_path, spec, stage, reason) -> None:
    contexts = _bundle(tmp_path, {ITEM_A: {}, ITEM_B: spec})

    result = _build(tmp_path, contexts)

    assert _single_failure(result) == (stage, reason)
    assert result.failures[0].item_id == ITEM_B
    # 성공한 item도 부분 발급하지 않는다.
    assert result.items == ()


@pytest.mark.parametrize(
    ("changes", "stage"),
    [
        ({"authoritative_observation_start": None}, "context"),
        ({"authoritative_observation_start": "2030-01-01T00:10:00"}, "context"),
        ({"authoritative_observation_end": (T0 - timedelta(seconds=1)).isoformat()}, "boundary"),
        ({"authoritative_observation_end": (T0 + timedelta(seconds=35)).isoformat()}, "boundary"),
        ({"raw_log_id": "RAW-OTHER"}, "context"),
        ({"raw_log_id": ""}, "context"),
        ({"host_id": "R1-OTHER"}, "partition"),
        ({"source_channel": "Security"}, "partition"),
        ({"approved_policy_version": "v0.2"}, "context"),
        ({"family_id": "remote_management"}, "context"),
        ({"telemetry_sha256": "0" * 64}, "input_integrity"),
        ({"canonical_event_count": 99}, "input_integrity"),
        ({"telemetry_member": "../outside.jsonl"}, "context"),
        ({"run_type": "attack"}, "context"),
        ({"label": 1}, "context"),
        ({"item_id": "RUN-20301101-934"}, "context"),
    ],
)
def test_invalid_context_fails_closed(tmp_path: Path, changes: dict, stage: str) -> None:
    contexts = _bundle(tmp_path, {ITEM_A: {}}, **{ITEM_A: changes})
    expected = [ITEM_A]

    result = _build(tmp_path, contexts, expected=expected)

    assert result.status == "blocked" and result.rows == ()
    assert stage in {failure.stage for failure in result.failures}


def test_tampered_telemetry_fails_integrity(tmp_path: Path) -> None:
    contexts = _bundle(tmp_path, {ITEM_A: {}})
    path = tmp_path / contexts[0]["telemetry_member"]
    path.write_bytes(path.read_bytes().replace(b"8443", b"8444"))

    assert _single_failure(_build(tmp_path, contexts)) == (
        "input_integrity",
        "telemetry SHA-256 mismatch",
    )


def test_mixed_channel_record_fails_partition(tmp_path: Path) -> None:
    records = _records()
    records[1] = _process(2, 30, 11, WSCRIPT, 10, WMI, channel="Security")
    digest = _write(tmp_path, "a/sysmon.jsonl", records)
    contexts = [_context(ITEM_A, "a/sysmon.jsonl", digest, len(records))]

    assert _single_failure(_build(tmp_path, contexts))[0] == "partition"


def test_duplicate_missing_and_unexpected_items_block_bundle(tmp_path: Path) -> None:
    contexts = _bundle(tmp_path, {ITEM_A: {}, ITEM_B: {}})

    duplicate = _build(tmp_path, [*contexts, contexts[0]], expected=[ITEM_A, ITEM_B])
    missing = _build(tmp_path, contexts[:1], expected=[ITEM_A, ITEM_B])
    unexpected = _build(tmp_path, contexts, expected=[ITEM_A])
    repeated_expected = _build(tmp_path, contexts, expected=[ITEM_A, ITEM_A, ITEM_B])
    empty = _build(tmp_path, [], expected=[])

    assert ("bundle", "duplicate item context") in {(f.stage, f.reason) for f in duplicate.failures}
    assert [(f.item_id, f.reason) for f in missing.failures] == [(ITEM_B, "expected item missing")]
    assert [(f.item_id, f.reason) for f in unexpected.failures] == [
        (ITEM_B, "item not in expected list")
    ]
    assert "duplicate expected item" in {f.reason for f in repeated_expected.failures}
    assert "expected item list is empty" in {f.reason for f in empty.failures}
    for result in (duplicate, missing, unexpected, repeated_expected, empty):
        assert result.status == "blocked" and result.rows == ()


def test_config_rejects_masqueraded_policy_and_schema(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="lifecycle"):
        _config(approved_policy_lifecycle="frozen")
    with pytest.raises(ValueError, match="config_hash"):
        _config(approved_policy_config_hash="0" * 64)
    with pytest.raises(ValueError, match="vocabulary"):
        _config(vocabulary_sha256="0" * 64)
    with pytest.raises(ValueError, match="unique"):
        _config(feature_names=[NAMES[0], NAMES[0]])
    with pytest.raises(ValueError, match="unmanaged"):
        _config(feature_names=["not_managed"])


def _cli_args(config: Path, context: Path, telemetry: Path, out: Path) -> list[str]:
    return [
        "--config",
        str(config),
        "--context",
        str(context),
        "--telemetry-root",
        str(telemetry),
        "--output-dir",
        str(out),
    ]


def test_writer_emits_rows_only_for_validated_bundle(tmp_path: Path) -> None:
    telemetry = tmp_path / "telemetry"
    contexts = _bundle(telemetry, {ITEM_A: {}, ITEM_B: {"middle": CSCRIPT}})
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps(_config().model_dump(mode="json")), encoding="utf-8")
    context_path = tmp_path / "context.json"
    document = {
        "schema_version": opaque.R1_OPAQUE_CONTEXT_SCHEMA,
        "expected_item_ids": [ITEM_A, ITEM_B],
        "items": contexts,
    }
    context_path.write_text(json.dumps(document), encoding="utf-8")

    out = tmp_path / "ok"
    assert opaque.main(_cli_args(config_path, context_path, telemetry, out)) == 0
    rows = json.loads((out / opaque.R1_OPAQUE_ROWS_FILENAME).read_text(encoding="utf-8"))
    manifest = json.loads((out / opaque.R1_OPAQUE_MANIFEST_FILENAME).read_text(encoding="utf-8"))
    assert manifest["status"] == "validated"
    assert manifest["feature_rows_sha256"] == opaque.opaque_feature_rows_digest(rows)
    assert manifest["extraction_config"]["approved_policy_lifecycle"] == "development"
    assert "label" not in json.dumps(manifest)

    document["expected_item_ids"].append("EC-00000000000000c3")
    context_path.write_text(json.dumps(document), encoding="utf-8")
    blocked = tmp_path / "blocked"
    assert opaque.main(_cli_args(config_path, context_path, telemetry, blocked)) == 1
    assert not (blocked / opaque.R1_OPAQUE_ROWS_FILENAME).exists()
    blocked_manifest = json.loads(
        (blocked / opaque.R1_OPAQUE_MANIFEST_FILENAME).read_text(encoding="utf-8")
    )
    assert blocked_manifest["status"] == "blocked"
    assert blocked_manifest["failures"][0]["item_id"] == "EC-00000000000000c3"
    with pytest.raises(FileExistsError):
        opaque.main(_cli_args(config_path, context_path, telemetry, out))


# --- _presence_values와 extract_static_features 동등성 ---

EQ_RUN = "RUN-20300101-001"


def _evidence(index: int, evidence_type: str, *, group="fusion_feature", run_id=EQ_RUN):
    return Evidence(
        evidence_id=f"E-{index}",
        run_id=run_id,
        timestamp=T0 + timedelta(seconds=index),
        entity_id=HOST,
        evidence_type=evidence_type,
        event_ids=[f"evt-{index}"],
        derived_from_source_layer="raw_telemetry",
        feature_channel_group=group,
        extractor_version="r1-v0.1",
    )


def _both(evidences, names=NAMES):
    reference = extract_static_features(
        evidences, feature_names=names, run_id=EQ_RUN, entity_id=HOST
    )
    ours = opaque._presence_values(evidences, feature_names=names, scope_id=EQ_RUN, entity_id=HOST)
    return reference.feature_names, reference.values, ours


@pytest.mark.parametrize(
    "subset",
    [s for k in range(len(NAMES) + 1) for s in itertools.combinations(NAMES, k)],
)
def test_presence_equals_static_features_for_every_type_combination(subset) -> None:
    evidences = [_evidence(i, name) for i, name in enumerate(subset)]
    names, values, ours = _both(evidences)
    assert names == NAMES
    assert ours == values


def test_presence_equivalence_edge_cases() -> None:
    base = [_evidence(0, NAMES[2]), _evidence(1, NAMES[3])]
    shuffled = list(base)
    random.Random(7).shuffle(shuffled)
    for evidences in (
        [],
        base + [base[0]],
        shuffled,
        list(reversed(base)),
        [_evidence(5, NAMES[0], group="diagnostic_only")],
        base + [_evidence(6, NAMES[0], group="diagnostic_only")],
    ):
        _, values, ours = _both(evidences)
        assert ours == values
    _, values, ours = _both(base, names=tuple(reversed(NAMES)))
    assert ours == values == (1, 1, 0, 0)


@pytest.mark.parametrize(
    "evidences",
    [
        [_evidence(0, NAMES[2]), _evidence(0, NAMES[3])],
        [_evidence(0, NAMES[2], run_id="RUN-20300101-002")],
    ],
)
def test_presence_rejects_the_same_inputs_as_static_features(evidences) -> None:
    with pytest.raises(ValueError):
        extract_static_features(evidences, feature_names=NAMES, run_id=EQ_RUN, entity_id=HOST)
    with pytest.raises(ValueError):
        opaque._presence_values(evidences, feature_names=NAMES, scope_id=EQ_RUN, entity_id=HOST)


def test_static_features_still_rejects_opaque_scope() -> None:
    # 기존 RUN ID 계약은 완화하지 않는다.
    with pytest.raises(ValueError):
        extract_static_features([], feature_names=NAMES, run_id=ITEM_A, entity_id=HOST)


def test_rows_validate_against_role5_opaque_contract(tmp_path: Path) -> None:
    role5 = pytest.importorskip("incident_awareness.evaluation.baselines.opaque")
    contexts = _bundle(tmp_path, {ITEM_A: {}, ITEM_B: {"middle": CSCRIPT}})
    rows = [role5.OpaqueFeatureRow.model_validate(r) for r in _build(tmp_path, contexts).rows]
    assert role5.feature_rows_digest(rows) == opaque.opaque_feature_rows_digest(
        [r.model_dump(mode="json") for r in rows]
    )
