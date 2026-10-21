import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from incident_awareness.common.models.event import NormalizedEvent
from incident_awareness.common.models.r1_stream import R1EventChunk
from incident_awareness.demo.r1_live_signal import (
    DemoSignalInputError,
    R1LocalDemoSignal,
    build_demo_signal,
    main,
    write_demo_signal,
)

RUN_ID = "RUN-20300101-001"
HOST_ID = "R1-TGTA"
DESTINATION_IP = "192.168.34.30"
T0 = datetime(2030, 1, 1, tzinfo=UTC)
ROOT_GUID = "{11111111-1111-1111-1111-111111111111}"
MIDDLE_GUID = "{22222222-2222-2222-2222-222222222222}"
TERMINAL_GUID = "{33333333-3333-3333-3333-333333333333}"


def _process(
    event_id: str,
    record_id: int,
    timestamp: datetime,
    name: str,
    process_guid: str,
    parent_process_guid: str | None,
) -> NormalizedEvent:
    return NormalizedEvent.model_validate(
        {
            "event_id": event_id,
            "run_id": RUN_ID,
            "timestamp": timestamp,
            "timestamp_source": "event_time",
            "event_time": timestamp,
            "record_time": None,
            "ingest_time": timestamp + timedelta(seconds=1),
            "host_id": HOST_ID,
            "source": "sysmon",
            "source_layer": "raw_telemetry",
            "source_event_id": str(record_id),
            "event_type": "process_create",
            "raw_ref": {
                "raw_log_id": "raw-live",
                "source_record_id": str(record_id),
                "segment_no": 1,
                "record_no": record_id,
            },
            "process": {
                "name": name,
                "process_guid": process_guid,
                "parent_process_guid": parent_process_guid,
            },
        }
    )


def _network(
    event_id: str,
    record_id: int,
    timestamp: datetime,
    *,
    protocol: str | None = "tcp",
) -> NormalizedEvent:
    return NormalizedEvent.model_validate(
        {
            "event_id": event_id,
            "run_id": RUN_ID,
            "timestamp": timestamp,
            "timestamp_source": "event_time",
            "event_time": timestamp,
            "record_time": None,
            "ingest_time": timestamp + timedelta(seconds=1),
            "host_id": HOST_ID,
            "source": "sysmon",
            "source_layer": "raw_telemetry",
            "source_event_id": str(record_id),
            "event_type": "network_connection",
            "raw_ref": {
                "raw_log_id": "raw-live",
                "source_record_id": str(record_id),
                "segment_no": 1,
                "record_no": record_id,
            },
            "process": {
                "name": "powershell.exe",
                "process_guid": TERMINAL_GUID,
                "parent_process_guid": MIDDLE_GUID,
            },
            "network": {
                "protocol": protocol,
                "dst_ip": DESTINATION_IP,
                "dst_port": 8443,
            },
        }
    )


def _events(middle_name: str, *, network_count: int = 1) -> tuple[NormalizedEvent, ...]:
    events = (
        _process("evt-root", 100, T0, "WmiPrvSE.exe", ROOT_GUID, None),
        _process("evt-middle", 101, T0 + timedelta(seconds=1), middle_name, MIDDLE_GUID, ROOT_GUID),
        _process(
            "evt-terminal",
            102,
            T0 + timedelta(seconds=2),
            "powershell.exe",
            TERMINAL_GUID,
            MIDDLE_GUID,
        ),
    )
    networks = tuple(
        _network(f"evt-network-{index}", 102 + index, T0 + timedelta(seconds=2 + index))
        for index in range(1, network_count + 1)
    )
    return (*events, *networks)


def _accepted_spool(
    root: Path,
    events: tuple[NormalizedEvent, ...],
    *,
    acknowledge: bool = True,
) -> Path:
    outbox = root / "outbox"
    acks = root / "acks"
    outbox.mkdir(parents=True)
    acks.mkdir(parents=True)
    for sequence, event in enumerate(events, start=1):
        chunk = R1EventChunk.model_validate(
            {
                "schema": "r1-incremental-stream",
                "contract_version": "v0.1",
                "message_type": "event_chunk",
                "chunk_id": f"chunk-{sequence}",
                "partition": {
                    "run_id": RUN_ID,
                    "host_id": HOST_ID,
                    "source": "sysmon",
                    "source_channel": "Microsoft-Windows-Sysmon/Operational",
                },
                "chunk_sequence": sequence,
                "chunk_content_sha256": f"{sequence:064x}",
                "event_contract_version": "v0.3",
                "events": [event],
            }
        )
        path = outbox / f"{sequence:012d}-event_chunk.json"
        content = chunk.model_dump_json(by_alias=True).encode("utf-8")
        path.write_bytes(content)
        if acknowledge:
            ack = {
                "message_path": str(path.resolve()),
                "message_sha256": hashlib.sha256(content).hexdigest(),
                "disposition": "accepted",
                "accepted_at": (T0 + timedelta(seconds=10 + sequence))
                .isoformat(timespec="milliseconds")
                .replace("+00:00", "Z"),
            }
            (acks / f"{path.name}.ack.json").write_text(
                json.dumps(ack, separators=(",", ":")), encoding="utf-8"
            )
    return root


def _build(spool: Path):
    return build_demo_signal(
        spool_root=spool,
        run_id=RUN_ID,
        destination_ip=DESTINATION_IP,
        clock=lambda: T0 + timedelta(minutes=1),
    )


def test_attack_requires_lineage_deviation_and_same_terminal_network(tmp_path: Path) -> None:
    signal = _build(_accepted_spool(tmp_path, _events("cmd.exe")))

    assert signal.state == "demo_rule_match"
    assert signal.observed_lineage == ("WmiPrvSE.exe", "cmd.exe", "powershell.exe")
    assert signal.lineage_event_ids == ("evt-root", "evt-middle", "evt-terminal")
    assert signal.network_event_id == "evt-network-1"
    assert signal.terminal_process_guid == TERMINAL_GUID
    assert signal.source_event_ids == ("100", "101", "102", "103")
    assert signal.policy.policy_id == "r1-wmi-management-approved-lineage"
    assert signal.policy.version == "v0.1"
    assert signal.policy.lifecycle == "development"
    assert signal.canonical_result is None


def test_approved_normal_lineage_is_not_a_demo_match(tmp_path: Path) -> None:
    signal = _build(_accepted_spool(tmp_path, _events("wscript.exe")))

    assert signal.state == "condition_not_met"
    assert signal.observed_lineage == ("WmiPrvSE.exe", "wscript.exe", "powershell.exe")
    assert signal.diagnostics == ()


def test_unacknowledged_events_are_not_consumed(tmp_path: Path) -> None:
    signal = _build(_accepted_spool(tmp_path, _events("cmd.exe"), acknowledge=False))

    assert signal.state == "observing"
    assert signal.accepted_chunk_count == 0
    assert signal.accepted_event_count == 0


def test_orphan_accepted_ack_is_rejected(tmp_path: Path) -> None:
    spool = _accepted_spool(tmp_path, _events("cmd.exe"))
    last_message = max((spool / "outbox").glob("*.json"))
    last_message.unlink()

    with pytest.raises(DemoSignalInputError, match="ack has no corresponding spool message"):
        _build(spool)


def test_network_event_without_complete_lineage_stays_observing(tmp_path: Path) -> None:
    signal = _build(_accepted_spool(tmp_path, (_network("evt-network", 200, T0),)))

    assert signal.state == "observing"


@pytest.mark.parametrize("protocol", ("udp", None))
def test_non_tcp_network_event_does_not_match(tmp_path: Path, protocol: str | None) -> None:
    events = (*_events("cmd.exe")[:-1], _network("evt-network", 103, T0, protocol=protocol))

    signal = _build(_accepted_spool(tmp_path, events))

    assert signal.state == "observing"
    assert signal.network_event_id is None


@pytest.mark.parametrize("duplicate_role", ("terminal", "parent"))
def test_duplicate_lineage_process_guid_is_input_error(tmp_path: Path, duplicate_role: str) -> None:
    duplicate = (
        _process(
            "evt-terminal-duplicate",
            104,
            T0 + timedelta(seconds=2),
            "powershell.exe",
            TERMINAL_GUID,
            MIDDLE_GUID,
        )
        if duplicate_role == "terminal"
        else _process(
            "evt-middle-duplicate",
            104,
            T0 + timedelta(seconds=1),
            "cmd.exe",
            MIDDLE_GUID,
            ROOT_GUID,
        )
    )
    signal = _build(_accepted_spool(tmp_path, (*_events("cmd.exe"), duplicate)))

    assert signal.state == "input_error"
    assert signal.diagnostics == ("duplicate_process_guid",)
    assert signal.network_event_id is None


def test_multiple_matching_connections_fail_closed(tmp_path: Path) -> None:
    signal = _build(_accepted_spool(tmp_path, _events("cmd.exe", network_count=2)))

    assert signal.state == "input_error"
    assert signal.diagnostics == ("ambiguous_demo_candidate",)
    assert signal.network_event_id is None


def test_message_mutation_after_ack_is_rejected(tmp_path: Path) -> None:
    spool = _accepted_spool(tmp_path, _events("cmd.exe"))
    path = sorted((spool / "outbox").glob("*.json"))[1]
    path.write_text(
        path.read_text(encoding="utf-8").replace("cmd.exe", "evil.exe"), encoding="utf-8"
    )

    with pytest.raises(ValueError, match="does not match"):
        _build(spool)


def test_spool_copy_with_ack_bound_to_original_path_is_rejected(tmp_path: Path) -> None:
    original = _accepted_spool(tmp_path / "original", _events("cmd.exe"))
    copied = tmp_path / "copied"
    copied.mkdir()
    for directory in ("outbox", "acks"):
        target = copied / directory
        target.mkdir()
        for source in (original / directory).iterdir():
            (target / source.name).write_bytes(source.read_bytes())

    with pytest.raises(ValueError, match="bound to another spool message path"):
        _build(copied)


def test_write_demo_signal_replaces_mutable_display_state(tmp_path: Path) -> None:
    output = tmp_path / "state" / "demo-state.json"
    attack = _build(_accepted_spool(tmp_path / "attack", _events("cmd.exe")))
    normal = _build(_accepted_spool(tmp_path / "normal", _events("wscript.exe")))

    write_demo_signal(output, attack)
    write_demo_signal(output, normal)

    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["schema"] == "r1-local-demo-signal"
    assert payload["data_class"] == "demo_only"
    assert payload["state"] == "condition_not_met"
    assert tuple(output.parent.glob(f".{output.name}.*.tmp")) == ()


def test_non_contiguous_accepted_chunks_are_rejected(tmp_path: Path) -> None:
    spool = _accepted_spool(tmp_path, _events("cmd.exe"))
    first_message = min((spool / "outbox").glob("*.json"))
    first_ack = spool / "acks" / f"{first_message.name}.ack.json"
    first_ack.unlink()

    with pytest.raises(DemoSignalInputError, match="contiguous"):
        _build(spool)


def test_cli_removes_stale_state_when_ack_validation_fails(tmp_path: Path) -> None:
    spool = _accepted_spool(tmp_path / "spool", _events("cmd.exe"))
    message = min((spool / "outbox").glob("*.json"))
    message.write_bytes(message.read_bytes() + b"\n")
    output = tmp_path / "demo-state.json"
    output.write_text('{"state":"demo_rule_match"}', encoding="utf-8")

    with pytest.raises(ValueError, match="does not match"):
        main(
            [
                "--spool-root",
                str(spool),
                "--run-id",
                RUN_ID,
                "--destination-ip",
                DESTINATION_IP,
                "--output",
                str(output),
            ]
        )

    assert not output.exists()


def test_cli_removes_stale_state_on_unexpected_build_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "demo-state.json"
    output.write_text('{"state":"demo_rule_match"}', encoding="utf-8")

    def fail_build(**_kwargs: object) -> R1LocalDemoSignal:
        raise RuntimeError("unexpected build failure")

    monkeypatch.setattr(
        "incident_awareness.demo.r1_live_signal.build_demo_signal",
        fail_build,
    )
    with pytest.raises(RuntimeError, match="unexpected build failure"):
        main(
            [
                "--spool-root",
                str(tmp_path / "spool"),
                "--run-id",
                RUN_ID,
                "--destination-ip",
                DESTINATION_IP,
                "--output",
                str(output),
            ]
        )

    assert not output.exists()


def test_role1_example_payload_conforms_to_contract() -> None:
    example = Path(__file__).parents[2] / "docs" / "demo" / "r1-local-video-signal.example.json"

    signal = R1LocalDemoSignal.model_validate_json(example.read_text(encoding="utf-8"))

    assert signal.state == "demo_rule_match"
    assert signal.data_class == "demo_only"
    assert signal.canonical_result is None


@pytest.mark.parametrize(
    ("middle_name", "final_state"),
    (("cmd.exe", "demo_rule_match"), ("wscript.exe", "condition_not_met")),
)
def test_incremental_accepted_chunks_drive_expected_display_states(
    tmp_path: Path,
    middle_name: str,
    final_state: str,
) -> None:
    spool = _accepted_spool(tmp_path, _events(middle_name))
    ack_paths = sorted((spool / "acks").glob("*.json"))
    ack_bytes = {path.name: path.read_bytes() for path in ack_paths}
    for path in ack_paths:
        path.unlink()

    observed = []
    for index, path in enumerate(ack_paths, start=1):
        path.write_bytes(ack_bytes[path.name])
        signal = _build(spool)
        observed.append(signal.state)
        assert signal.accepted_chunk_count == index
        assert signal.accepted_event_count == index

    assert observed == ["observing", "observing", "observing", final_state]


def test_accepted_chunk_for_another_run_is_rejected(tmp_path: Path) -> None:
    spool = _accepted_spool(tmp_path, (_events("cmd.exe")[0],))
    message_path = next((spool / "outbox").glob("*.json"))
    ack_path = spool / "acks" / f"{message_path.name}.ack.json"
    content = message_path.read_text(encoding="utf-8").replace(RUN_ID, "RUN-20300101-002")
    message_path.write_text(content, encoding="utf-8")
    ack = json.loads(ack_path.read_text(encoding="utf-8"))
    ack["message_sha256"] = hashlib.sha256(content.encode("utf-8")).hexdigest()
    ack_path.write_text(json.dumps(ack, separators=(",", ":")), encoding="utf-8")

    with pytest.raises(DemoSignalInputError, match="run_id does not match"):
        _build(spool)


def test_accepted_chunk_outside_sysmon_partition_is_rejected(tmp_path: Path) -> None:
    spool = _accepted_spool(tmp_path, (_events("cmd.exe")[0],))
    message_path = next((spool / "outbox").glob("*.json"))
    ack_path = spool / "acks" / f"{message_path.name}.ack.json"
    payload = json.loads(message_path.read_text(encoding="utf-8"))
    payload["partition"]["source_channel"] = "Security"
    content = json.dumps(payload, separators=(",", ":"))
    message_path.write_text(content, encoding="utf-8")
    ack = json.loads(ack_path.read_text(encoding="utf-8"))
    ack["message_sha256"] = hashlib.sha256(content.encode("utf-8")).hexdigest()
    ack_path.write_text(json.dumps(ack, separators=(",", ":")), encoding="utf-8")

    with pytest.raises(DemoSignalInputError, match="outside the Sysmon demo partition"):
        _build(spool)


def test_accepted_chunk_outside_demo_host_is_rejected(tmp_path: Path) -> None:
    spool = _accepted_spool(tmp_path, (_events("cmd.exe")[0],))
    message_path = next((spool / "outbox").glob("*.json"))
    ack_path = spool / "acks" / f"{message_path.name}.ack.json"
    payload = json.loads(message_path.read_text(encoding="utf-8"))
    payload["partition"]["host_id"] = "R1-OTHER"
    for event in payload["events"]:
        event["host_id"] = "R1-OTHER"
    content = json.dumps(payload, separators=(",", ":"))
    message_path.write_text(content, encoding="utf-8")
    ack = json.loads(ack_path.read_text(encoding="utf-8"))
    ack["message_sha256"] = hashlib.sha256(content.encode("utf-8")).hexdigest()
    ack_path.write_text(json.dumps(ack, separators=(",", ":")), encoding="utf-8")

    with pytest.raises(DemoSignalInputError, match="outside the Sysmon demo partition"):
        _build(spool)
