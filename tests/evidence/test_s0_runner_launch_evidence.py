"""Evidence contract for the command lines the S0 runner actually starts.

The S0 runner starts its connection worker through Get-WorkerLaunch in
scenarios/S0/run-common.ps1, with two explicit launch modes:

    Attack A01   powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass
                 -EncodedCommand <UTF-16LE base64 bootstrap>
    Normal N02   powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass
                 -File <worker> -ChannelDir <channel>

The PowerShell side of that contract is checked in
scenarios/S0/tests/Test-RunCommonGuards.ps1. This file checks the other half:
that those command lines, once normalised into a NormalizedEvent, make the
production extractor produce the Evidence the S0 Pair expects, and only that
Evidence. The Fusion behaviour on top of the Evidence is covered by
tests/decision/fusion/test_s0_fusion_behavior.py and is not repeated here.

No process is started and no socket is opened.
"""

import base64
from datetime import UTC, datetime, timedelta

from incident_awareness.common.models.event import (
    NetworkInfo,
    NormalizedEvent,
    ProcessInfo,
    RawLogReference,
)
from incident_awareness.evidence import extract_evidence

RUN_ID_ATTACK = "RUN-20260920-002"
RUN_ID_NORMAL = "RUN-20260920-001"
HOST_ID = "HOST-S0-001"
START_TIME = datetime(2026, 9, 20, 12, 0, 0, tzinfo=UTC)

# The approved destination is never stored in the repository; this is a global
# IPv4 fixture that only has to satisfy the Evidence condition.
APPROVED_TARGET = "9.9.9.9"
APPROVED_PORT = 443

WORKER_PATH = r"C:\S0\work\s0_conn_RUN-20260920-002\s0_worker.ps1"
CHANNEL_DIR = r"C:\S0\work\s0_conn_RUN-20260920-002"
NORMAL_WORKER_PATH = r"C:\S0\work\s0_conn_RUN-20260920-001\s0_worker.ps1"
NORMAL_CHANNEL_DIR = r"C:\S0\work\s0_conn_RUN-20260920-001"

_COMMON_ARGS = "-NoProfile -NonInteractive -ExecutionPolicy Bypass"


def _encoded_bootstrap(worker_path: str, channel_dir: str) -> str:
    """Mirror Get-WorkerLaunch: a single quoted invocation, UTF-16LE base64."""
    bootstrap = (
        f"& '{worker_path.replace(chr(39), chr(39) * 2)}' "
        f"-ChannelDir '{channel_dir.replace(chr(39), chr(39) * 2)}'"
    )
    return base64.b64encode(bootstrap.encode("utf-16-le")).decode("ascii")


def _attack_a01_command_line() -> str:
    return (
        f"powershell.exe {_COMMON_ARGS} "
        f"-EncodedCommand {_encoded_bootstrap(WORKER_PATH, CHANNEL_DIR)}"
    )


def _normal_n02_command_line() -> str:
    return (
        f"powershell.exe {_COMMON_ARGS} "
        f'-File "{NORMAL_WORKER_PATH}" -ChannelDir "{NORMAL_CHANNEL_DIR}"'
    )


def _event(
    *,
    event_id: str,
    run_id: str,
    event_type: str,
    command_line: str,
    offset_sec: int,
    network: NetworkInfo | None = None,
) -> NormalizedEvent:
    timestamp = START_TIME + timedelta(seconds=offset_sec)
    return NormalizedEvent(
        event_id=event_id,
        run_id=run_id,
        timestamp=timestamp,
        timestamp_source="event_time",
        event_time=timestamp,
        record_time=None,
        ingest_time=timestamp,
        host_id=HOST_ID,
        source="sysmon",
        source_layer="raw_telemetry",
        source_event_id=f"SOURCE-{event_id}",
        event_type=event_type,
        raw_ref=RawLogReference(raw_log_id="RAW-001", segment_no=1, record_no=1),
        process=ProcessInfo(
            pid=4242,
            name="powershell.exe",
            path=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            command_line=command_line,
            parent_pid=1200,
            parent_name="explorer.exe",
        ),
        network=network,
    )


def _connection_network() -> NetworkInfo:
    return NetworkInfo(
        protocol="tcp",
        src_ip="10.0.0.5",
        src_port=49152,
        dst_ip=APPROVED_TARGET,
        dst_port=APPROVED_PORT,
    )


def test_attack_a01_encoded_launch_produces_encoded_powershell_command() -> None:
    # Given: the A01 process create as the attack run starts it
    event = _event(
        event_id="evt-a01",
        run_id=RUN_ID_ATTACK,
        event_type="process_create",
        command_line=_attack_a01_command_line(),
        offset_sec=0,
    )

    # When
    (evidence,) = extract_evidence(event)

    # Then
    assert evidence.evidence_type == "encoded_powershell_command"
    assert evidence.features["matched_option"] == "-encodedcommand"
    assert evidence.run_id == RUN_ID_ATTACK
    assert evidence.entity_id == HOST_ID
    assert evidence.event_ids == ["evt-a01"]
    assert evidence.evidence_id.startswith("E-")


def test_attack_a02_connection_produces_external_connection_evidence() -> None:
    # Given: the A02 network connection made by that same worker process
    event = _event(
        event_id="evt-a02",
        run_id=RUN_ID_ATTACK,
        event_type="network_connection",
        command_line=_attack_a01_command_line(),
        offset_sec=120,
        network=_connection_network(),
    )

    # When
    (evidence,) = extract_evidence(event)

    # Then
    assert evidence.evidence_type == "script_interpreter_external_connection"
    assert evidence.features["dst_ip"] == APPROVED_TARGET
    assert evidence.features["dst_port"] == APPROVED_PORT
    assert evidence.event_ids == ["evt-a02"]


def test_attack_run_produces_both_s0_evidence_types_on_one_entity() -> None:
    # Given: both attack events, as one run on one host
    events = [
        _event(
            event_id="evt-a01",
            run_id=RUN_ID_ATTACK,
            event_type="process_create",
            command_line=_attack_a01_command_line(),
            offset_sec=0,
        ),
        _event(
            event_id="evt-a02",
            run_id=RUN_ID_ATTACK,
            event_type="network_connection",
            command_line=_attack_a01_command_line(),
            offset_sec=120,
            network=_connection_network(),
        ),
    ]

    # When
    evidences = [evidence for event in events for evidence in extract_evidence(event)]

    # Then
    assert [evidence.evidence_type for evidence in evidences] == [
        "encoded_powershell_command",
        "script_interpreter_external_connection",
    ]
    assert {evidence.run_id for evidence in evidences} == {RUN_ID_ATTACK}
    assert {evidence.entity_id for evidence in evidences} == {HOST_ID}
    assert len({evidence.evidence_id for evidence in evidences}) == 2


def test_normal_n02_file_launch_produces_no_encoded_evidence() -> None:
    # Given: the N02 worker process create, started with -File
    event = _event(
        event_id="evt-n02-start",
        run_id=RUN_ID_NORMAL,
        event_type="process_create",
        command_line=_normal_n02_command_line(),
        offset_sec=0,
    )

    # When
    evidences = extract_evidence(event)

    # Then
    assert evidences == []


def test_normal_n02_connection_produces_only_external_connection_evidence() -> None:
    # Given: the N02 connection from that same file-launched process
    events = [
        _event(
            event_id="evt-n02-start",
            run_id=RUN_ID_NORMAL,
            event_type="process_create",
            command_line=_normal_n02_command_line(),
            offset_sec=0,
        ),
        _event(
            event_id="evt-n02",
            run_id=RUN_ID_NORMAL,
            event_type="network_connection",
            command_line=_normal_n02_command_line(),
            offset_sec=120,
            network=_connection_network(),
        ),
    ]

    # When
    evidences = [evidence for event in events for evidence in extract_evidence(event)]

    # Then
    assert [evidence.evidence_type for evidence in evidences] == [
        "script_interpreter_external_connection"
    ]
    assert "encoded_powershell_command" not in {e.evidence_type for e in evidences}
    assert evidences[0].run_id == RUN_ID_NORMAL
    assert evidences[0].entity_id == HOST_ID
    assert evidences[0].event_ids == ["evt-n02"]


def test_both_runs_use_the_same_approved_destination() -> None:
    # Given: the attack and normal connection events
    attack = _event(
        event_id="evt-a02",
        run_id=RUN_ID_ATTACK,
        event_type="network_connection",
        command_line=_attack_a01_command_line(),
        offset_sec=120,
        network=_connection_network(),
    )
    normal = _event(
        event_id="evt-n02",
        run_id=RUN_ID_NORMAL,
        event_type="network_connection",
        command_line=_normal_n02_command_line(),
        offset_sec=120,
        network=_connection_network(),
    )

    # When
    (attack_evidence,) = extract_evidence(attack)
    (normal_evidence,) = extract_evidence(normal)

    # Then
    assert attack_evidence.features["dst_ip"] == normal_evidence.features["dst_ip"]
    assert attack_evidence.features["dst_port"] == normal_evidence.features["dst_port"]


def test_encoded_bootstrap_decodes_to_a_single_worker_invocation() -> None:
    # Given
    encoded = _encoded_bootstrap(WORKER_PATH, CHANNEL_DIR)

    # When
    decoded = base64.b64decode(encoded).decode("utf-16-le")

    # Then
    assert decoded == f"& '{WORKER_PATH}' -ChannelDir '{CHANNEL_DIR}'"
    assert "Invoke-Expression" not in decoded
    assert ";" not in decoded
