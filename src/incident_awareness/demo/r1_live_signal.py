"""Build a demo-only WMI signal from Role3-acknowledged R1 EventChunks.

This module deliberately does not create Evidence, FusionResult, DecisionResult, or
evaluation artifacts.  It validates each immutable spool message against the
post-commit Role3 ack before applying the registered approved-lineage policy.
"""

from __future__ import annotations

import argparse
import json
import os
import time
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from incident_awareness.common.models.event import NormalizedEvent
from incident_awareness.common.models.r1_stream import R1EventChunk
from incident_awareness.evidence.r1_approved_lineage_policy import (
    DEFAULT_R1_FAMILY_BOUND_APPROVED_LINEAGE_POLICIES_PATH,
    load_r1_approved_lineage_policy,
    validate_r1_policy_family_binding,
)
from incident_awareness.evidence.r1_multi_event import (
    ApprovedLineagePolicy,
    extract_remote_process_network_follow_on,
    extract_remote_session_process_lineage_deviation_with_diagnostics,
)
from incident_awareness.pipeline.r1_stream_wiring import load_accepted_spool_message

SCHEMA = "r1-local-demo-signal"
CONTRACT_VERSION = "v0.1"
FAMILY_ID = "wmi_management"
POLICY_ID = "r1-wmi-management-approved-lineage"
POLICY_VERSION = "v0.1"
HOST_ID = "R1-TGTA"
SOURCE = "sysmon"
SOURCE_CHANNEL = "Microsoft-Windows-Sysmon/Operational"

DemoSignalState = Literal["observing", "condition_not_met", "demo_rule_match", "input_error"]


class DemoPolicyIdentity(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    policy_id: str
    version: str
    config_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    lifecycle: str
    approved_lineage: tuple[str, ...]


class R1LocalDemoSignal(BaseModel):
    """Role1-facing, non-canonical state for the internal-evaluation video."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_id: Literal["r1-local-demo-signal"] = Field(
        validation_alias="schema", serialization_alias="schema"
    )
    contract_version: Literal["v0.1"]
    data_class: Literal["demo_only"]
    run_id: str
    host_id: str | None
    state: DemoSignalState
    generated_at: datetime
    last_accepted_at: datetime | None
    accepted_chunk_count: int = Field(ge=0)
    accepted_event_count: int = Field(ge=0)
    policy: DemoPolicyIdentity
    observed_lineage: tuple[str, ...] | None
    lineage_event_ids: tuple[str, ...]
    network_event_id: str | None
    source_event_ids: tuple[str, ...]
    terminal_process_guid: str | None
    destination_ip: str
    destination_port: int = Field(ge=0, le=65535)
    diagnostics: tuple[str, ...]
    canonical_result: None = None
    non_guarantees: tuple[str, ...] = (
        "canonical_evidence_or_decision",
        "source_completeness",
        "causal_or_online_eligibility",
        "ttsd",
    )


class DemoSignalInputError(ValueError):
    """The acknowledged spool cannot safely produce a demo signal."""


def build_demo_signal(
    *,
    spool_root: Path,
    run_id: str,
    destination_ip: str,
    destination_port: int = 8443,
    policy_config: Path = DEFAULT_R1_FAMILY_BOUND_APPROVED_LINEAGE_POLICIES_PATH,
    clock: Any = lambda: datetime.now(UTC),
) -> R1LocalDemoSignal:
    """Validate accepted chunks and derive one display-only state."""

    if not run_id.strip():
        raise DemoSignalInputError("run_id must be non-blank")
    if not destination_ip.strip():
        raise DemoSignalInputError("destination_ip must be non-blank")
    if not 0 <= destination_port <= 65535:
        raise DemoSignalInputError("destination_port must be between 0 and 65535")

    policy = load_r1_approved_lineage_policy(
        POLICY_ID,
        POLICY_VERSION,
        config_path=policy_config,
    )
    validate_r1_policy_family_binding(FAMILY_ID, policy)
    chunks, accepted_at = _load_accepted_chunks(spool_root=spool_root, run_id=run_id)
    events = _unique_events(chunks)
    host_ids = {event.host_id for event in events}
    if len(host_ids) > 1:
        raise DemoSignalInputError("accepted Events span more than one host")
    host_id = next(iter(host_ids), None)
    if host_id is not None and host_id != HOST_ID:
        raise DemoSignalInputError("accepted Events are outside the R1-TGTA demo host")

    diagnostics = _process_identity_diagnostics(events)
    candidates = (
        ()
        if diagnostics
        else _find_candidates(
            events=events,
            policy=policy,
            destination_ip=destination_ip,
            destination_port=destination_port,
        )
    )
    selected: _Candidate | None = None
    state: DemoSignalState = "input_error" if diagnostics else "observing"
    if not diagnostics and len(candidates) > 1:
        state = "input_error"
        diagnostics = ("ambiguous_demo_candidate",)
    elif candidates:
        selected = candidates[0]
        state = "demo_rule_match" if selected.is_deviation else "condition_not_met"

    return R1LocalDemoSignal.model_validate(
        {
            "schema": SCHEMA,
            "contract_version": CONTRACT_VERSION,
            "data_class": "demo_only",
            "run_id": run_id,
            "host_id": host_id,
            "state": state,
            "generated_at": _utc_milliseconds(clock()),
            "last_accepted_at": accepted_at,
            "accepted_chunk_count": len(chunks),
            "accepted_event_count": len(events),
            "policy": _policy_identity(policy),
            "observed_lineage": None if selected is None else selected.observed_lineage,
            "lineage_event_ids": () if selected is None else selected.lineage_event_ids,
            "network_event_id": None if selected is None else selected.network_event.event_id,
            "source_event_ids": () if selected is None else selected.source_event_ids,
            "terminal_process_guid": None if selected is None else selected.terminal_process_guid,
            "destination_ip": destination_ip,
            "destination_port": destination_port,
            "diagnostics": diagnostics,
            "canonical_result": None,
        }
    )


class _Candidate(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True, frozen=True)

    is_deviation: bool
    observed_lineage: tuple[str, ...]
    lineage_event_ids: tuple[str, ...]
    network_event: NormalizedEvent
    source_event_ids: tuple[str, ...]
    terminal_process_guid: str


def _load_accepted_chunks(
    *, spool_root: Path, run_id: str
) -> tuple[tuple[R1EventChunk, ...], datetime | None]:
    outbox = spool_root / "outbox"
    acks = spool_root / "acks"
    accepted: list[tuple[R1EventChunk, datetime]] = []
    for ack_path in sorted(acks.glob("*.ack.json")):
        message_name = ack_path.name.removesuffix(".ack.json")
        message_path = outbox / message_name
        if not message_path.is_file():
            raise DemoSignalInputError("accepted ack has no corresponding spool message")
        message = load_accepted_spool_message(message_path, ack_path)
        if not isinstance(message, R1EventChunk):
            continue
        if message.partition.run_id != run_id:
            raise DemoSignalInputError("accepted EventChunk run_id does not match the demo Run")
        if (
            message.partition.host_id != HOST_ID
            or message.partition.source != SOURCE
            or message.partition.source_channel != SOURCE_CHANNEL
        ):
            raise DemoSignalInputError("accepted EventChunk is outside the Sysmon demo partition")
        ack = json.loads(ack_path.read_text(encoding="utf-8"))
        accepted_at = _parse_utc(ack.get("accepted_at"))
        accepted.append((message, accepted_at))

    accepted.sort(key=lambda item: item[0].chunk_sequence)
    sequences = [chunk.chunk_sequence for chunk, _ in accepted]
    if sequences and sequences != list(range(1, len(sequences) + 1)):
        raise DemoSignalInputError("accepted chunk sequences are not contiguous from 1")
    if len(sequences) != len(set(sequences)):
        raise DemoSignalInputError("accepted chunk sequences are not unique")
    chunks = tuple(item[0] for item in accepted)
    chunk_ids = [chunk.chunk_id for chunk in chunks]
    if len(chunk_ids) != len(set(chunk_ids)):
        raise DemoSignalInputError("accepted chunk IDs are not unique")
    partitions = {
        (
            chunk.partition.host_id,
            chunk.partition.source,
            chunk.partition.source_channel,
        )
        for chunk in chunks
    }
    if len(partitions) > 1:
        raise DemoSignalInputError("accepted EventChunks span more than one partition")
    last_accepted_at = max((item[1] for item in accepted), default=None)
    return chunks, last_accepted_at


def _unique_events(chunks: tuple[R1EventChunk, ...]) -> tuple[NormalizedEvent, ...]:
    by_id: dict[str, NormalizedEvent] = {}
    for chunk in chunks:
        for event in chunk.events:
            existing = by_id.get(event.event_id)
            if existing is not None and existing != event:
                raise DemoSignalInputError("an Event identity has conflicting accepted content")
            by_id[event.event_id] = event
    return tuple(sorted(by_id.values(), key=lambda event: (event.timestamp, event.event_id)))


def _find_candidates(
    *,
    events: tuple[NormalizedEvent, ...],
    policy: ApprovedLineagePolicy,
    destination_ip: str,
    destination_port: int,
) -> tuple[_Candidate, ...]:
    root_name = policy.approved_lineage[0].casefold()
    anchors = tuple(
        event
        for event in events
        if event.event_type == "process_create"
        and event.process is not None
        and event.process.name is not None
        and event.process.name.casefold() == root_name
    )
    process_events = tuple(event for event in events if event.event_type == "process_create")
    network_events = tuple(
        event
        for event in events
        if event.event_type == "network_connection"
        and event.network is not None
        and event.network.protocol is not None
        and event.network.protocol.casefold() == "tcp"
        and event.network.dst_ip == destination_ip
        and event.network.dst_port == destination_port
    )
    candidates: list[_Candidate] = []
    identities: set[tuple[str, str]] = set()
    for network_event in network_events:
        network_guid = _process_guid(network_event)
        if network_guid is None:
            continue
        terminals = tuple(event for event in process_events if _process_guid(event) == network_guid)
        if len(terminals) != 1:
            continue
        terminal = terminals[0]
        if not extract_remote_process_network_follow_on(terminal, network_event):
            continue
        for anchor in anchors:
            lineage = _lineage(events, anchor=anchor, terminal=terminal)
            if lineage is None:
                continue
            result = extract_remote_session_process_lineage_deviation_with_diagnostics(
                events,
                anchor,
                terminal,
                policy,
            )
            if result.diagnostics:
                continue
            identity = (terminal.event_id, network_event.event_id)
            if identity in identities:
                continue
            identities.add(identity)
            candidates.append(
                _Candidate(
                    is_deviation=bool(result.evidences),
                    observed_lineage=tuple(
                        event.process.name for event in lineage if event.process is not None
                    ),
                    lineage_event_ids=tuple(event.event_id for event in lineage),
                    network_event=network_event,
                    source_event_ids=tuple(
                        event.source_event_id for event in (*lineage, network_event)
                    ),
                    terminal_process_guid=network_guid,
                )
            )
    return tuple(candidates)


def _process_identity_diagnostics(
    events: tuple[NormalizedEvent, ...],
) -> tuple[str, ...]:
    counts: dict[str, int] = {}
    for event in events:
        if event.event_type != "process_create":
            continue
        guid = _process_guid(event)
        if guid is not None:
            counts[guid] = counts.get(guid, 0) + 1
    if any(count > 1 for count in counts.values()):
        return ("duplicate_process_guid",)
    return ()


def _lineage(
    events: tuple[NormalizedEvent, ...],
    *,
    anchor: NormalizedEvent,
    terminal: NormalizedEvent,
) -> tuple[NormalizedEvent, ...] | None:
    process_events = tuple(event for event in events if event.event_type == "process_create")
    by_guid: dict[str, list[NormalizedEvent]] = {}
    for event in process_events:
        guid = _process_guid(event)
        if guid is not None:
            by_guid.setdefault(guid, []).append(event)
    anchor_guid = _process_guid(anchor)
    current = terminal
    lineage = [terminal]
    seen: set[str] = set()
    while True:
        current_guid = _process_guid(current)
        if current_guid is None or current_guid in seen:
            return None
        seen.add(current_guid)
        if current_guid == anchor_guid:
            return tuple(reversed(lineage))
        if current.process is None or current.process.parent_process_guid is None:
            return None
        parents = by_guid.get(current.process.parent_process_guid, [])
        if len(parents) != 1 or parents[0].timestamp > current.timestamp:
            return None
        current = parents[0]
        lineage.append(current)


# Six replace attempts, at most five requested sleeps totalling 155 milliseconds.
# Keep this well below the default one-second watch interval.
_SNAPSHOT_RETRY_DELAYS = (0.005, 0.01, 0.02, 0.04, 0.08)


class DemoSignalPublicationError(PermissionError):
    """Bounded publication failed; retain the original exception without printing paths."""

    def __init__(self, attempts: int, original_error: PermissionError) -> None:
        winerror = getattr(original_error, "winerror", None)
        super().__init__(
            original_error.errno,
            f"Snapshot atomic publication failed after {attempts} attempts (winerror={winerror})",
        )
        self.attempts = attempts
        self.winerror = winerror
        self.original_error = original_error


def _windows_replace_access_allows_retry(path: Path) -> bool:
    """Recognize sharing, including a lock already released, without retrying ACL denial."""
    import ctypes
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    attributes = kernel.GetFileAttributesW
    attributes.argtypes = [wintypes.LPCWSTR]
    attributes.restype = wintypes.DWORD
    flags = attributes(str(path))
    if flags == 0xFFFFFFFF or flags & (1 | 16):  # Missing, read-only, or a directory.
        return False
    create = kernel.CreateFileW
    create.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create.restype = wintypes.HANDLE
    close = kernel.CloseHandle
    close.argtypes = [wintypes.HANDLE]
    close.restype = wintypes.BOOL
    # DELETE, FILE_SHARE_READ|WRITE|DELETE, OPEN_EXISTING. No DELETE_ON_CLOSE flag.
    handle = create(str(path), 0x00010000, 7, None, 3, 0, None)
    if handle == wintypes.HANDLE(-1).value:
        return ctypes.get_last_error() in {32, 33}
    close(handle)
    # A short reader may have closed between os.replace's failure and this probe.
    # DELETE access is now allowed; retry that recovered race rather than stopping watch.
    return True


def _is_windows_sharing_violation(error: PermissionError, path: Path) -> bool:
    code = getattr(error, "winerror", None)
    if code in {32, 33}:
        return True
    # MoveFileEx/os.replace can report ACCESS_DENIED for an open destination.
    # Require native sharing or restored DELETE access, excluding read-only/ACL denial.
    return code == 5 and os.name == "nt" and _windows_replace_access_allows_retry(path)


def write_demo_signal(path: Path, signal: R1LocalDemoSignal) -> None:
    """Atomically publish once, retrying only bounded Windows sharing conflicts."""

    path.parent.mkdir(parents=True, exist_ok=True)
    payload = signal.model_dump_json(by_alias=True, exclude_none=False).encode("utf-8") + b"\n"
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        temporary.write_bytes(payload)
        for attempt in range(len(_SNAPSHOT_RETRY_DELAYS) + 1):
            try:
                os.replace(temporary, path)
                return
            except PermissionError as error:
                if not _is_windows_sharing_violation(error, path):
                    raise
                if attempt == len(_SNAPSHOT_RETRY_DELAYS):
                    # Keep the original exception for inspection, but suppress its path in logs.
                    raise DemoSignalPublicationError(attempt + 1, error) from None
                time.sleep(_SNAPSHOT_RETRY_DELAYS[attempt])
    finally:
        temporary.unlink(missing_ok=True)


def _policy_identity(policy: ApprovedLineagePolicy) -> DemoPolicyIdentity:
    if policy.lifecycle is None:
        raise DemoSignalInputError("demo policy must have an explicit lifecycle")
    return DemoPolicyIdentity(
        policy_id=policy.policy_id,
        version=policy.version,
        config_hash=policy.config_hash,
        lifecycle=policy.lifecycle,
        approved_lineage=policy.approved_lineage,
    )


def _process_guid(event: NormalizedEvent) -> str | None:
    return None if event.process is None else event.process.process_guid


def _parse_utc(value: object) -> datetime:
    if not isinstance(value, str):
        raise DemoSignalInputError("Role3 ack accepted_at must be a UTC timestamp")
    parsed = datetime.fromisoformat(value)
    return _utc_milliseconds(parsed)


def _utc_milliseconds(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise DemoSignalInputError("demo timestamps must be timezone-aware")
    utc = value.astimezone(UTC)
    return utc.replace(microsecond=(utc.microsecond // 1000) * 1000)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spool-root", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--destination-ip", required=True)
    parser.add_argument("--destination-port", type=int, default=8443)
    parser.add_argument("--output", required=True)
    parser.add_argument(
        "--policy-config", default=str(DEFAULT_R1_FAMILY_BOUND_APPROVED_LINEAGE_POLICIES_PATH)
    )
    parser.add_argument("--watch", action="store_true")
    parser.add_argument("--poll-seconds", type=float, default=1.0)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.poll_seconds <= 0:
        raise DemoSignalInputError("poll_seconds must be greater than zero")
    output_path = Path(args.output)
    while True:
        try:
            signal = build_demo_signal(
                spool_root=Path(args.spool_root),
                run_id=args.run_id,
                destination_ip=args.destination_ip,
                destination_port=args.destination_port,
                policy_config=Path(args.policy_config),
            )
        except Exception:
            output_path.unlink(missing_ok=True)
            raise
        write_demo_signal(output_path, signal)
        print(signal.model_dump_json(by_alias=True, exclude_none=False), flush=True)
        if not args.watch:
            return 0
        time.sleep(args.poll_seconds)


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "DemoSignalInputError",
    "DemoSignalPublicationError",
    "R1LocalDemoSignal",
    "build_demo_signal",
    "write_demo_signal",
]
