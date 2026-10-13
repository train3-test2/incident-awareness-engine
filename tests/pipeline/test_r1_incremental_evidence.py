import hashlib
import inspect
import json
from datetime import UTC, datetime, timedelta

import pytest

from incident_awareness.collection.r1_candidate_generation_seal import (
    R1VerifiedCandidateBoundary,
)
from incident_awareness.common.models.event import NormalizedEvent
from incident_awareness.common.models.r1_stream import R1EventChunk, R1RunClosed
from incident_awareness.evidence.r1_multi_event import ApprovedLineagePolicy
from incident_awareness.evidence.r1_selector import R1SelectorPolicy
from incident_awareness.pipeline.r1_evidence import run_r1_evidence_pipeline_with_selector
from incident_awareness.pipeline.r1_incremental_evidence import R1IncrementalEvidenceState

_RUN_ID = "RUN-20261013-001"
_HOST_ID = "R1-TGTA"
_RUN_START = datetime(2026, 10, 13, 1, 0, tzinfo=UTC)
_BOUNDARY_AT = _RUN_START + timedelta(minutes=12)
_RUN_END = _RUN_START + timedelta(minutes=13)
_ROOT_GUID = "{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}"
_MIDDLE_GUID = "{BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB}"
_TERMINAL_GUID = "{CCCCCCCC-CCCC-CCCC-CCCC-CCCCCCCCCCCC}"


def _event(
    event_id: str,
    event_type: str,
    timestamp: datetime,
    process_guid: str,
    *,
    parent_process_guid: str | None = None,
    process_name: str = "powershell.exe",
    host_id: str = _HOST_ID,
) -> NormalizedEvent:
    is_network = event_type == "network_connection"
    return NormalizedEvent.model_validate(
        {
            "event_id": event_id,
            "run_id": _RUN_ID,
            "timestamp": timestamp,
            "timestamp_source": "event_time",
            "event_time": timestamp,
            "record_time": timestamp,
            "ingest_time": timestamp,
            "host_id": host_id,
            "source": "sysmon",
            "source_layer": "raw_telemetry",
            "source_event_id": f"record-{event_id}",
            "event_type": event_type,
            "raw_ref": {
                "raw_log_id": "RAW-R1-INCREMENTAL",
                "source_record_id": f"record-{event_id}",
                "segment_no": 1,
                "record_no": 2 if is_network else 1,
                "parser_id": "sysmon-normalizer",
                "parser_version": "v0.3",
            },
            "process": {
                "pid": 4200,
                "process_guid": process_guid,
                "name": process_name,
                "path": rf"C:\Windows\System32\{process_name}",
                "command_line": process_name,
                "parent_pid": None,
                "parent_process_guid": parent_process_guid,
                "parent_name": None,
            },
            "network": (
                {
                    "protocol": "tcp",
                    "src_ip": "192.168.34.20",
                    "src_port": 50000,
                    "dst_ip": "192.168.34.30",
                    "dst_port": 8443,
                }
                if is_network
                else None
            ),
        }
    )


def _events() -> tuple[NormalizedEvent, ...]:
    return (
        _event(
            "evt-context-root",
            "process_create",
            _RUN_START - timedelta(seconds=10),
            _ROOT_GUID,
            process_name="WmiPrvSE.exe",
        ),
        _event(
            "evt-middle",
            "process_create",
            _RUN_START,
            _MIDDLE_GUID,
            parent_process_guid=_ROOT_GUID,
            process_name="cmd.exe",
        ),
        _event(
            "evt-terminal",
            "process_create",
            _RUN_START + timedelta(minutes=5),
            _TERMINAL_GUID,
            parent_process_guid=_MIDDLE_GUID,
            process_name="powershell.exe",
        ),
        _event(
            "evt-network",
            "network_connection",
            _RUN_START + timedelta(minutes=8),
            _TERMINAL_GUID,
            process_name="powershell.exe",
        ),
    )


def _selector_policy() -> R1SelectorPolicy:
    return R1SelectorPolicy(
        policy_id="r1-structural-lineage-selector",
        version="v0.1",
        config_hash="669520854868ae24182f502a2c118e66fce9a0fc464283232990182fa848072d",
        lineage_event_count=3,
    )


def _approved_policy() -> ApprovedLineagePolicy:
    return ApprovedLineagePolicy(
        policy_id="r1-wmi-management-approved-lineage",
        version="v0.1",
        config_hash="f5ca732ab6987bbca9d2d44fa51eb30c0a13ba980545b4cbf7c64c7ccf2b5a9a",
        approved_lineage=("WmiPrvSE.exe", "wscript.exe", "powershell.exe"),
        family_id="wmi_management",
        lifecycle="development",
    )


def _state() -> R1IncrementalEvidenceState:
    return R1IncrementalEvidenceState(
        run_id=_RUN_ID,
        entity_id=_HOST_ID,
        run_start=_RUN_START,
        scenario_family_id="wmi_management",
        selector_policy=_selector_policy(),
        approved_policy=_approved_policy(),
    )


def _chunk(
    events: tuple[NormalizedEvent, ...],
    *,
    chunk_id: str,
    sequence: int,
    source_channel: str = "Microsoft-Windows-Sysmon/Operational",
) -> R1EventChunk:
    payload: dict[str, object] = {
        "schema": "r1-incremental-stream",
        "contract_version": "v0.1",
        "message_type": "event_chunk",
        "chunk_id": chunk_id,
        "partition": {
            "run_id": _RUN_ID,
            "host_id": events[0].host_id,
            "source": "sysmon",
            "source_channel": source_channel,
        },
        "chunk_sequence": sequence,
        "chunk_content_sha256": "0" * 64,
        "event_contract_version": "v0.3",
        "events": [event.model_dump(mode="json") for event in events],
    }
    chunk = R1EventChunk.model_validate(payload)
    canonical = chunk.model_dump(mode="json", by_alias=True)
    del canonical["chunk_content_sha256"]
    digest = hashlib.sha256(
        json.dumps(
            canonical,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    return chunk.model_copy(update={"chunk_content_sha256": digest})


def _run_closed(
    *,
    watermark_at: datetime = _RUN_END,
    covered_through_chunk_sequence: int = 2,
    emitted_at: datetime = _BOUNDARY_AT + timedelta(seconds=2),
) -> R1RunClosed:
    return R1RunClosed.model_validate(
        {
            "schema": "r1-incremental-stream",
            "contract_version": "v0.1",
            "message_type": "run_closed",
            "close_id": "CLOSE-001",
            "run_id": _RUN_ID,
            "final_watermarks": [
                {
                    "partition": {
                        "run_id": _RUN_ID,
                        "host_id": _HOST_ID,
                        "source": "sysmon",
                        "source_channel": "Microsoft-Windows-Sysmon/Operational",
                    },
                    "watermark_id": "WM-001",
                    "watermark_sequence": 2,
                    "watermark_at": watermark_at,
                    "allowed_lateness_ms": 30000,
                    "covered_through_chunk_sequence": covered_through_chunk_sequence,
                }
            ],
            "emitted_at": emitted_at,
        }
    )


def _verified_boundary(*, close_id: str = "CLOSE-001") -> R1VerifiedCandidateBoundary:
    return R1VerifiedCandidateBoundary(
        run_id=_RUN_ID,
        seal_id="SEAL-001",
        input_close_id=close_id,
        candidate_boundary_at=_BOUNDARY_AT,
        verified_seal_at=_BOUNDARY_AT + timedelta(seconds=3),
    )


def _accept_all_events(state: R1IncrementalEvidenceState) -> None:
    events = _events()
    state.accept_chunk(_chunk(events[:2], chunk_id="CHK-001", sequence=1))
    state.accept_chunk(_chunk(events[2:], chunk_id="CHK-002", sequence=2))


def test_constructor_exposes_no_ground_truth_or_label_input() -> None:
    names = set(inspect.signature(R1IncrementalEvidenceState).parameters)

    assert names.isdisjoint({"ground_truth", "run_type", "attack_label", "label"})


def test_constructor_requires_family_bound_policy_for_the_scenario_family() -> None:
    legacy = ApprovedLineagePolicy(
        policy_id="legacy",
        version="v0.1",
        config_hash="a" * 64,
        approved_lineage=("WmiPrvSE.exe", "wscript.exe", "powershell.exe"),
    )
    mismatch = ApprovedLineagePolicy(
        policy_id="other-family",
        version="v0.1",
        config_hash="b" * 64,
        approved_lineage=("WmiPrvSE.exe", "wscript.exe", "powershell.exe"),
        family_id="remote_management",
        lifecycle="development",
    )

    with pytest.raises(ValueError, match="legacy unbound"):
        R1IncrementalEvidenceState(
            run_id=_RUN_ID,
            entity_id=_HOST_ID,
            run_start=_RUN_START,
            scenario_family_id="wmi_management",
            selector_policy=_selector_policy(),
            approved_policy=legacy,
        )
    with pytest.raises(ValueError, match="does not match"):
        R1IncrementalEvidenceState(
            run_id=_RUN_ID,
            entity_id=_HOST_ID,
            run_start=_RUN_START,
            scenario_family_id="wmi_management",
            selector_policy=_selector_policy(),
            approved_policy=mismatch,
        )


def test_does_not_publish_evidence_before_close() -> None:
    state = _state()

    _accept_all_events(state)

    assert state.snapshot.status == "provisional"
    assert state.snapshot.selector_result.selection is not None
    assert state.snapshot.evidences == ()
    assert state.snapshot.availability == ()
    assert state.snapshot.available_at is None


def test_verified_close_is_disabled_until_role2_safe_proof_exists() -> None:
    state = _state()
    _accept_all_events(state)
    state.accept_run_closed(_run_closed())

    with pytest.raises(ValueError, match="Role2-safe verified close proof"):
        state.accept_verified_boundary(_verified_boundary())

    assert state.snapshot.status == "provisional"
    assert state.snapshot.evidences == ()


def test_fallback_requires_accepted_close_and_watermark_coverage() -> None:
    state = _state()
    _accept_all_events(state)

    with pytest.raises(ValueError, match="accepted run_closed"):
        state.finalize_at_run_end(_RUN_END)

    state.accept_run_closed(_run_closed(watermark_at=_RUN_END - timedelta(milliseconds=1)))
    with pytest.raises(ValueError, match="watermark must cover"):
        state.finalize_at_run_end(_RUN_END)


def test_fallback_replay_is_idempotent_and_conflicting_run_end_is_rejected() -> None:
    state = _state()
    _accept_all_events(state)
    state.accept_run_closed(_run_closed())

    first = state.finalize_at_run_end(_RUN_END)
    replay = state.finalize_at_run_end(_RUN_END)

    assert replay == first
    with pytest.raises(ValueError, match="different authoritative_run_end"):
        state.finalize_at_run_end(_RUN_END + timedelta(seconds=1))


def test_run_close_waits_for_covered_chunk_sequences_delivered_after_control() -> None:
    state = _state()
    events = _events()
    state.accept_chunk(_chunk(events[:2], chunk_id="CHK-001", sequence=1))

    pending = state.accept_run_closed(_run_closed())

    assert pending.status == "accumulating"
    assert pending.evidences == ()
    assert "covered chunk sequence is missing" in pending.diagnostics[0]

    completed = state.accept_chunk(_chunk(events[2:], chunk_id="CHK-002", sequence=2))
    result = state.finalize_at_run_end(_RUN_END)

    assert completed.status == "provisional"
    assert completed.diagnostics == ()
    assert result.status == "finalized"
    assert result.available_at == _RUN_END


def test_missing_covered_chunk_sequence_fails_closed_at_finalization() -> None:
    state = _state()
    state.accept_chunk(_chunk(_events()[:2], chunk_id="CHK-001", sequence=1))
    state.accept_run_closed(_run_closed())

    result = state.finalize_at_run_end(_RUN_END)

    assert result.status == "failed_closed"
    assert result.evidences == ()
    assert result.available_at == _RUN_END
    assert "covered chunk sequence is missing" in result.diagnostics[0]


def test_chunk_after_run_close_must_be_within_declared_partition_coverage() -> None:
    state = _state()
    events = _events()
    state.accept_chunk(_chunk(events[:2], chunk_id="CHK-001", sequence=1))
    state.accept_run_closed(_run_closed(covered_through_chunk_sequence=1))

    with pytest.raises(ValueError, match="exceeds run_closed coverage"):
        state.accept_chunk(_chunk(events[2:], chunk_id="CHK-002", sequence=2))


def test_chunk_after_run_close_rejects_an_unsealed_partition() -> None:
    state = _state()
    _accept_all_events(state)
    state.accept_run_closed(_run_closed())
    other_host = _event(
        "evt-target-b",
        "process_create",
        _RUN_START + timedelta(seconds=1),
        "{DDDDDDDD-DDDD-DDDD-DDDD-DDDDDDDDDDDD}",
        host_id="R1-TGTB",
    )

    with pytest.raises(ValueError, match="partition is not sealed"):
        state.accept_chunk(_chunk((other_host,), chunk_id="CHK-001", sequence=1))


def test_exact_chunk_replay_remains_idempotent_after_run_close() -> None:
    state = _state()
    chunk = _chunk(_events(), chunk_id="CHK-001", sequence=1)
    state.accept_chunk(chunk)
    closed = state.accept_run_closed(_run_closed(covered_through_chunk_sequence=1))

    assert state.accept_chunk(chunk) == closed


def test_later_candidate_invalidates_provisional_selection_until_close() -> None:
    state = _state()
    _accept_all_events(state)
    assert state.snapshot.status == "provisional"
    second_guid = "{FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF}"
    second_candidate = (
        _event(
            "evt-second-terminal",
            "process_create",
            _RUN_START + timedelta(minutes=6),
            second_guid,
            parent_process_guid=_MIDDLE_GUID,
            process_name="powershell.exe",
        ),
        _event(
            "evt-second-network",
            "network_connection",
            _RUN_START + timedelta(minutes=9),
            second_guid,
            process_name="powershell.exe",
        ),
    )

    updated = state.accept_chunk(_chunk(second_candidate, chunk_id="CHK-003", sequence=3))

    assert updated.status == "accumulating"
    assert updated.selector_result.diagnostics == ("ambiguous_terminal_candidate",)
    assert updated.evidences == ()


def test_run_end_fallback_matches_the_existing_whole_episode_pipeline() -> None:
    state = _state()
    _accept_all_events(state)
    state.accept_run_closed(_run_closed())

    incremental = state.finalize_at_run_end(_RUN_END)
    whole_episode = run_r1_evidence_pipeline_with_selector(
        _events(),
        selector_policy=_selector_policy(),
        approved_policy=_approved_policy(),
        run_start=_RUN_START,
    )

    assert incremental.status == "finalized"
    assert incremental.evidences == whole_episode.evidences
    assert incremental.selector_result == whole_episode.selector_result
    assert incremental.lineage_input == whole_episode.lineage_input
    assert incremental.extraction_diagnostics == whole_episode.extraction_diagnostics


def test_run_end_fallback_excludes_post_run_tail_from_the_whole_episode_window() -> None:
    state = _state()
    events = _events()
    tail_guid = "{EEEEEEEE-EEEE-EEEE-EEEE-EEEEEEEEEEEE}"
    post_run_tail = (
        _event(
            "evt-post-run-terminal",
            "process_create",
            _RUN_END + timedelta(seconds=1),
            tail_guid,
            parent_process_guid=_MIDDLE_GUID,
            process_name="powershell.exe",
        ),
        _event(
            "evt-post-run-network",
            "network_connection",
            _RUN_END + timedelta(seconds=2),
            tail_guid,
            process_name="powershell.exe",
        ),
    )
    state.accept_chunk(_chunk(events, chunk_id="CHK-001", sequence=1))
    state.accept_chunk(_chunk(post_run_tail, chunk_id="CHK-002", sequence=2))
    state.accept_run_closed(
        _run_closed(watermark_at=post_run_tail[-1].timestamp).model_copy(
            update={"emitted_at": post_run_tail[-1].timestamp + timedelta(milliseconds=1)}
        )
    )

    incremental = state.finalize_at_run_end(_RUN_END)
    same_window = run_r1_evidence_pipeline_with_selector(
        events,
        selector_policy=_selector_policy(),
        approved_policy=_approved_policy(),
        run_start=_RUN_START,
    )
    including_tail = run_r1_evidence_pipeline_with_selector(
        events + post_run_tail,
        selector_policy=_selector_policy(),
        approved_policy=_approved_policy(),
        run_start=_RUN_START,
    )

    assert incremental.status == "finalized"
    assert incremental.evidences == same_window.evidences
    assert incremental.selector_result == same_window.selector_result
    assert including_tail.selector_result.selection is None
    assert including_tail.selector_result.diagnostics == ("ambiguous_terminal_candidate",)


def test_exact_chunk_replay_is_idempotent_and_conflicting_identity_fails() -> None:
    state = _state()
    chunk = _chunk(_events()[:2], chunk_id="CHK-001", sequence=1)

    first = state.accept_chunk(chunk)
    replay = state.accept_chunk(chunk)
    conflicting = _chunk(_events()[2:], chunk_id="CHK-001", sequence=2)

    assert replay == first
    with pytest.raises(ValueError, match="chunk identity was reused"):
        state.accept_chunk(conflicting)


def test_rejects_chunk_when_declared_content_hash_is_wrong() -> None:
    state = _state()
    chunk = _chunk(_events()[:2], chunk_id="CHK-001", sequence=1).model_copy(
        update={"chunk_content_sha256": "f" * 64}
    )

    with pytest.raises(ValueError, match="chunk_content_sha256"):
        state.accept_chunk(chunk)


def test_rejects_reused_partition_sequence_with_another_chunk_identity() -> None:
    state = _state()
    state.accept_chunk(_chunk(_events()[:2], chunk_id="CHK-001", sequence=1))

    with pytest.raises(ValueError, match="chunk sequence was reused"):
        state.accept_chunk(_chunk(_events()[2:], chunk_id="CHK-OTHER", sequence=1))


def test_rejects_reused_event_identity_with_different_content() -> None:
    state = _state()
    original = _events()[1]
    conflicting = original.model_copy(
        update={
            "process": original.process.model_copy(update={"command_line": "cmd.exe /d /c exit"})
        }
    )
    state.accept_chunk(_chunk((original,), chunk_id="CHK-001", sequence=1))

    with pytest.raises(ValueError, match="Event identity was reused"):
        state.accept_chunk(_chunk((conflicting,), chunk_id="CHK-002", sequence=2))


def test_partition_scoped_chunk_and_event_identities_do_not_conflict() -> None:
    state = _state()
    target_a = _event(
        "evt-shared",
        "process_create",
        _RUN_START,
        _MIDDLE_GUID,
        parent_process_guid=_ROOT_GUID,
        process_name="cmd.exe",
    )
    target_b = _event(
        "evt-shared",
        "process_create",
        _RUN_START + timedelta(milliseconds=1),
        "{DDDDDDDD-DDDD-DDDD-DDDD-DDDDDDDDDDDD}",
        process_name="other.exe",
        host_id="R1-TGTB",
    )

    state.accept_chunk(_chunk((target_a,), chunk_id="CHK-SHARED", sequence=1))
    state.accept_chunk(_chunk((target_b,), chunk_id="CHK-SHARED", sequence=1))

    assert state.snapshot.status == "accumulating"


def test_accepted_partition_absent_from_run_close_fails_closed() -> None:
    state = _state()
    _accept_all_events(state)
    other_host = _event(
        "evt-target-b",
        "process_create",
        _RUN_START + timedelta(seconds=1),
        "{DDDDDDDD-DDDD-DDDD-DDDD-DDDDDDDDDDDD}",
        host_id="R1-TGTB",
    )
    state.accept_chunk(_chunk((other_host,), chunk_id="CHK-B-001", sequence=1))
    state.accept_run_closed(_run_closed())

    result = state.finalize_at_run_end(_RUN_END)

    assert result.status == "failed_closed"
    assert result.evidences == ()
    assert "accepted chunk partition is absent" in result.diagnostics[0]


def test_run_close_replay_is_idempotent_and_conflicting_close_fails() -> None:
    state = _state()
    close = _run_closed()

    first = state.accept_run_closed(close)

    assert state.accept_run_closed(close) == first
    with pytest.raises(ValueError, match="different run_closed"):
        state.accept_run_closed(close.model_copy(update={"close_id": "CLOSE-OTHER"}))


def test_fallback_availability_is_authoritative_run_end_not_close_emission() -> None:
    state = _state()
    _accept_all_events(state)
    state.accept_run_closed(_run_closed(emitted_at=_RUN_END + timedelta(seconds=30)))

    finalized = state.finalize_at_run_end(_RUN_END)

    assert finalized.status == "finalized"
    assert finalized.available_at == _RUN_END
    assert {item.available_at for item in finalized.availability} == {_RUN_END}


def test_final_close_fails_closed_when_lineage_is_incomplete() -> None:
    state = _state()
    state.accept_chunk(_chunk(_events()[2:], chunk_id="CHK-001", sequence=1))
    state.accept_run_closed(_run_closed(covered_through_chunk_sequence=1))

    result = state.finalize_at_run_end(_RUN_END)

    assert result.status == "failed_closed"
    assert result.evidences == ()
    assert "truncated_lineage" in result.diagnostics


def test_ignores_other_host_events_for_host_local_selection() -> None:
    state = _state()
    _accept_all_events(state)
    other_host_events = (
        _event(
            "evt-target-b-process",
            "process_create",
            _RUN_START + timedelta(seconds=2),
            "{EEEEEEEE-EEEE-EEEE-EEEE-EEEEEEEEEEEE}",
            host_id="R1-TGTB",
        ),
    )
    state.accept_chunk(_chunk(other_host_events, chunk_id="CHK-B-001", sequence=1))

    assert state.snapshot.status == "provisional"
    assert state.snapshot.selector_result.selection is not None
    assert state.snapshot.selector_result.selection.entity_id == _HOST_ID
