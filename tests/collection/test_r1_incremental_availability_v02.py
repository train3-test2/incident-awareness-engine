from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest
import test_r1_candidate_generation_seal as seal_fixture
import test_r1_role2_verified_close_proof as proof_fixture

import incident_awareness.pipeline.r1_incremental_availability as availability_module
import incident_awareness.pipeline.r1_incremental_checkpoint as checkpoint_module
import incident_awareness.pipeline.r1_incremental_evidence as incremental_evidence_module
from incident_awareness.collection.r1_role2_verified_close_proof import (
    role2_safe_source_seal_projection_sha256,
)
from incident_awareness.common.models.event import NormalizedEvent
from incident_awareness.common.models.r1_required_partition import (
    R1RequiredPartitionContract,
    load_r1_required_partition_contract,
)
from incident_awareness.common.models.r1_stream import R1EventChunk, R1StreamPartition
from incident_awareness.common.models.run import RunMetadata
from incident_awareness.decision.fusion.config import (
    FusionConfig,
    ReplayConfig,
    ScoringConfig,
    StoppingConfig,
    WindowConfig,
)
from incident_awareness.evidence.r1_approved_lineage_policy import (
    load_r1_approved_lineage_policy,
)
from incident_awareness.evidence.r1_multi_event import ApprovedLineagePolicy
from incident_awareness.evidence.r1_selector import R1SelectorPolicy
from incident_awareness.pipeline.r1_artifact_io import ceil_utc_clock_observation
from incident_awareness.pipeline.r1_causal_replay import (
    prepare_r1_incremental_causal_replay_input,
)
from incident_awareness.pipeline.r1_evidence import run_r1_evidence_pipeline_with_selector
from incident_awareness.pipeline.r1_incremental_availability import (
    build_r1_incremental_causal_availability_envelope,
    incremental_availability_envelope_sha256,
    load_r1_incremental_availability_publication_receipt,
    load_r1_incremental_causal_availability_envelope,
    write_r1_incremental_causal_availability_envelope,
)
from incident_awareness.pipeline.r1_incremental_checkpoint import (
    build_r1_incremental_checkpoint,
    load_r1_incremental_checkpoint,
    write_r1_incremental_checkpoint,
)
from incident_awareness.pipeline.r1_incremental_evidence import R1IncrementalEvidenceState
from incident_awareness.pipeline.r1_stream_ingress import R1StreamIngress
from incident_awareness.storage.repositories.r1_stream_delivery_repository import (
    R1AcceptedRunCloseReceipt,
    R1ChunkAdmission,
)

_RUN_ID = seal_fixture.RUN_ID
_HOST_ID = "R1-TGTA"
_RUN_START = datetime(2026, 10, 13, 1, 0, tzinfo=UTC)
_RUN_END = datetime(2026, 10, 13, 1, 14, tzinfo=UTC)
_PROOF_VALIDATED_AT = datetime(2026, 10, 13, 1, 13, 4, tzinfo=UTC)
_EVIDENCE_READY_AT = _PROOF_VALIDATED_AT + timedelta(seconds=2)
_PUBLICATION_COMPLETED_AT = _EVIDENCE_READY_AT + timedelta(seconds=3)
_INPUTS_VALIDATED_AT = _PUBLICATION_COMPLETED_AT + timedelta(seconds=2)
_ROOT_GUID = "{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}"
_MIDDLE_GUID = "{BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB}"
_TERMINAL_GUID = "{CCCCCCCC-CCCC-CCCC-CCCC-CCCCCCCCCCCC}"
_APPROVED_CONFIG_PATH = Path("configs/r1_approved_lineage_policies_v0.2.yaml")


class _Ledger:
    def __init__(self) -> None:
        self.chunks: dict[tuple[R1StreamPartition, str], tuple[int, str]] = {}
        self.events: dict[tuple[R1StreamPartition, str], str] = {}

    def inspect_chunk_admission(
        self, *, partition, chunk_id, sequence, content_sha256, event_content_sha256s
    ) -> R1ChunkAdmission:
        previous = self.chunks.get((partition, chunk_id))
        if previous is not None:
            if previous != (sequence, content_sha256):
                raise ValueError("chunk identity conflict")
            return R1ChunkAdmission(True, (), None)
        new_ids: list[str] = []
        for event_id, digest in event_content_sha256s:
            previous_digest = self.events.get((partition, event_id))
            if previous_digest is None:
                new_ids.append(event_id)
            elif previous_digest != digest:
                raise ValueError("Event identity conflict")
        return R1ChunkAdmission(False, tuple(new_ids), None)

    def save_events(self, *, partition, event_content_sha256s) -> tuple[str, ...]:
        new_ids: list[str] = []
        for event_id, digest in event_content_sha256s:
            if (partition, event_id) not in self.events:
                self.events[partition, event_id] = digest
                new_ids.append(event_id)
        return tuple(new_ids)

    def save_chunk(self, *, partition, chunk_id, sequence, content_sha256) -> bool:
        self.chunks[partition, chunk_id] = (sequence, content_sha256)
        return True


class _DeadLetterSink:
    def write(self, _message) -> None:
        raise AssertionError("valid incremental input must not be dead-lettered")


def _ingress(ledger: _Ledger | None = None) -> R1StreamIngress:
    return R1StreamIngress(
        ledger or _Ledger(),  # type: ignore[arg-type]
        dead_letter_sink=_DeadLetterSink(),
        clock=lambda: _RUN_END,
    )


def _selector_policy() -> R1SelectorPolicy:
    return R1SelectorPolicy(
        policy_id="r1-structural-lineage-selector",
        version="v0.1",
        config_hash="669520854868ae24182f502a2c118e66fce9a0fc464283232990182fa848072d",
        lineage_event_count=3,
    )


def _approved_policy() -> ApprovedLineagePolicy:
    return load_r1_approved_lineage_policy(
        "r1-wmi-management-approved-lineage",
        "v0.1",
        config_path=_APPROVED_CONFIG_PATH,
    )


def _required_contract() -> R1RequiredPartitionContract:
    return R1RequiredPartitionContract.model_validate(
        {
            "schema": "r1-required-partitions",
            "contract_version": "v0.1",
            "target_host": _HOST_ID,
            "required_partitions": [
                {
                    "source": "sysmon",
                    "source_channel": "Microsoft-Windows-Sysmon/Operational",
                }
            ],
        }
    )


def _event(
    event_id: str,
    event_type: str,
    timestamp: datetime,
    process_guid: str,
    *,
    parent_process_guid: str | None = None,
    process_name: str,
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
            "host_id": _HOST_ID,
            "source": "sysmon",
            "source_layer": "raw_telemetry",
            "source_event_id": f"record-{event_id}",
            "event_type": event_type,
            "raw_ref": {
                "raw_log_id": "RAW-R1-INCREMENTAL-V02",
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
                    "src_ip": "192.0.2.10",
                    "src_port": 50000,
                    "dst_ip": "192.0.2.20",
                    "dst_port": 8443,
                }
                if is_network
                else None
            ),
        }
    )


def _events(*, middle_name: str = "cmd.exe") -> tuple[NormalizedEvent, ...]:
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
            process_name=middle_name,
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


def _chunk(event: NormalizedEvent, sequence: int) -> R1EventChunk:
    payload: dict[str, object] = {
        "schema": "r1-incremental-stream",
        "contract_version": "v0.1",
        "message_type": "event_chunk",
        "chunk_id": f"CHK-{sequence:03d}",
        "partition": {
            "run_id": _RUN_ID,
            "host_id": _HOST_ID,
            "source": "sysmon",
            "source_channel": "Microsoft-Windows-Sysmon/Operational",
        },
        "chunk_sequence": sequence,
        "chunk_content_sha256": "0" * 64,
        "event_contract_version": "v0.3",
        "events": [event.model_dump(mode="json")],
    }
    chunk = R1EventChunk.model_validate(payload)
    canonical = chunk.model_dump(mode="json", by_alias=True)
    del canonical["chunk_content_sha256"]
    digest = hashlib.sha256(
        json.dumps(canonical, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return chunk.model_copy(update={"chunk_content_sha256": digest})


def _state(
    *,
    middle_name: str = "cmd.exe",
    reverse: bool = False,
    evidence_ready_at: datetime | None = _EVIDENCE_READY_AT,
):
    selector = _selector_policy()
    approved = _approved_policy()
    candidate = seal_fixture._policy()
    state = R1IncrementalEvidenceState(
        run_id=_RUN_ID,
        entity_id=_HOST_ID,
        run_start=_RUN_START,
        scenario_family_id="wmi_management",
        selector_policy=selector,
        approved_policy=approved,
        ingress=_ingress(),
        required_partition_contract=_required_contract(),
        clock=None if evidence_ready_at is None else lambda: evidence_ready_at,
    )
    events = _events(middle_name=middle_name)
    chunks = tuple(_chunk(event, index) for index, event in enumerate(events, start=1)) + (
        _chunk(events[0], 5),
    )
    for chunk in reversed(chunks) if reverse else chunks:
        state.accept_chunk(chunk)
    close = seal_fixture._run_closed()
    state.accept_run_closed(close)
    seal = seal_fixture._seal()
    receipt = proof_fixture._receipt(close)
    snapshot = state.accept_verified_close_proof(
        proof_fixture._proof(),
        accepted_run_closed=close,
        accepted_close_receipt=receipt,
        candidate_policy=candidate,
        accepted_source_seal_id=seal.seal_id,
        accepted_source_seal_projection_sha256=(
            role2_safe_source_seal_projection_sha256(seal, host_id=_HOST_ID)
        ),
        proof_validated_at=_PROOF_VALIDATED_AT,
    )
    return state, snapshot, selector, approved, candidate, receipt, seal


@pytest.mark.parametrize(
    ("observed", "expected"),
    [
        (
            datetime(2026, 10, 13, 1, 13, 6, 123456, tzinfo=UTC),
            datetime(2026, 10, 13, 1, 13, 6, 124000, tzinfo=UTC),
        ),
        (
            datetime(2026, 10, 13, 1, 13, 6, 999999, tzinfo=UTC),
            datetime(2026, 10, 13, 1, 13, 7, tzinfo=UTC),
        ),
        (
            datetime(2026, 10, 13, 1, 13, 6, 123000, tzinfo=UTC),
            datetime(2026, 10, 13, 1, 13, 6, 123000, tzinfo=UTC),
        ),
    ],
)
def test_internal_clock_observation_is_ceiled_to_utc_milliseconds(
    observed: datetime,
    expected: datetime,
) -> None:
    actual = ceil_utc_clock_observation("observed_at", observed)

    assert actual == expected
    assert actual >= observed


@pytest.mark.parametrize(
    "observed",
    [
        _RUN_START.replace(tzinfo=None),
        datetime(2026, 10, 13, 10, 13, 6, tzinfo=timezone(timedelta(hours=9))),
    ],
)
def test_internal_clock_observation_does_not_normalize_invalid_time(
    observed: datetime,
) -> None:
    with pytest.raises(ValueError):
        ceil_utc_clock_observation("observed_at", observed)


def test_default_evidence_clock_is_ceiled_before_verified_close_finalization(monkeypatch) -> None:
    observed = _EVIDENCE_READY_AT + timedelta(microseconds=123456)
    expected = _EVIDENCE_READY_AT + timedelta(microseconds=124000)
    monkeypatch.setattr(incremental_evidence_module, "utc_now", lambda: observed)

    _, snapshot, *_ = _state(evidence_ready_at=None)

    assert snapshot.status == "finalized"
    assert snapshot.available_at == expected


def test_default_publication_clock_is_ceiled_after_immutable_publish(
    tmp_path: Path,
    monkeypatch,
) -> None:
    state, snapshot, selector, approved, candidate, *_ = _state()
    envelope = build_r1_incremental_causal_availability_envelope(
        snapshot,
        state.export_checkpoint(),
        run_metadata=_run_metadata(),
        selector_policy=selector,
        approved_policy=approved,
        candidate_policy=candidate,
    )
    observed = _PUBLICATION_COMPLETED_AT + timedelta(microseconds=999999)
    expected = _PUBLICATION_COMPLETED_AT + timedelta(seconds=1)
    monkeypatch.setattr(availability_module, "utc_now", lambda: observed)

    receipt = write_r1_incremental_causal_availability_envelope(
        tmp_path / "availability.json",
        envelope,
    )

    assert receipt.publication_completed_at == expected
    assert receipt.publication_completed_at >= observed


def _run_metadata(*, run_type: str = "attack") -> RunMetadata:
    payload = seal_fixture._metadata(run_type=run_type).model_dump(mode="python")
    payload["end_time"] = _RUN_END
    return RunMetadata.model_validate(payload)


def _config() -> FusionConfig:
    return FusionConfig(
        config_version="r1-incremental-v02-test",
        model_version=None,
        window=WindowConfig(window_size_sec=900),
        replay=ReplayConfig(step_size_sec=10),
        scoring=ScoringConfig(
            method="simple_score",
            scorer_version="simple-score-v0.1",
            profile_id="r1-incremental-v02-test",
            evidence_types=(
                "remote_session_process_lineage_deviation",
                "remote_process_network_follow_on",
            ),
        ),
        stopping=StoppingConfig(threshold_on=0.8, threshold_off=0.4, persistence_k=1),
    )


def test_verified_close_builds_persistent_v02_availability_and_causal_replay(
    tmp_path: Path,
) -> None:
    state, snapshot, selector, approved, candidate, receipt, seal = _state()
    checkpoint = state.export_checkpoint()
    checkpoint_path = tmp_path / "r1_incremental_checkpoint.json"
    envelope_path = tmp_path / "r1_incremental_availability_v0.2.json"
    input_validation_path = tmp_path / "r1_incremental_replay_input_validation.json"

    write_r1_incremental_checkpoint(checkpoint_path, checkpoint)
    loaded_checkpoint = load_r1_incremental_checkpoint(checkpoint_path)
    envelope = build_r1_incremental_causal_availability_envelope(
        snapshot,
        loaded_checkpoint,
        run_metadata=_run_metadata(),
        selector_policy=selector,
        approved_policy=approved,
        candidate_policy=candidate,
    )
    publication_receipt = write_r1_incremental_causal_availability_envelope(
        envelope_path,
        envelope,
        clock=lambda: _PUBLICATION_COMPLETED_AT,
    )
    loaded_publication_receipt = load_r1_incremental_availability_publication_receipt(
        envelope_path.with_name(f"{envelope_path.name}.publication.json")
    )
    loaded_envelope = load_r1_incremental_causal_availability_envelope(envelope_path)
    replay_input = prepare_r1_incremental_causal_replay_input(
        snapshot,
        loaded_envelope,
        loaded_checkpoint,
        loaded_publication_receipt,
        input_validation_path=input_validation_path,
        run_metadata=_run_metadata(),
        selector_policy=selector,
        approved_policy=approved,
        candidate_policy=candidate,
        clock=lambda: _INPUTS_VALIDATED_AT,
    )
    replay = (
        _config()
        .build_runner()
        .run_causal(
            replay_input.scheduled_evidences,
            run_id=_RUN_ID,
            entity_id=_HOST_ID,
            run_start=_RUN_START,
            run_end=_RUN_END,
        )
    )
    restored = R1IncrementalEvidenceState.restore_from_checkpoint(
        loaded_checkpoint,
        selector_policy=selector,
        approved_policy=approved,
        ingress=_ingress(),
        candidate_policy=candidate,
        accepted_close_receipt=receipt,
        accepted_source_seal_id=seal.seal_id,
        accepted_source_seal_projection_sha256=(
            role2_safe_source_seal_projection_sha256(seal, host_id=_HOST_ID)
        ),
    )
    whole_episode = run_r1_evidence_pipeline_with_selector(
        _events(),
        selector_policy=selector,
        approved_policy=approved,
        run_start=_RUN_START,
    )

    assert snapshot.status == "finalized"
    assert snapshot.availability_contract_version == "v0.2"
    assert snapshot.available_at == _EVIDENCE_READY_AT < _RUN_END
    assert len(snapshot.evidences) == 2
    assert snapshot.evidences == whole_episode.evidences
    assert snapshot.lineage_input == whole_episode.lineage_input
    assert {item.evidence_type for item in snapshot.evidences} == {
        "remote_session_process_lineage_deviation",
        "remote_process_network_follow_on",
    }
    assert loaded_checkpoint == checkpoint
    assert loaded_envelope == envelope
    assert loaded_publication_receipt == publication_receipt
    assert loaded_envelope.frontier.proof_validated_at == _PROOF_VALIDATED_AT
    assert loaded_envelope.frontier.evidence_ready_at == _EVIDENCE_READY_AT
    assert loaded_checkpoint.available_at == _EVIDENCE_READY_AT
    assert input_validation_path.exists()
    assert replay_input.incremental_input_validation is not None
    assert replay_input.incremental_input_validation.inputs_validated_at == _INPUTS_VALIDATED_AT
    assert hashlib.sha256(envelope_path.read_bytes()).hexdigest() == (
        incremental_availability_envelope_sha256(envelope)
    )
    assert restored.snapshot == snapshot
    assert all(
        item.available_at == _INPUTS_VALIDATED_AT for item in replay_input.scheduled_evidences
    )
    assert all(
        point.score == 0 for point in replay.trajectory if point.timestamp < _INPUTS_VALIDATED_AT
    )
    assert any(
        point.score > 0 for point in replay.trajectory if point.timestamp >= _INPUTS_VALIDATED_AT
    )
    assert (
        state.accept_verified_close_proof(
            proof_fixture._proof(),
            accepted_run_closed=seal_fixture._run_closed(),
            accepted_close_receipt=receipt,
            candidate_policy=candidate,
            accepted_source_seal_id=seal.seal_id,
            accepted_source_seal_projection_sha256=(
                role2_safe_source_seal_projection_sha256(seal, host_id=_HOST_ID)
            ),
            proof_validated_at=_PROOF_VALIDATED_AT,
        )
        == snapshot
    )
    with pytest.raises(ValueError, match="replay trusted binding"):
        state.accept_verified_close_proof(
            proof_fixture._proof(),
            accepted_run_closed=seal_fixture._run_closed(),
            accepted_close_receipt=R1AcceptedRunCloseReceipt(
                run_id=_RUN_ID,
                close_id=receipt.close_id,
                content_sha256="0" * 64,
            ),
            candidate_policy=candidate,
            accepted_source_seal_id=seal.seal_id,
            accepted_source_seal_projection_sha256=(
                role2_safe_source_seal_projection_sha256(seal, host_id=_HOST_ID)
            ),
            proof_validated_at=_PROOF_VALIDATED_AT,
        )
    assert (
        write_r1_incremental_causal_availability_envelope(
            envelope_path,
            envelope,
            clock=lambda: _RUN_END,
        )
        == publication_receipt
    )
    restarted_replay_input = prepare_r1_incremental_causal_replay_input(
        snapshot,
        loaded_envelope,
        loaded_checkpoint,
        loaded_publication_receipt,
        input_validation_path=input_validation_path,
        run_metadata=_run_metadata(),
        selector_policy=selector,
        approved_policy=approved,
        candidate_policy=candidate,
        clock=lambda: _RUN_END,
    )
    assert restarted_replay_input == replay_input
    tampered = loaded_envelope.model_copy(update={"source_state_checkpoint_sha256": "0" * 64})
    with pytest.raises(ValueError, match="does not match trusted inputs"):
        prepare_r1_incremental_causal_replay_input(
            snapshot,
            tampered,
            loaded_checkpoint,
            loaded_publication_receipt,
            input_validation_path=tmp_path / "unused-validation.json",
            run_metadata=_run_metadata(),
            selector_policy=selector,
            approved_policy=approved,
            candidate_policy=candidate,
        )


def test_replay_availability_is_observed_after_receipt_publication_and_validation(
    tmp_path: Path,
    monkeypatch,
) -> None:
    state, snapshot, selector, approved, candidate, *_ = _state()
    checkpoint = state.export_checkpoint()
    envelope = build_r1_incremental_causal_availability_envelope(
        snapshot,
        checkpoint,
        run_metadata=_run_metadata(),
        selector_policy=selector,
        approved_policy=approved,
        candidate_policy=candidate,
    )
    envelope_path = tmp_path / "availability.json"
    receipt_path = envelope_path.with_name(f"{envelope_path.name}.publication.json")
    receipt_published_at = _PUBLICATION_COMPLETED_AT + timedelta(seconds=1)
    original_publish = availability_module._publish_immutable_bytes
    publication_events: list[datetime] = []

    def publish_with_receipt_delay(path: Path, content: bytes) -> None:
        is_receipt = path == receipt_path
        if is_receipt:
            assert envelope_path.exists()
            assert not receipt_path.exists()
            with pytest.raises(ValueError, match="publication receipt is invalid"):
                load_r1_incremental_availability_publication_receipt(receipt_path)
        original_publish(path, content)
        if is_receipt:
            publication_events.append(receipt_published_at)

    monkeypatch.setattr(
        availability_module,
        "_publish_immutable_bytes",
        publish_with_receipt_delay,
    )
    write_r1_incremental_causal_availability_envelope(
        envelope_path,
        envelope,
        clock=lambda: _PUBLICATION_COMPLETED_AT,
    )
    loaded_receipt = load_r1_incremental_availability_publication_receipt(receipt_path)

    replay_input = prepare_r1_incremental_causal_replay_input(
        snapshot,
        envelope,
        checkpoint,
        loaded_receipt,
        input_validation_path=tmp_path / "replay-input-validation.json",
        run_metadata=_run_metadata(),
        selector_policy=selector,
        approved_policy=approved,
        candidate_policy=candidate,
        clock=lambda: _INPUTS_VALIDATED_AT,
    )

    assert publication_events == [receipt_published_at]
    assert loaded_receipt.publication_completed_at < receipt_published_at < _INPUTS_VALIDATED_AT
    assert all(
        item.available_at == _INPUTS_VALIDATED_AT for item in replay_input.scheduled_evidences
    )
    assert all(
        item.available_at >= receipt_published_at for item in replay_input.scheduled_evidences
    )


def test_required_partition_loader_output_is_the_incremental_source_of_truth(
    tmp_path: Path,
) -> None:
    contract_path = tmp_path / "required-partitions.json"
    contract_path.write_text(
        json.dumps(_required_contract().model_dump(mode="json", by_alias=True)),
        encoding="utf-8",
    )
    contract = load_r1_required_partition_contract(
        contract_path,
        run_metadata=_run_metadata(),
    )

    state = R1IncrementalEvidenceState(
        run_id=_RUN_ID,
        entity_id=_HOST_ID,
        run_start=_RUN_START,
        scenario_family_id="wmi_management",
        selector_policy=_selector_policy(),
        approved_policy=_approved_policy(),
        ingress=_ingress(),
        required_partition_contract=contract,
    )

    assert state.export_checkpoint().required_partition_contract == contract


@pytest.mark.parametrize(("middle_name", "expected_count"), [("cmd.exe", 2), ("wscript.exe", 1)])
def test_attack_and_normal_inputs_share_the_verified_runtime_path_and_are_deterministic(
    middle_name: str,
    expected_count: int,
) -> None:
    ordered = _state(middle_name=middle_name)
    reversed_input = _state(middle_name=middle_name, reverse=True)

    assert ordered[1] == reversed_input[1]
    assert ordered[0].export_checkpoint() == reversed_input[0].export_checkpoint()
    assert len(ordered[1].evidences) == expected_count
    assert {item.available_at for item in ordered[1].availability} == {_EVIDENCE_READY_AT}


def test_runtime_availability_does_not_branch_on_attack_or_normal_label() -> None:
    state, snapshot, selector, approved, candidate, *_ = _state()
    checkpoint = state.export_checkpoint()

    attack = build_r1_incremental_causal_availability_envelope(
        snapshot,
        checkpoint,
        run_metadata=_run_metadata(run_type="attack"),
        selector_policy=selector,
        approved_policy=approved,
        candidate_policy=candidate,
    )
    normal = build_r1_incremental_causal_availability_envelope(
        snapshot,
        checkpoint,
        run_metadata=_run_metadata(run_type="normal"),
        selector_policy=selector,
        approved_policy=approved,
        candidate_policy=candidate,
    )

    assert attack == normal


def test_evidence_readiness_after_run_end_is_not_clipped_to_look_early() -> None:
    state, snapshot, selector, approved, candidate, *_ = _state(
        evidence_ready_at=_RUN_END + timedelta(microseconds=1)
    )

    assert snapshot.available_at == _RUN_END + timedelta(milliseconds=1)
    with pytest.raises(ValueError, match="Evidence readiness must be inside"):
        build_r1_incremental_causal_availability_envelope(
            snapshot,
            state.export_checkpoint(),
            run_metadata=_run_metadata(),
            selector_policy=selector,
            approved_policy=approved,
            candidate_policy=candidate,
        )


def test_snapshot_evidence_content_must_match_checkpoint_digest(tmp_path: Path) -> None:
    state, snapshot, selector, approved, candidate, *_ = _state()
    checkpoint = state.export_checkpoint()
    evidence = snapshot.evidences[0]
    tampered_evidence = evidence.model_copy(
        update={"features": {**evidence.features, "tampered": True}}
    )
    tampered_evidences = (tampered_evidence, *snapshot.evidences[1:])
    tampered_snapshot = replace(snapshot, evidences=tampered_evidences)
    payload = [
        item.model_dump(mode="json", by_alias=True)
        for item in sorted(tampered_evidences, key=lambda item: item.evidence_id)
    ]
    recomputed_evidence_hash = hashlib.sha256(
        json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    original_envelope = build_r1_incremental_causal_availability_envelope(
        snapshot,
        checkpoint,
        run_metadata=_run_metadata(),
        selector_policy=selector,
        approved_policy=approved,
        candidate_policy=candidate,
    )
    envelope = original_envelope.model_copy(
        update={"source_evidence_sha256": recomputed_evidence_hash}
    )
    assert incremental_availability_envelope_sha256(envelope) != (
        incremental_availability_envelope_sha256(original_envelope)
    )
    publication_receipt = write_r1_incremental_causal_availability_envelope(
        tmp_path / "availability.json",
        original_envelope,
        clock=lambda: _PUBLICATION_COMPLETED_AT,
    )

    with pytest.raises(ValueError, match="checkpoint digests"):
        prepare_r1_incremental_causal_replay_input(
            tampered_snapshot,
            envelope,
            checkpoint,
            publication_receipt,
            input_validation_path=tmp_path / "unused-validation.json",
            run_metadata=_run_metadata(),
            selector_policy=selector,
            approved_policy=approved,
            candidate_policy=candidate,
        )


@pytest.mark.parametrize(
    ("updates", "message"),
    [
        ({"status": "failed_closed"}, "finalized checkpoint"),
        ({"close_mode": "authoritative_run_end_fallback"}, "close_mode"),
        ({"evidence_digests": ()}, "checkpoint digests"),
    ],
)
def test_availability_rejects_invalid_checkpoint_output_binding(updates, message: str) -> None:
    state, snapshot, selector, approved, candidate, *_ = _state()
    payload = state.export_checkpoint().model_dump(mode="python", by_alias=True)
    payload.update(updates)
    checkpoint = build_r1_incremental_checkpoint(payload)

    with pytest.raises(ValueError, match=message):
        build_r1_incremental_causal_availability_envelope(
            snapshot,
            checkpoint,
            run_metadata=_run_metadata(),
            selector_policy=selector,
            approved_policy=approved,
            candidate_policy=candidate,
        )


def test_artifact_writers_sync_parent_after_publication(tmp_path: Path, monkeypatch) -> None:
    state, snapshot, selector, approved, candidate, *_ = _state()
    checkpoint = state.export_checkpoint()
    envelope = build_r1_incremental_causal_availability_envelope(
        snapshot,
        checkpoint,
        run_metadata=_run_metadata(),
        selector_policy=selector,
        approved_policy=approved,
        candidate_policy=candidate,
    )
    observed: list[Path] = []

    def assert_published(path: Path) -> None:
        assert path.exists()
        assert not tuple(path.parent.glob(f".{path.name}.*"))
        observed.append(path)

    monkeypatch.setattr(checkpoint_module, "fsync_parent_directory", assert_published)
    monkeypatch.setattr(availability_module, "fsync_parent_directory", assert_published)
    checkpoint_path = tmp_path / "checkpoint.json"
    envelope_path = tmp_path / "availability.json"

    write_r1_incremental_checkpoint(checkpoint_path, checkpoint)
    write_r1_incremental_causal_availability_envelope(envelope_path, envelope)

    assert observed == [
        checkpoint_path,
        envelope_path,
        envelope_path.with_name(f"{envelope_path.name}.publication.json"),
    ]


def test_directory_sync_io_failure_is_not_reported_as_success(tmp_path: Path, monkeypatch) -> None:
    state, snapshot, selector, approved, candidate, *_ = _state()
    checkpoint = state.export_checkpoint()
    envelope = build_r1_incremental_causal_availability_envelope(
        snapshot,
        checkpoint,
        run_metadata=_run_metadata(),
        selector_policy=selector,
        approved_policy=approved,
        candidate_policy=candidate,
    )

    def fail_sync(_path: Path) -> None:
        raise OSError("directory sync failed")

    monkeypatch.setattr(checkpoint_module, "fsync_parent_directory", fail_sync)
    monkeypatch.setattr(availability_module, "fsync_parent_directory", fail_sync)

    with pytest.raises(OSError, match="directory sync failed"):
        write_r1_incremental_checkpoint(tmp_path / "checkpoint.json", checkpoint)
    with pytest.raises(OSError, match="directory sync failed"):
        write_r1_incremental_causal_availability_envelope(
            tmp_path / "availability.json",
            envelope,
        )


def test_invalid_accepted_close_receipt_fails_closed_without_evidence() -> None:
    state = R1IncrementalEvidenceState(
        run_id=_RUN_ID,
        entity_id=_HOST_ID,
        run_start=_RUN_START,
        scenario_family_id="wmi_management",
        selector_policy=_selector_policy(),
        approved_policy=_approved_policy(),
        ingress=_ingress(),
        required_partition_contract=_required_contract(),
    )
    events = _events()
    for sequence, event in enumerate((*events, events[0]), start=1):
        state.accept_chunk(_chunk(event, sequence))
    close = seal_fixture._run_closed()
    state.accept_run_closed(close)
    seal = seal_fixture._seal()
    invalid_receipt = R1AcceptedRunCloseReceipt(
        run_id=_RUN_ID,
        close_id=close.close_id,
        content_sha256="0" * 64,
    )

    with pytest.raises(ValueError, match="receipt content hash"):
        state.accept_verified_close_proof(
            proof_fixture._proof(),
            accepted_run_closed=close,
            accepted_close_receipt=invalid_receipt,
            candidate_policy=seal_fixture._policy(),
            accepted_source_seal_id=seal.seal_id,
            accepted_source_seal_projection_sha256=(
                role2_safe_source_seal_projection_sha256(seal, host_id=_HOST_ID)
            ),
            proof_validated_at=_PROOF_VALIDATED_AT,
        )

    assert state.snapshot.status == "failed_closed"
    assert state.snapshot.evidences == state.snapshot.availability == ()
    restored = R1IncrementalEvidenceState.restore_from_checkpoint(
        state.export_checkpoint(),
        selector_policy=_selector_policy(),
        approved_policy=_approved_policy(),
        ingress=_ingress(),
    )
    assert restored.snapshot == state.snapshot


def test_verified_close_with_missing_covered_chunk_fails_closed() -> None:
    state = R1IncrementalEvidenceState(
        run_id=_RUN_ID,
        entity_id=_HOST_ID,
        run_start=_RUN_START,
        scenario_family_id="wmi_management",
        selector_policy=_selector_policy(),
        approved_policy=_approved_policy(),
        ingress=_ingress(),
        required_partition_contract=_required_contract(),
    )
    for sequence, event in enumerate(_events(), start=1):
        state.accept_chunk(_chunk(event, sequence))
    close = seal_fixture._run_closed()
    state.accept_run_closed(close)
    seal = seal_fixture._seal()

    failed = state.accept_verified_close_proof(
        proof_fixture._proof(),
        accepted_run_closed=close,
        accepted_close_receipt=proof_fixture._receipt(close),
        candidate_policy=seal_fixture._policy(),
        accepted_source_seal_id=seal.seal_id,
        accepted_source_seal_projection_sha256=(
            role2_safe_source_seal_projection_sha256(seal, host_id=_HOST_ID)
        ),
        proof_validated_at=_PROOF_VALIDATED_AT,
    )

    assert failed.status == "failed_closed"
    assert failed.evidences == failed.availability == ()
    assert any("missing" in item for item in failed.diagnostics)


@pytest.mark.parametrize("invalid_ingest_time", [None, _RUN_START.replace(tzinfo=None)])
def test_verified_close_fails_closed_for_missing_or_invalid_event_ingest_time(
    invalid_ingest_time: object,
) -> None:
    state = R1IncrementalEvidenceState(
        run_id=_RUN_ID,
        entity_id=_HOST_ID,
        run_start=_RUN_START,
        scenario_family_id="wmi_management",
        selector_policy=_selector_policy(),
        approved_policy=_approved_policy(),
        ingress=_ingress(),
        required_partition_contract=_required_contract(),
    )
    events = _events()
    for sequence, event in enumerate((*events, events[0]), start=1):
        chunk = _chunk(event, sequence)
        if sequence == 3:
            invalid_event = event.model_copy(update={"ingest_time": invalid_ingest_time})
            chunk = chunk.model_copy(update={"events": (invalid_event,)})
            payload = chunk.model_dump(mode="json", by_alias=True)
            del payload["chunk_content_sha256"]
            chunk = chunk.model_copy(
                update={
                    "chunk_content_sha256": hashlib.sha256(
                        json.dumps(
                            payload,
                            ensure_ascii=False,
                            sort_keys=True,
                            separators=(",", ":"),
                        ).encode()
                    ).hexdigest()
                }
            )
        state.accept_chunk(chunk)
    close = seal_fixture._run_closed()
    state.accept_run_closed(close)
    seal = seal_fixture._seal()

    with pytest.raises(ValueError, match="missing_or_invalid_ingest_time"):
        state.accept_verified_close_proof(
            proof_fixture._proof(),
            accepted_run_closed=close,
            accepted_close_receipt=proof_fixture._receipt(close),
            candidate_policy=seal_fixture._policy(),
            accepted_source_seal_id=seal.seal_id,
            accepted_source_seal_projection_sha256=(
                role2_safe_source_seal_projection_sha256(seal, host_id=_HOST_ID)
            ),
            proof_validated_at=_PROOF_VALIDATED_AT,
        )

    assert state.snapshot.status == "failed_closed"
    assert state.snapshot.evidences == state.snapshot.availability == ()
    assert any("missing_or_invalid_ingest_time" in item for item in state.snapshot.diagnostics)


def test_corrupted_checkpoint_is_rejected(tmp_path: Path) -> None:
    state, *_ = _state()
    checkpoint_path = tmp_path / "checkpoint.json"
    write_r1_incremental_checkpoint(checkpoint_path, state.export_checkpoint())
    payload = json.loads(checkpoint_path.read_text(encoding="utf-8"))
    payload["diagnostics"] = ["tampered"]
    checkpoint_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="invalid or corrupted"):
        load_r1_incremental_checkpoint(checkpoint_path)


def test_run_end_fallback_checkpoint_restores_without_v02_availability() -> None:
    state = R1IncrementalEvidenceState(
        run_id=_RUN_ID,
        entity_id=_HOST_ID,
        run_start=_RUN_START,
        scenario_family_id="wmi_management",
        selector_policy=_selector_policy(),
        approved_policy=_approved_policy(),
        ingress=_ingress(),
        required_partition_contract=_required_contract(),
    )
    events = _events()
    for sequence, event in enumerate((*events, events[0]), start=1):
        state.accept_chunk(_chunk(event, sequence))
    close = seal_fixture._run_closed()
    state.accept_run_closed(close)
    fallback = state.finalize_at_run_end(close.final_watermarks[0].watermark_at)

    restored = R1IncrementalEvidenceState.restore_from_checkpoint(
        state.export_checkpoint(),
        selector_policy=_selector_policy(),
        approved_policy=_approved_policy(),
        ingress=_ingress(),
    )

    assert fallback.availability_contract_version == "v0.1"
    assert fallback.close_mode == "authoritative_run_end_fallback"
    assert restored.snapshot == fallback
