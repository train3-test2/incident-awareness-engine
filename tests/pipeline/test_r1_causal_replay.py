import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from incident_awareness.common.models.evidence import Evidence
from incident_awareness.common.models.run import RunMetadata, RunType, SchemaVersions
from incident_awareness.decision.fusion.config import (
    FusionConfig,
    ReplayConfig,
    ScoringConfig,
    StoppingConfig,
    WindowConfig,
)
from incident_awareness.evidence.r1_multi_event import ApprovedLineagePolicy
from incident_awareness.pipeline.r1_artifacts import (
    R1EvidenceArtifactRun,
    R1ExtractionSummary,
    R1LineageInputProvenance,
    R1SelectorProvenance,
)
from incident_awareness.pipeline.r1_causal_availability import (
    R1CausalAvailabilityEnvelope,
    R1CausalEvidenceAvailability,
    R1CausalPolicyIdentity,
)
from incident_awareness.pipeline.r1_causal_replay import (
    prepare_r1_causal_replay_input,
    run_and_write_r1_causal_replay,
    run_r1_causal_replay,
)
from incident_awareness.pipeline.r1_causal_replay_artifacts import (
    R1_CAUSAL_FUSION_RESULT_FILENAME,
    R1_CAUSAL_FUSION_STOPPING_TRACE_FILENAME,
    R1_CAUSAL_REPLAY_PROVENANCE_FILENAME,
    load_r1_causal_replay_artifacts,
    load_r1_causal_replay_provenance,
    serialize_r1_causal_replay_provenance,
    write_r1_causal_replay_provenance,
)

_RUN_ID = "RUN-20261012-001"
_HOST_ID = "TARGET-A"
_START = datetime(2026, 10, 12, 1, 0, tzinfo=UTC)
_END = _START + timedelta(seconds=35)
_EVIDENCE_HASH = "a" * 64
_SUMMARY_HASH = "b" * 64


def _evidence(
    evidence_id: str,
    *,
    timestamp: datetime,
    evidence_type: str,
    event_ids: list[str],
) -> Evidence:
    return Evidence(
        evidence_id=evidence_id,
        run_id=_RUN_ID,
        timestamp=timestamp,
        entity_id=_HOST_ID,
        evidence_type=evidence_type,
        event_ids=event_ids,
        derived_from_source_layer="raw_telemetry",
        feature_channel_group="fusion_feature",
        extractor_version="r1-multi-event-v0.1",
    )


def _evidences() -> tuple[Evidence, ...]:
    return (
        _evidence(
            "E-lineage",
            timestamp=_START + timedelta(seconds=20),
            evidence_type="remote_session_process_lineage_deviation",
            event_ids=["evt-anchor", "evt-middle", "evt-terminal"],
        ),
        _evidence(
            "E-network",
            timestamp=_START + timedelta(seconds=30),
            evidence_type="remote_process_network_follow_on",
            event_ids=["evt-terminal", "evt-network"],
        ),
    )


def _artifact_run(*, evidences: tuple[Evidence, ...] | None = None) -> R1EvidenceArtifactRun:
    loaded_evidences = evidences if evidences is not None else _evidences()
    summary = R1ExtractionSummary(
        run_id=_RUN_ID,
        extractor_version="r1-multi-event-v0.1",
        input_event_count=4,
        evidence_count=len(loaded_evidences),
        status="completed",
        telemetry_completeness="not_provided",
        lineage_inputs=(
            R1LineageInputProvenance(
                anchor_event_id="evt-anchor",
                terminal_event_id="evt-terminal",
                policy_id="approved-policy",
                policy_version="v0.3",
                policy_config_hash="approved-hash",
            ),
        ),
        warnings=(),
        diagnostics=(),
        error_type=None,
        error_message=None,
        evidence_artifact_sha256=_EVIDENCE_HASH,
        selector=R1SelectorProvenance(
            policy_id="selector-policy",
            version="v0.1",
            config_hash="selector-hash",
            status="selected",
            diagnostics=(),
        ),
    )
    return R1EvidenceArtifactRun(
        evidences=loaded_evidences,
        summary=summary,
        evidence_path=Path("r1_evidence.jsonl"),
        summary_path=Path("r1_extraction_summary.json"),
        summary_artifact_sha256=_SUMMARY_HASH,
    )


def _envelope(
    *,
    evidences: tuple[R1CausalEvidenceAvailability, ...] | None = None,
) -> R1CausalAvailabilityEnvelope:
    availability = evidences or tuple(
        R1CausalEvidenceAvailability(
            evidence_id=evidence.evidence_id,
            timestamp=evidence.timestamp,
            available_at=_END,
            event_ids=tuple(evidence.event_ids),
            context_event_ids=(),
        )
        for evidence in _evidences()
    )
    return R1CausalAvailabilityEnvelope(
        contract_version="v0.1",
        run_id=_RUN_ID,
        entity_id=_HOST_ID,
        run_start=_START,
        run_end=_END,
        watermark_at=_END,
        watermark_basis="authoritative_run_end",
        selector_policy_identity=R1CausalPolicyIdentity(
            policy_id="selector-policy",
            version="v0.1",
            config_hash="selector-hash",
        ),
        approved_policy_identity=R1CausalPolicyIdentity(
            policy_id="approved-policy",
            version="v0.3",
            config_hash="approved-hash",
        ),
        source_extractor_version="r1-multi-event-v0.1",
        source_evidence_count=len(availability),
        source_evidence_artifact_sha256=_EVIDENCE_HASH,
        source_extraction_summary_sha256=_SUMMARY_HASH,
        evidences=tuple(
            sorted(
                availability,
                key=lambda item: (item.available_at, item.timestamp, item.evidence_id),
            )
        ),
    )


def _metadata(
    *,
    run_type: RunType = RunType.ATTACK,
    family_id: str | None = "remote_management",
) -> RunMetadata:
    return RunMetadata(
        run_id=_RUN_ID,
        scenario_id="R1",
        run_type=run_type,
        target_host=_HOST_ID,
        start_time=_START,
        end_time=_END,
        family_id=family_id,
        schema_versions=SchemaVersions(
            run_metadata="v0.2",
            event="v0.3",
            evidence="v0.2",
            fast_hit="v0.1",
            detection_result="v0.2",
            fusion_result="v0.3",
            decision_result="v0.1",
            execution_record="v0.1",
            evaluation_input="v0.1",
        ),
    )


def _approved_policy(*, family_id: str = "remote_management") -> ApprovedLineagePolicy:
    return ApprovedLineagePolicy(
        policy_id="approved-policy",
        version="v0.3",
        config_hash="approved-hash",
        approved_lineage=("anchor.exe", "middle.exe", "terminal.exe"),
        family_id=family_id,
        lifecycle="frozen",
    )


def _config() -> FusionConfig:
    return FusionConfig(
        config_version="fusion-r1-causal-test-v0.1",
        model_version=None,
        window=WindowConfig(window_size_sec=60),
        replay=ReplayConfig(step_size_sec=10),
        scoring=ScoringConfig(
            method="simple_score",
            scorer_version="simple-score-v0.1",
            profile_id="r1-causal-test-v0.1",
            evidence_types=(
                "remote_session_process_lineage_deviation",
                "remote_process_network_follow_on",
            ),
        ),
        stopping=StoppingConfig(
            threshold_on=0.8,
            threshold_off=0.4,
            persistence_k=1,
        ),
    )


def test_strict_join_and_whole_episode_causal_replay() -> None:
    # Given
    artifact_run = _artifact_run()
    envelope = _envelope()

    # When
    result = run_r1_causal_replay(
        artifact_run,
        envelope,
        run_metadata=_metadata(),
        approved_policy=_approved_policy(),
        config=_config(),
        execution_commit="4ee119069b33470a1cd4a34626f1a1d0a88c4662",
    )

    # Then
    assert [point.score for point in result.replay_result.trajectory] == [0, 0, 0, 0, 1]
    assert result.fusion_result.fusion_time == _END
    assert result.fusion_result.contributing_evidence_ids == ["E-lineage", "E-network"]
    assert result.provenance.terminal_partial_tick is True
    assert result.provenance.evaluated_replay_points[-1] == _END


def test_runtime_does_not_branch_on_attack_or_normal_label() -> None:
    # Given
    artifact_run = _artifact_run()
    envelope = _envelope()

    # When
    attack = run_r1_causal_replay(
        artifact_run,
        envelope,
        run_metadata=_metadata(run_type=RunType.ATTACK),
        approved_policy=_approved_policy(),
        config=_config(),
        execution_commit="4ee119069b33470a1cd4a34626f1a1d0a88c4662",
    )
    normal = run_r1_causal_replay(
        artifact_run,
        envelope,
        run_metadata=_metadata(run_type=RunType.NORMAL),
        approved_policy=_approved_policy(),
        config=_config(),
        execution_commit="4ee119069b33470a1cd4a34626f1a1d0a88c4662",
    )

    # Then
    assert normal.replay_result == attack.replay_result
    assert normal.fusion_result == attack.fusion_result


def test_join_uses_canonical_availability_timestamp_id_order() -> None:
    # Given
    same_time_evidences = tuple(
        evidence.model_copy(update={"timestamp": _START + timedelta(seconds=20)})
        for evidence in reversed(_evidences())
    )
    artifact_run = _artifact_run(evidences=same_time_evidences)
    availability = tuple(
        R1CausalEvidenceAvailability(
            evidence_id=evidence.evidence_id,
            timestamp=evidence.timestamp,
            available_at=_END,
            event_ids=tuple(evidence.event_ids),
        )
        for evidence in same_time_evidences
    )

    # When
    causal_input = prepare_r1_causal_replay_input(
        artifact_run,
        _envelope(evidences=availability),
        run_metadata=_metadata(),
        approved_policy=_approved_policy(),
    )

    # Then
    assert [item.evidence.evidence_id for item in causal_input.scheduled_evidences] == [
        "E-lineage",
        "E-network",
    ]


@pytest.mark.parametrize(
    "invalid_envelope",
    [
        lambda value: value.model_copy(
            update={"evidences": value.evidences[:-1], "source_evidence_count": 1}
        ),
        lambda value: value.model_copy(
            update={"evidences": (*value.evidences, value.evidences[0]), "source_evidence_count": 3}
        ),
        lambda value: value.model_copy(update={"source_evidence_artifact_sha256": "c" * 64}),
        lambda value: value.model_copy(update={"source_extraction_summary_sha256": "c" * 64}),
        lambda value: value.model_copy(
            update={
                "approved_policy_identity": value.approved_policy_identity.model_copy(
                    update={"config_hash": "different"}
                )
            }
        ),
        lambda value: value.model_copy(
            update={
                "selector_policy_identity": value.selector_policy_identity.model_copy(
                    update={"config_hash": "different"}
                )
            }
        ),
        lambda value: value.model_copy(update={"run_id": "RUN-20261012-OTHER"}),
        lambda value: value.model_copy(update={"entity_id": "TARGET-B"}),
    ],
)
def test_strict_join_rejects_invalid_envelope(invalid_envelope) -> None:
    # Given
    invalid = invalid_envelope(_envelope())

    # When
    with pytest.raises(ValueError) as error_info:
        prepare_r1_causal_replay_input(
            _artifact_run(),
            invalid,
            run_metadata=_metadata(),
            approved_policy=_approved_policy(),
        )

    # Then
    assert str(error_info.value)


def test_strict_join_rejects_timestamp_mismatch() -> None:
    # Given
    first = _envelope().evidences[0]
    timestamp_mismatch = first.model_copy(
        update={"timestamp": first.timestamp + timedelta(seconds=1)}
    )

    # When
    with pytest.raises(ValueError, match="timestamp") as error_info:
        prepare_r1_causal_replay_input(
            _artifact_run(),
            _envelope(evidences=(timestamp_mismatch, _envelope().evidences[1])),
            run_metadata=_metadata(),
            approved_policy=_approved_policy(),
        )

    # Then
    assert "timestamp" in str(error_info.value)


def test_strict_join_rejects_event_id_mismatch() -> None:
    # Given
    first = _envelope().evidences[0]
    event_ids_mismatch = first.model_copy(update={"event_ids": ("different-event",)})

    # When
    with pytest.raises(ValueError, match="event_ids") as error_info:
        prepare_r1_causal_replay_input(
            _artifact_run(),
            _envelope(evidences=(event_ids_mismatch, _envelope().evidences[1])),
            run_metadata=_metadata(),
            approved_policy=_approved_policy(),
        )

    # Then
    assert "event_ids" in str(error_info.value)


def test_strict_join_rejects_duplicate_loaded_evidence_id() -> None:
    # Given
    duplicated = (_evidences()[0], _evidences()[0])

    # When
    with pytest.raises(ValueError, match="unique") as error_info:
        prepare_r1_causal_replay_input(
            _artifact_run(evidences=duplicated),
            _envelope(),
            run_metadata=_metadata(),
            approved_policy=_approved_policy(),
        )

    # Then
    assert "unique" in str(error_info.value)


def test_strict_join_requires_matching_family_bound_policy() -> None:
    # Given
    artifact_run = _artifact_run()
    envelope = _envelope()

    # When
    causal_input = prepare_r1_causal_replay_input(
        artifact_run,
        envelope,
        run_metadata=_metadata(),
        approved_policy=_approved_policy(),
    )

    # Then
    assert len(causal_input.scheduled_evidences) == 2


def test_strict_join_rejects_approved_policy_family_mismatch() -> None:
    # Given
    policy = _approved_policy(family_id="wmi_management")

    # When
    with pytest.raises(ValueError, match="family_id") as error_info:
        prepare_r1_causal_replay_input(
            _artifact_run(),
            _envelope(),
            run_metadata=_metadata(),
            approved_policy=policy,
        )

    # Then
    assert "does not match" in str(error_info.value)


def test_strict_join_rejects_loaded_approved_policy_identity_mismatch() -> None:
    # Given
    policy = ApprovedLineagePolicy(
        policy_id="different-policy",
        version="v0.3",
        config_hash="approved-hash",
        approved_lineage=("anchor.exe", "middle.exe", "terminal.exe"),
        family_id="remote_management",
        lifecycle="frozen",
    )

    # When
    with pytest.raises(ValueError, match="loaded approved policy identity") as error_info:
        prepare_r1_causal_replay_input(
            _artifact_run(),
            _envelope(),
            run_metadata=_metadata(),
            approved_policy=policy,
        )

    # Then
    assert "must match" in str(error_info.value)


def test_strict_join_rejects_missing_run_family() -> None:
    # Given
    metadata = _metadata(family_id=None)

    # When
    with pytest.raises(ValueError, match="family_id") as error_info:
        prepare_r1_causal_replay_input(
            _artifact_run(),
            _envelope(),
            run_metadata=metadata,
            approved_policy=_approved_policy(),
        )

    # Then
    assert "requires" in str(error_info.value)


def test_strict_join_rejects_legacy_policy_without_family_binding() -> None:
    # Given
    policy = ApprovedLineagePolicy(
        policy_id="approved-policy",
        version="v0.3",
        config_hash="approved-hash",
        approved_lineage=("anchor.exe", "middle.exe", "terminal.exe"),
    )

    # When
    with pytest.raises(ValueError, match="legacy unbound") as error_info:
        prepare_r1_causal_replay_input(
            _artifact_run(),
            _envelope(),
            run_metadata=_metadata(),
            approved_policy=policy,
        )

    # Then
    assert "not eligible" in str(error_info.value)


def test_provenance_artifact_is_deterministic_and_immutable(tmp_path: Path) -> None:
    # Given
    result = run_r1_causal_replay(
        _artifact_run(),
        _envelope(),
        run_metadata=_metadata(),
        approved_policy=_approved_policy(),
        config=_config(),
        execution_commit="4ee119069b33470a1cd4a34626f1a1d0a88c4662",
    )

    # When
    first_bytes = serialize_r1_causal_replay_provenance(result.provenance)
    second_bytes = serialize_r1_causal_replay_provenance(result.provenance)
    artifact = write_r1_causal_replay_provenance(
        result.provenance,
        output_directory=tmp_path,
    )
    restored = load_r1_causal_replay_provenance(artifact.path)
    with pytest.raises(FileExistsError) as error_info:
        write_r1_causal_replay_provenance(
            result.provenance,
            output_directory=tmp_path,
        )

    # Then
    assert first_bytes == second_bytes == artifact.path.read_bytes()
    assert restored == result.provenance
    assert artifact.path.name == R1_CAUSAL_REPLAY_PROVENANCE_FILENAME
    assert artifact.provenance.fusion_runtime_config.config_version == _config().config_version
    assert artifact.provenance.source_evidence_artifact_sha256 == _EVIDENCE_HASH
    assert artifact.provenance.source_extraction_summary_sha256 == _SUMMARY_HASH
    assert artifact.provenance.execution_commit == "4ee119069b33470a1cd4a34626f1a1d0a88c4662"
    assert "already exists" in str(error_info.value)


def test_run_and_write_pipeline_publishes_reloadable_causal_output_artifacts(
    tmp_path: Path,
) -> None:
    # Given
    artifact_run = _artifact_run()
    envelope = _envelope()

    # When
    result = run_and_write_r1_causal_replay(
        artifact_run,
        envelope,
        run_metadata=_metadata(),
        approved_policy=_approved_policy(),
        config=_config(),
        execution_commit="4ee119069b33470a1cd4a34626f1a1d0a88c4662",
        output_directory=tmp_path,
    )
    restored_provenance = load_r1_causal_replay_provenance(result.provenance_artifact.path)
    restored = load_r1_causal_replay_artifacts(tmp_path)

    # Then
    assert result.artifacts.fusion_result.path == (tmp_path / R1_CAUSAL_FUSION_RESULT_FILENAME)
    assert result.artifacts.fusion_stopping_trace.path == (
        tmp_path / R1_CAUSAL_FUSION_STOPPING_TRACE_FILENAME
    )
    assert result.provenance_artifact.path == (tmp_path / R1_CAUSAL_REPLAY_PROVENANCE_FILENAME)
    assert result.provenance_artifact.provenance == result.pipeline_result.provenance
    assert restored_provenance == result.pipeline_result.provenance
    assert restored.fusion_result == result.pipeline_result.fusion_result
    assert restored.fusion_stopping_trace == result.pipeline_result.stopping_trace
    assert restored.provenance == result.pipeline_result.provenance
    assert result.artifacts.fusion_result.sha256 == restored.provenance.fusion_result_sha256
    assert (
        result.artifacts.fusion_stopping_trace.sha256
        == restored.provenance.fusion_stopping_trace_sha256
    )
    assert (
        result.artifacts.fusion_result.sha256
        == hashlib.sha256(result.artifacts.fusion_result.path.read_bytes()).hexdigest()
    )
    assert (
        result.artifacts.fusion_stopping_trace.sha256
        == hashlib.sha256(result.artifacts.fusion_stopping_trace.path.read_bytes()).hexdigest()
    )


def test_provenance_serializes_all_external_times_as_utc_milliseconds() -> None:
    # Given
    result = run_r1_causal_replay(
        _artifact_run(),
        _envelope(),
        run_metadata=_metadata(),
        approved_policy=_approved_policy(),
        config=_config(),
        execution_commit="4ee119069b33470a1cd4a34626f1a1d0a88c4662",
    )
    payload = result.provenance.model_dump()
    shifted = tuple(
        point + timedelta(milliseconds=999) for point in result.provenance.evaluated_replay_points
    )
    payload.update(
        watermark_at=result.provenance.watermark_at + timedelta(milliseconds=999),
        replay_start=result.provenance.replay_start + timedelta(milliseconds=999),
        replay_end=result.provenance.replay_end + timedelta(milliseconds=999),
        fusion_time=result.provenance.fusion_time + timedelta(milliseconds=999),
        evaluated_replay_points=shifted,
    )
    provenance = type(result.provenance).model_validate(payload)

    # When
    serialized = json.loads(serialize_r1_causal_replay_provenance(provenance))

    # Then
    assert serialized["replay_start"] == "2026-10-12T01:00:00.999Z"
    assert serialized["replay_end"] == "2026-10-12T01:00:35.999Z"
    assert serialized["watermark_at"] == "2026-10-12T01:00:35.999Z"
    assert serialized["fusion_time"] == "2026-10-12T01:00:35.999Z"
    assert serialized["evaluated_replay_points"][0] == "2026-10-12T01:00:00.999Z"


def test_provenance_serializes_whole_seconds_with_milliseconds() -> None:
    # Given
    result = run_r1_causal_replay(
        _artifact_run(),
        _envelope(),
        run_metadata=_metadata(),
        approved_policy=_approved_policy(),
        config=_config(),
        execution_commit="4ee119069b33470a1cd4a34626f1a1d0a88c4662",
    )

    # When
    serialized = json.loads(serialize_r1_causal_replay_provenance(result.provenance))

    # Then
    assert serialized["replay_start"] == "2026-10-12T01:00:00.000Z"
    assert serialized["replay_end"] == "2026-10-12T01:00:35.000Z"
