from datetime import UTC, datetime

import pytest

from incident_awareness.collection.collector.sysmon_jsonl import SysmonJsonlRecord
from incident_awareness.common.models.event import NormalizedEvent, RawLogReference
from incident_awareness.common.models.fusion import FusionResult
from incident_awareness.common.models.result import DecisionResult, DetectionResult
from incident_awareness.common.models.run import RunMetadata
from incident_awareness.integration.fast_hit_handoff import FastDetectionAdapterResult
from incident_awareness.normalization.sysmon import SysmonNormalizationContext
from incident_awareness.pipeline.event_evidence import NormalizedEvidenceArtifacts
from incident_awareness.pipeline.persistence import persist_s0_results
from incident_awareness.pipeline.s0_artifacts import S0PipelineArtifacts

RUN_ID = "RUN-20260920-001"
ENTITY_ID = "WIN-01"


class _Cursor:
    def fetchone(self) -> None:
        return None


class _Connection:
    def __init__(self, *, fail_on_statement: int | None = None) -> None:
        self.statements: list[tuple[str, tuple[object, ...]]] = []
        self.commits = 0
        self.rollbacks = 0
        self._fail_on_statement = fail_on_statement

    def execute(self, query: str, params: tuple[object, ...]) -> _Cursor:
        self.statements.append((query, params))
        if self._fail_on_statement == len(self.statements):
            raise RuntimeError("database write failed")
        return _Cursor()

    def commit(self) -> None:
        self.commits += 1

    def rollback(self) -> None:
        self.rollbacks += 1


def test_persists_first_cycle_contracts_in_dependency_order() -> None:
    connection = _Connection()
    artifacts = _artifacts()
    event = _event()
    fusion_result, fast_result, decision_result = _results()

    persist_s0_results(
        artifacts,
        NormalizedEvidenceArtifacts(events=(event,), evidences=()),
        fusion_result,
        fast_result,
        decision_result,
        connection=connection,
    )

    assert [statement[0].split()[0:3] for statement in connection.statements] == [
        ["INSERT", "INTO", "runs"],
        ["INSERT", "INTO", "events"],
        ["INSERT", "INTO", "fusion_results"],
        ["INSERT", "INTO", "detection_results"],
        ["INSERT", "INTO", "decisions"],
    ]
    assert connection.commits == 1
    assert connection.rollbacks == 0


def test_rolls_back_all_writes_when_persistence_fails() -> None:
    connection = _Connection(fail_on_statement=4)
    fusion_result, fast_result, decision_result = _results()

    with pytest.raises(RuntimeError, match="database write failed"):
        persist_s0_results(
            _artifacts(),
            NormalizedEvidenceArtifacts(events=(_event(),), evidences=()),
            fusion_result,
            fast_result,
            decision_result,
            connection=connection,
        )

    assert connection.commits == 0
    assert connection.rollbacks == 1


def test_rejects_result_with_run_id_outside_persisted_run() -> None:
    fusion_result, fast_result, decision_result = _results()
    invalid_fusion = fusion_result.model_copy(update={"run_id": "RUN-20260920-002"})

    with pytest.raises(ValueError, match="result run_id"):
        persist_s0_results(
            _artifacts(),
            NormalizedEvidenceArtifacts(events=(), evidences=()),
            invalid_fusion,
            fast_result,
            decision_result,
            connection=_Connection(),
        )


def _artifacts() -> S0PipelineArtifacts:
    return S0PipelineArtifacts(
        run_metadata=RunMetadata.model_validate(
            {
                "run_id": RUN_ID,
                "scenario_id": "S0",
                "run_type": "attack",
                "target_host": ENTITY_ID,
                "start_time": datetime(2026, 9, 20, tzinfo=UTC),
                "schema_versions": {
                    "run_metadata": "v0.2",
                    "event": "v0.2",
                    "evidence": "v0.2",
                    "fast_hit": "v0.2",
                    "detection_result": "v0.2",
                    "fusion_result": "v0.2",
                    "decision_result": "v0.2",
                    "execution_record": "v0.1",
                    "evaluation_input": "v0.1",
                },
            }
        ),
        sysmon_records=(SysmonJsonlRecord(record_no=1, data={}),),
        normalization_context=SysmonNormalizationContext(
            run_id=RUN_ID,
            raw_log_id="RAW-002",
            segment_no=1,
        ),
    )


def _event() -> NormalizedEvent:
    timestamp = datetime(2026, 9, 20, tzinfo=UTC)
    return NormalizedEvent(
        event_id="evt-001",
        run_id=RUN_ID,
        timestamp=timestamp,
        timestamp_source="event_time",
        event_time=timestamp,
        host_id=ENTITY_ID,
        source="sysmon",
        source_layer="raw_telemetry",
        source_event_id="1",
        event_type="process_create",
        raw_ref=RawLogReference(raw_log_id="RAW-002", segment_no=1, record_no=1),
    )


def _results() -> tuple[FusionResult, FastDetectionAdapterResult, DecisionResult]:
    fusion_result = FusionResult(
        run_id=RUN_ID,
        entity_id=ENTITY_ID,
        fusion_time=None,
        fusion_status="miss",
        score_at_decision=None,
        contributing_evidence_ids=[],
        scoring_config_version="fusion-config-s0-pair-v0.1",
        scoring_profile_id="s0-profile",
        scoring_method="simple_score",
        scorer_version="simple-score-v0.1",
        fusion_episodes=[],
    )
    detection_result = DetectionResult(
        run_id=RUN_ID,
        entity_id=ENTITY_ID,
        detector_time=None,
        detector_status="miss",
        detector_id=None,
        rule_id=None,
        rule_version=None,
        severity=None,
    )
    fast_result = FastDetectionAdapterResult(
        detection_result=detection_result,
        source_hit_ids=(),
        selected_source_hit_id=None,
    )
    decision_result = DecisionResult(
        run_id=RUN_ID,
        decision_id="D-001",
        entity_id=ENTITY_ID,
        fast_status="miss",
        fusion_status="miss",
        detector_time=None,
        fusion_time=None,
        t_e=None,
        decision_path="none",
        winning_path="none",
        decision_reason="Both evaluated paths missed",
        config_version="parallel-v0.2",
        source_hit_ids=[],
    )
    return fusion_result, fast_result, decision_result
