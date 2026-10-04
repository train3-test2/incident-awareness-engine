import logging
from datetime import UTC, datetime

import pytest

from incident_awareness.collection.collector.sysmon_jsonl import SysmonJsonlRecord
from incident_awareness.common.models.event import NormalizedEvent, RawLogReference
from incident_awareness.common.models.fusion import (
    FusionEpisodeResult,
    FusionResult,
    FusionStoppingTrace,
    FusionStoppingTracePoint,
)
from incident_awareness.common.models.fusion_runtime_config import (
    FusionRuntimeConfigSnapshot,
    FusionRuntimeReplaySnapshot,
    FusionRuntimeScoringSnapshot,
    FusionRuntimeStoppingSnapshot,
    FusionRuntimeWindowSnapshot,
)
from incident_awareness.common.models.result import DecisionResult, DetectionResult
from incident_awareness.common.models.run import RunMetadata
from incident_awareness.integration.fast_hit_handoff import FastDetectionAdapterResult
from incident_awareness.normalization.sysmon import SysmonNormalizationContext
from incident_awareness.pipeline.event_evidence import NormalizedEvidenceArtifacts
from incident_awareness.pipeline.persistence import (
    _ACQUIRE_DECISION_ID_LOCK,
    _ACQUIRE_DECISION_SCOPE_LOCK,
    _SHOW_TRANSACTION_ISOLATION,
    DecisionConflictError,
    persist_s0_results,
    resolve_expected_supersedes_decision_id,
)
from incident_awareness.pipeline.s0_artifacts import S0PipelineArtifacts
from incident_awareness.storage.repositories.result_repository import (
    _INSERT_DECISION_RUNTIME_SNAPSHOT,
    _SELECT_CURRENT_DECISION_HEADS,
    _SELECT_DECISION_PAYLOAD,
    _UPSERT_FUSION_RUNTIME_CONFIG_SNAPSHOT,
    DecisionIntegrityError,
)

RUN_ID = "RUN-20260920-001"
ENTITY_ID = "WIN-01"


class _Cursor:
    def __init__(
        self,
        *,
        row: tuple[object, ...] | None = None,
        rows: list[tuple[object, ...]] | None = None,
    ) -> None:
        self._row = row
        self._rows = rows if rows is not None else []

    def fetchone(self) -> tuple[object, ...] | None:
        return self._row

    def fetchall(self) -> list[tuple[object, ...]]:
        return self._rows


class _Connection:
    def __init__(
        self,
        *,
        fail_on_statement: int | None = None,
        fail_on_query_prefix: str | None = None,
        fail_rollback: bool = False,
        existing_decision: DecisionResult | None = None,
        current_heads: tuple[DecisionResult, ...] = (),
        decision_in_scope: bool | None = None,
        autocommit: bool = False,
        transaction_isolation: str = "read committed",
    ) -> None:
        self.statements: list[tuple[str, tuple[object, ...]]] = []
        self.commits = 0
        self.rollbacks = 0
        self._fail_on_statement = fail_on_statement
        self._fail_on_query_prefix = fail_on_query_prefix
        self._fail_rollback = fail_rollback
        self._existing_decision = existing_decision
        self._current_heads = current_heads
        self._decision_in_scope = decision_in_scope
        self.autocommit = autocommit
        self._transaction_isolation = transaction_isolation

    def execute(self, query: str, params: tuple[object, ...]) -> _Cursor:
        self.statements.append((query, params))
        if self._fail_on_statement == len(self.statements):
            raise RuntimeError("database write failed")
        if self._fail_on_query_prefix is not None and query.lstrip().startswith(
            self._fail_on_query_prefix
        ):
            raise RuntimeError("database write failed")

        if query == _SHOW_TRANSACTION_ISOLATION:
            return _Cursor(row=(self._transaction_isolation,))
        if query == _SELECT_DECISION_PAYLOAD:
            if (
                self._existing_decision is not None
                and self._existing_decision.decision_id == params[0]
            ):
                return _Cursor(row=(self._existing_decision.model_dump(mode="json"),))
            return _Cursor()
        if query == _SELECT_CURRENT_DECISION_HEADS:
            decision_in_scope = (
                bool(self._current_heads)
                if self._decision_in_scope is None
                else self._decision_in_scope
            )
            rows = [
                (decision_in_scope, head.model_dump(mode="json")) for head in self._current_heads
            ]
            return _Cursor(rows=rows or [(decision_in_scope, None)])
        return _Cursor()

    def commit(self) -> None:
        self.commits += 1

    def rollback(self) -> None:
        self.rollbacks += 1
        if self._fail_rollback:
            raise RuntimeError("database rollback failed")


def test_persists_first_cycle_contracts_in_dependency_order() -> None:
    # Given
    connection = _Connection()
    artifacts = _artifacts()
    event = _event()
    fusion_result, fast_result, decision_result = _results()

    # When
    persist_s0_results(
        artifacts,
        NormalizedEvidenceArtifacts(events=(event,), evidences=()),
        fusion_result,
        _stopping_trace(),
        _runtime_config_snapshot(),
        fast_result,
        decision_result,
        connection=connection,
    )

    # Then
    write_statements = [
        statement
        for statement in connection.statements
        if statement[0].lstrip().startswith("INSERT")
    ]
    assert [statement[0].split()[0:3] for statement in write_statements] == [
        ["INSERT", "INTO", "runs"],
        ["INSERT", "INTO", "events"],
        ["INSERT", "INTO", "fusion_results"],
        ["INSERT", "INTO", "fusion_stopping_traces"],
        ["INSERT", "INTO", "fusion_runtime_config_snapshots"],
        ["INSERT", "INTO", "detection_results"],
        ["INSERT", "INTO", "decisions"],
        ["INSERT", "INTO", "decision_runtime_snapshots"],
    ]
    assert connection.statements[:5] == [
        (_SHOW_TRANSACTION_ISOLATION, ()),
        (_ACQUIRE_DECISION_ID_LOCK, ("D-001",)),
        (
            _ACQUIRE_DECISION_SCOPE_LOCK,
            (RUN_ID, ENTITY_ID),
        ),
        (_SELECT_DECISION_PAYLOAD, ("D-001",)),
        (_SELECT_CURRENT_DECISION_HEADS, (RUN_ID, ENTITY_ID)),
    ]
    assert connection.commits == 1
    assert connection.rollbacks == 0
    snapshot_payload = write_statements[-1][1][3]
    assert snapshot_payload.obj["decision_id"] == decision_result.decision_id
    assert snapshot_payload.obj["run_id"] == decision_result.run_id
    assert snapshot_payload.obj["entity_id"] == decision_result.entity_id
    assert snapshot_payload.obj["detection_result"] == fast_result.detection_result.model_dump(
        mode="json"
    )
    assert snapshot_payload.obj["fusion_result"] == fusion_result.model_dump(mode="json")
    assert snapshot_payload.obj["fusion_stopping_trace"] == _stopping_trace().model_dump(
        mode="json"
    )
    assert snapshot_payload.obj[
        "fusion_runtime_config_snapshot"
    ] == _runtime_config_snapshot().model_dump(mode="json")


def test_resolves_no_expected_supersedes_when_scope_has_no_decision() -> None:
    # Given
    connection = _Connection()

    # When
    supersedes_decision_id = resolve_expected_supersedes_decision_id(
        decision_id="D-001",
        run_id=RUN_ID,
        entity_id=ENTITY_ID,
        connection=connection,
    )

    # Then
    assert supersedes_decision_id is None
    assert connection.commits == 0
    assert connection.rollbacks == 0


def test_rejects_autocommit_connection_before_lifecycle_database_operation() -> None:
    # Given
    connection = _Connection(autocommit=True)

    # When
    with pytest.raises(RuntimeError, match="Decision lifecycle requires autocommit disabled"):
        resolve_expected_supersedes_decision_id(
            decision_id="D-001",
            run_id=RUN_ID,
            entity_id=ENTITY_ID,
            connection=connection,
        )

    # Then
    assert connection.statements == []
    assert connection.rollbacks == 1


def test_accepts_read_committed_transaction_isolation() -> None:
    # Given
    connection = _Connection(transaction_isolation="read committed")

    # When
    supersedes_decision_id = resolve_expected_supersedes_decision_id(
        decision_id="D-001",
        run_id=RUN_ID,
        entity_id=ENTITY_ID,
        connection=connection,
    )

    # Then
    assert supersedes_decision_id is None
    assert connection.statements[0] == (_SHOW_TRANSACTION_ISOLATION, ())
    assert connection.rollbacks == 0


def test_rejects_unsupported_transaction_isolation_before_lifecycle_reads() -> None:
    # Given
    connection = _Connection(transaction_isolation="repeatable read")

    # When
    with pytest.raises(
        RuntimeError,
        match="Decision lifecycle requires READ COMMITTED isolation",
    ):
        resolve_expected_supersedes_decision_id(
            decision_id="D-001",
            run_id=RUN_ID,
            entity_id=ENTITY_ID,
            connection=connection,
        )

    # Then
    assert connection.statements == [(_SHOW_TRANSACTION_ISOLATION, ())]
    assert connection.rollbacks == 1


def test_rejects_unsafe_connection_before_persistence_writes() -> None:
    # Given
    fusion_result, fast_result, decision_result = _results()
    connection = _Connection(autocommit=True)

    # When
    with pytest.raises(RuntimeError, match="Decision lifecycle requires autocommit disabled"):
        persist_s0_results(
            _artifacts(),
            NormalizedEvidenceArtifacts(events=(_event(),), evidences=()),
            fusion_result,
            _stopping_trace(),
            _runtime_config_snapshot(),
            fast_result,
            decision_result,
            connection=connection,
        )

    # Then
    assert connection.statements == []
    assert connection.commits == 0
    assert connection.rollbacks == 1


def test_resolves_current_head_for_new_decision_id() -> None:
    # Given
    current_head = _results()[2]
    connection = _Connection(current_heads=(current_head,))

    # When
    supersedes_decision_id = resolve_expected_supersedes_decision_id(
        decision_id="D-002",
        run_id=RUN_ID,
        entity_id=ENTITY_ID,
        connection=connection,
    )

    # Then
    assert supersedes_decision_id == "D-001"


def test_resolves_stored_supersedes_for_existing_decision_id() -> None:
    # Given
    existing = _results()[2].model_copy(update={"supersedes_decision_id": "D-000"})
    other_head = existing.model_copy(update={"decision_id": "D-002"})
    connection = _Connection(existing_decision=existing, current_heads=(other_head,))

    # When
    supersedes_decision_id = resolve_expected_supersedes_decision_id(
        decision_id="D-001",
        run_id=RUN_ID,
        entity_id=ENTITY_ID,
        connection=connection,
    )

    # Then
    assert supersedes_decision_id == "D-000"
    assert [query for query, _ in connection.statements] == [
        _SHOW_TRANSACTION_ISOLATION,
        _SELECT_DECISION_PAYLOAD,
    ]


def test_rejects_existing_decision_in_different_scope_during_resolution() -> None:
    # Given
    existing = _results()[2].model_copy(update={"run_id": "RUN-20260920-002"})
    connection = _Connection(existing_decision=existing)

    # When
    with pytest.raises(DecisionIntegrityError, match="different scope"):
        resolve_expected_supersedes_decision_id(
            decision_id="D-001",
            run_id=RUN_ID,
            entity_id=ENTITY_ID,
            connection=connection,
        )

    # Then
    assert [query for query, _ in connection.statements] == [
        _SHOW_TRANSACTION_ISOLATION,
        _SELECT_DECISION_PAYLOAD,
    ]
    assert connection.rollbacks == 1


def test_preserves_resolution_error_when_rollback_fails(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # Given
    existing = _results()[2].model_copy(update={"run_id": "RUN-20260920-002"})
    connection = _Connection(existing_decision=existing, fail_rollback=True)

    # When
    with (
        caplog.at_level(logging.ERROR),
        pytest.raises(DecisionIntegrityError, match="different scope"),
    ):
        resolve_expected_supersedes_decision_id(
            decision_id="D-001",
            run_id=RUN_ID,
            entity_id=ENTITY_ID,
            connection=connection,
        )

    # Then
    assert connection.rollbacks == 1
    assert "Decision lifecycle resolution rollback failed" in caplog.text


def test_persists_new_decision_when_expected_head_matches() -> None:
    # Given
    fusion_result, fast_result, current_head = _results()
    candidate = current_head.model_copy(
        update={
            "decision_id": "D-002",
            "supersedes_decision_id": "D-001",
        }
    )
    connection = _Connection(current_heads=(current_head,))

    # When
    persist_s0_results(
        _artifacts(),
        NormalizedEvidenceArtifacts(events=(_event(),), evidences=()),
        fusion_result,
        _stopping_trace(),
        _runtime_config_snapshot(),
        fast_result,
        candidate,
        connection=connection,
    )

    # Then
    assert connection.commits == 1
    assert connection.rollbacks == 0
    assert any(
        query.lstrip().startswith("INSERT INTO decisions") for query, _ in connection.statements
    )


def test_rejects_new_decision_when_current_head_changed() -> None:
    # Given
    fusion_result, fast_result, decision_result = _results()
    current_head = decision_result.model_copy(update={"decision_id": "D-002"})
    candidate = decision_result.model_copy(
        update={
            "decision_id": "D-003",
            "supersedes_decision_id": "D-001",
        }
    )
    connection = _Connection(current_heads=(current_head,))

    # When
    with pytest.raises(DecisionConflictError, match="current Decision head changed"):
        persist_s0_results(
            _artifacts(),
            NormalizedEvidenceArtifacts(events=(_event(),), evidences=()),
            fusion_result,
            _stopping_trace(),
            _runtime_config_snapshot(),
            fast_result,
            candidate,
            connection=connection,
        )

    # Then
    assert connection.commits == 0
    assert connection.rollbacks == 1
    assert not any(query.lstrip().startswith("INSERT") for query, _ in connection.statements)


def test_treats_identical_existing_decision_as_idempotent_no_op() -> None:
    # Given
    fusion_result, fast_result, decision_result = _results()
    retry_trace = _stopping_trace().model_copy(
        update={
            "points": [
                FusionStoppingTracePoint(
                    timestamp=datetime(2026, 9, 20, tzinfo=UTC),
                    score=0.6,
                    persistence_count=None,
                    policy_state="off",
                )
            ]
        }
    )
    connection = _Connection(existing_decision=decision_result)

    # When
    persist_s0_results(
        _artifacts(),
        NormalizedEvidenceArtifacts(events=(_event(),), evidences=()),
        fusion_result,
        retry_trace,
        _runtime_config_snapshot(),
        fast_result,
        decision_result,
        connection=connection,
    )

    # Then
    assert connection.commits == 1
    assert connection.rollbacks == 0
    assert retry_trace != _stopping_trace()
    assert not any(query.lstrip().startswith("INSERT") for query, _ in connection.statements)
    assert not any(
        query.lstrip().startswith("INSERT INTO fusion_stopping_traces")
        for query, _ in connection.statements
    )
    assert not any(
        query == _UPSERT_FUSION_RUNTIME_CONFIG_SNAPSHOT for query, _ in connection.statements
    )
    assert not any(query == _INSERT_DECISION_RUNTIME_SNAPSHOT for query, _ in connection.statements)


def test_skips_snapshot_factory_for_identical_decision_with_mismatched_runtime_input() -> None:
    # Given
    fusion_result, _, decision_result = _results()
    invalid_fast_result = _detected_fast_result()
    connection = _Connection(existing_decision=decision_result)

    # When
    persist_s0_results(
        _artifacts(),
        NormalizedEvidenceArtifacts(events=(_event(),), evidences=()),
        fusion_result,
        _stopping_trace(),
        _runtime_config_snapshot(),
        invalid_fast_result,
        decision_result,
        connection=connection,
    )

    # Then
    assert decision_result.fast_status != invalid_fast_result.detection_result.detector_status
    assert connection.commits == 1
    assert connection.rollbacks == 0
    assert not any(query.lstrip().startswith("INSERT") for query, _ in connection.statements)
    assert not any(query == _INSERT_DECISION_RUNTIME_SNAPSHOT for query, _ in connection.statements)


def test_rejects_new_decision_runtime_mismatch_before_persistence_writes() -> None:
    # Given
    fusion_result, _, decision_result = _results()
    invalid_fast_result = _detected_fast_result()
    connection = _Connection()

    # When
    with pytest.raises(
        ValueError,
        match="DecisionResult fast_status must match DetectionResult detector_status",
    ):
        persist_s0_results(
            _artifacts(),
            NormalizedEvidenceArtifacts(events=(_event(),), evidences=()),
            fusion_result,
            _stopping_trace(),
            _runtime_config_snapshot(),
            invalid_fast_result,
            decision_result,
            connection=connection,
        )

    # Then
    assert (_ACQUIRE_DECISION_ID_LOCK, (decision_result.decision_id,)) in connection.statements
    assert (_SELECT_CURRENT_DECISION_HEADS, (RUN_ID, ENTITY_ID)) in connection.statements
    assert not any(query.lstrip().startswith("INSERT") for query, _ in connection.statements)
    assert connection.commits == 0
    assert connection.rollbacks == 1


def test_rejects_existing_decision_id_with_different_content() -> None:
    # Given
    fusion_result, fast_result, decision_result = _results()
    existing = decision_result.model_copy(update={"decision_reason": "stored content"})
    connection = _Connection(existing_decision=existing)

    # When
    with pytest.raises(
        DecisionIntegrityError,
        match="decision_id already exists with different content",
    ):
        persist_s0_results(
            _artifacts(),
            NormalizedEvidenceArtifacts(events=(_event(),), evidences=()),
            fusion_result,
            _stopping_trace(),
            _runtime_config_snapshot(),
            fast_result,
            decision_result,
            connection=connection,
        )

    # Then
    assert connection.commits == 0
    assert connection.rollbacks == 1
    assert not any(query.lstrip().startswith("INSERT") for query, _ in connection.statements)


def test_rejects_existing_decision_id_in_different_scope_during_persistence() -> None:
    # Given
    fusion_result, fast_result, decision_result = _results()
    existing = decision_result.model_copy(update={"entity_id": "WIN-02"})
    connection = _Connection(existing_decision=existing)

    # When
    with pytest.raises(DecisionIntegrityError, match="different scope"):
        persist_s0_results(
            _artifacts(),
            NormalizedEvidenceArtifacts(events=(_event(),), evidences=()),
            fusion_result,
            _stopping_trace(),
            _runtime_config_snapshot(),
            fast_result,
            decision_result,
            connection=connection,
        )

    # Then
    assert connection.commits == 0
    assert connection.rollbacks == 1
    assert not any(query.lstrip().startswith("INSERT") for query, _ in connection.statements)


def test_rolls_back_all_writes_when_persistence_fails() -> None:
    connection = _Connection(fail_on_statement=8)
    fusion_result, fast_result, decision_result = _results()

    with pytest.raises(RuntimeError, match="database write failed"):
        persist_s0_results(
            _artifacts(),
            NormalizedEvidenceArtifacts(events=(_event(),), evidences=()),
            fusion_result,
            _stopping_trace(),
            _runtime_config_snapshot(),
            fast_result,
            decision_result,
            connection=connection,
        )

    assert connection.commits == 0
    assert connection.rollbacks == 1


def test_preserves_save_error_when_rollback_fails(caplog: pytest.LogCaptureFixture) -> None:
    connection = _Connection(fail_on_statement=8, fail_rollback=True)
    fusion_result, fast_result, decision_result = _results()

    with caplog.at_level(logging.ERROR), pytest.raises(RuntimeError, match="database write failed"):
        persist_s0_results(
            _artifacts(),
            NormalizedEvidenceArtifacts(events=(_event(),), evidences=()),
            fusion_result,
            _stopping_trace(),
            _runtime_config_snapshot(),
            fast_result,
            decision_result,
            connection=connection,
        )

    assert connection.rollbacks == 1
    assert "First Cycle persistence rollback failed" in caplog.text


def test_rolls_back_when_decision_runtime_snapshot_insert_fails() -> None:
    # Given
    connection = _Connection(fail_on_query_prefix="INSERT INTO decision_runtime_snapshots")
    fusion_result, fast_result, decision_result = _results()

    # When
    with pytest.raises(RuntimeError, match="database write failed"):
        persist_s0_results(
            _artifacts(),
            NormalizedEvidenceArtifacts(events=(_event(),), evidences=()),
            fusion_result,
            _stopping_trace(),
            _runtime_config_snapshot(),
            fast_result,
            decision_result,
            connection=connection,
        )

    # Then
    decision_index = next(
        index
        for index, (query, _) in enumerate(connection.statements)
        if query.lstrip().startswith("INSERT INTO decisions")
    )
    snapshot_index = next(
        index
        for index, (query, _) in enumerate(connection.statements)
        if query == _INSERT_DECISION_RUNTIME_SNAPSHOT
    )
    assert decision_index < snapshot_index
    assert connection.commits == 0
    assert connection.rollbacks == 1


def test_rolls_back_when_runtime_config_snapshot_save_fails() -> None:
    # Given
    connection = _Connection(fail_on_query_prefix="INSERT INTO fusion_runtime_config_snapshots")
    fusion_result, fast_result, decision_result = _results()

    # When
    with pytest.raises(RuntimeError, match="database write failed"):
        persist_s0_results(
            _artifacts(),
            NormalizedEvidenceArtifacts(events=(_event(),), evidences=()),
            fusion_result,
            _stopping_trace(),
            _runtime_config_snapshot(),
            fast_result,
            decision_result,
            connection=connection,
        )

    # Then
    assert connection.commits == 0
    assert connection.rollbacks == 1


@pytest.mark.parametrize(
    ("runtime_config_overrides", "expected_message"),
    [
        (
            {"run_id": "RUN-20260920-002"},
            "result run_id must match RunMetadata",
        ),
        (
            {"entity_id": "WIN-02"},
            "result entity_id must match RunMetadata target_host",
        ),
        (
            {"config_version": "other-config"},
            "config_version must match FusionResult scoring_config_version",
        ),
        (
            {"profile_id": "other-profile"},
            "scoring profile_id must match FusionResult scoring_profile_id",
        ),
        (
            {"scorer_version": "other-scorer"},
            "scoring scorer_version must match FusionResult scorer_version",
        ),
        (
            {"model_version": "model-v1"},
            "model_version must match FusionResult model_version",
        ),
    ],
)
def test_rejects_invalid_runtime_config_snapshot_before_database_access(
    runtime_config_overrides: dict[str, str],
    expected_message: str,
) -> None:
    # Given
    fusion_result, fast_result, decision_result = _results()
    runtime_config = _runtime_config_snapshot(**runtime_config_overrides)
    connection = _Connection()

    # When
    with pytest.raises(ValueError, match=expected_message):
        persist_s0_results(
            _artifacts(),
            NormalizedEvidenceArtifacts(events=(), evidences=()),
            fusion_result,
            _stopping_trace(),
            runtime_config,
            fast_result,
            decision_result,
            connection=connection,
        )

    # Then
    assert connection.statements == []
    assert connection.rollbacks == 1


def test_rejects_runtime_config_scoring_method_mismatch_before_database_access() -> None:
    # Given
    fusion_result, fast_result, decision_result = _results()
    invalid_fusion = fusion_result.model_copy(update={"scoring_method": "temporal_fusion"})
    connection = _Connection()

    # When
    with pytest.raises(
        ValueError,
        match="scoring method must match FusionResult scoring_method",
    ):
        persist_s0_results(
            _artifacts(),
            NormalizedEvidenceArtifacts(events=(), evidences=()),
            invalid_fusion,
            _stopping_trace(),
            _runtime_config_snapshot(),
            fast_result,
            decision_result,
            connection=connection,
        )

    # Then
    assert connection.statements == []
    assert connection.rollbacks == 1


def test_rejects_result_with_run_id_outside_persisted_run() -> None:
    # Given
    fusion_result, fast_result, decision_result = _results()
    invalid_fusion = fusion_result.model_copy(update={"run_id": "RUN-20260920-002"})
    connection = _Connection()

    # When
    with pytest.raises(ValueError, match="result run_id"):
        persist_s0_results(
            _artifacts(),
            NormalizedEvidenceArtifacts(events=(), evidences=()),
            invalid_fusion,
            _stopping_trace(),
            _runtime_config_snapshot(),
            fast_result,
            decision_result,
            connection=connection,
        )

    # Then
    assert connection.rollbacks == 1


def test_rejects_stopping_trace_with_run_id_outside_persisted_run() -> None:
    # Given
    fusion_result, fast_result, decision_result = _results()
    stopping_trace = _stopping_trace().model_copy(update={"run_id": "RUN-20260920-002"})
    connection = _Connection()

    # When
    with pytest.raises(ValueError, match="result run_id"):
        persist_s0_results(
            _artifacts(),
            NormalizedEvidenceArtifacts(events=(), evidences=()),
            fusion_result,
            stopping_trace,
            _runtime_config_snapshot(),
            fast_result,
            decision_result,
            connection=connection,
        )

    # Then
    assert connection.statements == []
    assert connection.rollbacks == 1


def test_rejects_stopping_trace_for_a_host_other_than_the_run_target() -> None:
    # Given
    fusion_result, fast_result, decision_result = _results()
    stopping_trace = _stopping_trace().model_copy(update={"entity_id": "WIN-02"})
    connection = _Connection()

    # When
    with pytest.raises(ValueError, match="entity_id must match RunMetadata target_host"):
        persist_s0_results(
            _artifacts(),
            NormalizedEvidenceArtifacts(events=(), evidences=()),
            fusion_result,
            stopping_trace,
            _runtime_config_snapshot(),
            fast_result,
            decision_result,
            connection=connection,
        )

    # Then
    assert connection.statements == []
    assert connection.rollbacks == 1


def test_rejects_stopping_trace_with_different_scoring_config_version() -> None:
    # Given
    fusion_result, fast_result, decision_result = _results()
    stopping_trace = _stopping_trace().model_copy(update={"scoring_config_version": "other"})
    connection = _Connection()

    # When
    with pytest.raises(ValueError, match="scoring_config_version must match FusionResult"):
        persist_s0_results(
            _artifacts(),
            NormalizedEvidenceArtifacts(events=(), evidences=()),
            fusion_result,
            stopping_trace,
            _runtime_config_snapshot(),
            fast_result,
            decision_result,
            connection=connection,
        )

    # Then
    assert connection.statements == []
    assert connection.rollbacks == 1


def test_rejects_not_evaluated_result_with_non_empty_stopping_trace() -> None:
    # Given
    fusion_result, fast_result, decision_result = _results()
    not_evaluated_result = fusion_result.model_copy(update={"fusion_status": "not_evaluated"})
    connection = _Connection()

    # When
    with pytest.raises(ValueError, match="requires an empty FusionStoppingTrace"):
        persist_s0_results(
            _artifacts(),
            NormalizedEvidenceArtifacts(events=(), evidences=()),
            not_evaluated_result,
            _stopping_trace(),
            _runtime_config_snapshot(),
            fast_result,
            decision_result,
            connection=connection,
        )

    # Then
    assert connection.statements == []
    assert connection.rollbacks == 1


@pytest.mark.parametrize("fusion_status", ["miss", "detected"])
def test_rejects_evaluated_result_with_empty_stopping_trace(
    fusion_status: str,
) -> None:
    # Given
    _, fast_result, decision_result = _results()
    fusion_result = _detected_fusion_result() if fusion_status == "detected" else _results()[0]
    empty_trace = _stopping_trace().model_copy(update={"points": []})
    connection = _Connection()

    # When
    with pytest.raises(ValueError, match="requires a non-empty FusionStoppingTrace"):
        persist_s0_results(
            _artifacts(),
            NormalizedEvidenceArtifacts(events=(), evidences=()),
            fusion_result,
            empty_trace,
            _runtime_config_snapshot(),
            fast_result,
            decision_result,
            connection=connection,
        )

    # Then
    assert connection.statements == []
    assert connection.rollbacks == 1


def test_accepts_not_evaluated_result_with_empty_stopping_trace() -> None:
    # Given
    fusion_result, fast_result, decision_result = _results()
    not_evaluated_result = FusionResult.model_validate(
        {
            **fusion_result.model_dump(mode="python"),
            "fusion_status": "not_evaluated",
        }
    )
    empty_trace = _stopping_trace().model_copy(update={"points": []})
    not_evaluated_decision = DecisionResult.model_validate(
        {
            **decision_result.model_dump(mode="python"),
            "fusion_status": "not_evaluated",
            "fusion_time": None,
            "t_e": None,
            "decision_path": None,
            "winning_path": None,
        }
    )
    connection = _Connection()

    # When
    persist_s0_results(
        _artifacts(),
        NormalizedEvidenceArtifacts(events=(), evidences=()),
        not_evaluated_result,
        empty_trace,
        _runtime_config_snapshot(),
        fast_result,
        not_evaluated_decision,
        connection=connection,
    )

    # Then
    assert connection.commits == 1
    assert connection.rollbacks == 0


def test_preserves_pre_persistence_validation_error_when_rollback_fails(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # Given
    fusion_result, fast_result, decision_result = _results()
    invalid_fusion = fusion_result.model_copy(update={"run_id": "RUN-20260920-002"})
    connection = _Connection(fail_rollback=True)

    # When
    with (
        caplog.at_level(logging.ERROR),
        pytest.raises(ValueError, match="result run_id"),
    ):
        persist_s0_results(
            _artifacts(),
            NormalizedEvidenceArtifacts(events=(), evidences=()),
            invalid_fusion,
            _stopping_trace(),
            _runtime_config_snapshot(),
            fast_result,
            decision_result,
            connection=connection,
        )

    # Then
    assert connection.rollbacks == 1
    assert "First Cycle pre-persistence validation rollback failed" in caplog.text


def test_rejects_result_for_a_host_other_than_the_run_target() -> None:
    fusion_result, fast_result, decision_result = _results()
    other_host = "WIN-02"
    invalid_fusion = fusion_result.model_copy(update={"entity_id": other_host})
    invalid_fast = FastDetectionAdapterResult(
        detection_result=fast_result.detection_result.model_copy(update={"entity_id": other_host}),
        source_hit_ids=fast_result.source_hit_ids,
        selected_source_hit_id=fast_result.selected_source_hit_id,
    )
    invalid_decision = decision_result.model_copy(update={"entity_id": other_host})

    with pytest.raises(ValueError, match="entity_id must match RunMetadata target_host"):
        persist_s0_results(
            _artifacts(),
            NormalizedEvidenceArtifacts(events=(_event(),), evidences=()),
            invalid_fusion,
            _stopping_trace(),
            _runtime_config_snapshot(),
            invalid_fast,
            invalid_decision,
            connection=_Connection(),
        )


def test_rejects_event_for_a_host_other_than_the_run_target() -> None:
    fusion_result, fast_result, decision_result = _results()
    invalid_event = _event().model_copy(update={"host_id": "WIN-02"})

    with pytest.raises(ValueError, match="host_id must match RunMetadata target_host"):
        persist_s0_results(
            _artifacts(),
            NormalizedEvidenceArtifacts(events=(invalid_event,), evidences=()),
            fusion_result,
            _stopping_trace(),
            _runtime_config_snapshot(),
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
                    "fusion_result": "v0.3",
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


def _stopping_trace() -> FusionStoppingTrace:
    return FusionStoppingTrace(
        run_id=RUN_ID,
        entity_id=ENTITY_ID,
        scoring_config_version="fusion-config-s0-pair-v0.1",
        points=[
            FusionStoppingTracePoint(
                timestamp=datetime(2026, 9, 20, tzinfo=UTC),
                score=0.5,
                persistence_count=None,
                policy_state="off",
            )
        ],
    )


def _runtime_config_snapshot(
    *,
    run_id: str = RUN_ID,
    entity_id: str = ENTITY_ID,
    config_version: str = "fusion-config-s0-pair-v0.1",
    profile_id: str = "s0-profile",
    scorer_version: str = "simple-score-v0.1",
    model_version: str | None = None,
) -> FusionRuntimeConfigSnapshot:
    return FusionRuntimeConfigSnapshot(
        run_id=run_id,
        entity_id=entity_id,
        config_version=config_version,
        model_version=model_version,
        window=FusionRuntimeWindowSnapshot(window_size_sec=60.0),
        replay=FusionRuntimeReplaySnapshot(step_size_sec=10.0),
        scoring=FusionRuntimeScoringSnapshot(
            method="simple_score",
            scorer_version=scorer_version,
            profile_id=profile_id,
            evidence_types=("process_start",),
        ),
        stopping=FusionRuntimeStoppingSnapshot(
            threshold_on=0.8,
            threshold_off=0.4,
            persistence_k=2,
        ),
    )


def _detected_fusion_result() -> FusionResult:
    timestamp = datetime(2026, 9, 20, tzinfo=UTC)
    evidence_ids = ["ev-001"]
    return FusionResult(
        run_id=RUN_ID,
        entity_id=ENTITY_ID,
        fusion_time=timestamp,
        fusion_status="detected",
        score_at_decision=0.8,
        contributing_evidence_ids=evidence_ids,
        scoring_config_version="fusion-config-s0-pair-v0.1",
        scoring_profile_id="s0-profile",
        scoring_method="simple_score",
        scorer_version="simple-score-v0.1",
        fusion_episodes=[
            FusionEpisodeResult(
                episode_id="episode-001",
                run_id=RUN_ID,
                entity_id=ENTITY_ID,
                start_time=timestamp,
                end_time=None,
                end_reason=None,
                score_at_start=0.8,
                peak_score=0.8,
                contributing_evidence_ids=evidence_ids,
            )
        ],
    )


def _detected_fast_result() -> FastDetectionAdapterResult:
    detection_result = DetectionResult(
        run_id=RUN_ID,
        entity_id=ENTITY_ID,
        detector_time=datetime(2026, 9, 20, tzinfo=UTC),
        detector_status="detected",
        detector_id="hayabusa",
        rule_id="RULE-001",
        rule_version="v0.2",
        severity="high",
    )
    return FastDetectionAdapterResult(
        detection_result=detection_result,
        source_hit_ids=("hit-001",),
        selected_source_hit_id="hit-001",
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
