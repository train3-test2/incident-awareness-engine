"""Persist completed First Cycle pipeline contracts through PostgreSQL repositories."""

import logging
from collections.abc import Mapping
from typing import Protocol

import psycopg

from incident_awareness.common.models.fusion import FusionResult, FusionStoppingTrace
from incident_awareness.common.models.fusion_runtime_config import FusionRuntimeConfigSnapshot
from incident_awareness.common.models.result import DecisionResult
from incident_awareness.common.models.runtime_snapshot import build_decision_runtime_snapshot
from incident_awareness.integration.fast_hit_handoff import FastDetectionAdapterResult
from incident_awareness.pipeline.event_evidence import NormalizedEvidenceArtifacts
from incident_awareness.pipeline.s0_artifacts import S0PipelineArtifacts
from incident_awareness.storage.config import DatabaseConfig
from incident_awareness.storage.repositories.event_repository import EventRepository
from incident_awareness.storage.repositories.result_repository import (
    DecisionIntegrityError,
    DecisionRepository,
    DecisionRuntimeSnapshotRepository,
    DetectionResultRepository,
    FusionResultRepository,
    FusionRuntimeConfigSnapshotRepository,
    FusionStoppingTraceRepository,
)
from incident_awareness.storage.repositories.run_repository import RunRepository

_LOGGER = logging.getLogger(__name__)

_SHOW_TRANSACTION_ISOLATION = "SHOW transaction_isolation"

_ACQUIRE_DECISION_ID_LOCK = """
SELECT pg_advisory_xact_lock(hashtext(%s)::bigint)
"""

_ACQUIRE_DECISION_SCOPE_LOCK = """
SELECT pg_advisory_xact_lock(hashtext(%s), hashtext(%s))
"""


class DecisionConflictError(RuntimeError):
    """Decision head가 사전 조회 이후 변경되어 저장할 수 없다."""


class DatabaseCursor(Protocol):
    def fetchone(self) -> tuple[object, ...] | Mapping[str, object] | None: ...


class DatabaseConnection(Protocol):
    """Repository operations needed to persist one First Cycle result set."""

    @property
    def autocommit(self) -> bool: ...

    def execute(self, query: str, params: tuple[object, ...]) -> DatabaseCursor: ...

    def commit(self) -> None: ...

    def rollback(self) -> None: ...


def persist_s0_results(
    artifacts: S0PipelineArtifacts,
    normalized_artifacts: NormalizedEvidenceArtifacts,
    fusion_result: FusionResult,
    stopping_trace: FusionStoppingTrace,
    runtime_config_snapshot: FusionRuntimeConfigSnapshot,
    fast_result: FastDetectionAdapterResult,
    decision_result: DecisionResult,
    *,
    connection: DatabaseConnection | None = None,
    commit: bool = True,
) -> None:
    """Atomically save First Cycle Runtime, Decision, and snapshot contracts.

    ``commit=False`` leaves a caller-provided transaction open so the saved
    contracts can be committed with another durable record, such as an S3
    worker receipt.
    """
    try:
        _validate_result_scope(
            artifacts,
            normalized_artifacts,
            fusion_result,
            stopping_trace,
            runtime_config_snapshot,
            fast_result,
            decision_result,
        )
        if connection is not None:
            _validate_decision_transaction_contract(connection)
    except Exception:
        if connection is not None:
            try:
                connection.rollback()
            except Exception:
                _LOGGER.exception("First Cycle pre-persistence validation rollback failed")
        raise

    if connection is not None:
        _persist(
            connection,
            artifacts,
            normalized_artifacts,
            fusion_result,
            stopping_trace,
            runtime_config_snapshot,
            fast_result,
            decision_result,
            commit=commit,
        )
        return

    database_config = DatabaseConfig.from_environment()
    with psycopg.connect(database_config.url) as database_connection:
        _validate_decision_transaction_contract(database_connection)
        _persist(
            database_connection,
            artifacts,
            normalized_artifacts,
            fusion_result,
            stopping_trace,
            runtime_config_snapshot,
            fast_result,
            decision_result,
            commit=True,
        )


def resolve_expected_supersedes_decision_id(
    *,
    decision_id: str,
    run_id: str,
    entity_id: str,
    connection: DatabaseConnection | None = None,
) -> str | None:
    """Hybrid 실행 전에 candidate가 기대할 현재 Decision head를 반환한다."""
    if connection is not None:
        try:
            _validate_decision_transaction_contract(connection)
            return _resolve_expected_supersedes_decision_id(
                connection,
                decision_id=decision_id,
                run_id=run_id,
                entity_id=entity_id,
            )
        except Exception:
            try:
                connection.rollback()
            except Exception:
                _LOGGER.exception("Decision lifecycle resolution rollback failed")
            raise

    database_config = DatabaseConfig.from_environment()
    with psycopg.connect(database_config.url) as database_connection:
        _validate_decision_transaction_contract(database_connection)
        return _resolve_expected_supersedes_decision_id(
            database_connection,
            decision_id=decision_id,
            run_id=run_id,
            entity_id=entity_id,
        )


def _resolve_expected_supersedes_decision_id(
    connection: DatabaseConnection,
    *,
    decision_id: str,
    run_id: str,
    entity_id: str,
) -> str | None:
    decision_repository = DecisionRepository(connection)
    existing = decision_repository.get(decision_id)
    if existing is not None:
        _validate_existing_decision_scope(
            existing,
            run_id=run_id,
            entity_id=entity_id,
        )
        return existing.supersedes_decision_id

    current_head = decision_repository.get_current_head(run_id, entity_id)
    return current_head.decision_id if current_head is not None else None


def _persist(
    connection: DatabaseConnection,
    artifacts: S0PipelineArtifacts,
    normalized_artifacts: NormalizedEvidenceArtifacts,
    fusion_result: FusionResult,
    stopping_trace: FusionStoppingTrace,
    runtime_config_snapshot: FusionRuntimeConfigSnapshot,
    fast_result: FastDetectionAdapterResult,
    decision_result: DecisionResult,
    *,
    commit: bool,
) -> None:
    try:
        connection.execute(
            _ACQUIRE_DECISION_ID_LOCK,
            (decision_result.decision_id,),
        )
        connection.execute(
            _ACQUIRE_DECISION_SCOPE_LOCK,
            (decision_result.run_id, decision_result.entity_id),
        )
        decision_repository = DecisionRepository(connection)
        existing = decision_repository.get(decision_result.decision_id)
        if existing is not None:
            _validate_existing_decision_scope(
                existing,
                run_id=decision_result.run_id,
                entity_id=decision_result.entity_id,
            )
            if existing == decision_result:
                if commit:
                    connection.commit()
                return
            raise DecisionIntegrityError(
                "decision_id already exists with different content: "
                f"decision_id={decision_result.decision_id!r}"
            )

        current_head = decision_repository.get_current_head(
            decision_result.run_id,
            decision_result.entity_id,
        )
        actual_head_id = current_head.decision_id if current_head is not None else None
        if actual_head_id != decision_result.supersedes_decision_id:
            raise DecisionConflictError(
                "current Decision head changed: "
                f"expected={decision_result.supersedes_decision_id!r}, "
                f"actual={actual_head_id!r}"
            )

        runtime_snapshot = build_decision_runtime_snapshot(
            decision_result=decision_result,
            detection_result=fast_result.detection_result,
            fusion_result=fusion_result,
            fusion_stopping_trace=stopping_trace,
            fusion_runtime_config_snapshot=runtime_config_snapshot,
        )

        RunRepository(connection).save(artifacts.run_metadata)
        event_repository = EventRepository(connection)
        for event in normalized_artifacts.events:
            event_repository.save(event)
        FusionResultRepository(connection).save(fusion_result)
        FusionStoppingTraceRepository(connection).save(stopping_trace)
        FusionRuntimeConfigSnapshotRepository(connection).save(runtime_config_snapshot)
        DetectionResultRepository(connection).save(fast_result.detection_result)
        decision_repository.save(decision_result)
        DecisionRuntimeSnapshotRepository(connection).save(runtime_snapshot)
        if commit:
            connection.commit()
    except Exception:
        try:
            connection.rollback()
        except Exception:
            _LOGGER.exception("First Cycle persistence rollback failed")
        raise


def _validate_decision_transaction_contract(connection: DatabaseConnection) -> None:
    if connection.autocommit:
        raise RuntimeError("Decision lifecycle requires autocommit disabled")

    row = connection.execute(_SHOW_TRANSACTION_ISOLATION, ()).fetchone()
    if isinstance(row, tuple):
        isolation = row[0]
    elif row:
        isolation = row["transaction_isolation"]
    else:
        isolation = None
    if not isinstance(isolation, str) or isolation.lower().replace("_", " ") != "read committed":
        raise RuntimeError("Decision lifecycle requires READ COMMITTED isolation")


def _validate_existing_decision_scope(
    existing: DecisionResult,
    *,
    run_id: str,
    entity_id: str,
) -> None:
    if existing.run_id != run_id or existing.entity_id != entity_id:
        raise DecisionIntegrityError(
            f"decision_id already exists in a different scope: decision_id={existing.decision_id!r}"
        )


def _validate_result_scope(
    artifacts: S0PipelineArtifacts,
    normalized_artifacts: NormalizedEvidenceArtifacts,
    fusion_result: FusionResult,
    stopping_trace: FusionStoppingTrace,
    runtime_config_snapshot: FusionRuntimeConfigSnapshot,
    fast_result: FastDetectionAdapterResult,
    decision_result: DecisionResult,
) -> None:
    run_id = artifacts.run_metadata.run_id
    if any(event.run_id != run_id for event in normalized_artifacts.events):
        raise ValueError("NormalizedEvent run_id must match RunMetadata before persistence")
    target_host = artifacts.run_metadata.target_host
    if any(event.host_id != target_host for event in normalized_artifacts.events):
        raise ValueError("NormalizedEvent host_id must match RunMetadata target_host")

    results = (
        fusion_result,
        stopping_trace,
        runtime_config_snapshot,
        fast_result.detection_result,
        decision_result,
    )
    if any(result.run_id != run_id for result in results):
        raise ValueError("result run_id must match RunMetadata before persistence")
    if any(result.entity_id != target_host for result in results):
        raise ValueError("result entity_id must match RunMetadata target_host")

    entity_ids = {result.entity_id for result in results}
    if len(entity_ids) != 1:
        raise ValueError("Fusion Runtime, Detection, and Decision results must share one entity_id")

    if stopping_trace.scoring_config_version != fusion_result.scoring_config_version:
        raise ValueError(
            "FusionStoppingTrace scoring_config_version must match FusionResult before persistence"
        )

    if runtime_config_snapshot.config_version != fusion_result.scoring_config_version:
        raise ValueError(
            "FusionRuntimeConfigSnapshot config_version must match "
            "FusionResult scoring_config_version before persistence"
        )
    if runtime_config_snapshot.config_version != stopping_trace.scoring_config_version:
        raise ValueError(
            "FusionRuntimeConfigSnapshot config_version must match "
            "FusionStoppingTrace scoring_config_version before persistence"
        )
    if runtime_config_snapshot.scoring.profile_id != fusion_result.scoring_profile_id:
        raise ValueError(
            "FusionRuntimeConfigSnapshot scoring profile_id must match "
            "FusionResult scoring_profile_id before persistence"
        )
    if runtime_config_snapshot.scoring.method != fusion_result.scoring_method:
        raise ValueError(
            "FusionRuntimeConfigSnapshot scoring method must match "
            "FusionResult scoring_method before persistence"
        )
    if runtime_config_snapshot.scoring.scorer_version != fusion_result.scorer_version:
        raise ValueError(
            "FusionRuntimeConfigSnapshot scoring scorer_version must match "
            "FusionResult scorer_version before persistence"
        )
    if runtime_config_snapshot.model_version != fusion_result.model_version:
        raise ValueError(
            "FusionRuntimeConfigSnapshot model_version must match "
            "FusionResult model_version before persistence"
        )

    if fusion_result.fusion_status == "not_evaluated":
        if stopping_trace.points:
            raise ValueError("not_evaluated FusionResult requires an empty FusionStoppingTrace")
    elif not stopping_trace.points:
        raise ValueError(
            f"{fusion_result.fusion_status} FusionResult requires a non-empty FusionStoppingTrace"
        )


__all__ = [
    "DecisionConflictError",
    "persist_s0_results",
    "resolve_expected_supersedes_decision_id",
]
