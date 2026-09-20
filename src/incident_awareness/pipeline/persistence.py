"""Persist completed First Cycle pipeline contracts through PostgreSQL repositories."""

from typing import Protocol

import psycopg

from incident_awareness.common.models.fusion import FusionResult
from incident_awareness.common.models.result import DecisionResult
from incident_awareness.integration.fast_hit_handoff import FastDetectionAdapterResult
from incident_awareness.pipeline.event_evidence import NormalizedEvidenceArtifacts
from incident_awareness.pipeline.s0_artifacts import S0PipelineArtifacts
from incident_awareness.storage.config import DatabaseConfig
from incident_awareness.storage.repositories.event_repository import EventRepository
from incident_awareness.storage.repositories.result_repository import (
    DecisionRepository,
    DetectionResultRepository,
    FusionResultRepository,
)
from incident_awareness.storage.repositories.run_repository import RunRepository


class DatabaseConnection(Protocol):
    """Repository operations needed to persist one First Cycle result set."""

    def execute(self, query: str, params: tuple[object, ...]) -> object: ...

    def commit(self) -> None: ...

    def rollback(self) -> None: ...


def persist_s0_results(
    artifacts: S0PipelineArtifacts,
    normalized_artifacts: NormalizedEvidenceArtifacts,
    fusion_result: FusionResult,
    fast_result: FastDetectionAdapterResult,
    decision_result: DecisionResult,
    *,
    connection: DatabaseConnection | None = None,
) -> None:
    """Atomically save Run, Event, Fusion, Detection, and Decision contracts."""
    _validate_result_scope(
        artifacts,
        normalized_artifacts,
        fusion_result,
        fast_result,
        decision_result,
    )

    if connection is not None:
        _persist(
            connection, artifacts, normalized_artifacts, fusion_result, fast_result, decision_result
        )
        return

    database_config = DatabaseConfig.from_environment()
    with psycopg.connect(database_config.url) as database_connection:
        _persist(
            database_connection,
            artifacts,
            normalized_artifacts,
            fusion_result,
            fast_result,
            decision_result,
        )


def _persist(
    connection: DatabaseConnection,
    artifacts: S0PipelineArtifacts,
    normalized_artifacts: NormalizedEvidenceArtifacts,
    fusion_result: FusionResult,
    fast_result: FastDetectionAdapterResult,
    decision_result: DecisionResult,
) -> None:
    try:
        RunRepository(connection).save(artifacts.run_metadata)
        event_repository = EventRepository(connection)
        for event in normalized_artifacts.events:
            event_repository.save(event)
        FusionResultRepository(connection).save(fusion_result)
        DetectionResultRepository(connection).save(fast_result.detection_result)
        DecisionRepository(connection).save(decision_result)
        connection.commit()
    except Exception:
        connection.rollback()
        raise


def _validate_result_scope(
    artifacts: S0PipelineArtifacts,
    normalized_artifacts: NormalizedEvidenceArtifacts,
    fusion_result: FusionResult,
    fast_result: FastDetectionAdapterResult,
    decision_result: DecisionResult,
) -> None:
    run_id = artifacts.run_metadata.run_id
    if any(event.run_id != run_id for event in normalized_artifacts.events):
        raise ValueError("NormalizedEvent run_id must match RunMetadata before persistence")
    target_host = artifacts.run_metadata.target_host
    if any(event.host_id != target_host for event in normalized_artifacts.events):
        raise ValueError("NormalizedEvent host_id must match RunMetadata target_host")

    results = (fusion_result, fast_result.detection_result, decision_result)
    if any(result.run_id != run_id for result in results):
        raise ValueError("result run_id must match RunMetadata before persistence")
    if any(result.entity_id != target_host for result in results):
        raise ValueError("result entity_id must match RunMetadata target_host")

    entity_ids = {result.entity_id for result in results}
    if len(entity_ids) != 1:
        raise ValueError("Fusion, Detection, and Decision results must share one entity_id")


__all__ = ["persist_s0_results"]
