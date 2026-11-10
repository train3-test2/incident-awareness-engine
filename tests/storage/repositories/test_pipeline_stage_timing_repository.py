from datetime import UTC, datetime

import psycopg
import pytest
from pydantic import ValidationError

from incident_awareness.common.models.pipeline_runtime import PipelineStage
from incident_awareness.pipeline.stage_timing import (
    PipelineStageTimingCollector,
    start_stage_timing,
)
from incident_awareness.storage.repositories.pipeline_stage_timing_repository import (
    PipelineStageTimingRepository,
    StageTimingIntegrityError,
)


class Connection:
    def __init__(self, row=None, error=None):
        self.row, self.error = row, error
        self.calls = []

    def execute(self, query, params=()):
        self.calls.append((query, params))
        if self.error:
            raise self.error
        return self

    def fetchone(self):
        return self.row


def snapshot():
    timing = start_stage_timing(PipelineStageTimingCollector())
    timing.finish(timing.begin(PipelineStage.FUSION), failed=False)
    timing.bind(execution_id="fixture", run_id="run", entity_id="entity")
    return timing.snapshot()


def test_repository_uses_model_json_and_does_not_own_commit_or_rollback():
    # Given
    actual = snapshot()
    connection = Connection({"saved": True})
    # When
    assert PipelineStageTimingRepository(connection).save_snapshot(actual)
    # Then
    assert connection.calls[0][1][0].obj == actual.model_dump(mode="json")
    assert not hasattr(connection, "commit") and not hasattr(connection, "rollback")


def test_dictionary_row_factory_is_restored_by_named_fields_not_mapping_order():
    # Given
    actual = snapshot()
    stored_at = datetime(2026, 10, 17, tzinfo=UTC)
    connection = Connection(
        {
            "execution_known": True,
            "persisted_at": stored_at,
            "snapshot": actual.model_dump(mode="json"),
        }
    )
    # When
    restored = PipelineStageTimingRepository(connection).read_execution("fixture")
    # Then
    assert restored == (actual, stored_at, True)


def test_unchecked_model_copy_is_revalidated_before_sql():
    # Given
    invalid = snapshot().model_copy(update={"execution_id": ""})
    connection = Connection()
    # When / Then
    with pytest.raises(ValidationError):
        PipelineStageTimingRepository(connection).save_snapshot(invalid)
    assert connection.calls == []


@pytest.mark.parametrize(
    "error", [psycopg.errors.UniqueViolation("fixture"), psycopg.errors.RaiseException("fixture")]
)
def test_storage_conflict_is_distinct_from_connectivity_error(error):
    # Given
    connection = Connection(error=error)
    # When / Then
    with pytest.raises(StageTimingIntegrityError):
        PipelineStageTimingRepository(connection).save_snapshot(snapshot())


def test_operational_failure_remains_available_for_observer_retry():
    # Given
    error = psycopg.OperationalError("fixture unavailable")
    # When / Then
    with pytest.raises(psycopg.OperationalError) as caught:
        PipelineStageTimingRepository(Connection(error=error)).save_snapshot(snapshot())
    assert caught.value is error


def test_execution_query_is_parameterized_and_missing_attempt_is_not_fabricated():
    # Given
    identifier = "literal'; DROP TABLE ignored; --"
    connection = Connection((None, None, False))
    # When
    assert PipelineStageTimingRepository(connection).read_execution(identifier) == (
        None,
        None,
        False,
    )
    # Then
    query, params = connection.calls[0]
    assert identifier not in query and params == (identifier,) * 3
    connection.row = None
    assert PipelineStageTimingRepository(connection).read_attempt("missing") is None
