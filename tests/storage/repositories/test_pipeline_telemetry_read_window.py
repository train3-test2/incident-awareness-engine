from datetime import UTC, datetime, timedelta

import pytest

from incident_awareness.storage.repositories.pipeline_telemetry_repository import (
    PipelineTelemetryRepository,
)

END = datetime(2026, 10, 14, 1, tzinfo=UTC)


class FakeConnection:
    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple]] = []

    def execute(self, query: str, params: tuple) -> "FakeConnection":
        self.calls.append((query, params))
        return self

    def fetchone(self) -> tuple[dict]:
        return ({"points": []},)


def test_read_window_uses_one_statement_for_counters_and_quality_without_runtime_join() -> None:
    # Given
    connection = FakeConnection()
    repository = PipelineTelemetryRepository(connection)
    start = END - timedelta(seconds=300)

    # When
    result = repository.read_window(start=start, end=END, run_id="RUN-A", entity_id="WIN-B")

    # Then
    assert result == {"points": []}
    assert len(connection.calls) == 1
    query, params = connection.calls[0]
    assert params == (
        None,
        None,
        "RUN-A",
        "RUN-A",
        "WIN-B",
        "WIN-B",
        False,
        start,
        END,
        "RUN-A",
        start,
        END,
        END,
    )
    assert "JOIN scoped e USING (execution_id)" in query
    assert "pipeline_runtime_status" not in query
    assert "sum(b.latency_sum_ns)" in query
    assert "WHERE run_id = %s" in query


@pytest.mark.parametrize(
    "kwargs",
    [
        {"start": END - timedelta(seconds=301), "end": END, "reported": True},
        {"start": END, "end": END, "reported": True},
        {"start": END, "end": END - timedelta(seconds=1), "reported": True},
        {"start": END - timedelta(seconds=1), "end": END, "reported": True, "run_id": "R"},
        {"start": END - timedelta(seconds=1), "end": END, "execution_id": "E", "run_id": "R"},
        {"start": END - timedelta(seconds=1), "end": END},
        {"start": END - timedelta(seconds=1, milliseconds=1), "end": END, "reported": True},
        {"start": END.replace(tzinfo=None) - timedelta(seconds=1), "end": END, "reported": True},
    ],
)
def test_read_window_rejects_invalid_scope_or_range_before_sql(kwargs: dict) -> None:
    # Given
    connection = FakeConnection()

    # When / Then
    with pytest.raises(ValueError):
        PipelineTelemetryRepository(connection).read_window(**kwargs)
    assert connection.calls == []
