from collections.abc import Mapping
from datetime import UTC, datetime

import pytest
from psycopg.types.json import Jsonb

from incident_awareness.common.models.run import RunMetadata, RunType, SchemaVersions
from incident_awareness.storage.repositories.run_repository import (
    _SELECT_RUN_METADATA,
    _UPSERT_RUN,
    RunRepository,
)


class FakeCursor:
    def __init__(self, row: tuple[object, ...] | Mapping[str, object] | None = None) -> None:
        self._row = row

    def fetchone(self) -> tuple[object, ...] | Mapping[str, object] | None:
        return self._row


class FakeConnection:
    def __init__(self, row: tuple[object, ...] | Mapping[str, object] | None = None) -> None:
        self.row = row
        self.statements: list[tuple[str, tuple[object, ...]]] = []
        self.commits = 0

    def execute(self, query: str, params: tuple[object, ...]) -> FakeCursor:
        self.statements.append((query, params))
        return FakeCursor(self.row)

    def commit(self) -> None:
        self.commits += 1


@pytest.fixture
def run_metadata() -> RunMetadata:
    return RunMetadata(
        run_id="RUN-20260911-001",
        scenario_id="scenario-001",
        run_type=RunType.ATTACK,
        target_host="WIN-01",
        start_time=datetime(2026, 9, 11, 1, tzinfo=UTC),
        schema_versions=SchemaVersions(
            run_metadata="v0.2",
            event="v0.2",
            evidence="v0.2",
            fast_hit="v0.2",
            detection_result="v0.2",
            fusion_result="v0.2",
            decision_result="v0.2",
            execution_record="v0.1",
            evaluation_input="v0.1",
        ),
    )


def test_save_upserts_run_metadata_and_commits(run_metadata: RunMetadata) -> None:
    connection = FakeConnection()

    RunRepository(connection).save(run_metadata)

    assert connection.commits == 1
    assert len(connection.statements) == 1
    query, params = connection.statements[0]
    assert query == _UPSERT_RUN
    assert params[:6] == (
        "RUN-20260911-001",
        "scenario-001",
        "attack",
        "WIN-01",
        datetime(2026, 9, 11, 1, tzinfo=UTC),
        None,
    )
    assert isinstance(params[6], Jsonb)
    assert params[6].obj["run_id"] == "RUN-20260911-001"


def test_get_rebuilds_run_metadata_from_json_payload(run_metadata: RunMetadata) -> None:
    connection = FakeConnection((run_metadata.model_dump(mode="json"),))

    stored_run = RunRepository(connection).get(run_metadata.run_id)

    assert stored_run == run_metadata
    assert connection.statements == [(_SELECT_RUN_METADATA, (run_metadata.run_id,))]


def test_get_returns_none_when_run_does_not_exist() -> None:
    connection = FakeConnection()

    assert RunRepository(connection).get("RUN-20260911-001") is None


def test_get_rejects_non_object_metadata() -> None:
    connection = FakeConnection(("not-an-object",))

    with pytest.raises(TypeError, match="JSON 객체"):
        RunRepository(connection).get("RUN-20260911-001")
