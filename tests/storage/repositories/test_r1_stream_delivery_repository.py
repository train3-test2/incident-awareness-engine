import pytest

from incident_awareness.common.models.r1_stream import (
    R1FinalPartitionWatermark,
    R1SourceWatermark,
    R1StreamPartition,
)
from incident_awareness.storage.repositories.r1_stream_delivery_repository import (
    R1AcceptedRunCloseReceipt,
    R1StreamDeliveryRepository,
)


def _partition() -> R1StreamPartition:
    return R1StreamPartition(
        run_id="RUN-20261012-001",
        host_id="WIN-01",
        source="sysmon",
        source_channel="Microsoft-Windows-Sysmon/Operational",
    )


def test_saves_a_new_chunk_once() -> None:
    connection = _Connection(rows=[("CHK-001",)])

    assert R1StreamDeliveryRepository(connection).save_chunk(
        partition=_partition(), chunk_id="CHK-001", sequence=1, content_sha256="a" * 64
    )

    chunk_insert_query = next(
        query for query, _ in connection.statements if "INSERT INTO r1_stream_chunks" in query
    )
    assert "ON CONFLICT DO NOTHING" in chunk_insert_query


def test_recovers_an_exact_chunk_replay_after_a_worker_restart() -> None:
    connection = _Connection(rows=[None, None, ("CHK-001", 1, "a" * 64)])

    assert not R1StreamDeliveryRepository(connection).save_chunk(
        partition=_partition(), chunk_id="CHK-001", sequence=1, content_sha256="a" * 64
    )


def test_rejects_a_chunk_identity_reused_with_different_content() -> None:
    connection = _Connection(rows=[None, None, ("CHK-001", 1, "a" * 64)])

    with pytest.raises(ValueError, match="identity conflicts"):
        R1StreamDeliveryRepository(connection).save_chunk(
            partition=_partition(), chunk_id="CHK-001", sequence=1, content_sha256="b" * 64
        )


def test_rejects_an_event_identity_reused_with_different_content() -> None:
    connection = _Connection(rows=[None, None, ("evt-001", "a" * 64)])

    with pytest.raises(ValueError, match="event identity conflicts"):
        R1StreamDeliveryRepository(connection).save_events(
            partition=_partition(),
            event_content_sha256s=(("evt-001", "b" * 64),),
        )


def test_returns_only_new_event_ids_for_an_exact_event_replay() -> None:
    connection = _Connection(rows=[("evt-001",), None, ("evt-002", "b" * 64)])

    new_event_ids = R1StreamDeliveryRepository(connection).save_events(
        partition=_partition(),
        event_content_sha256s=(("evt-001", "a" * 64), ("evt-002", "b" * 64)),
    )

    assert new_event_ids == ("evt-001",)


def test_allows_an_exact_chunk_replay_after_its_run_is_closed() -> None:
    connection = _Connection(rows=[(1,), ("CHK-001", 1, "a" * 64)])

    assert not R1StreamDeliveryRepository(connection).save_chunk(
        partition=_partition(), chunk_id="CHK-001", sequence=1, content_sha256="a" * 64
    )


def test_inspects_new_events_against_the_latest_durable_watermark_before_writes() -> None:
    watermark = _watermark(covered_through_chunk_sequence=1)
    connection = _Connection(
        rows=[
            None,
            None,
            None,
            None,
            _accepted_watermark_row(watermark),
            [(1,)],
        ]
    )

    admission = R1StreamDeliveryRepository(connection).inspect_chunk_admission(
        partition=_partition(),
        chunk_id="CHK-002",
        sequence=2,
        content_sha256="b" * 64,
        event_content_sha256s=(("evt-002", "c" * 64),),
    )

    assert not admission.is_exact_chunk_replay
    assert admission.new_event_ids == ("evt-002",)
    assert admission.latest_watermark is not None
    assert admission.latest_watermark.watermark_id == watermark.watermark_id
    assert any("FOR UPDATE" in query for query, _ in connection.statements)
    assert "FOR KEY SHARE" in connection.statements[-1][0]
    assert not any("INSERT INTO" in query for query, _ in connection.statements)


def test_defers_a_watermark_until_its_covered_chunks_are_durable() -> None:
    watermark = _watermark(covered_through_chunk_sequence=1)
    connection = _Connection(rows=[None, None, None, None, _accepted_watermark_row(watermark), []])

    admission = R1StreamDeliveryRepository(connection).inspect_chunk_admission(
        partition=_partition(),
        chunk_id="CHK-001",
        sequence=1,
        content_sha256="a" * 64,
        event_content_sha256s=(("evt-001", "b" * 64),),
    )

    assert admission.latest_watermark is None


def test_rejects_a_new_chunk_after_its_run_is_closed() -> None:
    connection = _Connection(rows=[(1,), None, None])

    with pytest.raises(ValueError, match="new chunk after run_closed"):
        R1StreamDeliveryRepository(connection).save_chunk(
            partition=_partition(), chunk_id="CHK-002", sequence=2, content_sha256="b" * 64
        )


def test_allows_only_exact_event_replays_after_its_run_is_closed() -> None:
    repository = R1StreamDeliveryRepository(_Connection(rows=[(1,), ("evt-001", "a" * 64)]))

    assert (
        repository.save_events(
            partition=_partition(), event_content_sha256s=(("evt-001", "a" * 64),)
        )
        == ()
    )

    with pytest.raises(ValueError, match="new event after run_closed"):
        R1StreamDeliveryRepository(_Connection(rows=[(1,), None])).save_events(
            partition=_partition(), event_content_sha256s=(("evt-002", "b" * 64),)
        )


def test_rejects_a_watermark_sequence_reused_by_another_identity() -> None:
    existing = _watermark(watermark_id="WM-001")
    connection = _Connection(
        rows=[
            None,
            _accepted_watermark_row(existing),
            None,
            (existing.watermark_id, existing.watermark_sequence, "b" * 64),
        ]
    )

    with pytest.raises(ValueError, match="sequence conflicts"):
        R1StreamDeliveryRepository(connection).save_watermark(_watermark(), content_sha256="a" * 64)


def test_recovers_an_exact_watermark_replay_after_a_worker_restart() -> None:
    watermark = _watermark()
    connection = _Connection(
        rows=[
            None,
            _accepted_watermark_row(watermark),
            (watermark.watermark_id, 2, "a" * 64),
        ]
    )

    assert not R1StreamDeliveryRepository(connection).save_watermark(
        watermark, content_sha256="a" * 64
    )


@pytest.mark.parametrize(
    ("updates", "error"),
    [
        ({"watermark_sequence": 1}, "sequence must advance"),
        ({"watermark_at": "2026-10-12T01:02:03.455Z"}, "watermark_at must not move backwards"),
        ({"allowed_lateness_ms": 30_001}, "allowed_lateness_ms must remain constant"),
    ],
)
def test_rejects_a_watermark_that_regresses_or_mutates_the_durable_frontier(
    updates: dict[str, object], error: str
) -> None:
    current = _watermark()
    candidate = _watermark(**{"watermark_id": "WM-003", "watermark_sequence": 3, **updates})
    connection = _Connection(rows=[None, _accepted_watermark_row(current), None, None])

    with pytest.raises(ValueError, match=error):
        R1StreamDeliveryRepository(connection).save_watermark(candidate, content_sha256="b" * 64)

    assert "pg_advisory_xact_lock" in connection.statements[0][0]
    assert "FROM r1_stream_run_closes" in connection.statements[1][0]
    assert "FOR UPDATE" in connection.statements[3][0]


def test_rejects_a_watermark_after_its_run_is_closed() -> None:
    connection = _Connection(rows=[(1,), None, None])

    with pytest.raises(ValueError, match="after run_closed"):
        R1StreamDeliveryRepository(connection).save_watermark(_watermark(), content_sha256="a" * 64)

    assert "pg_advisory_xact_lock" in connection.statements[0][0]


def test_allows_an_exact_watermark_replay_after_its_run_is_closed() -> None:
    watermark = _watermark()
    connection = _Connection(
        rows=[
            (1,),
            _accepted_watermark_row(watermark),
            (watermark.watermark_id, watermark.watermark_sequence, "a" * 64),
        ]
    )

    assert not R1StreamDeliveryRepository(connection).save_watermark(
        watermark, content_sha256="a" * 64
    )


def test_chunk_identity_is_scoped_to_its_partition() -> None:
    connection = _Connection(rows=[("CHK-001",), ("CHK-001",)])
    repository = R1StreamDeliveryRepository(connection)
    other_partition = R1StreamPartition(
        run_id="RUN-20261012-001",
        host_id="WIN-02",
        source="sysmon",
        source_channel="Microsoft-Windows-Sysmon/Operational",
    )

    assert repository.save_chunk(
        partition=_partition(), chunk_id="CHK-001", sequence=1, content_sha256="a" * 64
    )
    assert repository.save_chunk(
        partition=other_partition, chunk_id="CHK-001", sequence=1, content_sha256="a" * 64
    )

    chunk_insert_params = [
        params for query, params in connection.statements if "INSERT INTO r1_stream_chunks" in query
    ]
    assert chunk_insert_params[0][:4] != chunk_insert_params[1][:4]


def test_recovers_an_exact_run_close_replay() -> None:
    connection = _Connection(rows=[None, ("CLOSE-001", "a" * 64)])

    assert not R1StreamDeliveryRepository(connection).save_run_close(
        run_id="RUN-20261012-001", close_id="CLOSE-001", content_sha256="a" * 64
    )


def test_loads_the_durable_role3_run_close_receipt() -> None:
    connection = _Connection(rows=[("CLOSE-001", "a" * 64)])

    receipt = R1StreamDeliveryRepository(connection).load_accepted_run_close_receipt(
        "RUN-20261012-001"
    )

    assert receipt == R1AcceptedRunCloseReceipt(
        run_id="RUN-20261012-001",
        close_id="CLOSE-001",
        content_sha256="a" * 64,
    )
    query, params = connection.statements[-1]
    assert "FROM r1_stream_run_closes" in query
    assert params == ("RUN-20261012-001",)


def test_absent_role3_run_close_has_no_acceptance_receipt() -> None:
    connection = _Connection(rows=[None])

    assert (
        R1StreamDeliveryRepository(connection).load_accepted_run_close_receipt("RUN-20261012-001")
        is None
    )


def test_holds_the_same_run_lock_from_close_validation_through_close_recording() -> None:
    watermark = _watermark()
    connection = _Connection(rows=[_accepted_watermark_row(watermark), (1,), ("CLOSE-001",)])
    repository = R1StreamDeliveryRepository(connection)

    repository.assert_final_watermarks_match(_close_final_watermarks())
    assert repository.save_run_close(
        run_id=watermark.partition.run_id,
        close_id="CLOSE-001",
        content_sha256="a" * 64,
    )

    run_lock_queries = [
        query for query, _ in connection.statements if "hashtextextended(%s, 0)" in query
    ]
    assert len(run_lock_queries) == 2


def test_rejects_a_run_close_identity_reused_with_different_content() -> None:
    connection = _Connection(rows=[None, ("CLOSE-001", "a" * 64)])

    with pytest.raises(ValueError, match="identity conflicts"):
        R1StreamDeliveryRepository(connection).save_run_close(
            run_id="RUN-20261012-001", close_id="CLOSE-001", content_sha256="b" * 64
        )


def test_rejects_a_close_when_its_watermark_is_missing_from_the_same_partition() -> None:
    connection = _Connection(rows=[None])

    with pytest.raises(ValueError, match="not accepted for its partition"):
        R1StreamDeliveryRepository(connection).assert_final_watermarks_match(
            _close_final_watermarks()
        )


def test_accepts_a_close_watermark_only_when_every_bound_value_matches() -> None:
    watermark = _watermark()
    connection = _Connection(
        rows=[
            _accepted_watermark_row(watermark),
            (1,),
        ]
    )

    R1StreamDeliveryRepository(connection).assert_final_watermarks_match(_close_final_watermarks())


def test_rejects_a_close_watermark_with_different_frontier_values() -> None:
    watermark = _watermark()
    connection = _Connection(
        rows=[
            (
                watermark.watermark_id,
                watermark.watermark_sequence,
                watermark.watermark_at,
                watermark.allowed_lateness_ms,
                watermark.covered_through_chunk_sequence + 1,
            )
        ]
    )

    with pytest.raises(ValueError, match="does not match"):
        R1StreamDeliveryRepository(connection).assert_final_watermarks_match(
            _close_final_watermarks()
        )


def test_rejects_a_close_that_omits_a_partition_known_from_another_chunk() -> None:
    watermark = _watermark()
    connection = _Connection(rows=[_accepted_watermark_row(watermark), (2,)])

    with pytest.raises(ValueError, match="do not cover every accepted partition"):
        R1StreamDeliveryRepository(connection).assert_final_watermarks_match(
            _close_final_watermarks()
        )

    count_query, count_params = connection.statements[-1]
    assert "FROM r1_stream_chunks" in count_query
    assert "UNION" in count_query
    assert count_params == (watermark.partition.run_id, watermark.partition.run_id)


def test_rejects_a_close_that_references_an_older_partition_watermark() -> None:
    latest = _watermark()
    older = _watermark(
        watermark_id="WM-001",
        watermark_sequence=1,
        watermark_at="2026-10-12T01:02:03.000Z",
        covered_through_chunk_sequence=1,
    )
    connection = _Connection(rows=[_accepted_watermark_row(latest)])

    with pytest.raises(ValueError, match="latest accepted partition watermark"):
        R1StreamDeliveryRepository(connection).assert_final_watermarks_match(
            (_final_watermark(older),)
        )


def _watermark(**updates: object) -> R1SourceWatermark:
    payload: dict[str, object] = {
        "schema": "r1-incremental-stream",
        "contract_version": "v0.1",
        "message_type": "source_watermark",
        "watermark_id": "WM-002",
        "partition": _partition().model_dump(),
        "watermark_sequence": 2,
        "watermark_at": "2026-10-12T01:02:03.456Z",
        "allowed_lateness_ms": 30_000,
        "covered_through_chunk_sequence": 2,
        "emitted_at": "2026-10-12T01:02:04.000Z",
    }
    payload.update(updates)
    return R1SourceWatermark.model_validate(payload)


def _accepted_watermark_row(watermark: R1SourceWatermark) -> tuple[object, ...]:
    return (
        watermark.watermark_id,
        watermark.watermark_sequence,
        watermark.watermark_at,
        watermark.allowed_lateness_ms,
        watermark.covered_through_chunk_sequence,
    )


def _close_final_watermarks() -> tuple[R1FinalPartitionWatermark, ...]:
    watermark = _watermark()
    return (_final_watermark(watermark),)


def _final_watermark(watermark: R1SourceWatermark) -> R1FinalPartitionWatermark:
    return R1FinalPartitionWatermark(
        partition=watermark.partition,
        watermark_id=watermark.watermark_id,
        watermark_sequence=watermark.watermark_sequence,
        watermark_at=watermark.watermark_at,
        allowed_lateness_ms=watermark.allowed_lateness_ms,
        covered_through_chunk_sequence=watermark.covered_through_chunk_sequence,
    )


class _Cursor:
    def __init__(self, row: tuple[object, ...] | list[tuple[object, ...]] | None) -> None:
        self._row = row

    def fetchone(self) -> tuple[object, ...] | None:
        return self._row if isinstance(self._row, tuple) else None

    def fetchall(self) -> list[tuple[object, ...]]:
        return self._row if isinstance(self._row, list) else []


class _Connection:
    def __init__(self, *, rows: list[tuple[object, ...] | list[tuple[object, ...]] | None]) -> None:
        self._rows = rows
        self.statements: list[tuple[str, tuple[object, ...]]] = []

    def execute(self, query: str, params: tuple[object, ...]) -> _Cursor:
        self.statements.append((query, params))
        if "SELECT pg_advisory_xact_lock" in query:
            return _Cursor(None)
        if "SELECT 1\nFROM r1_stream_run_closes" in query:
            if self._rows and self._rows[0] in (None, (1,)):
                return _Cursor(self._rows.pop(0))
            return _Cursor(None)
        return _Cursor(self._rows.pop(0))
