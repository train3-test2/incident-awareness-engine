import pytest

from incident_awareness.common.models.r1_stream import (
    R1FinalPartitionWatermark,
    R1SourceWatermark,
    R1StreamPartition,
)
from incident_awareness.storage.repositories.r1_stream_delivery_repository import (
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

    assert "ON CONFLICT DO NOTHING" in connection.statements[0][0]


def test_recovers_an_exact_chunk_replay_after_a_worker_restart() -> None:
    connection = _Connection(rows=[None, ("CHK-001", 1, "a" * 64)])

    assert not R1StreamDeliveryRepository(connection).save_chunk(
        partition=_partition(), chunk_id="CHK-001", sequence=1, content_sha256="a" * 64
    )


def test_rejects_a_chunk_identity_reused_with_different_content() -> None:
    connection = _Connection(rows=[None, ("CHK-001", 1, "a" * 64)])

    with pytest.raises(ValueError, match="identity conflicts"):
        R1StreamDeliveryRepository(connection).save_chunk(
            partition=_partition(), chunk_id="CHK-001", sequence=1, content_sha256="b" * 64
        )


def test_rejects_a_watermark_sequence_reused_by_another_identity() -> None:
    connection = _Connection(rows=[None, None])

    with pytest.raises(ValueError, match="sequence conflicts"):
        R1StreamDeliveryRepository(connection).save_watermark(_watermark(), content_sha256="a" * 64)


def test_recovers_an_exact_watermark_replay_after_a_worker_restart() -> None:
    watermark = _watermark()
    connection = _Connection(rows=[None, (watermark.watermark_id, 2, "a" * 64)])

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

    assert connection.statements[0][1][:4] != connection.statements[1][1][:4]


def test_recovers_an_exact_run_close_replay() -> None:
    connection = _Connection(rows=[None, ("CLOSE-001", "a" * 64)])

    assert not R1StreamDeliveryRepository(connection).save_run_close(
        run_id="RUN-20261012-001", close_id="CLOSE-001", content_sha256="a" * 64
    )


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
            (
                watermark.watermark_id,
                watermark.watermark_sequence,
                watermark.watermark_at,
                watermark.allowed_lateness_ms,
                watermark.covered_through_chunk_sequence,
            )
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


def _watermark() -> R1SourceWatermark:
    return R1SourceWatermark.model_validate(
        {
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
    )


def _close_final_watermarks() -> tuple[R1FinalPartitionWatermark, ...]:
    watermark = _watermark()
    return (
        R1FinalPartitionWatermark(
            partition=watermark.partition,
            watermark_id=watermark.watermark_id,
            watermark_sequence=watermark.watermark_sequence,
            watermark_at=watermark.watermark_at,
            allowed_lateness_ms=watermark.allowed_lateness_ms,
            covered_through_chunk_sequence=watermark.covered_through_chunk_sequence,
        ),
    )


class _Cursor:
    def __init__(self, row: tuple[object, ...] | None) -> None:
        self._row = row

    def fetchone(self) -> tuple[object, ...] | None:
        return self._row


class _Connection:
    def __init__(self, *, rows: list[tuple[object, ...] | None]) -> None:
        self._rows = rows
        self.statements: list[tuple[str, tuple[object, ...]]] = []

    def execute(self, query: str, params: tuple[object, ...]) -> _Cursor:
        self.statements.append((query, params))
        return _Cursor(self._rows.pop(0))
