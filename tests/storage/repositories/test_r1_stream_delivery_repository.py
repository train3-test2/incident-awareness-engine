import pytest

from incident_awareness.common.models.r1_stream import R1StreamPartition
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
        R1StreamDeliveryRepository(connection).save_watermark(
            partition=_partition(), watermark_id="WM-002", sequence=2, content_sha256="a" * 64
        )


def test_recovers_an_exact_run_close_replay() -> None:
    connection = _Connection(rows=[None, ("CLOSE-001", "a" * 64)])

    assert not R1StreamDeliveryRepository(connection).save_run_close(
        run_id="RUN-20261012-001", close_id="CLOSE-001", content_sha256="a" * 64
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
