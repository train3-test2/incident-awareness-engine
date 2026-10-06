from incident_awareness.storage.repositories.s3_object_receipt_repository import (
    S3ObjectReceiptRepository,
)


def test_reads_a_successful_s3_object_receipt() -> None:
    connection = _Connection(rows=[("RUN-20261005-001",)])

    run_id = S3ObjectReceiptRepository(connection).get_successful_run_id(
        bucket="input-bucket",
        object_key="incoming/first-cycle/sysmon/ING-1/sysmon.jsonl",
        e_tag="etag-1",
    )

    assert run_id == "RUN-20261005-001"
    assert connection.statements[0][1] == (
        "input-bucket",
        "incoming/first-cycle/sysmon/ING-1/sysmon.jsonl",
        "etag-1",
    )


def test_returns_none_when_no_successful_s3_object_receipt_exists() -> None:
    connection = _Connection(rows=[None])

    assert (
        S3ObjectReceiptRepository(connection).get_successful_run_id(
            bucket="input-bucket",
            object_key="incoming/first-cycle/sysmon/ING-1/sysmon.jsonl",
            e_tag="etag-1",
        )
        is None
    )


def test_saves_a_successful_s3_object_receipt_once() -> None:
    connection = _Connection(rows=[("RUN-20261005-001",)])

    inserted = S3ObjectReceiptRepository(connection).save_success(
        bucket="input-bucket",
        object_key="incoming/first-cycle/sysmon/ING-1/sysmon.jsonl",
        e_tag="etag-1",
        run_id="RUN-20261005-001",
    )

    assert inserted is True
    assert "ON CONFLICT (bucket, object_key, e_tag) DO NOTHING" in connection.statements[0][0]


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
