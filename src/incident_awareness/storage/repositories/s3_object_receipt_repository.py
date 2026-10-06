"""Persist successful S3 object processing receipts for the First Cycle Worker."""

from typing import Protocol


class _Cursor(Protocol):
    def fetchone(self) -> tuple[object, ...] | None: ...


class _Connection(Protocol):
    def execute(self, query: str, params: tuple[object, ...]) -> _Cursor: ...


_SELECT_SUCCESSFUL_RECEIPT = """
SELECT run_id
FROM s3_object_receipts
WHERE bucket = %s AND object_key = %s AND e_tag = %s
"""

_INSERT_SUCCESSFUL_RECEIPT = """
INSERT INTO s3_object_receipts (bucket, object_key, e_tag, run_id)
VALUES (%s, %s, %s, %s)
ON CONFLICT (bucket, object_key, e_tag) DO NOTHING
RETURNING run_id
"""


class S3ObjectReceiptRepository:
    """Read and record successful processing of immutable S3 object versions."""

    def __init__(self, connection: _Connection) -> None:
        self._connection = connection

    def get_successful_run_id(self, *, bucket: str, object_key: str, e_tag: str) -> str | None:
        row = self._connection.execute(
            _SELECT_SUCCESSFUL_RECEIPT,
            (bucket, object_key, e_tag),
        ).fetchone()
        if row is None:
            return None
        run_id = row[0]
        if not isinstance(run_id, str) or not run_id.strip():
            raise TypeError("s3_object_receipts.run_id must be a non-blank string")
        return run_id

    def save_success(
        self,
        *,
        bucket: str,
        object_key: str,
        e_tag: str,
        run_id: str,
    ) -> bool:
        return (
            self._connection.execute(
                _INSERT_SUCCESSFUL_RECEIPT,
                (bucket, object_key, e_tag, run_id),
            ).fetchone()
            is not None
        )


__all__ = ["S3ObjectReceiptRepository"]
