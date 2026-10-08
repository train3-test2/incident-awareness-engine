"""Materialize the configured EvaluationSnapshot before starting Dashboard."""

from __future__ import annotations

import logging
import os
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
from urllib.parse import urlparse

import boto3

from incident_awareness.dashboard.evaluation_read_model import (
    EVALUATION_SNAPSHOT_PATH_ENV,
    evaluation_snapshot_path_from_environment,
)

_LOGGER = logging.getLogger(__name__)
EVALUATION_SNAPSHOT_S3_URI_ENV = "INCIDENT_AWARENESS_EVALUATION_SNAPSHOT_S3_URI"
_UVICORN_ARGUMENTS = (
    "uvicorn",
    "incident_awareness.dashboard.api.app:app",
    "--host",
    "0.0.0.0",
    "--port",
    "8080",
)


class S3DownloadClient(Protocol):
    """The exact-object S3 operation required by Dashboard startup."""

    def download_file(self, bucket: str, key: str, filename: str) -> None: ...


@dataclass(frozen=True, slots=True)
class S3EvaluationSnapshotLocation:
    """One exact EvaluationSnapshot object in S3."""

    bucket: str
    key: str


def parse_evaluation_snapshot_s3_uri(value: str) -> S3EvaluationSnapshotLocation:
    """Parse an exact ``s3://<bucket>/<object-key>`` source URI."""
    parsed = urlparse(value)
    if (
        parsed.scheme != "s3"
        or not parsed.netloc
        or parsed.params
        or parsed.query
        or parsed.fragment
        or parsed.netloc != parsed.hostname
        or any(character.isspace() for character in parsed.netloc)
    ):
        raise ValueError(f"{EVALUATION_SNAPSHOT_S3_URI_ENV} must be an exact S3 object URI")

    key = parsed.path.removeprefix("/")
    key_parts = key.split("/")
    if (
        not key
        or key.endswith("/")
        or any(not part or part in (".", "..") for part in key_parts)
        or "\\" in key
    ):
        raise ValueError(f"{EVALUATION_SNAPSHOT_S3_URI_ENV} must identify one S3 object")

    return S3EvaluationSnapshotLocation(bucket=parsed.netloc, key=key)


def materialize_evaluation_snapshot(
    location: S3EvaluationSnapshotLocation,
    target: Path,
    *,
    s3_client: S3DownloadClient | None = None,
) -> None:
    """Download one S3 object and atomically publish its bytes at ``target``."""
    client = s3_client or boto3.client("s3")
    temporary_path: Path | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            dir=target.parent,
            prefix=f".{target.name}.",
            suffix=".download",
        )
        os.close(descriptor)
        temporary_path = Path(temporary_name)
        client.download_file(location.bucket, location.key, str(temporary_path))
        temporary_path.replace(target)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def prepare_evaluation_snapshot(
    environment: Mapping[str, str] | None = None,
    *,
    s3_client: S3DownloadClient | None = None,
) -> bool:
    """Best-effort materialization that leaves no stale target after failure."""
    values = os.environ if environment is None else environment
    target: Path | None = None
    try:
        target = evaluation_snapshot_path_from_environment(values)
        source = _required_environment(values, EVALUATION_SNAPSHOT_S3_URI_ENV)
        location = parse_evaluation_snapshot_s3_uri(source)
        materialize_evaluation_snapshot(location, target, s3_client=s3_client)
    except Exception:
        if target is not None:
            try:
                target.unlink(missing_ok=True)
            except OSError:
                _LOGGER.exception("Failed to remove stale EvaluationSnapshot target")
        _LOGGER.exception("EvaluationSnapshot materialization failed")
        return False

    _LOGGER.info("EvaluationSnapshot materialization completed")
    return True


def start_dashboard_server() -> None:
    """Replace this process with the Dashboard Uvicorn server."""
    os.execvp(_UVICORN_ARGUMENTS[0], list(_UVICORN_ARGUMENTS))


def main() -> None:
    """Prepare the optional snapshot and always continue to Dashboard startup."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    prepared = False
    try:
        prepared = prepare_evaluation_snapshot()
    except Exception:
        _LOGGER.exception("Unexpected EvaluationSnapshot startup failure")
    if not prepared:
        os.environ.pop(EVALUATION_SNAPSHOT_PATH_ENV, None)
    start_dashboard_server()


def _required_environment(environment: Mapping[str, str], name: str) -> str:
    value = environment.get(name)
    if value is None or not value.strip() or value != value.strip():
        raise ValueError(f"{name} must be a non-blank environment variable")
    return value


if __name__ == "__main__":
    main()
