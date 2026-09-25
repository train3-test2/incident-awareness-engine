"""Run one First Cycle pipeline invocation from an S3 input prefix in ECS."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse

import boto3
from botocore.client import BaseClient
from pydantic import ValidationError

from incident_awareness.common.models.run import RunMetadata
from incident_awareness.pipeline.__main__ import main as pipeline_main

_LOGGER = logging.getLogger(__name__)
_INPUT_ROOT = Path("/inputs")
_S3_INPUT_URI_ENV = "INCIDENT_AWARENESS_S3_INPUT_URI"
_ENTITY_ID_ENV = "INCIDENT_AWARENESS_ENTITY_ID"
_DECISION_ID_ENV = "INCIDENT_AWARENESS_DECISION_ID"
_DECISION_CONFIG_VERSION_ENV = "INCIDENT_AWARENESS_DECISION_CONFIG_VERSION"


@dataclass(frozen=True, slots=True)
class S3InputLocation:
    """A First Cycle Run-specific S3 prefix."""

    bucket: str
    prefix: str
    run_id: str


def main() -> int:
    """Download an S3 First Cycle input prefix and invoke the pipeline CLI."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    location = parse_s3_input_location(_required_environment(_S3_INPUT_URI_ENV))
    download_s3_inputs(location, _INPUT_ROOT)
    _validate_downloaded_run_metadata(_INPUT_ROOT, location.run_id)

    return pipeline_main(
        [
            "--run-metadata",
            str(_INPUT_ROOT / "run_metadata.json"),
            "--manifest",
            str(_INPUT_ROOT / "manifest.json"),
            "--sysmon-jsonl",
            str(_INPUT_ROOT / "telemetry" / "sysmon-0001.jsonl"),
            "--fast-hits",
            str(_INPUT_ROOT / "fast" / "hits.jsonl"),
            "--fast-trace",
            str(_INPUT_ROOT / "fast" / "trace.json"),
            "--fast-selection",
            str(_INPUT_ROOT / "fast" / "selection.json"),
            "--fusion-config",
            "/app/configs/fusion/fusion_config_s0_pair_v0.1.yaml",
            "--entity-id",
            _required_environment(_ENTITY_ID_ENV),
            "--decision-id",
            _required_environment(_DECISION_ID_ENV),
            "--decision-config-version",
            _required_environment(_DECISION_CONFIG_VERSION_ENV),
        ]
    )


def parse_s3_input_location(value: str) -> S3InputLocation:
    """Parse only the documented s3://<bucket>/first-cycle/<run_id>/ form."""
    parsed = urlparse(value)
    if (
        parsed.scheme != "s3"
        or not parsed.netloc
        or parsed.params
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("INCIDENT_AWARENESS_S3_INPUT_URI must be an S3 URI")

    parts = PurePosixPath(parsed.path.lstrip("/")).parts
    if len(parts) != 2 or parts[0] != "first-cycle" or not parts[1]:
        raise ValueError(
            "INCIDENT_AWARENESS_S3_INPUT_URI must use s3://<bucket>/first-cycle/<run_id>/"
        )

    return S3InputLocation(
        bucket=parsed.netloc,
        prefix=f"first-cycle/{parts[1]}/",
        run_id=parts[1],
    )


def download_s3_inputs(
    location: S3InputLocation,
    destination: Path,
    *,
    s3_client: BaseClient | None = None,
) -> None:
    """Download every object under one approved S3 prefix into ``destination``."""
    client = s3_client or boto3.client("s3")
    paginator = client.get_paginator("list_objects_v2")
    downloaded_count = 0
    for page in paginator.paginate(Bucket=location.bucket, Prefix=location.prefix):
        for item in page.get("Contents", []):
            key = item.get("Key")
            if not isinstance(key, str):
                raise TypeError("S3 list response contains an invalid object key")
            if key == location.prefix:
                continue

            relative_path = _relative_object_path(key, location.prefix)
            target = destination.joinpath(*relative_path.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            temporary_target = target.with_name(f"{target.name}.download")
            client.download_file(location.bucket, key, str(temporary_target))
            temporary_target.replace(target)
            downloaded_count += 1

    if downloaded_count == 0:
        raise ValueError(
            f"S3 input prefix contains no files: s3://{location.bucket}/{location.prefix}"
        )

    _LOGGER.info(
        "Downloaded First Cycle input artifacts: bucket=%s prefix=%s files=%d",
        location.bucket,
        location.prefix,
        downloaded_count,
    )


def _relative_object_path(key: str, prefix: str) -> PurePosixPath:
    if not key.startswith(prefix):
        raise ValueError("S3 list response returned an object outside the requested prefix")

    relative_path = PurePosixPath(key.removeprefix(prefix))
    if not relative_path.parts or any(part in (".", "..") for part in relative_path.parts):
        raise ValueError("S3 input object key must resolve to a file below the input prefix")
    return relative_path


def _validate_downloaded_run_metadata(destination: Path, expected_run_id: str) -> None:
    path = destination / "run_metadata.json"
    try:
        run_metadata = RunMetadata.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValidationError) as error:
        raise ValueError(f"S3 input run_metadata is invalid: {path}") from error

    if run_metadata.run_id != expected_run_id:
        raise ValueError(
            "S3 input prefix run_id must match run_metadata run_id: "
            f"{expected_run_id!r} != {run_metadata.run_id!r}"
        )


def _required_environment(name: str) -> str:
    value = os.environ.get(name)
    if value is None or not value.strip() or value != value.strip():
        raise ValueError(f"{name} must be a non-blank environment variable")
    return value


if __name__ == "__main__":
    raise SystemExit(main())
