"""Parse the S3 Event messages accepted by the First Cycle SQS Worker."""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import re
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
from urllib.parse import unquote_plus

import boto3
import psycopg
from botocore.client import BaseClient
from botocore.exceptions import BotoCoreError, ClientError
from psycopg import OperationalError

from incident_awareness.pipeline.standalone import run_standalone_sysmon_jsonl
from incident_awareness.storage.config import DatabaseConfig
from incident_awareness.storage.repositories.s3_object_receipt_repository import (
    S3ObjectReceiptRepository,
)

_AUTOMATED_INPUT_PREFIX = "incoming/first-cycle/sysmon/"
_AUTOMATED_INPUT_KEY_PATTERN = re.compile(
    r"^incoming/first-cycle/sysmon/"
    r"(?P<ingest_id>ING-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})/"
    r"sysmon\.jsonl$"
)
_QUEUE_URL_ENV = "INCIDENT_AWARENESS_SQS_QUEUE_URL"
_INPUT_BUCKET_ENV = "INCIDENT_AWARENESS_S3_INPUT_BUCKET"
_WORKER_VISIBILITY_TIMEOUT_SECONDS = 3600
_WORKER_LONG_POLL_SECONDS = 20

_LOGGER = logging.getLogger(__name__)
_PERMANENT_S3_ERROR_CODES = frozenset({"AccessDenied", "NoSuchBucket", "NoSuchKey", "403", "404"})
_ACQUIRE_S3_OBJECT_RECEIPT_LOCK = "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))"


class PermanentWorkerError(Exception):
    """An input error that cannot succeed without an external correction."""


class RetryableWorkerError(Exception):
    """An operational error that may succeed on a later SQS delivery."""


class SuccessfulReceiptStore(Protocol):
    """Durably track immutable S3 object versions processed by the Worker."""

    def acquire_execution(self, input_object: S3SysmonInput) -> str | None: ...

    def save_success(self, input_object: S3SysmonInput, *, run_id: str) -> None: ...

    def release_execution(self) -> None: ...

    def rollback(self) -> None: ...


@dataclass(frozen=True, slots=True)
class S3SysmonInput:
    """One validated Sysmon JSONL object announced through SQS."""

    bucket: str
    key: str
    ingest_id: str
    e_tag: str
    sequencer: str


class _PostgresSuccessfulReceiptStore:
    """Commit successful Worker receipts with the active Pipeline transaction."""

    def __init__(self, connection: psycopg.Connection[tuple[object, ...]]) -> None:
        self._connection = connection
        self._repository = S3ObjectReceiptRepository(connection)

    def acquire_execution(self, input_object: S3SysmonInput) -> str | None:
        self._connection.execute(
            _ACQUIRE_S3_OBJECT_RECEIPT_LOCK,
            (_receipt_lock_key(input_object),),
        )
        return self._repository.get_successful_run_id(
            bucket=input_object.bucket,
            object_key=input_object.key,
            e_tag=input_object.e_tag,
        )

    def save_success(self, input_object: S3SysmonInput, *, run_id: str) -> None:
        self._repository.save_success(
            bucket=input_object.bucket,
            object_key=input_object.key,
            e_tag=input_object.e_tag,
            run_id=run_id,
        )
        self._connection.commit()

    def release_execution(self) -> None:
        self._connection.commit()

    def rollback(self) -> None:
        self._connection.rollback()


def parse_s3_sysmon_inputs(message_body: str, *, expected_bucket: str) -> tuple[S3SysmonInput, ...]:
    """Parse a direct S3 Event Notification body into validated Worker inputs.

    S3 may combine more than one object record into a notification. Every
    record must therefore satisfy the same bucket, event-type, and object-key
    contract before the Worker accepts the message.
    """
    if not expected_bucket.strip():
        raise ValueError("expected_bucket must be non-blank")

    try:
        payload = json.loads(message_body)
    except json.JSONDecodeError as error:
        raise ValueError("SQS message body must be valid JSON") from error
    if not isinstance(payload, Mapping):
        raise ValueError("SQS message body must be a JSON object")  # noqa: TRY004

    records = payload.get("Records")
    if not isinstance(records, Sequence) or isinstance(records, (str, bytes)) or not records:
        raise ValueError("S3 Event Notification must contain at least one Records entry")

    return tuple(_parse_s3_record(record, expected_bucket=expected_bucket) for record in records)


def build_parser() -> argparse.ArgumentParser:
    """Build the SQS Worker command-line contract."""
    parser = argparse.ArgumentParser(
        prog="incident-awareness-sqs-worker",
        description="Poll SQS and run standalone First Cycle for uploaded Sysmon JSONL files.",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Poll SQS once and exit after processing at most one message.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the SQS Worker using its ECS-provided environment configuration."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    namespace = build_parser().parse_args(argv)
    database_config = DatabaseConfig.from_environment()
    with psycopg.connect(database_config.url, autocommit=False) as connection:

        def run_standalone(sysmon_jsonl_path: Path, output_root: Path) -> str:
            execution = run_standalone_sysmon_jsonl(
                sysmon_jsonl_path=sysmon_jsonl_path,
                output_root=output_root,
                connection=connection,
            )
            return execution.summary.run_id

        return run_worker(
            queue_url=_required_environment(_QUEUE_URL_ENV),
            expected_bucket=_required_environment(_INPUT_BUCKET_ENV),
            sqs_client=boto3.client("sqs"),
            s3_client=boto3.client("s3"),
            run_standalone=run_standalone,
            receipt_store=_PostgresSuccessfulReceiptStore(connection),
            once=namespace.once,
        )


def run_worker(
    *,
    queue_url: str,
    expected_bucket: str,
    sqs_client: BaseClient,
    s3_client: BaseClient,
    run_standalone: Callable[[Path, Path], str],
    receipt_store: SuccessfulReceiptStore | None = None,
    once: bool = False,
) -> int:
    """Poll one SQS message at a time and delete only successful messages."""
    while True:
        response = sqs_client.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=1,
            WaitTimeSeconds=_WORKER_LONG_POLL_SECONDS,
            VisibilityTimeout=_WORKER_VISIBILITY_TIMEOUT_SECONDS,
        )
        messages = response.get("Messages", [])
        if not isinstance(messages, Sequence) or isinstance(messages, (str, bytes)):
            raise TypeError("SQS receive response Messages must be a sequence")

        for message in messages:
            try:
                _process_message(
                    message,
                    expected_bucket=expected_bucket,
                    s3_client=s3_client,
                    run_standalone=run_standalone,
                    receipt_store=receipt_store,
                )
            except PermanentWorkerError:
                _rollback_receipt_store(receipt_store)
                _LOGGER.exception(
                    "First Cycle Worker rejected permanent input error; retaining for DLQ"
                )
                continue
            except RetryableWorkerError:
                _rollback_receipt_store(receipt_store)
                _LOGGER.exception(
                    "First Cycle Worker failed transiently; retaining SQS message for retry"
                )
                continue
            except Exception:
                _rollback_receipt_store(receipt_store)
                _LOGGER.exception(
                    "First Cycle Worker failed unexpectedly; retaining SQS message for retry"
                )
                continue

            receipt_handle = _message_string(message, "ReceiptHandle")
            sqs_client.delete_message(QueueUrl=queue_url, ReceiptHandle=receipt_handle)
            _LOGGER.info("Completed and deleted SQS message")

        if once:
            return 0


def _process_message(
    message: object,
    *,
    expected_bucket: str,
    s3_client: BaseClient,
    run_standalone: Callable[[Path, Path], str],
    receipt_store: SuccessfulReceiptStore | None = None,
) -> None:
    if not isinstance(message, Mapping):
        raise ValueError("SQS message must be a JSON object")  # noqa: TRY004
    try:
        inputs = parse_s3_sysmon_inputs(
            _message_string(message, "Body"), expected_bucket=expected_bucket
        )
    except ValueError as error:
        raise PermanentWorkerError(str(error)) from error

    with tempfile.TemporaryDirectory(prefix="incident-awareness-sqs-worker-") as directory:
        work_root = Path(directory)
        for input_object in _unique_inputs(inputs):
            prior_run_id = (
                receipt_store.acquire_execution(input_object) if receipt_store is not None else None
            )
            if prior_run_id is not None:
                _log_input_status("skipped", input_uri=_s3_uri(input_object), run_id=prior_run_id)
                receipt_store.release_execution()
                continue
            input_dir = _input_directory(work_root, input_object)
            input_dir.mkdir()
            sysmon_jsonl_path = input_dir / "sysmon.jsonl"
            input_uri = _s3_uri(input_object)
            _log_input_status("started", input_uri=input_uri)
            try:
                _download_sysmon_jsonl(s3_client, input_object, sysmon_jsonl_path)
                try:
                    run_id = run_standalone(sysmon_jsonl_path, input_dir / "output")
                except ValueError as error:
                    raise PermanentWorkerError(str(error)) from error
                except (OperationalError, OSError) as error:
                    raise RetryableWorkerError(str(error)) from error
                if not run_id.strip():
                    raise RetryableWorkerError("standalone First Cycle returned a blank run_id")
            except Exception:
                _log_input_status("failed", input_uri=input_uri)
                raise
            else:
                if receipt_store is not None:
                    receipt_store.save_success(input_object, run_id=run_id)
                _log_input_status("succeeded", input_uri=input_uri, run_id=run_id)


def _unique_inputs(inputs: Sequence[S3SysmonInput]) -> tuple[S3SysmonInput, ...]:
    """Keep one input per immutable S3 object version in an SQS message.

    S3 event notifications are at-least-once.  The immutable object identity is
    the bucket, decoded key, and ETag; the sequencer describes event ordering
    and is intentionally not part of that identity.  Cross-message delivery
    deduplication is handled by the Worker receipt policy.
    """
    unique_inputs: list[S3SysmonInput] = []
    seen: set[tuple[str, str, str]] = set()
    for input_object in inputs:
        identity = (input_object.bucket, input_object.key, input_object.e_tag)
        if identity not in seen:
            seen.add(identity)
            unique_inputs.append(input_object)
    return tuple(unique_inputs)


def _input_directory(work_root: Path, input_object: S3SysmonInput) -> Path:
    """Return a safe, per-object-version workspace directory."""
    e_tag_digest = hashlib.sha256(input_object.e_tag.encode("utf-8")).hexdigest()[:16]
    return work_root / f"{input_object.ingest_id}-{e_tag_digest}"


def _download_sysmon_jsonl(
    s3_client: BaseClient,
    input_object: S3SysmonInput,
    destination: Path,
) -> None:
    try:
        s3_client.download_file(input_object.bucket, input_object.key, str(destination))
    except ClientError as error:
        error_code = str(error.response.get("Error", {}).get("Code", ""))
        if error_code in _PERMANENT_S3_ERROR_CODES:
            raise PermanentWorkerError(
                f"S3 object cannot be read for {input_object.bucket}/{input_object.key}: {error_code}"
            ) from error
        raise RetryableWorkerError(
            f"S3 download failed for {input_object.bucket}/{input_object.key}: {error_code}"
        ) from error
    except BotoCoreError as error:
        raise RetryableWorkerError(
            f"S3 download failed for {input_object.bucket}/{input_object.key}"
        ) from error


def _s3_uri(input_object: S3SysmonInput) -> str:
    return f"s3://{input_object.bucket}/{input_object.key}"


def _receipt_lock_key(input_object: S3SysmonInput) -> str:
    return f"{input_object.bucket}\x00{input_object.key}\x00{input_object.e_tag}"


def _log_input_status(status: str, *, input_uri: str, run_id: str | None = None) -> None:
    payload: dict[str, str] = {
        "event": "first_cycle_worker_input",
        "input_s3_uri": input_uri,
        "status": status,
    }
    if run_id is not None:
        payload["run_id"] = run_id
    _LOGGER.info("%s", json.dumps(payload, sort_keys=True))


def _rollback_receipt_store(receipt_store: SuccessfulReceiptStore | None) -> None:
    if receipt_store is not None:
        receipt_store.rollback()


def _message_string(message: Mapping[str, object], name: str) -> str:
    value = message.get(name)
    if not isinstance(value, str) or not value:
        raise ValueError(f"SQS message {name} must be a non-blank string")
    return value


def _required_environment(name: str) -> str:
    value = os.environ.get(name)
    if not value or not value.strip():
        raise ValueError(f"{name} must be configured")
    return value


def _parse_s3_record(record: object, *, expected_bucket: str) -> S3SysmonInput:
    if not isinstance(record, Mapping):
        raise ValueError("S3 Event Notification record must be a JSON object")  # noqa: TRY004
    if record.get("eventSource") != "aws:s3":
        raise ValueError("SQS message eventSource must be aws:s3")

    event_name = record.get("eventName")
    if not isinstance(event_name, str) or not event_name.startswith("ObjectCreated:"):
        raise ValueError("SQS message eventName must be an S3 ObjectCreated event")

    s3 = _required_mapping(record, "s3")
    bucket = _required_string(_required_mapping(s3, "bucket"), "name")
    if bucket != expected_bucket:
        raise ValueError("SQS message bucket does not match the configured input bucket")

    object_metadata = _required_mapping(s3, "object")
    encoded_key = _required_string(object_metadata, "key")
    key = unquote_plus(encoded_key)
    match = _AUTOMATED_INPUT_KEY_PATTERN.fullmatch(key)
    if match is None:
        raise ValueError(
            f"SQS message object key must use {_AUTOMATED_INPUT_PREFIX}ING-<uuidv4>/sysmon.jsonl"
        )

    return S3SysmonInput(
        bucket=bucket,
        key=key,
        ingest_id=match["ingest_id"],
        e_tag=_required_string(object_metadata, "eTag"),
        sequencer=_required_string(object_metadata, "sequencer"),
    )


def _required_mapping(value: Mapping[str, object], name: str) -> Mapping[str, object]:
    nested = value.get(name)
    if not isinstance(nested, Mapping):
        raise ValueError(f"SQS message {name} must be a JSON object")  # noqa: TRY004
    return nested


def _required_string(value: Mapping[str, object], name: str) -> str:
    nested = value.get(name)
    if not isinstance(nested, str) or not nested.strip():
        raise ValueError(f"SQS message {name} must be a non-blank string")
    return nested


__all__ = [
    "PermanentWorkerError",
    "RetryableWorkerError",
    "S3SysmonInput",
    "SuccessfulReceiptStore",
    "build_parser",
    "main",
    "parse_s3_sysmon_inputs",
    "run_worker",
]


if __name__ == "__main__":
    raise SystemExit(main())
