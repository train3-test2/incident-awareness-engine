"""Parse the S3 Event messages accepted by the First Cycle SQS Worker."""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote_plus

import boto3
from botocore.client import BaseClient

from incident_awareness.pipeline.standalone import main as standalone_main

_AUTOMATED_INPUT_PREFIX = "incoming/first-cycle/sysmon/"
_AUTOMATED_INPUT_KEY_PATTERN = re.compile(
    r"^incoming/first-cycle/sysmon/"
    r"(?P<ingest_id>ING-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/"
    r"sysmon\.jsonl$"
)
_QUEUE_URL_ENV = "INCIDENT_AWARENESS_SQS_QUEUE_URL"
_INPUT_BUCKET_ENV = "INCIDENT_AWARENESS_S3_INPUT_BUCKET"
_WORKER_VISIBILITY_TIMEOUT_SECONDS = 3600
_WORKER_LONG_POLL_SECONDS = 20

_LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class S3SysmonInput:
    """One validated Sysmon JSONL object announced through SQS."""

    bucket: str
    key: str
    ingest_id: str
    e_tag: str
    sequencer: str


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
    return run_worker(
        queue_url=_required_environment(_QUEUE_URL_ENV),
        expected_bucket=_required_environment(_INPUT_BUCKET_ENV),
        sqs_client=boto3.client("sqs"),
        s3_client=boto3.client("s3"),
        once=namespace.once,
    )


def run_worker(
    *,
    queue_url: str,
    expected_bucket: str,
    sqs_client: BaseClient,
    s3_client: BaseClient,
    run_standalone: Callable[[Sequence[str]], int] = standalone_main,
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
                )
            except Exception:
                _LOGGER.exception("First Cycle Worker failed; retaining SQS message for retry")
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
    run_standalone: Callable[[Sequence[str]], int],
) -> None:
    if not isinstance(message, Mapping):
        raise ValueError("SQS message must be a JSON object")  # noqa: TRY004
    inputs = parse_s3_sysmon_inputs(
        _message_string(message, "Body"), expected_bucket=expected_bucket
    )

    with tempfile.TemporaryDirectory(prefix="incident-awareness-sqs-worker-") as directory:
        work_root = Path(directory)
        for input_object in _unique_inputs(inputs):
            input_dir = work_root / input_object.ingest_id
            input_dir.mkdir()
            sysmon_jsonl_path = input_dir / "sysmon.jsonl"
            s3_client.download_file(input_object.bucket, input_object.key, str(sysmon_jsonl_path))
            exit_code = run_standalone(
                [
                    "--sysmon-jsonl",
                    str(sysmon_jsonl_path),
                    "--output-dir",
                    str(input_dir / "output"),
                ]
            )
            if exit_code != 0:
                raise RuntimeError(
                    f"standalone First Cycle failed for S3 object {input_object.bucket}/{input_object.key}"
                )


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
    "S3SysmonInput",
    "build_parser",
    "main",
    "parse_s3_sysmon_inputs",
    "run_worker",
]


if __name__ == "__main__":
    raise SystemExit(main())
