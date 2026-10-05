"""Parse the S3 Event messages accepted by the First Cycle SQS Worker."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from urllib.parse import unquote_plus

_AUTOMATED_INPUT_PREFIX = "incoming/first-cycle/sysmon/"
_AUTOMATED_INPUT_KEY_PATTERN = re.compile(
    r"^incoming/first-cycle/sysmon/"
    r"(?P<ingest_id>ING-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/"
    r"sysmon\.jsonl$"
)


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


__all__ = ["S3SysmonInput", "parse_s3_sysmon_inputs"]
