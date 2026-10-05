import json
import logging
from collections.abc import Callable, Sequence
from pathlib import Path

import pytest
from botocore.exceptions import ClientError

from incident_awareness.pipeline.sqs_worker import (
    PermanentWorkerError,
    RetryableWorkerError,
    _process_message,
    parse_s3_sysmon_inputs,
    run_worker,
)

_BUCKET = "incident-awareness-first-cycle-998301375101-ap-northeast-2-an"
_INGEST_ID = "ING-550e8400-e29b-41d4-a716-446655440000"
_KEY = f"incoming/first-cycle/sysmon/{_INGEST_ID}/sysmon.jsonl"


def _s3_event(
    *,
    bucket: str = _BUCKET,
    event_name: str = "ObjectCreated:Put",
    key: str = _KEY,
    e_tag: str = "opaque-etag",
) -> dict[str, object]:
    return {
        "Records": [
            {
                "eventSource": "aws:s3",
                "eventName": event_name,
                "s3": {
                    "bucket": {"name": bucket},
                    "object": {"key": key, "eTag": e_tag, "sequencer": "001"},
                },
            }
        ]
    }


def test_parses_url_encoded_s3_sysmon_object_key() -> None:
    inputs = parse_s3_sysmon_inputs(
        json.dumps(_s3_event(key=_KEY.replace("/", "%2F"))),
        expected_bucket=_BUCKET,
    )

    assert inputs[0].bucket == _BUCKET
    assert inputs[0].key == _KEY
    assert inputs[0].ingest_id == _INGEST_ID
    assert inputs[0].e_tag == "opaque-etag"
    assert inputs[0].sequencer == "001"


def test_parses_every_record_in_a_batched_s3_event() -> None:
    second_ingest_id = "ING-123e4567-e89b-42d3-a456-426614174000"
    second_key = f"incoming/first-cycle/sysmon/{second_ingest_id}/sysmon.jsonl"

    inputs = parse_s3_sysmon_inputs(
        json.dumps(
            {
                "Records": [
                    _s3_event(key=_KEY)["Records"][0],
                    _s3_event(key=second_key)["Records"][0],
                ]
            }
        ),
        expected_bucket=_BUCKET,
    )

    assert [item.ingest_id for item in inputs] == [_INGEST_ID, second_ingest_id]


@pytest.mark.parametrize(
    ("event", "message"),
    [
        (_s3_event(bucket="other-bucket"), "bucket does not match"),
        (_s3_event(event_name="ObjectRemoved:Delete"), "ObjectCreated"),
        (_s3_event(key="first-cycle/RUN-20261004-001/telemetry/sysmon-0001.jsonl"), "object key"),
        (_s3_event(key="incoming/first-cycle/sysmon/ING-not-a-uuid/sysmon.jsonl"), "object key"),
        (_s3_event(e_tag=""), "eTag"),
    ],
)
def test_rejects_s3_records_outside_worker_input_contract(
    event: dict[str, object],
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        parse_s3_sysmon_inputs(json.dumps(event), expected_bucket=_BUCKET)


def test_rejects_non_json_or_empty_s3_event() -> None:
    with pytest.raises(ValueError, match="valid JSON"):
        parse_s3_sysmon_inputs("not-json", expected_bucket=_BUCKET)
    with pytest.raises(ValueError, match="at least one Records"):
        parse_s3_sysmon_inputs(json.dumps({"Records": []}), expected_bucket=_BUCKET)


def test_worker_downloads_and_deletes_a_successful_message(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO, logger="incident_awareness.pipeline.sqs_worker")
    sqs = _FakeSqs([{"Body": json.dumps(_s3_event()), "ReceiptHandle": "receipt-1"}])
    s3 = _FakeS3()
    calls: list[list[str]] = []

    result = run_worker(
        queue_url="https://example.test/queue",
        expected_bucket=_BUCKET,
        sqs_client=sqs,
        s3_client=s3,
        run_standalone=_successful_standalone(calls),
        once=True,
    )

    assert result == 0
    assert s3.downloads == [(_BUCKET, _KEY)]
    assert sqs.deleted_receipts == ["receipt-1"]
    assert calls[0][0] == "--sysmon-jsonl"
    assert Path(calls[0][1]).name == "sysmon.jsonl"
    assert calls[0][2] == "--output-dir"
    assert Path(calls[0][3]).name == "output"
    statuses = [
        json.loads(record.getMessage())
        for record in caplog.records
        if record.getMessage().startswith('{"event": "first_cycle_worker_input"')
    ]
    assert statuses == [
        {
            "event": "first_cycle_worker_input",
            "input_s3_uri": f"s3://{_BUCKET}/{_KEY}",
            "status": "started",
        },
        {
            "event": "first_cycle_worker_input",
            "input_s3_uri": f"s3://{_BUCKET}/{_KEY}",
            "run_id": "RUN-20261005-001",
            "status": "succeeded",
        },
    ]


def test_worker_logs_failed_status_and_retains_message_when_standalone_execution_fails(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO, logger="incident_awareness.pipeline.sqs_worker")
    sqs = _FakeSqs([{"Body": json.dumps(_s3_event()), "ReceiptHandle": "receipt-1"}])

    run_worker(
        queue_url="https://example.test/queue",
        expected_bucket=_BUCKET,
        sqs_client=sqs,
        s3_client=_FakeS3(),
        run_standalone=lambda _: 1,
        once=True,
    )

    assert sqs.deleted_receipts == []
    statuses = [
        json.loads(record.getMessage())
        for record in caplog.records
        if record.getMessage().startswith('{"event": "first_cycle_worker_input"')
    ]
    assert statuses[-1] == {
        "event": "first_cycle_worker_input",
        "input_s3_uri": f"s3://{_BUCKET}/{_KEY}",
        "status": "failed",
    }


def test_worker_retains_message_when_standalone_rejects_invalid_sysmon_jsonl() -> None:
    sqs = _FakeSqs([{"Body": json.dumps(_s3_event()), "ReceiptHandle": "receipt-1"}])

    run_worker(
        queue_url="https://example.test/queue",
        expected_bucket=_BUCKET,
        sqs_client=sqs,
        s3_client=_FakeS3(),
        run_standalone=_reject_invalid_sysmon_jsonl,
        once=True,
    )

    assert sqs.deleted_receipts == []


def test_worker_processes_duplicate_object_versions_once_per_sqs_message() -> None:
    duplicate_record = _s3_event()["Records"][0]
    sqs = _FakeSqs(
        [
            {
                "Body": json.dumps({"Records": [duplicate_record, duplicate_record]}),
                "ReceiptHandle": "receipt-1",
            }
        ]
    )
    s3 = _FakeS3()
    calls: list[list[str]] = []

    run_worker(
        queue_url="https://example.test/queue",
        expected_bucket=_BUCKET,
        sqs_client=sqs,
        s3_client=s3,
        run_standalone=_successful_standalone(calls),
        once=True,
    )

    assert s3.downloads == [(_BUCKET, _KEY)]
    assert len(calls) == 1
    assert sqs.deleted_receipts == ["receipt-1"]


def test_classifies_invalid_s3_event_as_permanent_error() -> None:
    with pytest.raises(PermanentWorkerError, match="ObjectCreated"):
        _process_message(
            {"Body": json.dumps(_s3_event(event_name="ObjectRemoved:Delete"))},
            expected_bucket=_BUCKET,
            s3_client=_FakeS3(),
            run_standalone=lambda _: 0,
        )


def test_classifies_transient_s3_download_error_as_retryable() -> None:
    error = ClientError(
        {"Error": {"Code": "SlowDown", "Message": "try later"}},
        "GetObject",
    )
    with pytest.raises(RetryableWorkerError, match="SlowDown"):
        _process_message(
            {"Body": json.dumps(_s3_event())},
            expected_bucket=_BUCKET,
            s3_client=_FailingS3(error),
            run_standalone=lambda _: 0,
        )


def test_classifies_missing_s3_object_as_permanent_error() -> None:
    error = ClientError(
        {"Error": {"Code": "NoSuchKey", "Message": "missing"}},
        "GetObject",
    )
    with pytest.raises(PermanentWorkerError, match="NoSuchKey"):
        _process_message(
            {"Body": json.dumps(_s3_event())},
            expected_bucket=_BUCKET,
            s3_client=_FailingS3(error),
            run_standalone=lambda _: 0,
        )


class _FakeSqs:
    def __init__(self, messages: list[dict[str, str]]) -> None:
        self._messages = messages
        self.deleted_receipts: list[str] = []

    def receive_message(self, **_: object) -> dict[str, list[dict[str, str]]]:
        return {"Messages": self._messages}

    def delete_message(self, *, QueueUrl: str, ReceiptHandle: str) -> None:
        assert QueueUrl == "https://example.test/queue"
        self.deleted_receipts.append(ReceiptHandle)


class _FakeS3:
    def __init__(self) -> None:
        self.downloads: list[tuple[str, str]] = []

    def download_file(self, bucket: str, key: str, filename: str) -> None:
        self.downloads.append((bucket, key))
        Path(filename).write_text("{}\n", encoding="utf-8")


class _FailingS3:
    def __init__(self, error: ClientError) -> None:
        self._error = error

    def download_file(self, bucket: str, key: str, filename: str) -> None:
        raise self._error


def _successful_standalone(calls: list[list[str]]) -> Callable[[Sequence[str]], int]:
    def run(arguments: Sequence[str]) -> int:
        calls.append(list(arguments))
        output_dir = Path(arguments[3])
        output_dir.mkdir()
        (output_dir / "run_metadata.json").write_text(
            '{"run_id": "RUN-20261005-001"}',
            encoding="utf-8",
        )
        return 0

    return run


def _reject_invalid_sysmon_jsonl(_: Sequence[str]) -> int:
    raise ValueError("standalone Sysmon JSONL EventData.UtcTime must be in non-decreasing order")
