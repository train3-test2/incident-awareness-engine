import json
import logging
from collections.abc import Callable
from hashlib import sha256
from pathlib import Path

import pytest
from botocore.exceptions import ClientError

from incident_awareness.common.models.pipeline_runtime import PipelineStage
from incident_awareness.pipeline.reporting import PipelineExecutionSummary
from incident_awareness.pipeline.sqs_worker import (
    PermanentWorkerError,
    RetryableWorkerError,
    S3SysmonInput,
    _PostgresSuccessfulReceiptStore,
    _process_message,
    parse_s3_sysmon_inputs,
    run_worker,
)
from incident_awareness.pipeline.standalone import StandaloneExecution

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
        (
            _s3_event(
                key="incoming/first-cycle/sysmon/ING-550e8400-e29b-51d4-a716-446655440000/sysmon.jsonl"
            ),
            "object key",
        ),
        (
            _s3_event(
                key="incoming/first-cycle/sysmon/ING-550e8400-e29b-41d4-c716-446655440000/sysmon.jsonl"
            ),
            "object key",
        ),
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
    calls: list[tuple[Path, Path]] = []

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
    assert calls[0][0].name == "sysmon.jsonl"
    assert calls[0][1].name == "output"
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
    observer = _ObserverContextSpy()

    run_worker(
        queue_url="https://example.test/queue",
        expected_bucket=_BUCKET,
        sqs_client=sqs,
        s3_client=_FakeS3(),
        run_standalone=_failing_standalone,
        runtime_observer_factory=lambda: observer,
        once=True,
    )

    assert sqs.deleted_receipts == []
    assert observer.closed is True
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
    calls: list[tuple[Path, Path]] = []

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


def test_worker_uses_distinct_workspaces_for_different_versions_of_one_ingest() -> None:
    first_record = _s3_event(e_tag="first-version")["Records"][0]
    second_record = _s3_event(e_tag="second-version")["Records"][0]
    sqs = _FakeSqs(
        [
            {
                "Body": json.dumps({"Records": [first_record, second_record]}),
                "ReceiptHandle": "receipt-1",
            }
        ]
    )
    calls: list[tuple[Path, Path]] = []

    run_worker(
        queue_url="https://example.test/queue",
        expected_bucket=_BUCKET,
        sqs_client=sqs,
        s3_client=_FakeS3(),
        run_standalone=_successful_standalone(calls),
        once=True,
    )

    assert len(calls) == 2
    assert calls[0][0].parent != calls[1][0].parent
    assert calls[0][0].parent.name.startswith(f"{_INGEST_ID}-")
    assert calls[1][0].parent.name.startswith(f"{_INGEST_ID}-")


def test_worker_skips_a_successfully_receipted_s3_object_version(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO, logger="incident_awareness.pipeline.sqs_worker")
    receipts = _FakeReceiptStore()
    calls: list[tuple[Path, Path]] = []
    observers: list[_ObserverContextSpy] = []

    def observer_factory() -> "_ObserverContextSpy":
        observer = _ObserverContextSpy()
        observers.append(observer)
        return observer

    run_worker(
        queue_url="https://example.test/queue",
        expected_bucket=_BUCKET,
        sqs_client=_FakeSqs([{"Body": json.dumps(_s3_event()), "ReceiptHandle": "receipt-1"}]),
        s3_client=_FakeS3(),
        run_standalone=_successful_standalone(calls),
        receipt_store=receipts,
        runtime_observer_factory=observer_factory,
        once=True,
    )
    run_worker(
        queue_url="https://example.test/queue",
        expected_bucket=_BUCKET,
        sqs_client=_FakeSqs([{"Body": json.dumps(_s3_event()), "ReceiptHandle": "receipt-2"}]),
        s3_client=_FakeS3(),
        run_standalone=_successful_standalone(calls),
        receipt_store=receipts,
        runtime_observer_factory=observer_factory,
        once=True,
    )

    assert len(calls) == 1
    assert receipts.successful_run_ids == {(_BUCKET, _KEY, "opaque-etag"): "RUN-20261005-001"}
    assert receipts.acquired_inputs == [(_BUCKET, _KEY, "opaque-etag")] * 2
    assert receipts.released_executions == 1
    assert len(observers) == 1
    assert observers[0].closed is True
    assert any('"status": "skipped"' in record.getMessage() for record in caplog.records)


def test_worker_completes_after_receipt_commit_and_closes_per_run_observer() -> None:
    # Given
    first_record = _s3_event(e_tag="first-version")["Records"][0]
    second_record = _s3_event(e_tag="second-version")["Records"][0]
    sqs = _FakeSqs(
        [
            {
                "Body": json.dumps({"Records": [first_record, second_record]}),
                "ReceiptHandle": "receipt-1",
            }
        ]
    )
    events: list[str] = []
    receipts = _OrderedReceiptStore(events)
    observers: list[_ObserverContextSpy] = []
    trackers: list[_RuntimeTrackerSpy] = []

    def observer_factory() -> "_ObserverContextSpy":
        observer = _ObserverContextSpy()
        observers.append(observer)
        return observer

    def run_standalone(
        sysmon_jsonl_path: Path,
        output_root: Path,
        runtime_observer: object | None,
    ) -> StandaloneExecution:
        assert runtime_observer is observers[-1]
        tracker = _RuntimeTrackerSpy(events)
        trackers.append(tracker)
        return _execution(output_root, tracker=tracker)

    # When
    run_worker(
        queue_url="https://example.test/queue",
        expected_bucket=_BUCKET,
        sqs_client=sqs,
        s3_client=_FakeS3(),
        run_standalone=run_standalone,
        receipt_store=receipts,
        runtime_observer_factory=observer_factory,
        once=True,
    )

    # Then
    assert len(observers) == 2
    assert all(observer.closed for observer in observers)
    assert len(trackers) == 2
    assert events == [
        "receipt-commit",
        "runtime-completed",
        "receipt-commit",
        "runtime-completed",
    ]
    assert sqs.deleted_receipts == ["receipt-1"]


def test_worker_without_receipt_does_not_publish_unconfirmed_completion() -> None:
    # Given
    sqs = _FakeSqs([{"Body": json.dumps(_s3_event()), "ReceiptHandle": "receipt-1"}])
    events: list[str] = []
    tracker = _RuntimeTrackerSpy(events)
    observer = _ObserverContextSpy()

    def run_standalone(
        sysmon_jsonl_path: Path,
        output_root: Path,
        runtime_observer: object | None,
    ) -> StandaloneExecution:
        assert runtime_observer is observer
        return _execution(output_root, tracker=tracker)

    # When
    run_worker(
        queue_url="https://example.test/queue",
        expected_bucket=_BUCKET,
        sqs_client=sqs,
        s3_client=_FakeS3(),
        run_standalone=run_standalone,
        runtime_observer_factory=lambda: observer,
        once=True,
    )

    # Then
    assert events == []
    assert observer.closed is True
    assert sqs.deleted_receipts == ["receipt-1"]


def test_worker_receipt_commit_failure_publishes_failed_and_retains_message() -> None:
    # Given
    sqs = _FakeSqs([{"Body": json.dumps(_s3_event()), "ReceiptHandle": "receipt-1"}])
    events: list[str] = []
    tracker = _RuntimeTrackerSpy(events)
    observer = _ObserverContextSpy()
    receipts = _FailingReceiptStore()

    def run_standalone(
        sysmon_jsonl_path: Path,
        output_root: Path,
        runtime_observer: object | None,
    ) -> StandaloneExecution:
        assert runtime_observer is observer
        return _execution(output_root, tracker=tracker)

    # When
    run_worker(
        queue_url="https://example.test/queue",
        expected_bucket=_BUCKET,
        sqs_client=sqs,
        s3_client=_FakeS3(),
        run_standalone=run_standalone,
        receipt_store=receipts,
        runtime_observer_factory=lambda: observer,
        once=True,
    )

    # Then
    assert events == ["runtime-failed:persistence"]
    assert receipts.rollbacks == 1
    assert observer.closed is True
    assert sqs.deleted_receipts == []


def test_worker_observer_factory_failure_does_not_change_business_success() -> None:
    # Given
    sqs = _FakeSqs([{"Body": json.dumps(_s3_event()), "ReceiptHandle": "receipt-1"}])
    calls: list[tuple[Path, Path]] = []

    def fail_observer_creation():
        raise RuntimeError("telemetry unavailable")

    # When
    run_worker(
        queue_url="https://example.test/queue",
        expected_bucket=_BUCKET,
        sqs_client=sqs,
        s3_client=_FakeS3(),
        run_standalone=_successful_standalone(calls),
        receipt_store=_FakeReceiptStore(),
        runtime_observer_factory=fail_observer_creation,
        once=True,
    )

    # Then
    assert len(calls) == 1
    assert sqs.deleted_receipts == ["receipt-1"]


def test_worker_uses_fresh_observer_after_prior_run_telemetry_failure() -> None:
    # Given
    first_record = _s3_event(e_tag="first-version")["Records"][0]
    second_record = _s3_event(e_tag="second-version")["Records"][0]
    sqs = _FakeSqs(
        [
            {
                "Body": json.dumps({"Records": [first_record, second_record]}),
                "ReceiptHandle": "receipt-1",
            }
        ]
    )
    available_observers = iter((_ObserverContextSpy(fail=True), _ObserverContextSpy()))
    observers: list[_ObserverContextSpy] = []

    def observer_factory() -> "_ObserverContextSpy":
        observer = next(available_observers)
        observers.append(observer)
        return observer

    def run_standalone(
        sysmon_jsonl_path: Path,
        output_root: Path,
        runtime_observer: object | None,
    ) -> StandaloneExecution:
        try:
            runtime_observer(object())
        except RuntimeError:
            pass
        return _successful_run_id(sysmon_jsonl_path, output_root)

    # When
    run_worker(
        queue_url="https://example.test/queue",
        expected_bucket=_BUCKET,
        sqs_client=sqs,
        s3_client=_FakeS3(),
        run_standalone=run_standalone,
        receipt_store=_FakeReceiptStore(),
        runtime_observer_factory=observer_factory,
        once=True,
    )

    # Then
    assert len(observers) == 2
    assert observers[0] is not observers[1]
    assert [observer.calls for observer in observers] == [1, 1]
    assert all(observer.closed for observer in observers)
    assert sqs.deleted_receipts == ["receipt-1"]


def test_worker_delete_failure_does_not_change_committed_runtime_completion() -> None:
    # Given
    sqs = _DeleteFailingSqs([{"Body": json.dumps(_s3_event()), "ReceiptHandle": "receipt-1"}])
    events: list[str] = []
    tracker = _RuntimeTrackerSpy(events)
    observer = _ObserverContextSpy()
    receipts = _OrderedReceiptStore(events)

    def run_standalone(
        sysmon_jsonl_path: Path,
        output_root: Path,
        runtime_observer: object | None,
    ) -> StandaloneExecution:
        return _execution(output_root, tracker=tracker)

    # When
    with pytest.raises(RuntimeError, match="delete failed"):
        run_worker(
            queue_url="https://example.test/queue",
            expected_bucket=_BUCKET,
            sqs_client=sqs,
            s3_client=_FakeS3(),
            run_standalone=run_standalone,
            receipt_store=receipts,
            runtime_observer_factory=lambda: observer,
            once=True,
        )

    # Then
    assert events == ["receipt-commit", "runtime-completed"]
    assert receipts.rollbacks == 0
    assert observer.closed is True


def test_worker_redelivery_skips_first_runtime_after_later_object_failure() -> None:
    # Given
    first_record = _s3_event(e_tag="first-version")["Records"][0]
    second_record = _s3_event(e_tag="second-version")["Records"][0]
    message_body = json.dumps({"Records": [first_record, second_record]})
    first_sqs = _FakeSqs([{"Body": message_body, "ReceiptHandle": "receipt-1"}])
    second_sqs = _FakeSqs([{"Body": message_body, "ReceiptHandle": "receipt-2"}])
    receipts = _FakeReceiptStore()
    first_runtime_events: list[str] = []
    retried_runtime_events: list[str] = []
    observers: list[_ObserverContextSpy] = []
    standalone_calls = 0

    def observer_factory() -> "_ObserverContextSpy":
        observer = _ObserverContextSpy()
        observers.append(observer)
        return observer

    def run_standalone(
        sysmon_jsonl_path: Path,
        output_root: Path,
        runtime_observer: object | None,
    ) -> StandaloneExecution:
        nonlocal standalone_calls
        standalone_calls += 1
        if standalone_calls == 2:
            raise OSError("second object failed")
        tracker_events = first_runtime_events if standalone_calls == 1 else retried_runtime_events
        return _execution(output_root, tracker=_RuntimeTrackerSpy(tracker_events))

    # When
    run_worker(
        queue_url="https://example.test/queue",
        expected_bucket=_BUCKET,
        sqs_client=first_sqs,
        s3_client=_FakeS3(),
        run_standalone=run_standalone,
        receipt_store=receipts,
        runtime_observer_factory=observer_factory,
        once=True,
    )
    run_worker(
        queue_url="https://example.test/queue",
        expected_bucket=_BUCKET,
        sqs_client=second_sqs,
        s3_client=_FakeS3(),
        run_standalone=run_standalone,
        receipt_store=receipts,
        runtime_observer_factory=observer_factory,
        once=True,
    )

    # Then
    first_identity = (_BUCKET, _KEY, "first-version")
    second_identity = (_BUCKET, _KEY, "second-version")
    assert first_sqs.deleted_receipts == []
    assert second_sqs.deleted_receipts == ["receipt-2"]
    assert standalone_calls == 3
    assert receipts.acquired_inputs == [
        first_identity,
        second_identity,
        first_identity,
        second_identity,
    ]
    assert set(receipts.successful_run_ids) == {first_identity, second_identity}
    assert receipts.released_executions == 1
    assert first_runtime_events == ["runtime-completed"]
    assert retried_runtime_events == ["runtime-completed"]
    assert len(observers) == 3
    assert all(observer.closed for observer in observers)


def test_postgres_receipt_store_acquires_an_object_lock_before_lookup() -> None:
    connection = _ReceiptConnection(rows=[None, ("RUN-20261005-001",)])
    store = _PostgresSuccessfulReceiptStore(connection)  # type: ignore[arg-type]
    input_object = S3SysmonInput(
        bucket=_BUCKET,
        key=_KEY,
        ingest_id=_INGEST_ID,
        e_tag="opaque-etag",
        sequencer="001",
    )

    run_id = store.acquire_execution(input_object)
    store.release_execution()

    assert run_id == "RUN-20261005-001"
    assert "pg_advisory_xact_lock" in connection.queries[0][0]
    expected_identity = f"{_BUCKET}\x00{_KEY}\x00opaque-etag"
    expected_lock_key = f"first-cycle:s3-object:{sha256(expected_identity.encode()).hexdigest()}"
    assert connection.queries[0][1] == (expected_lock_key,)
    assert "\x00" not in expected_lock_key
    assert "FROM s3_object_receipts" in connection.queries[1][0]
    assert connection.commits == 1


def test_classifies_invalid_s3_event_as_permanent_error() -> None:
    with pytest.raises(PermanentWorkerError, match="ObjectCreated"):
        _process_message(
            {"Body": json.dumps(_s3_event(event_name="ObjectRemoved:Delete"))},
            expected_bucket=_BUCKET,
            s3_client=_FakeS3(),
            run_standalone=_successful_run_id,
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
            run_standalone=_successful_run_id,
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
            run_standalone=_successful_run_id,
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


class _DeleteFailingSqs(_FakeSqs):
    def delete_message(self, *, QueueUrl: str, ReceiptHandle: str) -> None:
        raise RuntimeError("delete failed")


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


class _ReceiptCursor:
    def __init__(self, row: tuple[str] | None) -> None:
        self._row = row

    def fetchone(self) -> tuple[str] | None:
        return self._row


class _ReceiptConnection:
    def __init__(self, *, rows: list[tuple[str] | None]) -> None:
        self._rows = rows
        self.queries: list[tuple[str, tuple[object, ...]]] = []
        self.commits = 0

    def execute(self, query: str, params: tuple[object, ...]) -> _ReceiptCursor:
        self.queries.append((query, params))
        return _ReceiptCursor(self._rows.pop(0))

    def commit(self) -> None:
        self.commits += 1

    def rollback(self) -> None:
        return None


class _FakeReceiptStore:
    def __init__(self) -> None:
        self.successful_run_ids: dict[tuple[str, str, str], str] = {}
        self.acquired_inputs: list[tuple[str, str, str]] = []
        self.released_executions = 0
        self.rollbacks = 0

    def acquire_execution(self, input_object: S3SysmonInput) -> str | None:
        identity = (input_object.bucket, input_object.key, input_object.e_tag)
        self.acquired_inputs.append(identity)
        return self.successful_run_ids.get(identity)

    def save_success(self, input_object: S3SysmonInput, *, run_id: str) -> None:
        self.successful_run_ids[(input_object.bucket, input_object.key, input_object.e_tag)] = (
            run_id
        )

    def release_execution(self) -> None:
        self.released_executions += 1

    def rollback(self) -> None:
        self.rollbacks += 1


class _OrderedReceiptStore(_FakeReceiptStore):
    def __init__(self, events: list[str]) -> None:
        super().__init__()
        self._events = events

    def save_success(self, input_object: S3SysmonInput, *, run_id: str) -> None:
        super().save_success(input_object, run_id=run_id)
        self._events.append("receipt-commit")


class _FailingReceiptStore(_FakeReceiptStore):
    def save_success(self, input_object: S3SysmonInput, *, run_id: str) -> None:
        raise RuntimeError("receipt commit failed; transaction outcome may be unknown")


class _ObserverContextSpy:
    def __init__(self, *, fail: bool = False) -> None:
        self.closed = False
        self.calls = 0
        self._fail = fail

    def __call__(self, status: object) -> None:
        self.calls += 1
        if self._fail:
            raise RuntimeError("telemetry unavailable")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.closed = True


class _RuntimeTrackerSpy:
    def __init__(self, events: list[str]) -> None:
        self._events = events

    def complete(self) -> None:
        self._events.append("runtime-completed")

    def fail(self, stage: PipelineStage) -> None:
        self._events.append(f"runtime-failed:{stage.value}")


def _execution(output_root: Path, *, tracker: _RuntimeTrackerSpy) -> StandaloneExecution:
    execution = _successful_run_id(Path("sysmon.jsonl"), output_root)
    return StandaloneExecution(
        output_dir=execution.output_dir,
        summary=execution.summary,
        _runtime_tracker=tracker,
    )


def _successful_standalone(
    calls: list[tuple[Path, Path]],
) -> Callable[[Path, Path, object | None], StandaloneExecution]:
    def run(
        sysmon_jsonl_path: Path,
        output_root: Path,
        runtime_observer: object | None,
    ) -> StandaloneExecution:
        calls.append((sysmon_jsonl_path, output_root))
        return _successful_run_id(sysmon_jsonl_path, output_root)

    return run


def _successful_run_id(_: Path, output_root: Path, __: object | None = None) -> StandaloneExecution:
    return StandaloneExecution(
        output_dir=output_root,
        summary=PipelineExecutionSummary(
            run_id="RUN-20261005-001",
            entity_id="WIN-01",
            normalized_event_count=1,
            evidence_count=1,
            fusion_status="detected",
            detector_status="not_evaluated",
            decision_path=None,
        ),
    )


def _failing_standalone(_: Path, __: Path, ___: object | None) -> StandaloneExecution:
    raise OSError("standalone First Cycle failed")


def _reject_invalid_sysmon_jsonl(_: Path, __: Path, ___: object | None) -> StandaloneExecution:
    raise ValueError("standalone Sysmon JSONL EventData.UtcTime must be in non-decreasing order")
